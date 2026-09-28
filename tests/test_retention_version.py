"""Tests for version-pinned retention policy resolution.

``RequestStore.resolve_retention`` with the optional ``version`` argument
reads one immutable published policy catalog version from storage and
resolves the effective retention against that fixed version instead of
catalogs passed by the caller. The version source and the passing
catalog source are mutually exclusive; the entry stays strictly
read-only and the result is traceable to one concrete version.
"""

import json
import os
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor

from forgetting_evidence.requests import (
    PolicyCatalogNotFound,
    RequestStore,
)

_FAILURE = "retention_policy_resolution_failed"


def _rule(selector, days, reason="ordinary reason"):
    return {"selector": selector, "days": days, "reason": reason}


def _exception(subject, selector, days, reason="exception reason"):
    return {
        "subject": subject,
        "selector": selector,
        "days": days,
        "reason": reason,
    }


def _parse(text):
    return json.loads(text)


class RetentionVersionResolutionTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "evidence.db")
        self.store = RequestStore(self.db_path)
        self.rules_v1 = {
            "p-default": _rule("*", 30, "default retention"),
            "p-users": _rule("users*", 60, "users group"),
        }
        self.exceptions_v1 = {
            "x-1": _exception("subject-1", "users*", 90, "legal hold"),
        }

    def tearDown(self):
        self._tmp.cleanup()

    def _publish(self, tenant="tenant-a", rules=None, exceptions=None):
        return self.store.publish_policy_catalog(
            tenant,
            self.rules_v1 if rules is None else rules,
            self.exceptions_v1 if exceptions is None else exceptions,
        )

    def _resolve_version(self, scopes, version, *,
                         tenant="tenant-a", subject="subject-1"):
        return self.store.resolve_retention(
            tenant, subject, scopes, version=version
        )

    # -- basic fixed-version resolution --------------------------------

    def test_version_resolution_matches_passing_catalog(self):
        publication = self._publish()
        self.assertEqual(publication["version"], 1)
        resolved = self._resolve_version(["users:alice"], 1)
        self.assertEqual(
            resolved,
            {
                "retention_days": 90,
                "policy_id": "x-1",
                "exceptions": [
                    {
                        "subject": "subject-1",
                        "scope": "users:alice",
                        "retention_days": 90,
                        "reason": "legal hold",
                    }
                ],
                "reason": "legal hold",
            },
        )
        self.assertEqual(
            list(resolved),
            ["retention_days", "policy_id", "exceptions", "reason"],
        )
        equivalent = self.store.resolve_retention(
            "tenant-a", "subject-1", ["users:alice"],
            self.rules_v1, self.exceptions_v1,
        )
        self.assertEqual(resolved, equivalent)

    def test_version_resolution_applies_ordinary_rules_without_exception(self):
        self._publish(exceptions={})
        resolved = self._resolve_version(["users:alice"], 1)
        self.assertEqual(resolved["retention_days"], 60)
        self.assertEqual(resolved["policy_id"], "p-users")
        self.assertEqual(resolved["reason"], "users group")
        self.assertEqual(resolved["exceptions"], [])

    def test_exception_for_other_subject_does_not_apply(self):
        self._publish(
            exceptions={"x-9": _exception("subject-2", "*", 365, "hold")}
        )
        resolved = self._resolve_version(["users:alice"], 1)
        self.assertEqual(resolved["retention_days"], 60)
        self.assertEqual(resolved["policy_id"], "p-users")
        self.assertEqual(resolved["exceptions"], [])

    def test_hit_exceptions_stable_by_normalized_scope_and_verbatim(self):
        rules = {"p-default": _rule("*", 1, "d")}
        exceptions = {
            "x-users": _exception("subject-1", "users*", 60, "users 理由"),
            "x-orders": _exception("subject-1", "orders:o1", 90, "order 理由"),
        }
        self._publish(rules=rules, exceptions=exceptions)
        resolved = self._resolve_version(
            ["media:m1", "users:a", "orders:o1"], 1
        )
        self.assertEqual(
            [item["scope"] for item in resolved["exceptions"]],
            ["orders:o1", "users:a"],
        )
        self.assertEqual(
            [item["reason"] for item in resolved["exceptions"]],
            ["order 理由", "users 理由"],
        )
        for item in resolved["exceptions"]:
            self.assertEqual(
                list(item), ["subject", "scope", "retention_days", "reason"]
            )
        self.assertEqual(resolved["retention_days"], 90)

    def test_max_retention_across_scopes_with_version(self):
        self._publish(exceptions={})
        resolved = self._resolve_version(
            ["users:alice", "orders:o1"], 1
        )
        # users* -> 60 covers the first scope; the plain default 30
        # covers the order scope, so the effective maximum is 60.
        self.assertEqual(resolved["retention_days"], 60)

    # -- fixed version stays stable across later publications ----------

    def test_fixed_version_ignores_later_publications(self):
        self._publish()
        rules_v2 = {
            "p-default": _rule("*", 30, "default retention"),
            "p-users": _rule("users*", 120, "users changed"),
        }
        second = self.store.publish_policy_catalog(
            "tenant-a", rules_v2, {}
        )
        self.assertEqual(second["version"], 2)
        first = self._resolve_version(["users:alice"], 1)
        again = self._resolve_version(["users:alice"], 1)
        self.assertEqual(first, again)
        self.assertEqual(first["retention_days"], 90)
        self.assertEqual(first["policy_id"], "x-1")
        latest = self._resolve_version(["users:alice"], 2)
        self.assertEqual(latest["retention_days"], 120)
        self.assertEqual(latest["policy_id"], "p-users")

    def test_resolution_independent_of_publish_order(self):
        rules_a = {
            "p-users": _rule("users*", 60, "grp"),
            "p-default": _rule("*", 30, "def"),
        }
        rules_b = dict(reversed(list(rules_a.items())))
        first = self.store.publish_policy_catalog("tenant-a", rules_a, {})
        reused = self.store.publish_policy_catalog("tenant-a", rules_b, {})
        self.assertEqual(reused, first)
        resolved = self._resolve_version(["users:a"], first["version"])
        self.assertEqual(resolved["retention_days"], 60)

    def test_republished_same_catalog_keeps_version_and_result(self):
        self._publish()
        self.store.publish_policy_catalog(
            "tenant-a",
            {"p-default": _rule("*", 7, "seven")},
            {},
        )
        # Republishing the v1 normalized catalog reuses version 1 and
        # its first effective time; the pinned result is unchanged.
        reused = self._publish()
        self.assertEqual(reused["version"], 1)
        resolved = self._resolve_version(["users:alice"], 1)
        self.assertEqual(resolved["retention_days"], 90)

    # -- mutual exclusivity / source validation ------------------------

    def test_version_and_passing_catalogs_are_mutually_exclusive(self):
        self._publish()
        kwargs_list = [
            {"rules": self.rules_v1},
            {"exceptions": {}},
            {"rules": self.rules_v1, "exceptions": self.exceptions_v1},
        ]
        for kwargs in kwargs_list:
            with self.subTest(kwargs=sorted(kwargs)):
                with self.assertRaises(ValueError) as caught:
                    self.store.resolve_retention(
                        "tenant-a", "subject-1", ["users:a"],
                        version=1, **kwargs
                    )
                self.assertEqual(str(caught.exception), _FAILURE)
        # Explicitly passing a null catalog alongside a version is the
        # same exclusivity error, not a silent empty catalog.
        with self.assertRaises(ValueError) as caught:
            self.store.resolve_retention(
                "tenant-a", "subject-1", ["users:a"], None, version=1
            )
        self.assertEqual(str(caught.exception), _FAILURE)

    def test_no_version_and_no_catalogs_rejected(self):
        with self.assertRaises(ValueError) as caught:
            self.store.resolve_retention(
                "tenant-a", "subject-1", ["users:a"]
            )
        self.assertEqual(str(caught.exception), _FAILURE)
        with self.assertRaises(ValueError):
            self.store.resolve_retention(
                "tenant-a", "subject-1", ["users:a"], exceptions={}
            )
        with self.assertRaises(ValueError):
            self.store.resolve_retention(
                "tenant-a", "subject-1", ["users:a"], rules=self.rules_v1
            )

    def test_invalid_version_rejected_without_touching_storage(self):
        self._publish()
        for bad in [True, False, 0, -1, -100, 1.0, "1", 1.5, None, [1]]:
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(ValueError) as caught:
                    self.store.resolve_retention(
                        "tenant-a", "subject-1", ["users:a"], version=bad
                    )
                self.assertEqual(str(caught.exception), _FAILURE)

    def test_blank_tenant_or_subject_rejected_with_version(self):
        self._publish()
        for bad in [None, "", "   ", 7, True]:
            with self.assertRaises(ValueError):
                self.store.resolve_retention(
                    bad, "subject-1", ["users:a"], version=1
                )
            with self.assertRaises(ValueError):
                self.store.resolve_retention(
                    "tenant-a", bad, ["users:a"], version=1
                )

    def test_bad_scopes_rejected_with_version_before_read(self):
        self._publish()
        for bad in [[], (), "users:a", {"users:a"}, iter(["users:a"]),
                    [""], [None], ["users"], ["a", "a"]]:
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(ValueError):
                    self.store.resolve_retention(
                        "tenant-a", "subject-1", bad, version=1
                    )
        # A bad scope never reaches the version lookup: an unknown
        # version with a bad scope is still the validation error.
        with self.assertRaises(ValueError):
            self.store.resolve_retention(
                "tenant-a", "subject-1", [], version=99
            )

    # -- PolicyCatalogNotFound -----------------------------------------

    def test_missing_version_raises_not_found(self):
        self._publish()
        with self.assertRaises(PolicyCatalogNotFound):
            self._resolve_version(["users:a"], 2)
        with self.assertRaises(PolicyCatalogNotFound):
            self._resolve_version(["users:a"], 999)

    def test_no_publications_raises_not_found(self):
        with self.assertRaises(PolicyCatalogNotFound):
            self._resolve_version(["users:a"], 1)

    def test_cross_tenant_version_raises_not_found(self):
        self._publish(tenant="tenant-a")
        # tenant-b has no version 1; tenant-a does. The outcome must be
        # identical to a genuinely missing version.
        with self.assertRaises(PolicyCatalogNotFound) as foreign:
            self._resolve_version(
                ["users:a"], 1, tenant="tenant-b"
            )
        self.store.publish_policy_catalog(
            "tenant-b", {"p-default": _rule("*", 5, "b")}, {}
        )
        with self.assertRaises(PolicyCatalogNotFound) as missing:
            self._resolve_version(
                ["users:a"], 99, tenant="tenant-b"
            )
        self.assertEqual(
            type(foreign.exception), type(missing.exception)
        )

    # -- OSError contract ----------------------------------------------

    def test_corrupt_catalog_content_raises_retention_oserror(self):
        self._publish()
        with sqlite3.connect(self.db_path) as conn:
            # Tamper one rule row out of band: the version fingerprint
            # no longer matches the stored content.
            conn.execute(
                "UPDATE policy_catalog_rules SET days = 7 WHERE version = 1"
            )
            conn.commit()
        with self.assertRaises(OSError) as caught:
            self._resolve_version(["users:a"], 1)
        self.assertEqual(str(caught.exception), _FAILURE)
        # Catalog corruption must not surface catalog wording.
        self.assertNotIn("catalog", str(caught.exception))

    def test_missing_catalog_row_raises_retention_oserror(self):
        self._publish(exceptions={})
        with sqlite3.connect(self.db_path) as conn:
            # Remove the default rule: fingerprint mismatch and a broken
            # default invariant both count as catalog corruption.
            conn.execute("DELETE FROM policy_catalog_rules WHERE version = 1")
            conn.commit()
        with self.assertRaises(OSError) as caught:
            self._resolve_version(["users:a"], 1)
        self.assertEqual(str(caught.exception), _FAILURE)

    def test_corrupt_version_row_raises_retention_oserror(self):
        self._publish()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE policy_catalog_versions SET effective_at = 'nope' "
                "WHERE tenant_id = 'tenant-a' AND version = 1"
            )
            conn.commit()
        with self.assertRaises(OSError) as caught:
            self._resolve_version(["users:a"], 1)
        self.assertEqual(str(caught.exception), _FAILURE)

    def test_storage_fault_raises_retention_oserror(self):
        self._publish()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DROP TABLE requests")
            conn.commit()
        with self.assertRaises(OSError) as caught:
            self._resolve_version(["users:a"], 1)
        self.assertEqual(str(caught.exception), _FAILURE)

    def test_corrupt_request_record_under_version_path_oserror(self):
        receipt = self.store.submit(
            "tenant-a", "subject-1", ["users:a"], "key-1"
        )
        self._publish()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE requests SET scopes_json = 'not-json' WHERE request_id = ?",
                (receipt["request_id"],),
            )
            conn.commit()
        with self.assertRaises(OSError) as caught:
            self._resolve_version(["users:a"], 1)
        self.assertEqual(str(caught.exception), _FAILURE)

    # -- read-only / determinism ---------------------------------------

    def test_version_resolution_never_writes(self):
        self.store.submit("tenant-a", "subject-1", ["users:a"], "key-1")
        self._publish()
        tables = (
            "requests",
            "status_events",
            "claim_attempts",
            "claim_tokens",
            "inspection_batches",
            "inspection_batch_items",
            "audit_anchors",
            "deletion_receipts",
            "policy_catalog_versions",
            "policy_catalog_rules",
            "policy_catalog_exceptions",
        )
        with sqlite3.connect(self.db_path) as conn:
            before = {
                table: conn.execute(
                    f"SELECT count(*) FROM {table}"
                ).fetchone()[0]
                for table in tables
            }
        for _ in range(3):
            self._resolve_version(["users:a", "users*"], 1)
            with self.assertRaises(PolicyCatalogNotFound):
                self._resolve_version(["users:a"], 77)
        with sqlite3.connect(self.db_path) as conn:
            after = {
                table: conn.execute(
                    f"SELECT count(*) FROM {table}"
                ).fetchone()[0]
                for table in tables
            }
        self.assertEqual(before, after)

    def test_repeat_and_rebuild_are_stable(self):
        self.store.submit("tenant-a", "subject-1", ["users:a"], "key-1")
        self._publish()
        first = self._resolve_version(["users:a"], 1)
        second = self._resolve_version(["users:a"], 1)
        rebuilt = RequestStore(self.db_path).resolve_retention(
            "tenant-a", "subject-1", ["users:a"], version=1
        )
        self.assertEqual(first, second)
        self.assertEqual(first, rebuilt)

    def test_concurrent_version_reads_are_stable(self):
        for i in range(10):
            self.store.submit(
                "tenant-a", "subject-1", [f"coll:item-{i}"], f"key-{i}"
            )
        self._publish(
            rules={
                "p-default": _rule("*", 30),
                "p-group": _rule("coll*", 60),
            },
            exceptions={
                "x-1": _exception("subject-1", "coll:item-3", 90)
            },
        )
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(
                pool.map(
                    lambda _: self.store.resolve_retention(
                        "tenant-a", "subject-1",
                        ["coll:item-3", "coll:item-4"], version=1
                    ),
                    range(16),
                )
            )
        for result in results:
            self.assertEqual(result, results[0])
        self.assertEqual(results[0]["retention_days"], 90)

    def test_existing_requests_do_not_change_version_result(self):
        self._publish(exceptions={})
        before = self._resolve_version(["users:a"], 1)
        self.store.submit("tenant-a", "subject-1", ["users:a"], "key-1")
        self.store.submit("tenant-a", "subject-1", ["users*"], "key-2")
        self.assertEqual(self._resolve_version(["users:a"], 1), before)

    # -- in-memory store ------------------------------------------------

    def test_in_memory_store_version_resolution(self):
        store = RequestStore(":memory:")
        store.publish_policy_catalog(
            "t",
            {"p-default": _rule("*", 11, "mem def")},
            {"x-1": _exception("s1", "*", 22, "mem hold")},
        )
        resolved = store.resolve_retention(
            "t", "s1", ["anything:x"], version=1
        )
        self.assertEqual(
            resolved,
            {
                "retention_days": 22,
                "policy_id": "x-1",
                "exceptions": [
                    {
                        "subject": "s1",
                        "scope": "anything:x",
                        "retention_days": 22,
                        "reason": "mem hold",
                    }
                ],
                "reason": "mem hold",
            },
        )
        with self.assertRaises(PolicyCatalogNotFound):
            store.resolve_retention("t", "s1", ["x:y"], version=2)


if __name__ == "__main__":
    unittest.main()
