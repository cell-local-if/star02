"""Tests for versioned retention policy resolution.

``RequestStore.resolve_retention`` keeps its call-time rule/exception
catalogs when no version is named and, when ``version`` names a
published catalog, reads that immutable version from the store as its
sole catalog source. The two sources can never be supplied together.
Resolution stays read-only and the result is traceable to one definite
version.
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


class VersionedRetentionResolutionTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "evidence.db")
        self.store = RequestStore(self.db_path)
        self.rules = {
            "p-default": _rule("*", 30, "default retention"),
            "p-users": _rule("users*", 60, "users group"),
        }
        self.exceptions = {
            "x-alice": _exception("subject-1", "users:alice", 365, "legal hold"),
        }

    def tearDown(self):
        self._tmp.cleanup()

    def _publish(self, tenant="tenant-a", rules=None, exceptions=None):
        return self.store.publish_policy_catalog(
            tenant,
            self.rules if rules is None else rules,
            self.exceptions if exceptions is None else exceptions,
        )

    def _resolve(self, scopes, version, tenant="tenant-a", subject="subject-1"):
        return self.store.resolve_retention(
            tenant, subject, scopes, version=version
        )

    # -- basic version sourcing ----------------------------------------

    def test_named_version_drives_resolution(self):
        self._publish()
        result = self._resolve(["users:alice"], version=1)
        self.assertEqual(
            result,
            {
                "retention_days": 365,
                "policy_id": "x-alice",
                "exceptions": [
                    {
                        "subject": "subject-1",
                        "scope": "users:alice",
                        "retention_days": 365,
                        "reason": "legal hold",
                    }
                ],
                "reason": "legal hold",
            },
        )
        self.assertEqual(
            list(result),
            ["retention_days", "policy_id", "exceptions", "reason"],
        )
        self.assertEqual(
            list(result["exceptions"][0]),
            ["subject", "scope", "retention_days", "reason"],
        )

    def test_version_result_matches_its_published_catalog(self):
        self._publish()
        from_version = self._resolve(["users:alice", "users*"], version=1)
        from_inputs = self.store.resolve_retention(
            "tenant-a",
            "subject-1",
            ["users:alice", "users*"],
            self.rules,
            self.exceptions,
        )
        self.assertEqual(from_version, from_inputs)

    def test_specific_version_is_pinned(self):
        self._publish(rules=self.rules, exceptions=self.exceptions)
        short_rules = {"p-default": _rule("*", 7, "short")}
        self.store.publish_policy_catalog("tenant-a", short_rules, {})
        v1 = self._resolve(["users:alice"], version=1)
        v2 = self._resolve(["users:alice"], version=2)
        self.assertEqual(v1["retention_days"], 365)
        self.assertEqual(v1["policy_id"], "x-alice")
        self.assertEqual(v2["retention_days"], 7)
        self.assertEqual(v2["policy_id"], "p-default")
        self.assertEqual(v2["exceptions"], [])
        # Re-resolving the old version is unaffected by the newer one.
        self.assertEqual(self._resolve(["users:alice"], version=1), v1)

    def test_republished_catalog_keeps_version_semantics(self):
        self._publish(rules=self.rules, exceptions=self.exceptions)
        self.store.publish_policy_catalog(
            "tenant-a", {"p-default": _rule("*", 7, "short")}, {}
        )
        reused = self._publish(rules=self.rules, exceptions=self.exceptions)
        self.assertEqual(reused["version"], 1)
        result = self._resolve(["users:alice"], version=1)
        self.assertEqual(result["retention_days"], 365)

    def test_stored_rules_keep_selector_precedence(self):
        rules = {
            "p-default": _rule("*", 30, "def"),
            "p-group": _rule("users*", 60, "grp"),
            "p-entry": _rule("users:alice", 90, "ent"),
        }
        self._publish(rules=rules, exceptions={})
        self.assertEqual(
            self._resolve(["users:alice"], version=1)["policy_id"], "p-entry"
        )
        self.assertEqual(
            self._resolve(["users*"], version=1)["policy_id"], "p-group"
        )
        self.assertEqual(
            self._resolve(["*"], version=1)["policy_id"], "p-default"
        )

    def test_effective_days_is_max_and_exceptions_follow_scope_order(self):
        rules = {
            "p-default": _rule("*", 30, "def"),
            "p-big": _rule("media*", 400, "big ordinary"),
        }
        exceptions = {
            "x-users": _exception("subject-1", "users*", 60, "users hold"),
            "x-order": _exception("subject-1", "orders:o1", 90, "order hold"),
        }
        self._publish(rules=rules, exceptions=exceptions)
        result = self._resolve(
            ["users:alice", "orders:o1", "media:m1"], version=1
        )
        self.assertEqual(result["retention_days"], 400)
        self.assertEqual(result["policy_id"], "p-big")
        self.assertEqual(result["reason"], "big ordinary")
        self.assertEqual(
            [item["scope"] for item in result["exceptions"]],
            ["orders:o1", "users:alice"],
        )

    def test_result_independent_of_passing_order(self):
        rules = dict(reversed(list({
            "p-z": _rule("users:alice", 10, "z rule"),
            "p-a": _rule("users:alice", 20, "a rule"),
            "p-default": _rule("*", 30, "def"),
        }.items())))
        self._publish(rules=rules, exceptions={})
        result = self._resolve(["users:alice"], version=1)
        self.assertEqual(result["policy_id"], "p-a")
        self.assertEqual(result["retention_days"], 20)

    def test_scopes_still_normalize(self):
        self._publish(rules=self.rules, exceptions={})
        result = self._resolve(["users:a", "users*", "users:b"], version=1)
        self.assertEqual(result["retention_days"], 60)
        self.assertEqual(result["policy_id"], "p-users")

    def test_values_are_plain_json_types(self):
        self._publish()
        result = self._resolve(["users:alice"], version=1)
        self.assertEqual(json.loads(json.dumps(result)), result)
        self.assertIsInstance(result["retention_days"], int)

    def test_exceptions_bound_to_other_subjects_never_hit(self):
        self._publish()
        result = self._resolve(["users:alice"], version=1, subject="subject-2")
        self.assertEqual(result["retention_days"], 60)
        self.assertEqual(result["policy_id"], "p-users")
        self.assertEqual(result["exceptions"], [])

    # -- source exclusivity and validation -----------------------------

    def test_version_and_catalog_inputs_are_mutually_exclusive(self):
        self._publish()
        for kwargs in (
            {"rules": self.rules},
            {"exceptions": self.exceptions},
            {"rules": self.rules, "exceptions": self.exceptions},
        ):
            with self.subTest(kwargs=sorted(kwargs)):
                with self.assertRaises(ValueError) as caught:
                    self.store.resolve_retention(
                        "tenant-a",
                        "subject-1",
                        ["users:alice"],
                        version=1,
                        **kwargs,
                    )
                self.assertEqual(str(caught.exception), _FAILURE)

    def test_omitting_both_sources_is_value_error(self):
        self._publish()
        with self.assertRaises(ValueError) as caught:
            self.store.resolve_retention(
                "tenant-a", "subject-1", ["users:alice"]
            )
        self.assertEqual(str(caught.exception), _FAILURE)
        with self.assertRaises(ValueError):
            self.store.resolve_retention(
                "tenant-a", "subject-1", ["users:alice"], rules=self.rules
            )

    def test_invalid_version_rejected(self):
        self._publish()
        # None is the "version omitted" selector and is exercised
        # separately below; every other non-positive/non-int value is a
        # value error even when catalog inputs are supplied.
        for bad in [True, False, 0, -1, 1.5, "1", [], (1,)]:
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(ValueError):
                    self.store.resolve_retention(
                        "tenant-a",
                        "subject-1",
                        ["users:alice"],
                        self.rules,
                        self.exceptions,
                        bad,
                    )
        # None explicitly means "no version": it keeps the input path.
        result = self.store.resolve_retention(
            "tenant-a",
            "subject-1",
            ["users:alice"],
            self.rules,
            self.exceptions,
            None,
        )
        self.assertEqual(result["retention_days"], 365)

    def test_invalid_identity_and_scopes_rejected_on_version_path(self):
        self._publish()
        for bad_tenant in [None, "", "   ", 7, True]:
            with self.assertRaises(ValueError):
                self._resolve(["users:a"], version=1, tenant=bad_tenant)
        for bad_subject in [None, "", "  ", 7, True]:
            with self.assertRaises(ValueError):
                self._resolve(["users:a"], version=1, subject=bad_subject)
        for bad_scopes in [
            [], (), "users:a", {"users:a"}, {"users:a": 1},
            iter(["users:a"]), [""], [None], [7], ["users"], ["a", "a"],
        ]:
            with self.assertRaises(ValueError):
                self._resolve(bad_scopes, version=1)

    # -- not found ------------------------------------------------------

    def test_unknown_and_cross_tenant_versions_raise_not_found(self):
        self._publish()
        self.store.publish_policy_catalog(
            "tenant-b", {"p-default": _rule("*", 1, "x")}, {}
        )
        for tenant, version in [
            ("tenant-a", 99),
            ("tenant-other", 1),
            ("tenant-c", 1),
            ("never-published", 1),
        ]:
            with self.subTest(tenant=tenant, version=version):
                with self.assertRaises(PolicyCatalogNotFound):
                    self._resolve(["*"], version=version, tenant=tenant)

    def test_not_found_message_has_no_tenant_or_path_detail(self):
        try:
            self._resolve(["*"], version=4)
        except PolicyCatalogNotFound as exc:
            message = str(exc)
            self.assertNotIn("tenant", message.lower())
            self.assertNotIn("/", message)
        else:
            self.fail("expected PolicyCatalogNotFound")

    # -- corruption / storage failures ----------------------------------

    def _published_db(self):
        self._publish()
        self.assertEqual(
            self._resolve(["users:alice"], version=1)["retention_days"],
            365,
        )

    def test_corrupt_version_row_raises_retention_oserror(self):
        self._published_db()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE policy_catalog_versions SET effective_at = 'broken'"
            )
            conn.commit()
        with self.assertRaises(OSError) as caught:
            self._resolve(["*"], version=1)
        self.assertEqual(str(caught.exception), _FAILURE)

    def test_corrupt_rule_row_raises_retention_oserror(self):
        self._published_db()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("UPDATE policy_catalog_rules SET days = -1")
            conn.commit()
        with self.assertRaises(OSError) as caught:
            self._resolve(["*"], version=1)
        self.assertEqual(str(caught.exception), _FAILURE)

    def test_fingerprint_tamper_raises_retention_oserror(self):
        self._published_db()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("UPDATE policy_catalog_rules SET days = 31")
            conn.commit()
        with self.assertRaises(OSError) as caught:
            self._resolve(["*"], version=1)
        self.assertEqual(str(caught.exception), _FAILURE)

    def test_missing_catalog_table_raises_retention_oserror(self):
        self._published_db()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DROP TABLE policy_catalog_versions")
            conn.commit()
        with self.assertRaises(OSError) as caught:
            self._resolve(["*"], version=1)
        self.assertEqual(str(caught.exception), _FAILURE)

    def test_corrupt_request_record_raises_retention_oserror(self):
        self._published_db()
        receipt = self.store.submit(
            "tenant-a", "subject-1", ["users:a"], "key-1"
        )
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE requests SET scopes_json = 'not-json' WHERE request_id = ?",
                (receipt["request_id"],),
            )
            conn.commit()
        with self.assertRaises(OSError) as caught:
            self._resolve(["users:a"], version=1)
        self.assertEqual(str(caught.exception), _FAILURE)

    # -- read-only ------------------------------------------------------

    def test_versioned_resolution_never_writes(self):
        self._publish()
        self.store.submit("tenant-a", "subject-1", ["users:a"], "key-1")
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
            self._resolve(["users:a", "users*"], version=1)
            try:
                self._resolve(["*"], version=99)
            except PolicyCatalogNotFound:
                pass
            try:
                self._resolve([], version=1)
            except ValueError:
                pass
        with sqlite3.connect(self.db_path) as conn:
            after = {
                table: conn.execute(
                    f"SELECT count(*) FROM {table}"
                ).fetchone()[0]
                for table in tables
            }
        self.assertEqual(before, after)

    def test_validation_and_not_found_leave_data_unchanged(self):
        self._publish()
        catalog_tables = (
            "policy_catalog_versions",
            "policy_catalog_rules",
            "policy_catalog_exceptions",
        )
        with sqlite3.connect(self.db_path) as conn:
            schema_before = conn.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' ORDER BY name"
            ).fetchall()
            counts = {
                name: conn.execute(
                    f"SELECT count(*) FROM {name}"
                ).fetchone()[0]
                for name in catalog_tables
            }
        for call in (
            lambda: self._resolve(["*"], version=True),
            lambda: self._resolve(["*"], version=0),
            lambda: self.store.resolve_retention(
                "tenant-a", "subject-1", ["*"], version=1, rules=self.rules
            ),
            lambda: self._resolve(["*"], version=5),
        ):
            self.assertRaises((ValueError, PolicyCatalogNotFound), call)
        with sqlite3.connect(self.db_path) as conn:
            schema_after = conn.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' ORDER BY name"
            ).fetchall()
            after = {
                name: conn.execute(
                    f"SELECT count(*) FROM {name}"
                ).fetchone()[0]
                for name in catalog_tables
            }
        self.assertEqual(counts, after)
        self.assertEqual(schema_before, schema_after)

    # -- determinism ----------------------------------------------------

    def test_repeat_and_rebuild_are_stable(self):
        self._publish()
        first = self._resolve(["users:alice"], version=1)
        second = self._resolve(["users:alice"], version=1)
        rebuilt = RequestStore(self.db_path).resolve_retention(
            "tenant-a", "subject-1", ["users:alice"], version=1
        )
        self.assertEqual(first, second)
        self.assertEqual(first, rebuilt)

    def test_concurrent_read_only_calls_agree(self):
        rules = {
            "p-default": _rule("*", 30, "def"),
            "p-coll": _rule("coll*", 60, "grp"),
        }
        exceptions = {
            "x-1": _exception("subject-1", "coll:item-3", 90, "hold"),
        }
        self._publish(rules=rules, exceptions=exceptions)
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(
                pool.map(
                    lambda _: self.store.resolve_retention(
                        "tenant-a",
                        "subject-1",
                        ["coll:item-3", "coll:item-4"],
                        version=1,
                    ),
                    range(16),
                )
            )
        self.assertTrue(all(result == results[0] for result in results))
        self.assertEqual(results[0]["retention_days"], 90)

    def test_publication_after_resolution_does_not_change_pinned_result(self):
        self._publish(rules=self.rules, exceptions=self.exceptions)
        pinned = self._resolve(["users:alice"], version=1)
        self.store.publish_policy_catalog(
            "tenant-a", {"p-default": _rule("*", 1, "new")}, {}
        )
        self.assertEqual(self._resolve(["users:alice"], version=1), pinned)

    def test_in_memory_store_versioned_resolution(self):
        store = RequestStore(":memory:")
        store.publish_policy_catalog("t", self.rules, self.exceptions)
        store.publish_policy_catalog(
            "t", {"p-default": _rule("*", 2, "two")}, {}
        )
        self.assertEqual(
            store.resolve_retention("t", "subject-1", ["users:alice"], version=1)[
                "retention_days"
            ],
            365,
        )
        self.assertEqual(
            store.resolve_retention("t", "subject-1", ["users:alice"], version=2)[
                "retention_days"
            ],
            2,
        )
        with self.assertRaises(PolicyCatalogNotFound):
            store.resolve_retention("other", "s", ["*"], version=1)


if __name__ == "__main__":
    unittest.main()
