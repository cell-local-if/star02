"""Tests for the versioned policy catalog storage entries.

``RequestStore.publish_policy_catalog`` freezes the ordinary rule
catalog and the subject exception catalog as one immutable,
auto-numbered version; ``read_policy_catalog`` reads a version back
(latest by default) as one compact JSON line and
``audit_policy_catalog`` lists the tenant's version history in
ascending version order with counts and status only. All three entries
are storage-layer only and never change acceptance, status, execution,
receipts, anchors or inspection progress.
"""

import json
import os
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from forgetting_evidence.requests import (
    PolicyCatalogConflict,
    PolicyCatalogNotFound,
    RequestStore,
)

_FAILURE = "policy_catalog_failed"


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
    assert text.endswith("\n")
    assert text.count("\n") == 1
    assert text == json.dumps(
        json.loads(text), ensure_ascii=False, separators=(",", ":")
    ) + "\n"
    return json.loads(text)


class PolicyCatalogTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "evidence.db")
        self.store = RequestStore(self.db_path)
        self.rules = {
            "p-default": _rule("*", 30, "default retention"),
        }
        self.exceptions = {
            "x-1": _exception("subject-1", "users*", 90, "legal hold"),
        }

    def tearDown(self):
        self._tmp.cleanup()

    def _publish(self, tenant="tenant-a", rules=None, exceptions=None):
        return self.store.publish_policy_catalog(
            tenant,
            self.rules if rules is None else rules,
            self.exceptions if exceptions is None else exceptions,
        )

    def _assert_rfc3339(self, value):
        self.assertIsInstance(value, str)
        self.assertTrue(value.endswith("Z"))
        datetime.fromisoformat(value[:-1] + "+00:00")

    # -- first publication ---------------------------------------------

    def test_first_publication_is_version_one(self):
        result = self._publish()
        self.assertEqual(list(result), ["version", "effective_at"])
        self.assertEqual(result["version"], 1)
        self._assert_rfc3339(result["effective_at"])

    def test_normalization_keeps_priority_and_order(self):
        rules = {
            "p-z": _rule("users:b", 90),
            "p-a": _rule("users*", 60),
            "p-default": _rule("*", 30, "def"),
        }
        exceptions = {
            "x-z": _exception("subject-1", "*", 5),
            "x-a": _exception("subject-2", "users:a", 7),
        }
        self._publish(
            rules=dict(reversed(list(rules.items()))),
            exceptions=dict(reversed(list(exceptions.items()))),
        )
        doc = _parse(self.store.read_policy_catalog("tenant-a"))
        self.assertEqual(
            list(doc), ["version", "effective_at", "rules", "exceptions"]
        )
        self.assertEqual(doc["version"], 1)
        self.assertEqual([r["policy_id"] for r in doc["rules"]],
                         ["p-a", "p-default", "p-z"])
        for rule in doc["rules"]:
            self.assertEqual(
                list(rule), ["policy_id", "selector", "days", "reason"]
            )
        self.assertEqual(
            [e["policy_id"] for e in doc["exceptions"]], ["x-a", "x-z"]
        )
        for exception in doc["exceptions"]:
            self.assertEqual(
                list(exception),
                ["policy_id", "subject", "selector", "days", "reason"],
            )

    def test_empty_exception_catalog_serializes_as_empty_array(self):
        self._publish(exceptions={})
        doc = _parse(self.store.read_policy_catalog("tenant-a"))
        self.assertEqual(doc["exceptions"], [])

    def test_reason_text_and_zero_days_survive_verbatim(self):
        rules = {"p-default": _rule("*", 0, "理由：零日保留 ✓")}
        self._publish(rules=rules)
        doc = _parse(self.store.read_policy_catalog("tenant-a"))
        self.assertEqual(doc["rules"][0]["days"], 0)
        self.assertEqual(doc["rules"][0]["reason"], "理由：零日保留 ✓")

    # -- idempotent republish and sequencing ---------------------------

    def test_same_normalized_catalog_reuses_first_version(self):
        first = self._publish()
        second = self._publish(
            rules=dict(reversed(list(self.rules.items()))),
            exceptions={"x-1": dict(self.exceptions["x-1"])},
        )
        self.assertEqual(second, first)
        self._assert_version_count("tenant-a", 1)

    def test_different_catalog_issues_next_integer_version(self):
        first = self._publish()
        changed = {"p-default": _rule("*", 7, "shorter")}
        second = self._publish(rules=changed, exceptions={})
        self.assertEqual(second["version"], 2)
        self.assertNotEqual(second["effective_at"], first["effective_at"])
        self._assert_version_count("tenant-a", 2)

    def test_republishing_old_catalog_after_newer_reuses_old_version(self):
        first = self._publish(exceptions={})
        second = self._publish(
            rules={"p-default": _rule("*", 7, "shorter")}, exceptions={}
        )
        again = self._publish(exceptions={})
        self.assertEqual(again, first)
        self.assertNotEqual(again, second)
        self._assert_version_count("tenant-a", 2)

    def test_exception_change_alone_is_a_new_version(self):
        first = self._publish()
        second = self._publish(
            exceptions={"x-1": _exception("subject-1", "users*", 91, "hold")}
        )
        self.assertEqual(second["version"], 2)

    def test_versions_are_independent_per_tenant(self):
        a = self._publish(tenant="tenant-a")
        b = self._publish(
            tenant="tenant-b",
            rules={"p-default": _rule("*", 7, "other")},
            exceptions={},
        )
        self.assertEqual(a["version"], 1)
        self.assertEqual(b["version"], 1)
        self.assertNotEqual(a["effective_at"], b["effective_at"])

    def test_versions_are_read_only_via_store_api(self):
        first = self._publish()
        self._publish(rules={"p-default": _rule("*", 5, "five")}, exceptions={})
        # Re-reading the first version always yields the frozen first
        # snapshot; the store exposes no update entry point.
        doc = _parse(self.store.read_policy_catalog("tenant-a", 1))
        self.assertEqual(doc["version"], 1)
        self.assertEqual(doc["effective_at"], first["effective_at"])
        self.assertEqual(doc["rules"][0]["days"], 30)

    # -- reads ----------------------------------------------------------

    def test_read_omitted_version_uses_latest(self):
        self._publish(exceptions={})
        self._publish(
            rules={"p-default": _rule("*", 9, "nine")}, exceptions={}
        )
        doc = _parse(self.store.read_policy_catalog("tenant-a"))
        self.assertEqual(doc["version"], 2)
        self.assertEqual(doc["rules"][0]["days"], 9)

    def test_read_named_version_returns_that_snapshot(self):
        first = self._publish()
        self._publish(
            rules={"p-default": _rule("*", 9, "nine")}, exceptions={}
        )
        doc = _parse(self.store.read_policy_catalog("tenant-a", 1))
        self.assertEqual(doc["version"], 1)
        self.assertEqual(doc["effective_at"], first["effective_at"])
        self.assertEqual(doc["rules"][0]["days"], 30)
        self.assertEqual(len(doc["exceptions"]), 1)

    def test_unknown_and_cross_tenant_versions_are_indistinguishable(self):
        self._publish()
        for tenant, version in [
            ("tenant-a", 9),
            ("tenant-b", 1),
            ("never-seen", None),
            ("never-seen", 1),
        ]:
            with self.subTest(tenant=tenant, version=version):
                with self.assertRaises(PolicyCatalogNotFound) as caught:
                    self.store.read_policy_catalog(tenant, version)
                self.assertEqual(str(caught.exception), _FAILURE)

    # -- audit ----------------------------------------------------------

    def test_audit_orders_versions_ascending_with_summary_only(self):
        for index in range(1, 4):
            self._publish(
                rules={"p-default": _rule("*", index, f"r{index}")},
                exceptions={} if index % 2 else {"x": _exception("s", "*", 1)},
            )
        payload = _parse(self.store.audit_policy_catalog("tenant-a"))
        self.assertEqual(list(payload), ["versions"])
        entries = payload["versions"]
        self.assertEqual([e["version"] for e in entries], [1, 2, 3])
        self.assertEqual(
            [e["exception_count"] for e in entries], [0, 1, 0]
        )
        self.assertEqual([e["rule_count"] for e in entries], [1, 1, 1])
        self.assertEqual(
            [e["status"] for e in entries], [False, False, True]
        )
        for entry in entries:
            self.assertEqual(
                list(entry),
                [
                    "version",
                    "effective_at",
                    "rule_count",
                    "exception_count",
                    "status",
                ],
            )
            self._assert_rfc3339(entry["effective_at"])
            self.assertIsInstance(entry["rule_count"], int)
            self.assertIsInstance(entry["exception_count"], int)
            self.assertIsInstance(entry["status"], bool)
            self.assertNotIn("subject", entry)

    def test_audit_is_scoped_to_tenant(self):
        self._publish(tenant="tenant-a")
        self._publish(
            tenant="tenant-b",
            rules={"p-default": _rule("*", 1, "b")},
            exceptions={},
        )
        payload = _parse(self.store.audit_policy_catalog("tenant-a"))
        self.assertEqual([e["version"] for e in payload["versions"]], [1])

    def test_audit_for_tenant_without_publications_is_empty(self):
        self.assertEqual(
            _parse(self.store.audit_policy_catalog("never-seen")),
            {"versions": []},
        )

    # -- validation -----------------------------------------------------

    def test_blank_tenant_rejected_at_every_entry(self):
        for bad in [None, "", "   ", "\t\n", 7, True, b"v", ["v"]]:
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(ValueError) as caught:
                    self.store.publish_policy_catalog(bad, self.rules, {})
                self.assertEqual(str(caught.exception), _FAILURE)
                with self.assertRaises(ValueError):
                    self.store.read_policy_catalog(bad, 1)
                with self.assertRaises(ValueError):
                    self.store.read_policy_catalog(bad)
                with self.assertRaises(ValueError):
                    self.store.audit_policy_catalog(bad)

    def test_non_mapping_catalogs_rejected(self):
        for bad in [None, [], "rules", 7, True, [("p", _rule("*", 1))]]:
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(ValueError) as caught:
                    self.store.publish_policy_catalog("tenant-a", bad, {})
                self.assertEqual(str(caught.exception), _FAILURE)
                with self.assertRaises(ValueError) as caught:
                    self.store.publish_policy_catalog(
                        "tenant-a", self.rules, bad
                    )
                self.assertEqual(str(caught.exception), _FAILURE)

    def test_missing_default_rule_rejected(self):
        with self.assertRaises(ValueError) as caught:
            self._publish(rules={"p-1": _rule("users*", 10)}, exceptions={})
        self.assertEqual(str(caught.exception), _FAILURE)

    def test_duplicate_policy_number_across_catalogs_rejected(self):
        with self.assertRaises(ValueError):
            self._publish(
                exceptions={"p-default": _exception("s", "*", 1)}
            )

    def test_out_of_domain_days_rejected(self):
        for bad_days in [-1, 1.5, "30", True, False, None]:
            with self.subTest(bad_days=repr(bad_days)):
                with self.assertRaises(ValueError):
                    self._publish(rules={"p": _rule("*", bad_days)})
                with self.assertRaises(ValueError):
                    self._publish(
                        exceptions={
                            "x-1": _exception("subject-1", "*", bad_days)
                        }
                    )

    def test_illegal_version_selector_rejected(self):
        self._publish()
        for bad in [0, -1, 1.0, True, False, "1", "x", [], 1.5]:
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(ValueError) as caught:
                    self.store.read_policy_catalog("tenant-a", bad)
                self.assertEqual(str(caught.exception), _FAILURE)

    def test_validation_failures_write_nothing(self):
        bad_calls = [
            lambda: self.store.publish_policy_catalog(None, self.rules, {}),
            lambda: self.store.publish_policy_catalog(
                "  ", self.rules, {}
            ),
            lambda: self.store.publish_policy_catalog("tenant-a", {}, {}),
            lambda: self.store.publish_policy_catalog(
                "tenant-a", self.rules, None
            ),
            lambda: self.store.publish_policy_catalog(
                "tenant-a", {"p": _rule("*", True, "r")}, {}
            ),
            lambda: self.store.publish_policy_catalog(
                "tenant-a",
                self.rules,
                {"p-default": _exception("s", "*", 1, "r")},
            ),
        ]
        with sqlite3.connect(self.db_path) as conn:
            before = conn.execute(
                "SELECT count(*) FROM policy_catalog_versions"
            ).fetchone()
        for call in bad_calls:
            with self.assertRaises(ValueError):
                call()
        with sqlite3.connect(self.db_path) as conn:
            after = conn.execute(
                "SELECT count(*) FROM policy_catalog_versions"
            ).fetchone()
        self.assertEqual(before, after)

    # -- storage failures and atomicity --------------------------------

    def test_corrupt_content_raises_fixed_text_oserror(self):
        self._publish()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE policy_catalog_rules SET days = 999 WHERE version = 1"
            )
            conn.commit()
        for call in (
            lambda: self.store.read_policy_catalog("tenant-a", 1),
            lambda: self.store.audit_policy_catalog("tenant-a"),
        ):
            with self.assertRaises(OSError) as caught:
                call()
            self.assertEqual(str(caught.exception), _FAILURE)

    def test_corrupt_fingerprint_raises_oserror(self):
        self._publish()
        with sqlite3.connect(self.db_path) as conn:
            fingerprint = conn.execute(
                "SELECT content_fingerprint FROM policy_catalog_versions"
            ).fetchone()[0]
            replacement = fingerprint[:-1] + (
                "1" if fingerprint[-1] != "1" else "2"
            )
            conn.execute(
                "UPDATE policy_catalog_versions SET content_fingerprint = ?",
                (replacement,),
            )
            conn.commit()
        with self.assertRaises(OSError) as caught:
            self.store.read_policy_catalog("tenant-a")
        self.assertEqual(str(caught.exception), _FAILURE)

    def test_orphan_rule_row_is_corruption(self):
        self._publish(exceptions={})
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO policy_catalog_rules VALUES "
                "('tenant-a', 9, 1, 'p-z', '*', 5, 'zombie')"
            )
            conn.commit()
        with self.assertRaises(OSError) as caught:
            self.store.audit_policy_catalog("tenant-a")
        self.assertEqual(str(caught.exception), _FAILURE)

    def test_half_written_version_never_visible(self):
        self._publish()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DROP TABLE policy_catalog_rules")
            conn.commit()
        with self.assertRaises(OSError) as caught:
            self.store.publish_policy_catalog(
                "tenant-a",
                {"p-default": _rule("*", 3, "r3")},
                {},
            )
        self.assertEqual(str(caught.exception), _FAILURE)
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT version FROM policy_catalog_versions "
                "WHERE tenant_id = 'tenant-a' ORDER BY version"
            ).fetchall()
        self.assertEqual(rows, [(1,)])

    def test_failed_publish_conflict_leaves_winner_untouched(self):
        winner = self._publish(exceptions={})
        changed = {"p-default": _rule("*", 99, "other")}

        def publish(index):
            try:
                return self.store.publish_policy_catalog(
                    "tenant-a", changed if index else self.rules, {}
                )
            except PolicyCatalogConflict:
                return None

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(publish, range(16)))
        successes = [r for r in results if r is not None]
        self.assertTrue(successes)
        self.assertTrue(any(r is None for r in results))
        # Only v1 (the identical replays) can succeed concurrently with
        # a conflicting first publication.
        self.assertTrue(all(r == winner for r in successes))
        self._assert_version_count("tenant-a", 1)

    # -- concurrency ----------------------------------------------------

    def test_concurrent_identical_publish_lands_once(self):
        with ThreadPoolExecutor(max_workers=12) as pool:
            results = list(
                pool.map(
                    lambda _: self.store.publish_policy_catalog(
                        "tenant-a", self.rules, {}
                    ),
                    range(24),
                )
            )
        self.assertTrue(all(result == results[0] for result in results))
        self.assertEqual(results[0]["version"], 1)
        self._assert_version_count("tenant-a", 1)

    def test_concurrent_identical_publish_across_instances_lands_once(self):
        stores = [RequestStore(self.db_path) for _ in range(8)]
        barrier = threading.Barrier(8)

        def publish(index):
            barrier.wait()
            return stores[index].publish_policy_catalog(
                "tenant-x", self.rules, {}
            )

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(publish, range(8)))
        self.assertEqual(
            {(r["version"], r["effective_at"]) for r in results},
            {(results[0]["version"], results[0]["effective_at"])},
        )
        self._assert_version_count("tenant-x", 1)

    def test_concurrent_different_publish_has_single_winner(self):
        barrier = threading.Barrier(12)

        def publish(index):
            barrier.wait()
            try:
                return (
                    "ok",
                    self.store.publish_policy_catalog(
                        "tenant-c",
                        {"p-default": _rule("*", 100 + index, f"r{index}")},
                        {},
                    ),
                )
            except PolicyCatalogConflict:
                return ("conflict", None)

        with ThreadPoolExecutor(max_workers=12) as pool:
            outcomes = list(pool.map(publish, range(12)))
        winners = [outcome for outcome in outcomes if outcome[0] == "ok"]
        self.assertEqual(len(winners), 1)
        self.assertEqual(
            len([o for o in outcomes if o[0] == "conflict"]), 11
        )
        self._assert_version_count("tenant-c", 1)

    def test_concurrent_different_publish_across_instances_single_winner(self):
        stores = [RequestStore(self.db_path) for _ in range(10)]
        barrier = threading.Barrier(10)

        def publish(index):
            barrier.wait()
            try:
                stores[index].publish_policy_catalog(
                    "tenant-y",
                    {"p-default": _rule("*", 1000 + index, f"r{index}")},
                    {},
                )
            except PolicyCatalogConflict:
                pass

        with ThreadPoolExecutor(max_workers=10) as pool:
            list(pool.map(publish, range(10)))
        self._assert_version_count("tenant-y", 1)

    # -- stability, read-only and isolation -----------------------------

    def test_rebuild_preserves_versions(self):
        first = self._publish()
        self._publish(rules={"p-default": _rule("*", 5, "five")}, exceptions={})
        rebuilt = RequestStore(self.db_path)
        self.assertEqual(
            _parse(rebuilt.read_policy_catalog("tenant-a", 1))["effective_at"],
            first["effective_at"],
        )
        self.assertEqual(
            [
                e["version"]
                for e in _parse(rebuilt.audit_policy_catalog("tenant-a"))[
                    "versions"
                ]
            ],
            [1, 2],
        )

    def test_reads_and_audit_write_nothing(self):
        self.store.submit("tenant-a", "subject-1", ["users:a"], "key-1")
        self._publish()
        tables = (
            "policy_catalog_versions",
            "policy_catalog_rules",
            "policy_catalog_exceptions",
            "requests",
            "status_events",
            "deletion_receipts",
            "audit_anchors",
        )
        with sqlite3.connect(self.db_path) as conn:
            before = {
                table: conn.execute(
                    f"SELECT count(*) FROM {table}"
                ).fetchone()[0]
                for table in tables
            }
        for _ in range(3):
            self.store.read_policy_catalog("tenant-a")
            self.store.read_policy_catalog("tenant-a", 1)
            self.store.audit_policy_catalog("tenant-a")
            try:
                self.store.read_policy_catalog("other")
            except PolicyCatalogNotFound:
                pass
        with sqlite3.connect(self.db_path) as conn:
            after = {
                table: conn.execute(
                    f"SELECT count(*) FROM {table}"
                ).fetchone()[0]
                for table in tables
            }
        self.assertEqual(before, after)

    def test_published_catalog_is_usable_by_retention_resolution(self):
        self._publish()
        doc = _parse(self.store.read_policy_catalog("tenant-a"))
        rules = {
            rule["policy_id"]: {
                "selector": rule["selector"],
                "days": rule["days"],
                "reason": rule["reason"],
            }
            for rule in doc["rules"]
        }
        exceptions = {
            exception["policy_id"]: {
                "subject": exception["subject"],
                "selector": exception["selector"],
                "days": exception["days"],
                "reason": exception["reason"],
            }
            for exception in doc["exceptions"]
        }
        resolved = self.store.resolve_retention(
            "tenant-a",
            "subject-1",
            ["users:alice"],
            rules,
            exceptions,
        )
        self.assertEqual(resolved["retention_days"], 90)
        self.assertEqual(resolved["policy_id"], "x-1")

    def test_publication_independent_of_publish_order_for_resolution(self):
        rules_a = {"p-default": _rule("*", 30, "def")}
        rules_b = {
            "p-default": _rule("*", 30, "def"),
            "p-users": _rule("users*", 60, "grp"),
        }
        self.store.publish_policy_catalog("tenant-a", rules_a, {})
        self.store.publish_policy_catalog("tenant-a", rules_b, {})
        doc = _parse(self.store.read_policy_catalog("tenant-a", 2))
        rules = {
            rule["policy_id"]: {
                "selector": rule["selector"],
                "days": rule["days"],
                "reason": rule["reason"],
            }
            for rule in doc["rules"]
        }
        resolved = self.store.resolve_retention(
            "tenant-a", "subject-1", ["users:a"], rules, {}
        )
        self.assertEqual(resolved["retention_days"], 60)

    # -- in-memory store ------------------------------------------------

    def test_in_memory_store_full_cycle(self):
        store = RequestStore(":memory:")
        first = store.publish_policy_catalog("t", self.rules, {})
        self.assertEqual(first["version"], 1)
        again = store.publish_policy_catalog("t", self.rules, {})
        self.assertEqual(again, first)
        second = store.publish_policy_catalog(
            "t", {"p-default": _rule("*", 2, "two")}, {}
        )
        self.assertEqual(second["version"], 2)
        self.assertEqual(
            _parse(store.read_policy_catalog("t"))["version"], 2
        )
        self.assertEqual(
            [e["version"] for e in _parse(store.audit_policy_catalog("t"))["versions"]],
            [1, 2],
        )

    # -- helpers --------------------------------------------------------

    def _assert_version_count(self, tenant, count):
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT count(*) FROM policy_catalog_versions "
                "WHERE tenant_id = ?",
                (tenant,),
            ).fetchone()[0]
            rule_rows = conn.execute(
                "SELECT count(*) FROM policy_catalog_rules WHERE tenant_id = ?",
                (tenant,),
            ).fetchone()[0]
        self.assertEqual(rows, count)
        # Every version carries at least the default rule.
        self.assertGreaterEqual(rule_rows, count)


if __name__ == "__main__":
    unittest.main()
