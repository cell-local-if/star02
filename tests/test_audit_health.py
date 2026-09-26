"""Tests for the instantaneous tenant-wide audit health snapshot.

Covers RequestStore.audit_health on the storage layer only: the fixed
plain-dict shape, the four-status distribution with explicit zeros,
verified/unverified counts that cover every request exactly once, the
merged Unicode-ordered reason list, agreement with the inspection
sweep's per-item verdicts, tamper and legacy/secret-missing reason
codes, validation without writes, the fixed-text OSError contract and
the strict read-only guarantee. This entry point is deliberately not
exposed over HTTP.
"""

import json
import os
import sqlite3
import tempfile
import unittest

from forgetting_evidence.requests import RequestStore


class _StoreCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "evidence.db")

    def tearDown(self):
        self._tmp.cleanup()

    def _store(self, secret="anchor-secret", history=None, path=None):
        return RequestStore(
            path or self.db_path, anchor_secret=secret, anchor_history_secrets=history
        )

    def _submit_many(self, store, count, tenant="tenant-a"):
        return [
            store.submit(tenant, f"subject-{i}", ["email"], f"key-{i}")["request_id"]
            for i in range(count)
        ]

    def _raw(self):
        return sqlite3.connect(self.db_path)


class HealthShapeTests(_StoreCase):
    def test_empty_tenant_reports_explicit_zeros(self):
        store = self._store()
        self.assertEqual(
            store.audit_health("tenant-a"),
            {
                "total": 0,
                "statuses": {
                    "accepted": 0,
                    "processing": 0,
                    "completed": 0,
                    "failed": 0,
                },
                "verified": 0,
                "unverified": 0,
                "reasons": [],
            },
        )

    def test_result_is_a_plain_dict_with_only_the_fixed_keys(self):
        store = self._store()
        self._submit_many(store, 1)
        snapshot = store.audit_health("tenant-a")
        self.assertIs(type(snapshot), dict)
        self.assertEqual(
            list(snapshot), ["total", "statuses", "verified", "unverified", "reasons"]
        )
        self.assertIs(type(snapshot["statuses"]), dict)
        self.assertEqual(
            list(snapshot["statuses"]),
            ["accepted", "processing", "completed", "failed"],
        )
        # Every count is a plain non-negative integer: never a float, a
        # boolean, a negative zero or a non-finite value.
        counts = [snapshot["total"], snapshot["verified"], snapshot["unverified"]]
        counts += list(snapshot["statuses"].values())
        for count in counts:
            self.assertIs(type(count), int)
            self.assertGreaterEqual(count, 0)
        json.dumps(snapshot)  # the snapshot stays machine-readable

    def test_status_distribution_covers_the_whole_lifecycle(self):
        store = self._store()
        ids = self._submit_many(store, 4)
        store.transition("tenant-a", ids[1], "processing")
        store.transition("tenant-a", ids[2], "processing")
        store.transition("tenant-a", ids[2], "completed")
        store.transition("tenant-a", ids[3], "failed")
        snapshot = store.audit_health("tenant-a")
        self.assertEqual(
            snapshot["statuses"],
            {"accepted": 1, "processing": 1, "completed": 1, "failed": 1},
        )
        self.assertEqual(snapshot["total"], 4)
        self.assertEqual(snapshot["total"], sum(snapshot["statuses"].values()))

    def test_healthy_tenant_is_fully_verified_with_no_reasons(self):
        store = self._store()
        self._submit_many(store, 3)
        snapshot = store.audit_health("tenant-a")
        self.assertEqual(snapshot["verified"], 3)
        self.assertEqual(snapshot["unverified"], 0)
        self.assertEqual(snapshot["reasons"], [])
        self.assertEqual(
            snapshot["total"], snapshot["verified"] + snapshot["unverified"]
        )

    def test_other_tenants_are_not_counted(self):
        store = self._store()
        self._submit_many(store, 2, tenant="tenant-a")
        self._submit_many(store, 3, tenant="tenant-b")
        snapshot = store.audit_health("tenant-a")
        self.assertEqual(snapshot["total"], 2)
        self.assertEqual(snapshot["verified"], 2)

    def test_repeated_reads_and_rebuilds_agree(self):
        store = self._store()
        self._submit_many(store, 3)
        first = store.audit_health("tenant-a")
        self.assertEqual(store.audit_health("tenant-a"), first)
        rebuilt = self._store()
        self.assertEqual(rebuilt.audit_health("tenant-a"), first)

    def test_in_memory_store_reports_health(self):
        store = RequestStore(":memory:", anchor_secret="anchor-secret")
        store.submit("tenant-a", "subject", ["email"], "key")
        snapshot = store.audit_health("tenant-a")
        self.assertEqual(snapshot["total"], 1)
        self.assertEqual(snapshot["verified"], 1)


class HealthEvidenceTests(_StoreCase):
    def test_tampered_event_marks_exactly_its_request_unverified(self):
        store = self._store()
        ids = self._submit_many(store, 3)
        with self._raw() as raw:
            raw.execute(
                "DELETE FROM status_events WHERE request_id = ? AND seq = 0",
                (ids[1],),
            )
        snapshot = store.audit_health("tenant-a")
        self.assertEqual(snapshot["verified"], 2)
        self.assertEqual(snapshot["unverified"], 1)
        self.assertEqual(len(snapshot["reasons"]), 1)
        reason = snapshot["reasons"][0]
        self.assertEqual(list(reason), ["reason", "count"])
        self.assertIs(type(reason["reason"]), str)
        self.assertTrue(reason["reason"])
        self.assertEqual(reason["count"], 1)

    def test_health_agrees_with_the_inspection_sweep(self):
        store = self._store()
        ids = self._submit_many(store, 4)
        with self._raw() as raw:
            raw.execute(
                "DELETE FROM status_events WHERE request_id = ? AND seq = 0",
                (ids[1],),
            )
            raw.execute(
                "UPDATE status_events SET status = 'failed' "
                "WHERE request_id = ? AND seq = 0",
                (ids[3],),
            )
        sweep = store.audit_inspection("tenant-a")
        snapshot = store.audit_health("tenant-a")
        items = sweep["items"]
        self.assertEqual(
            snapshot["verified"], sum(1 for item in items if item["verified"])
        )
        self.assertEqual(
            snapshot["unverified"], sum(1 for item in items if not item["verified"])
        )
        merged = {}
        for item in items:
            if not item["verified"]:
                merged[item["reason"]] = merged.get(item["reason"], 0) + 1
        self.assertEqual(
            snapshot["reasons"],
            [{"reason": reason, "count": merged[reason]} for reason in sorted(merged)],
        )

    def test_equal_reasons_merge_and_sort_by_code_point(self):
        store = self._store()
        ids = self._submit_many(store, 2)
        with self._raw() as raw:
            for request_id in ids:
                raw.execute(
                    "DELETE FROM status_events WHERE request_id = ? AND seq = 0",
                    (request_id,),
                )
        snapshot = store.audit_health("tenant-a")
        self.assertEqual(snapshot["unverified"], 2)
        self.assertEqual(len(snapshot["reasons"]), 1)
        self.assertEqual(snapshot["reasons"][0]["count"], 2)
        reasons = [entry["reason"] for entry in snapshot["reasons"]]
        self.assertEqual(reasons, sorted(reasons))

    def test_legacy_unanchored_database_is_untrusted(self):
        path = os.path.join(self._tmp.name, "legacy.db")
        store = self._store(secret=None, path=path)
        store.submit("tenant-a", "subject", ["email"], "key")
        snapshot = store.audit_health("tenant-a")
        self.assertEqual(snapshot["verified"], 0)
        self.assertEqual(
            snapshot["reasons"], [{"reason": "unanchored_database", "count": 1}]
        )

    def test_missing_secret_is_untrusted(self):
        store = self._store()
        self._submit_many(store, 1)
        snapshot = self._store(secret=None).audit_health("tenant-a")
        self.assertEqual(
            snapshot["reasons"], [{"reason": "anchor_secret_missing", "count": 1}]
        )

    def test_missing_historical_secret_is_untrusted(self):
        store = self._store(secret="old-secret")
        self._submit_many(store, 1)
        store.rotate_anchor_key("old-secret", "new-secret")
        snapshot = self._store(secret="new-secret").audit_health("tenant-a")
        self.assertEqual(
            snapshot["reasons"], [{"reason": "anchor_key_missing", "count": 1}]
        )
        healed = self._store(secret="new-secret", history={1: "old-secret"})
        self.assertEqual(healed.audit_health("tenant-a")["verified"], 1)


class HealthValidationTests(_StoreCase):
    def test_invalid_tenant_raises_value_error_without_writing(self):
        store = self._store()
        self._submit_many(store, 1)
        before = self._dump_all()
        for bad in ("", None, 0, 1.5, b"tenant", ["tenant"], {"t": 1}):
            with self.assertRaises(ValueError):
                store.audit_health(bad)
        self.assertEqual(self._dump_all(), before)

    def _dump_all(self):
        with self._raw() as raw:
            return {
                table: raw.execute(f"SELECT * FROM {table}").fetchall()
                for table in (
                    "requests",
                    "status_events",
                    "inspection_batches",
                    "inspection_batch_items",
                )
            }

    def test_corrupt_bookkeeping_raises_fixed_os_error(self):
        store = self._store()
        ids = self._submit_many(store, 1)
        with self._raw() as raw:
            raw.execute(
                "UPDATE requests SET status = 'bogus' WHERE request_id = ?",
                (ids[0],),
            )
        with self.assertRaises(OSError) as caught:
            store.audit_health("tenant-a")
        self.assertEqual(str(caught.exception), "audit_health_failed")

    def test_unreadable_storage_raises_fixed_os_error(self):
        store = self._store()
        os.remove(self.db_path)
        with self.assertRaises(OSError) as caught:
            store.audit_health("tenant-a")
        self.assertEqual(str(caught.exception), "audit_health_failed")

    def test_snapshot_is_strictly_read_only(self):
        store = self._store()
        self._submit_many(store, 2)
        before = self._dump_all()
        store.audit_health("tenant-a")
        store.audit_health("tenant-a")
        self.assertEqual(self._dump_all(), before)


if __name__ == "__main__":
    unittest.main()
