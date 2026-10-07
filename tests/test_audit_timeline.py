"""Storage-layer tests for the read-only request status timeline.

``RequestStore.get_audit_timeline`` backs the
``GET /requests/{request_id}/audit-timeline`` HTTP endpoint. It reads
the current status and the ordered state-event timeline from one committed
snapshot and only renders once that history is whole: a damaged event,
rewound timestamp, replaced head or split current status raises the
fixed-text storage error, never a partial or fabricated timeline.
"""

import os
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor

from forgetting_evidence.requests import (
    InvalidStatusTransition,
    RequestNotFound,
    RequestStore,
)

_STORAGE_MESSAGE = "request store is unavailable"


class AuditTimelineStoreTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "evidence.db")

    def tearDown(self):
        self._tmp.cleanup()

    def _store(self):
        return RequestStore(self.db_path)

    def _lifecycle(self, store, statuses=("processing", "completed"), key="key-1"):
        receipt = store.submit("tenant-a", "subject-1", ["email"], key)
        rid = receipt["request_id"]
        for target in statuses:
            store.transition("tenant-a", rid, target)
        return receipt

    def _raw(self):
        return sqlite3.connect(self.db_path)

    def _tamper(self, sql, params=()):
        with self._raw() as conn:
            conn.execute(sql, params)

    # -- success shape --------------------------------------------------

    def test_accepted_request_timeline_shape(self):
        store = self._store()
        receipt = self._lifecycle(store, ())
        rid = receipt["request_id"]
        timeline = store.get_audit_timeline("tenant-a", rid)
        self.assertEqual(set(timeline), {"request_id", "events"})
        self.assertEqual(timeline["request_id"], rid)
        events = timeline["events"]
        self.assertEqual(
            events,
            [{"status": "accepted", "occurred_at": receipt["created_at"]}],
        )
        self.assertEqual(set(events[0]), {"status", "occurred_at"})

    def test_completed_lifecycle_order_and_fields(self):
        store = self._store()
        receipt = self._lifecycle(store)
        rid = receipt["request_id"]
        timeline = store.get_audit_timeline("tenant-a", rid)
        self.assertEqual([e["status"] for e in timeline["events"]],
                         ["accepted", "processing", "completed"])
        for event in timeline["events"]:
            self.assertEqual(set(event), {"status", "occurred_at"})
            self.assertIn(event["status"],
                          {"accepted", "processing", "completed", "failed"})
            # Canonical UTC RFC3339 with six-digit fraction and Z.
            self.assertRegex(
                event["occurred_at"],
                r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$",
            )
        stamps = [e["occurred_at"] for e in timeline["events"]]
        self.assertEqual(stamps, sorted(stamps))
        self.assertEqual(
            timeline["events"][-1]["status"],
            store.get_status("tenant-a", rid)["status"],
        )

    def test_accepted_to_failed_timeline(self):
        store = self._store()
        receipt = self._lifecycle(store, ("failed",))
        timeline = store.get_audit_timeline("tenant-a", receipt["request_id"])
        self.assertEqual([e["status"] for e in timeline["events"]],
                         ["accepted", "failed"])

    def test_idempotent_replays_append_no_event(self):
        store = self._store()
        receipt = self._lifecycle(
            store, ("accepted", "processing", "processing",
                    "completed", "completed")
        )
        timeline = store.get_audit_timeline("tenant-a", receipt["request_id"])
        self.assertEqual([e["status"] for e in timeline["events"]],
                         ["accepted", "processing", "completed"])

    def test_matches_audit_on_intact_history(self):
        store = self._store()
        receipt = self._lifecycle(store, ("processing", "failed"))
        rid = receipt["request_id"]
        timeline = store.get_audit_timeline("tenant-a", rid)
        self.assertEqual(timeline["events"], store.audit("tenant-a", rid))

    def test_timelines_are_partitioned(self):
        store = self._store()
        one = self._lifecycle(store, ("failed",), key="key-1")
        two = self._lifecycle(store, ("processing",), key="key-2")
        self.assertEqual(
            [e["status"] for e
             in store.get_audit_timeline("tenant-a", one["request_id"])["events"]],
            ["accepted", "failed"],
        )
        self.assertEqual(
            [e["status"] for e
             in store.get_audit_timeline("tenant-a", two["request_id"])["events"]],
            ["accepted", "processing"],
        )

    def test_in_memory_store_timeline(self):
        store = RequestStore(":memory:")
        receipt = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        store.transition("tenant-a", receipt["request_id"], "processing")
        timeline = store.get_audit_timeline("tenant-a", receipt["request_id"])
        self.assertEqual([e["status"] for e in timeline["events"]],
                         ["accepted", "processing"])
        with self.assertRaises(RequestNotFound):
            store.get_audit_timeline("tenant-b", receipt["request_id"])

    # -- error semantics -----------------------------------------------

    def test_unknown_malformed_and_cross_tenant_ids_raise_not_found(self):
        store = self._store()
        receipt = self._lifecycle(store, ())
        rid = receipt["request_id"]
        for tenant, request_id in (
            ("tenant-a", "00000000-0000-4000-8000-000000000000"),
            ("tenant-a", "not-a-uuid"),
            ("tenant-a", ""),
            ("tenant-a", None),
            ("tenant-b", rid),
        ):
            with self.subTest(tenant=tenant, request_id=request_id):
                with self.assertRaises(RequestNotFound):
                    store.get_audit_timeline(tenant, request_id)

    def test_tenant_validation_raises_value_error(self):
        store = self._store()
        receipt = self._lifecycle(store, ())
        for tenant in ("", None, 7):
            with self.subTest(tenant=tenant):
                with self.assertRaises(ValueError):
                    store.get_audit_timeline(tenant, receipt["request_id"])

    def test_unreadable_database_is_fixed_storage_error(self):
        store = self._store()
        receipt = self._lifecycle(store, ("processing",))
        with open(self.db_path, "wb") as handle:
            handle.write(b"not a sqlite database")
        with self.assertRaises(OSError) as ctx:
            store.get_audit_timeline("tenant-a", receipt["request_id"])
        self.assertEqual(str(ctx.exception), _STORAGE_MESSAGE)

    # -- corruption never renders a half or forged timeline --------------

    def _assert_storage_failure(self, store, rid):
        with self.assertRaises(OSError) as ctx:
            store.get_audit_timeline("tenant-a", rid)
        self.assertEqual(str(ctx.exception), _STORAGE_MESSAGE)

    def test_deleted_genesis_event_is_storage_failure(self):
        store = self._store()
        receipt = self._lifecycle(store, ("processing", "completed"))
        rid = receipt["request_id"]
        self._tamper(
            "DELETE FROM status_events WHERE request_id = ? AND seq = 0", (rid,)
        )
        self._assert_storage_failure(store, rid)

    def test_all_events_deleted_is_storage_failure(self):
        store = self._store()
        receipt = self._lifecycle(store, ())
        rid = receipt["request_id"]
        self._tamper("DELETE FROM status_events WHERE request_id = ?", (rid,))
        self._assert_storage_failure(store, rid)

    def test_altered_event_status_is_storage_failure(self):
        store = self._store()
        receipt = self._lifecycle(store, ("processing", "completed"))
        rid = receipt["request_id"]
        self._tamper(
            "UPDATE status_events SET status = 'failed' "
            "WHERE request_id = ? AND seq = 1",
            (rid,),
        )
        self._assert_storage_failure(store, rid)

    def test_foreign_status_text_is_storage_failure(self):
        store = self._store()
        receipt = self._lifecycle(store, ("processing",))
        rid = receipt["request_id"]
        self._tamper(
            "UPDATE status_events SET status = 'cancelled' "
            "WHERE request_id = ? AND seq = 1",
            (rid,),
        )
        self._assert_storage_failure(store, rid)

    def test_forged_event_hash_is_storage_failure(self):
        store = self._store()
        receipt = self._lifecycle(store, ("processing",))
        rid = receipt["request_id"]
        self._tamper(
            "UPDATE status_events SET chain_hash = ? "
            "WHERE request_id = ? AND seq = 0",
            ("a" * 64, rid),
        )
        self._assert_storage_failure(store, rid)

    def test_seq_gap_is_storage_failure(self):
        store = self._store()
        receipt = self._lifecycle(store, ("processing", "completed"))
        rid = receipt["request_id"]
        self._tamper(
            "UPDATE status_events SET seq = 4 "
            "WHERE request_id = ? AND seq = 1",
            (rid,),
        )
        self._assert_storage_failure(store, rid)

    def test_inserted_event_with_repeated_status_is_storage_failure(self):
        store = self._store()
        receipt = self._lifecycle(store, ("processing",))
        rid = receipt["request_id"]
        events = store.audit("tenant-a", rid)
        # An appended processing event repeats the current status; the
        # writer never does this, so an in-band row like this means
        # out-of-band alteration.
        self._tamper(
            "INSERT INTO status_events "
            "(tenant_id, request_id, seq, status, occurred_at, chain_hash) "
            "VALUES ('tenant-a', ?, 2, 'processing', ?, ?)",
            (rid, events[-1]["occurred_at"], "0" * 64),
        )
        self._assert_storage_failure(store, rid)

    def test_rewound_timestamp_is_storage_failure(self):
        store = self._store()
        receipt = self._lifecycle(store, ("processing", "completed"))
        rid = receipt["request_id"]
        self._tamper(
            "UPDATE status_events SET occurred_at = '2000-01-01T00:00:00.000000Z' "
            "WHERE request_id = ? AND seq = 1",
            (rid,),
        )
        self._assert_storage_failure(store, rid)

    def test_malformed_timestamp_is_storage_failure(self):
        store = self._store()
        receipt = self._lifecycle(store, ("processing",))
        rid = receipt["request_id"]
        self._tamper(
            "UPDATE status_events SET occurred_at = '2026-01-01 00:00:00' "
            "WHERE request_id = ? AND seq = 1",
            (rid,),
        )
        self._assert_storage_failure(store, rid)

    def test_replaced_head_is_storage_failure(self):
        store = self._store()
        receipt = self._lifecycle(store, ("processing", "completed"))
        rid = receipt["request_id"]
        self._tamper(
            "UPDATE requests SET chain_hash = ? WHERE request_id = ?",
            ("a" * 64, rid),
        )
        self._assert_storage_failure(store, rid)

    def test_split_current_status_is_storage_failure(self):
        store = self._store()
        receipt = self._lifecycle(store, ("processing", "completed"))
        rid = receipt["request_id"]
        self._tamper(
            "UPDATE requests SET status = 'failed' WHERE request_id = ?", (rid,)
        )
        self._assert_storage_failure(store, rid)

    def test_cross_request_rebound_event_is_storage_failure(self):
        store = self._store()
        one = self._lifecycle(store, ("processing",), key="key-1")
        two = store.submit("tenant-a", "subject-2", ["email"], "key-2")
        store.transition("tenant-a", two["request_id"], "processing")
        with self._raw() as conn:
            forgery = conn.execute(
                "SELECT status, occurred_at, chain_hash FROM status_events "
                "WHERE request_id = ? AND seq = 0",
                (two["request_id"],),
            ).fetchone()
            conn.execute(
                "UPDATE status_events SET status = ?, occurred_at = ?, "
                "chain_hash = ? WHERE request_id = ? AND seq = 0",
                (*forgery, one["request_id"]),
            )
        self._assert_storage_failure(store, one["request_id"])

    # -- read-only, stability and concurrency ---------------------------

    def test_repeated_reads_do_not_write(self):
        store = self._store()
        receipt = self._lifecycle(store, ("processing", "failed"))
        rid = receipt["request_id"]
        first = store.get_audit_timeline("tenant-a", rid)
        with open(self.db_path, "rb") as handle:
            before = handle.read()
        for _ in range(5):
            again = store.get_audit_timeline("tenant-a", rid)
            self.assertEqual(again, first)
        with open(self.db_path, "rb") as handle:
            after = handle.read()
        self.assertEqual(before, after)

    def test_timeline_stable_across_rebuild(self):
        first = self._store()
        receipt = self._lifecycle(first, ("processing", "completed"))
        rid = receipt["request_id"]
        expected = first.get_audit_timeline("tenant-a", rid)
        rebuilt = self._store()
        self.assertEqual(
            rebuilt.get_audit_timeline("tenant-a", rid), expected
        )
        self.assertEqual(
            [e["occurred_at"] for e
             in rebuilt.get_audit_timeline("tenant-a", rid)["events"]],
            [e["occurred_at"] for e in expected["events"]],
        )

    def test_timeline_creates_no_other_records(self):
        store = self._store()
        receipt = self._lifecycle(store, ("processing", "completed"))
        rid = receipt["request_id"]
        with self._raw() as conn:
            anchor_count = conn.execute(
                "SELECT count(*) FROM audit_anchors WHERE request_id = ?",
                (rid,),
            ).fetchone()[0]
            event_count = conn.execute(
                "SELECT count(*) FROM status_events WHERE request_id = ?",
                (rid,),
            ).fetchone()[0]
        self.assertEqual(event_count, 3)
        for _ in range(3):
            self.assertEqual(store.get_audit_timeline("tenant-a", rid)["request_id"], rid)
        with self._raw() as conn:
            self.assertEqual(
                conn.execute(
                    "SELECT count(*) FROM claim_attempts WHERE request_id = ?",
                    (rid,),
                ).fetchone()[0],
                0,
            )
            self.assertEqual(
                conn.execute(
                    "SELECT count(*) FROM deletion_tombstones WHERE request_id = ?",
                    (rid,),
                ).fetchone()[0],
                0,
            )
            self.assertEqual(
                conn.execute(
                    "SELECT count(*) FROM deletion_receipts WHERE request_id = ?",
                    (rid,),
                ).fetchone()[0],
                0,
            )
            # The read adds neither state events nor audit anchors.
            self.assertEqual(
                conn.execute(
                    "SELECT count(*) FROM audit_anchors WHERE request_id = ?",
                    (rid,),
                ).fetchone()[0],
                anchor_count,
            )
            self.assertEqual(
                conn.execute(
                    "SELECT count(*) FROM status_events WHERE request_id = ?",
                    (rid,),
                ).fetchone()[0],
                event_count,
            )

    def test_concurrent_transitions_always_render_consistent_timeline(self):
        store = self._store()
        receipt = self._lifecycle(store, ())
        rid = receipt["request_id"]

        def move():
            for target in ("processing", "completed", "accepted",
                           "processing", "failed", "processing"):
                try:
                    store.transition("tenant-a", rid, target)
                except InvalidStatusTransition:
                    pass

        legal = {
            "accepted": {"processing", "failed"},
            "processing": {"completed", "failed"},
        }

        def read():
            # Each read is internally self-consistent: the store only
            # renders a snapshot whose final event equals that same
            # snapshot's current status. Comparing against a separate
            # get_status while writers move would compare two different
            # committed snapshots, so that cross-check happens only
            # after the writers finish.
            timeline = store.get_audit_timeline("tenant-a", rid)
            statuses = [e["status"] for e in timeline["events"]]
            self.assertEqual(statuses[0], "accepted")
            for prev, nxt in zip(statuses, statuses[1:]):
                self.assertIn(nxt, legal.get(prev, set()))
            stamps = [e["occurred_at"] for e in timeline["events"]]
            self.assertEqual(stamps, sorted(stamps))

        with ThreadPoolExecutor(max_workers=8) as pool:
            movers = [pool.submit(move) for _ in range(4)]
            readers = [pool.submit(read) for _ in range(4) for _ in range(25)]
            for future in movers + readers:
                future.result()
        # Once writers have quiesced the final event is the current
        # persisted status in the same snapshot.
        timeline = store.get_audit_timeline("tenant-a", rid)
        self.assertEqual(
            timeline["events"][-1]["status"],
            store.get_status("tenant-a", rid)["status"],
        )


if __name__ == "__main__":
    unittest.main()
