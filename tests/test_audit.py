import os
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from forgetting_evidence.requests import (
    InvalidStatusTransition,
    RequestNotFound,
    RequestStore,
)


def _parse_utc(value):
    # RFC 3339 with trailing Z.
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class AuditTimelineTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "evidence.db")

    def tearDown(self):
        self._tmp.cleanup()

    def _submit(self, store=None, tenant="tenant-a", key="key-1"):
        store = store if store is not None else RequestStore(self.db_path)
        return store.submit(tenant, "subject-1", ["email"], key)

    def test_submit_records_single_accepted_event(self):
        store = RequestStore(self.db_path)
        receipt = self._submit(store)
        events = store.audit("tenant-a", receipt["request_id"])
        self.assertEqual(
            events,
            [{"status": "accepted", "occurred_at": receipt["created_at"]}],
        )
        event = events[0]
        self.assertEqual(set(event), {"status", "occurred_at"})
        parsed = _parse_utc(event["occurred_at"])
        self.assertEqual(parsed.utcoffset().total_seconds(), 0)

    def test_each_actual_transition_appends_target_event(self):
        store = RequestStore(self.db_path)
        receipt = self._submit(store)
        store.transition("tenant-a", receipt["request_id"], "processing")
        store.transition("tenant-a", receipt["request_id"], "completed")
        events = store.audit("tenant-a", receipt["request_id"])
        self.assertEqual([e["status"] for e in events],
                         ["accepted", "processing", "completed"])
        self.assertEqual(events[-1]["status"],
                         store.get_status("tenant-a", receipt["request_id"])["status"])
        # The acceptance query stays frozen at accepted.
        self.assertEqual(
            store.get("tenant-a", receipt["request_id"])["status"], "accepted"
        )
        for event in events:
            self.assertEqual(set(event), {"status", "occurred_at"})

    def test_accepted_to_failed_timeline(self):
        store = RequestStore(self.db_path)
        receipt = self._submit(store)
        store.transition("tenant-a", receipt["request_id"], "failed")
        self.assertEqual(
            [e["status"] for e in store.audit("tenant-a", receipt["request_id"])],
            ["accepted", "failed"],
        )

    def test_timestamps_are_utc_rfc3339_and_non_decreasing(self):
        store = RequestStore(self.db_path)
        receipt = self._submit(store)
        store.transition("tenant-a", receipt["request_id"], "processing")
        store.transition("tenant-a", receipt["request_id"], "failed")
        stamps = [e["occurred_at"]
                  for e in store.audit("tenant-a", receipt["request_id"])]
        for stamp in stamps:
            parsed = _parse_utc(stamp)
            self.assertEqual(parsed.utcoffset().total_seconds(), 0)
        self.assertEqual(stamps, sorted(stamps))

    def test_same_status_transition_appends_no_event(self):
        store = RequestStore(self.db_path)
        receipt = self._submit(store)
        # Idempotent replays at every point in the lifecycle.
        store.transition("tenant-a", receipt["request_id"], "accepted")
        store.transition("tenant-a", receipt["request_id"], "processing")
        store.transition("tenant-a", receipt["request_id"], "processing")
        store.transition("tenant-a", receipt["request_id"], "completed")
        store.transition("tenant-a", receipt["request_id"], "completed")
        self.assertEqual(
            [e["status"] for e in store.audit("tenant-a", receipt["request_id"])],
            ["accepted", "processing", "completed"],
        )

    def test_illegal_and_unknown_transitions_append_no_event(self):
        store = RequestStore(self.db_path)
        receipt = self._submit(store)
        with self.assertRaises(InvalidStatusTransition):
            store.transition("tenant-a", receipt["request_id"], "completed")
        # An undefined target is out of range (ValueError), not a graph edge.
        with self.assertRaises(ValueError):
            store.transition("tenant-a", receipt["request_id"], "cancelled")
        store.transition("tenant-a", receipt["request_id"], "processing")
        with self.assertRaises(InvalidStatusTransition):
            store.transition("tenant-a", receipt["request_id"], "accepted")
        store.transition("tenant-a", receipt["request_id"], "completed")
        with self.assertRaises(InvalidStatusTransition):
            store.transition("tenant-a", receipt["request_id"], "failed")
        self.assertEqual(
            [e["status"] for e in store.audit("tenant-a", receipt["request_id"])],
            ["accepted", "processing", "completed"],
        )

    def test_failed_submit_validation_appends_no_event(self):
        store = RequestStore(self.db_path)
        for bad_scopes in ([], ["email", "email"], 123, None):
            with self.assertRaises(ValueError):
                store.submit("tenant-a", "subject-1", bad_scopes, "key-x")
        with sqlite3.connect(self.db_path) as conn:
            self.assertEqual(
                conn.execute("SELECT count(*) FROM status_events").fetchone()[0], 0
            )

    def test_transition_validation_failures_append_no_event(self):
        store = RequestStore(self.db_path)
        receipt = self._submit(store)
        for bad in ("", None, 7, b"x", ["x"]):
            # Tenant and target stay caller errors...
            with self.assertRaises(ValueError):
                store.transition(bad, receipt["request_id"], "processing")
            with self.assertRaises(ValueError):
                store.transition("tenant-a", receipt["request_id"], bad)
            # ...while a malformed request id is treated as not found.
            with self.assertRaises(RequestNotFound):
                store.transition("tenant-a", bad, "processing")
        self.assertEqual(
            [e["status"] for e in store.audit("tenant-a", receipt["request_id"])],
            ["accepted"],
        )

    def test_missing_and_cross_tenant_raise_not_found(self):
        store = RequestStore(self.db_path)
        receipt = self._submit(store)
        store.transition("tenant-a", receipt["request_id"], "processing")
        with self.assertRaises(RequestNotFound):
            store.audit("tenant-a", "does-not-exist")
        with self.assertRaises(RequestNotFound):
            store.audit("tenant-b", receipt["request_id"])

    def test_audit_rejects_invalid_arguments(self):
        store = RequestStore(self.db_path)
        for bad in ("", None, 7, b"tenant", ["tenant"]):
            with self.subTest(bad=bad):
                # A bad tenant is caller error...
                with self.assertRaises(ValueError):
                    store.audit(bad, "some-id")
                # ...but a bad request id must look exactly like a missing one.
                with self.assertRaises(RequestNotFound):
                    store.audit("tenant-a", bad)

    def test_cross_tenant_access_does_not_leak_timeline(self):
        store = RequestStore(self.db_path)
        receipt = self._submit(store)
        store.transition("tenant-a", receipt["request_id"], "processing")
        store.transition("tenant-a", receipt["request_id"], "completed")
        # tenant-b sees exactly the same outcome as for an unknown id.
        with self.assertRaises(RequestNotFound):
            store.audit("tenant-b", receipt["request_id"])
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT status FROM status_events WHERE tenant_id = ?",
                ("tenant-b",),
            ).fetchall()
        self.assertEqual(rows, [])

    def test_audit_results_contain_no_sensitive_fields(self):
        secret_subject = "subject-SECRET"
        secret_scope = "scope-SECRET"
        secret_key = "key-SECRET"
        store = RequestStore(self.db_path)
        receipt = store.submit(
            "tenant-a", secret_subject, [secret_scope, "email"], secret_key
        )
        store.transition("tenant-a", receipt["request_id"], "processing")
        rendered = repr(store.audit("tenant-a", receipt["request_id"]))
        self.assertNotIn(secret_subject, rendered)
        self.assertNotIn(secret_scope, rendered)
        self.assertNotIn(secret_key, rendered)

    def test_idempotent_submit_replay_adds_no_event(self):
        store = RequestStore(self.db_path)
        first = self._submit(store)
        second = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        self.assertEqual(first, second)
        events = store.audit("tenant-a", first["request_id"])
        self.assertEqual([e["status"] for e in events], ["accepted"])
        with sqlite3.connect(self.db_path) as conn:
            self.assertEqual(
                conn.execute("SELECT count(*) FROM status_events").fetchone()[0], 1
            )

    def test_timeline_persists_across_store_rebuild(self):
        first_store = RequestStore(self.db_path)
        receipt = self._submit(first_store)
        first_store.transition("tenant-a", receipt["request_id"], "processing")
        first_store.transition("tenant-a", receipt["request_id"], "completed")
        rebuilt = RequestStore(self.db_path)
        events = rebuilt.audit("tenant-a", receipt["request_id"])
        self.assertEqual([e["status"] for e in events],
                         ["accepted", "processing", "completed"])
        self.assertEqual(events[-1]["status"],
                         rebuilt.get_status("tenant-a", receipt["request_id"])["status"])
        stamps = [e["occurred_at"] for e in events]
        self.assertEqual(stamps, sorted(stamps))
        # The original acceptance timestamp survives unchanged.
        self.assertEqual(events[0]["occurred_at"], receipt["created_at"])

    def test_timeline_for_independent_requests_stays_partitioned(self):
        store = RequestStore(self.db_path)
        one = self._submit(store, key="key-1")
        two = self._submit(store, key="key-2")
        store.transition("tenant-a", one["request_id"], "failed")
        store.transition("tenant-a", two["request_id"], "processing")
        self.assertEqual(
            [e["status"] for e in store.audit("tenant-a", one["request_id"])],
            ["accepted", "failed"],
        )
        self.assertEqual(
            [e["status"] for e in store.audit("tenant-a", two["request_id"])],
            ["accepted", "processing"],
        )

    def test_in_memory_store_timeline(self):
        store = RequestStore(":memory:")
        receipt = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        store.transition("tenant-a", receipt["request_id"], "processing")
        self.assertEqual(
            [e["status"] for e in store.audit("tenant-a", receipt["request_id"])],
            ["accepted", "processing"],
        )
        with self.assertRaises(RequestNotFound):
            store.audit("tenant-b", receipt["request_id"])

    def test_concurrent_transitions_keep_timeline_consistent(self):
        store = RequestStore(self.db_path)
        receipt = self._submit(store)
        targets = ("processing", "completed", "failed", "accepted", "completed")

        def move(target):
            try:
                store.transition("tenant-a", receipt["request_id"], target)
            except InvalidStatusTransition:
                pass

        with ThreadPoolExecutor(max_workers=16) as pool:
            list(pool.map(move, targets * 16))

        events = store.audit("tenant-a", receipt["request_id"])
        statuses = [e["status"] for e in events]
        # No duplicates, in occurrence order, and every adjacent pair must be
        # a legal edge in the lifecycle graph.
        self.assertEqual(statuses[0], "accepted")
        self.assertEqual(len(statuses), len(set(statuses)))
        legal = {
            "accepted": {"processing", "failed"},
            "processing": {"completed", "failed"},
        }
        for prev, nxt in zip(statuses, statuses[1:]):
            self.assertIn(nxt, legal.get(prev, set()))
        # Timestamps may tie but may never go backwards.
        stamps = [e["occurred_at"] for e in events]
        self.assertEqual(stamps, sorted(stamps))
        # The final event always agrees with the authoritative status.
        self.assertEqual(
            events[-1]["status"],
            store.get_status("tenant-a", receipt["request_id"])["status"],
        )

    def test_concurrent_terminal_race_produces_single_terminal_event(self):
        store = RequestStore(self.db_path)
        receipt = self._submit(store)
        store.transition("tenant-a", receipt["request_id"], "processing")

        def move(target):
            try:
                store.transition("tenant-a", receipt["request_id"], target)
            except InvalidStatusTransition:
                pass

        with ThreadPoolExecutor(max_workers=16) as pool:
            list(pool.map(move, ("completed", "failed") * 32))
        events = store.audit("tenant-a", receipt["request_id"])
        statuses = [e["status"] for e in events]
        self.assertEqual(statuses[0], "accepted")
        terminal = [s for s in statuses if s in ("completed", "failed")]
        self.assertEqual(len(terminal), 1)
        self.assertEqual(events[-1]["status"],
                         store.get_status("tenant-a", receipt["request_id"])["status"])

    def test_event_rows_share_transaction_with_request_row(self):
        # Direct schema-level check: each request has at least its accepted
        # event and event sequences are gap-free from zero.
        store = RequestStore(self.db_path)
        one = self._submit(store, key="key-1")
        two = self._submit(store, key="key-2")
        store.transition("tenant-a", one["request_id"], "processing")
        store.transition("tenant-a", one["request_id"], "completed")
        with sqlite3.connect(self.db_path) as conn:
            for request_id, expected in ((one["request_id"], 3), (two["request_id"], 1)):
                seqs = [row[0] for row in conn.execute(
                    "SELECT seq FROM status_events "
                    "WHERE tenant_id = 'tenant-a' AND request_id = ? ORDER BY seq",
                    (request_id,),
                )]
                self.assertEqual(seqs, list(range(expected)))
            # The last persisted event status must equal the request status.
            mismatch = conn.execute(
                "SELECT count(*) FROM requests r "
                "WHERE r.status != ( "
                "    SELECT e.status FROM status_events e "
                "    WHERE e.tenant_id = r.tenant_id AND e.request_id = r.request_id "
                "    ORDER BY e.seq DESC LIMIT 1 "
                ")"
            ).fetchone()[0]
        self.assertEqual(mismatch, 0)


if __name__ == "__main__":
    unittest.main()
