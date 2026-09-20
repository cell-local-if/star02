import io
import logging
import os
import re
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor

from forgetting_evidence.requests import (
    InvalidStatusTransition,
    RequestNotFound,
    RequestStore,
)

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_BAD_VALUES = ["", None, 7, b"tenant", ["tenant"]]


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "evidence.db")

    def tearDown(self):
        self._tmp.cleanup()

    def _submit(self, store=None, tenant="tenant-a", key="key-1", subject="subject-1"):
        store = store if store is not None else RequestStore(self.db_path)
        return store.submit(tenant, subject, ["email"], key)

    def _raw(self):
        return sqlite3.connect(self.db_path)

    # ---- evidence() shape ------------------------------------------------

    def test_evidence_after_acceptance(self):
        store = RequestStore(self.db_path)
        receipt = self._submit(store)
        ev = store.evidence("tenant-a", receipt["request_id"])
        self.assertEqual(
            set(ev), {"request_id", "status", "event_count", "chain_hash"}
        )
        self.assertEqual(ev["request_id"], receipt["request_id"])
        self.assertEqual(
            ev["status"], store.get("tenant-a", receipt["request_id"])["status"]
        )
        self.assertEqual(
            ev["event_count"], len(store.audit("tenant-a", receipt["request_id"]))
        )
        self.assertEqual(ev["status"], "accepted")
        self.assertEqual(ev["event_count"], 1)
        self.assertRegex(ev["chain_hash"], _HEX64)

    def test_evidence_tracks_each_real_transition(self):
        store = RequestStore(self.db_path)
        receipt = self._submit(store)
        rid = receipt["request_id"]
        seen = {store.evidence("tenant-a", rid)["chain_hash"]}
        for target, expected_status, expected_count in (
            ("processing", "processing", 2),
            ("completed", "completed", 3),
        ):
            store.transition("tenant-a", rid, target)
            ev = store.evidence("tenant-a", rid)
            self.assertEqual(ev["status"], expected_status)
            self.assertEqual(
                ev["status"], store.get("tenant-a", rid)["status"]
            )
            self.assertEqual(ev["event_count"], expected_count)
            self.assertEqual(
                ev["event_count"], len(store.audit("tenant-a", rid))
            )
            self.assertRegex(ev["chain_hash"], _HEX64)
            # Every real state change seals a distinct new tip.
            self.assertNotIn(ev["chain_hash"], seen)
            seen.add(ev["chain_hash"])

    def test_chain_hash_is_persisted_tip(self):
        store = RequestStore(self.db_path)
        receipt = self._submit(store)
        store.transition("tenant-a", receipt["request_id"], "failed")
        ev = store.evidence("tenant-a", receipt["request_id"])
        with self._raw() as conn:
            stored = conn.execute(
                "SELECT chain_hash FROM event_chain "
                "WHERE tenant_id = ? AND request_id = ? ORDER BY seq DESC LIMIT 1",
                ("tenant-a", receipt["request_id"]),
            ).fetchone()[0]
        self.assertEqual(ev["chain_hash"], stored)

    # ---- verify_evidence() happy paths -----------------------------------

    def test_verify_true_through_lifecycle(self):
        store = RequestStore(self.db_path)
        receipt = self._submit(store)
        rid = receipt["request_id"]
        self.assertTrue(store.verify_evidence("tenant-a", rid))
        store.transition("tenant-a", rid, "processing")
        self.assertTrue(store.verify_evidence("tenant-a", rid))
        store.transition("tenant-a", rid, "completed")
        self.assertTrue(store.verify_evidence("tenant-a", rid))

    def test_verify_true_for_failed_branch_and_in_memory_store(self):
        store = RequestStore(":memory:")
        receipt = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        store.transition("tenant-a", receipt["request_id"], "failed")
        self.assertTrue(store.verify_evidence("tenant-a", receipt["request_id"]))

    def test_chain_survives_store_rebuild_and_extends_afterwards(self):
        first = RequestStore(self.db_path)
        receipt = self._submit(first)
        first.transition("tenant-a", receipt["request_id"], "processing")
        before = first.evidence("tenant-a", receipt["request_id"])
        rebuilt = RequestStore(self.db_path)
        after = rebuilt.evidence("tenant-a", receipt["request_id"])
        self.assertEqual(before, after)
        self.assertTrue(rebuilt.verify_evidence("tenant-a", receipt["request_id"]))
        # A link sealed after reopening the database must chain onto the
        # persisted predecessor and still verify.
        rebuilt.transition("tenant-a", receipt["request_id"], "completed")
        self.assertTrue(rebuilt.verify_evidence("tenant-a", receipt["request_id"]))
        self.assertEqual(
            rebuilt.evidence("tenant-a", receipt["request_id"])["event_count"], 3
        )

    # ---- rejected operations leave evidence untouched --------------------

    def test_rejected_operations_do_not_change_evidence(self):
        store = RequestStore(self.db_path)
        receipt = self._submit(store)
        rid = receipt["request_id"]
        store.transition("tenant-a", rid, "processing")
        # Idempotent replay before the terminal move seals nothing.
        self.assertEqual(
            store.transition("tenant-a", rid, "processing")["status"], "processing"
        )
        store.transition("tenant-a", rid, "completed")
        snapshot = store.evidence("tenant-a", rid)
        self.assertEqual(snapshot["event_count"], 3)

        # Every same-status replay and edge out of a terminal state fails
        # to persist, as do unknown statuses.
        for bad in ("completed", "processing", "failed", "accepted", "cancelled"):
            if bad == "completed":
                # Same-status: idempotent no-op receipt, no write.
                self.assertEqual(
                    store.transition("tenant-a", rid, bad)["status"], "completed"
                )
            else:
                with self.assertRaises(InvalidStatusTransition):
                    store.transition("tenant-a", rid, bad)
        # Invalid parameters.
        for bad in _BAD_VALUES:
            with self.assertRaises(ValueError):
                store.submit(bad, "subject-1", ["email"], "key-x")
            with self.assertRaises(ValueError):
                store.transition(bad, rid, "failed")
            with self.assertRaises(ValueError):
                store.evidence(bad, rid)
            with self.assertRaises(ValueError):
                store.verify_evidence(bad, rid)
        # Missing and cross-tenant access attempts.
        with self.assertRaises(RequestNotFound):
            store.transition("tenant-a", "no-such-request", "failed")
        with self.assertRaises(RequestNotFound):
            store.transition("tenant-b", rid, "failed")
        with self.assertRaises(RequestNotFound):
            store.evidence("tenant-b", rid)
        with self.assertRaises(RequestNotFound):
            store.verify_evidence("tenant-b", rid)

        self.assertEqual(store.evidence("tenant-a", rid), snapshot)
        self.assertTrue(store.verify_evidence("tenant-a", rid))
        with self._raw() as conn:
            self.assertEqual(
                conn.execute("SELECT count(*) FROM event_chain").fetchone()[0], 3
            )

    # ---- tamper detection ------------------------------------------------

    def _mature_request(self, store, key="key-1"):
        receipt = self._submit(store, key=key)
        rid = receipt["request_id"]
        store.transition("tenant-a", rid, "processing")
        store.transition("tenant-a", rid, "completed")
        return rid

    def test_verify_fails_after_event_delete(self):
        store = RequestStore(self.db_path)
        rid = self._mature_request(store)
        with self._raw() as conn:
            conn.execute(
                "DELETE FROM status_events WHERE tenant_id = ? AND request_id = ? "
                "AND seq = 1",
                ("tenant-a", rid),
            )
        self.assertFalse(store.verify_evidence("tenant-a", rid))

    def test_verify_fails_after_event_modification(self):
        store = RequestStore(self.db_path)
        rid = self._mature_request(store)
        with self._raw() as conn:
            conn.execute(
                "UPDATE status_events SET status = 'failed' "
                "WHERE tenant_id = ? AND request_id = ? AND seq = 1",
                ("tenant-a", rid),
            )
        self.assertFalse(store.verify_evidence("tenant-a", rid))

    def test_verify_fails_after_timestamp_modification(self):
        store = RequestStore(self.db_path)
        rid = self._mature_request(store)
        with self._raw() as conn:
            conn.execute(
                "UPDATE status_events SET occurred_at = occurred_at || 'X' "
                "WHERE tenant_id = ? AND request_id = ? AND seq = 0",
                ("tenant-a", rid),
            )
        self.assertFalse(store.verify_evidence("tenant-a", rid))

    def test_verify_fails_after_event_inserted_without_link(self):
        store = RequestStore(self.db_path)
        rid = self._mature_request(store)
        with self._raw() as conn:
            conn.execute(
                "INSERT INTO status_events ("
                "tenant_id, request_id, seq, status, occurred_at"
                ") VALUES (?, ?, 9, 'failed', '2000-01-01T00:00:00Z')",
                ("tenant-a", rid),
            )
        self.assertFalse(store.verify_evidence("tenant-a", rid))

    def test_verify_fails_after_events_swapped(self):
        store = RequestStore(self.db_path)
        rid = self._mature_request(store)
        with self._raw() as conn:
            # Swap the statuses carried by seq 1 and seq 2: order in the
            # timeline changes without any row being deleted.
            conn.execute(
                "UPDATE status_events SET status = 'completed' "
                "WHERE tenant_id = ? AND request_id = ? AND seq = 1",
                ("tenant-a", rid),
            )
            conn.execute(
                "UPDATE status_events SET status = 'processing' "
                "WHERE tenant_id = ? AND request_id = ? AND seq = 2",
                ("tenant-a", rid),
            )
        self.assertFalse(store.verify_evidence("tenant-a", rid))

    def test_verify_fails_after_link_delete_or_modification(self):
        store = RequestStore(self.db_path)
        rid = self._mature_request(store)

        with self._raw() as conn:
            conn.execute(
                "DELETE FROM event_chain WHERE tenant_id = ? AND request_id = ? "
                "AND seq = 2",
                ("tenant-a", rid),
            )
        self.assertFalse(store.verify_evidence("tenant-a", rid))

        # Restore the row with a forged digest: still fails.
        with self._raw() as conn:
            conn.execute(
                "INSERT INTO event_chain (tenant_id, request_id, seq, chain_hash) "
                "VALUES (?, ?, 2, ?)",
                ("tenant-a", rid, "0" * 64),
            )
        self.assertFalse(store.verify_evidence("tenant-a", rid))

        with self._raw() as conn:
            conn.execute(
                "UPDATE event_chain SET chain_hash = ? "
                "WHERE tenant_id = ? AND request_id = ? AND seq = 0",
                ("f" * 64, "tenant-a", rid),
            )
        self.assertFalse(store.verify_evidence("tenant-a", rid))

    def test_verify_fails_after_links_swapped(self):
        store = RequestStore(self.db_path)
        rid = self._mature_request(store)
        with self._raw() as conn:
            first = conn.execute(
                "SELECT chain_hash FROM event_chain "
                "WHERE tenant_id = ? AND request_id = ? AND seq = 1",
                ("tenant-a", rid),
            ).fetchone()[0]
            second = conn.execute(
                "SELECT chain_hash FROM event_chain "
                "WHERE tenant_id = ? AND request_id = ? AND seq = 2",
                ("tenant-a", rid),
            ).fetchone()[0]
            conn.execute(
                "UPDATE event_chain SET chain_hash = ? "
                "WHERE tenant_id = ? AND request_id = ? AND seq = 1",
                (second, "tenant-a", rid),
            )
            conn.execute(
                "UPDATE event_chain SET chain_hash = ? "
                "WHERE tenant_id = ? AND request_id = ? AND seq = 2",
                (first, "tenant-a", rid),
            )
        self.assertFalse(store.verify_evidence("tenant-a", rid))

    def test_verify_fails_when_request_row_status_altered(self):
        store = RequestStore(self.db_path)
        rid = self._mature_request(store)
        with self._raw() as conn:
            conn.execute(
                "UPDATE requests SET status = 'failed' WHERE request_id = ?",
                (rid,),
            )
        self.assertFalse(store.verify_evidence("tenant-a", rid))

    def test_verify_fails_after_transplant_from_other_request(self):
        store = RequestStore(self.db_path)
        rid_a = self._mature_request(store)
        rid_b = self._mature_request(store, key="key-2")
        # Replace A's timeline and links with B's, relabelled with A's
        # identifiers. The links still bind B's request id, so A must not
        # validate.
        with self._raw() as conn:
            conn.execute(
                "DELETE FROM status_events "
                "WHERE tenant_id = 'tenant-a' AND request_id = ?",
                (rid_a,),
            )
            conn.execute(
                "DELETE FROM event_chain "
                "WHERE tenant_id = 'tenant-a' AND request_id = ?",
                (rid_a,),
            )
            conn.execute(
                "INSERT INTO status_events ("
                "tenant_id, request_id, seq, status, occurred_at"
                ") SELECT 'tenant-a', ?, seq, status, occurred_at "
                "FROM status_events WHERE tenant_id = 'tenant-a' AND request_id = ?",
                (rid_a, rid_b),
            )
            conn.execute(
                "INSERT INTO event_chain (tenant_id, request_id, seq, chain_hash) "
                "SELECT 'tenant-a', ?, seq, chain_hash "
                "FROM event_chain WHERE tenant_id = 'tenant-a' AND request_id = ?",
                (rid_a, rid_b),
            )
        self.assertFalse(store.verify_evidence("tenant-a", rid_a))
        # The donor chain itself remains intact.
        self.assertTrue(store.verify_evidence("tenant-a", rid_b))

    def test_independent_chains_do_not_cross_validate(self):
        store = RequestStore(self.db_path)
        one = self._submit(store, key="key-1")
        two = self._submit(store, key="key-2")
        store.transition("tenant-a", one["request_id"], "failed")
        store.transition("tenant-a", two["request_id"], "processing")
        self.assertTrue(store.verify_evidence("tenant-a", one["request_id"]))
        self.assertTrue(store.verify_evidence("tenant-a", two["request_id"]))
        self.assertNotEqual(
            store.evidence("tenant-a", one["request_id"])["chain_hash"],
            store.evidence("tenant-a", two["request_id"])["chain_hash"],
        )

    def test_verify_never_overwrites_stored_evidence(self):
        store = RequestStore(self.db_path)
        rid = self._mature_request(store)
        with self._raw() as conn:
            conn.execute(
                "UPDATE status_events SET status = 'failed' "
                "WHERE tenant_id = ? AND request_id = ? AND seq = 2",
                ("tenant-a", rid),
            )
            stored_before = conn.execute(
                "SELECT seq, chain_hash FROM event_chain "
                "WHERE tenant_id = ? AND request_id = ? ORDER BY seq",
                ("tenant-a", rid),
            ).fetchall()
        # Repeated verification must keep reporting the tampering and
        # must not "repair" the persisted links by recomputing them.
        for _ in range(3):
            self.assertFalse(store.verify_evidence("tenant-a", rid))
        with self._raw() as conn:
            stored_after = conn.execute(
                "SELECT seq, chain_hash FROM event_chain "
                "WHERE tenant_id = ? AND request_id = ? ORDER BY seq",
                ("tenant-a", rid),
            ).fetchall()
        self.assertEqual(stored_before, stored_after)

    # ---- argument validation and tenant isolation ------------------------

    def test_evidence_rejects_invalid_arguments(self):
        store = RequestStore(self.db_path)
        for bad in _BAD_VALUES:
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    store.evidence(bad, "some-id")
                with self.assertRaises(ValueError):
                    store.evidence("tenant-a", bad)
                with self.assertRaises(ValueError):
                    store.verify_evidence(bad, "some-id")
                with self.assertRaises(ValueError):
                    store.verify_evidence("tenant-a", bad)

    def test_evidence_missing_and_cross_tenant_raise_not_found(self):
        store = RequestStore(self.db_path)
        receipt = self._submit(store)
        store.transition("tenant-a", receipt["request_id"], "processing")
        with self.assertRaises(RequestNotFound):
            store.evidence("tenant-a", "does-not-exist")
        with self.assertRaises(RequestNotFound):
            store.evidence("tenant-b", receipt["request_id"])
        with self.assertRaises(RequestNotFound):
            store.verify_evidence("tenant-a", "does-not-exist")
        with self.assertRaises(RequestNotFound):
            store.verify_evidence("tenant-b", receipt["request_id"])

    def test_validation_failures_write_nothing(self):
        store = RequestStore(self.db_path)
        receipt = self._submit(store)
        for bad in _BAD_VALUES:
            with self.assertRaises(ValueError):
                store.evidence(bad, receipt["request_id"])
            with self.assertRaises(ValueError):
                store.verify_evidence(bad, receipt["request_id"])
        with self._raw() as conn:
            self.assertEqual(
                conn.execute(
                    "SELECT count(*) FROM event_chain WHERE tenant_id = 'tenant-a'"
                ).fetchone()[0],
                1,
            )

    # ---- concurrency -----------------------------------------------------

    def test_concurrent_transitions_leave_valid_chain(self):
        store = RequestStore(self.db_path)
        receipt = self._submit(store)
        rid = receipt["request_id"]
        targets = ("processing", "completed", "failed", "accepted", "completed")

        def move(target):
            try:
                store.transition("tenant-a", rid, target)
            except InvalidStatusTransition:
                pass

        with ThreadPoolExecutor(max_workers=16) as pool:
            list(pool.map(move, targets * 16))

        self.assertTrue(store.verify_evidence("tenant-a", rid))
        events = store.audit("tenant-a", rid)
        ev = store.evidence("tenant-a", rid)
        self.assertEqual(ev["event_count"], len(events))
        self.assertEqual(ev["status"], events[-1]["status"])
        self.assertEqual(
            ev["status"], store.get("tenant-a", rid)["status"]
        )
        # Sequences stay gap-free and one link per event was sealed.
        with self._raw() as conn:
            seqs = [row[0] for row in conn.execute(
                "SELECT seq FROM event_chain "
                "WHERE tenant_id = ? AND request_id = ? ORDER BY seq",
                ("tenant-a", rid),
            )]
            self.assertEqual(seqs, list(range(len(events))))

    def test_chain_verifies_after_rebuild_following_concurrency(self):
        store = RequestStore(self.db_path)
        receipt = self._submit(store)
        rid = receipt["request_id"]

        def move(target):
            try:
                store.transition("tenant-a", rid, target)
            except InvalidStatusTransition:
                pass

        with ThreadPoolExecutor(max_workers=16) as pool:
            list(pool.map(move, ("processing", "failed", "completed") * 16))
        snapshot = store.evidence("tenant-a", rid)
        rebuilt = RequestStore(self.db_path)
        self.assertTrue(rebuilt.verify_evidence("tenant-a", rid))
        self.assertEqual(rebuilt.evidence("tenant-a", rid), snapshot)

    # ---- confidentiality -------------------------------------------------

    def test_evidence_and_errors_do_not_leak_sensitive_data(self):
        secret_subject = "subject-SECRET"
        secret_scope = "scope-SECRET"
        secret_key = "key-SECRET"
        store = RequestStore(self.db_path)
        receipt = store.submit(
            "tenant-a", secret_subject, [secret_scope, "email"], secret_key
        )
        store.transition("tenant-a", receipt["request_id"], "processing")
        rendered = repr(store.evidence("tenant-a", receipt["request_id"]))
        self.assertNotIn(secret_subject, rendered)
        self.assertNotIn(secret_scope, rendered)
        self.assertNotIn(secret_key, rendered)

        for call in (
            lambda: store.evidence("tenant-a", "missing-request"),
            lambda: store.verify_evidence("tenant-a", "missing-request"),
        ):
            try:
                call()
            except RequestNotFound as exc:
                message = str(exc)
            else:
                self.fail("expected RequestNotFound")
            self.assertNotIn(secret_subject, message)
            self.assertNotIn(secret_scope, message)
            self.assertNotIn(secret_key, message)

    def test_logs_do_not_leak_chain_preimage_or_payload(self):
        store = RequestStore(self.db_path)
        secret_subject = "subject-SECRET"
        secret_scope = "scope-SECRET"
        receipt = store.submit(
            "tenant-a", secret_subject, [secret_scope], "key-1"
        )
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        logger = logging.getLogger("forgetting_evidence.requests")
        logger.addHandler(handler)
        old_level = logger.level
        logger.setLevel(logging.DEBUG)
        try:
            store.transition("tenant-a", receipt["request_id"], "processing")
            store.evidence("tenant-a", receipt["request_id"])
            store.verify_evidence("tenant-a", receipt["request_id"])
        finally:
            logger.removeHandler(handler)
            logger.setLevel(old_level)
        logs = stream.getvalue()
        self.assertNotIn(secret_subject, logs)
        self.assertNotIn(secret_scope, logs)
        # The chain preimage embeds these fields; the raw preimage and the
        # JSON encoding keyword must never appear in logs.
        self.assertNotIn('"prev_hash"', logs)
        self.assertNotIn("forgetting-evidence/status-chain", logs)


if __name__ == "__main__":
    unittest.main()
