import hashlib
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


HEX64 = re.compile(r"^[0-9a-f]{64}$")


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "evidence.db")

    def tearDown(self):
        self._tmp.cleanup()

    def _store(self):
        return RequestStore(self.db_path)

    def _fresh_lifecycle(self, statuses=("processing", "completed"), key="key-1"):
        store = self._store()
        receipt = store.submit("tenant-a", "subject-1", ["email"], key)
        for status in statuses:
            store.transition("tenant-a", receipt["request_id"], status)
        return store, receipt

    def test_evidence_fields_and_shapes(self):
        store, receipt = self._fresh_lifecycle()
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
        self.assertIsInstance(ev["event_count"], int)
        self.assertTrue(HEX64.match(ev["chain_hash"]))
        self.assertEqual(ev["chain_hash"], ev["chain_hash"].lower())

    def test_evidence_after_submit_only(self):
        store = self._store()
        receipt = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        ev = store.evidence("tenant-a", receipt["request_id"])
        self.assertEqual(ev["event_count"], 1)
        self.assertEqual(ev["status"], "accepted")
        self.assertTrue(HEX64.match(ev["chain_hash"]))
        self.assertTrue(store.verify_evidence("tenant-a", receipt["request_id"]))

    def test_evidence_status_tracks_get(self):
        store = self._store()
        receipt = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        for target in ("processing", "failed"):
            store.transition("tenant-a", receipt["request_id"], target)
            ev = store.evidence("tenant-a", receipt["request_id"])
            got = store.get("tenant-a", receipt["request_id"])
            self.assertEqual(ev["status"], got["status"])
            self.assertEqual(
                ev["event_count"],
                len(store.audit("tenant-a", receipt["request_id"])),
            )
            self.assertTrue(store.verify_evidence("tenant-a", receipt["request_id"]))

    def test_verify_true_on_clean_chain_every_lifecycle(self):
        for index, path in enumerate(
            (
                ("processing", "completed"),
                ("failed",),
                ("processing", "failed"),
            )
        ):
            store, receipt = self._fresh_lifecycle(path, key=f"key-{index}")
            self.assertTrue(
                store.verify_evidence("tenant-a", receipt["request_id"]), path
            )

    def test_evidence_does_not_leak_sensitive_data(self):
        secret_subject = "subject-SECRET"
        secret_scope = "scope-SECRET"
        secret_key = "key-SECRET"
        store = self._store()
        receipt = store.submit(
            "tenant-a", secret_subject, [secret_scope, "email"], secret_key
        )
        store.transition("tenant-a", receipt["request_id"], "processing")
        rendered = repr(store.evidence("tenant-a", receipt["request_id"]))
        self.assertNotIn(secret_subject, rendered)
        self.assertNotIn(secret_scope, rendered)
        self.assertNotIn(secret_key, rendered)

    def test_chain_persists_across_store_rebuild(self):
        store, receipt = self._fresh_lifecycle()
        ev_before = store.evidence("tenant-a", receipt["request_id"])
        rebuilt = self._store()
        ev_after = rebuilt.evidence("tenant-a", receipt["request_id"])
        self.assertEqual(ev_before, ev_after)
        self.assertTrue(rebuilt.verify_evidence("tenant-a", receipt["request_id"]))

    def test_in_memory_chain(self):
        store = RequestStore(":memory:")
        receipt = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        store.transition("tenant-a", receipt["request_id"], "processing")
        self.assertTrue(store.verify_evidence("tenant-a", receipt["request_id"]))
        self.assertTrue(HEX64.match(store.evidence("tenant-a", receipt["request_id"])["chain_hash"]))

    # --- argument / access errors -------------------------------------

    def test_invalid_arguments_raise_value_error(self):
        store, receipt = self._fresh_lifecycle()
        for bad in ("", None, 7, b"tenant", ["tenant"], 3.14):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    store.evidence(bad, receipt["request_id"])
                with self.assertRaises(ValueError):
                    store.evidence("tenant-a", bad)
                with self.assertRaises(ValueError):
                    store.verify_evidence(bad, receipt["request_id"])
                with self.assertRaises(ValueError):
                    store.verify_evidence("tenant-a", bad)

    def test_missing_and_cross_tenant_raise_not_found(self):
        store, receipt = self._fresh_lifecycle()
        for method in ("evidence", "verify_evidence"):
            with self.assertRaises(RequestNotFound):
                getattr(store, method)("tenant-a", "does-not-exist")
            with self.assertRaises(RequestNotFound):
                getattr(store, method)("tenant-b", receipt["request_id"])

    def test_errors_do_not_leak(self):
        store, receipt = self._fresh_lifecycle()
        secret = "subject-SECRETZZZ"
        store.submit("tenant-a", secret, ["email"], "key-secret")
        try:
            store.evidence("tenant-a", secret)
        except RequestNotFound as exc:
            self.assertNotIn(secret, str(exc))
        else:
            self.fail()

    # --- tamper detection ---------------------------------------------

    def _raw(self):
        return sqlite3.connect(self.db_path)

    def test_modify_event_status_breaks_verification(self):
        store, receipt = self._fresh_lifecycle()
        with self._raw() as conn:
            conn.execute(
                "UPDATE status_events SET status = 'failed' "
                "WHERE request_id = ? AND seq = 1",
                (receipt["request_id"],),
            )
        self.assertFalse(store.verify_evidence("tenant-a", receipt["request_id"]))

    def test_modify_event_timestamp_breaks_verification(self):
        store, receipt = self._fresh_lifecycle()
        with self._raw() as conn:
            conn.execute(
                "UPDATE status_events SET occurred_at = occurred_at || 'X' "
                "WHERE request_id = ? AND seq = 0",
                (receipt["request_id"],),
            )
        self.assertFalse(store.verify_evidence("tenant-a", receipt["request_id"]))

    def test_modify_stored_hash_breaks_verification(self):
        store, receipt = self._fresh_lifecycle()
        with self._raw() as conn:
            row = conn.execute(
                "SELECT chain_hash FROM status_events WHERE request_id = ? AND seq = 0",
                (receipt["request_id"],),
            ).fetchone()
            flipped = ("0" if row[0][0] != "0" else "1") + row[0][1:]
            conn.execute(
                "UPDATE status_events SET chain_hash = ? WHERE request_id = ? AND seq = 0",
                (flipped, receipt["request_id"]),
            )
        self.assertFalse(store.verify_evidence("tenant-a", receipt["request_id"]))

    def test_delete_event_breaks_verification(self):
        store, receipt = self._fresh_lifecycle()
        with self._raw() as conn:
            conn.execute(
                "DELETE FROM status_events WHERE request_id = ? AND seq = 1",
                (receipt["request_id"],),
            )
        self.assertFalse(store.verify_evidence("tenant-a", receipt["request_id"]))

    def test_delete_all_events_breaks_verification(self):
        store, receipt = self._fresh_lifecycle()
        with self._raw() as conn:
            conn.execute(
                "DELETE FROM status_events WHERE request_id = ?",
                (receipt["request_id"],),
            )
        self.assertFalse(store.verify_evidence("tenant-a", receipt["request_id"]))

    def test_insert_forged_event_breaks_verification(self):
        store, receipt = self._fresh_lifecycle(("failed",))
        events = store.audit("tenant-a", receipt["request_id"])
        with self._raw() as conn:
            # Insert a bogus "processing" event after the terminal event.
            conn.execute(
                "INSERT INTO status_events "
                "(tenant_id, request_id, seq, status, occurred_at, chain_hash) "
                "VALUES ('tenant-a', ?, 2, 'processing', ?, ?)",
                (
                    receipt["request_id"],
                    events[-1]["occurred_at"],
                    "0" * 64,
                ),
            )
        self.assertFalse(store.verify_evidence("tenant-a", receipt["request_id"]))

    def test_swap_events_breaks_verification(self):
        store, receipt = self._fresh_lifecycle()
        with self._raw() as conn:
            # Swap the statuses of seq 1 and 2 while keeping hashes.
            conn.execute(
                "UPDATE status_events SET status = CASE seq "
                "WHEN 1 THEN 'completed' WHEN 2 THEN 'processing' END "
                "WHERE request_id = ? AND seq IN (1, 2)",
                (receipt["request_id"],),
            )
        self.assertFalse(store.verify_evidence("tenant-a", receipt["request_id"]))

    def test_reorder_by_reseq_breaks_verification(self):
        store, receipt = self._fresh_lifecycle()
        with self._raw() as conn:
            # Renumber seq 1 -> 5 (a gap): must fail.
            conn.execute(
                "UPDATE status_events SET seq = 5 "
                "WHERE request_id = ? AND seq = 1",
                (receipt["request_id"],),
            )
        self.assertFalse(store.verify_evidence("tenant-a", receipt["request_id"]))

    def test_cross_request_event_substitution_breaks_chain(self):
        store = self._store()
        one = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        two = store.submit("tenant-a", "subject-2", ["email"], "key-2")
        store.transition("tenant-a", one["request_id"], "processing")
        store.transition("tenant-a", two["request_id"], "processing")
        with self._raw() as conn:
            # Copy request two's genesis row over request one's seq-0.
            forgery = conn.execute(
                "SELECT status, occurred_at, chain_hash FROM status_events "
                "WHERE request_id = ? AND seq = 0",
                (two["request_id"],),
            ).fetchone()
            conn.execute(
                "UPDATE status_events SET status = ?, occurred_at = ?, chain_hash = ? "
                "WHERE request_id = ? AND seq = 0",
                (*forgery, one["request_id"]),
            )
        self.assertFalse(store.verify_evidence("tenant-a", one["request_id"]))

    def test_cross_tenant_event_substitution_breaks_chain(self):
        store = self._store()
        a = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        b = store.submit("tenant-b", "subject-1", ["email"], "key-1")
        store.transition("tenant-a", a["request_id"], "processing")
        store.transition("tenant-b", b["request_id"], "processing")
        with self._raw() as conn:
            forgery = conn.execute(
                "SELECT status, occurred_at, chain_hash FROM status_events "
                "WHERE tenant_id = 'tenant-b' AND request_id = ? AND seq = 0",
                (b["request_id"],),
            ).fetchone()
            conn.execute(
                "UPDATE status_events SET status = ?, occurred_at = ?, chain_hash = ? "
                "WHERE tenant_id = 'tenant-a' AND request_id = ? AND seq = 0",
                (*forgery, a["request_id"],),
            )
        self.assertFalse(store.verify_evidence("tenant-a", a["request_id"]))

    def test_tampered_request_head_breaks_verification(self):
        store, receipt = self._fresh_lifecycle()
        with self._raw() as conn:
            conn.execute(
                "UPDATE requests SET chain_hash = ? WHERE request_id = ?",
                ("0" * 64, receipt["request_id"]),
            )
        self.assertFalse(store.verify_evidence("tenant-a", receipt["request_id"]))

    def test_tampered_request_status_breaks_verification(self):
        store, receipt = self._fresh_lifecycle()
        with self._raw() as conn:
            conn.execute(
                "UPDATE requests SET status = 'failed' WHERE request_id = ?",
                (receipt["request_id"],),
            )
        self.assertFalse(store.verify_evidence("tenant-a", receipt["request_id"]))

    def test_evidence_reports_stored_head_not_recomputed(self):
        store, receipt = self._fresh_lifecycle()
        clean = store.evidence("tenant-a", receipt["request_id"])
        forged = "a" * 64
        self.assertNotEqual(forged, clean["chain_hash"])
        with self._raw() as conn:
            conn.execute(
                "UPDATE requests SET chain_hash = ? WHERE request_id = ?",
                (forged, receipt["request_id"]),
            )
        # evidence() reflects what was persisted rather than silently
        # recomputing a "convenient" replacement...
        observed = store.evidence("tenant-a", receipt["request_id"])
        self.assertEqual(observed["chain_hash"], forged)
        self.assertEqual(observed["status"], clean["status"])
        self.assertEqual(observed["event_count"], clean["event_count"])
        # ...while verification flags the substituted head.
        self.assertFalse(store.verify_evidence("tenant-a", receipt["request_id"]))

    def test_malformed_persisted_head_is_not_presented_as_evidence(self):
        store, receipt = self._fresh_lifecycle()
        with self._raw() as conn:
            conn.execute(
                "UPDATE requests SET chain_hash = 'not-a-digest' WHERE request_id = ?",
                (receipt["request_id"],),
            )
        with self.assertRaises(RequestNotFound):
            store.evidence("tenant-a", receipt["request_id"])
        self.assertFalse(store.verify_evidence("tenant-a", receipt["request_id"]))

    # --- no-write guarantees -------------------------------------------

    def test_idempotent_transition_does_not_change_evidence(self):
        store = self._store()
        receipt = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        self.assertTrue(store.verify_evidence("tenant-a", receipt["request_id"]))
        accepted_ev = store.evidence("tenant-a", receipt["request_id"])
        store.transition("tenant-a", receipt["request_id"], "accepted")
        self.assertEqual(
            store.evidence("tenant-a", receipt["request_id"]), accepted_ev
        )
        store.transition("tenant-a", receipt["request_id"], "processing")
        processing_ev = store.evidence("tenant-a", receipt["request_id"])
        store.transition("tenant-a", receipt["request_id"], "processing")
        self.assertEqual(
            store.evidence("tenant-a", receipt["request_id"]), processing_ev
        )
        store.transition("tenant-a", receipt["request_id"], "completed")
        completed_ev = store.evidence("tenant-a", receipt["request_id"])
        store.transition("tenant-a", receipt["request_id"], "completed")
        self.assertEqual(
            store.evidence("tenant-a", receipt["request_id"]), completed_ev
        )
        self.assertTrue(store.verify_evidence("tenant-a", receipt["request_id"]))

    def test_illegal_transitions_do_not_change_evidence(self):
        store = self._store()
        receipt = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        before = store.evidence("tenant-a", receipt["request_id"])
        with self.assertRaises(InvalidStatusTransition):
            store.transition("tenant-a", receipt["request_id"], "completed")
        with self.assertRaises(InvalidStatusTransition):
            store.transition("tenant-a", receipt["request_id"], "cancelled")
        self.assertEqual(
            store.evidence("tenant-a", receipt["request_id"]), before
        )
        self.assertTrue(store.verify_evidence("tenant-a", receipt["request_id"]))

    def test_verify_never_writes(self):
        store, receipt = self._fresh_lifecycle()
        before = snapshot(self.db_path)
        for _ in range(5):
            self.assertTrue(store.verify_evidence("tenant-a", receipt["request_id"]))
        after = snapshot(self.db_path)
        self.assertEqual(before, after)

    def test_verify_tampered_then_rebuilt_still_fails(self):
        store, receipt = self._fresh_lifecycle()
        with self._raw() as conn:
            conn.execute(
                "UPDATE status_events SET occurred_at = occurred_at || 'Z' "
                "WHERE request_id = ? AND seq = 1",
                (receipt["request_id"],),
            )
        rebuilt = self._store()
        self.assertFalse(rebuilt.verify_evidence("tenant-a", receipt["request_id"]))

    # --- concurrency ---------------------------------------------------

    def test_concurrent_transitions_chain_matches_final_timeline(self):
        store = self._store()
        receipt = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        targets = ("processing", "completed", "failed", "accepted", "completed")

        def move(target):
            try:
                store.transition("tenant-a", receipt["request_id"], target)
            except InvalidStatusTransition:
                pass

        with ThreadPoolExecutor(max_workers=16) as pool:
            list(pool.map(move, targets * 16))
        self.assertTrue(store.verify_evidence("tenant-a", receipt["request_id"]))
        ev = store.evidence("tenant-a", receipt["request_id"])
        events = store.audit("tenant-a", receipt["request_id"])
        self.assertEqual(ev["event_count"], len(events))
        self.assertEqual(ev["status"], events[-1]["status"])
        rebuilt = self._store()
        self.assertTrue(rebuilt.verify_evidence("tenant-a", receipt["request_id"]))

    def test_genesis_hash_is_sha256_of_documented_preimage(self):        # Independent recomputation guards the length-prefixed encoding.
        store = self._store()
        receipt = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        events = store.audit("tenant-a", receipt["request_id"])
        import struct

        digest = hashlib.sha256()
        values = (
            "tenant-a",
            receipt["request_id"],
            "0",
            "accepted",
            events[0]["occurred_at"],
            hashlib.sha256(b"").hexdigest(),
        )
        for value in values:
            raw = value.encode()
            digest.update(struct.pack(">Q", len(raw)))
            digest.update(raw)
        self.assertEqual(
            digest.hexdigest(),
            store.evidence("tenant-a", receipt["request_id"])["chain_hash"],
        )


def snapshot(path):
    with open(path, "rb") as handle:
        return handle.read()


class LegacySchemaMigrationTests(unittest.TestCase):
    """Databases created before chain hashes upgrade without trust."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "evidence.db")

    def tearDown(self):
        self._tmp.cleanup()

    def _create_legacy_database(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "CREATE TABLE requests ("
                "request_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, "
                "idempotency_key TEXT NOT NULL, subject_id TEXT NOT NULL, "
                "scopes_json TEXT NOT NULL, status TEXT NOT NULL, "
                "created_at TEXT NOT NULL)"
            )
            conn.execute(
                "CREATE UNIQUE INDEX idx_requests_tenant_idempotency "
                "ON requests(tenant_id, idempotency_key)"
            )
            conn.execute(
                "CREATE TABLE status_events ("
                "tenant_id TEXT NOT NULL, request_id TEXT NOT NULL, "
                "seq INTEGER NOT NULL, status TEXT NOT NULL, "
                "occurred_at TEXT NOT NULL, "
                "PRIMARY KEY (tenant_id, request_id, seq))"
            )
            conn.execute(
                "INSERT INTO requests VALUES (?, 'tenant-a', 'k1', 's1', "
                "'[\"email\"]', 'processing', '2026-01-01T00:00:00Z')",
                ("rid-1",),
            )
            conn.executemany(
                "INSERT INTO status_events VALUES (?, ?, ?, ?, ?)",
                [
                    ("tenant-a", "rid-1", 0, "accepted", "2026-01-01T00:00:00Z"),
                    ("tenant-a", "rid-1", 1, "processing", "2026-01-01T00:00:01Z"),
                ],
            )

    def _legacy_event_rows(self):
        with sqlite3.connect(self.db_path) as conn:
            return conn.execute(
                "SELECT tenant_id, request_id, seq, status, occurred_at "
                "FROM status_events ORDER BY seq"
            ).fetchall()

    def test_unanchored_legacy_database_is_not_silently_trusted(self):
        self._create_legacy_database()
        before = self._legacy_event_rows()
        store = RequestStore(self.db_path)
        # The additive migration still backfills chain columns, but no
        # sidecar exists, so the database is incomplete rather than valid.
        self.assertEqual(store.recover(), "incomplete")
        self.assertFalse(store.verify_evidence("tenant-a", "rid-1"))
        # Reads keep their existing behaviour.
        ev = store.evidence("tenant-a", "rid-1")
        self.assertEqual(ev["status"], "processing")
        self.assertEqual(ev["event_count"], 2)
        # Writes are refused rather than silently anchoring untrusted data.
        with self.assertRaises(RuntimeError):
            store.transition("tenant-a", "rid-1", "completed")
        with self.assertRaises(RuntimeError):
            store.submit("tenant-a", "subject-2", ["email"], "key-2")
        # The upgrade never overwrote audit records.
        self.assertEqual(self._legacy_event_rows(), before)

    def test_legacy_database_adopted_with_key_anchors_and_verifies(self):
        self._create_legacy_database()
        before = self._legacy_event_rows()
        key = b"operator-adoption-key-0123456789ab"
        store = RequestStore(self.db_path, integrity_key=key)
        self.assertEqual(store.recover(), "valid")
        ev = store.evidence("tenant-a", "rid-1")
        self.assertEqual(ev["status"], "processing")
        self.assertEqual(ev["event_count"], 2)
        self.assertTrue(HEX64.match(ev["chain_hash"]))
        self.assertTrue(store.verify_evidence("tenant-a", "rid-1"))
        # Audit rows are byte-for-byte preserved by adoption.
        self.assertEqual(self._legacy_event_rows(), before)
        # A rebuilt instance (key lives only in the sidecar) keeps
        # verifying and accepts further transitions on the same chain.
        rebuilt = RequestStore(self.db_path)
        self.assertEqual(rebuilt.recover(), "valid")
        self.assertTrue(rebuilt.verify_evidence("tenant-a", "rid-1"))
        rebuilt.transition("tenant-a", "rid-1", "completed")
        self.assertTrue(rebuilt.verify_evidence("tenant-a", "rid-1"))
        self.assertEqual(
            rebuilt.evidence("tenant-a", "rid-1")["event_count"], 3
        )

    def test_legacy_tampered_timeline_fails_after_adoption(self):
        self._create_legacy_database()
        with sqlite3.connect(self.db_path) as conn:
            # Tamper before the store ever opens the file.
            conn.execute(
                "UPDATE status_events SET status = 'failed' "
                "WHERE request_id = 'rid-1' AND seq = 1"
            )
        store = RequestStore(self.db_path, integrity_key=b"x" * 32)
        # Adoption anchors the (tampered) state as-is; the per-request
        # chain still detects the semantic inconsistency.
        self.assertEqual(store.recover(), "valid")
        self.assertFalse(store.verify_evidence("tenant-a", "rid-1"))


if __name__ == "__main__":
    unittest.main()
