import hashlib
import json
import os
import re
import sqlite3
import struct
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest import mock

from forgetting_evidence.requests import (
    InvalidStatusTransition,
    RequestNotFound,
    RequestStore,
)


HEX64 = re.compile(r"^[0-9a-f]{64}$")

# Test-only integrity key. Trusted verification requires a caller-held key;
# stores that should verify must be built with one.
KEY = "test-integrity-key"


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "evidence.db")

    def tearDown(self):
        self._tmp.cleanup()

    def _store(self):
        return RequestStore(self.db_path, integrity_key=KEY)

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
        store = RequestStore(":memory:", integrity_key=KEY)
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
        anchors_before = snapshot(self.db_path + ".anchors")
        for _ in range(5):
            self.assertTrue(store.verify_evidence("tenant-a", receipt["request_id"]))
        after = snapshot(self.db_path)
        anchors_after = snapshot(self.db_path + ".anchors")
        self.assertEqual(before, after)
        self.assertEqual(anchors_before, anchors_after)

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
    """Databases created before chain hashes must upgrade transparently."""

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

    def test_legacy_database_is_upgraded_but_never_trusted(self):
        self._create_legacy_database()
        store = RequestStore(self.db_path, integrity_key=KEY)
        ev = store.evidence("tenant-a", "rid-1")
        self.assertEqual(ev["status"], "processing")
        self.assertEqual(ev["event_count"], 2)
        self.assertTrue(HEX64.match(ev["chain_hash"]))
        # Rows that predate keyed anchoring can never verify: the upgrade
        # backfills plain chain links only and never fabricates an anchor.
        self.assertFalse(store.verify_evidence("tenant-a", "rid-1"))
        # A later keyed transition persists in SQLite but must not
        # backfill trust onto the unanchored history.
        store.transition("tenant-a", "rid-1", "completed")
        self.assertEqual(store.get("tenant-a", "rid-1")["status"], "completed")
        self.assertEqual(store.evidence("tenant-a", "rid-1")["event_count"], 3)
        self.assertFalse(store.verify_evidence("tenant-a", "rid-1"))
        rebuilt = RequestStore(self.db_path, integrity_key=KEY)
        self.assertFalse(rebuilt.verify_evidence("tenant-a", "rid-1"))
        report = rebuilt.recover()
        entry = next(
            item for item in report["requests"] if item["request_id"] == "rid-1"
        )
        self.assertEqual(entry["state"], "unanchored")

    def test_legacy_tampered_timeline_fails_after_upgrade(self):
        self._create_legacy_database()
        with sqlite3.connect(self.db_path) as conn:
            # Tamper before the store ever opens the file.
            conn.execute(
                "UPDATE status_events SET status = 'failed' "
                "WHERE request_id = 'rid-1' AND seq = 1"
            )
        store = RequestStore(self.db_path)
        self.assertFalse(store.verify_evidence("tenant-a", "rid-1"))


class TrustedAnchorTests(unittest.TestCase):
    """Keyed sidecar anchoring: fail-closed verification semantics."""

    KEY_A = "integrity-key-alpha"
    KEY_B = "integrity-key-bravo"

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "evidence.db")
        self.anchor_path = self.db_path + ".anchors"

    def tearDown(self):
        self._tmp.cleanup()

    def _lifecycle(self, store, tenant="tenant-a", key="key-1",
                   statuses=("processing", "completed")):
        receipt = store.submit(tenant, "subject-1", ["email"], key)
        for status in statuses:
            store.transition(tenant, receipt["request_id"], status)
        return receipt

    # --- happy path ------------------------------------------------------

    def test_clean_keyed_chain_verifies_at_every_step_and_after_rebuild(self):
        store = RequestStore(self.db_path, integrity_key=self.KEY_A)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        self.assertTrue(store.verify_evidence("tenant-a", receipt["request_id"]))
        store.transition("tenant-a", receipt["request_id"], "processing")
        self.assertTrue(store.verify_evidence("tenant-a", receipt["request_id"]))
        store.transition("tenant-a", receipt["request_id"], "completed")
        self.assertTrue(store.verify_evidence("tenant-a", receipt["request_id"]))
        rebuilt = RequestStore(self.db_path, integrity_key=self.KEY_A)
        self.assertTrue(rebuilt.verify_evidence("tenant-a", receipt["request_id"]))
        report = rebuilt.recover()
        self.assertEqual(report["state"], "committed")
        self.assertEqual(report["sidecar"], "ok")
        self.assertTrue(report["key_configured"])
        self.assertEqual(
            report["requests"],
            [{"tenant_id": "tenant-a", "request_id": receipt["request_id"],
              "state": "committed"}],
        )

    def test_bytes_key_and_string_key_equivalent(self):
        store = RequestStore(self.db_path, integrity_key=self.KEY_A)
        receipt = self._lifecycle(store)
        rebuilt = RequestStore(self.db_path, integrity_key=self.KEY_A.encode())
        self.assertTrue(rebuilt.verify_evidence("tenant-a", receipt["request_id"]))

    def test_explicit_anchor_path_outside_database_directory(self):
        anchor = os.path.join(self._tmp.name, "elsewhere", "anchors.json")
        store = RequestStore(
            self.db_path, anchor_path=anchor, integrity_key=self.KEY_A
        )
        receipt = self._lifecycle(store)
        self.assertTrue(os.path.exists(anchor))
        self.assertFalse(os.path.exists(self.anchor_path))
        rebuilt = RequestStore(
            self.db_path, anchor_path=anchor, integrity_key=self.KEY_A
        )
        self.assertTrue(rebuilt.verify_evidence("tenant-a", receipt["request_id"]))

    # --- failure modes ---------------------------------------------------

    def test_without_key_verification_is_false_but_operations_work(self):
        store = RequestStore(self.db_path)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        self.assertFalse(store.verify_evidence("tenant-a", receipt["request_id"]))
        # A key provided later cannot retroactively trust unanchored rows.
        keyed = RequestStore(self.db_path, integrity_key=self.KEY_A)
        self.assertFalse(keyed.verify_evidence("tenant-a", receipt["request_id"]))
        keyed.transition("tenant-a", receipt["request_id"], "processing")
        self.assertFalse(keyed.verify_evidence("tenant-a", receipt["request_id"]))
        report = keyed.recover()
        self.assertEqual(report["sidecar"], "missing")
        self.assertEqual(report["state"], "unanchored")

    def test_empty_key_is_treated_as_no_key(self):
        store = RequestStore(self.db_path, integrity_key="")
        receipt = store.submit("tenant-a", "subject-1", ["email"], "k")
        self.assertFalse(store.verify_evidence("tenant-a", receipt["request_id"]))

    def test_wrong_key_fails(self):
        store = RequestStore(self.db_path, integrity_key=self.KEY_A)
        receipt = self._lifecycle(store)
        wrong = RequestStore(self.db_path, integrity_key=self.KEY_B)
        self.assertFalse(wrong.verify_evidence("tenant-a", receipt["request_id"]))
        self.assertEqual(wrong.recover()["sidecar"], "corrupt")

    def test_missing_sidecar_fails(self):
        store = RequestStore(self.db_path, integrity_key=self.KEY_A)
        receipt = self._lifecycle(store)
        os.unlink(self.anchor_path)
        rebuilt = RequestStore(self.db_path, integrity_key=self.KEY_A)
        self.assertFalse(rebuilt.verify_evidence("tenant-a", receipt["request_id"]))
        report = rebuilt.recover()
        self.assertEqual(report["sidecar"], "missing")
        self.assertEqual(report["state"], "unanchored")

    def test_corrupt_sidecar_fails(self):
        store = RequestStore(self.db_path, integrity_key=self.KEY_A)
        receipt = self._lifecycle(store)
        with open(self.anchor_path, "rb") as handle:
            clean = handle.read()
        for tamper in (_flip_middle_byte, _write_garbage, _remove_one_record):
            with self.subTest(tamper=tamper.__name__):
                with open(self.anchor_path, "wb") as handle:
                    handle.write(clean)
                tamper(self.anchor_path)
                rebuilt = RequestStore(self.db_path, integrity_key=self.KEY_A)
                self.assertFalse(
                    rebuilt.verify_evidence("tenant-a", receipt["request_id"])
                )
                self.assertEqual(rebuilt.recover()["sidecar"], "corrupt")
        with open(self.anchor_path, "wb") as handle:
            handle.write(clean)
        self.assertTrue(
            RequestStore(self.db_path, integrity_key=self.KEY_A)
            .verify_evidence("tenant-a", receipt["request_id"])
        )

    def test_sidecar_from_other_database_or_key_fails(self):
        store = RequestStore(self.db_path, integrity_key=self.KEY_A)
        receipt = self._lifecycle(store)
        other_path = os.path.join(self._tmp.name, "other.db")
        other = RequestStore(other_path, integrity_key=self.KEY_B)
        other.submit("tenant-a", "subject-1", ["email"], "k")
        with open(other_path + ".anchors", "rb") as handle:
            foreign = handle.read()
        with open(self.anchor_path, "wb") as handle:
            handle.write(foreign)
        rebuilt = RequestStore(self.db_path, integrity_key=self.KEY_A)
        self.assertFalse(rebuilt.verify_evidence("tenant-a", receipt["request_id"]))

    def test_anchor_records_cannot_be_swapped_between_requests(self):
        store = RequestStore(self.db_path, integrity_key=self.KEY_A)
        one = store.submit("tenant-a", "subject-1", ["email"], "k1")
        two = store.submit("tenant-a", "subject-2", ["email"], "k2")
        with open(self.anchor_path) as handle:
            document = json.load(handle)
        keys = sorted(document["records"])
        document["records"][keys[0]], document["records"][keys[1]] = (
            document["records"][keys[1]],
            document["records"][keys[0]],
        )
        with open(self.anchor_path, "w") as handle:
            json.dump(document, handle)
        rebuilt = RequestStore(self.db_path, integrity_key=self.KEY_A)
        self.assertFalse(rebuilt.verify_evidence("tenant-a", one["request_id"]))
        self.assertFalse(rebuilt.verify_evidence("tenant-a", two["request_id"]))
        self.assertEqual(rebuilt.recover()["sidecar"], "corrupt")

    def test_anchor_records_cannot_be_swapped_between_tenants(self):
        store = RequestStore(self.db_path, integrity_key=self.KEY_A)
        a = store.submit("tenant-a", "subject-1", ["email"], "k")
        b = store.submit("tenant-b", "subject-1", ["email"], "k")
        store.transition("tenant-a", a["request_id"], "failed")
        store.transition("tenant-b", b["request_id"], "failed")
        with open(self.anchor_path) as handle:
            document = json.load(handle)
        keys = sorted(document["records"])
        document["records"][keys[0]], document["records"][keys[1]] = (
            document["records"][keys[1]],
            document["records"][keys[0]],
        )
        with open(self.anchor_path, "w") as handle:
            json.dump(document, handle)
        rebuilt = RequestStore(self.db_path, integrity_key=self.KEY_A)
        self.assertFalse(rebuilt.verify_evidence("tenant-a", a["request_id"]))
        self.assertFalse(rebuilt.verify_evidence("tenant-b", b["request_id"]))

    def test_full_recompute_forgery_without_key_fails(self):
        """Attacker rewrites SQLite AND the sidecar but lacks the key."""
        store = RequestStore(self.db_path, integrity_key=self.KEY_A)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "k")
        store.transition("tenant-a", receipt["request_id"], "processing")
        rid = receipt["request_id"]
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT seq, status, occurred_at FROM status_events "
                "WHERE request_id = ? ORDER BY seq",
                (rid,),
            ).fetchall()
        head = _recompute_chain("tenant-a", rid, rows)
        forged_link = _chain_hash_for(
            "tenant-a", rid, 2, "completed", rows[-1][2], head
        )
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO status_events VALUES ('tenant-a', ?, 2, ?, ?, ?)",
                (rid, "completed", rows[-1][2], forged_link),
            )
            conn.execute(
                "UPDATE requests SET status = 'completed', chain_hash = ? "
                "WHERE request_id = ?",
                (forged_link, rid),
            )
        # Replace the sidecar with any public-content-only document.
        with open(self.anchor_path, "w") as handle:
            json.dump({"version": 1, "records": {}}, handle)
        self.assertFalse(store.verify_evidence("tenant-a", rid))
        # A re-anchoring attempt by someone without the key cannot help.
        attacker = RequestStore(self.db_path, integrity_key="attacker-guess")
        self.assertFalse(attacker.verify_evidence("tenant-a", rid))

    def test_key_material_is_never_persisted_or_returned(self):
        store = RequestStore(self.db_path, integrity_key=self.KEY_A)
        receipt = self._lifecycle(store, key="key-SECRET")
        with open(self.db_path, "rb") as handle:
            db_bytes = handle.read()
        with open(self.anchor_path, "rb") as handle:
            anchor_bytes = handle.read()
        self.assertNotIn(self.KEY_A.encode(), db_bytes)
        self.assertNotIn(self.KEY_A.encode(), anchor_bytes)
        for rendered in (
            repr(receipt),
            repr(store.get("tenant-a", receipt["request_id"])),
            repr(store.audit("tenant-a", receipt["request_id"])),
            repr(store.evidence("tenant-a", receipt["request_id"])),
            repr(store.recover()),
        ):
            self.assertNotIn(self.KEY_A, rendered)

    # --- commit protocol / crash consistency -----------------------------

    def test_submit_failure_between_phases_never_reports_success(self):
        store = RequestStore(self.db_path, integrity_key=self.KEY_A)
        # Phase two (anchor commit) fails after the SQLite commit: the
        # submit must surface an error and the row must verify False.
        original = type(store)._commit_anchor

        def broken(self, *args, **kwargs):
            raise RuntimeError("simulated crash")

        with mock.patch.object(type(store), "_commit_anchor", broken):
            with self.assertRaises(RuntimeError):
                store.submit("tenant-a", "subject-1", ["email"], "k")
        # Either the SQLite row was committed (then it verifies False and
        # recover reports prepared) or it was not (nothing exists); both
        # are explicit non-valid states.
        rebuilt = RequestStore(self.db_path, integrity_key=self.KEY_A)
        report = rebuilt.recover()
        for entry in report["requests"]:
            self.assertIn(entry["state"], ("prepared", "inconsistent"))
            self.assertFalse(
                rebuilt.verify_evidence(entry["tenant_id"], entry["request_id"])
            )

    def test_transition_failure_after_sqlite_commit_marks_prepared(self):
        store = RequestStore(self.db_path, integrity_key=self.KEY_A)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "k")
        with mock.patch.object(
            type(store),
            "_commit_anchor",
            side_effect=RuntimeError("simulated crash"),
        ):
            with self.assertRaises(RuntimeError):
                store.transition("tenant-a", receipt["request_id"], "failed")
        rebuilt = RequestStore(self.db_path, integrity_key=self.KEY_A)
        self.assertFalse(rebuilt.verify_evidence("tenant-a", receipt["request_id"]))
        report = rebuilt.recover()
        self.assertEqual(report["state"], "prepared")
        self.assertEqual(
            [entry["state"] for entry in report["requests"]], ["prepared"]
        )

    def test_stage_failure_rolls_back_sqlite_and_leaves_no_evidence_change(self):
        store = RequestStore(self.db_path, integrity_key=self.KEY_A)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "k")
        before = store.evidence("tenant-a", receipt["request_id"])
        with mock.patch.object(
            type(store),
            "_stage_anchor",
            side_effect=RuntimeError("simulated crash"),
        ):
            with self.assertRaises(RuntimeError):
                store.transition("tenant-a", receipt["request_id"], "failed")
        # SQLite change rolled back: status and evidence are unchanged.
        self.assertEqual(
            store.get("tenant-a", receipt["request_id"])["status"], "accepted"
        )
        self.assertEqual(
            store.evidence("tenant-a", receipt["request_id"]), before
        )
        self.assertTrue(store.verify_evidence("tenant-a", receipt["request_id"]))

    def test_prepared_anchor_never_verifies_even_if_sqlite_matches(self):
        store = RequestStore(self.db_path, integrity_key=self.KEY_A)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "k")
        head = store.evidence("tenant-a", receipt["request_id"])["chain_hash"]
        link = _chain_hash_for(
            "tenant-a", receipt["request_id"], 1, "failed",
            "2026-09-22T00:00:00Z", head,
        )
        # Phase one happens, then the process dies before phase two; the
        # SQLite transaction happens to have committed too.
        store._stage_anchor(
            "tenant-a", receipt["request_id"], 1, "failed",
            link, head,
        )
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO status_events "
                "(tenant_id, request_id, seq, status, occurred_at, chain_hash) "
                "VALUES ('tenant-a', ?, 1, 'failed', '2026-09-22T00:00:00Z', ?)",
                (receipt["request_id"], link),
            )
            conn.execute(
                "UPDATE requests SET status = 'failed', chain_hash = ? "
                "WHERE request_id = ?",
                (link, receipt["request_id"]),
            )
        rebuilt = RequestStore(self.db_path, integrity_key=self.KEY_A)
        self.assertFalse(
            rebuilt.verify_evidence("tenant-a", receipt["request_id"])
        )
        self.assertEqual(rebuilt.recover()["state"], "prepared")

    def test_sidecar_truncation_fails(self):
        """Rolling the append-only journal back while SQLite advances."""
        store = RequestStore(self.db_path, integrity_key=self.KEY_A)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "k")
        store.transition("tenant-a", receipt["request_id"], "processing")
        with open(self.anchor_path, "rb") as handle:
            journal_at_one = handle.read()
        store.transition("tenant-a", receipt["request_id"], "completed")
        # Attacker restores the journal as it was after seq 1.
        with open(self.anchor_path, "wb") as handle:
            handle.write(journal_at_one)
        self.assertFalse(store.verify_evidence("tenant-a", receipt["request_id"]))
        self.assertEqual(store.recover()["state"], "inconsistent")

    def test_sqlite_rollback_with_append_only_anchors_fails(self):
        """Rolling SQLite back while anchors retain later seq fails."""
        store = RequestStore(self.db_path, integrity_key=self.KEY_A)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "k")
        store.transition("tenant-a", receipt["request_id"], "processing")
        store.transition("tenant-a", receipt["request_id"], "completed")
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "DELETE FROM status_events WHERE request_id = ? AND seq IN (1, 2)",
                (receipt["request_id"],),
            )
            conn.execute(
                "UPDATE requests SET status = 'accepted', chain_hash = ("
                "SELECT chain_hash FROM status_events WHERE request_id = ? "
                "AND seq = 0) WHERE request_id = ?",
                (receipt["request_id"], receipt["request_id"]),
            )
        self.assertFalse(store.verify_evidence("tenant-a", receipt["request_id"]))
        self.assertEqual(store.recover()["state"], "inconsistent")

    def test_journal_digest_blocks_per_record_mac_valid_edits(self):
        """All per-record MACs stay valid, yet the set digest must fail."""
        store = RequestStore(self.db_path, integrity_key=self.KEY_A)
        one = store.submit("tenant-a", "subject-1", ["email"], "k1")
        store.transition("tenant-a", one["request_id"], "processing")
        two = store.submit("tenant-a", "subject-2", ["email"], "k2")
        with open(self.anchor_path) as handle:
            document = json.load(handle)
        # Delete two's records while leaving one's MACs untouched.
        document["records"] = {
            key: value
            for key, value in document["records"].items()
            if value["request_id"] == one["request_id"]
        }
        with open(self.anchor_path, "w") as handle:
            json.dump(document, handle)
        rebuilt = RequestStore(self.db_path, integrity_key=self.KEY_A)
        self.assertFalse(rebuilt.verify_evidence("tenant-a", one["request_id"]))
        self.assertEqual(rebuilt.recover()["sidecar"], "corrupt")
        self.assertEqual(rebuilt.recover()["state"], "corrupt")

    def test_prepared_state_is_sticky_after_rebuild(self):
        """An interrupted commit is recognized, never silently resumed."""
        store = RequestStore(self.db_path, integrity_key=self.KEY_A)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "k")
        with mock.patch.object(
            type(store),
            "_commit_anchor",
            side_effect=RuntimeError("simulated crash"),
        ):
            with self.assertRaises(RuntimeError):
                store.transition("tenant-a", receipt["request_id"], "failed")
        rebuilt = RequestStore(self.db_path, integrity_key=self.KEY_A)
        # SQLite committed the failed status, so replay is a no-op and
        # must not repair the anchor.
        replay = rebuilt.transition("tenant-a", receipt["request_id"], "failed")
        self.assertEqual(replay["status"], "failed")
        self.assertFalse(rebuilt.verify_evidence("tenant-a", receipt["request_id"]))
        self.assertEqual(rebuilt.recover()["state"], "prepared")

    def test_recover_and_verify_are_strictly_read_only(self):
        store = RequestStore(self.db_path, integrity_key=self.KEY_A)
        receipt = self._lifecycle(store)
        # Introduce a prepared record so recover has non-trivial work.
        head = store.evidence("tenant-a", receipt["request_id"])["chain_hash"]
        link = _chain_hash_for(
            "tenant-a", receipt["request_id"], 3, "failed",
            "2026-09-22T00:00:00Z", head,
        )
        store._stage_anchor(
            "tenant-a", receipt["request_id"], 3, "failed", link, head
        )
        db_before = snapshot(self.db_path)
        anchor_before = snapshot(self.anchor_path)
        store.recover()
        store.verify_evidence("tenant-a", receipt["request_id"])
        rebuilt = RequestStore(self.db_path, integrity_key=self.KEY_A)
        rebuilt.recover()
        rebuilt.verify_evidence("tenant-a", receipt["request_id"])
        self.assertEqual(snapshot(self.db_path), db_before)
        self.assertEqual(snapshot(self.anchor_path), anchor_before)

    def test_no_replay_of_same_anchor_at_older_position(self):
        store = RequestStore(self.db_path, integrity_key=self.KEY_A)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "k")
        store.transition("tenant-a", receipt["request_id"], "processing")
        committed = store.evidence("tenant-a", receipt["request_id"])
        # Attacker tries to make SQLite match an older anchored head:
        # anchor seq-0 stays committed to the genesis head; the journal
        # binds seq/event_count, so a downgraded SQLite state mismatches.
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "DELETE FROM status_events WHERE request_id = ? AND seq = 1",
                (receipt["request_id"],),
            )
            conn.execute(
                "UPDATE requests SET status = 'accepted', chain_hash = ("
                "SELECT chain_hash FROM status_events WHERE request_id = ? "
                "AND seq = 0) WHERE request_id = ?",
                (receipt["request_id"], receipt["request_id"]),
            )
        self.assertFalse(store.verify_evidence("tenant-a", receipt["request_id"]))

    def test_rejected_writes_do_not_change_anchor_state(self):
        store = RequestStore(self.db_path, integrity_key=self.KEY_A)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "k")
        anchor_before = snapshot(self.anchor_path)
        # Idempotent replay.
        again = store.submit("tenant-a", "subject-1", ["email"], "k")
        self.assertEqual(again["request_id"], receipt["request_id"])
        # Same-status transition.
        store.transition("tenant-a", receipt["request_id"], "accepted")
        # Illegal and unknown transitions.
        with self.assertRaises(InvalidStatusTransition):
            store.transition("tenant-a", receipt["request_id"], "completed")
        with self.assertRaises(InvalidStatusTransition):
            store.transition("tenant-a", receipt["request_id"], "cancelled")
        # Missing and cross-tenant attempts.
        with self.assertRaises(RequestNotFound):
            store.transition("tenant-a", "missing-id", "processing")
        with self.assertRaises(RequestNotFound):
            store.transition("tenant-b", receipt["request_id"], "processing")
        self.assertEqual(snapshot(self.anchor_path), anchor_before)
        self.assertTrue(store.verify_evidence("tenant-a", receipt["request_id"]))

    def test_concurrent_transitions_keep_anchors_consistent(self):
        store = RequestStore(self.db_path, integrity_key=self.KEY_A)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "k")

        def move(target):
            try:
                store.transition("tenant-a", receipt["request_id"], target)
            except InvalidStatusTransition:
                pass

        with ThreadPoolExecutor(max_workers=16) as pool:
            list(pool.map(move, ("processing", "completed", "failed") * 16))
        self.assertTrue(store.verify_evidence("tenant-a", receipt["request_id"]))
        rebuilt = RequestStore(self.db_path, integrity_key=self.KEY_A)
        self.assertTrue(
            rebuilt.verify_evidence("tenant-a", receipt["request_id"])
        )
        self.assertEqual(rebuilt.recover()["state"], "committed")

    def test_in_memory_keyed_store_verifies(self):
        store = RequestStore(":memory:", integrity_key=self.KEY_A)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "k")
        store.transition("tenant-a", receipt["request_id"], "failed")
        self.assertTrue(store.verify_evidence("tenant-a", receipt["request_id"]))
        self.assertEqual(store.recover()["sidecar"], "ok")
        self.assertEqual(store.recover()["state"], "committed")


def _chain_hash_for(tenant_id, request_id, seq, status, occurred_at, predecessor):
    digest = hashlib.sha256()
    for value in (tenant_id, request_id, str(seq), status, occurred_at, predecessor):
        raw = value.encode("utf-8")
        digest.update(struct.pack(">Q", len(raw)))
        digest.update(raw)
    return digest.hexdigest()


def _recompute_chain(tenant_id, request_id, rows):
    predecessor = hashlib.sha256(b"").hexdigest()
    head = predecessor
    for seq, status, occurred_at in rows:
        head = _chain_hash_for(
            tenant_id, request_id, seq, status, occurred_at, predecessor
        )
        predecessor = head
    return head


def _flip_middle_byte(path):
    with open(path, "rb") as handle:
        raw = bytearray(handle.read())
    raw[len(raw) // 2] ^= 0x01
    with open(path, "wb") as handle:
        handle.write(bytes(raw))


def _write_garbage(path):
    with open(path, "wb") as handle:
        handle.write(b"not json at all")


def _remove_one_record(path):
    with open(path) as handle:
        document = json.load(handle)
    key = next(iter(document["records"]))
    del document["records"][key]
    with open(path, "w") as handle:
        json.dump(document, handle)


if __name__ == "__main__":
    unittest.main()
