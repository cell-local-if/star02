import hashlib
import hmac
import os
import re
import sqlite3
import stat
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor

from forgetting_evidence.requests import (
    InvalidStatusTransition,
    IntegrityAnchor,
    RequestNotFound,
    RequestStore,
    UnprotectedEvidenceError,
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

    def test_genesis_hash_is_keyed_mac_of_documented_preimage(self):
        # Independent recomputation guards the length-prefixed encoding
        # and the HKDF-style key derivation. The link is an HMAC, so the
        # digest cannot be reproduced from database contents alone.
        import hmac as _hmac
        import struct

        master = b"unit-test-master-secret"
        store = RequestStore(self.db_path, integrity_key=master)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        events = store.audit("tenant-a", receipt["request_id"])

        domain = b"forgetting-evidence/v1"
        event_key = _hmac.new(master, domain + b"/event-mac", hashlib.sha256).digest()
        mac = _hmac.new(event_key, digestmod=hashlib.sha256)
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
            mac.update(struct.pack(">Q", len(raw)))
            mac.update(raw)
        self.assertEqual(
            mac.hexdigest(),
            store.evidence("tenant-a", receipt["request_id"])["chain_hash"],
        )


def snapshot(path):
    with open(path, "rb") as handle:
        return handle.read()


class LegacySchemaMigrationTests(unittest.TestCase):
    """Databases created before keyed anchoring are never silently trusted."""

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

    def _legacy_bytes(self):
        with sqlite3.connect(self.db_path) as conn:
            return (
                conn.execute(
                    "SELECT status, occurred_at FROM status_events "
                    "WHERE request_id = 'rid-1' ORDER BY seq"
                ).fetchall(),
                conn.execute(
                    "SELECT status, created_at FROM requests WHERE request_id = 'rid-1'"
                ).fetchone(),
            )

    def test_legacy_database_opens_and_keeps_serving_reads(self):
        self._create_legacy_database()
        before_events, before_request = self._legacy_bytes()
        store = RequestStore(self.db_path)
        # Ordinary reads still work; the timeline is returned intact.
        self.assertEqual(store.get("tenant-a", "rid-1")["status"], "processing")
        self.assertEqual(
            [e["status"] for e in store.audit("tenant-a", "rid-1")],
            ["accepted", "processing"],
        )
        # The upgrade added columns but never touched existing records.
        self.assertEqual(self._legacy_bytes(), (before_events, before_request))

    def test_legacy_evidence_is_explicitly_unprotected(self):
        self._create_legacy_database()
        store = RequestStore(self.db_path)
        with self.assertRaises(UnprotectedEvidenceError):
            store.evidence("tenant-a", "rid-1")
        with self.assertRaises(UnprotectedEvidenceError):
            store.verify_evidence("tenant-a", "rid-1")
        rebuilt = RequestStore(self.db_path)
        with self.assertRaises(UnprotectedEvidenceError):
            rebuilt.verify_evidence("tenant-a", "rid-1")

    def test_legacy_records_cannot_be_extended(self):
        self._create_legacy_database()
        store = RequestStore(self.db_path)
        with self.assertRaises(UnprotectedEvidenceError):
            store.transition("tenant-a", "rid-1", "completed")
        # The rejected extension performed no write: status and events
        # remain exactly as the legacy database had them.
        self.assertEqual(store.get("tenant-a", "rid-1")["status"], "processing")
        self.assertEqual(
            len(store.audit("tenant-a", "rid-1")), 2
        )
        with sqlite3.connect(self.db_path) as conn:
            self.assertIsNone(
                conn.execute(
                    "SELECT chain_hash FROM requests WHERE request_id = 'rid-1'"
                ).fetchone()[0]
            )
            self.assertIsNone(
                conn.execute(
                    "SELECT anchor_token FROM requests WHERE request_id = 'rid-1'"
                ).fetchone()[0]
            )

    def test_legacy_upgrade_does_not_overwrite_audit_records(self):
        self._create_legacy_database()
        store = RequestStore(self.db_path)  # performs the additive upgrade
        with sqlite3.connect(self.db_path) as conn:
            # Every legacy row keeps NULL evidence; nothing was backfilled.
            heads = conn.execute(
                "SELECT chain_hash, anchor_token FROM requests"
            ).fetchall()
            self.assertEqual(heads, [(None, None)])
            links = conn.execute(
                "SELECT chain_hash FROM status_events ORDER BY seq"
            ).fetchall()
            self.assertEqual(links, [(None,), (None,)])
            # The audit payload itself is byte-for-byte unchanged.
            events = conn.execute(
                "SELECT tenant_id, request_id, seq, status, occurred_at "
                "FROM status_events ORDER BY seq"
            ).fetchall()
        self.assertEqual(
            events,
            [
                ("tenant-a", "rid-1", 0, "accepted", "2026-01-01T00:00:00Z"),
                ("tenant-a", "rid-1", 1, "processing", "2026-01-01T00:00:01Z"),
            ],
        )

    def test_legacy_error_does_not_leak_record_data(self):
        self._create_legacy_database()
        store = RequestStore(self.db_path)
        try:
            store.verify_evidence("tenant-a", "rid-1")
        except UnprotectedEvidenceError as exc:
            message = str(exc)
        else:
            self.fail("expected UnprotectedEvidenceError")
        self.assertNotIn("rid-1", message)
        self.assertNotIn("s1", message)

    def test_new_records_alongside_legacy_are_protected_and_verifiable(self):
        self._create_legacy_database()
        store = RequestStore(self.db_path)
        receipt = store.submit("tenant-a", "subject-2", ["email"], "k2")
        store.transition("tenant-a", receipt["request_id"], "processing")
        self.assertTrue(store.verify_evidence("tenant-a", receipt["request_id"]))
        # The legacy record is still unprotected.
        with self.assertRaises(UnprotectedEvidenceError):
            store.verify_evidence("tenant-a", "rid-1")

    def test_legacy_tampered_timeline_is_reported_unprotected(self):
        self._create_legacy_database()
        with sqlite3.connect(self.db_path) as conn:
            # Tamper before the store ever opens the file.
            conn.execute(
                "UPDATE status_events SET status = 'failed' "
                "WHERE request_id = 'rid-1' AND seq = 1"
            )
        store = RequestStore(self.db_path)
        # No unkeyed chain can be trusted regardless of its contents.
        with self.assertRaises(UnprotectedEvidenceError):
            store.verify_evidence("tenant-a", "rid-1")


class KeyedAnchorTests(unittest.TestCase):
    """Keyed links and external anchors defeat database-only attackers."""

    MASTER = b"unit-test-master-secret"

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "evidence.db")

    def tearDown(self):
        self._tmp.cleanup()

    def _lifecycle(self, store, key="key-1"):
        receipt = store.submit("tenant-a", "subject-1", ["email"], key)
        store.transition("tenant-a", receipt["request_id"], "processing")
        store.transition("tenant-a", receipt["request_id"], "completed")
        return receipt

    # --- key configuration / rebuild ----------------------------------

    def test_explicit_key_verifies_across_rebuild(self):
        store = RequestStore(self.db_path, integrity_key=self.MASTER)
        receipt = self._lifecycle(store)
        rebuilt = RequestStore(self.db_path, integrity_key=self.MASTER)
        self.assertTrue(rebuilt.verify_evidence("tenant-a", receipt["request_id"]))
        self.assertEqual(
            rebuilt.evidence("tenant-a", receipt["request_id"]),
            store.evidence("tenant-a", receipt["request_id"]),
        )

    def test_different_key_fails_verification(self):
        store = RequestStore(self.db_path, integrity_key=self.MASTER)
        receipt = self._lifecycle(store)
        other = RequestStore(self.db_path, integrity_key=b"a-different-secret")
        # Ordinary tenant-scoped reads do not depend on the key...
        self.assertEqual(
            other.get("tenant-a", receipt["request_id"])["status"], "completed"
        )
        # ...but evidence written under another key can never verify.
        self.assertFalse(other.verify_evidence("tenant-a", receipt["request_id"]))

    def test_default_sidecar_key_enables_rebuild_and_is_protected(self):
        store = RequestStore(self.db_path)
        receipt = self._lifecycle(store)
        key_path = self.db_path + ".integrity.key"
        self.assertTrue(os.path.exists(key_path))
        mode = stat.S_IMODE(os.stat(key_path).st_mode)
        self.assertEqual(mode, 0o600)
        # No key material anywhere in the SQLite database file...
        with open(key_path, "rb") as handle:
            secret = handle.read().strip()
        with open(self.db_path, "rb") as handle:
            db_bytes = handle.read()
        self.assertNotIn(secret, db_bytes)
        # ...yet a rebuilt, default-configured store keeps verifying.
        rebuilt = RequestStore(self.db_path)
        self.assertTrue(rebuilt.verify_evidence("tenant-a", receipt["request_id"]))

    def test_explicit_key_creates_no_sidecar(self):
        RequestStore(self.db_path, integrity_key=self.MASTER)
        self.assertFalse(os.path.exists(self.db_path + ".integrity.key"))

    def test_key_file_configuration(self):
        key_file = os.path.join(self._tmp.name, "custom.key")
        with open(key_file, "wb") as handle:
            handle.write(b"file-based-secret\n")
        store = RequestStore(self.db_path, integrity_key_file=key_file)
        receipt = self._lifecycle(store)
        rebuilt = RequestStore(self.db_path, integrity_key_file=key_file)
        self.assertTrue(rebuilt.verify_evidence("tenant-a", receipt["request_id"]))
        self.assertFalse(
            os.path.exists(self.db_path + ".integrity.key")
        )

    def test_environment_key_configuration(self):
        os.environ["FORGETTING_EVIDENCE_INTEGRITY_KEY"] = "env-based-secret"
        self.addCleanup(os.environ.pop, "FORGETTING_EVIDENCE_INTEGRITY_KEY", None)
        store = RequestStore(self.db_path)
        receipt = self._lifecycle(store)
        self.assertFalse(os.path.exists(self.db_path + ".integrity.key"))
        rebuilt = RequestStore(self.db_path)
        self.assertTrue(rebuilt.verify_evidence("tenant-a", receipt["request_id"]))
        os.environ["FORGETTING_EVIDENCE_INTEGRITY_KEY"] = "wrong-env-secret"
        wrong = RequestStore(self.db_path)
        self.assertFalse(wrong.verify_evidence("tenant-a", receipt["request_id"]))

    def test_empty_explicit_key_rejected(self):
        with self.assertRaises(ValueError):
            RequestStore(self.db_path, integrity_key=b"")
        with self.assertRaises(ValueError):
            RequestStore(self.db_path, integrity_key="")

    # --- key material never reaches database / outputs ----------------

    def test_key_material_never_persisted_or_returned(self):
        secret = b"supersecret-master-key-DO-NOT-LEAK-1234567890"
        store = RequestStore(self.db_path, integrity_key=secret)
        receipt = self._lifecycle(store, key="key-secret")
        with open(self.db_path, "rb") as handle:
            db_bytes = handle.read()
        self.assertNotIn(secret, db_bytes)
        # Derived-key leakage would be just as fatal: neither raw HMAC
        # derived key may appear as stored text either.
        ev = store.evidence("tenant-a", receipt["request_id"])
        self.assertNotIn(secret.decode(), repr(ev))
        self.assertNotIn(secret.decode(), repr(receipt))
        with sqlite3.connect(self.db_path) as conn:
            for table in ("requests", "status_events"):
                for row in conn.execute(f"SELECT * FROM {table}"):
                    rendered = repr(row)
                    self.assertNotIn(secret.decode(), rendered)

    # --- the headline attacks -----------------------------------------

    def test_full_unkeyed_recomputation_replacement_fails(self):
        # Attacker model: arbitrary write access to the database, no key.
        # The attacker rewrites the timeline to end in 'failed' and
        # recomputes EVERY event link, the request head and the in-database
        # anchor field purely from the (public) preimage encoding, so the
        # timeline is internally consistent under the old unkeyed scheme;
        # only the missing protected key stands between the forgery and
        # verification success.
        import struct

        store = RequestStore(self.db_path, integrity_key=self.MASTER)
        receipt = self._lifecycle(store)
        rid = receipt["request_id"]

        def unkeyed_link(tenant, request, seq, status, occurred_at, pred):
            digest = hashlib.sha256()
            for value in (tenant, request, str(seq), status, occurred_at, pred):
                raw = value.encode()
                digest.update(struct.pack(">Q", len(raw)))
                digest.update(raw)
            return digest.hexdigest()

        with sqlite3.connect(self.db_path) as conn:
            # accepted -> failed: shorten the chain and flip seq 1.
            conn.execute(
                "DELETE FROM status_events WHERE request_id = ? AND seq = 2",
                (rid,),
            )
            conn.execute(
                "UPDATE status_events SET status = 'failed' "
                "WHERE request_id = ? AND seq = 1",
                (rid,),
            )
            predecessor = hashlib.sha256(b"").hexdigest()
            rows = conn.execute(
                "SELECT seq, status, occurred_at FROM status_events "
                "WHERE request_id = ? ORDER BY seq",
                (rid,),
            ).fetchall()
            for seq, status, occurred_at in rows:
                link = unkeyed_link(
                    "tenant-a", rid, seq, status, occurred_at, predecessor
                )
                conn.execute(
                    "UPDATE status_events SET chain_hash = ? "
                    "WHERE request_id = ? AND seq = ?",
                    (link, rid, seq),
                )
                predecessor = link
            # Head status matches the final forged event, so only the
            # keyed MAC and anchor can expose the replacement.
            conn.execute(
                "UPDATE requests SET status = 'failed', chain_hash = ?, "
                "anchor_token = ? WHERE request_id = ?",
                (
                    predecessor,
                    hashlib.sha256(predecessor.encode()).hexdigest(),
                    rid,
                ),
            )
        self.assertFalse(store.verify_evidence("tenant-a", rid))
        rebuilt = RequestStore(self.db_path, integrity_key=self.MASTER)
        self.assertFalse(rebuilt.verify_evidence("tenant-a", rid))

    def test_internally_consistent_cross_key_replacement_fails(self):
        # Strongest substitution: the attacker holds THEIR OWN valid key
        # and replaces the victim's events, head and anchor with a chain
        # that is fully consistent (links + anchor) under the attacker's
        # key -- including a valid anchor for the victim's request id.
        # Because the victim's key is in neither database, the forged
        # timeline verifies under the attacker key but never the victim
        # key.
        import struct

        victim = RequestStore(self.db_path, integrity_key=b"victim-key")
        receipt = self._lifecycle(victim)
        rid = receipt["request_id"]

        attacker_key = b"attacker-key"

        def derive(master, label):
            return hmac.new(
                master, b"forgetting-evidence/v1/" + label, hashlib.sha256
            ).digest()

        def keyed_link(event_key, tenant, request, seq, status, ts, pred):
            mac = hmac.new(event_key, digestmod=hashlib.sha256)
            for value in (tenant, request, str(seq), status, ts, pred):
                raw = value.encode()
                mac.update(struct.pack(">Q", len(raw)))
                mac.update(raw)
            return mac.hexdigest()

        def keyed_anchor(anchor_key, tenant, request, status, count, head):
            mac = hmac.new(anchor_key, digestmod=hashlib.sha256)
            label = b"request-anchor"
            mac.update(struct.pack(">Q", len(label)))
            mac.update(label)
            for value in (tenant, request, status, str(count), head):
                raw = value.encode()
                mac.update(struct.pack(">Q", len(raw)))
                mac.update(raw)
            return mac.hexdigest()

        with sqlite3.connect(self.db_path) as conn:
            # Read the persisted timeline metadata to reuse its shape.
            meta = conn.execute(
                "SELECT seq, occurred_at FROM status_events "
                "WHERE request_id = ? ORDER BY seq",
                (rid,),
            ).fetchall()
            # Forge an accepted -> failed timeline under the attacker key.
            forged_statuses = ("accepted", "failed")
            event_key = derive(attacker_key, b"event-mac")
            anchor_key = derive(attacker_key, b"anchor-mac")
            predecessor = hashlib.sha256(b"").hexdigest()
            forged_events = []
            for (seq, occurred_at), status in zip(meta, forged_statuses):
                link = keyed_link(
                    event_key, "tenant-a", rid, seq, status,
                    occurred_at, predecessor,
                )
                forged_events.append((seq, status, occurred_at, link))
                predecessor = link
            token = keyed_anchor(
                anchor_key, "tenant-a", rid, "failed",
                len(forged_events), predecessor,
            )
            conn.execute(
                "DELETE FROM status_events WHERE request_id = ?", (rid,)
            )
            conn.executemany(
                "INSERT INTO status_events "
                "(tenant_id, request_id, seq, status, occurred_at, chain_hash) "
                "VALUES ('tenant-a', ?, ?, ?, ?, ?)",
                [(rid, seq, status, ts, link)
                 for seq, status, ts, link in forged_events],
            )
            conn.execute(
                "UPDATE requests SET status = 'failed', chain_hash = ?, "
                "anchor_token = ? WHERE request_id = ?",
                (predecessor, token, rid),
            )

        # The replacement genuinely verifies for anyone holding the
        # attacker key (it is internally consistent)...
        attacker_view = RequestStore(self.db_path, integrity_key=attacker_key)
        self.assertTrue(attacker_view.verify_evidence("tenant-a", rid))
        # ...and fails for the victim, whose key was never in the database.
        self.assertFalse(victim.verify_evidence("tenant-a", rid))

    def test_forged_anchor_token_with_intact_links_fails(self):
        store = RequestStore(self.db_path, integrity_key=self.MASTER)
        receipt = self._lifecycle(store)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE requests SET anchor_token = ? WHERE request_id = ?",
                ("0" * 64, receipt["request_id"]),
            )
        self.assertFalse(
            store.verify_evidence("tenant-a", receipt["request_id"])
        )

    def test_anchor_token_cannot_be_copied_between_requests(self):
        store = RequestStore(self.db_path, integrity_key=self.MASTER)
        one = self._lifecycle(store, key="key-1")
        two = self._lifecycle(store, key="key-2")
        with sqlite3.connect(self.db_path) as conn:
            token = conn.execute(
                "SELECT anchor_token FROM requests WHERE request_id = ?",
                (two["request_id"],),
            ).fetchone()[0]
            # Give request one the same head context shape where possible
            # but substitute another request's anchor token.
            conn.execute(
                "UPDATE requests SET anchor_token = ? WHERE request_id = ?",
                (token, one["request_id"]),
            )
        self.assertFalse(store.verify_evidence("tenant-a", one["request_id"]))
        self.assertTrue(store.verify_evidence("tenant-a", two["request_id"]))

    def test_anchor_binds_event_count(self):
        store = RequestStore(self.db_path, integrity_key=self.MASTER)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "k")
        store.transition("tenant-a", receipt["request_id"], "processing")
        with sqlite3.connect(self.db_path) as conn:
            # Delete an event while keeping the stored head: the anchor's
            # event-count binding must reject the shortened timeline even
            # before chain linkage is considered (it fails either way).
            conn.execute(
                "DELETE FROM status_events WHERE request_id = ? AND seq = 1",
                (receipt["request_id"],),
            )
        self.assertFalse(
            store.verify_evidence("tenant-a", receipt["request_id"])
        )

    # --- external anchor implementation -------------------------------

    def test_external_anchor_is_used_and_verified(self):
        anchor = _RecordingAnchor()
        store = RequestStore(
            self.db_path, integrity_key=self.MASTER, anchor=anchor
        )
        receipt = store.submit("tenant-a", "subject-1", ["email"], "k")
        self.assertEqual(len(anchor.anchored), 1)
        self.assertEqual(anchor.anchored[0][:2], ("tenant-a", receipt["request_id"]))
        self.assertEqual(anchor.anchored[0][2], "accepted")
        self.assertEqual(anchor.anchored[0][3], 1)
        store.transition("tenant-a", receipt["request_id"], "processing")
        self.assertEqual(len(anchor.anchored), 2)
        self.assertEqual(anchor.anchored[1][2], "processing")
        self.assertEqual(anchor.anchored[1][3], 2)
        self.assertEqual(anchor.verify_calls, 0)
        self.assertTrue(
            store.verify_evidence("tenant-a", receipt["request_id"])
        )
        self.assertGreaterEqual(anchor.verify_calls, 1)

    def test_external_anchor_failure_is_negative_verdict(self):
        anchor = _RecordingAnchor()
        store = RequestStore(
            self.db_path, integrity_key=self.MASTER, anchor=anchor
        )
        receipt = self._lifecycle(store)
        anchor.fail = True
        self.assertFalse(
            store.verify_evidence("tenant-a", receipt["request_id"])
        )
        anchor.fail = False
        anchor.raise_on_verify = True
        self.assertFalse(
            store.verify_evidence("tenant-a", receipt["request_id"])
        )

    def test_noop_calls_neither_anchor_nor_alter_evidence(self):
        anchor = _RecordingAnchor()
        store = RequestStore(
            self.db_path, integrity_key=self.MASTER, anchor=anchor
        )
        receipt = store.submit("tenant-a", "subject-1", ["email"], "k")
        anchored_after_submit = len(anchor.anchored)
        # Idempotent submit replay and same-status replays generate no
        # new anchor and leave persisted evidence untouched.
        store.submit("tenant-a", "subject-1", ["email"], "k")
        store.transition("tenant-a", receipt["request_id"], "accepted")
        self.assertEqual(len(anchor.anchored), anchored_after_submit)
        with sqlite3.connect(self.db_path) as conn:
            token_before = conn.execute(
                "SELECT anchor_token FROM requests WHERE request_id = ?",
                (receipt["request_id"],),
            ).fetchone()[0]
        for bad in ("completed", "cancelled"):
            with self.assertRaises(InvalidStatusTransition):
                store.transition("tenant-a", receipt["request_id"], bad)
        with sqlite3.connect(self.db_path) as conn:
            token_after = conn.execute(
                "SELECT anchor_token FROM requests WHERE request_id = ?",
                (receipt["request_id"],),
            ).fetchone()[0]
        self.assertEqual(token_before, token_after)

    def test_anchor_implements_protocol(self):
        self.assertIsInstance(_RecordingAnchor(), IntegrityAnchor)


class _RecordingAnchor:
    """Deterministic test double for an external anchoring service."""

    def __init__(self):
        self.anchored: list[tuple] = []
        self.verify_calls = 0
        self.fail = False
        self.raise_on_verify = False

    def _token(self, tenant_id, request_id, status, event_count, head_hash):
        message = repr(
            (tenant_id, request_id, status, event_count, head_hash)
        ).encode()
        return hmac.new(b"external-anchor-secret", message, hashlib.sha256).hexdigest()

    def anchor(self, *, tenant_id, request_id, status, event_count, head_hash):
        self.anchored.append(
            (tenant_id, request_id, status, event_count, head_hash)
        )
        return self._token(
            tenant_id, request_id, status, event_count, head_hash
        )

    def verify(self, *, tenant_id, request_id, status, event_count,
               head_hash, token):
        self.verify_calls += 1
        if self.raise_on_verify:
            raise RuntimeError("anchor service unavailable")
        if self.fail:
            return False
        return hmac.compare_digest(
            self._token(
                tenant_id, request_id, status, event_count, head_hash
            ),
            token,
        )


if __name__ == "__main__":
    unittest.main()
