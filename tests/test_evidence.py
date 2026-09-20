import hashlib
import hmac
import os
import re
import shutil
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor

from forgetting_evidence.requests import (
    IntegrityAnchor,
    IntegrityConfigurationError,
    InvalidStatusTransition,
    LegacyEvidenceUnsupported,
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

    def test_genesis_hash_is_keyed_hmac_of_documented_preimage(self):
        # Independent recomputation guards the length-prefixed HMAC
        # encoding and the external key binding.
        key = bytes(range(32))
        store = RequestStore(self.db_path, integrity_key=key)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        events = store.audit("tenant-a", receipt["request_id"])
        import struct

        purpose = "forgetting-evidence/status-event/v1"
        values = (
            "tenant-a",
            receipt["request_id"],
            "0",
            "accepted",
            events[0]["occurred_at"],
            hashlib.sha256(b"").hexdigest(),
        )
        digest = hmac.new(key, b"", hashlib.sha256)
        for value in (purpose, *values):
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
    """Databases created before keyed evidence are never silently trusted."""

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
            return {
                "request": conn.execute(
                    "SELECT request_id, tenant_id, idempotency_key, "
                    "subject_id, scopes_json, status, created_at "
                    "FROM requests WHERE request_id = 'rid-1'"
                ).fetchone(),
                "events": conn.execute(
                    "SELECT tenant_id, request_id, seq, status, occurred_at "
                    "FROM status_events ORDER BY seq"
                ).fetchall(),
            }

    def test_legacy_database_verifies_false_without_backfill(self):
        self._create_legacy_database()
        before = self._legacy_bytes()
        store = RequestStore(self.db_path)
        # Readable, but explicitly unprotected...
        self.assertEqual(store.get("tenant-a", "rid-1")["status"], "processing")
        self.assertEqual(
            [e["status"] for e in store.audit("tenant-a", "rid-1")],
            ["accepted", "processing"],
        )
        # ...and never reported as trustworthy evidence.
        with self.assertRaises(LegacyEvidenceUnsupported):
            store.evidence("tenant-a", "rid-1")
        self.assertFalse(store.verify_evidence("tenant-a", "rid-1"))
        # Rebuild does not change the verdict either.
        rebuilt = RequestStore(self.db_path)
        self.assertFalse(rebuilt.verify_evidence("tenant-a", "rid-1"))
        with self.assertRaises(LegacyEvidenceUnsupported):
            rebuilt.evidence("tenant-a", "rid-1")
        # The upgrade is additive: original request/event rows were
        # neither overwritten nor backfilled.
        after = self._legacy_bytes()
        self.assertEqual(before, after)

    def test_legacy_request_cannot_be_extended(self):
        self._create_legacy_database()
        store = RequestStore(self.db_path)
        with self.assertRaises(LegacyEvidenceUnsupported):
            store.transition("tenant-a", "rid-1", "completed")
        # Even a same-status replay must not attach a fresh anchor to a
        # legacy record.
        with self.assertRaises(LegacyEvidenceUnsupported):
            store.transition("tenant-a", "rid-1", "processing")
        self.assertFalse(store.verify_evidence("tenant-a", "rid-1"))
        with sqlite3.connect(self.db_path) as conn:
            self.assertIsNone(
                conn.execute(
                    "SELECT anchor_value FROM requests WHERE request_id = 'rid-1'"
                ).fetchone()[0]
            )

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

    def test_new_requests_in_upgraded_database_are_protected(self):
        self._create_legacy_database()
        store = RequestStore(self.db_path)
        receipt = store.submit("tenant-a", "subject-9", ["email"], "key-new")
        self.assertTrue(store.verify_evidence("tenant-a", receipt["request_id"]))
        store.transition("tenant-a", receipt["request_id"], "processing")
        self.assertTrue(store.verify_evidence("tenant-a", receipt["request_id"]))
        # The legacy row is still untouched and untrusted.
        self.assertFalse(store.verify_evidence("tenant-a", "rid-1"))
        rebuilt = RequestStore(self.db_path)
        self.assertTrue(
            rebuilt.verify_evidence("tenant-a", receipt["request_id"])
        )
        self.assertFalse(rebuilt.verify_evidence("tenant-a", "rid-1"))


class ExternalTrustAnchorTests(unittest.TestCase):
    """The integrity basis must not live in SQLite."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "evidence.db")

    def tearDown(self):
        self._tmp.cleanup()

    def _fresh_lifecycle(self, **kwargs):
        store = RequestStore(self.db_path, **kwargs)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        store.transition("tenant-a", receipt["request_id"], "processing")
        store.transition("tenant-a", receipt["request_id"], "completed")
        return store, receipt

    def test_default_sidecar_files_exist_outside_database(self):
        store, receipt = self._fresh_lifecycle()
        base = self.db_path
        self.assertTrue(os.path.exists(base + ".integrity.key"))
        self.assertTrue(os.path.exists(base + ".integrity.heads"))
        mode = os.stat(base + ".integrity.key").st_mode & 0o777
        self.assertEqual(mode, 0o600)
        # The raw key material never appears inside the database or in
        # any evidence surface.
        with open(base + ".integrity.key", "rb") as handle:
            secret = handle.read()
        with sqlite3.connect(self.db_path) as conn:
            pages = b"".join(
                str(row).encode()
                for row in conn.execute(
                    "SELECT name, sql FROM sqlite_master"
                ).fetchall()
            )
            for table in ("requests", "status_events", "evidence_meta"):
                pages += b"||".join(
                    b"|".join(
                        b"" if v is None else str(v).encode()
                        for v in row
                    )
                    for row in conn.execute(f"SELECT * FROM {table}").fetchall()
                )
        self.assertNotIn(secret, pages)
        rendered = repr(
            (
                store.evidence("tenant-a", receipt["request_id"]),
                store.audit("tenant-a", receipt["request_id"]),
            )
        ).encode()
        self.assertNotIn(secret, rendered)

    def test_rebuild_without_external_files_cannot_verify(self):
        _, receipt = self._fresh_lifecycle()
        # Attacker obtains only the SQLite file (no key, no head ledger).
        stolen = os.path.join(self._tmp.name, "stolen.db")
        shutil.copyfile(self.db_path, stolen)
        with self.assertRaises(IntegrityConfigurationError):
            RequestStore(stolen)

    def test_full_database_recompute_with_key_cannot_move_external_head(self):
        store, receipt = self._fresh_lifecycle()
        # Copy the whole deployment, including the key: the external
        # ledger holds the previously attested head, so forging a
        # different timeline and recomputing events/heads/anchors still
        # has to disagree with that recorded state.
        alt_dir = os.path.join(self._tmp.name, "alt")
        os.makedirs(alt_dir)
        alt_db = os.path.join(alt_dir, "evidence.db")
        for suffix in (".integrity.key", ".integrity.heads"):
            shutil.copyfile(self.db_path + suffix, alt_db + suffix)
        # Build a forged database from scratch using the stolen key.
        with open(self.db_path + ".integrity.key", "rb") as handle:
            key = handle.read()
        forged = RequestStore(alt_db, integrity_key=key)
        fr = forged.submit("tenant-a", "subject-1", ["email"], "key-1")
        forged.transition("tenant-a", fr["request_id"], "failed")
        # Overwrite the *original* database rows with the forged request's
        # id while reusing its recomputed chain/anchor fields wholesale.
        with sqlite3.connect(alt_db) as conn:
            frow = conn.execute(
                "SELECT chain_hash, anchor_value, status FROM requests "
                "WHERE request_id = ?",
                (fr["request_id"],),
            ).fetchone()
            fevents = conn.execute(
                "SELECT seq, status, occurred_at, chain_hash "
                "FROM status_events WHERE request_id = ? ORDER BY seq",
                (fr["request_id"],),
            ).fetchall()
        with sqlite3.connect(alt_db) as conn:
            conn.execute(
                "UPDATE requests SET request_id = ?, chain_hash = ?, "
                "anchor_value = ?, status = ? WHERE request_id = ?",
                (receipt["request_id"], frow[0], frow[1], frow[2], fr["request_id"]),
            )
            conn.execute(
                "DELETE FROM status_events WHERE request_id = ?",
                (receipt["request_id"],),
            )
            for seq, status, occurred_at, chain in fevents:
                conn.execute(
                    "INSERT INTO status_events "
                    "(tenant_id, request_id, seq, status, occurred_at, chain_hash) "
                    "VALUES ('tenant-a', ?, ?, ?, ?, ?)",
                    (receipt["request_id"], seq, status, occurred_at, chain),
                )
            # Attacker recomputes every in-database anchor field too.
            conn.execute(
                "UPDATE evidence_meta SET domain = ?, value = ? "
                "WHERE domain = ?",
                (
                    "head\x1ftenant-a\x1f" + receipt["request_id"],
                    frow[1],
                    "head\x1ftenant-a\x1f" + fr["request_id"],
                ),
            )
        # The external ledger still records the genuine head; the
        # substituted anchor cannot match it.
        stolen_store = RequestStore(alt_db, integrity_key=key)
        self.assertFalse(
            stolen_store.verify_evidence("tenant-a", receipt["request_id"])
        )

    def test_wrong_key_fails_to_open_protected_database(self):
        self._fresh_lifecycle()
        with self.assertRaises(IntegrityConfigurationError):
            RequestStore(self.db_path, integrity_key=b"x" * 32)

    def test_explicit_key_rebuild_verifies(self):
        key = bytes((i * 7 + 3) % 256 for i in range(32))
        store, receipt = self._fresh_lifecycle(integrity_key=key)
        rebuilt = RequestStore(self.db_path, integrity_key=key)
        self.assertTrue(
            rebuilt.verify_evidence("tenant-a", receipt["request_id"])
        )
        # The auto-generated sidecar key is not created when a key is
        # supplied explicitly.
        self.assertFalse(os.path.exists(self.db_path + ".integrity.key"))

    def test_external_ledger_tamper_breaks_live_verification(self):
        store, receipt = self._fresh_lifecycle()
        ledger = self.db_path + ".integrity.heads"
        with open(ledger, "rb") as handle:
            state = bytearray(handle.read())
        state[-5] ^= 0x01
        with open(ledger, "wb") as handle:
            handle.write(bytes(state))
        # An already-open store strictly reads current persisted state
        # and never repairs it: the corrupt ledger fails closed.
        self.assertFalse(
            store.verify_evidence("tenant-a", receipt["request_id"])
        )
        # Reopening reconciles the tag-only ledger from key-verified DB
        # anchors, restoring the genuine state. Healing copies only tags
        # that re-verify under the secret key, so it can never admit a
        # forged head.
        rebuilt = RequestStore(self.db_path)
        self.assertTrue(
            rebuilt.verify_evidence("tenant-a", receipt["request_id"])
        )

    def test_deleted_ledger_fails_until_writer_reconciles(self):
        _, receipt = self._fresh_lifecycle()
        os.unlink(self.db_path + ".integrity.heads")
        rebuilt = RequestStore(self.db_path)
        # Reopening reconciles the tag-only ledger from key-verified DB
        # anchors, restoring the genuine state; a forged DB without the
        # key still cannot produce valid tags to reconcile from.
        self.assertTrue(
            rebuilt.verify_evidence("tenant-a", receipt["request_id"])
        )

    def test_custom_anchor_implementation_is_honoured(self):
        class RecordingAnchor(IntegrityAnchor):
            def __init__(self):
                self.calls = 0

            def attest(self, purpose, parts):
                self.calls += 1
                return hmac.new(
                    b"z" * 32,
                    _encode(purpose, parts),
                    hashlib.sha256,
                ).hexdigest()

            def verify_attestation(self, purpose, parts, tag):
                return hmac.compare_digest(self.attest(purpose, parts), tag)

        import struct as _struct

        def _encode(purpose, parts):
            out = bytearray()
            for field in (purpose, *parts):
                raw = field.encode()
                out += _struct.pack(">Q", len(raw))
                out += raw
            return bytes(out)

        anchor = RecordingAnchor()
        store = RequestStore(self.db_path, integrity_anchor=anchor)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        self.assertGreater(anchor.calls, 0)
        self.assertTrue(store.verify_evidence("tenant-a", receipt["request_id"]))

    def test_key_material_never_in_errors_or_logs(self):
        wrong = b"a" * 32
        self._fresh_lifecycle(integrity_key=bytes(range(32)))
        try:
            RequestStore(self.db_path, integrity_key=wrong)
        except IntegrityConfigurationError as exc:
            message = str(exc)
        else:
            self.fail("expected IntegrityConfigurationError")
        self.assertNotIn(wrong.hex(), message)
        self.assertNotIn(wrong.decode(), message)
        import io
        import logging

        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        logger = logging.getLogger("forgetting_evidence.requests")
        logger.addHandler(handler)
        try:
            store = RequestStore(self.db_path, integrity_key=bytes(range(32)))
            receipt = store.submit("tenant-a", "s", ["email"], "k")
            store.transition("tenant-a", receipt["request_id"], "failed")
        finally:
            logger.removeHandler(handler)
        self.assertNotIn(bytes(range(32)).hex(), stream.getvalue())


if __name__ == "__main__":
    unittest.main()
