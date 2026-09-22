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
    _AnchorLog,
)


HEX64 = re.compile(r"^[0-9a-f]{64}$")
KEY = b"caller-held-integrity-key-0123456789"
OTHER_KEY = b"a-different-caller-held-key-zzzzzz"


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "evidence.db")

    def tearDown(self):
        self._tmp.cleanup()

    def _store(self, key=KEY):
        return RequestStore(self.db_path, integrity_key=key)

    def _anchor_path(self):
        return self.db_path + ".anchor"

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
        self.assertEqual(rebuilt.recover(), {"status": "consistent"})

    def test_in_memory_chain(self):
        store = RequestStore(":memory:", integrity_key=KEY)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        store.transition("tenant-a", receipt["request_id"], "processing")
        self.assertTrue(store.verify_evidence("tenant-a", receipt["request_id"]))
        self.assertTrue(HEX64.match(store.evidence("tenant-a", receipt["request_id"])["chain_hash"]))
        self.assertEqual(store.recover(), {"status": "consistent"})

    def test_custom_anchor_path(self):
        anchor = os.path.join(self._tmp.name, "elsewhere", "anchors.bin")
        store = RequestStore(
            self.db_path, anchor_path=anchor, integrity_key=KEY
        )
        receipt = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        self.assertTrue(os.path.exists(anchor))
        self.assertFalse(os.path.exists(self.db_path + ".anchor"))
        rebuilt = RequestStore(
            self.db_path, anchor_path=anchor, integrity_key=KEY
        )
        self.assertTrue(rebuilt.verify_evidence("tenant-a", receipt["request_id"]))

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

    def test_invalid_integrity_key_raises_value_error(self):
        for bad in ("", b""):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    RequestStore(self.db_path, integrity_key=bad)

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

    # --- key anchoring -------------------------------------------------

    def test_no_key_verify_returns_false(self):
        # A store opened without a key keeps full read/write behavior but
        # its chains carry no trust anchor.
        keyless = RequestStore(self.db_path)
        receipt = keyless.submit("tenant-a", "subject-1", ["email"], "key-1")
        keyless.transition("tenant-a", receipt["request_id"], "processing")
        self.assertFalse(keyless.verify_evidence("tenant-a", receipt["request_id"]))
        # Unknown / cross-tenant still raise identically.
        with self.assertRaises(RequestNotFound):
            keyless.verify_evidence("tenant-a", "missing")
        with self.assertRaises(RequestNotFound):
            keyless.verify_evidence("tenant-b", receipt["request_id"])
        # Opening with a key afterwards cannot conjure an anchor.
        keyed = self._store()
        self.assertEqual(keyed.recover(), {"status": "no_sidecar"})
        self.assertFalse(keyed.verify_evidence("tenant-a", receipt["request_id"]))

    def test_wrong_key_returns_false(self):
        store, receipt = self._fresh_lifecycle()
        attacker = self._store(key=OTHER_KEY)
        self.assertEqual(attacker.recover(), {"status": "corrupt_anchor"})
        self.assertFalse(
            attacker.verify_evidence("tenant-a", receipt["request_id"])
        )
        # The correct key still verifies.
        self.assertTrue(store.verify_evidence("tenant-a", receipt["request_id"]))

    def test_missing_sidecar_returns_false(self):
        store, receipt = self._fresh_lifecycle()
        os.remove(self._anchor_path())
        self.assertEqual(store.recover(), {"status": "no_sidecar"})
        self.assertFalse(store.verify_evidence("tenant-a", receipt["request_id"]))
        rebuilt = self._store()
        self.assertEqual(rebuilt.recover(), {"status": "no_sidecar"})
        self.assertFalse(
            rebuilt.verify_evidence("tenant-a", receipt["request_id"])
        )

    def test_corrupt_sidecar_returns_false(self):
        store, receipt = self._fresh_lifecycle()
        path = self._anchor_path()
        raw = bytearray(open(path, "rb").read())
        raw[-1] ^= 0xFF
        with open(path, "wb") as handle:
            handle.write(raw)
        self.assertEqual(store.recover(), {"status": "corrupt_anchor"})
        self.assertFalse(store.verify_evidence("tenant-a", receipt["request_id"]))

    def test_truncated_frame_returns_false(self):
        store, receipt = self._fresh_lifecycle()
        path = self._anchor_path()
        with open(path, "rb") as handle:
            raw = handle.read()
        # Keep the header and drop only part of the last frame.
        with open(path, "wb") as handle:
            handle.write(raw[:-7])
        self.assertEqual(store.recover(), {"status": "corrupt_anchor"})
        self.assertFalse(store.verify_evidence("tenant-a", receipt["request_id"]))

    def test_attacker_full_recompute_and_replace_still_fails(self):
        # Attacker edits SQLite, recomputes every public chain hash and
        # rebuilds the whole sidecar under a key they control. The real
        # caller's key must reject it.
        store, receipt = self._fresh_lifecycle(("processing",))
        with sqlite3.connect(self.db_path) as conn:
            # Rewrite the genesis event to a different status and recompute
            # every public link (the plain-hash algorithm is public).
            import struct

            def plain_link(tenant, rid, seq, status, ts, predecessor):
                digest = hashlib.sha256()
                for field in (tenant, rid, str(seq), status, ts, predecessor):
                    raw = field.encode()
                    digest.update(struct.pack(">Q", len(raw)))
                    digest.update(raw)
                return digest.hexdigest()

            rows = conn.execute(
                "SELECT seq, status, occurred_at FROM status_events "
                "WHERE request_id = ? ORDER BY seq",
                (receipt["request_id"],),
            ).fetchall()
            predecessor = hashlib.sha256(b"").hexdigest()
            forged = []
            for index, (seq, status, ts) in enumerate(rows):
                status = "failed" if seq == 0 else status
                link = plain_link(
                    "tenant-a", receipt["request_id"], seq, status, ts, predecessor
                )
                conn.execute(
                    "UPDATE status_events SET status = ?, chain_hash = ? "
                    "WHERE request_id = ? AND seq = ?",
                    (status, link, receipt["request_id"], seq),
                )
                forged.append((seq, link))
                predecessor = link
            conn.execute(
                "UPDATE requests SET status = 'failed', chain_hash = ? "
                "WHERE request_id = ?",
                (forged[-1][1], receipt["request_id"]),
            )
        # Rebuild a fully consistent-looking sidecar under attacker key.
        attacker_anchor = _AnchorLog(self._anchor_path(), OTHER_KEY)
        # Truncate by overwriting the file through a fresh log instance.
        open(self._anchor_path(), "wb").close()
        attacker_anchor.initialize_locked()
        prev = b"\x00" * 32
        for frame_seq, (seq, link) in enumerate(forged):
            attacker_anchor.append_locked(
                frame_seq,
                "tenant-a",
                receipt["request_id"],
                seq,
                link,
                prev,
            )
            prev = attacker_anchor.last_label()
        self.assertEqual(store.recover(), {"status": "corrupt_anchor"})
        self.assertFalse(store.verify_evidence("tenant-a", receipt["request_id"]))
        rebuilt = self._store()
        self.assertFalse(
            rebuilt.verify_evidence("tenant-a", receipt["request_id"])
        )

    # --- crash consistency / recover -----------------------------------

    def test_interrupted_submit_detected_after_rebuild(self):
        # Simulate: durable anchor frame appended, SQLite commit lost
        # (e.g. process killed between fsync and COMMIT).
        anchor = _AnchorLog(self._anchor_path(), KEY)
        anchor.initialize_locked()
        anchor.append_locked(
            0, "tenant-a", "phantom-request", 0, "0" * 64, b"\x00" * 32
        )
        self.assertFalse(os.path.exists(self.db_path))
        # Constructing the store creates an empty database; the lone
        # frame still identifies an interrupted commit.
        rebuilt = self._store()
        self.assertEqual(rebuilt.recover(), {"status": "interrupted"})
        with self.assertRaises(RequestNotFound):
            rebuilt.verify_evidence("tenant-a", "phantom-request")
        # Writes are refused until the operator resolves the state.
        with self.assertRaises(RuntimeError):
            rebuilt.submit("tenant-a", "subject-1", ["email"], "key-1")

    def test_interrupted_transition_detected(self):
        store, receipt = self._fresh_lifecycle(("processing",))
        # Durable frame for the next event exists but its SQLite commit
        # was lost.
        anchor = _AnchorLog(self._anchor_path(), KEY)
        anchor.append_locked(
            2, "tenant-a", receipt["request_id"], 2, "f" * 64,
            anchor.last_label(),
        )
        self.assertEqual(store.recover(), {"status": "interrupted"})
        self.assertFalse(store.verify_evidence("tenant-a", receipt["request_id"]))
        rebuilt = self._store()
        self.assertEqual(rebuilt.recover(), {"status": "interrupted"})
        self.assertFalse(
            rebuilt.verify_evidence("tenant-a", receipt["request_id"])
        )
        # Further writes (even along a legal edge) are refused rather
        # than hiding the unresolved state.
        with self.assertRaises(RuntimeError):
            rebuilt.transition("tenant-a", receipt["request_id"], "completed")
        with self.assertRaises(RuntimeError):
            rebuilt.submit("tenant-a", "subject-2", ["email"], "key-2")

    def test_diverged_sqlite_without_anchor_detected(self):
        store, receipt = self._fresh_lifecycle()
        with self._raw() as conn:
            # An event row the sidecar never sealed.
            conn.execute(
                "INSERT INTO status_events "
                "(tenant_id, request_id, seq, status, occurred_at, chain_hash) "
                "VALUES ('tenant-a', ?, 9, 'failed', '2026-01-01T00:00:00Z', ?)",
                (receipt["request_id"], "a" * 64),
            )
        self.assertEqual(store.recover(), {"status": "diverged"})
        self.assertFalse(store.verify_evidence("tenant-a", receipt["request_id"]))

    def test_recover_never_writes_or_repairs(self):
        store, receipt = self._fresh_lifecycle()
        path = self._anchor_path()
        clean_anchor = snapshot(path)
        clean_db = snapshot(self.db_path)
        # Corrupt, then call recover repeatedly: nothing changes.
        raw = bytearray(clean_anchor)
        raw[-1] ^= 0xFF
        with open(path, "wb") as handle:
            handle.write(raw)
        before = {
            "db": snapshot(self.db_path),
            "anchor": snapshot(path),
        }
        for _ in range(3):
            result = store.recover()
            self.assertEqual(result, {"status": "corrupt_anchor"})
        self.assertEqual(snapshot(self.db_path), before["db"])
        self.assertEqual(snapshot(path), before["anchor"])
        # Restore the authentic sidecar, then simulate a realistic
        # interrupted commit: one more durable frame whose SQLite commit
        # was lost. This too is never auto-repaired.
        with open(path, "wb") as handle:
            handle.write(clean_anchor)
        anchor = _AnchorLog(path, KEY)
        frames, _partial = anchor.replay()
        next_frame_seq = len(frames)
        with self._raw() as conn:
            event_count = conn.execute(
                "SELECT count(*) FROM status_events WHERE request_id = ?",
                (receipt["request_id"],),
            ).fetchone()[0]
        anchor.append_locked(
            next_frame_seq,
            "tenant-a",
            receipt["request_id"],
            event_count,
            "1" * 64,
            anchor.last_label(),
        )
        for _ in range(2):
            self.assertEqual(store.recover(), {"status": "interrupted"})
        self.assertFalse(store.verify_evidence("tenant-a", receipt["request_id"]))
        # The authentic SQLite database was never touched by recovery.
        self.assertEqual(snapshot(self.db_path), clean_db)

    def test_interruption_fails_closed_for_every_tenant(self):
        # Global fail-closed: an interrupted commit anywhere invalidates
        # evidence for every request, including an unaffected tenant's.
        store = self._store()
        a = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        b = store.submit("tenant-b", "subject-1", ["email"], "key-2")
        self.assertTrue(store.verify_evidence("tenant-a", a["request_id"]))
        self.assertTrue(store.verify_evidence("tenant-b", b["request_id"]))
        anchor = _AnchorLog(self._anchor_path(), KEY)
        anchor.append_locked(
            2, "tenant-a", a["request_id"], 1, "9" * 64, anchor.last_label()
        )
        self.assertEqual(store.recover(), {"status": "interrupted"})
        self.assertFalse(store.verify_evidence("tenant-a", a["request_id"]))
        self.assertFalse(store.verify_evidence("tenant-b", b["request_id"]))

    def test_key_material_never_persisted_or_logged(self):
        token = "UNIQUE-KEY-TOKEN-abcdef"
        store = RequestStore(self.db_path, integrity_key=token)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        store.transition("tenant-a", receipt["request_id"], "processing")
        store.verify_evidence("tenant-a", receipt["request_id"])
        store.recover()
        with open(self.db_path, "rb") as handle:
            db_bytes = handle.read()
        with open(self._anchor_path(), "rb") as handle:
            anchor_bytes = handle.read()
        token_bytes = token.encode()
        self.assertNotIn(token_bytes, db_bytes)
        self.assertNotIn(token_bytes, anchor_bytes)
        # No key-equivalent material: the HMAC label is 32 random bytes;
        # ensure the raw key and common encodings never appear.
        self.assertNotIn(token_bytes.hex().encode(), anchor_bytes)
        self.assertNotIn(token, repr(store.evidence("tenant-a", receipt["request_id"])))
        self.assertNotIn(token, repr(store.audit("tenant-a", receipt["request_id"])))
        self.assertNotIn(token, repr(store.recover()))

        import io
        import logging

        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        logger = logging.getLogger("forgetting_evidence.requests")
        logger.addHandler(handler)
        old_level = logger.level
        logger.setLevel(logging.DEBUG)
        try:
            store.transition("tenant-a", receipt["request_id"], "completed")
        finally:
            logger.removeHandler(handler)
            logger.setLevel(old_level)
        self.assertNotIn(token, stream.getvalue())

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
                (flipped, receipt["request_id"],),
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
        # Replays must not have appended anchor frames.
        frames, partial = _AnchorLog(self._anchor_path(), KEY).replay()
        self.assertFalse(partial)
        self.assertEqual(len(frames), 3)

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
        before = {
            "db": snapshot(self.db_path),
            "anchor": snapshot(self._anchor_path()),
        }
        for _ in range(5):
            self.assertTrue(store.verify_evidence("tenant-a", receipt["request_id"]))
        self.assertEqual(snapshot(self.db_path), before["db"])
        self.assertEqual(snapshot(self._anchor_path()), before["anchor"])

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
        frames, partial = _AnchorLog(self._anchor_path(), KEY).replay()
        self.assertFalse(partial)
        self.assertEqual(len(frames), len(events))

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
    """Databases created before chain hashes upgrade structurally, but
    legacy rows carry no caller-key anchor and can never verify."""

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

    def test_legacy_database_upgrades_but_never_verifies_without_anchor(self):
        self._create_legacy_database()
        store = RequestStore(self.db_path, integrity_key=KEY)
        ev = store.evidence("tenant-a", "rid-1")
        self.assertEqual(ev["status"], "processing")
        self.assertEqual(ev["event_count"], 2)
        self.assertTrue(HEX64.match(ev["chain_hash"]))
        # No trusted anchor exists for legacy data.
        self.assertEqual(store.recover(), {"status": "no_sidecar"})
        self.assertFalse(store.verify_evidence("tenant-a", "rid-1"))
        rebuilt = RequestStore(self.db_path, integrity_key=KEY)
        self.assertFalse(rebuilt.verify_evidence("tenant-a", "rid-1"))
        # Writes onto the unanchored legacy chain are refused rather than
        # returning false success.
        with self.assertRaises(RuntimeError):
            rebuilt.transition("tenant-a", "rid-1", "completed")
        self.assertEqual(
            rebuilt.get("tenant-a", "rid-1")["status"], "processing"
        )

    def test_legacy_tampered_timeline_fails_after_upgrade(self):
        self._create_legacy_database()
        with sqlite3.connect(self.db_path) as conn:
            # Tamper before the store ever opens the file.
            conn.execute(
                "UPDATE status_events SET status = 'failed' "
                "WHERE request_id = 'rid-1' AND seq = 1"
            )
        store = RequestStore(self.db_path, integrity_key=KEY)
        self.assertFalse(store.verify_evidence("tenant-a", "rid-1"))
        self.assertEqual(store.recover()["status"], "no_sidecar")


if __name__ == "__main__":
    unittest.main()
