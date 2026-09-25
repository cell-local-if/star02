"""Tests for the cross-restart trust anchors and full-chain verification.

The audit chain hashes already proved event order and the request head;
the anchors add the one thing the database cannot provide itself:
trust material held outside the database file. These tests cover the
clean lifecycle (anchors land atomically with acceptance and every
actual status change, survive rebuilds and never drift on repeated
reads), the argument/access boundary, and the tampering matrix --
including the attacker who recomputes every event link, the request
head and the public anchor rows: without the externally held anchor
key such a chain must still verify False.
"""

import hashlib
import os
import re
import sqlite3
import struct
import tempfile
import unittest

from forgetting_evidence.requests import (
    RequestNotFound,
    RequestStore,
)

HEX64 = re.compile(r"^[0-9a-f]{64}$")
GENESIS_PREDECESSOR = hashlib.sha256(b"").hexdigest()

_REASONS = {
    "event_chain_invalid",
    "request_head_mismatch",
    "anchors_missing",
    "anchor_event_mismatch",
    "anchor_sequence_broken",
    "anchor_head_mismatch",
    "anchor_authentication_failed",
}


def _chain_hash(tenant_id, request_id, seq, status, occurred_at, predecessor):
    """Independent recomputation of one event link (test-only)."""
    digest = hashlib.sha256()
    for field in (
        tenant_id,
        request_id,
        str(seq),
        status,
        occurred_at,
        predecessor,
    ):
        raw = field.encode("utf-8")
        digest.update(struct.pack(">Q", len(raw)))
        digest.update(raw)
    return digest.hexdigest()


def snapshot(path):
    with open(path, "rb") as handle:
        return handle.read()


class AnchorLifecycleTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "evidence.db")

    def tearDown(self):
        self._tmp.cleanup()

    def _store(self, **kwargs):
        return RequestStore(self.db_path, **kwargs)

    def _lifecycle(self, store=None):
        store = store or self._store()
        receipt = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        store.transition("tenant-a", receipt["request_id"], "processing")
        store.transition("tenant-a", receipt["request_id"], "completed")
        return store, receipt

    def test_anchor_rows_match_events_one_per_actual_change(self):
        store, receipt = self._lifecycle()
        with sqlite3.connect(self.db_path) as conn:
            anchors = conn.execute(
                "SELECT anchor_seq, event_seq, event_hash, anchor_hash "
                "FROM chain_anchors WHERE request_id = ? ORDER BY event_seq",
                (receipt["request_id"],),
            ).fetchall()
            events = conn.execute(
                "SELECT seq, chain_hash FROM status_events "
                "WHERE request_id = ? ORDER BY seq",
                (receipt["request_id"],),
            ).fetchall()
            head = conn.execute(
                "SELECT anchor_seq, anchor_hash FROM chain_anchor_head"
            ).fetchone()
        self.assertEqual(len(anchors), 3)
        self.assertEqual([row[1] for row in anchors], [0, 1, 2])
        self.assertTrue(all(HEX64.match(row[2]) for row in anchors))
        self.assertTrue(all(HEX64.match(row[3]) for row in anchors))
        # Anchor n names event n's own chain link.
        self.assertEqual(
            [row[2] for row in anchors], [row[1] for row in events]
        )
        # Store-wide sequences are gap-free from one and the head pins
        # the final anchor.
        self.assertEqual([row[0] for row in anchors], [1, 2, 3])
        self.assertEqual(head[0], 3)
        self.assertEqual(head[1], anchors[-1][3])

    def test_idempotent_replay_and_same_status_add_no_anchor(self):
        store = self._store()
        receipt = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        store.submit("tenant-a", "subject-1", ["email"], "key-1")
        store.transition("tenant-a", receipt["request_id"], "accepted")
        with sqlite3.connect(self.db_path) as conn:
            count = conn.execute(
                "SELECT count(*) FROM chain_anchors"
            ).fetchone()[0]
        self.assertEqual(count, 1)

    def test_clean_chain_verifies_at_every_stage(self):
        store = self._store()
        receipt = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        self.assertTrue(store.verify_chain("tenant-a", receipt["request_id"]))
        self.assertTrue(store.verify_evidence("tenant-a", receipt["request_id"]))
        self.assertEqual(
            store.diagnose_chain("tenant-a", receipt["request_id"]),
            {"trusted": True, "reason": None},
        )
        store.transition("tenant-a", receipt["request_id"], "processing")
        self.assertTrue(store.verify_chain("tenant-a", receipt["request_id"]))
        store.transition("tenant-a", receipt["request_id"], "failed")
        self.assertTrue(store.verify_chain("tenant-a", receipt["request_id"]))

    def test_chain_verifies_after_rebuild(self):
        store, receipt = self._lifecycle()
        rebuilt = self._store()
        self.assertTrue(rebuilt.verify_chain("tenant-a", receipt["request_id"]))
        # A rebuilt instance can extend the anchored chain further.
        rebuilt.transition  # terminal already; check a fresh request too
        other = rebuilt.submit("tenant-b", "subject-2", ["email"], "key-2")
        rebuilt.transition("tenant-b", other["request_id"], "failed")
        self.assertTrue(rebuilt.verify_chain("tenant-b", other["request_id"]))
        self.assertTrue(rebuilt.verify_chain("tenant-a", receipt["request_id"]))

    def test_global_anchor_chain_spans_tenants_and_requests(self):
        store = self._store()
        one = store.submit("tenant-a", "s1", ["email"], "k1")
        two = store.submit("tenant-b", "s2", ["email"], "k2")
        store.transition("tenant-a", one["request_id"], "failed")
        store.transition("tenant-b", two["request_id"], "failed")
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT anchor_seq, tenant_id, request_id, event_seq "
                "FROM chain_anchors ORDER BY anchor_seq"
            ).fetchall()
        self.assertEqual(len(rows), 4)
        self.assertEqual([row[0] for row in rows], [1, 2, 3, 4])
        self.assertEqual(
            [(row[1], row[3]) for row in rows],
            [
                ("tenant-a", 0),
                ("tenant-b", 0),
                ("tenant-a", 1),
                ("tenant-b", 1),
            ],
        )
        self.assertTrue(store.verify_chain("tenant-a", one["request_id"]))
        self.assertTrue(store.verify_chain("tenant-b", two["request_id"]))

    def test_repeated_verification_and_diagnosis_change_nothing(self):
        store, receipt = self._lifecycle()
        before = snapshot(self.db_path)
        for _ in range(5):
            self.assertTrue(store.verify_chain("tenant-a", receipt["request_id"]))
            self.assertTrue(
                store.verify_evidence("tenant-a", receipt["request_id"])
            )
            self.assertTrue(
                store.diagnose_chain("tenant-a", receipt["request_id"])[
                    "trusted"
                ]
            )
        self.assertEqual(before, snapshot(self.db_path))

    def test_anchor_sidecar_lives_outside_database(self):
        self._lifecycle()
        sidecar = os.path.join(self._tmp.name, "nested", ".evidence.db.anchor-key")
        self.assertTrue(os.path.exists(sidecar))
        # Owner-only permissions.
        mode = os.stat(sidecar).st_mode & 0o777
        self.assertEqual(mode, 0o600)
        # The raw key bytes must never appear inside the database file.
        with open(sidecar, "rb") as handle:
            secret = handle.read()
        self.assertEqual(len(secret), 32)
        with open(self.db_path, "rb") as handle:
            db_bytes = handle.read()
        self.assertNotIn(secret, db_bytes)

    def test_explicit_anchor_key_round_trips_across_rebuilds(self):
        store = RequestStore(self.db_path, anchor_key="external-secret")
        receipt = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        rebuilt = RequestStore(self.db_path, anchor_key="external-secret")
        self.assertTrue(rebuilt.verify_chain("tenant-a", receipt["request_id"]))
        with self.assertRaises(OSError) as ctx:
            RequestStore(self.db_path, anchor_key="different-secret")
        self.assertEqual(str(ctx.exception), "request store is unavailable")

    def test_in_memory_store_has_private_anchor_key(self):
        store = RequestStore(":memory:")
        receipt = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        self.assertTrue(store.verify_chain("tenant-a", receipt["request_id"]))
        with self.assertRaises(ValueError):
            RequestStore(":memory:", anchor_key="")
        with self.assertRaises(ValueError):
            RequestStore(":memory:", anchor_key=7)

    def test_invalid_anchor_key_argument(self):
        with self.assertRaises(ValueError):
            self._store(anchor_key="")
        with self.assertRaises(ValueError):
            self._store(anchor_key=b"")
        with self.assertRaises(ValueError):
            self._store(anchor_key=123)


class AnchorAccessValidationTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "evidence.db")
        store = RequestStore(self.db_path)
        self.receipt = store.submit(
            "tenant-a", "subject-1", ["email"], "key-1"
        )
        store.transition("tenant-a", self.receipt["request_id"], "processing")

    def tearDown(self):
        self._tmp.cleanup()

    def test_bad_arguments_raise_value_error(self):
        store = RequestStore(self.db_path)
        for bad in ("", None, 7, b"tenant", ["tenant"], 3.14):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    store.verify_chain(bad, self.receipt["request_id"])
                with self.assertRaises(ValueError):
                    store.diagnose_chain(bad, self.receipt["request_id"])
                with self.assertRaises(RequestNotFound):
                    store.verify_chain("tenant-a", bad)
                with self.assertRaises(RequestNotFound):
                    store.diagnose_chain("tenant-a", bad)

    def test_unknown_and_cross_tenant_raise_not_found(self):
        store = RequestStore(self.db_path)
        for method in ("verify_chain", "diagnose_chain"):
            with self.assertRaises(RequestNotFound):
                getattr(store, method)("tenant-a", "does-not-exist")
            with self.assertRaises(RequestNotFound):
                getattr(store, method)(
                    "tenant-b", self.receipt["request_id"]
                )

    def test_diagnosis_shape_and_reason_codes(self):
        store = RequestStore(self.db_path)
        diagnosis = store.diagnose_chain(
            "tenant-a", self.receipt["request_id"]
        )
        self.assertEqual(set(diagnosis), {"trusted", "reason"})
        self.assertIsInstance(diagnosis["trusted"], bool)
        self.assertIsNone(diagnosis["reason"])


class AnchorTamperTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "evidence.db")
        store = RequestStore(self.db_path)
        self.receipt = store.submit(
            "tenant-a", "subject-1", ["email"], "key-1"
        )
        store.transition("tenant-a", self.receipt["request_id"], "processing")
        store.transition("tenant-a", self.receipt["request_id"], "completed")
        self.other = store.submit("tenant-b", "subject-2", ["email"], "key-2")
        store.transition("tenant-b", self.other["request_id"], "failed")

    def tearDown(self):
        self._tmp.cleanup()

    def _store(self):
        return RequestStore(self.db_path)

    def _raw(self):
        return sqlite3.connect(self.db_path)

    def _verdict(self, request_id=None):
        request_id = request_id or self.receipt["request_id"]
        store = self._store()
        diagnosis = store.diagnose_chain("tenant-a", request_id)
        return (
            store.verify_chain("tenant-a", request_id),
            diagnosis,
        )

    def test_modify_event_breaks_chain(self):
        with self._raw() as conn:
            conn.execute(
                "UPDATE status_events SET status = 'failed' "
                "WHERE request_id = ? AND seq = 1",
                (self.receipt["request_id"],),
            )
        trusted, diagnosis = self._verdict()
        self.assertFalse(trusted)
        self.assertFalse(diagnosis["trusted"])
        self.assertIn(diagnosis["reason"], _REASONS)

    def test_delete_event_breaks_chain(self):
        with self._raw() as conn:
            conn.execute(
                "DELETE FROM status_events WHERE request_id = ? AND seq = 1",
                (self.receipt["request_id"],),
            )
        trusted, diagnosis = self._verdict()
        self.assertFalse(trusted)
        self.assertIn(diagnosis["reason"], _REASONS)

    def test_recomputed_public_hashes_and_head_still_fail(self):
        """The core threat: public content alone must not restore trust."""
        with self._raw() as conn:
            conn.execute(
                "UPDATE status_events SET status = 'failed' "
                "WHERE request_id = ? AND seq = 1",
                (self.receipt["request_id"],),
            )
            conn.execute(
                "UPDATE status_events SET status = 'failed' "
                "WHERE request_id = ? AND seq = 2",
                (self.receipt["request_id"],),
            )
            conn.execute(
                "UPDATE requests SET status = 'failed' "
                "WHERE request_id = ?",
                (self.receipt["request_id"],),
            )
            rows = conn.execute(
                "SELECT seq, status, occurred_at FROM status_events "
                "WHERE request_id = ? ORDER BY seq",
                (self.receipt["request_id"],),
            ).fetchall()
            predecessor = GENESIS_PREDECESSOR
            for seq, status, occurred_at in rows:
                link = _chain_hash(
                    "tenant-a",
                    self.receipt["request_id"],
                    seq,
                    status,
                    occurred_at,
                    predecessor,
                )
                conn.execute(
                    "UPDATE status_events SET chain_hash = ? "
                    "WHERE request_id = ? AND seq = ?",
                    (link, self.receipt["request_id"], seq),
                )
                predecessor = link
            conn.execute(
                "UPDATE requests SET chain_hash = ? WHERE request_id = ?",
                (predecessor, self.receipt["request_id"]),
            )
        trusted, diagnosis = self._verdict()
        self.assertFalse(trusted)
        self.assertIn(diagnosis["reason"], _REASONS)
        # The request head looks self-consistent; the anchors expose it.
        self.assertNotEqual(diagnosis["reason"], "event_chain_invalid")

    def test_replaced_public_anchor_rows_without_key_still_fail(self):
        """Attacker rewrites events, head and the public anchor columns."""
        with self._raw() as conn:
            conn.execute(
                "UPDATE status_events SET occurred_at = occurred_at || 'Z' "
                "WHERE request_id = ? AND seq = 0",
                (self.receipt["request_id"],),
            )
            rows = conn.execute(
                "SELECT seq, status, occurred_at FROM status_events "
                "WHERE request_id = ? ORDER BY seq",
                (self.receipt["request_id"],),
            ).fetchall()
            predecessor = GENESIS_PREDECESSOR
            for seq, status, occurred_at in rows:
                link = _chain_hash(
                    "tenant-a",
                    self.receipt["request_id"],
                    seq,
                    status,
                    occurred_at,
                    predecessor,
                )
                conn.execute(
                    "UPDATE status_events SET chain_hash = ? "
                    "WHERE request_id = ? AND seq = ?",
                    (link, self.receipt["request_id"], seq),
                )
                conn.execute(
                    "UPDATE chain_anchors SET event_hash = ? "
                    "WHERE request_id = ? AND event_seq = ?",
                    (link, self.receipt["request_id"], seq),
                )
                predecessor = link
            conn.execute(
                "UPDATE requests SET chain_hash = ? WHERE request_id = ?",
                (predecessor, self.receipt["request_id"]),
            )
        trusted, diagnosis = self._verdict()
        self.assertFalse(trusted)
        self.assertEqual(diagnosis["reason"], "anchor_authentication_failed")

    def test_delete_anchors_fails(self):
        with self._raw() as conn:
            conn.execute(
                "DELETE FROM chain_anchors WHERE request_id = ?",
                (self.receipt["request_id"],),
            )
        trusted, diagnosis = self._verdict()
        self.assertFalse(trusted)
        # Removing the request's anchors leaves a hole in the global
        # sequence; either structural code is acceptable, never trust.
        self.assertIn(
            diagnosis["reason"],
            {"anchor_sequence_broken", "anchor_event_mismatch"},
        )

    def test_delete_all_anchors_reports_missing(self):
        with self._raw() as conn:
            conn.execute("DELETE FROM chain_anchors")
        trusted, diagnosis = self._verdict()
        self.assertFalse(trusted)
        self.assertEqual(diagnosis["reason"], "anchors_missing")

    def test_damaged_anchor_hash_fails(self):
        with self._raw() as conn:
            conn.execute(
                "UPDATE chain_anchors SET anchor_hash = ? "
                "WHERE request_id = ? AND event_seq = 0",
                ("0" * 64, self.receipt["request_id"]),
            )
        trusted, diagnosis = self._verdict()
        self.assertFalse(trusted)
        self.assertEqual(diagnosis["reason"], "anchor_authentication_failed")

    def test_anchor_head_damaged_fails(self):
        with self._raw() as conn:
            conn.execute(
                "UPDATE chain_anchor_head SET anchor_hash = ?",
                ("1" * 64,),
            )
        trusted, diagnosis = self._verdict()
        self.assertFalse(trusted)
        self.assertEqual(diagnosis["reason"], "anchor_head_mismatch")

    def test_anchor_head_sequence_damaged_fails(self):
        with self._raw() as conn:
            conn.execute("UPDATE chain_anchor_head SET anchor_seq = 99")
        trusted, diagnosis = self._verdict()
        self.assertFalse(trusted)
        self.assertEqual(diagnosis["reason"], "anchor_head_mismatch")

    def test_forged_tail_anchor_fails_even_for_unrelated_request(self):
        """A global tail forgery invalidates every chain in the store."""
        with self._raw() as conn:
            conn.execute(
                "INSERT INTO chain_anchors "
                "(anchor_seq, tenant_id, request_id, event_seq, "
                "event_hash, anchor_hash) VALUES (99, ?, ?, 0, ?, ?)",
                (
                    "tenant-c",
                    "forged",
                    "2" * 64,
                    "3" * 64,
                ),
            )
        store = self._store()
        # The untouched, previously clean request cannot verify either:
        # the store-wide anchor sequence is broken.
        self.assertFalse(
            store.verify_chain("tenant-a", self.receipt["request_id"])
        )
        self.assertFalse(
            store.verify_chain("tenant-b", self.other["request_id"])
        )

    def test_cross_request_anchor_substitution_fails(self):
        with self._raw() as conn:
            conn.execute(
                "UPDATE chain_anchors SET request_id = ? "
                "WHERE request_id = ? AND event_seq = 0",
                (self.receipt["request_id"], self.other["request_id"]),
            )
        store = self._store()
        self.assertFalse(
            store.verify_chain("tenant-a", self.receipt["request_id"])
        )

    def test_cross_tenant_anchor_substitution_fails(self):
        with self._raw() as conn:
            conn.execute(
                "UPDATE chain_anchors SET tenant_id = 'tenant-b' "
                "WHERE tenant_id = 'tenant-a' AND request_id = ? "
                "AND event_seq = 0",
                (self.receipt["request_id"],),
            )
        store = self._store()
        self.assertFalse(
            store.verify_chain("tenant-a", self.receipt["request_id"])
        )

    def test_interrupted_commit_event_without_anchor_fails(self):
        # Simulate a crash between the event insert and the anchor insert.
        with self._raw() as conn:
            conn.execute(
                "DELETE FROM chain_anchors WHERE request_id = ?",
                (self.receipt["request_id"],),
            )
        store = self._store()
        self.assertFalse(
            store.verify_chain("tenant-a", self.receipt["request_id"])
        )

    def test_diagnosis_never_repairs(self):
        with self._raw() as conn:
            conn.execute(
                "DELETE FROM chain_anchors WHERE request_id = ?",
                (self.receipt["request_id"],),
            )
        store = self._store()
        first = store.diagnose_chain(
            "tenant-a", self.receipt["request_id"]
        )
        second = store.diagnose_chain(
            "tenant-a", self.receipt["request_id"]
        )
        self.assertEqual(first, second)
        with sqlite3.connect(self.db_path) as conn:
            count = conn.execute(
                "SELECT count(*) FROM chain_anchors WHERE request_id = ?",
                (self.receipt["request_id"],),
            ).fetchone()[0]
        self.assertEqual(count, 0)

    def test_lost_anchor_key_invalidates_chain(self):
        sidecar = os.path.join(
            self._tmp.name, "nested", ".evidence.db.anchor-key"
        )
        os.unlink(sidecar)
        # A rebuilt store generates fresh trust material; old anchors
        # were written under the lost key and must not authenticate.
        rebuilt = self._store()
        self.assertFalse(
            rebuilt.verify_chain("tenant-a", self.receipt["request_id"])
        )
        self.assertEqual(
            rebuilt.diagnose_chain(
                "tenant-a", self.receipt["request_id"]
            )["reason"],
            "anchor_authentication_failed",
        )


class LegacyDatabaseAnchorTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "evidence.db")
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
                "'[\"email\"]', 'accepted', '2026-01-01T00:00:00Z')",
                ("rid-1",),
            )
            conn.execute(
                "INSERT INTO status_events VALUES "
                "('tenant-a', 'rid-1', 0, 'accepted', "
                "'2026-01-01T00:00:00Z')"
            )

    def tearDown(self):
        self._tmp.cleanup()

    def test_pre_anchor_database_verifies_false_without_backfill(self):
        store = RequestStore(self.db_path)
        self.assertFalse(store.verify_chain("tenant-a", "rid-1"))
        self.assertEqual(
            store.diagnose_chain("tenant-a", "rid-1"),
            {"trusted": False, "reason": "anchors_missing"},
        )
        with sqlite3.connect(self.db_path) as conn:
            self.assertEqual(
                conn.execute("SELECT count(*) FROM chain_anchors").fetchone()[0],
                0,
            )


class AtomicAnchorWriteTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "evidence.db")

    def tearDown(self):
        self._tmp.cleanup()

    def test_damaged_head_makes_subsequent_write_fail_without_half_records(self):
        store = RequestStore(self.db_path)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE chain_anchor_head SET anchor_hash = ?",
                ("z" * 64,),
            )
        # A write that would append an anchored event cannot commit; it
        # raises the fixed storage error and leaves no event behind.
        with self.assertRaises(OSError) as ctx:
            store.transition("tenant-a", receipt["request_id"], "processing")
        self.assertEqual(str(ctx.exception), "request store is unavailable")
        with sqlite3.connect(self.db_path) as conn:
            event_count = conn.execute(
                "SELECT count(*) FROM status_events WHERE request_id = ?",
                (receipt["request_id"],),
            ).fetchone()[0]
            anchor_count = conn.execute(
                "SELECT count(*) FROM chain_anchors"
            ).fetchone()[0]
        self.assertEqual(event_count, 1)
        self.assertEqual(anchor_count, 1)
        self.assertEqual(
            store.get_status("tenant-a", receipt["request_id"])["status"],
            "accepted",
        )


if __name__ == "__main__":
    unittest.main()
