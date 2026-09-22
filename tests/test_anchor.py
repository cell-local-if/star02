"""Tests for the externally anchored, keyed evidence.

These cover the properties the plain SHA-256 chain cannot provide on
its own:

* trusted verification depends on an ``integrity_key`` the caller keeps
  outside SQLite and the sidecar;
* the key, key-equivalent material and chain preimages never appear in
  SQLite, the sidecar, receipts, exceptions or logs;
* missing/corrupt/mismatched sidecar, legacy databases and interrupted
  prepare/commit all fail verification;
* an attacker who recomputes and replaces *all* public content of both
  stores still cannot forge a valid anchor without the key;
* ``recover()`` is read-only and only reports valid/invalid/incomplete;
* replays, illegal migrations, bad parameters and cross-tenant access
  never touch the anchor.
"""

import hashlib
import io
import json
import logging
import os
import sqlite3
import struct
import tempfile
import unittest

from forgetting_evidence.requests import (
    IdempotencyConflict,
    InvalidStatusTransition,
    RequestNotFound,
    RequestStore,
)

KEY_A = b"caller-held-secret-key-A-0123456789abcdef"
KEY_B = b"caller-held-secret-key-B-abcdef0123456789"


def chain_hash(tenant, request, seq, status, occurred_at, predecessor):
    digest = hashlib.sha256()
    for field in (tenant, request, str(seq), status, occurred_at, predecessor):
        raw = field.encode("utf-8")
        digest.update(struct.pack(">Q", len(raw)))
        digest.update(raw)
    return digest.hexdigest()


GENESIS = hashlib.sha256(b"").hexdigest()


class AnchorTestBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "evidence.db")
        self.anchor_path = os.path.join(self._tmp.name, "nested", "evidence.anchor")
        self.key = KEY_A

    def tearDown(self):
        self._tmp.cleanup()

    def store(self, key=KEY_A, db_path=None, anchor_path=None):
        return RequestStore(
            db_path or self.db_path,
            anchor_path=self.anchor_path if anchor_path is None else anchor_path,
            integrity_key=key,
        )

    def fresh_lifecycle(self, statuses=("processing", "completed"), tenant="tenant-a"):
        store = self.store()
        receipt = store.submit(tenant, "subject-1", ["email"], "key-1")
        for status in statuses:
            store.transition(tenant, receipt["request_id"], status)
        return store, receipt

    def raw_db(self):
        return sqlite3.connect(self.db_path)

    def read_sidecar(self):
        with open(self.anchor_path, "rb") as handle:
            return handle.read()


class ConstructorTests(AnchorTestBase):
    def test_anchor_and_key_required_together(self):
        with self.assertRaises(ValueError):
            RequestStore(self.db_path, anchor_path=self.anchor_path)
        with self.assertRaises(ValueError):
            RequestStore(self.db_path, integrity_key=KEY_A)

    def test_key_validation(self):
        with self.assertRaises(ValueError):
            RequestStore(self.db_path, anchor_path=self.anchor_path, integrity_key="")
        with self.assertRaises(ValueError):
            RequestStore(
                self.db_path, anchor_path=self.anchor_path, integrity_key=12345
            )

    def test_unanchored_store_never_verifies(self):
        # Backward-compatible constructor still works for the non
        # verifying APIs, but trusted verification is impossible.
        store = RequestStore(self.db_path)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        store.transition("tenant-a", receipt["request_id"], "processing")
        self.assertEqual(
            set(receipt), {"request_id", "status", "created_at"}
        )
        self.assertFalse(store.verify_evidence("tenant-a", receipt["request_id"]))
        self.assertEqual(store.recover(), "incomplete")

    def test_unanchored_missing_record_still_raises(self):
        # Compatibility: missing / cross-tenant access keeps raising
        # RequestNotFound even without an anchor configured.
        store = RequestStore(self.db_path)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        with self.assertRaises(RequestNotFound):
            store.verify_evidence("tenant-a", "does-not-exist")
        with self.assertRaises(RequestNotFound):
            store.verify_evidence("tenant-b", receipt["request_id"])


class HappyPathAndRebuildTests(AnchorTestBase):
    def test_clean_lifecycle_verifies(self):
        store, receipt = self.fresh_lifecycle()
        self.assertTrue(store.verify_evidence("tenant-a", receipt["request_id"]))
        self.assertEqual(store.recover(), "valid")

    def test_rebuild_with_same_key_verifies(self):
        store, receipt = self.fresh_lifecycle(("failed",))
        rebuilt = self.store()
        self.assertTrue(rebuilt.verify_evidence("tenant-a", receipt["request_id"]))
        self.assertEqual(rebuilt.recover(), "valid")
        # Evidence bytes are identical across rebuild.
        self.assertEqual(
            store.evidence("tenant-a", receipt["request_id"]),
            rebuilt.evidence("tenant-a", receipt["request_id"]),
        )

    def test_extending_after_rebuild_keeps_chain_contiguous(self):
        store, receipt = self.fresh_lifecycle(("processing",))
        rebuilt = self.store()
        rebuilt.transition("tenant-a", receipt["request_id"], "completed")
        self.assertTrue(rebuilt.verify_evidence("tenant-a", receipt["request_id"]))
        again = self.store()
        self.assertTrue(again.verify_evidence("tenant-a", receipt["request_id"]))
        self.assertEqual(again.recover(), "valid")

    def test_two_requests_both_verify(self):
        store = self.store()
        one = store.submit("tenant-a", "subject-1", ["email"], "k1")
        two = store.submit("tenant-a", "subject-2", ["email"], "k2")
        store.transition("tenant-a", two["request_id"], "failed")
        self.assertTrue(store.verify_evidence("tenant-a", one["request_id"]))
        self.assertTrue(store.verify_evidence("tenant-a", two["request_id"]))


class WrongKeyTests(AnchorTestBase):
    def test_wrong_key_fails_after_rebuild(self):
        _store, receipt = self.fresh_lifecycle()
        attacker = self.store(key=KEY_B)
        # The same sidecar, different key: every HMAC fails to verify.
        self.assertFalse(
            attacker.verify_evidence("tenant-a", receipt["request_id"])
        )
        self.assertEqual(attacker.recover(), "invalid")

    def test_wrong_key_also_fails_for_submit_only(self):
        store = self.store()
        receipt = store.submit("tenant-a", "subject-1", ["email"], "k1")
        self.assertTrue(store.verify_evidence("tenant-a", receipt["request_id"]))
        rebuilt = self.store(key=KEY_B)
        self.assertFalse(
            rebuilt.verify_evidence("tenant-a", receipt["request_id"])
        )


class MissingAndCorruptSidecarTests(AnchorTestBase):
    def test_missing_sidecar_fails(self):
        _store, receipt = self.fresh_lifecycle()
        os.remove(self.anchor_path)
        rebuilt = self.store()
        self.assertFalse(
            rebuilt.verify_evidence("tenant-a", receipt["request_id"])
        )
        # DB claims anchor_seq but the sidecar cannot prove it.
        self.assertEqual(rebuilt.recover(), "invalid")

    def test_truncated_sidecar_fails(self):
        _store, receipt = self.fresh_lifecycle()
        data = self.read_sidecar()
        with open(self.anchor_path, "wb") as handle:
            handle.write(data[: len(data) // 2])
        rebuilt = self.store()
        self.assertFalse(
            rebuilt.verify_evidence("tenant-a", receipt["request_id"])
        )
        self.assertIn(rebuilt.recover(), ("invalid", "incomplete"))

    def test_corrupt_tag_fails(self):
        _store, receipt = self.fresh_lifecycle()
        lines = self.read_sidecar().splitlines()
        first = json.loads(lines[0])
        flipped = ("0" if first["t"][0] != "0" else "1") + first["t"][1:]
        first["t"] = flipped
        lines[0] = json.dumps(first, separators=(",", ":"), sort_keys=True).encode()
        with open(self.anchor_path, "wb") as handle:
            handle.write(b"\n".join(lines) + b"\n")
        rebuilt = self.store()
        self.assertFalse(
            rebuilt.verify_evidence("tenant-a", receipt["request_id"])
        )
        self.assertEqual(rebuilt.recover(), "invalid")

    def test_extra_field_fails(self):
        _store, receipt = self.fresh_lifecycle()
        lines = self.read_sidecar().splitlines()
        first = json.loads(lines[0])
        first["evil"] = "x"
        lines[0] = json.dumps(first, separators=(",", ":"), sort_keys=True).encode()
        with open(self.anchor_path, "wb") as handle:
            handle.write(b"\n".join(lines) + b"\n")
        rebuilt = self.store()
        self.assertFalse(
            rebuilt.verify_evidence("tenant-a", receipt["request_id"])
        )
        self.assertEqual(rebuilt.recover(), "invalid")

    def test_garbage_bytes_fail(self):
        _store, receipt = self.fresh_lifecycle()
        with open(self.anchor_path, "ab") as handle:
            handle.write(b"\x00\x01not-json\n")
        rebuilt = self.store()
        self.assertFalse(
            rebuilt.verify_evidence("tenant-a", receipt["request_id"])
        )
        self.assertEqual(rebuilt.recover(), "invalid")

    def test_anchor_path_unrelated_file_fails(self):
        _store, receipt = self.fresh_lifecycle()
        other = os.path.join(self._tmp.name, "other.anchor")
        with open(other, "wb") as handle:
            handle.write(b"unrelated content\n")
        rebuilt = RequestStore(self.db_path, anchor_path=other, integrity_key=self.key)
        self.assertFalse(
            rebuilt.verify_evidence("tenant-a", receipt["request_id"])
        )

    def test_first_record_deleted_fails(self):
        _store, receipt = self.fresh_lifecycle(("failed",))
        lines = self.read_sidecar().splitlines()
        # Drop the first P/C pair: counter 1 is missing, so counter 2
        # can never authenticate.
        with open(self.anchor_path, "wb") as handle:
            handle.write(b"\n".join(lines[2:]) + b"\n")
        rebuilt = self.store()
        self.assertFalse(
            rebuilt.verify_evidence("tenant-a", receipt["request_id"])
        )
        self.assertEqual(rebuilt.recover(), "invalid")

    def test_reordered_records_fail(self):
        _store, receipt = self.fresh_lifecycle(("failed",))
        lines = self.read_sidecar().splitlines()
        # Move the first prepare after its commit: prepares must be
        # strictly increasing and a commit cannot precede its prepare.
        reordered = [lines[1], lines[0]] + lines[2:]
        with open(self.anchor_path, "wb") as handle:
            handle.write(b"\n".join(reordered) + b"\n")
        rebuilt = self.store()
        self.assertFalse(
            rebuilt.verify_evidence("tenant-a", receipt["request_id"])
        )
        self.assertEqual(rebuilt.recover(), "invalid")

    def test_commit_with_wrong_prepare_reference_fails(self):
        _store, receipt = self.fresh_lifecycle(("failed",))
        lines = self.read_sidecar().splitlines()
        commit = json.loads(lines[1])
        commit["p"] = "f" * 64
        # Recompute nothing: the tag also no longer matches.
        lines[1] = json.dumps(commit, separators=(",", ":"), sort_keys=True).encode()
        with open(self.anchor_path, "wb") as handle:
            handle.write(b"\n".join(lines) + b"\n")
        rebuilt = self.store()
        self.assertFalse(
            rebuilt.verify_evidence("tenant-a", receipt["request_id"])
        )
        self.assertEqual(rebuilt.recover(), "invalid")

    def test_torn_final_line_treated_as_unacknowledged(self):
        _store, receipt = self.fresh_lifecycle(("failed",))
        # Simulate a torn append: bytes with no terminating newline.
        with open(self.anchor_path, "ab") as handle:
            handle.write(b'{"c":99,"k":"P"')
            handle.flush()
            os.fsync(handle.fileno())
        rebuilt = self.store()
        # The torn bytes never formed a durable record; the clean prefix
        # remains authentic.
        self.assertTrue(
            rebuilt.verify_evidence("tenant-a", receipt["request_id"])
        )
        self.assertEqual(rebuilt.recover(), "valid")

    def test_cross_tenant_anchor_claim_fails(self):
        store = self.store()
        a = store.submit("tenant-a", "subject-1", ["email"], "ka")
        b = store.submit("tenant-b", "subject-1", ["email"], "kb")
        store.transition("tenant-a", a["request_id"], "processing")
        store.transition("tenant-b", b["request_id"], "processing")
        with self.raw_db() as conn:
            # Try to make tenant-a's request present tenant-b's anchor.
            b_seq = conn.execute(
                "SELECT anchor_seq FROM requests "
                "WHERE tenant_id = 'tenant-b' AND request_id = ?",
                (b["request_id"],),
            ).fetchone()[0]
            conn.execute(
                "UPDATE requests SET anchor_seq = ? "
                "WHERE tenant_id = 'tenant-a' AND request_id = ?",
                (b_seq, a["request_id"]),
            )
        rebuilt = self.store()
        self.assertFalse(rebuilt.verify_evidence("tenant-a", a["request_id"]))
        self.assertTrue(rebuilt.verify_evidence("tenant-b", b["request_id"]))


class AnchorDatabaseMismatchTests(AnchorTestBase):
    def test_db_head_does_not_match_anchor(self):
        _store, receipt = self.fresh_lifecycle()
        with self.raw_db() as conn:
            # Alter an event but leave the anchor sidecar untouched.
            conn.execute(
                "UPDATE status_events SET occurred_at = occurred_at || 'X' "
                "WHERE request_id = ? AND seq = 0",
                (receipt["request_id"],),
            )
        rebuilt = self.store()
        self.assertFalse(
            rebuilt.verify_evidence("tenant-a", receipt["request_id"])
        )
        self.assertEqual(rebuilt.recover(), "invalid")

    def test_request_status_changed_out_of_band(self):
        _store, receipt = self.fresh_lifecycle()
        with self.raw_db() as conn:
            conn.execute(
                "UPDATE requests SET status = 'failed' WHERE request_id = ?",
                (receipt["request_id"],),
            )
        rebuilt = self.store()
        self.assertFalse(
            rebuilt.verify_evidence("tenant-a", receipt["request_id"])
        )

    def test_anchor_seq_cleared_fails(self):
        _store, receipt = self.fresh_lifecycle()
        with self.raw_db() as conn:
            conn.execute(
                "UPDATE requests SET anchor_seq = NULL WHERE request_id = ?",
                (receipt["request_id"],),
            )
        rebuilt = self.store()
        self.assertFalse(
            rebuilt.verify_evidence("tenant-a", receipt["request_id"])
        )

    def test_swap_anchor_between_requests_fails(self):
        store = self.store()
        one = store.submit("tenant-a", "subject-1", ["email"], "k1")
        two = store.submit("tenant-a", "subject-2", ["email"], "k2")
        with self.raw_db() as conn:
            # Point request one at request two's anchor counter.
            other_seq = conn.execute(
                "SELECT anchor_seq FROM requests WHERE request_id = ?",
                (two["request_id"],),
            ).fetchone()[0]
            conn.execute(
                "UPDATE requests SET anchor_seq = ? WHERE request_id = ?",
                (other_seq, one["request_id"]),
            )
        rebuilt = self.store()
        self.assertFalse(rebuilt.verify_evidence("tenant-a", one["request_id"]))
        self.assertTrue(rebuilt.verify_evidence("tenant-a", two["request_id"]))


class RecomputeAttackTests(AnchorTestBase):
    """The attacker rewrites ALL public content of both stores."""

    def test_full_recompute_without_key_still_fails(self):
        store = self.store()
        receipt = store.submit("tenant-a", "subject-1", ["email"], "k1")
        store.transition("tenant-a", receipt["request_id"], "processing")

        # Attacker rewrites the timeline: accepted -> failed at seq 1,
        # recomputing every public chain hash consistently.
        new_ts = "2030-01-01T00:00:00.000000Z"
        events = store.audit("tenant-a", receipt["request_id"])
        h0 = chain_hash(
            "tenant-a", receipt["request_id"], 0, "accepted",
            events[0]["occurred_at"], GENESIS,
        )
        h1 = chain_hash(
            "tenant-a", receipt["request_id"], 1, "failed", new_ts, h0
        )
        with self.raw_db() as conn:
            conn.execute(
                "UPDATE status_events SET status='failed', occurred_at=?, "
                "chain_hash=? WHERE request_id=? AND seq=1",
                (new_ts, h1, receipt["request_id"]),
            )
            conn.execute(
                "UPDATE requests SET status='failed', chain_hash=? "
                "WHERE request_id=?",
                (h1, receipt["request_id"]),
            )

        rebuilt = self.store()
        # The attacker cannot recompute the HMAC anchor without the key,
        # so the keyed anchor still names processing/h1-old: mismatch.
        self.assertFalse(
            rebuilt.verify_evidence("tenant-a", receipt["request_id"])
        )
        self.assertEqual(rebuilt.recover(), "invalid")

    def test_forged_sidecar_records_without_key_fail(self):
        _store, receipt = self.fresh_lifecycle(("failed",))
        with open(self.anchor_path, "ab") as handle:
            # Any structure the attacker likes, with an arbitrary tag;
            # HMAC cannot be matched without the key.
            forged = {
                "v": 1, "k": "P", "n": 5, "t": "0" * 64,
                "tenant": "tenant-a", "r": receipt["request_id"],
                "c": 1, "h": "1" * 64,
            }
            handle.write(
                json.dumps(forged, separators=(",", ":"), sort_keys=True).encode()
                + b"\n"
            )
        rebuilt = self.store()
        # Out-of-order/forged counter also breaks the strict ordering.
        self.assertFalse(
            rebuilt.verify_evidence("tenant-a", receipt["request_id"])
        )
        self.assertEqual(rebuilt.recover(), "invalid")


class InterruptedCommitTests(AnchorTestBase):
    def _drop_last_line(self):
        data = self.read_sidecar()
        trimmed = data[: data.rfind(b"\n", 0, -1) + 1]
        with open(self.anchor_path, "wb") as handle:
            handle.write(trimmed)

    def test_prepare_without_commit_is_incomplete(self):
        # Build a clean history, then simulate a crash after the last
        # durable prepare but before its commit marker.
        store, receipt = self.fresh_lifecycle(("processing",))
        self.assertTrue(store.verify_evidence("tenant-a", receipt["request_id"]))
        store.transition("tenant-a", receipt["request_id"], "completed")
        # Remove the final C record (and the P it completes if we strip
        # both): first strip only C to model P-persisted/C-lost.
        records = [json.loads(line) for line in self.read_sidecar().splitlines()]
        self.assertEqual(records[-1]["k"], "C")
        self._drop_last_line()

        rebuilt = self.store()
        self.assertEqual(rebuilt.recover(), "incomplete")
        self.assertFalse(
            rebuilt.verify_evidence("tenant-a", receipt["request_id"])
        )

    def test_interrupted_then_reopened_does_not_silently_repair(self):
        _store, receipt = self.fresh_lifecycle(("processing",))
        self._drop_last_line()  # leaves a dangling P
        rebuilt = self.store()
        self.assertEqual(rebuilt.recover(), "incomplete")
        # New writes are refused rather than papering over the gap.
        with self.assertRaises(RuntimeError):
            rebuilt.transition("tenant-a", receipt["request_id"], "completed")
        # recover() after the refusal still reports the same state and
        # nothing was appended to fix the evidence.
        before = self.read_sidecar()
        self.assertEqual(rebuilt.recover(), "incomplete")
        self.assertEqual(before, self.read_sidecar())


class RecoverTests(AnchorTestBase):
    def test_recover_valid_on_clean_store(self):
        self.fresh_lifecycle()
        self.assertEqual(self.store().recover(), "valid")

    def test_recover_incomplete_on_legacy_db(self):
        # Hand-build a pre-anchor (chained but unanchored) database.
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "CREATE TABLE requests (request_id TEXT PRIMARY KEY, "
                "tenant_id TEXT NOT NULL, idempotency_key TEXT NOT NULL, "
                "subject_id TEXT NOT NULL, scopes_json TEXT NOT NULL, "
                "status TEXT NOT NULL, created_at TEXT NOT NULL, "
                "chain_hash TEXT NOT NULL, anchor_seq INTEGER)"
            )
            conn.execute(
                "CREATE UNIQUE INDEX idx_requests_tenant_idempotency "
                "ON requests(tenant_id, idempotency_key)"
            )
            conn.execute(
                "CREATE TABLE status_events (tenant_id TEXT NOT NULL, "
                "request_id TEXT NOT NULL, seq INTEGER NOT NULL, "
                "status TEXT NOT NULL, occurred_at TEXT NOT NULL, "
                "chain_hash TEXT NOT NULL, "
                "PRIMARY KEY (tenant_id, request_id, seq))"
            )
            h0 = chain_hash(
                "tenant-a", "rid", 0, "accepted",
                "2026-01-01T00:00:00Z", GENESIS,
            )
            conn.execute(
                "INSERT INTO requests VALUES "
                "('rid','tenant-a','k','s','[\"email\"]','accepted',"
                "'2026-01-01T00:00:00Z', ?, NULL)",
                (h0,),
            )
            conn.execute(
                "INSERT INTO status_events VALUES "
                "('tenant-a','rid',0,'accepted','2026-01-01T00:00:00Z', ?)",
                (h0,),
            )
        store = self.store()
        self.assertEqual(store.recover(), "incomplete")

    def test_recover_never_writes(self):
        self.fresh_lifecycle()
        with open(self.db_path, "rb") as db_before:
            db_snapshot = db_before.read()
        anchor_snapshot = self.read_sidecar()
        store = self.store()
        for _ in range(3):
            self.assertEqual(store.recover(), "valid")
        with open(self.db_path, "rb") as db_after:
            self.assertEqual(db_snapshot, db_after.read())
        self.assertEqual(anchor_snapshot, self.read_sidecar())

    def test_recover_invalid_on_corrupt_sidecar(self):
        self.fresh_lifecycle()
        with open(self.anchor_path, "ab") as handle:
            handle.write(b"garbage\n")
        self.assertEqual(self.store().recover(), "invalid")


class NoAnchorWriteTests(AnchorTestBase):
    def _anchor_bytes(self):
        try:
            return self.read_sidecar()
        except FileNotFoundError:
            return None

    def test_idempotent_submit_replay_does_not_anchor(self):
        store = self.store()
        store.submit("tenant-a", "subject-1", ["email"], "k1")
        after_first = self._anchor_bytes()
        for _ in range(3):
            store.submit("tenant-a", "subject-1", ["email"], "k1")
        self.assertEqual(after_first, self._anchor_bytes())

    def test_same_status_replay_does_not_anchor(self):
        store, receipt = self.fresh_lifecycle()
        before = self._anchor_bytes()
        store.transition("tenant-a", receipt["request_id"], "completed")
        store.transition("tenant-a", receipt["request_id"], "completed")
        self.assertEqual(before, self._anchor_bytes())

    def test_illegal_transition_does_not_anchor(self):
        store, receipt = self.fresh_lifecycle()
        before = self._anchor_bytes()
        with self.assertRaises(InvalidStatusTransition):
            store.transition("tenant-a", receipt["request_id"], "failed")
        self.assertEqual(before, self._anchor_bytes())

    def test_bad_arguments_do_not_anchor(self):
        store = self.store()
        before = self._anchor_bytes()
        for bad in ("", None, 7):
            with self.assertRaises(ValueError):
                store.submit(bad, "subject-1", ["email"], "k")
            with self.assertRaises(ValueError):
                store.submit("tenant-a", bad, ["email"], "k")
            with self.assertRaises(ValueError):
                store.submit("tenant-a", "subject-1", [], "k")
        self.assertEqual(before, self._anchor_bytes())

    def test_missing_and_cross_tenant_do_not_anchor(self):
        store, receipt = self.fresh_lifecycle()
        before = self._anchor_bytes()
        with self.assertRaises(RequestNotFound):
            store.transition("tenant-a", "missing-id", "processing")
        with self.assertRaises(RequestNotFound):
            store.transition("tenant-b", receipt["request_id"], "processing")
        with self.assertRaises(RequestNotFound):
            store.verify_evidence("tenant-b", receipt["request_id"])
        self.assertEqual(before, self._anchor_bytes())

    def test_verify_never_writes_anchor_or_db(self):
        self.fresh_lifecycle()
        with open(self.db_path, "rb") as handle:
            db_before = handle.read()
        anchor_before = self._anchor_bytes()
        store = self.store()
        ids = [
            row[0]
            for row in sqlite3.connect(self.db_path).execute(
                "SELECT request_id FROM requests"
            )
        ]
        for _ in range(3):
            for rid in ids:
                self.assertTrue(store.verify_evidence("tenant-a", rid))
        with open(self.db_path, "rb") as handle:
            self.assertEqual(db_before, handle.read())
        self.assertEqual(anchor_before, self._anchor_bytes())


class SecretBoundaryTests(AnchorTestBase):
    def test_key_never_in_sidecar_or_db(self):
        secret = b"the-super-secret-integrity-key-9999"
        store = RequestStore(
            self.db_path, anchor_path=self.anchor_path, integrity_key=secret
        )
        receipt = store.submit(
            "tenant-a", "subject-SECRET", ["scope-SECRET"], "idem-SECRET"
        )
        store.transition("tenant-a", receipt["request_id"], "processing")
        sidecar = self.read_sidecar()
        self.assertNotIn(secret, sidecar)
        with open(self.db_path, "rb") as handle:
            db_bytes = handle.read()
        self.assertNotIn(secret, db_bytes)
        # Receipts and evidence carry no key or anchor counter.
        rendered = repr(receipt) + repr(
            store.evidence("tenant-a", receipt["request_id"])
        )
        self.assertNotIn(secret.decode(), rendered)
        self.assertNotIn("anchor", rendered.lower())

    def test_exceptions_do_not_leak_key(self):
        secret = b"another-secret-key-value-zzzzzzzzzz"
        store = RequestStore(
            self.db_path, anchor_path=self.anchor_path, integrity_key=secret
        )
        store.submit("tenant-a", "subject-1", ["email"], "k1")
        for call in (
            lambda: store.submit("tenant-a", "subject-2", ["email"], "k1"),
            lambda: store.get("tenant-a", "nope"),
            lambda: store.transition("tenant-a", "nope", "processing"),
        ):
            try:
                call()
            except (IdempotencyConflict, RequestNotFound, InvalidStatusTransition) as exc:
                self.assertNotIn(secret.decode(), str(exc))
            else:
                self.fail("expected an error")

    def test_logs_do_not_leak_key(self):
        secret = b"logged-secret-key-value-aaaaaaaaaaaa"
        store = RequestStore(
            self.db_path, anchor_path=self.anchor_path, integrity_key=secret
        )
        receipt = store.submit("tenant-a", "subject-1", ["email"], "k1")
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        logger = logging.getLogger("forgetting_evidence.requests")
        logger.addHandler(handler)
        old_level = logger.level
        logger.setLevel(logging.DEBUG)
        try:
            store.transition("tenant-a", receipt["request_id"], "processing")
        finally:
            logger.removeHandler(handler)
            logger.setLevel(old_level)
        self.assertNotIn(secret.decode(), stream.getvalue())


if __name__ == "__main__":
    unittest.main()
