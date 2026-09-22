"""Tests for the external sidecar anchor and recoverable commits."""

import base64
import json
import os
import sqlite3
import tempfile
import unittest
from multiprocessing import Process

from forgetting_evidence.requests import (
    RequestStore,
    _GENESIS_PREDECESSOR,
    _chain_hash,
)

HEX64 = "0123456789abcdef"


def _is_hex64(value):
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(c in HEX64 for c in value)
    )


class AnchorBasicsTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "evidence.db")
        self.anchor_path = self.db_path + ".anchor"

    def tearDown(self):
        self._tmp.cleanup()

    def test_sidecar_created_next_to_database(self):
        self.assertFalse(os.path.exists(self.anchor_path))
        RequestStore(self.db_path)
        self.assertTrue(os.path.exists(self.anchor_path))
        with open(self.anchor_path, "rb") as handle:
            document = json.loads(handle.read())
        self.assertEqual(document["version"], 1)
        self.assertEqual(document["seq"], 1)
        self.assertTrue(_is_hex64(document["pred"]))
        self.assertTrue(_is_hex64(document["head"]))
        key = base64.b64decode(document["key"], validate=True)
        self.assertGreaterEqual(len(key), 32)

    def test_custom_anchor_path_outside_database(self):
        custom = os.path.join(self._tmp.name, "elsewhere", "a.json")
        store = RequestStore(self.db_path, anchor_path=custom)
        self.assertTrue(os.path.exists(custom))
        receipt = store.submit("tenant-a", "subject-1", ["email"], "k1")
        rebuilt = RequestStore(self.db_path, anchor_path=custom)
        self.assertEqual(rebuilt.recover(), "valid")
        self.assertTrue(rebuilt.verify_evidence("tenant-a", receipt["request_id"]))

    def test_anchor_path_must_differ_from_database(self):
        with self.assertRaises(ValueError):
            RequestStore(self.db_path, anchor_path=self.db_path)

    def test_integrity_key_validation(self):
        for bad in (b"", "", 123, b"x" * 0):
            with self.assertRaises(ValueError):
                RequestStore(self.db_path, integrity_key=bad)
        # str and bytes are both accepted.
        RequestStore(self.db_path + "1.db", integrity_key="k" * 32)
        RequestStore(self.db_path + "2.db", integrity_key=b"k" * 32)

    def test_random_key_lives_only_in_sidecar(self):
        store = RequestStore(self.db_path)
        store.submit("tenant-a", "subject-1", ["email"], "k1")
        with open(self.anchor_path, "rb") as handle:
            key_b64 = json.loads(handle.read())["key"]
        # The key material never lands in the SQLite file.
        with open(self.db_path, "rb") as handle:
            db_bytes = handle.read()
        self.assertNotIn(key_b64.encode("ascii"), db_bytes)
        self.assertNotIn(base64.b64decode(key_b64), db_bytes)
        with sqlite3.connect(self.db_path) as conn:
            tables = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
        self.assertEqual(tables, {"requests", "status_events"})

    def test_rebuild_without_key_keeps_verifying(self):
        store = RequestStore(self.db_path)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "k1")
        store.transition("tenant-a", receipt["request_id"], "processing")
        rebuilt = RequestStore(self.db_path)
        self.assertEqual(rebuilt.recover(), "valid")
        self.assertTrue(rebuilt.verify_evidence("tenant-a", receipt["request_id"]))

    def test_wrong_explicit_key_is_invalid_and_readonly(self):
        store = RequestStore(self.db_path, integrity_key=b"a" * 32)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "k1")
        rebuilt = RequestStore(self.db_path, integrity_key=b"b" * 32)
        self.assertEqual(rebuilt.recover(), "invalid")
        self.assertFalse(rebuilt.verify_evidence("tenant-a", receipt["request_id"]))
        with self.assertRaises(RuntimeError):
            rebuilt.submit("tenant-a", "subject-2", ["email"], "k2")
        with self.assertRaises(RuntimeError):
            rebuilt.transition("tenant-a", receipt["request_id"], "completed")

    def test_matching_explicit_key_across_rebuilds(self):
        key = b"shared-operator-key-0123456789abcd"
        store = RequestStore(self.db_path, integrity_key=key)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "k1")
        rebuilt = RequestStore(self.db_path, integrity_key=key)
        self.assertEqual(rebuilt.recover(), "valid")
        self.assertTrue(rebuilt.verify_evidence("tenant-a", receipt["request_id"]))

    def test_anchor_seq_advances_per_actual_write_only(self):
        store = RequestStore(self.db_path)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "k1")

        def seq_now():
            with open(self.anchor_path) as handle:
                return json.loads(handle.read())["seq"]

        seq_after_submit = seq_now()
        # Idempotent replays append no anchor link.
        store.submit("tenant-a", "subject-1", ["email"], "k1")
        store.transition("tenant-a", receipt["request_id"], "accepted")
        self.assertEqual(seq_now(), seq_after_submit)
        store.transition("tenant-a", receipt["request_id"], "processing")
        self.assertEqual(seq_now(), seq_after_submit + 1)

    def test_no_temp_files_left_after_writes(self):
        store = RequestStore(self.db_path)
        for i in range(3):
            receipt = store.submit("tenant-a", f"s{i}", ["email"], f"k{i}")
            store.transition("tenant-a", receipt["request_id"], "failed")
        entries = set(os.listdir(os.path.dirname(self.anchor_path)))
        self.assertNotIn(os.path.basename(self.anchor_path) + ".tmp", entries)
        self.assertNotIn(os.path.basename(self.anchor_path) + ".intent", entries)

    def test_in_memory_store_is_valid(self):
        store = RequestStore(":memory:")
        self.assertEqual(store.recover(), "valid")
        receipt = store.submit("tenant-a", "subject-1", ["email"], "k1")
        self.assertEqual(store.recover(), "valid")
        self.assertTrue(store.verify_evidence("tenant-a", receipt["request_id"]))


class AnchorTamperTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "evidence.db")
        self.anchor_path = self.db_path + ".anchor"

    def tearDown(self):
        self._tmp.cleanup()

    def _lifecycle(self):
        store = RequestStore(self.db_path)
        one = store.submit("tenant-a", "subject-1", ["email"], "k1")
        store.transition("tenant-a", one["request_id"], "processing")
        two = store.submit("tenant-b", "subject-2", ["email"], "k2")
        store.transition("tenant-b", two["request_id"], "failed")
        return store, one, two

    def test_delete_sidecar_is_incomplete(self):
        store, one, _ = self._lifecycle()
        os.remove(self.anchor_path)
        self.assertEqual(store.recover(), "incomplete")
        self.assertFalse(store.verify_evidence("tenant-a", one["request_id"]))
        with self.assertRaises(RuntimeError):
            store.submit("tenant-a", "subject-3", ["email"], "k3")
        with self.assertRaises(RuntimeError):
            store.transition("tenant-a", one["request_id"], "completed")
        # recover() did not recreate the sidecar.
        self.assertFalse(os.path.exists(self.anchor_path))

    def test_corrupt_sidecar_is_incomplete(self):
        store, one, _ = self._lifecycle()
        for corruption in (b"", b"not json", b'{"version": 1}'):
            with open(self.anchor_path, "wb") as handle:
                handle.write(corruption)
            rebuilt = RequestStore(self.db_path)
            self.assertEqual(rebuilt.recover(), "incomplete")
            self.assertFalse(rebuilt.verify_evidence("tenant-a", one["request_id"]))

    def test_modified_sidecar_head_is_invalid(self):
        _, one, _ = self._lifecycle()
        with open(self.anchor_path, "rb") as handle:
            document = json.loads(handle.read())
        document["head"] = ("0" if document["head"][0] != "0" else "1") + document["head"][1:]
        with open(self.anchor_path, "wb") as handle:
            handle.write(json.dumps(document).encode())
        rebuilt = RequestStore(self.db_path)
        self.assertEqual(rebuilt.recover(), "invalid")
        self.assertFalse(rebuilt.verify_evidence("tenant-a", one["request_id"]))

    def test_rekeyed_sidecar_is_invalid(self):
        _, one, _ = self._lifecycle()
        with open(self.anchor_path, "rb") as handle:
            document = json.loads(handle.read())
        document["key"] = base64.b64encode(b"z" * 40).decode("ascii")
        with open(self.anchor_path, "wb") as handle:
            handle.write(json.dumps(document).encode())
        rebuilt = RequestStore(self.db_path)
        self.assertEqual(rebuilt.recover(), "invalid")
        self.assertFalse(rebuilt.verify_evidence("tenant-a", one["request_id"]))

    def test_sidecar_from_other_database_is_invalid(self):
        _, one, _ = self._lifecycle()
        other_db = os.path.join(self._tmp.name, "other.db")
        other = RequestStore(other_db)
        other.submit("tenant-a", "subject-1", ["email"], "k1")
        # Substitute the other database's anchor for ours.
        with open(other_db + ".anchor", "rb") as src, open(
            self.anchor_path, "wb"
        ) as dst:
            dst.write(src.read())
        rebuilt = RequestStore(self.db_path)
        self.assertEqual(rebuilt.recover(), "invalid")
        self.assertFalse(rebuilt.verify_evidence("tenant-a", one["request_id"]))

    def test_database_substituted_with_other_is_invalid(self):
        _, one, _ = self._lifecycle()
        other_db = os.path.join(self._tmp.name, "other.db")
        other = RequestStore(other_db)
        other_receipt = other.submit("tenant-a", "subject-1", ["email"], "k1")
        # Flush both WAL files into their main databases and drop the
        # side connection so a raw file copy captures the whole state.
        del other
        import gc

        gc.collect()
        for path in (self.db_path, other_db):
            with sqlite3.connect(path) as conn:
                conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        # Copy the other database file over ours, discarding our WAL,
        # while keeping our anchor.
        for suffix in ("-wal", "-shm"):
            try:
                os.remove(self.db_path + suffix)
            except FileNotFoundError:
                pass
        with open(other_db, "rb") as src, open(self.db_path, "wb") as dst:
            dst.write(src.read())
        rebuilt = RequestStore(self.db_path)
        self.assertEqual(rebuilt.recover(), "invalid")
        # The request that exists in the substituted database cannot
        # verify against the original database's anchor.
        self.assertFalse(
            rebuilt.verify_evidence("tenant-a", other_receipt["request_id"])
        )

    def test_wholesale_recompute_after_delete_is_invalid(self):
        _, one, _ = self._lifecycle()
        # Attacker deletes an event and recomputes every per-request chain
        # hash and request head, leaving the per-request chains internally
        # consistent. The external anchor must still reject it.
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "DELETE FROM status_events WHERE request_id = ? AND seq = 1",
                (one["request_id"],),
            )
            _recompute_all_chains(conn)
        rebuilt = RequestStore(self.db_path)
        self.assertEqual(rebuilt.recover(), "invalid")
        self.assertFalse(rebuilt.verify_evidence("tenant-a", one["request_id"]))

    def test_wholesale_recompute_after_insert_is_invalid(self):
        _, one, _ = self._lifecycle()
        with sqlite3.connect(self.db_path) as conn:
            ts = conn.execute(
                "SELECT occurred_at FROM status_events WHERE request_id = ? AND seq = 1",
                (one["request_id"],),
            ).fetchone()[0]
            # Insert an extra forged event, then recompute all chains.
            conn.execute(
                "INSERT INTO status_events "
                "(tenant_id, request_id, seq, status, occurred_at, chain_hash) "
                "VALUES ('tenant-a', ?, 2, 'completed', ?, '0')",
                (one["request_id"], ts),
            )
            _recompute_all_chains(conn)
        rebuilt = RequestStore(self.db_path)
        self.assertEqual(rebuilt.recover(), "invalid")
        self.assertFalse(rebuilt.verify_evidence("tenant-a", one["request_id"]))

    def test_cross_request_event_swap_with_recompute_is_invalid(self):
        _, one, two = self._lifecycle()
        with sqlite3.connect(self.db_path) as conn:
            # Give request one request two's accepted event content.
            row = conn.execute(
                "SELECT occurred_at FROM status_events "
                "WHERE tenant_id = 'tenant-b' AND request_id = ? AND seq = 0",
                (two["request_id"],),
            ).fetchone()
            conn.execute(
                "UPDATE status_events SET occurred_at = ? "
                "WHERE tenant_id = 'tenant-a' AND request_id = ? AND seq = 0",
                (row[0], one["request_id"]),
            )
            _recompute_all_chains(conn)
        rebuilt = RequestStore(self.db_path)
        self.assertEqual(rebuilt.recover(), "invalid")
        self.assertFalse(rebuilt.verify_evidence("tenant-a", one["request_id"]))

    def test_anchor_file_replaced_with_garbage_then_rebuild(self):
        _, one, _ = self._lifecycle()
        with open(self.anchor_path, "wb") as handle:
            handle.write(b"\x00\x01\x02binary garbage")
        rebuilt = RequestStore(self.db_path)
        self.assertEqual(rebuilt.recover(), "incomplete")
        self.assertFalse(rebuilt.verify_evidence("tenant-a", one["request_id"]))
        with self.assertRaises(RuntimeError):
            rebuilt.transition("tenant-a", one["request_id"], "completed")


def _recompute_all_chains(conn):
    """Recompute per-request chain hashes the way an attacker would."""
    rows = conn.execute(
        "SELECT tenant_id, request_id, seq, status, occurred_at "
        "FROM status_events ORDER BY tenant_id, request_id, seq"
    ).fetchall()
    current = None
    predecessor = _GENESIS_PREDECESSOR
    for tenant_id, request_id, seq, status, occurred_at in rows:
        key = (tenant_id, request_id)
        if key != current:
            current = key
            predecessor = _GENESIS_PREDECESSOR
        link = _chain_hash(
            tenant_id, request_id, seq, status, occurred_at, predecessor
        )
        conn.execute(
            "UPDATE status_events SET chain_hash = ? "
            "WHERE tenant_id = ? AND request_id = ? AND seq = ?",
            (link, tenant_id, request_id, seq),
        )
        predecessor = link
    conn.execute(
        "UPDATE requests SET chain_hash = ( "
        "SELECT e.chain_hash FROM status_events e "
        "WHERE e.tenant_id = requests.tenant_id "
        "  AND e.request_id = requests.request_id "
        "ORDER BY e.seq DESC LIMIT 1)"
    )


class RecoverableCommitTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "evidence.db")
        self.anchor_path = self.db_path + ".anchor"

    def tearDown(self):
        self._tmp.cleanup()

    def _anchor_seq(self):
        with open(self.anchor_path) as handle:
            return json.loads(handle.read())["seq"]

    def test_crash_after_sqlite_commit_before_anchor(self):
        store = RequestStore(self.db_path)
        seq_before = self._anchor_seq()
        real_finalize = store._finalize_commit
        state = {"crashed": False}

        def crash_after_commit(conn, prepared):
            if not state["crashed"]:
                state["crashed"] = True
                # Simulate phase-2 crash: SQLite durably committed,
                # sidecar never replaced, intent stays staged.
                conn.execute("COMMIT")
                raise RuntimeError("simulated crash")
            return real_finalize(conn, prepared)

        store._finalize_commit = crash_after_commit
        with self.assertRaises(RuntimeError):
            store.submit("tenant-a", "subject-1", ["email"], "k1")

        # Same instance must not claim success and must report incomplete.
        self.assertEqual(store.recover(), "incomplete")
        with sqlite3.connect(self.db_path) as conn:
            request_id = conn.execute(
                "SELECT request_id FROM requests WHERE idempotency_key = 'k1'"
            ).fetchone()[0]
        self.assertFalse(store.verify_evidence("tenant-a", request_id))

        # recover() must not repair anything.
        for _ in range(2):
            self.assertEqual(store.recover(), "incomplete")
        self.assertEqual(self._anchor_seq(), seq_before)

        # The next write rolls the interrupted commit forward.
        next_receipt = store.submit("tenant-a", "subject-2", ["email"], "k2")
        self.assertEqual(store.recover(), "valid")
        self.assertTrue(store.verify_evidence("tenant-a", request_id))
        self.assertTrue(
            store.verify_evidence("tenant-a", next_receipt["request_id"])
        )
        # The roll-forward advanced the anchor exactly once for the
        # interrupted write, then once for the new write.
        self.assertEqual(self._anchor_seq(), seq_before + 2)

    def test_crash_after_intent_before_sqlite_commit(self):
        store = RequestStore(self.db_path)
        store.submit("tenant-a", "subject-1", ["email"], "k1")
        seq_before = self._anchor_seq()
        real_finalize = store._finalize_commit
        state = {"crashed": False}

        def crash_before_commit(conn, prepared):
            if not state["crashed"]:
                state["crashed"] = True
                # Simulate phase-1 crash: intent staged, SQLite rolled
                # back.
                conn.execute("ROLLBACK")
                raise RuntimeError("simulated crash")
            return real_finalize(conn, prepared)

        store._finalize_commit = crash_before_commit
        with self.assertRaises(RuntimeError):
            store.submit("tenant-a", "subject-2", ["email"], "k2")
        self.assertEqual(store.recover(), "incomplete")

        # The rolled-back request never existed.
        with sqlite3.connect(self.db_path) as conn:
            count = conn.execute("SELECT count(*) FROM requests").fetchone()[0]
        self.assertEqual(count, 1)

        # Next write discards the stale intent and proceeds normally.
        receipt = store.submit("tenant-a", "subject-3", ["email"], "k3")
        self.assertEqual(store.recover(), "valid")
        self.assertTrue(store.verify_evidence("tenant-a", receipt["request_id"]))
        self.assertEqual(self._anchor_seq(), seq_before + 1)

    def test_crash_after_anchor_before_intent_cleanup(self):
        store = RequestStore(self.db_path)

        real_clear = store._clear_intent
        store._clear_intent_calls = 0

        def swallow_clear():
            store._clear_intent_calls += 1
            # Simulate crash immediately after the anchor replacement.

        store._clear_intent = swallow_clear
        receipt = store.submit("tenant-a", "subject-1", ["email"], "k1")
        # Anchor and SQLite are both current; the lingering intent is the
        # residue of a commit that actually completed.
        self.assertEqual(store.recover(), "valid")
        self.assertTrue(store.verify_evidence("tenant-a", receipt["request_id"]))

        # Next write clears the residue and keeps working.
        store._clear_intent = real_clear
        moved = store.transition("tenant-a", receipt["request_id"], "failed")
        self.assertEqual(moved["status"], "failed")
        self.assertEqual(store.recover(), "valid")
        self.assertTrue(store.verify_evidence("tenant-a", receipt["request_id"]))

    def test_interrupted_commit_survives_process_restart(self):
        store = RequestStore(self.db_path)

        def crash_after_commit(conn, prepared):
            conn.execute("COMMIT")
            raise RuntimeError("simulated crash")

        store._finalize_commit = crash_after_commit
        with self.assertRaises(RuntimeError):
            store.submit("tenant-a", "subject-1", ["email"], "k1")

        # A brand-new instance observes the same interrupted state...
        rebuilt = RequestStore(self.db_path)
        self.assertEqual(rebuilt.recover(), "incomplete")
        # ...and a successful write on the new instance resolves it.
        receipt = rebuilt.submit("tenant-a", "subject-2", ["email"], "k2")
        self.assertEqual(rebuilt.recover(), "valid")
        self.assertTrue(
            rebuilt.verify_evidence("tenant-a", receipt["request_id"])
        )
        with sqlite3.connect(self.db_path) as conn:
            request_id = conn.execute(
                "SELECT request_id FROM requests WHERE idempotency_key = 'k1'"
            ).fetchone()[0]
        self.assertTrue(rebuilt.verify_evidence("tenant-a", request_id))

    def test_recover_never_writes(self):
        store = RequestStore(self.db_path)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "k1")
        with open(self.anchor_path, "rb") as before:
            anchor_bytes = before.read()
        intent_path = self.anchor_path + ".intent"
        self.assertFalse(os.path.exists(intent_path))
        for _ in range(5):
            self.assertEqual(store.recover(), "valid")
            self.assertTrue(
                store.verify_evidence("tenant-a", receipt["request_id"])
            )
        with open(self.anchor_path, "rb") as after:
            self.assertEqual(after.read(), anchor_bytes)
        self.assertFalse(os.path.exists(intent_path))


class MultiInstanceTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "evidence.db")

    def tearDown(self):
        self._tmp.cleanup()

    def test_two_instances_alternating_writes(self):
        first = RequestStore(self.db_path)
        second = RequestStore(self.db_path)
        r1 = first.submit("tenant-a", "subject-1", ["email"], "k1")
        self.assertEqual(second.recover(), "valid")
        second.transition("tenant-a", r1["request_id"], "processing")
        self.assertEqual(first.recover(), "valid")
        r2 = first.submit("tenant-a", "subject-2", ["email"], "k2")
        second.transition("tenant-a", r1["request_id"], "completed")
        first.transition("tenant-a", r2["request_id"], "failed")
        for store in (first, second):
            self.assertEqual(store.recover(), "valid")
            self.assertTrue(
                store.verify_evidence("tenant-a", r1["request_id"])
            )
            self.assertTrue(
                store.verify_evidence("tenant-a", r2["request_id"])
            )

    def test_multiprocess_writers_end_valid(self):
        db_path = self.db_path
        processes = [
            Process(target=_worker, args=(db_path, f"tenant-{i}", i))
            for i in range(4)
        ]
        for process in processes:
            process.start()
        for process in processes:
            process.join(timeout=60)
            self.assertEqual(process.exitcode, 0)
        store = RequestStore(db_path)
        self.assertEqual(store.recover(), "valid")
        with sqlite3.connect(db_path) as conn:
            request_ids = [
                row[0]
                for row in conn.execute(
                    "SELECT request_id FROM requests ORDER BY request_id"
                )
            ]
        self.assertEqual(len(request_ids), 16)
        for request_id in request_ids:
            tenant = conn_execute(
                db_path,
                "SELECT tenant_id FROM requests WHERE request_id = ?",
                (request_id,),
            )
            self.assertTrue(store.verify_evidence(tenant, request_id))


def conn_execute(db_path, sql, params):
    with sqlite3.connect(db_path) as conn:
        return conn.execute(sql, params).fetchone()[0]


def _worker(db_path, tenant, worker_index):
    store = RequestStore(db_path)
    for i in range(4):
        receipt = store.submit(
            tenant, f"subject-{i}", ["email"], f"k-{worker_index}-{i}"
        )
        store.transition(tenant, receipt["request_id"], "processing")
        store.transition(tenant, receipt["request_id"], "completed")
        assert store.recover() == "valid"
        assert store.verify_evidence(tenant, receipt["request_id"])


if __name__ == "__main__":
    unittest.main()
