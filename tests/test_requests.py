import os
import tempfile
import threading
import unittest
import uuid
from datetime import datetime

from forgetting_evidence.requests import (
    IdempotencyConflict,
    RequestNotFound,
    RequestStore,
)


class RequestStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp.name, "requests.db")
        self.store = RequestStore(self.db_path)

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_creates_db_file_and_table(self):
        self.assertTrue(os.path.exists(self.db_path))
        import sqlite3

        conn = sqlite3.connect(self.db_path)
        try:
            tables = {r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
        finally:
            conn.close()
        self.assertIn("requests", tables)

    def test_submit_returns_accepted_record(self):
        result = self.store.submit("t1", "s1", ["a", "b"], "k1")
        self.assertEqual(set(result), {"request_id", "status", "created_at"})
        uuid.UUID(result["request_id"])
        self.assertEqual(result["status"], "accepted")
        parsed = datetime.fromisoformat(result["created_at"].replace("Z", "+00:00"))
        self.assertIsNotNone(parsed.tzinfo)

    def test_submit_rejects_invalid_identifiers_without_writing(self):
        for bad in ("", None, 123, b"x"):
            with self.assertRaises(ValueError):
                self.store.submit(bad, "s1", ["a"], "k1")
            with self.assertRaises(ValueError):
                self.store.submit("t1", bad, ["a"], "k1")
            with self.assertRaises(ValueError):
                self.store.submit("t1", "s1", ["a"], bad)
        self.assertEqual(self._count_rows(), 0)

    def test_submit_rejects_invalid_scopes_without_writing(self):
        for bad in ([], (), "abc", None, 5, ["a", "a"], ["a", ""], ["a", 1], ["a", None]):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.store.submit("t1", "s1", bad, "k1")
        self.assertEqual(self._count_rows(), 0)

    def test_idempotent_replay_returns_original_record(self):
        first = self.store.submit("t1", "s1", ["a", "b"], "k1")
        second = self.store.submit("t1", "s1", ["b", "a"], "k1")
        self.assertEqual(first, second)
        self.assertEqual(self._count_rows(), 1)

    def test_conflicting_payload_raises(self):
        self.store.submit("t1", "s1", ["a"], "k1")
        with self.assertRaises(IdempotencyConflict):
            self.store.submit("t1", "s2", ["a"], "k1")
        with self.assertRaises(IdempotencyConflict):
            self.store.submit("t1", "s1", ["a", "b"], "k1")
        self.assertEqual(self._count_rows(), 1)

    def test_idempotency_keys_are_tenant_scoped(self):
        r1 = self.store.submit("t1", "s1", ["a"], "k1")
        r2 = self.store.submit("t2", "s1", ["a"], "k1")
        self.assertNotEqual(r1["request_id"], r2["request_id"])
        self.assertEqual(self._count_rows(), 2)

    def test_get_returns_record(self):
        submitted = self.store.submit("t1", "s1", ["a"], "k1")
        self.assertEqual(self.store.get("t1", submitted["request_id"]), submitted)

    def test_get_missing_and_cross_tenant_raise_same_error(self):
        submitted = self.store.submit("t1", "s1", ["a"], "k1")
        with self.assertRaises(RequestNotFound):
            self.store.get("t1", str(uuid.uuid4()))
        with self.assertRaises(RequestNotFound):
            self.store.get("t2", submitted["request_id"])

    def test_results_survive_reopen(self):
        submitted = self.store.submit("t1", "s1", ["a", "b"], "k1")
        self.store.close()
        self.store = RequestStore(self.db_path)
        self.assertEqual(self.store.get("t1", submitted["request_id"]), submitted)
        self.assertEqual(self.store.submit("t1", "s1", ["b", "a"], "k1"), submitted)

    def test_concurrent_same_key_creates_single_record(self):
        results = []
        errors = []

        def worker():
            try:
                results.append(self.store.submit("t1", "s1", ["a", "b"], "k1"))
            except Exception as exc:  # pragma: no cover - diagnostic
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(16)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        self.assertEqual(len(results), 16)
        self.assertEqual(len({r["request_id"] for r in results}), 1)
        self.assertEqual(self._count_rows(), 1)

    def _count_rows(self):
        import sqlite3

        conn = sqlite3.connect(self.db_path)
        try:
            return conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0]
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()
