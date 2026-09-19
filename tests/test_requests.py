import os
import sqlite3
import tempfile
import unittest
import uuid
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

from forgetting_evidence.requests import (
    IdempotencyConflict,
    RequestNotFound,
    RequestStore,
)


def _parse_utc(value):
    # RFC 3339 with trailing Z.
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class RequestStoreTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "evidence.db")

    def tearDown(self):
        self._tmp.cleanup()

    def test_creates_database_file_and_table(self):
        self.assertFalse(os.path.exists(self.db_path))
        RequestStore(self.db_path)
        self.assertTrue(os.path.exists(self.db_path))
        with sqlite3.connect(self.db_path) as conn:
            names = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type IN ('table', 'index')"
                )
            }
        self.assertIn("requests", names)
        self.assertIn("idx_requests_tenant_idempotency", names)

    def test_submit_returns_fixed_receipt_fields(self):
        store = RequestStore(self.db_path)
        receipt = store.submit("tenant-a", "subject-1", ["email", "profile"], "key-1")
        self.assertEqual(set(receipt), {"request_id", "status", "created_at"})
        self.assertEqual(receipt["status"], "accepted")
        parsed = _parse_utc(receipt["created_at"])
        self.assertEqual(parsed.utcoffset().total_seconds(), 0)
        # UUID-shaped identifier.
        uuid.UUID(receipt["request_id"])

    def test_get_returns_same_receipt(self):
        store = RequestStore(self.db_path)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        fetched = store.get("tenant-a", receipt["request_id"])
        self.assertEqual(fetched, receipt)

    def test_get_missing_and_cross_tenant(self):
        store = RequestStore(self.db_path)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        with self.assertRaises(RequestNotFound):
            store.get("tenant-a", "does-not-exist")
        with self.assertRaises(RequestNotFound):
            store.get("tenant-b", receipt["request_id"])

    def test_idempotent_replay_same_payload(self):
        store = RequestStore(self.db_path)
        first = store.submit("tenant-a", "subject-1", ["email", "profile"], "key-1")
        # Different scope ordering must compare as the same payload.
        second = store.submit("tenant-a", "subject-1", ["profile", "email"], "key-1")
        self.assertEqual(first, second)
        with sqlite3.connect(self.db_path) as conn:
            count = conn.execute(
                "SELECT count(*) FROM requests WHERE idempotency_key = 'key-1'"
            ).fetchone()[0]
        self.assertEqual(count, 1)

    def test_idempotency_scoped_per_tenant(self):
        store = RequestStore(self.db_path)
        first = store.submit("tenant-a", "subject-1", ["email"], "shared-key")
        other = store.submit("tenant-b", "subject-1", ["email"], "shared-key")
        self.assertNotEqual(first["request_id"], other["request_id"])

    def test_conflict_on_different_subject(self):
        store = RequestStore(self.db_path)
        store.submit("tenant-a", "subject-1", ["email"], "key-1")
        with self.assertRaises(IdempotencyConflict):
            store.submit("tenant-a", "subject-2", ["email"], "key-1")

    def test_conflict_on_different_scopes(self):
        store = RequestStore(self.db_path)
        store.submit("tenant-a", "subject-1", ["email"], "key-1")
        with self.assertRaises(IdempotencyConflict):
            store.submit("tenant-a", "subject-1", ["email", "billing"], "key-1")

    def test_invalid_identifiers_rejected_without_writes(self):
        store = RequestStore(self.db_path)
        bad_values = ["", None, 7, b"tenant", ["tenant"]]
        for bad in bad_values:
            with self.assertRaises(ValueError):
                store.submit(bad, "subject-1", ["email"], "key-1")
            with self.assertRaises(ValueError):
                store.submit("tenant-a", bad, ["email"], "key-1")
            with self.assertRaises(ValueError):
                store.submit("tenant-a", "subject-1", ["email"], bad)
        with sqlite3.connect(self.db_path) as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM requests").fetchone()[0], 0)

    def test_invalid_scopes_rejected_without_writes(self):
        store = RequestStore(self.db_path)
        bad_scopes = [
            [],
            (),
            ["email", "email"],
            ["email", 7],
            "email",
            b"email",
            {"email": 1},
            None,
            123,
        ]
        for scopes in bad_scopes:
            with self.subTest(scopes=scopes):
                with self.assertRaises(ValueError):
                    store.submit("tenant-a", "subject-1", scopes, "key-1")
        with sqlite3.connect(self.db_path) as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM requests").fetchone()[0], 0)

    def test_persistence_survives_store_rebuild(self):
        first_store = RequestStore(self.db_path)
        receipt = first_store.submit("tenant-a", "subject-1", ["email"], "key-1")
        rebuilt = RequestStore(self.db_path)
        self.assertEqual(rebuilt.get("tenant-a", receipt["request_id"]), receipt)
        replay = rebuilt.submit("tenant-a", "subject-1", ["email"], "key-1")
        self.assertEqual(replay, receipt)

    def test_concurrent_same_key_creates_one_record(self):
        store = RequestStore(self.db_path)

        def submit():
            return store.submit("tenant-a", "subject-1", ["email", "billing"], "hot-key")

        with ThreadPoolExecutor(max_workers=16) as pool:
            receipts = list(pool.submit(submit) for _ in range(32))
            results = [future.result() for future in receipts]
        request_ids = {result["request_id"] for result in results}
        self.assertEqual(len(request_ids), 1)
        with sqlite3.connect(self.db_path) as conn:
            count = conn.execute(
                "SELECT count(*) FROM requests "
                "WHERE tenant_id = 'tenant-a' AND idempotency_key = 'hot-key'"
            ).fetchone()[0]
        self.assertEqual(count, 1)

    def test_errors_do_not_leak_payload(self):
        store = RequestStore(self.db_path)
        secret_subject = "subject-SECRET"
        secret_scope = "scope-SECRET"
        store.submit("tenant-a", secret_subject, [secret_scope, "email"], "key-1")
        try:
            store.submit("tenant-a", "other-subject", [secret_scope], "key-1")
        except IdempotencyConflict as exc:
            message = str(exc)
        else:
            self.fail("expected IdempotencyConflict")
        self.assertNotIn(secret_subject, message)
        self.assertNotIn(secret_scope, message)
        try:
            store.get("tenant-a", secret_subject)
        except RequestNotFound as exc:
            self.assertNotIn(secret_scope, str(exc))
        else:
            self.fail("expected RequestNotFound")

    def test_table_can_be_reused_when_already_initialized(self):
        RequestStore(self.db_path)
        # Second instance against the same database must not raise.
        store = RequestStore(self.db_path)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        self.assertEqual(set(receipt), {"request_id", "status", "created_at"})


if __name__ == "__main__":
    unittest.main()
