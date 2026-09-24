import io
import logging
import os
import sqlite3
import tempfile
import threading
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

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

    def test_database_contains_only_request_storage(self):
        # The acceptance core persists accepted requests alone; it must not
        # introduce status timelines or other unrelated tables.
        RequestStore(self.db_path)
        with sqlite3.connect(self.db_path) as conn:
            tables = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }
        self.assertEqual(tables, {"requests"})

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

    def test_get_missing_illegal_and_cross_tenant_unified(self):
        store = RequestStore(self.db_path)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        # Missing request, unknown/illegal id shape and cross-tenant access
        # all share one entry point and one exception type.
        with self.assertRaises(RequestNotFound):
            store.get("tenant-a", "does-not-exist")
        with self.assertRaises(RequestNotFound):
            store.get(
                "tenant-a", "not-a-uuid-but-queried-through-the-same-entry"
            )
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

    def test_idempotent_replay_accepts_equivalent_scope_sequence_types(self):
        store = RequestStore(self.db_path)
        first = store.submit("tenant-a", "subject-1", ["email", "profile"], "key-1")
        second = store.submit(
            "tenant-a", "subject-1", ("profile", "email"), "key-1"
        )
        self.assertEqual(second, first)

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
        # The first record stays untouched after a conflicting replay.
        self.assertEqual(
            store.submit("tenant-a", "subject-1", ["email"], "key-1")["status"],
            "accepted",
        )

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
            ["email", ""],
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

    def test_rejected_validation_does_not_reserve_idempotency_key(self):
        store = RequestStore(self.db_path)
        with self.assertRaises(ValueError):
            store.submit("tenant-clean", "subject-1", [], "clean-key")
        receipt = store.submit("tenant-clean", "subject-1", ["email"], "clean-key")
        self.assertEqual(receipt["status"], "accepted")

    def test_get_rejects_invalid_arguments(self):
        store = RequestStore(self.db_path)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        bad_values = ["", None, 7, b"tenant", ["tenant"]]
        for bad in bad_values:
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    store.get(bad, receipt["request_id"])
                with self.assertRaises(ValueError):
                    store.get("tenant-a", bad)

    def test_persistence_survives_store_rebuild(self):
        first_store = RequestStore(self.db_path)
        receipt = first_store.submit("tenant-a", "subject-1", ["email"], "key-1")
        rebuilt = RequestStore(self.db_path)
        self.assertEqual(rebuilt.get("tenant-a", receipt["request_id"]), receipt)
        replay = rebuilt.submit("tenant-a", "subject-1", ["email"], "key-1")
        self.assertEqual(replay, receipt)

    def test_rebuild_preserves_all_receipt_values(self):
        first_store = RequestStore(self.db_path)
        receipt = first_store.submit("tenant-a", "subject-1", ["email"], "key-1")
        rebuilt = RequestStore(self.db_path)
        fetched = rebuilt.get("tenant-a", receipt["request_id"])
        self.assertEqual(fetched["request_id"], receipt["request_id"])
        self.assertEqual(fetched["status"], receipt["status"])
        self.assertEqual(fetched["created_at"], receipt["created_at"])

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

    def test_concurrent_same_key_across_separate_instances(self):
        barrier = threading.Barrier(8)
        results = []
        errors = []
        lock = threading.Lock()

        def submit_once():
            try:
                barrier.wait()
                value = RequestStore(self.db_path).submit(
                    "tenant-c", "subject-1", ["email"], "same-key"
                )
                with lock:
                    results.append(value)
            except Exception as exc:  # noqa: BLE001 - surface any leak in assert
                with lock:
                    errors.append(exc)

        threads = [threading.Thread(target=submit_once) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        self.assertEqual(len(results), 8)
        self.assertEqual(len({r["request_id"] for r in results}), 1)
        with sqlite3.connect(self.db_path) as conn:
            count = conn.execute(
                "SELECT count(*) FROM requests "
                "WHERE tenant_id = 'tenant-c' AND idempotency_key = 'same-key'"
            ).fetchone()[0]
        self.assertEqual(count, 1)

    def test_errors_do_not_leak_payload(self):
        store = RequestStore(self.db_path)
        secret_subject = "subject-SECRET"
        secret_scope = "scope-SECRET"
        secret_key = "key-SECRET"
        store.submit("tenant-a", secret_subject, [secret_scope, "email"], secret_key)
        try:
            store.submit("tenant-a", "other-subject", [secret_scope], secret_key)
        except IdempotencyConflict as exc:
            message = str(exc)
        else:
            self.fail("expected IdempotencyConflict")
        self.assertNotIn(secret_subject, message)
        self.assertNotIn(secret_scope, message)
        self.assertNotIn(secret_key, message)
        self.assertNotIn(self.db_path, message)
        try:
            store.get("tenant-a", secret_subject)
        except RequestNotFound as exc:
            message = str(exc)
        else:
            self.fail("expected RequestNotFound")
        self.assertNotIn(secret_subject, message)
        self.assertNotIn(secret_scope, message)

    def test_logs_contain_only_request_id_status_and_time(self):
        store = RequestStore(self.db_path)
        secret_subject = "subject-LOG-SECRET"
        secret_scope = "scope-LOG-SECRET"
        secret_key = "key-LOG-SECRET"
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        logger = logging.getLogger("forgetting_evidence.requests")
        logger.addHandler(handler)
        old_level = logger.level
        logger.setLevel(logging.INFO)
        try:
            receipt = store.submit(
                "tenant-a", secret_subject, [secret_scope, "email"], secret_key
            )
        finally:
            logger.removeHandler(handler)
            logger.setLevel(old_level)
        logs = stream.getvalue()
        self.assertIn(receipt["request_id"], logs)
        self.assertIn("accepted", logs)
        self.assertNotIn(secret_subject, logs)
        self.assertNotIn(secret_scope, logs)
        self.assertNotIn(secret_key, logs)
        self.assertNotIn("tenant-a", logs)
        self.assertNotIn(self.db_path, logs)

    def test_table_can_be_reused_when_already_initialized(self):
        RequestStore(self.db_path)
        # Second instance against the same database must not raise.
        store = RequestStore(self.db_path)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        self.assertEqual(set(receipt), {"request_id", "status", "created_at"})

    def test_in_memory_store_keeps_contract(self):
        store = RequestStore(":memory:")
        receipt = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        self.assertEqual(store.get("tenant-a", receipt["request_id"]), receipt)
        with self.assertRaises(RequestNotFound):
            store.get("tenant-b", receipt["request_id"])
        replay = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        self.assertEqual(replay, receipt)


class ConstructorErrorTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self._tmp.cleanup()

    def test_path_must_be_non_empty_string(self):
        for bad in ("", None, 7, b"/tmp/x.db", ["/tmp/x.db"], object()):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    RequestStore(bad)  # type: ignore[arg-type]

    def test_unwritable_directory_raises_os_error(self):
        readonly = os.path.join(self._tmp.name, "readonly")
        os.makedirs(readonly)
        os.chmod(readonly, 0o500)
        try:
            with self.assertRaises(OSError):
                RequestStore(os.path.join(readonly, "nested", "evidence.db"))
        finally:
            os.chmod(readonly, 0o700)

    def test_path_pointing_at_directory_raises_os_error(self):
        with self.assertRaises(OSError):
            RequestStore(self._tmp.name)

    def test_corrupt_database_raises_os_error(self):
        db_path = os.path.join(self._tmp.name, "evidence.db")
        with open(db_path, "wb") as handle:
            handle.write(b"this is definitely not a sqlite database")
        with self.assertRaises(OSError) as context:
            RequestStore(db_path)
        self.assertNotIn(db_path, str(context.exception))

    def test_init_errors_do_not_leak_path_or_engine_text(self):
        db_path = os.path.join(self._tmp.name, "evidence.db")
        with open(db_path, "wb") as handle:
            handle.write(b"not a database")
        try:
            RequestStore(db_path)
        except OSError as exc:
            message = str(exc)
        else:
            self.fail("expected OSError")
        self.assertNotIn(db_path, message)
        self.assertNotIn("sqlite", message.lower())


if __name__ == "__main__":
    unittest.main()
