import os
import sqlite3
import tempfile
import unittest
import uuid
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

from forgetting_evidence.requests import (
    IdempotencyConflict,
    InvalidStatusTransition,
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
            [""],
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


class TransitionTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "evidence.db")

    def tearDown(self):
        self._tmp.cleanup()

    def _submit(self, store=None, tenant="tenant-a", key="key-1"):
        store = store if store is not None else RequestStore(self.db_path)
        return store.submit(tenant, "subject-1", ["email"], key)

    def test_accepted_to_processing_and_completed(self):
        store = RequestStore(self.db_path)
        receipt = self._submit(store)
        moved = store.transition("tenant-a", receipt["request_id"], "processing")
        self.assertEqual(set(moved), {"request_id", "status", "created_at"})
        self.assertEqual(moved["request_id"], receipt["request_id"])
        self.assertEqual(moved["status"], "processing")
        self.assertEqual(moved["created_at"], receipt["created_at"])
        done = store.transition("tenant-a", receipt["request_id"], "completed")
        self.assertEqual(done["status"], "completed")
        # created_at stays the original acceptance timestamp.
        self.assertEqual(done["created_at"], receipt["created_at"])
        # The status query tracks the current state...
        self.assertEqual(
            store.get_status("tenant-a", receipt["request_id"]), done
        )
        # ...while the acceptance query stays frozen at accepted.
        self.assertEqual(store.get("tenant-a", receipt["request_id"]), receipt)

    def test_accepted_to_failed(self):
        store = RequestStore(self.db_path)
        receipt = self._submit(store)
        failed = store.transition("tenant-a", receipt["request_id"], "failed")
        self.assertEqual(failed["status"], "failed")
        self.assertEqual(failed["created_at"], receipt["created_at"])

    def test_processing_to_failed(self):
        store = RequestStore(self.db_path)
        receipt = self._submit(store)
        store.transition("tenant-a", receipt["request_id"], "processing")
        failed = store.transition("tenant-a", receipt["request_id"], "failed")
        self.assertEqual(failed["status"], "failed")

    def test_terminal_states_reject_further_moves(self):
        store = RequestStore(self.db_path)
        receipt = self._submit(store)
        store.transition("tenant-a", receipt["request_id"], "processing")
        store.transition("tenant-a", receipt["request_id"], "completed")
        for target in ("processing", "failed", "accepted"):
            with self.subTest(target=target):
                with self.assertRaises(InvalidStatusTransition):
                    store.transition("tenant-a", receipt["request_id"], target)

        other = self._submit(store, key="key-2")
        store.transition("tenant-a", other["request_id"], "failed")
        for target in ("processing", "completed", "accepted"):
            with self.subTest(target=target):
                with self.assertRaises(InvalidStatusTransition):
                    store.transition("tenant-a", other["request_id"], target)

    def test_illegal_edges_rejected(self):
        store = RequestStore(self.db_path)
        receipt = self._submit(store)
        with self.assertRaises(InvalidStatusTransition):
            store.transition("tenant-a", receipt["request_id"], "completed")
        # State unchanged after rejected moves.
        self.assertEqual(
            store.get_status("tenant-a", receipt["request_id"])["status"], "accepted"
        )

    def test_same_target_is_idempotent(self):
        store = RequestStore(self.db_path)
        receipt = self._submit(store)
        again = store.transition("tenant-a", receipt["request_id"], "accepted")
        self.assertEqual(again, receipt)
        store.transition("tenant-a", receipt["request_id"], "processing")
        replay = store.transition("tenant-a", receipt["request_id"], "processing")
        self.assertEqual(replay["request_id"], receipt["request_id"])
        self.assertEqual(replay["status"], "processing")
        self.assertEqual(replay["created_at"], receipt["created_at"])
        store.transition("tenant-a", receipt["request_id"], "completed")
        terminal = store.transition("tenant-a", receipt["request_id"], "completed")
        self.assertEqual(terminal["status"], "completed")

    def test_unknown_target_status_is_value_error(self):
        store = RequestStore(self.db_path)
        receipt = self._submit(store)
        for bad in ("cancelled", "PROCESSING", " done", "", None, 7):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    store.transition("tenant-a", receipt["request_id"], bad)
        # Out-of-range targets perform no write.
        self.assertEqual(
            store.get_status("tenant-a", receipt["request_id"])["status"], "accepted"
        )

    def test_non_string_arguments_rejected(self):
        store = RequestStore(self.db_path)
        receipt = self._submit(store)
        bad_values = ["", None, 7, b"tenant", ["tenant"]]
        for bad in bad_values:
            with self.subTest(bad=bad):
                # Tenant and target stay caller errors...
                with self.assertRaises(ValueError):
                    store.transition(bad, receipt["request_id"], "processing")
                with self.assertRaises(ValueError):
                    store.transition("tenant-a", receipt["request_id"], bad)
                # ...but a malformed request id is indistinguishable from a
                # missing one and must raise RequestNotFound, never ValueError.
                with self.assertRaises(RequestNotFound):
                    store.transition("tenant-a", bad, "processing")
                with self.assertRaises(RequestNotFound):
                    store.get("tenant-a", bad)
                with self.assertRaises(RequestNotFound):
                    store.get_status("tenant-a", bad)
        with sqlite3.connect(self.db_path) as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM requests").fetchone()[0], 1)

    def test_unknown_and_cross_tenant_raise_not_found(self):
        store = RequestStore(self.db_path)
        receipt = self._submit(store)
        with self.assertRaises(RequestNotFound):
            store.transition("tenant-a", "does-not-exist", "processing")
        with self.assertRaises(RequestNotFound):
            store.transition("tenant-b", receipt["request_id"], "processing")
        # A cross-tenant attempt must not have moved the record.
        self.assertEqual(
            store.get_status("tenant-a", receipt["request_id"])["status"], "accepted"
        )

    def test_rejected_transitions_perform_no_write(self):
        store = RequestStore(self.db_path)
        receipt = self._submit(store)
        with self.assertRaises(InvalidStatusTransition):
            store.transition("tenant-a", receipt["request_id"], "completed")
        with sqlite3.connect(self.db_path) as conn:
            status = conn.execute(
                "SELECT status FROM requests WHERE request_id = ?",
                (receipt["request_id"],),
            ).fetchone()[0]
        self.assertEqual(status, "accepted")

    def test_latest_status_visible_after_rebuild(self):
        first_store = RequestStore(self.db_path)
        receipt = self._submit(first_store)
        first_store.transition("tenant-a", receipt["request_id"], "processing")
        first_store.transition("tenant-a", receipt["request_id"], "completed")
        rebuilt = RequestStore(self.db_path)
        fetched = rebuilt.get_status("tenant-a", receipt["request_id"])
        self.assertEqual(fetched["status"], "completed")
        self.assertEqual(fetched["created_at"], receipt["created_at"])
        # The acceptance receipt remains frozen and byte-stable after rebuild.
        self.assertEqual(rebuilt.get("tenant-a", receipt["request_id"]), receipt)
        # Terminal state is still enforced on the rebuilt store.
        with self.assertRaises(InvalidStatusTransition):
            rebuilt.transition("tenant-a", receipt["request_id"], "failed")
        # Idempotent replay still succeeds post-rebuild.
        self.assertEqual(
            rebuilt.transition("tenant-a", receipt["request_id"], "completed"),
            fetched,
        )
        # A status query rebuilt from another instance agrees.
        another = RequestStore(self.db_path)
        self.assertEqual(
            another.get_status("tenant-a", receipt["request_id"]), fetched
        )

    def test_concurrent_transitions_never_violate_graph(self):
        store = RequestStore(self.db_path)
        receipt = self._submit(store)

        # Every worker races every legal and illegal edge; the persisted
        # result must be reachable from accepted without passing through a
        # terminal state.
        targets = ("processing", "completed", "failed", "accepted", "completed")

        def move(target):
            try:
                return store.transition("tenant-a", receipt["request_id"], target)
            except InvalidStatusTransition:
                return None

        with ThreadPoolExecutor(max_workers=16) as pool:
            outcomes = list(pool.map(move, targets * 8))
        final = store.get_status("tenant-a", receipt["request_id"])
        self.assertIn(final["status"], ("processing", "completed", "failed"))
        if final["status"] == "completed":
            # completed can only win if the accepted->processing edge and
            # the processing->completed edge were both honoured; no
            # accepted->completed shortcut exists.
            self.assertIsNotNone(
                next(o for o in outcomes if o and o["status"] == "completed")
            )
        # A terminal result is stable.
        if final["status"] in ("completed", "failed"):
            with self.assertRaises(InvalidStatusTransition):
                store.transition("tenant-a", receipt["request_id"], "processing")

    def test_concurrent_completed_and_failed_only_one_wins(self):
        store = RequestStore(self.db_path)
        receipt = self._submit(store)
        store.transition("tenant-a", receipt["request_id"], "processing")
        errors = []

        def move(target):
            try:
                return store.transition("tenant-a", receipt["request_id"], target)
            except InvalidStatusTransition as exc:
                return exc

        with ThreadPoolExecutor(max_workers=16) as pool:
            results = list(pool.map(move, ("completed", "failed") * 16))
        final = store.get_status("tenant-a", receipt["request_id"])
        self.assertIn(final["status"], ("completed", "failed"))
        winners = [
            r for r in results if isinstance(r, dict) and r["status"] == final["status"]
        ]
        losers = [
            r
            for r in results
            if isinstance(r, dict) and r["status"] != final["status"]
        ]
        # The winning terminal edge may replay idempotently; the losing edge
        # can never report success.
        self.assertTrue(winners)
        self.assertFalse(losers)
        self.assertEqual(errors, [])

    def test_errors_and_logs_do_not_leak_payload(self):
        store = RequestStore(self.db_path)
        secret_subject = "subject-SECRET"
        secret_scope = "scope-SECRET"
        receipt = store.submit(
            "tenant-a", secret_subject, [secret_scope, "email"], "key-1"
        )
        try:
            store.transition("tenant-a", receipt["request_id"], "completed")
        except InvalidStatusTransition as exc:
            self.assertNotIn(secret_subject, str(exc))
            self.assertNotIn(secret_scope, str(exc))
        else:
            self.fail("expected InvalidStatusTransition")

        import io
        import logging

        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        logger = logging.getLogger("forgetting_evidence.requests")
        logger.addHandler(handler)
        old_level = logger.level
        logger.setLevel(logging.INFO)
        try:
            store.transition("tenant-a", receipt["request_id"], "failed")
        finally:
            logger.removeHandler(handler)
            logger.setLevel(old_level)
        logs = stream.getvalue()
        self.assertNotIn(secret_subject, logs)
        self.assertNotIn(secret_scope, logs)
        self.assertIn(receipt["request_id"], logs)


if __name__ == "__main__":
    unittest.main()
