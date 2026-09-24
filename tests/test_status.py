import os
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor

from forgetting_evidence.requests import (
    InvalidStatusTransition,
    RequestNotFound,
    RequestStore,
)


class GetStatusTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "evidence.db")

    def tearDown(self):
        self._tmp.cleanup()

    def _accepted(self):
        store = RequestStore(self.db_path)
        return store, store.submit(
            "tenant-a", "subject-1", ["email"], "key-1"
        )

    def test_status_record_shape_and_field_order(self):
        store, receipt = self._accepted()
        record = store.get_status("tenant-a", receipt["request_id"])
        self.assertEqual(
            set(record), {"request_id", "status", "created_at"}
        )
        self.assertEqual(record["request_id"], receipt["request_id"])
        self.assertEqual(record["created_at"], receipt["created_at"])

    def test_status_tracks_every_lifecycle_edge(self):
        store, receipt = self._accepted()
        rid = receipt["request_id"]
        self.assertEqual(
            store.get_status("tenant-a", rid)["status"], "accepted"
        )
        store.transition("tenant-a", rid, "processing")
        self.assertEqual(
            store.get_status("tenant-a", rid)["status"], "processing"
        )
        store.transition("tenant-a", rid, "completed")
        self.assertEqual(
            store.get_status("tenant-a", rid)["status"], "completed"
        )
        # created_at is the acceptance time at every point.
        self.assertEqual(
            store.get_status("tenant-a", rid)["created_at"],
            receipt["created_at"],
        )

    def test_status_for_failed_branch(self):
        store, receipt = self._accepted()
        rid = receipt["request_id"]
        store.transition("tenant-a", rid, "failed")
        self.assertEqual(store.get_status("tenant-a", rid)["status"], "failed")

    def test_status_persists_across_rebuild(self):
        store, receipt = self._accepted()
        rid = receipt["request_id"]
        store.transition("tenant-a", rid, "processing")
        store.transition("tenant-a", rid, "failed")
        rebuilt = RequestStore(self.db_path)
        record = rebuilt.get_status("tenant-a", rid)
        self.assertEqual(record["status"], "failed")
        self.assertEqual(record["created_at"], receipt["created_at"])
        self.assertEqual(record["request_id"], rid)

    def test_get_stays_accepted_throughout(self):
        # The acceptance query must never reflect status advancement.
        store, receipt = self._accepted()
        rid = receipt["request_id"]
        for target in ("processing", "completed"):
            store.transition("tenant-a", rid, target)
            self.assertEqual(
                store.get("tenant-a", rid),
                receipt,
                f"acceptance receipt changed after {target}",
            )
        # Idempotent submission replay is likewise frozen at accepted.
        replayed = store.submit(
            "tenant-a", "subject-1", ["email"], "key-1"
        )
        self.assertEqual(replayed, receipt)
        rebuilt = RequestStore(self.db_path)
        self.assertEqual(rebuilt.get("tenant-a", rid), receipt)

    def test_get_status_missing_invalid_and_cross_tenant(self):
        store, receipt = self._accepted()
        for bad in ("", None, 7, b"x", ["x"], "not-a-uuid"):
            with self.subTest(bad=bad):
                with self.assertRaises(RequestNotFound):
                    store.get_status("tenant-a", bad)
        with self.assertRaises(RequestNotFound):
            store.get_status("tenant-a", "does-not-exist")
        with self.assertRaises(RequestNotFound):
            store.get_status("tenant-b", receipt["request_id"])
        # A bad tenant is caller error, not a missing record.
        for bad in ("", None, 7):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    store.get_status(bad, receipt["request_id"])

    def test_same_status_replay_does_not_duplicate_or_alter(self):
        store, receipt = self._accepted()
        rid = receipt["request_id"]
        store.transition("tenant-a", rid, "processing")
        first = store.get_status("tenant-a", rid)
        # Repeating the same transition returns the current record and
        # appends no additional state.
        again = store.transition("tenant-a", rid, "processing")
        self.assertEqual(again, first)
        with sqlite3.connect(self.db_path) as conn:
            count = conn.execute(
                "SELECT count(*) FROM status_events "
                "WHERE request_id = ?",
                (rid,),
            ).fetchone()[0]
        self.assertEqual(count, 2)  # accepted + processing only
        self.assertEqual(
            store.get_status("tenant-a", rid)["created_at"],
            receipt["created_at"],
        )

    def test_concurrent_advancement_leaves_one_graph_legal_status(self):
        store, receipt = self._accepted()
        rid = receipt["request_id"]
        targets = ("processing", "completed", "failed", "accepted")

        def move(target):
            try:
                store.transition("tenant-a", rid, target)
            except InvalidStatusTransition:
                pass

        with ThreadPoolExecutor(max_workers=16) as pool:
            list(pool.map(move, targets * 16))
        final = store.get_status("tenant-a", rid)["status"]
        self.assertIn(final, ("processing", "completed", "failed"))
        # The acceptance query is untouched regardless of the race winner.
        self.assertEqual(store.get("tenant-a", rid), receipt)


class StorageErrorTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "evidence.db")

    def tearDown(self):
        self._tmp.cleanup()

    def test_empty_and_non_string_path_is_value_error(self):
        for bad in ("", None, 7, b"/tmp/x.db", 1.5):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    RequestStore(bad)

    def test_pathlike_object_is_accepted(self):
        from pathlib import Path

        store = RequestStore(Path(self.db_path))
        receipt = store.submit("tenant-a", "subject-1", ["email"], "k")
        self.assertEqual(
            store.get_status("tenant-a", receipt["request_id"])["status"],
            "accepted",
        )

    def test_unwritable_directory_is_os_error_without_detail(self):
        blocker = os.path.join(self._tmp.name, "a-file")
        with open(blocker, "wb") as handle:
            handle.write(b"x")
        impossible = os.path.join(blocker, "nested", "evidence.db")
        with self.assertRaises(OSError) as ctx:
            RequestStore(impossible)
        self.assertEqual(str(ctx.exception), "request store is unavailable")
        self.assertNotIn(impossible, str(ctx.exception))

    def test_corrupt_database_is_os_error_without_detail(self):
        RequestStore(self.db_path)
        with open(self.db_path, "wb") as handle:
            handle.write(b"this is not a sqlite database")
        with self.assertRaises(OSError) as ctx:
            RequestStore(self.db_path)
        message = str(ctx.exception)
        self.assertEqual(message, "request store is unavailable")
        self.assertNotIn("sqlite", message.lower())
        self.assertNotIn(self.db_path, message)

    def test_storage_failure_text_is_stable(self):
        RequestStore(self.db_path)
        with open(self.db_path, "wb") as handle:
            handle.write(b"garbage")
        with self.assertRaises(OSError) as ctx:
            RequestStore(self.db_path)
        self.assertEqual(str(ctx.exception), "request store is unavailable")


if __name__ == "__main__":
    unittest.main()
