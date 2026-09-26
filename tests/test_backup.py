import json
import os
import sqlite3
import tempfile
import threading
import unittest

from forgetting_evidence.requests import (
    BackupConflict,
    RequestStore,
)


_ANCHOR_SECRET_V1 = "anchor-secret-generation-one"
_ANCHOR_SECRET_V2 = "anchor-secret-generation-two"
_RECEIPT_KEY = "receipt-key-material"


def _populate(store, tenant="tenant-a"):
    """Create a request with execution, receipt and inspection state."""
    receipt = store.submit(tenant, "subject-1", ["email", "profile"], "key-1")
    request_id = receipt["request_id"]
    claim = store.claim_next(tenant, "worker-1", 60)
    store.finish_claim(tenant, request_id, claim["claim_token"], "completed")
    receipt_text = store.generate_receipt(tenant, request_id, _RECEIPT_KEY)
    inspection = store.audit_inspection(tenant)
    return request_id, receipt_text, inspection


class BackupTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "evidence.db")
        self.target = os.path.join(self._tmp.name, "snapshot.db")

    def tearDown(self):
        self._tmp.cleanup()

    def test_backup_returns_target_and_snapshot_opens(self):
        store = RequestStore(self.db_path)
        request_id, receipt_text, _ = _populate(store)

        result = store.backup_to(self.target)

        self.assertEqual(result, self.target)
        self.assertTrue(os.path.exists(self.target))
        snapshot = RequestStore(self.target)
        self.assertEqual(snapshot.get("tenant-a", request_id)["request_id"], request_id)
        self.assertEqual(
            snapshot.get_status("tenant-a", request_id)["status"], "completed"
        )
        self.assertEqual(
            snapshot.get_execution_log("tenant-a", request_id),
            store.get_execution_log("tenant-a", request_id),
        )
        self.assertEqual(
            snapshot.generate_receipt("tenant-a", request_id, _RECEIPT_KEY),
            receipt_text,
        )
        self.assertTrue(snapshot.verify_receipt(receipt_text, _RECEIPT_KEY))

    def test_snapshot_is_transaction_consistent_view(self):
        store = RequestStore(self.db_path)
        first = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        second = store.submit("tenant-a", "subject-2", ["email"], "key-2")
        store.transition("tenant-a", first["request_id"], "failed")

        store.backup_to(self.target)

        snapshot = RequestStore(self.target)
        self.assertEqual(
            snapshot.get_status("tenant-a", first["request_id"])["status"], "failed"
        )
        self.assertEqual(
            snapshot.get_status("tenant-a", second["request_id"])["status"],
            "accepted",
        )
        # The audit timeline of the snapshot is internally complete.
        events = snapshot.audit("tenant-a", first["request_id"])
        self.assertEqual([event["status"] for event in events], ["accepted", "failed"])

    def test_invalid_target_raises_value_error_and_changes_nothing(self):
        store = RequestStore(self.db_path)
        store.submit("tenant-a", "subject-1", ["email"], "key-1")
        before = self._file_bytes(self.db_path)

        for bad in ("", None, 123, 4.5, b"snapshot.db", ":memory:", "a\0b"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                store.backup_to(bad)

        self.assertFalse(os.path.exists(self.target))
        self.assertEqual(self._file_bytes(self.db_path), before)
        # The source store is fully usable afterwards.
        store.submit("tenant-a", "subject-2", ["email"], "key-2")

    def test_existing_target_raises_conflict_and_is_not_overwritten(self):
        store = RequestStore(self.db_path)
        _populate(store)
        with open(self.target, "wb") as handle:
            handle.write(b"pre-existing content")

        with self.assertRaises(BackupConflict):
            store.backup_to(self.target)

        with open(self.target, "rb") as handle:
            self.assertEqual(handle.read(), b"pre-existing content")

    def test_missing_directory_raises_fixed_oserror(self):
        store = RequestStore(self.db_path)
        _populate(store)
        target = os.path.join(self._tmp.name, "missing", "snapshot.db")

        with self.assertRaises(OSError) as caught:
            store.backup_to(target)

        self.assertEqual(str(caught.exception), "request store is unavailable")
        self.assertFalse(os.path.exists(target))

    def test_parent_that_is_a_file_raises_fixed_oserror(self):
        store = RequestStore(self.db_path)
        _populate(store)
        blocker = os.path.join(self._tmp.name, "blocker")
        with open(blocker, "wb") as handle:
            handle.write(b"not a directory")
        target = os.path.join(blocker, "snapshot.db")

        with self.assertRaises(OSError) as caught:
            store.backup_to(target)

        self.assertEqual(str(caught.exception), "request store is unavailable")
        self.assertFalse(os.path.exists(target))

    def test_corrupt_source_raises_fixed_oserror_and_leaves_no_target(self):
        store = RequestStore(self.db_path)
        _populate(store)
        with open(self.db_path, "r+b") as handle:
            handle.write(b"this is not a sqlite database at all")

        with self.assertRaises(OSError) as caught:
            store.backup_to(self.target)

        self.assertEqual(str(caught.exception), "request store is unavailable")
        self.assertFalse(os.path.exists(self.target))
        # No temporary file is left behind in the target directory.
        leftovers = [
            name
            for name in os.listdir(self._tmp.name)
            if name.startswith(".evidence-backup-")
        ]
        self.assertEqual(leftovers, [])

    def test_concurrent_backups_land_exactly_one(self):
        store = RequestStore(self.db_path)
        _populate(store)
        outcomes = []
        errors = []

        def run():
            try:
                outcomes.append(store.backup_to(self.target))
            except BackupConflict:
                errors.append("conflict")

        threads = [threading.Thread(target=run) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(outcomes, [self.target])
        self.assertEqual(errors, ["conflict"] * 3)
        # The single landed snapshot is a usable database.
        snapshot = RequestStore(self.target)
        self.assertTrue(snapshot.verify_chain() is not None)

    def test_source_database_is_unchanged_by_backup(self):
        store = RequestStore(self.db_path, anchor_secret=_ANCHOR_SECRET_V1)
        request_id, receipt_text, _ = _populate(store)
        store.rotate_anchor_key(_ANCHOR_SECRET_V1, _ANCHOR_SECRET_V2)
        before_bytes = self._file_bytes(self.db_path)
        before_status = store.get_status("tenant-a", request_id)
        before_log = store.get_execution_log("tenant-a", request_id)
        before_verify = store.verify_chain()

        store.backup_to(self.target)

        self.assertEqual(self._file_bytes(self.db_path), before_bytes)
        self.assertEqual(store.get_status("tenant-a", request_id), before_status)
        self.assertEqual(store.get_execution_log("tenant-a", request_id), before_log)
        self.assertEqual(store.verify_chain(), before_verify)
        self.assertTrue(store.verify_receipt(receipt_text, _RECEIPT_KEY))

    def test_snapshot_preserves_anchor_chain_conclusions(self):
        store = RequestStore(self.db_path, anchor_secret=_ANCHOR_SECRET_V1)
        _populate(store)
        store.rotate_anchor_key(_ANCHOR_SECRET_V1, _ANCHOR_SECRET_V2)
        # Seal an anchor under the new generation as well.
        followup = store.submit("tenant-a", "subject-2", ["email"], "key-2")
        store.transition("tenant-a", followup["request_id"], "failed")
        self.assertTrue(store.verify_chain())
        self.assertEqual(store.diagnose_chain(), [])

        store.backup_to(self.target)

        # Rebuilt with the current secret and the historical generation:
        # identical conclusions to the source.
        rebuilt = RequestStore(
            self.target,
            anchor_secret=_ANCHOR_SECRET_V2,
            anchor_history_secrets={1: _ANCHOR_SECRET_V1},
        )
        self.assertTrue(rebuilt.verify_chain())
        self.assertEqual(rebuilt.diagnose_chain(), [])

        # Rebuilt missing the historical secret: the same untrusted
        # conclusion and reason code the source would give.
        source_missing = RequestStore(self.db_path, anchor_secret=_ANCHOR_SECRET_V2)
        snapshot_missing = RequestStore(self.target, anchor_secret=_ANCHOR_SECRET_V2)
        self.assertFalse(snapshot_missing.verify_chain())
        self.assertIn("anchor_key_missing", snapshot_missing.diagnose_chain())
        self.assertEqual(
            snapshot_missing.diagnose_chain(), source_missing.diagnose_chain()
        )

    def test_snapshot_preserves_inspection_bookkeeping(self):
        store = RequestStore(self.db_path, anchor_secret=_ANCHOR_SECRET_V1)
        first = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        store.submit("tenant-a", "subject-2", ["email"], "key-2")
        page = store.audit_inspection("tenant-a", limit=1)
        batch_id = page["batch_id"]
        cursor = page["next_cursor"]
        self.assertIsNotNone(cursor)

        store.backup_to(self.target)

        snapshot = RequestStore(self.target, anchor_secret=_ANCHOR_SECRET_V1)
        self.assertEqual(
            snapshot.audit_inspection_summary("tenant-a", batch_id),
            store.audit_inspection_summary("tenant-a", batch_id),
        )
        self.assertEqual(
            snapshot.audit_inspection_metrics("tenant-a", batch_id),
            store.audit_inspection_metrics("tenant-a", batch_id),
        )
        self.assertEqual(
            snapshot.audit_metrics("tenant-a", [batch_id]),
            store.audit_metrics("tenant-a", [batch_id]),
        )
        # The snapshot resumes the same batch from the committed position.
        resumed = snapshot.audit_inspection("tenant-a", cursor=cursor)
        self.assertEqual(resumed["batch_id"], batch_id)
        self.assertEqual(len(resumed["items"]), 1)
        self.assertNotEqual(resumed["items"][0]["request_id"], first["request_id"])

    def test_backup_from_memory_store(self):
        store = RequestStore(":memory:")
        receipt = store.submit("tenant-a", "subject-1", ["email"], "key-1")

        result = store.backup_to(self.target)

        self.assertEqual(result, self.target)
        snapshot = RequestStore(self.target)
        self.assertEqual(
            snapshot.get("tenant-a", receipt["request_id"]), receipt
        )

    def test_snapshot_contains_no_secret_material(self):
        store = RequestStore(self.db_path, anchor_secret=_ANCHOR_SECRET_V1)
        _populate(store)
        store.rotate_anchor_key(_ANCHOR_SECRET_V1, _ANCHOR_SECRET_V2)

        store.backup_to(self.target)

        with open(self.target, "rb") as handle:
            content = handle.read()
        for secret in (_ANCHOR_SECRET_V1, _ANCHOR_SECRET_V2, _RECEIPT_KEY):
            self.assertNotIn(secret.encode("utf-8"), content)

    def test_backup_during_concurrent_writes_stays_consistent(self):
        store = RequestStore(self.db_path, anchor_secret=_ANCHOR_SECRET_V1)
        store.submit("tenant-a", "subject-0", ["email"], "key-0")
        stop = threading.Event()
        write_errors = []

        def writer():
            counter = 0
            while not stop.is_set():
                counter += 1
                try:
                    store.submit(
                        "tenant-b", f"subject-{counter}", ["email"], f"key-{counter}"
                    )
                except Exception as exc:  # pragma: no cover - failure aid
                    write_errors.append(exc)
                    return

        thread = threading.Thread(target=writer)
        thread.start()
        try:
            store.backup_to(self.target)
        finally:
            stop.set()
            thread.join()

        self.assertEqual(write_errors, [])
        snapshot = RequestStore(self.target, anchor_secret=_ANCHOR_SECRET_V1)
        # Every transaction either landed in full or not at all: the
        # snapshot's own audit chain verifies end to end.
        self.assertTrue(snapshot.verify_chain())
        self.assertEqual(snapshot.diagnose_chain(), [])

    def test_error_messages_carry_no_path_or_payload(self):
        store = RequestStore(self.db_path)
        _populate(store)
        target = os.path.join(self._tmp.name, "missing", "snapshot.db")
        try:
            store.backup_to(target)
        except OSError as exc:
            self.assertNotIn(target, str(exc))
            self.assertNotIn("tenant", str(exc))
        try:
            store.backup_to("")
        except ValueError as exc:
            self.assertNotIn("tenant", str(exc))

    @staticmethod
    def _file_bytes(path):
        with open(path, "rb") as handle:
            return handle.read()


class BackupSummaryShapeTests(unittest.TestCase):
    """The snapshot serves the read-only aggregates with identical text."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "evidence.db")
        self.target = os.path.join(self._tmp.name, "snapshot.db")

    def tearDown(self):
        self._tmp.cleanup()

    def test_summary_lines_match_byte_for_byte(self):
        store = RequestStore(self.db_path)
        store.submit("tenant-a", "subject-1", ["email"], "key-1")
        page = store.audit_inspection("tenant-a")
        batch_id = page["batch_id"]

        store.backup_to(self.target)

        snapshot = RequestStore(self.target)
        summary = snapshot.audit_inspection_summary("tenant-a", batch_id)
        metrics = snapshot.audit_inspection_metrics("tenant-a", batch_id)
        aggregate = snapshot.audit_metrics("tenant-a", [batch_id])
        for line in (summary, metrics, aggregate):
            self.assertTrue(line.endswith("\n"))
            json.loads(line)
        self.assertEqual(summary, store.audit_inspection_summary("tenant-a", batch_id))
        self.assertEqual(metrics, store.audit_inspection_metrics("tenant-a", batch_id))
        self.assertEqual(aggregate, store.audit_metrics("tenant-a", [batch_id]))


if __name__ == "__main__":
    unittest.main()
