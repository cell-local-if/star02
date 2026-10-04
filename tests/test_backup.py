"""Tests for RequestStore.backup_to storage-layer snapshots.

Covers the backup entry point: target-path validation (ValueError),
existing-target and racing-backup conflicts (BackupConflict), the
fixed-text storage failure (OSError) for unreadable/corrupt sources,
missing directories and failed validation, atomic temp-file staging
with no leftover artifacts, transaction-consistent content across
requests, statuses, executions, receipts, anchors and inspection
bookkeeping, source immutability, and secret confidentiality.

Also covers the strictly read-only ``backup_database`` export behind
the ``python -m forgetting_evidence backup`` command and the command's
fixed markers and exit codes.
"""

import contextlib
import hashlib
import io
import os
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor

from forgetting_evidence.requests import (
    BackupConflict,
    RequestStore,
    backup_database,
)
from forgetting_evidence.__main__ import main

SECRET_A = "anchor-secret-alpha-0001"
SECRET_B = "anchor-secret-bravo-0002"
RECEIPT_KEY = "receipt-key-0001"


def _sha256(path):
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


class BackupTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "evidence.db")
        self.target = os.path.join(self._tmp.name, "snapshot.db")

    def tearDown(self):
        self._tmp.cleanup()

    def _populated_store(self):
        """Build a store exercising every persisted capability."""
        store = RequestStore(self.db_path, anchor_secret=SECRET_A)
        # A completed request with execution history and a receipt.
        first = store.submit("tenant-a", "subject-1", ["email"], "idem-1")
        claim = store.claim_next("tenant-a", "worker-1", 60)
        self.assertEqual(claim["request_id"], first["request_id"])
        store.finish_claim(
            "tenant-a", first["request_id"], claim["claim_token"], "completed"
        )
        receipt = store.generate_receipt("tenant-a", first["request_id"], RECEIPT_KEY)
        # A request still in flight and one left accepted.
        second = store.submit("tenant-a", "subject-2", ["profile"], "idem-2")
        store.transition("tenant-a", second["request_id"], "processing")
        store.submit("tenant-a", "subject-3", ["email"], "idem-3")
        # Anchor key rotation, so the file carries two generations.
        store.rotate_anchor_key(SECRET_A, SECRET_B)
        store.submit("tenant-b", "subject-9", ["email"], "idem-9")
        # An inspection batch with committed progress.
        page = store.audit_inspection("tenant-a")
        self.assertTrue(page["items"])
        return store, first, second, receipt, page

    def test_backup_returns_target_and_snapshot_matches_source(self):
        store, first, second, receipt, page = self._populated_store()
        result = store.backup_to(self.target)
        self.assertEqual(result, self.target)
        self.assertTrue(os.path.isfile(self.target))

        snapshot = RequestStore(self.target, anchor_secret=SECRET_B,
                                anchor_history_secrets={1: SECRET_A})
        # Acceptance and status records survive identically.
        self.assertEqual(snapshot.get("tenant-a", first["request_id"]), first)
        self.assertEqual(
            snapshot.get_status("tenant-a", second["request_id"]),
            store.get_status("tenant-a", second["request_id"]),
        )
        # Execution history survives identically.
        self.assertEqual(
            snapshot.get_execution_log("tenant-a", first["request_id"]),
            store.get_execution_log("tenant-a", first["request_id"]),
        )
        # The persisted receipt is served byte-identically.
        self.assertEqual(
            snapshot.generate_receipt("tenant-a", first["request_id"], RECEIPT_KEY),
            receipt,
        )
        # Chain verification reaches the same conclusion.
        self.assertTrue(store.verify_chain())
        self.assertTrue(snapshot.verify_chain())
        self.assertEqual(snapshot.diagnose_chain(), [])
        # Inspection bookkeeping keeps its progress and aggregates.
        batch_id = page["batch_id"]
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

    def test_snapshot_is_openable_plain_sqlite_and_consistent(self):
        store, _first, _second, _receipt, _page = self._populated_store()
        store.backup_to(self.target)
        with sqlite3.connect(self.target) as conn:
            self.assertEqual(
                conn.execute("PRAGMA integrity_check").fetchall(), [("ok",)]
            )
            names = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }
        for table in (
            "requests",
            "status_events",
            "claim_attempts",
            "claim_tokens",
            "reconcile_batches",
            "reconcile_batch_items",
            "inspection_batches",
            "inspection_batch_items",
            "deletion_receipts",
            "receipt_keys",
            "audit_anchors",
            "audit_anchor_meta",
            "anchor_key_generations",
        ):
            self.assertIn(table, names)

    def test_source_database_is_untouched(self):
        store, _first, _second, _receipt, _page = self._populated_store()
        before = _sha256(self.db_path)
        store.backup_to(self.target)
        self.assertEqual(_sha256(self.db_path), before)

    def test_snapshot_contains_no_secret_material(self):
        store, _first, _second, _receipt, _page = self._populated_store()
        store.backup_to(self.target)
        with open(self.target, "rb") as handle:
            content = handle.read()
        for secret in (SECRET_A, SECRET_B, RECEIPT_KEY):
            self.assertNotIn(secret.encode(), content)

    def test_rebuilt_snapshot_without_history_secret_keeps_same_diagnosis(self):
        store, _first, _second, _receipt, _page = self._populated_store()
        store.backup_to(self.target)
        # Both source and snapshot, rebuilt without the generation-1
        # secret, must report the same untrusted conclusion and codes.
        source_rebuilt = RequestStore(self.db_path, anchor_secret=SECRET_B)
        snapshot_rebuilt = RequestStore(self.target, anchor_secret=SECRET_B)
        self.assertFalse(source_rebuilt.verify_chain())
        self.assertFalse(snapshot_rebuilt.verify_chain())
        self.assertEqual(
            snapshot_rebuilt.diagnose_chain(), source_rebuilt.diagnose_chain()
        )
        self.assertIn("anchor_key_missing", snapshot_rebuilt.diagnose_chain())

    def test_empty_and_non_string_targets_raise_value_error(self):
        store, _first, _second, _receipt, _page = self._populated_store()
        before = _sha256(self.db_path)
        for bad in ("", None, 123, b"bytes", ":memory:"):
            with self.assertRaises(ValueError):
                store.backup_to(bad)
        self.assertEqual(_sha256(self.db_path), before)
        self.assertFalse(os.path.exists(self.target))

    def test_directory_target_raises_value_error(self):
        store, _first, _second, _receipt, _page = self._populated_store()
        with self.assertRaises(ValueError):
            store.backup_to(self._tmp.name)

    def test_existing_target_raises_conflict_and_is_not_overwritten(self):
        store, _first, _second, _receipt, _page = self._populated_store()
        with open(self.target, "wb") as handle:
            handle.write(b"pre-existing content")
        with self.assertRaises(BackupConflict):
            store.backup_to(self.target)
        with open(self.target, "rb") as handle:
            self.assertEqual(handle.read(), b"pre-existing content")

    def test_second_backup_to_same_target_raises_conflict(self):
        store, _first, _second, _receipt, _page = self._populated_store()
        store.backup_to(self.target)
        with self.assertRaises(BackupConflict):
            store.backup_to(self.target)

    def test_missing_directory_is_fixed_text_storage_error(self):
        store, _first, _second, _receipt, _page = self._populated_store()
        missing = os.path.join(self._tmp.name, "no-such-dir", "snapshot.db")
        with self.assertRaises(OSError) as caught:
            store.backup_to(missing)
        self.assertEqual(str(caught.exception), "request store is unavailable")
        self.assertFalse(os.path.exists(missing))

    def test_corrupt_source_is_fixed_text_storage_error_without_target(self):
        store, _first, _second, _receipt, _page = self._populated_store()
        with open(self.db_path, "r+b") as handle:
            handle.write(b"not-a-sqlite-database-at-all")
        with self.assertRaises(OSError) as caught:
            store.backup_to(self.target)
        self.assertEqual(str(caught.exception), "request store is unavailable")
        # No target and no staged temporary file is left behind.
        self.assertFalse(os.path.exists(self.target))
        leftovers = [
            name
            for name in os.listdir(self._tmp.name)
            if name.startswith(".forgetting-evidence-backup-")
        ]
        self.assertEqual(leftovers, [])

    def test_concurrent_backups_to_same_target_land_exactly_once(self):
        store, _first, _second, _receipt, _page = self._populated_store()
        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(
                pool.map(lambda _ignored: self._backup_once(store), range(2))
            )
        self.assertEqual(outcomes.count("ok"), 1)
        self.assertEqual(outcomes.count("conflict"), 1)
        # The single landed snapshot is a valid, openable store.
        snapshot = RequestStore(self.target, anchor_secret=SECRET_B,
                                anchor_history_secrets={1: SECRET_A})
        self.assertTrue(snapshot.verify_chain())

    def _backup_once(self, store):
        try:
            store.backup_to(self.target)
        except BackupConflict:
            return "conflict"
        return "ok"

    def test_backup_from_memory_store(self):
        store = RequestStore(":memory:", anchor_secret=SECRET_A)
        accepted = store.submit("tenant-a", "subject-1", ["email"], "idem-1")
        store.backup_to(self.target)
        snapshot = RequestStore(self.target, anchor_secret=SECRET_A)
        self.assertEqual(snapshot.get("tenant-a", accepted["request_id"]), accepted)
        self.assertTrue(snapshot.verify_chain())

    def test_error_messages_carry_no_path_or_secret(self):
        store, _first, _second, _receipt, _page = self._populated_store()
        with open(self.target, "wb") as handle:
            handle.write(b"taken")
        with self.assertRaises(BackupConflict) as conflict:
            store.backup_to(self.target)
        self.assertNotIn(self.target, str(conflict.exception))
        with self.assertRaises(ValueError) as invalid:
            store.backup_to("")
        self.assertNotIn(self.target, str(invalid.exception))
        missing = os.path.join(self._tmp.name, "absent", "snapshot.db")
        with self.assertRaises(OSError) as storage:
            store.backup_to(missing)
        self.assertNotIn(missing, str(storage.exception))
        self.assertNotIn(SECRET_A, str(storage.exception))


class BackupCommandTests(unittest.TestCase):
    """The read-only backup_database export and the backup CLI command."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "evidence.db")
        self.target = os.path.join(self._tmp.name, "snapshot.db")

    def tearDown(self):
        self._tmp.cleanup()

    def _populated_store(self):
        store = RequestStore(self.db_path, anchor_secret=SECRET_A)
        first = store.submit("tenant-a", "subject-1", ["email"], "idem-1")
        claim = store.claim_next("tenant-a", "worker-1", 60)
        self.assertEqual(claim["request_id"], first["request_id"])
        store.finish_claim(
            "tenant-a", first["request_id"], claim["claim_token"], "completed"
        )
        receipt = store.generate_receipt("tenant-a", first["request_id"], RECEIPT_KEY)
        second = store.submit("tenant-a", "subject-2", ["profile"], "idem-2")
        store.transition("tenant-a", second["request_id"], "processing")
        store.submit("tenant-a", "subject-3", ["email"], "idem-3")
        store.rotate_anchor_key(SECRET_A, SECRET_B)
        store.submit("tenant-b", "subject-9", ["email"], "idem-9")
        page = store.audit_inspection("tenant-a")
        self.assertTrue(page["items"])
        return store, first, second, receipt, page

    def _assert_no_staging_files(self):
        leftovers = [
            name
            for name in os.listdir(self._tmp.name)
            if name.startswith(".forgetting-evidence-backup-")
        ]
        self.assertEqual(leftovers, [])

    # -- backup_database roundtrip --------------------------------------

    def test_backup_database_returns_target_and_snapshot_matches_source(self):
        store, first, second, receipt, page = self._populated_store()
        result = backup_database(self.db_path, self.target)
        self.assertEqual(result, self.target)
        snapshot = RequestStore(
            self.target, anchor_secret=SECRET_B,
            anchor_history_secrets={1: SECRET_A},
        )
        self.assertEqual(
            snapshot.get("tenant-a", first["request_id"]),
            store.get("tenant-a", first["request_id"]),
        )
        self.assertEqual(
            snapshot.get_status("tenant-a", second["request_id"]),
            store.get_status("tenant-a", second["request_id"]),
        )
        self.assertEqual(
            snapshot.get_execution_log("tenant-a", first["request_id"]),
            store.get_execution_log("tenant-a", first["request_id"]),
        )
        self.assertEqual(
            snapshot.generate_receipt("tenant-a", first["request_id"], RECEIPT_KEY),
            receipt,
        )
        self.assertTrue(snapshot.verify_chain())
        self.assertEqual(snapshot.diagnose_chain(), store.diagnose_chain())
        self.assertEqual(
            snapshot.verify_audit_chain("tenant-a", first["request_id"]),
            store.verify_audit_chain("tenant-a", first["request_id"]),
        )
        self.assertEqual(
            snapshot.audit_health("tenant-a"), store.audit_health("tenant-a")
        )
        batch_id = page["batch_id"]
        self.assertEqual(
            snapshot.audit_inspection_summary("tenant-a", batch_id),
            store.audit_inspection_summary("tenant-a", batch_id),
        )
        self.assertEqual(
            snapshot.audit_inspection_metrics("tenant-a", batch_id),
            store.audit_inspection_metrics("tenant-a", batch_id),
        )

    def test_backup_database_snapshot_is_consistent_plain_sqlite(self):
        self._populated_store()
        backup_database(self.db_path, self.target)
        with sqlite3.connect(self.target) as conn:
            self.assertEqual(
                conn.execute("PRAGMA integrity_check").fetchall(), [("ok",)]
            )
            names = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }
        for table in (
            "requests",
            "status_events",
            "claim_attempts",
            "claim_tokens",
            "inspection_batches",
            "inspection_batch_items",
            "deletion_receipts",
            "receipt_keys",
            "audit_anchors",
            "audit_anchor_meta",
            "anchor_key_generations",
        ):
            self.assertIn(table, names)

    def test_backup_database_leaves_source_byte_identical(self):
        self._populated_store()
        before = _sha256(self.db_path)
        backup_database(self.db_path, self.target)
        self.assertEqual(_sha256(self.db_path), before)
        # A repeat rebuild and another backup cannot move the source.
        RequestStore(self.db_path, anchor_secret=SECRET_B,
                     anchor_history_secrets={1: SECRET_A})
        second = os.path.join(self._tmp.name, "snapshot-2.db")
        backup_database(self.db_path, second)
        self.assertEqual(_sha256(self.db_path), before)

    def test_backup_database_creates_no_source_sidecars(self):
        self._populated_store()
        backup_database(self.db_path, self.target)
        sidecars = [
            name
            for name in os.listdir(self._tmp.name)
            if name.startswith("evidence.db-wal")
            or name.startswith("evidence.db-journal")
            or name.startswith("evidence.db-shm")
        ]
        self.assertEqual(sidecars, [])

    def test_backup_database_snapshot_carries_no_secret(self):
        self._populated_store()
        backup_database(self.db_path, self.target)
        with open(self.target, "rb") as handle:
            content = handle.read()
        for secret in (SECRET_A, SECRET_B, RECEIPT_KEY):
            self.assertNotIn(secret.encode(), content)

    # -- backup_database validation --------------------------------------

    def test_backup_database_invalid_paths_raise_value_error(self):
        self._populated_store()
        bad_values = ("", None, 123, b"bytes", ":memory:", "a\x00b")
        for bad in bad_values:
            with self.assertRaises(ValueError):
                backup_database(bad, self.target)
            with self.assertRaises(ValueError):
                backup_database(self.db_path, bad)
        self.assertFalse(os.path.exists(self.target))

    def test_backup_database_directory_target_raises_value_error(self):
        self._populated_store()
        with self.assertRaises(ValueError):
            backup_database(self.db_path, self._tmp.name)

    def test_backup_database_existing_target_raises_conflict(self):
        self._populated_store()
        with open(self.target, "wb") as handle:
            handle.write(b"pre-existing content")
        with self.assertRaises(BackupConflict):
            backup_database(self.db_path, self.target)
        with open(self.target, "rb") as handle:
            self.assertEqual(handle.read(), b"pre-existing content")

    def test_backup_database_second_run_raises_conflict(self):
        self._populated_store()
        backup_database(self.db_path, self.target)
        with self.assertRaises(BackupConflict):
            backup_database(self.db_path, self.target)

    def test_backup_database_missing_source_is_fixed_text_failure(self):
        missing = os.path.join(self._tmp.name, "absent.db")
        with self.assertRaises(OSError) as caught:
            backup_database(missing, self.target)
        self.assertEqual(str(caught.exception), "request store is unavailable")
        self.assertFalse(os.path.exists(missing))
        self.assertFalse(os.path.exists(self.target))

    def test_backup_database_corrupt_source_is_fixed_text_failure(self):
        self._populated_store()
        with open(self.db_path, "r+b") as handle:
            handle.write(b"not-a-sqlite-database-at-all")
        with self.assertRaises(OSError):
            backup_database(self.db_path, self.target)
        self.assertFalse(os.path.exists(self.target))
        self._assert_no_staging_files()

    def test_backup_database_sqlite_file_without_schema_is_failure(self):
        self._populated_store()
        plain = os.path.join(self._tmp.name, "plain.db")
        with sqlite3.connect(plain) as conn:
            conn.execute("CREATE TABLE unrelated (id INTEGER PRIMARY KEY)")
            conn.execute("INSERT INTO unrelated VALUES (1)")
        with self.assertRaises(OSError):
            backup_database(plain, self.target)
        self.assertFalse(os.path.exists(self.target))
        self._assert_no_staging_files()

    def test_backup_database_missing_parent_is_fixed_text_failure(self):
        self._populated_store()
        missing = os.path.join(self._tmp.name, "no-such-dir", "snapshot.db")
        with self.assertRaises(OSError):
            backup_database(self.db_path, missing)
        self.assertFalse(os.path.exists(missing))
        self._assert_no_staging_files()

    def test_backup_database_concurrent_land_exactly_once(self):
        self._populated_store()
        with ThreadPoolExecutor(max_workers=4) as pool:
            outcomes = list(
                pool.map(lambda _i: self._backup_once(), range(4))
            )
        self.assertEqual(outcomes.count("ok"), 1)
        self.assertEqual(outcomes.count("conflict"), 3)
        snapshot = RequestStore(
            self.target, anchor_secret=SECRET_B,
            anchor_history_secrets={1: SECRET_A},
        )
        self.assertTrue(snapshot.verify_chain())

    def _backup_once(self):
        try:
            backup_database(self.db_path, self.target)
        except BackupConflict:
            return "conflict"
        return "ok"

    def test_backup_database_error_messages_carry_no_path(self):
        self._populated_store()
        with open(self.target, "wb") as handle:
            handle.write(b"taken")
        with self.assertRaises(BackupConflict) as conflict:
            backup_database(self.db_path, self.target)
        self.assertNotIn(self.target, str(conflict.exception))
        with self.assertRaises(ValueError) as invalid:
            backup_database(self.db_path, "")
        self.assertNotIn(self.target, str(invalid.exception))
        missing = os.path.join(self._tmp.name, "absent.db")
        other_target = os.path.join(self._tmp.name, "other-snapshot.db")
        with self.assertRaises(OSError) as failed:
            backup_database(missing, other_target)
        self.assertNotIn(missing, str(failed.exception))

    # -- CLI -------------------------------------------------------------

    def _run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["backup", *argv])
        return code, out.getvalue(), err.getvalue()

    def test_cli_success_outputs_one_json_line_and_zero(self):
        self._populated_store()
        code, out, err = self._run_cli(self.db_path, self.target)
        self.assertEqual(code, 0)
        self.assertEqual(out, '{"status":"backed_up"}\n')
        self.assertEqual(err, "")
        self.assertTrue(os.path.isfile(self.target))

    def test_cli_wrong_argument_count_is_usage_exit_2(self):
        self._populated_store()
        for argv in (
            (),
            (self.db_path,),
            (self.db_path, self.target, "extra"),
        ):
            code, out, err = self._run_cli(*argv)
            self.assertEqual(code, 2)
            self.assertEqual(out, "")
            self.assertEqual(err.strip(), "backup_usage")

    def test_cli_existing_target_is_conflict_exit_3(self):
        self._populated_store()
        with open(self.target, "wb") as handle:
            handle.write(b"taken")
        code, out, err = self._run_cli(self.db_path, self.target)
        self.assertEqual(code, 3)
        self.assertEqual(out, "")
        self.assertEqual(err.strip(), "backup_conflict")
        with open(self.target, "rb") as handle:
            self.assertEqual(handle.read(), b"taken")

    def test_cli_missing_source_is_failure_exit_2(self):
        missing = os.path.join(self._tmp.name, "absent.db")
        code, out, err = self._run_cli(missing, self.target)
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertEqual(err.strip(), "backup_failed")
        self.assertFalse(os.path.exists(self.target))

    def test_cli_empty_target_is_failure_exit_2(self):
        self._populated_store()
        code, out, err = self._run_cli(self.db_path, "")
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertEqual(err.strip(), "backup_failed")

    def test_cli_directory_target_is_failure_exit_2(self):
        self._populated_store()
        code, out, err = self._run_cli(self.db_path, self._tmp.name)
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertEqual(err.strip(), "backup_failed")

    def test_cli_corrupt_source_is_failure_exit_2_without_leftovers(self):
        self._populated_store()
        with open(self.db_path, "r+b") as handle:
            handle.write(b"not-a-sqlite-database-at-all")
        code, out, err = self._run_cli(self.db_path, self.target)
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertEqual(err.strip(), "backup_failed")
        self.assertFalse(os.path.exists(self.target))
        self._assert_no_staging_files()

    def test_cli_missing_parent_is_failure_exit_2(self):
        self._populated_store()
        missing = os.path.join(self._tmp.name, "no-such-dir", "snapshot.db")
        code, out, err = self._run_cli(self.db_path, missing)
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertEqual(err.strip(), "backup_failed")
        self.assertFalse(os.path.exists(missing))

    def test_cli_does_not_change_source(self):
        self._populated_store()
        before = _sha256(self.db_path)
        self._run_cli(self.db_path, self.target)
        self._run_cli(self.db_path, os.path.join(self._tmp.name, "again.db"))
        self.assertEqual(_sha256(self.db_path), before)


if __name__ == "__main__":
    unittest.main()
