"""Tests for the create-only snapshot restore entry point.

Covers ``restore_backup``: a complete roundtrip that reopens through
``RequestStore`` with identical requests, statuses, execution attempts,
receipts, tombstones, audit anchors, inspection bookkeeping, policy
catalog and evidence conclusions; source immutability; path validation
(ValueError for empty, non-string, in-memory, NUL-bearing and directory
paths); existing-target and racing-target conflicts (RestoreConflict)
for files, directories and symbolic links; the fixed-text
``restore_failed`` OSError for missing, unreadable, incomplete or
inconsistent snapshots, missing parents and failed landings; the
all-or-nothing staging guarantee with no leftover artifacts; and the
``python -m forgetting_evidence restore`` command markers and exit
codes.
"""

import contextlib
import hashlib
import io
import os
import pathlib
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor

from forgetting_evidence.requests import (
    RequestStore,
    RestoreConflict,
    restore_backup,
)
from forgetting_evidence.__main__ import main

SECRET_A = "anchor-secret-alpha-0001"
SECRET_B = "anchor-secret-bravo-0002"
RECEIPT_KEY = "receipt-key-0001"


def _sha256(path):
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


class _BadPath(os.PathLike):
    """A path-like whose fspath returns a non-str/non-bytes value."""

    def __fspath__(self):
        return 123


class RestoreTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "source.db")
        self.snapshot = os.path.join(self._tmp.name, "snapshot.db")
        self.target = os.path.join(self._tmp.name, "restored.db")

    def tearDown(self):
        self._tmp.cleanup()

    def _populated_snapshot(self):
        """Build a snapshot exercising every persisted capability."""
        store = RequestStore(self.db_path, anchor_secret=SECRET_A)
        # A completed request with execution history and a receipt.
        first = store.submit("tenant-a", "subject-1", ["email"], "idem-1")
        claim = store.claim_next("tenant-a", "worker-1", 60)
        self.assertEqual(claim["request_id"], first["request_id"])
        store.finish_claim(
            "tenant-a", first["request_id"], claim["claim_token"], "completed"
        )
        receipt = store.generate_receipt(
            "tenant-a", first["request_id"], RECEIPT_KEY
        )
        # A request whose deletion recorded per-scope tombstones.
        second = store.submit(
            "tenant-a", "subject-2", ["email", "profile"], "idem-2"
        )
        claim2 = store.claim_next("tenant-a", "worker-2", 60)
        proof = hashlib.sha256(b"op-2").hexdigest()
        tombstones = [
            {
                "adapter_id": "adapter-1",
                "scope": "email",
                "operation_id": "op-email",
                "outcome": "deleted",
                "proof_digest": proof,
            },
            {
                "adapter_id": "adapter-1",
                "scope": "profile",
                "operation_id": "op-profile",
                "outcome": "absent",
                "proof_digest": hashlib.sha256(b"op-3").hexdigest(),
            },
        ]
        store.record_deletion_tombstones(
            "tenant-a", second["request_id"], claim2["claim_token"], tombstones
        )
        store.finish_scoped_claim(
            "tenant-a", second["request_id"], claim2["claim_token"], "completed"
        )
        # A request still in flight and one left accepted.
        third = store.submit("tenant-a", "subject-3", ["profile"], "idem-3")
        store.transition("tenant-a", third["request_id"], "processing")
        store.submit("tenant-a", "subject-4", ["email"], "idem-4")
        # Anchor key rotation, so the file carries two generations.
        store.rotate_anchor_key(SECRET_A, SECRET_B)
        store.submit("tenant-b", "subject-9", ["email"], "idem-9")
        # A policy catalog publication.
        store.publish_policy_catalog(
            "tenant-a",
            {"p-default": {"selector": "*", "days": 30, "reason": "default"}},
            {},
        )
        # An inspection batch with committed progress.
        page = store.audit_inspection("tenant-a")
        self.assertTrue(page["items"])
        store.backup_to(self.snapshot)
        return store, first, second, receipt, page

    def _reopen_restored(self):
        return RequestStore(
            self.target,
            anchor_secret=SECRET_B,
            anchor_history_secrets={1: SECRET_A},
        )

    # -- roundtrip parity ------------------------------------------------

    def test_restore_returns_target_and_restored_matches_snapshot(self):
        store, first, second, receipt, page = self._populated_snapshot()
        snapshot = RequestStore(
            self.snapshot,
            anchor_secret=SECRET_B,
            anchor_history_secrets={1: SECRET_A},
        )
        result = restore_backup(self.snapshot, self.target)
        self.assertEqual(result, self.target)
        restored = self._reopen_restored()

        # Requests and statuses survive identically.
        self.assertEqual(restored.get("tenant-a", first["request_id"]),
                         snapshot.get("tenant-a", first["request_id"]))
        self.assertEqual(restored.get("tenant-a", second["request_id"]),
                         snapshot.get("tenant-a", second["request_id"]))
        for request_id in (first["request_id"], second["request_id"]):
            self.assertEqual(
                restored.get_status("tenant-a", request_id),
                snapshot.get_status("tenant-a", request_id),
            )
            # Execution attempts survive identically.
            self.assertEqual(
                restored.get_execution_log("tenant-a", request_id),
                snapshot.get_execution_log("tenant-a", request_id),
            )
        # Tombstones survive identically.
        self.assertEqual(
            restored.get_deletion_tombstones("tenant-a", second["request_id"]),
            snapshot.get_deletion_tombstones("tenant-a", second["request_id"]),
        )
        # The persisted receipt is served byte-identically.
        self.assertEqual(
            restored.generate_receipt("tenant-a", first["request_id"], RECEIPT_KEY),
            receipt,
        )
        # Audit anchors reach the same evidence conclusions.
        self.assertTrue(store.verify_chain())
        self.assertTrue(snapshot.verify_chain())
        self.assertTrue(restored.verify_chain())
        self.assertEqual(restored.diagnose_chain(), snapshot.diagnose_chain())
        self.assertEqual(
            restored.verify_audit_chain("tenant-a", first["request_id"]),
            snapshot.verify_audit_chain("tenant-a", first["request_id"]),
        )
        self.assertEqual(
            restored.diagnose_audit_chain("tenant-a", first["request_id"]),
            snapshot.diagnose_audit_chain("tenant-a", first["request_id"]),
        )
        self.assertEqual(
            restored.evidence("tenant-a", first["request_id"]),
            snapshot.evidence("tenant-a", first["request_id"]),
        )
        self.assertEqual(
            restored.export_audit_bundle("tenant-a", first["request_id"]),
            snapshot.export_audit_bundle("tenant-a", first["request_id"]),
        )
        self.assertEqual(
            restored.audit_health("tenant-a"),
            snapshot.audit_health("tenant-a"),
        )
        # Inspection bookkeeping keeps its progress and aggregates.
        batch_id = page["batch_id"]
        self.assertEqual(
            restored.audit_inspection_summary("tenant-a", batch_id),
            snapshot.audit_inspection_summary("tenant-a", batch_id),
        )
        self.assertEqual(
            restored.audit_inspection_metrics("tenant-a", batch_id),
            snapshot.audit_inspection_metrics("tenant-a", batch_id),
        )
        self.assertEqual(
            restored.audit_metrics("tenant-a", [batch_id]),
            snapshot.audit_metrics("tenant-a", [batch_id]),
        )
        # The policy catalog survives identically.
        self.assertEqual(
            restored.read_policy_catalog("tenant-a"),
            snapshot.read_policy_catalog("tenant-a"),
        )
        self.assertEqual(
            restored.audit_policy_catalog("tenant-a"),
            snapshot.audit_policy_catalog("tenant-a"),
        )

    def test_restored_file_passes_sqlite_consistency_and_table_structure(self):
        self._populated_snapshot()
        restore_backup(self.snapshot, self.target)
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
            "policy_catalog_versions",
            "policy_catalog_rules",
            "policy_catalog_exceptions",
        ):
            self.assertIn(table, names)

    def test_restored_bytes_equal_snapshot_bytes(self):
        self._populated_snapshot()
        restore_backup(self.snapshot, self.target)
        self.assertEqual(_sha256(self.target), _sha256(self.snapshot))

    def test_source_snapshot_is_untouched(self):
        self._populated_snapshot()
        before = _sha256(self.snapshot)
        restore_backup(self.snapshot, self.target)
        self.assertEqual(_sha256(self.snapshot), before)

    def test_restore_accepts_pathlib_paths(self):
        self._populated_snapshot()
        result = restore_backup(
            pathlib.Path(self.snapshot), pathlib.Path(self.target)
        )
        self.assertEqual(result, str(pathlib.Path(self.target)))
        self.assertTrue(os.path.isfile(self.target))

    def test_restore_from_in_memory_backup(self):
        store = RequestStore(":memory:", anchor_secret=SECRET_A)
        accepted = store.submit("tenant-a", "subject-1", ["email"], "idem-1")
        store.backup_to(self.snapshot)
        restore_backup(self.snapshot, self.target)
        restored = RequestStore(self.target, anchor_secret=SECRET_A)
        self.assertEqual(
            restored.get("tenant-a", accepted["request_id"]), accepted
        )
        self.assertTrue(restored.verify_chain())

    # -- path validation -------------------------------------------------

    def test_empty_and_non_string_paths_raise_value_error(self):
        self._populated_snapshot()
        before = _sha256(self.snapshot)
        bad_values = ("", None, 123, b"bytes", ":memory:", "a\x00b", _BadPath())
        for bad in bad_values:
            with self.assertRaises(ValueError):
                restore_backup(bad, self.target)
            with self.assertRaises(ValueError):
                restore_backup(self.snapshot, bad)
        self.assertEqual(_sha256(self.snapshot), before)
        self.assertFalse(os.path.exists(self.target))

    def test_directory_paths_raise_value_error(self):
        self._populated_snapshot()
        with self.assertRaises(ValueError):
            restore_backup(self._tmp.name, self.target)
        self.assertFalse(os.path.exists(self.target))

    # -- conflicts -------------------------------------------------------

    def test_existing_file_target_raises_conflict_and_is_not_overwritten(self):
        self._populated_snapshot()
        with open(self.target, "wb") as handle:
            handle.write(b"pre-existing content")
        with self.assertRaises(RestoreConflict):
            restore_backup(self.snapshot, self.target)
        with open(self.target, "rb") as handle:
            self.assertEqual(handle.read(), b"pre-existing content")

    def test_existing_directory_target_raises_conflict(self):
        self._populated_snapshot()
        os.mkdir(self.target)
        with self.assertRaises(RestoreConflict):
            restore_backup(self.snapshot, self.target)
        self.assertTrue(os.path.isdir(self.target))

    def test_existing_symlink_target_raises_conflict_and_is_not_replaced(self):
        self._populated_snapshot()
        elsewhere = os.path.join(self._tmp.name, "elsewhere")
        with open(elsewhere, "wb") as handle:
            handle.write(b"link target content")
        os.symlink(elsewhere, self.target)
        with self.assertRaises(RestoreConflict):
            restore_backup(self.snapshot, self.target)
        self.assertTrue(os.path.islink(self.target))
        with open(elsewhere, "rb") as handle:
            self.assertEqual(handle.read(), b"link target content")

    def test_dangling_symlink_target_raises_conflict(self):
        self._populated_snapshot()
        os.symlink(os.path.join(self._tmp.name, "missing"), self.target)
        with self.assertRaises(RestoreConflict):
            restore_backup(self.snapshot, self.target)
        self.assertTrue(os.path.islink(self.target))

    def test_second_restore_to_same_target_raises_conflict(self):
        self._populated_snapshot()
        restore_backup(self.snapshot, self.target)
        with self.assertRaises(RestoreConflict):
            restore_backup(self.snapshot, self.target)

    def test_concurrent_restores_land_exactly_once(self):
        self._populated_snapshot()
        with ThreadPoolExecutor(max_workers=4) as pool:
            outcomes = list(pool.map(lambda _i: self._restore_once(), range(4)))
        self.assertEqual(outcomes.count("ok"), 1)
        self.assertEqual(outcomes.count("conflict"), 3)
        restored = self._reopen_restored()
        self.assertTrue(restored.verify_chain())

    def _restore_once(self):
        try:
            restore_backup(self.snapshot, self.target)
        except RestoreConflict:
            return "conflict"
        return "ok"

    # -- fixed-text failures --------------------------------------------

    def test_missing_snapshot_is_fixed_text_failure(self):
        missing = os.path.join(self._tmp.name, "no-such-snapshot.db")
        with self.assertRaises(OSError) as caught:
            restore_backup(missing, self.target)
        self.assertEqual(str(caught.exception), "restore_failed")
        self.assertFalse(os.path.exists(self.target))

    def test_garbage_snapshot_is_fixed_text_failure_without_leftovers(self):
        with open(self.snapshot, "wb") as handle:
            handle.write(b"not-a-sqlite-database-at-all")
        with self.assertRaises(OSError) as caught:
            restore_backup(self.snapshot, self.target)
        self.assertEqual(str(caught.exception), "restore_failed")
        self.assertFalse(os.path.exists(self.target))
        self._assert_no_staging_files()

    def test_sqlite_file_without_schema_is_fixed_text_failure(self):
        other = os.path.join(self._tmp.name, "plain.db")
        with sqlite3.connect(other) as conn:
            conn.execute("CREATE TABLE unrelated (id INTEGER PRIMARY KEY)")
            conn.execute("INSERT INTO unrelated VALUES (1)")
        with self.assertRaises(OSError) as caught:
            restore_backup(other, self.target)
        self.assertEqual(str(caught.exception), "restore_failed")
        self.assertFalse(os.path.exists(self.target))
        self._assert_no_staging_files()

    def test_truncated_snapshot_is_fixed_text_failure(self):
        self._populated_snapshot()
        size = os.path.getsize(self.snapshot)
        with open(self.snapshot, "r+b") as handle:
            handle.truncate(size // 2)
        with self.assertRaises(OSError):
            restore_backup(self.snapshot, self.target)
        self.assertFalse(os.path.exists(self.target))
        self._assert_no_staging_files()

    def test_missing_parent_directory_is_fixed_text_failure(self):
        self._populated_snapshot()
        missing = os.path.join(self._tmp.name, "no-such-dir", "restored.db")
        with self.assertRaises(OSError) as caught:
            restore_backup(self.snapshot, missing)
        self.assertEqual(str(caught.exception), "restore_failed")
        self.assertFalse(os.path.exists(missing))
        self.assertFalse(os.path.isdir(os.path.dirname(missing)))
        self._assert_no_staging_files()

    def test_directory_snapshot_is_value_error_not_failure(self):
        self._populated_snapshot()
        with self.assertRaises(ValueError):
            restore_backup(self._tmp.name, self.target)

    def test_failure_leaves_no_target_and_no_staging_file(self):
        self._populated_snapshot()
        with open(self.snapshot, "r+b") as handle:
            handle.seek(0)
            handle.write(b"\x00" * 16)
        with self.assertRaises(OSError):
            restore_backup(self.snapshot, self.target)
        self.assertFalse(os.path.exists(self.target))
        self._assert_no_staging_files()

    def _assert_no_staging_files(self):
        leftovers = [
            name
            for name in os.listdir(self._tmp.name)
            if name.startswith(".forgetting-evidence-restore-")
        ]
        self.assertEqual(leftovers, [])

    def test_error_messages_carry_no_path(self):
        self._populated_snapshot()
        with open(self.target, "wb") as handle:
            handle.write(b"taken")
        with self.assertRaises(RestoreConflict) as conflict:
            restore_backup(self.snapshot, self.target)
        self.assertNotIn(self.target, str(conflict.exception))
        with self.assertRaises(ValueError) as invalid:
            restore_backup("", self.target)
        self.assertNotIn(self.target, str(invalid.exception))
        missing = os.path.join(self._tmp.name, "absent.snapshot")
        other_target = os.path.join(self._tmp.name, "other-restored.db")
        with self.assertRaises(OSError) as failed:
            restore_backup(missing, other_target)
        self.assertNotIn(missing, str(failed.exception))

    # -- CLI -------------------------------------------------------------

    def _run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["restore", *argv])
        return code, out.getvalue(), err.getvalue()

    def test_cli_success_outputs_one_json_line_and_zero(self):
        self._populated_snapshot()
        code, out, err = self._run_cli(self.snapshot, self.target)
        self.assertEqual(code, 0)
        self.assertEqual(out, '{"status":"restored"}\n')
        self.assertEqual(err, "")
        self.assertTrue(os.path.isfile(self.target))

    def test_cli_wrong_argument_count_is_usage_exit_2(self):
        self._populated_snapshot()
        for argv in ((), (self.snapshot,), (self.snapshot, self.target, "extra")):
            code, out, err = self._run_cli(*argv)
            self.assertEqual(code, 2)
            self.assertEqual(out, "")
            self.assertEqual(err.strip(), "restore_usage")

    def test_cli_conflict_is_marker_exit_3(self):
        self._populated_snapshot()
        with open(self.target, "wb") as handle:
            handle.write(b"taken")
        code, out, err = self._run_cli(self.snapshot, self.target)
        self.assertEqual(code, 3)
        self.assertEqual(out, "")
        self.assertEqual(err.strip(), "restore_conflict")

    def test_cli_other_failure_is_marker_exit_2(self):
        missing = os.path.join(self._tmp.name, "missing-snapshot.db")
        code, out, err = self._run_cli(missing, self.target)
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertEqual(err.strip(), "restore_failed")

    def test_cli_invalid_path_arguments_are_usage_exit_2(self):
        self._populated_snapshot()
        code, _out, err = self._run_cli(self.snapshot, ":memory:")
        self.assertEqual(code, 2)
        self.assertEqual(err.strip(), "restore_failed")


if __name__ == "__main__":
    unittest.main()
