"""Tests for the read-only snapshot verification entry point.

Covers ``verify_backup``: a valid snapshot verifies clean; a snapshot
missing contract tables, failing SQLite's consistency check, or both
reports the matching reasons; a non-SQLite file, a missing file and an
unreadable candidate report ``not_sqlite``/``read_failed``; empty,
non-string, in-memory, NUL-bearing and directory paths raise the
fixed-text ``ValueError``; and the entry is strictly read-only and
repeatable -- identical JSON on repeated calls, unchanged candidate
bytes and timestamps, and no new files.
"""

import hashlib
import json
import os
import pathlib
import sqlite3
import tempfile
import unittest

from forgetting_evidence.requests import (
    RequestStore,
    run_backup,
    verify_backup,
)

SECRET_A = "anchor-secret-alpha-0001"


def _sha256(path):
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


class _BadPath(os.PathLike):
    """A path-like whose fspath returns a non-str/non-bytes value."""

    def __fspath__(self):
        return 123


class VerifyBackupTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = self._tmp.name
        self.db_path = os.path.join(self.dir, "source.db")
        self.snapshot = os.path.join(self.dir, "snapshot.db")

    def tearDown(self):
        self._tmp.cleanup()

    def _populated_snapshot(self):
        """Build a real snapshot through the existing backup entry."""
        store = RequestStore(self.db_path, anchor_secret=SECRET_A)
        first = store.submit("tenant-a", "subject-1", ["email"], "idem-1")
        claim = store.claim_next("tenant-a", "worker-1", 60)
        store.finish_claim(
            "tenant-a", first["request_id"], claim["claim_token"], "completed"
        )
        run_backup(self.db_path, self.snapshot)
        return self.snapshot

    def _verify(self, path):
        return json.loads(verify_backup(path))

    # -- valid candidates -------------------------------------------------

    def test_valid_snapshot_verifies_clean(self):
        self._populated_snapshot()
        result = verify_backup(self.snapshot)
        self.assertIsInstance(result, str)
        self.assertNotIn("\n", result)
        report = json.loads(result)
        self.assertEqual(
            report,
            {
                "valid": True,
                "tables_ok": True,
                "integrity_ok": True,
                "reasons": [],
            },
        )

    def test_report_is_compact_and_fixed_shape(self):
        self._populated_snapshot()
        result = verify_backup(self.snapshot)
        self.assertTrue(result.startswith('{"valid":'))
        # Compact separators and exactly the four fixed keys, in order.
        self.assertEqual(
            result,
            json.dumps(
                json.loads(result), ensure_ascii=False, separators=(",", ":")
            ),
        )
        self.assertEqual(
            list(json.loads(result)),
            ["valid", "tables_ok", "integrity_ok", "reasons"],
        )

    def test_pathlike_and_extra_tables_are_accepted(self):
        self._populated_snapshot()
        conn = sqlite3.connect(self.snapshot)
        try:
            conn.execute("CREATE TABLE extra_operator_note (note TEXT)")
            conn.commit()
        finally:
            conn.close()
        report = self._verify(pathlib.Path(self.snapshot))
        self.assertTrue(report["valid"])
        self.assertEqual(report["reasons"], [])

    # -- structural and consistency failures ------------------------------

    def test_missing_tables_report_missing_tables_only(self):
        conn = sqlite3.connect(self.snapshot)
        try:
            conn.execute("CREATE TABLE unrelated (x TEXT)")
            conn.commit()
        finally:
            conn.close()
        report = self._verify(self.snapshot)
        self.assertEqual(
            report,
            {
                "valid": False,
                "tables_ok": False,
                "integrity_ok": True,
                "reasons": ["missing_tables"],
            },
        )

    def test_corrupt_snapshot_reports_integrity_failure(self):
        self._populated_snapshot()
        self._corrupt_tail_pages(self.snapshot)
        report = self._verify(self.snapshot)
        self.assertFalse(report["valid"])
        self.assertTrue(report["tables_ok"])
        self.assertFalse(report["integrity_ok"])
        self.assertEqual(report["reasons"], ["integrity_check_failed"])

    def test_missing_tables_and_corruption_report_both_reasons(self):
        # A queryable SQLite image without the contract tables whose
        # consistency check also fails: both reasons, code-point order.
        conn = sqlite3.connect(self.snapshot)
        try:
            conn.execute("CREATE TABLE unrelated (x TEXT)")
            conn.commit()
        finally:
            conn.close()
        self._corrupt_tail_pages(self.snapshot)
        report = self._verify(self.snapshot)
        self.assertEqual(
            report,
            {
                "valid": False,
                "tables_ok": False,
                "integrity_ok": False,
                "reasons": ["integrity_check_failed", "missing_tables"],
            },
        )

    def _corrupt_tail_pages(self, path):
        """Corrupt data pages past the schema so the file stays openable."""
        # Pad the image with real btree leaf pages so the tail is plain
        # table data, far from sqlite_master.
        conn = sqlite3.connect(path)
        try:
            conn.execute("CREATE TABLE IF NOT EXISTS pad (data BLOB)")
            conn.execute(
                "WITH RECURSIVE c(x) AS ("
                "SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 20000"
                ") INSERT INTO pad SELECT randomblob(100) FROM c"
            )
            conn.commit()
        finally:
            conn.close()
        size = os.path.getsize(path)
        with open(path, "r+b") as handle:
            handle.seek(size - 8192)
            handle.write(b"\xAA" * 4096)

    # -- non-images and unreadable candidates -----------------------------

    def test_non_sqlite_file_reports_not_sqlite(self):
        with open(self.snapshot, "wb") as handle:
            handle.write(b"this is not a sqlite database at all" * 16)
        report = self._verify(self.snapshot)
        self.assertEqual(
            report,
            {
                "valid": False,
                "tables_ok": False,
                "integrity_ok": False,
                "reasons": ["not_sqlite"],
            },
        )

    def test_missing_file_reports_read_failed(self):
        report = self._verify(os.path.join(self.dir, "absent.db"))
        self.assertEqual(
            report,
            {
                "valid": False,
                "tables_ok": False,
                "integrity_ok": False,
                "reasons": ["read_failed"],
            },
        )

    # -- caller-error paths ------------------------------------------------

    def test_invalid_paths_raise_fixed_value_error(self):
        for bad in ("", None, 123, _BadPath()):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError) as ctx:
                    verify_backup(bad)
                self.assertEqual(
                    str(ctx.exception),
                    "snapshot path must be a non-empty string",
                )
        for bad in (":memory:", "snap\x00shot.db"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError) as ctx:
                    verify_backup(bad)
                self.assertEqual(
                    str(ctx.exception),
                    "snapshot path must be a usable file path",
                )
                self.assertNotIn(bad.replace("\x00", ""), str(ctx.exception))

    def test_directory_raises_fixed_value_error(self):
        with self.assertRaises(ValueError) as ctx:
            verify_backup(self.dir)
        self.assertEqual(
            str(ctx.exception), "snapshot path must be a usable file path"
        )
        self.assertNotIn(self.dir, str(ctx.exception))

    # -- strict read-only repeatability ------------------------------------

    def test_verification_is_repeatable_and_leaves_no_trace(self):
        self._populated_snapshot()
        before_bytes = _sha256(self.snapshot)
        before_stat = os.stat(self.snapshot)
        before_listing = sorted(os.listdir(self.dir))

        first = verify_backup(self.snapshot)
        second = verify_backup(self.snapshot)

        self.assertEqual(first, second)
        self.assertEqual(_sha256(self.snapshot), before_bytes)
        after_stat = os.stat(self.snapshot)
        self.assertEqual(after_stat.st_mtime_ns, before_stat.st_mtime_ns)
        self.assertEqual(after_stat.st_size, before_stat.st_size)
        # No staged file, journal, WAL or shared-memory artifact appears.
        self.assertEqual(sorted(os.listdir(self.dir)), before_listing)

    def test_failed_verification_also_leaves_no_trace(self):
        with open(self.snapshot, "wb") as handle:
            handle.write(b"not a database" * 64)
        before_bytes = _sha256(self.snapshot)
        before_listing = sorted(os.listdir(self.dir))
        first = verify_backup(self.snapshot)
        second = verify_backup(self.snapshot)
        self.assertEqual(first, second)
        self.assertEqual(_sha256(self.snapshot), before_bytes)
        self.assertEqual(sorted(os.listdir(self.dir)), before_listing)


if __name__ == "__main__":
    unittest.main()
