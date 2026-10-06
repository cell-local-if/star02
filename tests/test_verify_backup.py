"""Tests for the read-only backup verification entry point.

Covers ``verify_backup``: the compact single-line JSON verdict
(``valid``, ``tables_ok``, ``integrity_ok``, ``reasons``) for a valid
snapshot, a snapshot with extra tables, missing tables, a failed
``integrity_check``, both failures at once, a non-SQLite candidate and
a missing file; path validation (ValueError for empty, non-string,
in-memory, NUL-bearing and directory paths) with fixed, path-free
messages; and the strict read-only guarantee -- the candidate's bytes
and timestamps are unchanged, no file is created, repeated checks
return identical JSON and no outcome leaks paths, SQL text or secrets.
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
RECEIPT_KEY = "receipt-key-0001"


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
        self.db_path = os.path.join(self._tmp.name, "evidence.db")
        self.snapshot = os.path.join(self._tmp.name, "snapshot.db")

    def tearDown(self):
        self._tmp.cleanup()

    def _populated_store(self):
        store = RequestStore(self.db_path, anchor_secret=SECRET_A)
        first = store.submit("tenant-a", "subject-1", ["email"], "idem-1")
        claim = store.claim_next("tenant-a", "worker-1", 60)
        store.finish_claim(
            "tenant-a", first["request_id"], claim["claim_token"], "completed"
        )
        store.generate_receipt("tenant-a", first["request_id"], RECEIPT_KEY)
        store.submit("tenant-a", "subject-2", ["profile"], "idem-2")
        return store

    def _valid_snapshot(self):
        self._populated_store()
        run_backup(self.db_path, self.snapshot)
        return self.snapshot

    def _listing(self):
        return sorted(os.listdir(self._tmp.name))

    def test_valid_snapshot_verdict_is_exact_compact_line(self):
        self._valid_snapshot()
        result = verify_backup(self.snapshot)
        self.assertEqual(
            result,
            '{"valid":true,"tables_ok":true,'
            '"integrity_ok":true,"reasons":[]}',
        )
        self.assertNotIn("\n", result)
        verdict = json.loads(result)
        self.assertEqual(
            set(verdict), {"valid", "tables_ok", "integrity_ok", "reasons"}
        )

    def test_path_like_argument_is_accepted(self):
        self._valid_snapshot()
        verdict = json.loads(verify_backup(pathlib.Path(self.snapshot)))
        self.assertTrue(verdict["valid"])

    def test_extra_tables_are_allowed(self):
        self._valid_snapshot()
        with sqlite3.connect(self.snapshot) as conn:
            conn.execute("CREATE TABLE extra_bookkeeping (id INTEGER)")
        verdict = json.loads(verify_backup(self.snapshot))
        self.assertTrue(verdict["tables_ok"])
        self.assertTrue(verdict["integrity_ok"])
        self.assertTrue(verdict["valid"])
        self.assertEqual(verdict["reasons"], [])

    def test_missing_tables_report_missing_tables_only(self):
        with sqlite3.connect(self.snapshot) as conn:
            conn.execute("CREATE TABLE unrelated (id INTEGER)")
        verdict = json.loads(verify_backup(self.snapshot))
        self.assertFalse(verdict["tables_ok"])
        self.assertTrue(verdict["integrity_ok"])
        self.assertFalse(verdict["valid"])
        self.assertEqual(verdict["reasons"], ["missing_tables"])

    def _corrupt_until_integrity_fails(self, path):
        """Corrupt a trailing page so integrity_check reports errors."""
        size = os.path.getsize(path)
        for offset in range(size - 4096, 4095, -4096):
            with open(path, "r+b") as handle:
                handle.seek(offset)
                handle.write(b"\xff" * 4096)
            with sqlite3.connect(path) as conn:
                try:
                    checks = conn.execute("PRAGMA integrity_check").fetchall()
                except sqlite3.Error:
                    checks = None
            if checks != [("ok",)]:
                return
        self.fail("could not corrupt the snapshot into an integrity failure")

    def test_integrity_failure_reports_integrity_check_failed_only(self):
        self._valid_snapshot()
        self._corrupt_until_integrity_fails(self.snapshot)
        verdict = json.loads(verify_backup(self.snapshot))
        self.assertTrue(verdict["tables_ok"])
        self.assertFalse(verdict["integrity_ok"])
        self.assertFalse(verdict["valid"])
        self.assertEqual(verdict["reasons"], ["integrity_check_failed"])

    def test_missing_tables_and_integrity_failure_report_both_sorted(self):
        with sqlite3.connect(self.snapshot) as conn:
            conn.execute("CREATE TABLE payload (data BLOB)")
            conn.execute(
                "INSERT INTO payload VALUES (zeroblob(1048576))"
            )
        self._corrupt_until_integrity_fails(self.snapshot)
        verdict = json.loads(verify_backup(self.snapshot))
        self.assertFalse(verdict["tables_ok"])
        self.assertFalse(verdict["integrity_ok"])
        self.assertFalse(verdict["valid"])
        self.assertEqual(
            verdict["reasons"],
            ["integrity_check_failed", "missing_tables"],
        )

    def test_non_sqlite_candidate_reports_not_sqlite(self):
        with open(self.snapshot, "wb") as handle:
            handle.write(b"this is not a sqlite database at all" * 16)
        verdict = json.loads(verify_backup(self.snapshot))
        self.assertFalse(verdict["tables_ok"])
        self.assertFalse(verdict["integrity_ok"])
        self.assertFalse(verdict["valid"])
        self.assertEqual(verdict["reasons"], ["not_sqlite"])

    def test_empty_candidate_reports_not_sqlite(self):
        open(self.snapshot, "wb").close()
        verdict = json.loads(verify_backup(self.snapshot))
        self.assertFalse(verdict["valid"])
        self.assertEqual(verdict["reasons"], ["not_sqlite"])

    def test_missing_file_reports_read_failed(self):
        verdict = json.loads(verify_backup(self.snapshot))
        self.assertFalse(verdict["tables_ok"])
        self.assertFalse(verdict["integrity_ok"])
        self.assertFalse(verdict["valid"])
        self.assertEqual(verdict["reasons"], ["read_failed"])
        # The check created nothing.
        self.assertNotIn("snapshot.db", self._listing())

    def test_directory_candidate_raises_value_error(self):
        with self.assertRaises(ValueError) as caught:
            verify_backup(self._tmp.name)
        self.assertNotIn(self._tmp.name, str(caught.exception))

    def test_invalid_paths_raise_fixed_value_errors(self):
        for bad in ("", None, 123, b"bytes", ":memory:", "nul\x00path",
                    _BadPath()):
            with self.assertRaises(ValueError) as caught:
                verify_backup(bad)
            message = str(caught.exception)
            self.assertIn(
                message,
                (
                    "snapshot path must be a non-empty string",
                    "snapshot path must be a usable file path",
                ),
            )
        self.assertEqual(self._listing(), [])

    def test_verification_is_strictly_read_only_and_repeatable(self):
        self._valid_snapshot()
        before_bytes = _sha256(self.snapshot)
        before_stat = os.stat(self.snapshot)
        before_listing = self._listing()
        first = verify_backup(self.snapshot)
        second = verify_backup(self.snapshot)
        self.assertEqual(first, second)
        self.assertEqual(_sha256(self.snapshot), before_bytes)
        after_stat = os.stat(self.snapshot)
        self.assertEqual(after_stat.st_mtime_ns, before_stat.st_mtime_ns)
        self.assertEqual(after_stat.st_size, before_stat.st_size)
        self.assertEqual(self._listing(), before_listing)

    def test_repeated_checks_on_failures_are_identical(self):
        with open(self.snapshot, "wb") as handle:
            handle.write(b"garbage")
        self.assertEqual(verify_backup(self.snapshot),
                         verify_backup(self.snapshot))
        missing = os.path.join(self._tmp.name, "absent.db")
        self.assertEqual(verify_backup(missing), verify_backup(missing))

    def test_verdict_and_errors_carry_no_path_or_secret(self):
        self._valid_snapshot()
        result = verify_backup(self.snapshot)
        self.assertNotIn(self.snapshot, result)
        self.assertNotIn(SECRET_A, result)
        self.assertNotIn(RECEIPT_KEY, result)
        # The missing-file verdict never names the path either.
        missing = os.path.join(self._tmp.name, "absent.db")
        self.assertNotIn(missing, verify_backup(missing))


if __name__ == "__main__":
    unittest.main()
