"""Tests for the read-only ``python -m forgetting_evidence audit-health`` command.

Covers the CLI surface only: the two strict invocation styles (two
positionals or the named flags, never mixed), the single compact JSON
line with the fixed field order (``total``, ``statuses``, ``verified``,
``unverified``, ``reasons``), the all-zero snapshot of an empty tenant,
unverified evidence as a successful read with its stable reason codes,
byte-identical repeats, the strictly read-only behaviour (the database
is never created, migrated, repaired or overwritten), the fixed
detail-free markers (``audit_health_usage`` at exit 2,
``audit_health_failed`` at exit 3 with an empty stdout) and the
unchanged behaviour of the existing commands.
"""

import contextlib
import io
import json
import os
import tempfile
import unittest

from forgetting_evidence.__main__ import main
from forgetting_evidence.requests import RequestStore

_STATUS_NAMES = ("accepted", "processing", "completed", "failed")


class AuditHealthCommandTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "evidence.db")

    def tearDown(self):
        self._tmp.cleanup()

    def _run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["audit-health", *argv])
        return code, out.getvalue(), err.getvalue()

    def _db_bytes(self):
        with open(self.db_path, "rb") as handle:
            return handle.read()

    # -- success ---------------------------------------------------------

    def test_positional_success_outputs_compact_json_line(self):
        store = RequestStore(self.db_path)  # historical no-secret store
        store.submit("tenant-a", "subject-1", ["email"], "key-1")
        store.submit("tenant-a", "subject-2", ["email"], "key-2")
        code, out, err = self._run_cli(self.db_path, "tenant-a")
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertTrue(out.endswith("\n"))
        self.assertEqual(out.count("\n"), 1)
        snapshot = json.loads(out)
        self.assertEqual(
            list(snapshot),
            ["total", "statuses", "verified", "unverified", "reasons"],
        )
        self.assertEqual(list(snapshot["statuses"]), list(_STATUS_NAMES))
        self.assertEqual(snapshot["total"], 2)
        self.assertEqual(
            snapshot["statuses"],
            {"accepted": 2, "processing": 0, "completed": 0, "failed": 0},
        )
        # The command carries no anchor secrets, so the legacy
        # un-anchored requests are reported unverified with their stable
        # reason -- still a successful read, never a storage failure.
        self.assertEqual(snapshot["verified"], 0)
        self.assertEqual(snapshot["unverified"], 2)
        self.assertEqual(
            snapshot["reasons"],
            [{"reason": "unanchored_database", "count": 2}],
        )
        # Compact: no whitespace outside string values.
        self.assertEqual(
            out.strip(), json.dumps(snapshot, separators=(",", ":"))
        )

    def test_flag_styles_and_equals_forms_are_equivalent(self):
        store = RequestStore(self.db_path)
        store.submit("tenant-a", "subject-1", ["email"], "key-1")
        expected = self._run_cli(self.db_path, "tenant-a")
        self.assertEqual(expected[0], 0)
        for argv in (
            ("--db", self.db_path, "--tenant-id", "tenant-a"),
            ("--database", self.db_path, "--tenant-id", "tenant-a"),
            (f"--db={self.db_path}", "--tenant-id=tenant-a"),
            (f"--database={self.db_path}", "--tenant-id=tenant-a"),
        ):
            with self.subTest(argv=argv):
                self.assertEqual(self._run_cli(*argv), expected)

    def test_empty_tenant_is_an_all_zero_snapshot(self):
        store = RequestStore(self.db_path)
        store.submit("tenant-a", "subject-1", ["email"], "key-1")
        code, out, err = self._run_cli(self.db_path, "tenant-empty")
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertEqual(
            json.loads(out),
            {
                "total": 0,
                "statuses": {name: 0 for name in _STATUS_NAMES},
                "verified": 0,
                "unverified": 0,
                "reasons": [],
            },
        )

    def test_unverified_evidence_is_still_a_successful_read(self):
        store = RequestStore(self.db_path, anchor_secret="anchor-secret")
        store.submit("tenant-a", "subject-1", ["email"], "key-1")
        code, out, err = self._run_cli(self.db_path, "tenant-a")
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        snapshot = json.loads(out)
        # Anchored requests cannot authenticate without the secret the
        # command never receives; the stable reason is reported as-is.
        self.assertEqual(snapshot["verified"], 0)
        self.assertEqual(snapshot["unverified"], 1)
        self.assertEqual(
            snapshot["reasons"],
            [{"reason": "anchor_secret_missing", "count": 1}],
        )

    def test_status_counts_cover_every_lifecycle_state(self):
        store = RequestStore(self.db_path)
        ids = [
            store.submit("tenant-a", f"subject-{i}", ["email"], f"key-{i}")[
                "request_id"
            ]
            for i in range(4)
        ]
        claim = store.claim_next("tenant-a", "worker-1", 300)
        store.finish_claim("tenant-a", ids[0], claim["claim_token"], "completed")
        store.transition("tenant-a", ids[1], "processing")
        store.transition("tenant-a", ids[2], "failed")
        code, out, _err = self._run_cli(self.db_path, "tenant-a")
        self.assertEqual(code, 0)
        snapshot = json.loads(out)
        self.assertEqual(snapshot["total"], 4)
        self.assertEqual(
            snapshot["statuses"],
            {"accepted": 1, "processing": 1, "completed": 1, "failed": 1},
        )
        self.assertEqual(
            snapshot["total"],
            snapshot["verified"] + snapshot["unverified"],
        )

    def test_repeated_runs_are_byte_identical(self):
        store = RequestStore(self.db_path)
        store.submit("tenant-a", "subject-1", ["email"], "key-1")
        first = self._run_cli(self.db_path, "tenant-a")
        second = self._run_cli(self.db_path, "tenant-a")
        self.assertEqual(first, second)
        self.assertEqual(first[0], 0)

    def test_command_does_not_write_to_the_database(self):
        store = RequestStore(self.db_path)
        store.submit("tenant-a", "subject-1", ["email"], "key-1")
        before = self._db_bytes()
        code, _out, _err = self._run_cli(self.db_path, "tenant-a")
        self.assertEqual(code, 0)
        self.assertEqual(self._db_bytes(), before)
        self.assertEqual(os.listdir(self._tmp.name), ["evidence.db"])

    # -- usage errors ----------------------------------------------------

    def test_missing_duplicate_extra_mixed_or_empty_args_are_usage(self):
        store = RequestStore(self.db_path)
        store.submit("tenant-a", "subject-1", ["email"], "key-1")
        cases = (
            (),
            (self.db_path,),
            (self.db_path, "tenant-a", "extra"),
            # Mixed positional and flag styles.
            (self.db_path, "--tenant-id", "tenant-a"),
            ("--db", self.db_path, "tenant-a"),
            # Duplicated flags, across aliases too.
            ("--db", self.db_path, "--database", self.db_path,
             "--tenant-id", "tenant-a"),
            ("--db", self.db_path, "--tenant-id", "tenant-a",
             "--tenant-id", "tenant-a"),
            # Unknown flags.
            ("--db", self.db_path, "--tenant-id", "tenant-a", "--verbose"),
            ("--request-id", "x", "--tenant-id", "tenant-a"),
            # Empty values in either style.
            ("", "tenant-a"),
            (self.db_path, ""),
            ("--db=", "--tenant-id=tenant-a"),
            ("--tenant-id=", "--db", self.db_path),
            ("--db", self.db_path, "--tenant-id", ""),
            # A flag missing its value.
            ("--db", self.db_path, "--tenant-id"),
        )
        for argv in cases:
            with self.subTest(argv=argv):
                code, out, err = self._run_cli(*argv)
                self.assertEqual(code, 2)
                self.assertEqual(out, "")
                self.assertEqual(err.strip(), "audit_health_usage")

    # -- storage failures --------------------------------------------------

    def test_missing_database_is_audit_health_failed_and_not_created(self):
        missing = os.path.join(self._tmp.name, "no-such.db")
        code, out, err = self._run_cli(missing, "tenant-a")
        self.assertEqual(code, 3)
        self.assertEqual(out, "")
        self.assertEqual(err.strip(), "audit_health_failed")
        self.assertFalse(os.path.exists(missing))

    def test_corrupt_database_is_audit_health_failed(self):
        RequestStore(self.db_path)
        with open(self.db_path, "wb") as handle:
            handle.write(b"this is not a sqlite database")
        code, out, err = self._run_cli(self.db_path, "tenant-a")
        self.assertEqual(code, 3)
        self.assertEqual(out, "")
        self.assertEqual(err.strip(), "audit_health_failed")

    def test_directory_as_database_is_audit_health_failed(self):
        code, out, err = self._run_cli(self._tmp.name, "tenant-a")
        self.assertEqual(code, 3)
        self.assertEqual(out, "")
        self.assertEqual(err.strip(), "audit_health_failed")

    def test_dropped_table_is_audit_health_failed(self):
        import sqlite3

        store = RequestStore(self.db_path)
        store.submit("tenant-a", "subject-1", ["email"], "key-1")
        with sqlite3.connect(self.db_path) as raw:
            raw.execute("DROP TABLE audit_anchors")
        code, out, err = self._run_cli(self.db_path, "tenant-a")
        self.assertEqual(code, 3)
        self.assertEqual(out, "")
        self.assertEqual(err.strip(), "audit_health_failed")

    # -- output hygiene ----------------------------------------------------

    def test_error_output_carries_no_details(self):
        store = RequestStore(self.db_path)
        store.submit("tenant-a", "subject-1", ["email"], "key-1")
        missing = os.path.join(self._tmp.name, "absent.db")
        for argv in (
            (missing, "tenant-a"),
            (self.db_path, "tenant-a", "extra"),
        ):
            for _attempt in range(2):
                _code, out, err = self._run_cli(*argv)
                self.assertEqual(out, "")
                for sensitive in (
                    self.db_path, missing, "tenant-a",
                    "subject-1", "email", "sqlite",
                ):
                    self.assertNotIn(sensitive, err)

    def test_success_output_carries_no_sensitive_fields(self):
        store = RequestStore(self.db_path)
        store.submit("tenant-a", "subject-secret", ["scope-secret"], "key-1")
        code, out, _err = self._run_cli(self.db_path, "tenant-a")
        self.assertEqual(code, 0)
        for sensitive in ("tenant-a", "subject-secret", "scope-secret",
                          "key-1", self.db_path):
            self.assertNotIn(sensitive, out)

    # -- the existing surface is unchanged ---------------------------------

    def test_health_and_status_commands_are_unchanged(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["health"])
        self.assertEqual(code, 0)
        self.assertEqual(err.getvalue(), "")
        self.assertEqual(
            json.loads(out.getvalue()),
            {"service": "forgetting-evidence", "status": "ok"},
        )
        store = RequestStore(self.db_path)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(
                ["status", self.db_path, "tenant-a", receipt["request_id"]]
            )
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out.getvalue())["status"], "accepted")


if __name__ == "__main__":
    unittest.main()
