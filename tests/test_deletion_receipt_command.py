"""Tests for the read-only ``python -m forgetting_evidence deletion-receipt`` command.

Covers the CLI surface only: the two strict invocation styles (three
positionals or the named flags, spaced or equals form, never mixed),
the recovered receipt text being byte-identical to the stored first
receipt (no key presented, no JSON wrapper, exactly one trailing
newline), the strictly read-only behaviour (the database is never
created, migrated or written, and no receipt, key generation, status
event, execution record or audit record is added), the fixed
detail-free markers (``deletion_receipt_usage`` at exit 2,
``request_not_found`` at exit 3, ``receipt_unavailable`` at exit 3 and
``deletion_receipt_failed`` at exit 2, always with an empty stdout) and
the unchanged behaviour of the existing commands.
"""

import contextlib
import io
import json
import os
import sqlite3
import tempfile
import unittest

from forgetting_evidence.__main__ import main
from forgetting_evidence.requests import RequestStore

KEY = "receipt-key-0001"
NEW_KEY = "receipt-key-0002"


class DeletionReceiptCommandTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "evidence.db")

    def tearDown(self):
        self._tmp.cleanup()

    def _run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["deletion-receipt", *argv])
        return code, out.getvalue(), err.getvalue()

    def _db_bytes(self):
        with open(self.db_path, "rb") as handle:
            return handle.read()

    def _submit(self, tenant="tenant-a"):
        store = RequestStore(self.db_path)
        return store.submit(tenant, "subject-1", ["email"], "key-1")["request_id"]

    def _completed(self, tenant="tenant-a"):
        store = RequestStore(self.db_path)
        request_id = store.submit(tenant, "subject-1", ["email"], "key-1")[
            "request_id"
        ]
        claim = store.claim_next(tenant, "worker-1", 60)
        store.finish_claim(tenant, request_id, claim["claim_token"], "completed")
        return request_id

    def _receipted(self, tenant="tenant-a"):
        request_id = self._completed(tenant)
        store = RequestStore(self.db_path)
        first = store.generate_receipt(tenant, request_id, KEY)
        return request_id, first

    # -- success ---------------------------------------------------------

    def test_positional_success_replays_stored_receipt_byte_for_byte(self):
        request_id, first = self._receipted()
        code, out, err = self._run_cli(self.db_path, "tenant-a", request_id)
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertEqual(out, first)
        self.assertTrue(out.endswith("\n"))
        self.assertEqual(out.count("\n"), 1)
        parsed = json.loads(out[:-1])
        self.assertEqual(
            list(parsed),
            [
                "tenant_id",
                "request_id",
                "created_at",
                "completed_at",
                "scope_digest",
                "attempt_digest",
                "tag",
            ],
        )

    def test_flag_styles_and_equals_forms_are_equivalent(self):
        request_id, _first = self._receipted()
        expected = self._run_cli(self.db_path, "tenant-a", request_id)
        self.assertEqual(expected[0], 0)
        for argv in (
            ("--db", self.db_path, "--tenant-id", "tenant-a",
             "--request-id", request_id),
            ("--database", self.db_path, "--tenant-id", "tenant-a",
             "--request-id", request_id),
            (f"--db={self.db_path}", "--tenant-id=tenant-a",
             f"--request-id={request_id}"),
            (f"--database={self.db_path}", "--tenant-id=tenant-a",
             f"--request-id={request_id}"),
        ):
            with self.subTest(argv=argv):
                self.assertEqual(self._run_cli(*argv), expected)

    def test_read_needs_no_key_and_survives_rotation(self):
        request_id, first = self._receipted()
        store = RequestStore(self.db_path)
        store.rotate_receipt_key("tenant-a", KEY, NEW_KEY)
        code, out, err = self._run_cli(self.db_path, "tenant-a", request_id)
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(out, first)

    def test_command_does_not_write_to_the_database(self):
        request_id, _first = self._receipted()
        before = self._db_bytes()
        code, _out, _err = self._run_cli(self.db_path, "tenant-a", request_id)
        self.assertEqual(code, 0)
        self.assertEqual(self._db_bytes(), before)
        self.assertEqual(os.listdir(self._tmp.name), ["evidence.db"])

    # -- usage errors ----------------------------------------------------

    def test_missing_duplicate_extra_mixed_or_empty_args_are_usage(self):
        request_id, _first = self._receipted()
        cases = (
            (),
            (self.db_path,),
            (self.db_path, "tenant-a"),
            (self.db_path, "tenant-a", request_id, "extra"),
            # Mixed positional and flag styles.
            (self.db_path, "--tenant-id", "tenant-a",
             "--request-id", request_id),
            ("--db", self.db_path, "tenant-a", request_id),
            # Duplicated flags.
            ("--db", self.db_path, "--db", self.db_path,
             "--tenant-id", "tenant-a", "--request-id", request_id),
            ("--db", self.db_path, "--tenant-id", "tenant-a",
             "--request-id", request_id, "--request-id", request_id),
            # Unknown flags.
            ("--db", self.db_path, "--tenant-id", "tenant-a",
             "--request-id", request_id, "--verbose"),
            # Empty values in either style.
            ("", "tenant-a", request_id),
            (self.db_path, "", request_id),
            (self.db_path, "tenant-a", ""),
            ("--db=", "--tenant-id=tenant-a", "--request-id=x"),
            ("--tenant-id=", "--db", self.db_path, "--request-id", request_id),
            ("--db", self.db_path, "--tenant-id", "tenant-a",
             "--request-id", ""),
            # A flag missing its value.
            ("--db", self.db_path, "--tenant-id", "tenant-a", "--request-id"),
        )
        for argv in cases:
            with self.subTest(argv=argv):
                code, out, err = self._run_cli(*argv)
                self.assertEqual(code, 2)
                self.assertEqual(out, "")
                self.assertEqual(err.strip(), "deletion_receipt_usage")

    # -- not found ---------------------------------------------------------

    def test_unknown_and_cross_tenant_requests_are_indistinguishable(self):
        request_id, _first = self._receipted()
        results = []
        for argv in (
            (self.db_path, "tenant-a", "no-such-request"),
            (self.db_path, "tenant-b", request_id),
            ("--db", self.db_path, "--tenant-id", "tenant-b",
             "--request-id", request_id),
        ):
            with self.subTest(argv=argv):
                code, out, err = self._run_cli(*argv)
                self.assertEqual(code, 3)
                self.assertEqual(out, "")
                self.assertEqual(err.strip(), "request_not_found")
                results.append((code, out, err))
        # Cross-tenant and never-accepted ids share one byte-identical
        # outcome, so the command cannot reveal which records exist.
        self.assertEqual(results[0], results[1])
        self.assertEqual(results[1], results[2])

    # -- unavailable -------------------------------------------------------

    def test_accepted_and_failed_requests_are_unavailable(self):
        store = RequestStore(self.db_path)
        failed_id = store.submit("tenant-a", "subject-2", ["email"], "key-2")[
            "request_id"
        ]
        claim = store.claim_next("tenant-a", "worker-1", 60)
        store.finish_claim("tenant-a", failed_id, claim["claim_token"], "failed")
        accepted_id = self._submit()
        for request_id in (accepted_id, failed_id):
            with self.subTest(request_id=request_id):
                code, out, err = self._run_cli(
                    self.db_path, "tenant-a", request_id
                )
                self.assertEqual(code, 3)
                self.assertEqual(out, "")
                self.assertEqual(err.strip(), "receipt_unavailable")

    def test_completed_without_settled_execution_record_is_unavailable(self):
        request_id = self._submit()
        with sqlite3.connect(self.db_path) as raw:
            raw.execute(
                "UPDATE requests SET status = 'completed' WHERE request_id = ?",
                (request_id,),
            )
        code, out, err = self._run_cli(self.db_path, "tenant-a", request_id)
        self.assertEqual(code, 3)
        self.assertEqual(out, "")
        self.assertEqual(err.strip(), "receipt_unavailable")

    # -- storage failures --------------------------------------------------

    def test_missing_database_is_failed_and_not_created(self):
        missing = os.path.join(self._tmp.name, "no-such.db")
        code, out, err = self._run_cli(missing, "tenant-a", "request-1")
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertEqual(err.strip(), "deletion_receipt_failed")
        self.assertFalse(os.path.exists(missing))

    def test_corrupt_database_is_failed(self):
        RequestStore(self.db_path)
        with open(self.db_path, "wb") as handle:
            handle.write(b"this is not a sqlite database")
        code, out, err = self._run_cli(self.db_path, "tenant-a", "request-1")
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertEqual(err.strip(), "deletion_receipt_failed")

    def test_unreadable_stored_receipt_is_failed(self):
        request_id, _first = self._receipted()
        with sqlite3.connect(self.db_path) as raw:
            raw.execute(
                "UPDATE deletion_receipts SET receipt_json = 'not a receipt' "
                "WHERE request_id = ?",
                (request_id,),
            )
        code, out, err = self._run_cli(self.db_path, "tenant-a", request_id)
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertEqual(err.strip(), "deletion_receipt_failed")

    # -- output hygiene ----------------------------------------------------

    def test_error_output_carries_no_details(self):
        request_id, first = self._receipted()
        missing = os.path.join(self._tmp.name, "absent.db")
        for argv in (
            (missing, "tenant-a", request_id),
            (self.db_path, "tenant-a", "no-such-request"),
            (self.db_path, "tenant-b", request_id),
            (self.db_path, "tenant-a", request_id, "extra"),
        ):
            for _attempt in range(2):
                _code, out, err = self._run_cli(*argv)
                self.assertEqual(out, "")
                for sensitive in (
                    self.db_path, missing, "tenant-a", "tenant-b",
                    request_id, first.strip(), KEY, "sqlite",
                ):
                    self.assertNotIn(sensitive, err)

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
        request_id = self._submit()
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["status", self.db_path, "tenant-a", request_id])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out.getvalue())["status"], "accepted")


if __name__ == "__main__":
    unittest.main()
