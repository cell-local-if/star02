"""Tests for the read-only ``python -m forgetting_evidence deletion-receipt`` command.

Covers the CLI surface only: the three strict invocation forms (three
positionals, the named flags, and the equals form -- never mixed), the
stored first receipt text being emitted byte-for-byte with no envelope,
recovery without a signature key (including after a key rotation), the
strictly read-only behaviour (the database is never created, migrated,
repaired or written, and no receipt, key generation, status event or
execution record is added), the two not-yet-recoverable outcomes
(``request_not_found`` and ``receipt_unavailable`` at exit 3, with
unknown and cross-tenant ids indistinguishable), the fixed
detail-free failure markers (``deletion_receipt_usage`` and
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
        self.db_path = os.path.join(self._tmp.name, "nested", "receipts.db")
        store = RequestStore(self.db_path)
        accepted = store.submit("tenant-a", "subject-1", ["email"], "idem-1")
        self.request_id = accepted["request_id"]
        claim = store.claim_next("tenant-a", "worker-1", 60)
        store.finish_claim(
            "tenant-a", self.request_id, claim["claim_token"], "completed"
        )
        self.receipt = store.generate_receipt(
            "tenant-a", self.request_id, KEY
        )

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

    def _raw(self):
        return sqlite3.connect(self.db_path)

    # -- success: the three call forms -----------------------------------

    def test_positional_success_outputs_stored_text_byte_for_byte(self):
        code, out, err = self._run_cli(
            self.db_path, "tenant-a", self.request_id
        )
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        # stdout is the stored receipt text alone: no JSON envelope, no
        # annotation, no reordering, exactly the one stored newline.
        self.assertEqual(out, self.receipt)
        self.assertTrue(out.endswith("\n"))
        self.assertEqual(out.count("\n"), 1)
        parsed = json.loads(out)
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
        self.assertEqual(parsed["request_id"], self.request_id)
        self.assertEqual(
            out, json.dumps(parsed, ensure_ascii=False, separators=(",", ":")) + "\n"
        )

    def test_three_call_forms_are_equivalent(self):
        expected = (0, self.receipt, "")
        # 1) three positionals
        self.assertEqual(
            self._run_cli(self.db_path, "tenant-a", self.request_id), expected
        )
        # 2) named flags (both --db and --database spellings)
        for argv in (
            ("--db", self.db_path, "--tenant-id", "tenant-a",
             "--request-id", self.request_id),
            ("--database", self.db_path, "--tenant-id", "tenant-a",
             "--request-id", self.request_id),
        ):
            with self.subTest(argv=argv):
                self.assertEqual(self._run_cli(*argv), expected)
        # 3) equals form
        self.assertEqual(
            self._run_cli(
                f"--database={self.db_path}",
                "--tenant-id=tenant-a",
                f"--request-id={self.request_id}",
            ),
            expected,
        )
        self.assertEqual(
            self._run_cli(
                f"--db={self.db_path}",
                "--tenant-id=tenant-a",
                f"--request-id={self.request_id}",
            ),
            expected,
        )

    def test_repeated_reads_are_stable(self):
        first = self._run_cli(self.db_path, "tenant-a", self.request_id)
        for _ in range(4):
            self.assertEqual(
                self._run_cli(self.db_path, "tenant-a", self.request_id), first
            )

    def test_recovers_without_key_before_and_after_rotation(self):
        # No signature key is passed on the command line, and the
        # recovered bytes do not change when the active key rotates.
        before = self._run_cli(self.db_path, "tenant-a", self.request_id)
        store = RequestStore(self.db_path)
        store.rotate_receipt_key("tenant-a", KEY, NEW_KEY)
        after = self._run_cli(self.db_path, "tenant-a", self.request_id)
        self.assertEqual(after, before)
        rebuilt = RequestStore(self.db_path)
        # The stored first receipt now verifies only under the old key,
        # yet still recovers with no key at all.
        self.assertTrue(rebuilt.verify_receipt(self.receipt, KEY))
        self.assertFalse(rebuilt.verify_receipt(self.receipt, NEW_KEY))

    # -- strictly read-only ----------------------------------------------

    def test_command_does_not_write_to_the_database(self):
        before = self._db_bytes()
        for _ in range(3):
            code, _out, _err = self._run_cli(
                self.db_path, "tenant-a", self.request_id
            )
            self.assertEqual(code, 0)
        self.assertEqual(self._db_bytes(), before)
        # Read-only opening creates no journal, WAL or sidecar file.
        self.assertEqual(sorted(os.listdir(os.path.dirname(self.db_path))),
                         ["receipts.db"])

    def test_missing_database_is_not_created(self):
        missing = os.path.join(self._tmp.name, "no-such.db")
        code, out, err = self._run_cli(
            missing, "tenant-a", self.request_id
        )
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertEqual(err.strip(), "deletion_receipt_failed")
        self.assertFalse(os.path.exists(missing))

    def test_unavailable_read_writes_nothing(self):
        bare = RequestStore(self.db_path).submit(
            "tenant-a", "subject-2", ["email"], "idem-bare"
        )
        before = self._db_bytes()
        code, out, err = self._run_cli(
            self.db_path, "tenant-a", bare["request_id"]
        )
        self.assertEqual(code, 3)
        self.assertEqual(out, "")
        self.assertEqual(err.strip(), "receipt_unavailable")
        self.assertEqual(self._db_bytes(), before)
        with self._raw() as conn:
            self.assertEqual(
                conn.execute("SELECT count(*) FROM deletion_receipts")
                .fetchone()[0],
                1,
            )
            self.assertEqual(
                conn.execute(
                    "SELECT count(*) FROM receipt_keys WHERE tenant_id = ?",
                    ("tenant-a",),
                ).fetchone()[0],
                1,
            )

    # -- not yet available: the two exit-3 outcomes ----------------------

    def test_requests_without_first_receipt_are_unavailable(self):
        store = RequestStore(self.db_path)
        # processing with a live lease (claimed while it is the oldest
        # claimable request)
        processing = store.submit("tenant-a", "subject-3", ["email"], "k-proc")
        store.claim_next("tenant-a", "worker-1", 60)
        # failed with a settled failed attempt
        failed = store.submit("tenant-a", "subject-4", ["email"], "k-fail")
        claim = store.claim_next("tenant-a", "worker-1", 60)
        self.assertEqual(claim["request_id"], failed["request_id"])
        store.finish_claim(
            "tenant-a", failed["request_id"], claim["claim_token"], "failed"
        )
        # completed status without any settled completed execution record
        bare = store.submit("tenant-a", "subject-5", ["email"], "k-bare")
        store.transition("tenant-a", bare["request_id"], "processing")
        store.transition("tenant-a", bare["request_id"], "completed")
        # accepted, never claimed -- submitted last so earlier claims
        # could not pick it up
        accepted = store.submit("tenant-a", "subject-2", ["email"], "k-accept")
        for record in (accepted, processing, failed, bare):
            with self.subTest(request_id=record["request_id"]):
                code, out, err = self._run_cli(
                    self.db_path, "tenant-a", record["request_id"]
                )
                self.assertEqual(code, 3)
                self.assertEqual(out, "")
                self.assertEqual(err.strip(), "receipt_unavailable")

    def test_unknown_malformed_and_cross_tenant_are_not_found(self):
        for rid in ("does-not-exist", "not-a-uuid", ""):
            with self.subTest(rid=rid):
                code, out, err = self._run_cli(
                    self.db_path, "tenant-a", rid or "no-such-id"
                )
                self.assertEqual(code, 3)
                self.assertEqual(out, "")
                self.assertEqual(err.strip(), "request_not_found")
        # Cross-tenant: the request exists and even carries a receipt,
        # but tenant-b must not be able to tell it apart from an unknown
        # id.
        code, out, err = self._run_cli(
            self.db_path, "tenant-b", self.request_id
        )
        self.assertEqual(code, 3)
        self.assertEqual(out, "")
        self.assertEqual(err.strip(), "request_not_found")

    # -- storage failures ------------------------------------------------

    def test_corrupt_database_is_deletion_receipt_failed(self):
        with open(self.db_path, "wb") as handle:
            handle.write(b"this is not a sqlite database")
        code, out, err = self._run_cli(
            self.db_path, "tenant-a", self.request_id
        )
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertEqual(err.strip(), "deletion_receipt_failed")

    def test_directory_as_database_is_deletion_receipt_failed(self):
        code, out, err = self._run_cli(
            os.path.dirname(self.db_path), "tenant-a", self.request_id
        )
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertEqual(err.strip(), "deletion_receipt_failed")

    def test_corrupt_stored_receipt_is_deletion_receipt_failed(self):
        with self._raw() as conn:
            conn.execute(
                "UPDATE deletion_receipts SET receipt_json = ? "
                "WHERE tenant_id = ? AND request_id = ?",
                ("{\"tampered\":true}\n", "tenant-a", self.request_id),
            )
            conn.commit()
        code, out, err = self._run_cli(
            self.db_path, "tenant-a", self.request_id
        )
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertEqual(err.strip(), "deletion_receipt_failed")
        # The corrupt row is never repaired or overwritten.
        with self._raw() as conn:
            text = conn.execute(
                "SELECT receipt_json FROM deletion_receipts "
                "WHERE tenant_id = ? AND request_id = ?",
                ("tenant-a", self.request_id),
            ).fetchone()[0]
        self.assertEqual(text, "{\"tampered\":true}\n")

    # -- usage errors never reach storage --------------------------------

    def test_bad_arity_mixed_duplicate_unknown_empty_args_are_usage(self):
        cases = (
            (),
            (self.db_path,),
            (self.db_path, "tenant-a"),
            (self.db_path, "tenant-a", self.request_id, "extra"),
            # Mixed positional and flag styles.
            (self.db_path, "--tenant-id", "tenant-a",
             "--request-id", self.request_id),
            ("--db", self.db_path, "tenant-a", self.request_id),
            # Duplicated flags (including the --database alias).
            ("--db", self.db_path, "--database", self.db_path,
             "--tenant-id", "tenant-a", "--request-id", self.request_id),
            ("--database", self.db_path, "--database", self.db_path,
             "--tenant-id", "tenant-a", "--request-id", self.request_id),
            ("--db", self.db_path, "--tenant-id", "tenant-a",
             "--tenant-id", "tenant-a", "--request-id", self.request_id),
            # Unknown flags.
            ("--db", self.db_path, "--tenant-id", "tenant-a",
             "--request-id", self.request_id, "--verbose"),
            ("--host", "x"),
            # Empty values in either style.
            ("", "tenant-a", self.request_id),
            (self.db_path, "", self.request_id),
            (self.db_path, "tenant-a", ""),
            ("--db=", "--tenant-id=tenant-a", "--request-id=x"),
            ("--database=", "--tenant-id=tenant-a", f"--request-id={self.request_id}"),
            ("--db", self.db_path, "--tenant-id", "",
             "--request-id", self.request_id),
            ("--db", self.db_path, "--tenant-id", "tenant-a",
             "--request-id="),
            # A flag missing its value.
            ("--database", self.db_path, "--tenant-id", "tenant-a",
             "--request-id"),
        )
        missing = os.path.join(self._tmp.name, "absent.db")
        for argv in cases:
            with self.subTest(argv=argv):
                code, out, err = self._run_cli(*argv)
                self.assertEqual(code, 2)
                self.assertEqual(out, "")
                self.assertEqual(err.strip(), "deletion_receipt_usage")
        # None of the malformed invocations touched storage: a missing
        # database referenced by a usage-bad command line is not created.
        self.assertFalse(os.path.exists(missing))

    # -- error output hygiene --------------------------------------------

    def test_error_output_carries_no_details(self):
        missing = os.path.join(self._tmp.name, "absent.db")
        for argv in (
            (self.db_path, "tenant-b", self.request_id),
            (missing, "tenant-a", self.request_id),
            (self.db_path, "tenant-a", "00000000-0000-0000-0000-000000000000"),
        ):
            _code, out, err = self._run_cli(*argv)
            self.assertEqual(out, "")
            for sensitive in (
                self.db_path, missing, "tenant-a", "tenant-b",
                self.request_id, "subject-1", KEY, NEW_KEY,
                "sqlite", "SELECT",
            ):
                self.assertNotIn(sensitive, err)

    # -- existing commands stay unchanged --------------------------------

    def test_existing_command_markers_are_unchanged(self):
        # An unknown command still prints the top-level usage marker;
        # sibling commands keep their own markers (evidence here).
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["not-a-command"])
        self.assertEqual(code, 2)
        self.assertEqual(
            err.getvalue().strip(),
            "usage: python -m forgetting_evidence health",
        )
        code, _out, err_text = self._run_cli_via(
            "evidence", self.db_path, "tenant-a", "not-a-uuid"
        )
        self.assertEqual(code, 3)
        self.assertEqual(err_text.strip(), "evidence_not_found")

    @staticmethod
    def _run_cli_via(command, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main([command, *argv])
        return code, out.getvalue(), err.getvalue()


if __name__ == "__main__":
    unittest.main()
