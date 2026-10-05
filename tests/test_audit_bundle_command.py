"""Tests for the read-only ``python -m forgetting_evidence audit-bundle`` command.

Covers the CLI surface only: the two strict invocation styles (three
positionals or the three named flags, never mixed), the exported
single-line JSON text being byte-identical to the store's
``export_audit_bundle`` from the same database, byte-identical repeats,
the strictly read-only behaviour (the database is never created,
migrated, repaired or overwritten, and no status event, execution
attempt, tombstone, anchor or audit record is added), the fixed
detail-free markers (``audit_bundle_usage`` at exit 2,
``bundle_not_found`` at exit 3, ``bundle_unavailable`` at exit 4 and
``bundle_failed`` at exit 2, always with an empty stdout) and the
unchanged behaviour of the existing commands.
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

SECRET_A = "anchor-secret-alpha-0001"
SECRET_B = "anchor-secret-bravo-0002"


class AuditBundleCommandTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "evidence.db")

    def tearDown(self):
        self._tmp.cleanup()

    def _run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["audit-bundle", *argv])
        return code, out.getvalue(), err.getvalue()

    def _db_bytes(self):
        with open(self.db_path, "rb") as handle:
            return handle.read()

    def _anchored_request(self, tenant="tenant-a"):
        store = RequestStore(self.db_path, anchor_secret=SECRET_A)
        return store.submit(tenant, "subject-1", ["email"], "key-1")[
            "request_id"
        ]

    # -- success ---------------------------------------------------------

    def test_positional_success_matches_store_export_byte_for_byte(self):
        request_id = self._anchored_request()
        store = RequestStore(self.db_path, anchor_secret=SECRET_A)
        expected = store.export_audit_bundle("tenant-a", request_id)
        code, out, err = self._run_cli(self.db_path, "tenant-a", request_id)
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertEqual(out, expected)
        self.assertTrue(out.endswith("\n"))
        self.assertEqual(out.count("\n"), 1)
        bundle = json.loads(out)
        self.assertEqual(
            list(bundle),
            ["request_id", "status", "events", "chain", "anchors", "generations"],
        )
        # The exported line verifies fully offline with the caller-held
        # secret generation mapping.
        self.assertTrue(
            RequestStore.verify_audit_bundle(out, {1: SECRET_A})
        )

    def test_flag_styles_and_equals_forms_are_equivalent(self):
        request_id = self._anchored_request()
        expected = self._run_cli(self.db_path, "tenant-a", request_id)
        self.assertEqual(expected[0], 0)
        for argv in (
            ("--db", self.db_path, "--tenant-id", "tenant-a",
             "--request-id", request_id),
            (f"--db={self.db_path}", "--tenant-id=tenant-a",
             f"--request-id={request_id}"),
        ):
            with self.subTest(argv=argv):
                self.assertEqual(self._run_cli(*argv), expected)

    def test_rotation_keeps_every_generation_exportable(self):
        store = RequestStore(self.db_path, anchor_secret=SECRET_A)
        first = store.submit("tenant-a", "subject-1", ["email"], "key-1")[
            "request_id"
        ]
        store.rotate_anchor_key(SECRET_A, SECRET_B)
        rebuilt = RequestStore(
            self.db_path,
            anchor_secret=SECRET_B,
            anchor_history_secrets={1: SECRET_A},
        )
        second = rebuilt.submit("tenant-a", "subject-2", ["email"], "key-2")[
            "request_id"
        ]
        for request_id in (first, second):
            with self.subTest(request_id=request_id):
                expected = rebuilt.export_audit_bundle("tenant-a", request_id)
                code, out, err = self._run_cli(
                    self.db_path, "tenant-a", request_id
                )
                self.assertEqual((code, err), (0, ""))
                self.assertEqual(out, expected)
                self.assertTrue(
                    RequestStore.verify_audit_bundle(
                        out, {1: SECRET_A, 2: SECRET_B}
                    )
                )

    def test_repeated_runs_are_byte_identical(self):
        request_id = self._anchored_request()
        first = self._run_cli(self.db_path, "tenant-a", request_id)
        second = self._run_cli(self.db_path, "tenant-a", request_id)
        self.assertEqual(first, second)
        self.assertEqual(first[0], 0)

    def test_command_does_not_write_to_the_database(self):
        request_id = self._anchored_request()
        before = self._db_bytes()
        code, _out, _err = self._run_cli(self.db_path, "tenant-a", request_id)
        self.assertEqual(code, 0)
        self.assertEqual(self._db_bytes(), before)
        self.assertEqual(os.listdir(self._tmp.name), ["evidence.db"])

    # -- usage errors ----------------------------------------------------

    def test_missing_duplicate_extra_mixed_or_empty_args_are_usage(self):
        request_id = self._anchored_request()
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
            ("--database", self.db_path, "--tenant-id", "tenant-a",
             "--request-id", request_id),
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
                self.assertEqual(err.strip(), "audit_bundle_usage")

    # -- not found ---------------------------------------------------------

    def test_unknown_and_cross_tenant_requests_are_not_found(self):
        request_id = self._anchored_request()
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
                self.assertEqual(err.strip(), "bundle_not_found")

    # -- unavailable -------------------------------------------------------

    def test_unanchored_chain_is_unavailable(self):
        store = RequestStore(self.db_path)  # historical no-secret store
        receipt = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        code, out, err = self._run_cli(
            self.db_path, "tenant-a", receipt["request_id"]
        )
        self.assertEqual(code, 4)
        self.assertEqual(out, "")
        self.assertEqual(err.strip(), "bundle_unavailable")

    def test_damaged_evidence_is_unavailable(self):
        request_id = self._anchored_request()
        with sqlite3.connect(self.db_path) as raw:
            raw.execute(
                "UPDATE status_events SET status = 'failed' "
                "WHERE request_id = ? AND seq = 0",
                (request_id,),
            )
        code, out, err = self._run_cli(self.db_path, "tenant-a", request_id)
        self.assertEqual(code, 4)
        self.assertEqual(out, "")
        self.assertEqual(err.strip(), "bundle_unavailable")

    def test_deleted_anchor_is_unavailable(self):
        request_id = self._anchored_request()
        with sqlite3.connect(self.db_path) as raw:
            raw.execute(
                "DELETE FROM audit_anchors WHERE request_id = ?",
                (request_id,),
            )
        code, out, err = self._run_cli(self.db_path, "tenant-a", request_id)
        self.assertEqual(code, 4)
        self.assertEqual(out, "")
        self.assertEqual(err.strip(), "bundle_unavailable")

    def test_missing_generation_record_is_unavailable(self):
        store = RequestStore(self.db_path, anchor_secret=SECRET_A)
        request_id = store.submit(
            "tenant-a", "subject-1", ["email"], "key-1"
        )["request_id"]
        store.rotate_anchor_key(SECRET_A, SECRET_B)
        # The request's anchors name generation 1; without its
        # fingerprint record the historical key association cannot be
        # rendered.
        with sqlite3.connect(self.db_path) as raw:
            raw.execute("DELETE FROM anchor_key_generations WHERE generation = 1")
        code, out, err = self._run_cli(self.db_path, "tenant-a", request_id)
        self.assertEqual(code, 4)
        self.assertEqual(out, "")
        self.assertEqual(err.strip(), "bundle_unavailable")

    def test_missing_current_generation_record_is_unavailable(self):
        store = RequestStore(self.db_path, anchor_secret=SECRET_A)
        store.submit("tenant-a", "subject-1", ["email"], "key-1")
        store.rotate_anchor_key(SECRET_A, SECRET_B)
        rebuilt = RequestStore(
            self.db_path,
            anchor_secret=SECRET_B,
            anchor_history_secrets={1: SECRET_A},
        )
        request_id = rebuilt.submit(
            "tenant-a", "subject-2", ["email"], "key-2"
        )["request_id"]
        # The remaining records stay gap-free, but the request's anchors
        # name the deleted current generation.
        with sqlite3.connect(self.db_path) as raw:
            raw.execute("DELETE FROM anchor_key_generations WHERE generation = 2")
        code, out, err = self._run_cli(self.db_path, "tenant-a", request_id)
        self.assertEqual(code, 4)
        self.assertEqual(out, "")
        self.assertEqual(err.strip(), "bundle_unavailable")

    # -- storage failures --------------------------------------------------

    def test_missing_database_is_bundle_failed_and_not_created(self):
        missing = os.path.join(self._tmp.name, "no-such.db")
        code, out, err = self._run_cli(missing, "tenant-a", "request-1")
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertEqual(err.strip(), "bundle_failed")
        self.assertFalse(os.path.exists(missing))

    def test_corrupt_database_is_bundle_failed(self):
        RequestStore(self.db_path)
        with open(self.db_path, "wb") as handle:
            handle.write(b"this is not a sqlite database")
        code, out, err = self._run_cli(self.db_path, "tenant-a", "request-1")
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertEqual(err.strip(), "bundle_failed")

    def test_directory_as_database_is_bundle_failed(self):
        code, out, err = self._run_cli(self._tmp.name, "tenant-a", "request-1")
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertEqual(err.strip(), "bundle_failed")

    def test_dropped_table_is_bundle_failed(self):
        request_id = self._anchored_request()
        with sqlite3.connect(self.db_path) as raw:
            raw.execute("DROP TABLE audit_anchors")
        code, out, err = self._run_cli(self.db_path, "tenant-a", request_id)
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertEqual(err.strip(), "bundle_failed")

    # -- output hygiene ----------------------------------------------------

    def test_error_output_carries_no_details(self):
        request_id = self._anchored_request()
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
                    request_id, "subject-1", "email", "key-1",
                    SECRET_A, "sqlite",
                ):
                    self.assertNotIn(sensitive, err)

    def test_success_output_carries_no_sensitive_fields(self):
        store = RequestStore(self.db_path, anchor_secret=SECRET_A)
        receipt = store.submit(
            "tenant-a", "subject-secret", ["scope-secret"], "key-1"
        )
        code, out, _err = self._run_cli(
            self.db_path, "tenant-a", receipt["request_id"]
        )
        self.assertEqual(code, 0)
        for sensitive in ("subject-secret", "scope-secret", "key-1",
                          SECRET_A, self.db_path):
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
