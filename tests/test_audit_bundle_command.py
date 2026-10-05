"""Tests for the read-only ``python -m forgetting_evidence audit-bundle`` command.

Covers the CLI surface only: the two strict invocation styles (three
positionals or the three named flags, never mixed), the verbatim
single-line compact JSON text of ``RequestStore.export_audit_bundle``
(exactly one trailing newline), byte-identical repeats, the strictly
read-only behaviour (the database is never created, migrated, repaired
or overwritten, and no state event, attempt, tombstone, anchor or audit
record is added), the fixed detail-free markers (``audit_bundle_usage``
at exit 2, ``bundle_not_found`` at exit 3, ``bundle_unavailable`` at
exit 4 and ``bundle_failed`` at exit 2, always with an empty stdout)
and the unchanged behaviour of the existing commands.
"""

import contextlib
import io
import json
import os
import tempfile
import unittest

from forgetting_evidence.__main__ import main
from forgetting_evidence.requests import RequestStore

_SECRET = "anchor-secret"


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
        store = RequestStore(self.db_path, anchor_secret=_SECRET)
        receipt = store.submit(tenant, "subject-1", ["email"], "key-1")
        store.transition(tenant, receipt["request_id"], "processing")
        store.transition(tenant, receipt["request_id"], "completed")
        return store, receipt["request_id"]

    # -- success ---------------------------------------------------------

    def test_positional_success_is_verbatim_store_text(self):
        store, rid = self._anchored_request()
        expected = store.export_audit_bundle("tenant-a", rid)
        code, out, err = self._run_cli(self.db_path, "tenant-a", rid)
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        # Exactly the store's text: one compact line, one trailing
        # newline, nothing more.
        self.assertEqual(out, expected)
        self.assertTrue(out.endswith("\n"))
        self.assertEqual(out.count("\n"), 1)
        payload = json.loads(out)
        self.assertEqual(
            list(payload),
            ["request_id", "status", "events", "chain", "anchors", "generations"],
        )
        self.assertEqual(payload["request_id"], rid)
        self.assertEqual(payload["status"], "completed")

    def test_flag_styles_and_equals_forms_are_equivalent(self):
        _store, rid = self._anchored_request()
        expected = self._run_cli(self.db_path, "tenant-a", rid)
        self.assertEqual(expected[0], 0)
        for argv in (
            ("--db", self.db_path, "--tenant-id", "tenant-a",
             "--request-id", rid),
            (f"--db={self.db_path}", f"--tenant-id=tenant-a",
             f"--request-id={rid}"),
            ("--tenant-id", "tenant-a", "--db", self.db_path,
             "--request-id", rid),
        ):
            with self.subTest(argv=argv):
                self.assertEqual(self._run_cli(*argv), expected)

    def test_repeated_runs_are_byte_identical(self):
        _store, rid = self._anchored_request()
        first = self._run_cli(self.db_path, "tenant-a", rid)
        second = self._run_cli(self.db_path, "tenant-a", rid)
        self.assertEqual(first, second)
        self.assertEqual(first[0], 0)

    def test_exported_bundle_verifies_offline(self):
        _store, rid = self._anchored_request()
        code, out, _err = self._run_cli(self.db_path, "tenant-a", rid)
        self.assertEqual(code, 0)
        self.assertTrue(
            RequestStore.verify_audit_bundle(out, {1: _SECRET})
        )

    def test_command_does_not_write_to_the_database(self):
        _store, rid = self._anchored_request()
        before = self._db_bytes()
        code, _out, _err = self._run_cli(self.db_path, "tenant-a", rid)
        self.assertEqual(code, 0)
        self.assertEqual(self._db_bytes(), before)
        self.assertEqual(os.listdir(self._tmp.name), ["evidence.db"])

    # -- not found ---------------------------------------------------------

    def test_unknown_request_id_is_bundle_not_found(self):
        self._anchored_request()
        code, out, err = self._run_cli(self.db_path, "tenant-a", "no-such-id")
        self.assertEqual(code, 3)
        self.assertEqual(out, "")
        self.assertEqual(err.strip(), "bundle_not_found")

    def test_cross_tenant_lookup_is_bundle_not_found(self):
        _store, rid = self._anchored_request()
        code, out, err = self._run_cli(self.db_path, "tenant-b", rid)
        self.assertEqual(code, 3)
        self.assertEqual(out, "")
        self.assertEqual(err.strip(), "bundle_not_found")

    # -- unavailable -------------------------------------------------------

    def test_unanchored_chain_is_bundle_unavailable(self):
        store = RequestStore(self.db_path)  # historical no-secret store
        rid = store.submit("tenant-a", "subject-1", ["email"], "key-1")[
            "request_id"
        ]
        code, out, err = self._run_cli(self.db_path, "tenant-a", rid)
        self.assertEqual(code, 4)
        self.assertEqual(out, "")
        self.assertEqual(err.strip(), "bundle_unavailable")

    def test_damaged_evidence_is_bundle_unavailable(self):
        import sqlite3

        _store, rid = self._anchored_request()
        with sqlite3.connect(self.db_path) as raw:
            raw.execute(
                "UPDATE status_events SET status = 'failed' "
                "WHERE tenant_id = 'tenant-a' AND seq = 2"
            )
        code, out, err = self._run_cli(self.db_path, "tenant-a", rid)
        self.assertEqual(code, 4)
        self.assertEqual(out, "")
        self.assertEqual(err.strip(), "bundle_unavailable")

    # -- usage errors ------------------------------------------------------

    def test_missing_duplicate_extra_mixed_or_empty_args_are_usage(self):
        _store, rid = self._anchored_request()
        cases = (
            (),
            (self.db_path,),
            (self.db_path, "tenant-a"),
            (self.db_path, "tenant-a", rid, "extra"),
            # Mixed positional and flag styles.
            (self.db_path, "tenant-a", "--request-id", rid),
            ("--db", self.db_path, "tenant-a", rid),
            # Duplicated flags.
            ("--db", self.db_path, "--db", self.db_path,
             "--tenant-id", "tenant-a", "--request-id", rid),
            ("--db", self.db_path, "--tenant-id", "tenant-a",
             "--tenant-id", "tenant-a", "--request-id", rid),
            # Unknown flags.
            ("--db", self.db_path, "--tenant-id", "tenant-a",
             "--request-id", rid, "--verbose"),
            ("--database", self.db_path, "--tenant-id", "tenant-a",
             "--request-id", rid),
            # Empty values in either style.
            ("", "tenant-a", rid),
            (self.db_path, "", rid),
            (self.db_path, "tenant-a", ""),
            ("--db=", "--tenant-id=tenant-a", "--request-id=x"),
            ("--request-id=", "--db", self.db_path, "--tenant-id", "tenant-a"),
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

    def test_usage_errors_never_touch_the_database(self):
        missing = os.path.join(self._tmp.name, "absent.db")
        code, out, err = self._run_cli(missing, "tenant-a")
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertEqual(err.strip(), "audit_bundle_usage")
        self.assertFalse(os.path.exists(missing))

    # -- storage failures --------------------------------------------------

    def test_missing_database_is_bundle_failed_and_not_created(self):
        missing = os.path.join(self._tmp.name, "no-such.db")
        code, out, err = self._run_cli(missing, "tenant-a", "req-1")
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertEqual(err.strip(), "bundle_failed")
        self.assertFalse(os.path.exists(missing))

    def test_corrupt_database_is_bundle_failed(self):
        RequestStore(self.db_path)
        with open(self.db_path, "wb") as handle:
            handle.write(b"this is not a sqlite database")
        code, out, err = self._run_cli(self.db_path, "tenant-a", "req-1")
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertEqual(err.strip(), "bundle_failed")

    def test_directory_as_database_is_bundle_failed(self):
        code, out, err = self._run_cli(self._tmp.name, "tenant-a", "req-1")
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertEqual(err.strip(), "bundle_failed")

    def test_dropped_table_is_bundle_failed(self):
        import sqlite3

        _store, rid = self._anchored_request()
        with sqlite3.connect(self.db_path) as raw:
            raw.execute("DROP TABLE audit_anchors")
        code, out, err = self._run_cli(self.db_path, "tenant-a", rid)
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertEqual(err.strip(), "bundle_failed")

    # -- output hygiene ------------------------------------------------------

    def test_error_output_carries_no_details(self):
        _store, rid = self._anchored_request()
        missing = os.path.join(self._tmp.name, "absent.db")
        for argv in (
            (missing, "tenant-a", rid),
            (self.db_path, "tenant-b", rid),
            (self.db_path, "tenant-a", rid, "extra"),
        ):
            for _attempt in range(2):
                _code, out, err = self._run_cli(*argv)
                self.assertEqual(out, "")
                for sensitive in (
                    self.db_path, missing, "tenant-a", "tenant-b", rid,
                    "subject-1", "email", "key-1", _SECRET, "sqlite",
                ):
                    self.assertNotIn(sensitive, err)

    def test_success_output_carries_no_sensitive_fields(self):
        store = RequestStore(self.db_path, anchor_secret=_SECRET)
        receipt = store.submit(
            "tenant-a", "subject-secret", ["scope-secret"], "key-secret"
        )
        claim = store.claim_next("tenant-a", "worker-secret", 300)
        store.finish_claim(
            "tenant-a",
            receipt["request_id"],
            claim["claim_token"],
            "completed",
        )
        code, out, _err = self._run_cli(
            self.db_path, "tenant-a", receipt["request_id"]
        )
        self.assertEqual(code, 0)
        for sensitive in ("subject-secret", "scope-secret", "key-secret",
                          "worker-secret", claim["claim_token"], _SECRET,
                          self.db_path):
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
