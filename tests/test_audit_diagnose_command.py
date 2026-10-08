"""Tests for the read-only ``python -m forgetting_evidence audit-diagnose`` command.

Covers the CLI surface only: the strict two-flag invocation (``--bundle``
and ``--anchor-secrets``, separated or equals form, never positional,
mixed, duplicated or empty), the UTF-8 as-is file reads, the secret
mapping file shape (one JSON object, canonical positive-integer decimal
keys without repetition, non-empty string values), the single-line
compact JSON result being byte-identical to
``RequestStore.diagnose_audit_bundle`` on the same inputs, trusted and
untrusted outcomes (including ``anchor_key_missing`` when a generation
secret is absent), byte-identical repeats, the fully offline and
strictly read-only behaviour (no database connection, no RequestStore,
input files byte-for-byte intact, works with the database deleted), the
fixed detail-free markers (``audit_diagnose_usage`` and
``audit_diagnose_failed``, both at exit 2 with an empty stdout) and the
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

SECRET_A = "anchor-secret-alpha-0001"
SECRET_B = "anchor-secret-bravo-0002"

HEX64 = "0" * 64


class AuditDiagnoseCommandTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "evidence.db")
        self.bundle_path = os.path.join(self._tmp.name, "bundle.json")
        self.secrets_path = os.path.join(self._tmp.name, "secrets.json")

    def tearDown(self):
        self._tmp.cleanup()

    def _run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["audit-diagnose", *argv])
        return code, out.getvalue(), err.getvalue()

    def _write(self, path, text):
        with open(path, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)

    def _write_bytes(self, path, data):
        with open(path, "wb") as handle:
            handle.write(data)

    def _read_bytes(self, path):
        with open(path, "rb") as handle:
            return handle.read()

    def _exported_bundle(self, tenant="tenant-a"):
        store = RequestStore(self.db_path, anchor_secret=SECRET_A)
        request_id = store.submit(tenant, "subject-1", ["email"], "key-1")[
            "request_id"
        ]
        store.transition(tenant, request_id, "processing")
        store.transition(tenant, request_id, "completed")
        return store.export_audit_bundle(tenant, request_id)

    def _trusted_files(self):
        text = self._exported_bundle()
        self._write(self.bundle_path, text)
        self._write(self.secrets_path, json.dumps({"1": SECRET_A}))
        return text

    # -- success ---------------------------------------------------------

    def test_trusted_success_matches_store_diagnosis_byte_for_byte(self):
        text = self._trusted_files()
        expected = RequestStore.diagnose_audit_bundle(text, {1: SECRET_A})
        code, out, err = self._run_cli(
            "--bundle", self.bundle_path, "--anchor-secrets", self.secrets_path
        )
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(out, expected)
        self.assertEqual(out, '{"trusted":true,"reasons":[]}\n')

    def test_flag_order_and_equals_forms_are_equivalent(self):
        self._trusted_files()
        expected = self._run_cli(
            "--bundle", self.bundle_path, "--anchor-secrets", self.secrets_path
        )
        self.assertEqual(expected[0], 0)
        for argv in (
            ("--anchor-secrets", self.secrets_path, "--bundle", self.bundle_path),
            (f"--bundle={self.bundle_path}",
             f"--anchor-secrets={self.secrets_path}"),
            (f"--anchor-secrets={self.secrets_path}",
             f"--bundle={self.bundle_path}"),
            ("--bundle", self.bundle_path,
             f"--anchor-secrets={self.secrets_path}"),
        ):
            with self.subTest(argv=argv):
                self.assertEqual(self._run_cli(*argv), expected)

    def test_untrusted_bundle_reports_sorted_stable_reasons(self):
        text = self._exported_bundle()
        payload = json.loads(text)
        payload["chain"]["head"] = HEX64
        payload["anchors"][0]["anchor_hmac"] = HEX64
        tampered = json.dumps(payload, separators=(",", ":")) + "\n"
        self._write(self.bundle_path, tampered)
        self._write(self.secrets_path, json.dumps({"1": SECRET_A}))
        expected = RequestStore.diagnose_audit_bundle(tampered, {1: SECRET_A})
        code, out, err = self._run_cli(
            "--bundle", self.bundle_path, "--anchor-secrets", self.secrets_path
        )
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(out, expected)
        parsed = json.loads(out)
        self.assertEqual(list(parsed), ["trusted", "reasons"])
        self.assertFalse(parsed["trusted"])
        self.assertEqual(
            parsed["reasons"], ["anchor_auth_failed", "chain_head_mismatch"]
        )

    def test_missing_generation_secret_reports_anchor_key_missing(self):
        store = RequestStore(self.db_path, anchor_secret=SECRET_A)
        request_id = store.submit("tenant-a", "subject-1", ["email"], "key-1")[
            "request_id"
        ]
        store.rotate_anchor_key(SECRET_A, SECRET_B)
        rotated = RequestStore(
            self.db_path, anchor_secret=SECRET_B,
            anchor_history_secrets={1: SECRET_A},
        )
        rotated.transition("tenant-a", request_id, "processing")
        text = rotated.export_audit_bundle("tenant-a", request_id)
        self._write(self.bundle_path, text)
        # Only the current generation's secret is handed over; the
        # historical generation is reported missing, never guessed.
        self._write(self.secrets_path, json.dumps({"2": SECRET_B}))
        code, out, err = self._run_cli(
            "--bundle", self.bundle_path, "--anchor-secrets", self.secrets_path
        )
        self.assertEqual((code, err), (0, ""))
        parsed = json.loads(out)
        self.assertFalse(parsed["trusted"])
        self.assertIn("anchor_key_missing", parsed["reasons"])
        self.assertEqual(
            out, RequestStore.diagnose_audit_bundle(text, {2: SECRET_B})
        )

    def test_repeated_runs_are_byte_identical(self):
        self._trusted_files()
        argv = ("--bundle", self.bundle_path,
                "--anchor-secrets", self.secrets_path)
        first = self._run_cli(*argv)
        second = self._run_cli(*argv)
        self.assertEqual(first, second)
        self.assertEqual(first[0], 0)

    def test_diagnosis_is_fully_offline_with_the_database_gone(self):
        self._trusted_files()
        os.unlink(self.db_path)
        code, out, err = self._run_cli(
            "--bundle", self.bundle_path, "--anchor-secrets", self.secrets_path
        )
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(out, '{"trusted":true,"reasons":[]}\n')
        # The database was never recreated and no other file appeared.
        self.assertEqual(
            sorted(os.listdir(self._tmp.name)), ["bundle.json", "secrets.json"]
        )

    def test_command_does_not_modify_the_input_files(self):
        self._trusted_files()
        before = (
            self._read_bytes(self.bundle_path),
            self._read_bytes(self.secrets_path),
        )
        code, _out, _err = self._run_cli(
            "--bundle", self.bundle_path, "--anchor-secrets", self.secrets_path
        )
        self.assertEqual(code, 0)
        self.assertEqual(
            (self._read_bytes(self.bundle_path),
             self._read_bytes(self.secrets_path)),
            before,
        )
        self.assertEqual(
            sorted(os.listdir(self._tmp.name)),
            ["bundle.json", "evidence.db", "secrets.json"],
        )

    # -- usage errors: arguments ------------------------------------------

    def test_missing_duplicate_unknown_or_positional_args_are_usage(self):
        self._trusted_files()
        cases = (
            (),
            ("--bundle", self.bundle_path),
            ("--anchor-secrets", self.secrets_path),
            # Positional style is not accepted.
            (self.bundle_path, self.secrets_path),
            (self.bundle_path, "--anchor-secrets", self.secrets_path),
            ("--bundle", self.bundle_path, self.secrets_path),
            # Duplicated flags in either form.
            ("--bundle", self.bundle_path, "--bundle", self.bundle_path,
             "--anchor-secrets", self.secrets_path),
            (f"--bundle={self.bundle_path}", f"--bundle={self.bundle_path}",
             "--anchor-secrets", self.secrets_path),
            ("--bundle", self.bundle_path,
             "--anchor-secrets", self.secrets_path,
             "--anchor-secrets", self.secrets_path),
            # Unknown flags.
            ("--bundle", self.bundle_path, "--anchor-secrets",
             self.secrets_path, "--verbose"),
            ("--db", self.db_path, "--bundle", self.bundle_path,
             "--anchor-secrets", self.secrets_path),
            # Empty values in either form.
            ("--bundle=", "--anchor-secrets", self.secrets_path),
            ("--bundle", self.bundle_path, "--anchor-secrets="),
            ("--bundle", "", "--anchor-secrets", self.secrets_path),
            ("--bundle", self.bundle_path, "--anchor-secrets", ""),
            # A flag missing its value.
            ("--bundle", self.bundle_path, "--anchor-secrets"),
            ("--bundle",),
            # Extra trailing argument.
            ("--bundle", self.bundle_path, "--anchor-secrets",
             self.secrets_path, "extra"),
        )
        for argv in cases:
            with self.subTest(argv=argv):
                code, out, err = self._run_cli(*argv)
                self.assertEqual(code, 2)
                self.assertEqual(out, "")
                self.assertEqual(err.strip(), "audit_diagnose_usage")

    # -- usage errors: files ----------------------------------------------

    def test_unreadable_files_are_usage(self):
        self._trusted_files()
        missing = os.path.join(self._tmp.name, "no-such-file")
        for argv in (
            ("--bundle", missing, "--anchor-secrets", self.secrets_path),
            ("--bundle", self.bundle_path, "--anchor-secrets", missing),
            # A directory is not a readable file.
            ("--bundle", self._tmp.name,
             "--anchor-secrets", self.secrets_path),
            ("--bundle", self.bundle_path,
             "--anchor-secrets", self._tmp.name),
        ):
            with self.subTest(argv=argv):
                code, out, err = self._run_cli(*argv)
                self.assertEqual(code, 2)
                self.assertEqual(out, "")
                self.assertEqual(err.strip(), "audit_diagnose_usage")

    def test_non_utf8_files_are_usage(self):
        self._trusted_files()
        bad = os.path.join(self._tmp.name, "bad.bin")
        self._write_bytes(bad, b"\xff\xfe not utf-8")
        for argv in (
            ("--bundle", bad, "--anchor-secrets", self.secrets_path),
            ("--bundle", self.bundle_path, "--anchor-secrets", bad),
        ):
            with self.subTest(argv=argv):
                code, out, err = self._run_cli(*argv)
                self.assertEqual(code, 2)
                self.assertEqual(out, "")
                self.assertEqual(err.strip(), "audit_diagnose_usage")

    def test_invalid_secrets_json_is_usage(self):
        self._trusted_files()
        for content in (
            "not json",
            "{",
            "",
            # Not a JSON object at the top level.
            '[["1", "secret"]]',
            '"just a string"',
            "42",
            "null",
        ):
            self._write(self.secrets_path, content)
            with self.subTest(content=content):
                code, out, err = self._run_cli(
                    "--bundle", self.bundle_path,
                    "--anchor-secrets", self.secrets_path,
                )
                self.assertEqual(code, 2)
                self.assertEqual(out, "")
                self.assertEqual(err.strip(), "audit_diagnose_usage")

    def test_invalid_secrets_keys_and_values_are_usage(self):
        self._trusted_files()
        cases = (
            # Keys must be canonical positive-integer decimal strings.
            {"0": SECRET_A},
            {"01": SECRET_A},
            {"-1": SECRET_A},
            {"1.0": SECRET_A},
            {"a": SECRET_A},
            {"": SECRET_A},
            {" 1": SECRET_A},
            {"1 ": SECRET_A},
            {"+1": SECRET_A},
            # Values must be non-empty strings.
            {"1": ""},
            {"1": None},
            {"1": 1},
            {"1": True},
            {"1": [SECRET_A]},
            {"1": {"nested": SECRET_A}},
        )
        for mapping in cases:
            self._write(self.secrets_path, json.dumps(mapping))
            with self.subTest(mapping=mapping):
                code, out, err = self._run_cli(
                    "--bundle", self.bundle_path,
                    "--anchor-secrets", self.secrets_path,
                )
                self.assertEqual(code, 2)
                self.assertEqual(out, "")
                self.assertEqual(err.strip(), "audit_diagnose_usage")

    def test_duplicate_secrets_keys_are_usage(self):
        self._trusted_files()
        self._write(
            self.secrets_path,
            '{"1":"%s","1":"%s"}' % (SECRET_A, SECRET_B),
        )
        code, out, err = self._run_cli(
            "--bundle", self.bundle_path,
            "--anchor-secrets", self.secrets_path,
        )
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertEqual(err.strip(), "audit_diagnose_usage")

    def test_empty_secrets_mapping_is_a_valid_call(self):
        self._trusted_files()
        self._write(self.secrets_path, "{}")
        code, out, err = self._run_cli(
            "--bundle", self.bundle_path,
            "--anchor-secrets", self.secrets_path,
        )
        self.assertEqual((code, err), (0, ""))
        parsed = json.loads(out)
        self.assertFalse(parsed["trusted"])
        self.assertIn("anchor_key_missing", parsed["reasons"])

    # -- contract failures --------------------------------------------------

    def test_malformed_bundle_text_is_audit_diagnose_failed(self):
        self._trusted_files()
        for content in (
            "not json\n",
            "{}\n",
            "",
            "null\n",
            '{"request_id":"x"}\n',
            # Missing or duplicated trailing newline.
            self._read_bytes(self.bundle_path).decode("utf-8").rstrip("\n"),
            self._read_bytes(self.bundle_path).decode("utf-8") + "\n",
        ):
            self._write(self.bundle_path, content)
            with self.subTest(content=content[:40]):
                code, out, err = self._run_cli(
                    "--bundle", self.bundle_path,
                    "--anchor-secrets", self.secrets_path,
                )
                self.assertEqual(code, 2)
                self.assertEqual(out, "")
                self.assertEqual(err.strip(), "audit_diagnose_failed")

    # -- output hygiene ----------------------------------------------------

    def test_error_output_carries_no_details(self):
        text = self._trusted_files()
        self._write(self.bundle_path, "not json\n")
        missing = os.path.join(self._tmp.name, "absent.json")
        for argv in (
            ("--bundle", missing, "--anchor-secrets", self.secrets_path),
            ("--bundle", self.bundle_path, "--anchor-secrets", missing),
            ("--bundle", self.bundle_path,
             "--anchor-secrets", self.secrets_path),
            ("--bundle", self.bundle_path),
            ("--bundle", self.bundle_path, "--anchor-secrets",
             self.secrets_path, "extra"),
        ):
            for _attempt in range(2):
                code, out, err = self._run_cli(*argv)
                self.assertEqual(code, 2)
                self.assertEqual(out, "")
                self.assertIn(err.strip(),
                              ("audit_diagnose_usage", "audit_diagnose_failed"))
                for sensitive in (
                    self.db_path, self.bundle_path, self.secrets_path,
                    missing, SECRET_A, SECRET_B, "subject-1", "email",
                    "key-1", "Traceback", "ValueError", "OSError",
                ):
                    self.assertNotIn(sensitive, err)
        # The malformed bundle never leaks into the failure either.
        self.assertNotIn("not json", err)
        self.assertNotIn(text, err)

    def test_success_output_carries_no_secret_material(self):
        self._trusted_files()
        code, out, _err = self._run_cli(
            "--bundle", self.bundle_path, "--anchor-secrets", self.secrets_path
        )
        self.assertEqual(code, 0)
        for sensitive in (SECRET_A, SECRET_B, self.db_path,
                          self.bundle_path, self.secrets_path,
                          "subject-1", "key-1"):
            self.assertNotIn(sensitive, out)

    # -- the existing surface is unchanged ---------------------------------

    def test_health_and_audit_bundle_commands_are_unchanged(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["health"])
        self.assertEqual(code, 0)
        self.assertEqual(err.getvalue(), "")
        self.assertEqual(
            json.loads(out.getvalue()),
            {"service": "forgetting-evidence", "status": "ok"},
        )
        store = RequestStore(self.db_path, anchor_secret=SECRET_A)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        expected = store.export_audit_bundle("tenant-a", receipt["request_id"])
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(
                ["audit-bundle", self.db_path, "tenant-a",
                 receipt["request_id"]]
            )
        self.assertEqual(code, 0)
        self.assertEqual(err.getvalue(), "")
        self.assertEqual(out.getvalue(), expected)


if __name__ == "__main__":
    unittest.main()
