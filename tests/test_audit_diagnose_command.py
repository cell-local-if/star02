"""Tests for the read-only ``python -m forgetting_evidence audit-diagnose``
command.

Covers the CLI surface only: the strict named-only invocation (both
``--bundle`` and ``--anchor-secrets``, space or equals form, each
exactly once, no positionals or unknown flags), the successful
single-line compact JSON output (exactly ``trusted`` then ``reasons``,
one trailing newline), trusted diagnosis with the database deleted,
byte-identical repeats, untrusted diagnoses with the stable reason
codes (including ``anchor_key_missing``, never guessing a missing
generation), malformed inputs (unreadable file, non-UTF-8, illegal
JSON or illegal secret-mapping keys) mapped to ``audit_diagnose_usage``
at exit 2, contract violations of readable inputs mapped to
``audit_diagnose_failed`` at exit 2, strictly read-only behaviour and
the absence of any path, secret, bundle body or exception leakage,
plus the unchanged behaviour of the existing commands.
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


class AuditDiagnoseCommandTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "evidence.db")
        self.bundle_path = os.path.join(self._tmp.name, "bundle.json")
        self.secrets_path = os.path.join(self._tmp.name, "secrets.json")
        self.store = RequestStore(self.db_path, anchor_secret=SECRET_A)
        self.rid = self.store.submit(
            "tenant-a", "subject-1", ["email"], "key-1"
        )["request_id"]
        self.store.transition("tenant-a", self.rid, "processing")
        self.store.transition("tenant-a", self.rid, "completed")
        self.bundle_text = self.store.export_audit_bundle(
            "tenant-a", self.rid
        )
        with open(self.bundle_path, "w", encoding="utf-8") as handle:
            handle.write(self.bundle_text)
        self._write_secrets({"1": SECRET_A})

    def tearDown(self):
        self._tmp.cleanup()

    def _write_secrets(self, mapping):
        with open(self.secrets_path, "w", encoding="utf-8") as handle:
            json.dump(mapping, handle, ensure_ascii=False)

    def _write_secrets_bytes(self, data):
        with open(self.secrets_path, "wb") as handle:
            handle.write(data)

    def _write_bundle_bytes(self, data):
        with open(self.bundle_path, "wb") as handle:
            handle.write(data)

    def _run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["audit-diagnose", *argv])
        return code, out.getvalue(), err.getvalue()

    def _assert_usage(self, *argv):
        code, out, err = self._run_cli(*argv)
        self.assertEqual((code, out, err.strip()),
                         (2, "", "audit_diagnose_usage"))

    def _assert_failed(self, *argv):
        code, out, err = self._run_cli(*argv)
        self.assertEqual((code, out, err.strip()),
                         (2, "", "audit_diagnose_failed"))

    # -- success ---------------------------------------------------------

    def test_flag_success_outputs_trusted_line(self):
        code, out, err = self._run_cli(
            "--bundle", self.bundle_path,
            "--anchor-secrets", self.secrets_path,
        )
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(out, '{"trusted":true,"reasons":[]}\n')
        self.assertTrue(out.endswith("\n"))
        self.assertEqual(out.count("\n"), 1)

    def test_equals_form_is_equivalent(self):
        expected = self._run_cli(
            "--bundle", self.bundle_path,
            "--anchor-secrets", self.secrets_path,
        )
        code, out, err = self._run_cli(
            f"--bundle={self.bundle_path}",
            f"--anchor-secrets={self.secrets_path}",
        )
        self.assertEqual((code, out, err), expected)

    def test_empty_secret_mapping_object_is_a_valid_call(self):
        # {} is a legal UTF-8 JSON object; the call succeeds and the
        # missing generation is diagnosed, never a usage failure.
        self._write_secrets({})
        code, out, err = self._run_cli(
            "--bundle", self.bundle_path,
            "--anchor-secrets", self.secrets_path,
        )
        self.assertEqual((code, err), (0, ""))
        record = json.loads(out)
        self.assertIs(record["trusted"], False)
        self.assertIn("anchor_key_missing", record["reasons"])

    def test_trusted_with_database_deleted(self):
        os.unlink(self.db_path)
        code, out, err = self._run_cli(
            "--bundle", self.bundle_path,
            "--anchor-secrets", self.secrets_path,
        )
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(out, '{"trusted":true,"reasons":[]}\n')
        self.assertFalse(os.path.exists(self.db_path))

    def test_repeated_runs_are_byte_identical(self):
        first = self._run_cli(
            "--bundle", self.bundle_path,
            "--anchor-secrets", self.secrets_path,
        )
        for _ in range(3):
            self.assertEqual(
                self._run_cli(
                    "--bundle", self.bundle_path,
                    "--anchor-secrets", self.secrets_path,
                ),
                first,
            )

    def test_reasons_deduplicated_and_code_point_sorted(self):
        # Tamper the bundle independently in several ways; the CLI only
        # relays what the storage diagnosis reports.
        payload = json.loads(self.bundle_text)
        payload["events"] = payload["events"][::-1]
        payload["events"][1]["chain_hash"] = "0" * 64
        payload["chain"]["head"] = "0" * 64
        payload["status"] = "failed"
        self._write_bundle_bytes(
            (json.dumps(payload, ensure_ascii=False,
                        separators=(",", ":")) + "\n").encode("utf-8")
        )
        code, out, err = self._run_cli(
            "--bundle", self.bundle_path,
            "--anchor-secrets", self.secrets_path,
        )
        self.assertEqual((code, err), (0, ""))
        record = json.loads(out)
        self.assertIs(record["trusted"], False)
        self.assertEqual(
            record["reasons"],
            sorted(set(record["reasons"]),
                   key=lambda reason: [ord(char) for char in reason]),
        )
        self.assertEqual(
            set(record["reasons"]),
            {
                "event_order_invalid",
                "chain_hash_mismatch",
                "chain_head_mismatch",
                "request_association_mismatch",
                "anchor_auth_failed",
            },
        )

    def test_missing_historical_secret_is_reported_not_guessed(self):
        # A request accepted under generation 1 anchors a processing
        # event under generation 2 after rotation; hand only the
        # generation-2 (current) secret.
        gen1 = RequestStore(self.db_path, anchor_secret=SECRET_A)
        rid = gen1.submit(
            "tenant-a", "subject-2", ["email"], "key-rotate"
        )["request_id"]
        gen1.rotate_anchor_key(SECRET_A, SECRET_B)
        rotated = RequestStore(
            self.db_path,
            anchor_secret=SECRET_B,
            anchor_history_secrets={1: SECRET_A},
        )
        rotated.transition("tenant-a", rid, "processing")
        text = rotated.export_audit_bundle("tenant-a", rid)
        self._write_bundle_bytes(text.encode("utf-8"))
        self._write_secrets({"2": SECRET_B})
        code, out, err = self._run_cli(
            "--bundle", self.bundle_path,
            "--anchor-secrets", self.secrets_path,
        )
        self.assertEqual((code, err), (0, ""))
        record = json.loads(out)
        self.assertIs(record["trusted"], False)
        self.assertIn("anchor_key_missing", record["reasons"])
        # Handing the current secret under generation 1 must bind-fail,
        # never authenticate the historical anchors.
        self._write_secrets({"1": SECRET_B, "2": SECRET_B})
        code, out, err = self._run_cli(
            "--bundle", self.bundle_path,
            "--anchor-secrets", self.secrets_path,
        )
        self.assertEqual(code, 0)
        self.assertIn(
            "anchor_generation_mismatch", json.loads(out)["reasons"]
        )

    def test_anchor_auth_failure_is_untrusted_not_failed(self):
        payload = json.loads(self.bundle_text)
        payload["anchors"][0]["anchor_hmac"] = "f" * 64
        self._write_bundle_bytes(
            (json.dumps(payload, ensure_ascii=False,
                        separators=(",", ":")) + "\n").encode("utf-8")
        )
        code, out, err = self._run_cli(
            "--bundle", self.bundle_path,
            "--anchor-secrets", self.secrets_path,
        )
        self.assertEqual((code, err), (0, ""))
        self.assertIs(json.loads(out)["trusted"], False)
        self.assertIn("anchor_auth_failed", json.loads(out)["reasons"])

    # -- usage errors ----------------------------------------------------

    def test_missing_duplicate_empty_or_unknown_args_are_usage(self):
        cases = (
            (),
            ("--bundle", self.bundle_path),
            ("--anchor-secrets", self.secrets_path),
            ("--bundle",),
            ("--anchor-secrets",),
            ("--bundle", self.bundle_path,
             "--anchor-secrets", self.secrets_path, "extra"),
            # Positional form is deliberately unsupported.
            (self.bundle_path, self.secrets_path),
            # Duplicated flags in either form.
            ("--bundle", self.bundle_path, "--bundle", self.bundle_path,
             "--anchor-secrets", self.secrets_path),
            ("--bundle=" + self.bundle_path, "--bundle", self.bundle_path,
             "--anchor-secrets", self.secrets_path),
            ("--bundle", self.bundle_path,
             "--anchor-secrets", self.secrets_path,
             "--anchor-secrets", self.secrets_path),
            # Unknown flags and flag-like tokens.
            ("--bundle", self.bundle_path,
             "--anchor-secrets", self.secrets_path, "--verbose"),
            ("--bundl", self.bundle_path,
             "--anchor-secrets", self.secrets_path),
            # Empty values.
            ("--bundle=", "--anchor-secrets", self.secrets_path),
            ("--bundle", "", "--anchor-secrets", self.secrets_path),
            ("--bundle", self.bundle_path, "--anchor-secrets="),
            ("--bundle", self.bundle_path, "--anchor-secrets", ""),
            # A flag consuming its neighbour flag as its value is still
            # missing the other input.
            ("--bundle", "--anchor-secrets", self.secrets_path),
        )
        for argv in cases:
            with self.subTest(argv=argv):
                self._assert_usage(*argv)

    def test_unreadable_files_are_usage(self):
        missing = os.path.join(self._tmp.name, "absent.json")
        self._assert_usage(
            "--bundle", missing, "--anchor-secrets", self.secrets_path
        )
        self._assert_usage(
            "--bundle", self.bundle_path, "--anchor-secrets", missing
        )
        # A directory is not a readable file.
        self._assert_usage(
            "--bundle", self._tmp.name,
            "--anchor-secrets", self.secrets_path,
        )
        self._assert_usage(
            "--bundle", self.bundle_path,
            "--anchor-secrets", self._tmp.name,
        )

    def test_non_utf8_bundle_is_usage(self):
        self._write_bundle_bytes(b"\xff\xfe\x00not utf-8")
        self._assert_usage(
            "--bundle", self.bundle_path,
            "--anchor-secrets", self.secrets_path,
        )

    def test_illegal_secret_mappings_are_usage(self):
        valid_suffix = b"\n  \t"
        cases = (
            b"",                              # empty file
            b"not json\n",
            b"\xff\xfe",                      # non-UTF-8
            b"[]",                            # not an object
            b'"string"',
            b"42",
            b'null',
            b'{"1": "x"} trailing',           # trailing data
            b'{"1":"x","1":"y"}',             # duplicate member
            b'{"01": "x"}',                   # leading zero
            b'{"0": "x"}',                    # zero is not positive
            b'{"-1": "x"}',
            b'{"+1": "x"}',
            b'{"1.0": "x"}',
            b'{" 1": "x"}',
            b'{"1e0": "x"}',
            b'{"abc": "x"}',
            b'{"1": ""}',                     # empty secret
            b'{"1": 5}',                      # non-string secret
            b'{"1": null}',
            b'{"1": ["x"]}',
        )
        for data in cases:
            with self.subTest(data=data):
                self._write_secrets_bytes(data)
                self._assert_usage(
                    "--bundle", self.bundle_path,
                    "--anchor-secrets", self.secrets_path,
                )
        # Trailing JSON whitespace around an otherwise valid object is
        # still the same UTF-8 JSON object.
        self._write_secrets_bytes(b'{"1": "anchor-secret-alpha-0001"}'
                                  + valid_suffix)
        code, out, err = self._run_cli(
            "--bundle", self.bundle_path,
            "--anchor-secrets", self.secrets_path,
        )
        self.assertEqual((code, out, err),
                         (0, '{"trusted":true,"reasons":[]}\n', ""))

    def test_mapping_keys_are_not_constrained_to_small_generations(self):
        # Arbitrary no-leading-zero positive decimal keys parse as
        # generations; an unneeded generation simply stays unused.
        self._write_secrets({"1": SECRET_A, "9007199254740993": "later"})
        code, out, err = self._run_cli(
            "--bundle", self.bundle_path,
            "--anchor-secrets", self.secrets_path,
        )
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(out, '{"trusted":true,"reasons":[]}\n')

    # -- contract failures of readable inputs ----------------------------

    def test_malformed_bundle_is_failed(self):
        for data in (
            b"",
            b"not json\n",
            b'{"request_id": 1}\n',
            # Missing the required trailing newline.
            self.bundle_text[:-1].encode("utf-8"),
        ):
            with self.subTest(data=data[:12]):
                self._write_bundle_bytes(data)
                self._assert_failed(
                    "--bundle", self.bundle_path,
                    "--anchor-secrets", self.secrets_path,
                )

    def test_non_canonical_whitespace_bundle_is_failed(self):
        body = self.bundle_text[:-1]
        self._write_bundle_bytes((body + " \n").encode("utf-8"))
        self._assert_failed(
            "--bundle", self.bundle_path,
            "--anchor-secrets", self.secrets_path,
        )

    # -- read-only and hygiene -------------------------------------------

    def test_command_never_writes_inputs_or_creates_database(self):
        other_db = os.path.join(self._tmp.name, "never-created.db")
        self.assertFalse(os.path.exists(other_db))
        with open(self.bundle_path, "rb") as handle:
            bundle_before = handle.read()
        with open(self.secrets_path, "rb") as handle:
            secrets_before = handle.read()
        for _ in range(3):
            code, _out, _err = self._run_cli(
                "--bundle", self.bundle_path,
                "--anchor-secrets", self.secrets_path,
            )
            self.assertEqual(code, 0)
        with open(self.bundle_path, "rb") as handle:
            self.assertEqual(handle.read(), bundle_before)
        with open(self.secrets_path, "rb") as handle:
            self.assertEqual(handle.read(), secrets_before)
        self.assertFalse(os.path.exists(other_db))

    def test_database_file_is_never_touched(self):
        with open(self.db_path, "rb") as handle:
            before = handle.read()
        code, _out, _err = self._run_cli(
            "--bundle", self.bundle_path,
            "--anchor-secrets", self.secrets_path,
        )
        self.assertEqual(code, 0)
        with open(self.db_path, "rb") as handle:
            self.assertEqual(handle.read(), before)

    def test_errors_never_leak_paths_secrets_or_bundle_content(self):
        secret = "super-secret-material-7777"
        self._write_secrets({"1": secret})
        missing = os.path.join(self._tmp.name, "absent.json")
        # A malformed bundle body that must never surface on stderr.
        self._write_bundle_bytes("BUNDLE-LEAK-MARKER\n".encode("utf-8"))
        for argv in (
            ("--bundle", missing, "--anchor-secrets", self.secrets_path),
            ("--bundle", self.bundle_path, "--anchor-secrets", missing),
            ("--bundle", self.bundle_path,),
            (),
        ):
            code, out, err = self._run_cli(*argv)
            self.assertEqual((code, out), (2, ""))
            for leaked in (
                self.bundle_path, self.secrets_path, missing,
                secret, "BUNDLE-LEAK-MARKER", self.rid, "tenant-a",
                "Traceback", "Error",
            ):
                self.assertNotIn(leaked, err)
        # The malformed bundle reaches the storage contract -> failed.
        code, out, err = self._run_cli(
            "--bundle", self.bundle_path,
            "--anchor-secrets", self.secrets_path,
        )
        self.assertEqual((code, out), (2, ""))
        for leaked in (secret, "BUNDLE-LEAK-MARKER", self.bundle_path,
                       "Traceback", "Error"):
            self.assertNotIn(leaked, err)

    def test_success_output_carries_no_secret_or_paths(self):
        secret = "super-secret-material-8888"
        self._write_secrets({"1": secret})
        code, out, err = self._run_cli(
            "--bundle", self.bundle_path,
            "--anchor-secrets", self.secrets_path,
        )
        self.assertEqual(code, 0)
        for leaked in (secret, self.bundle_path, self.secrets_path,
                       self.db_path, "key-1", "subject-1"):
            self.assertNotIn(leaked, out)
        self.assertNotIn(secret, err)

    # -- the existing surface is unchanged -------------------------------

    def test_existing_commands_are_unchanged(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["health"])
        self.assertEqual(code, 0)
        self.assertEqual(
            json.loads(out.getvalue()),
            {"service": "forgetting-evidence", "status": "ok"},
        )
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(
                ["status", self.db_path, "tenant-a", self.rid]
            )
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out.getvalue())["status"], "completed")
        # An unknown command still gets the generic usage marker.
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["audit-diagnos"])
        self.assertEqual((code, out.getvalue(), err.getvalue().strip()),
                         (2, "",
                          "usage: python -m forgetting_evidence health"))


if __name__ == "__main__":
    unittest.main()
