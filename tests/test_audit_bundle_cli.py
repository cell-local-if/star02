"""Tests for the three read-only evidence-bundle command line entries.

Covers ``python -m forgetting_evidence export-bundle``,
``verify-bundle`` and ``diagnose-bundle``: the exact single-line JSON
outputs and trailing newlines, the fixed exit codes (0 trusted/success,
1 untrusted/unavailable, 2 not-found/invalid-input, 3
storage-unavailable), the stdout/stderr split, read-only/no-database
creation behavior, offline verification with the database gone, secret
mapping validation, byte parity with the storage-layer bundle and
diagnosis, and unchanged ``health``/``serve`` surface with no secret,
subject, scope, SQL or path leakage.
"""

import contextlib
import io
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest

from forgetting_evidence.__main__ import main
from forgetting_evidence.requests import RequestStore

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(REPO_ROOT, "src")

SECRET_A = "anchor-secret-alpha-0001"
SECRET_B = "anchor-secret-bravo-0002"

INVALID_INPUT = '{"error":"invalid_input"}\n'
NOT_FOUND = '{"error":"not_found"}\n'
BUNDLE_UNAVAILABLE = '{"error":"bundle_unavailable"}\n'
STORAGE_UNAVAILABLE = '{"error":"storage_unavailable"}\n'
TRUSTED = '{"trusted":true}\n'
UNTRUSTED = '{"trusted":false}\n'

_TABLES = (
    "requests",
    "status_events",
    "audit_anchors",
    "audit_anchor_meta",
    "anchor_key_generations",
    "inspection_batches",
    "inspection_batch_items",
)


class _CliCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name
        self.db_path = os.path.join(self.tmp, "nested", "evidence.db")

    def tearDown(self):
        self._tmp.cleanup()

    # -- fixtures -------------------------------------------------------

    def _store(self, secret=SECRET_A, history=None):
        return RequestStore(
            self.db_path, anchor_secret=secret, anchor_history_secrets=history
        )

    def _seed(self, tenant="tenant-a", idem="key-1", secret=SECRET_A):
        store = self._store(secret=secret)
        request_id = store.submit(tenant, "subject-1", ["email", "files"], idem)[
            "request_id"
        ]
        store.transition(tenant, request_id, "processing")
        store.transition(tenant, request_id, "completed")
        return store, request_id

    def _secrets_file(self, mapping):
        path = os.path.join(self.tmp, "secrets.json")
        with open(path, "wb") as handle:
            handle.write(json.dumps(mapping).encode("utf-8"))
        return path

    def _all_tables(self):
        with sqlite3.connect(self.db_path) as raw:
            return {
                name: raw.execute(f"SELECT * FROM {name}").fetchall()
                for name in _TABLES
            }

    # -- in-process invocation -----------------------------------------

    def _run(self, argv, stdin=""):
        out, err = io.StringIO(), io.StringIO()
        old_stdin = sys.stdin
        sys.stdin = io.StringIO(stdin)
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = main(list(argv))
        finally:
            sys.stdin = old_stdin
        return code, out.getvalue(), err.getvalue()

    # -- real subprocess invocation (exact bytes/UTF-8 boundary) --------

    def _run_proc(self, argv, stdin=None):
        env = dict(os.environ)
        env["PYTHONPATH"] = SRC + os.pathsep + env.get("PYTHONPATH", "")
        proc = subprocess.run(
            [sys.executable, "-m", "forgetting_evidence", *argv],
            cwd=REPO_ROOT,
            env=env,
            input=(stdin.encode("utf-8") if stdin is not None else None),
            capture_output=True,
        )
        return proc.returncode, proc.stdout, proc.stderr


class ExportBundleTests(_CliCase):
    def test_success_is_storage_layer_bundle_byte_identical(self):
        store, request_id = self._seed()
        expected = store.export_audit_bundle("tenant-a", request_id)
        code, out, err = self._run([
            "export-bundle", "--db", self.db_path,
            "--tenant-id", "tenant-a", "--request-id", request_id,
        ])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertEqual(out, expected)
        self.assertTrue(out.endswith("\n"))
        self.assertFalse(out.endswith("\n\n"))
        # Subject, raw scopes, idempotency key and the secret never leak.
        self.assertNotIn("subject-1", out)
        self.assertNotIn("email", out)
        self.assertNotIn("files", out)
        self.assertNotIn("key-1", out)
        self.assertNotIn(SECRET_A, out)

    def test_equals_flag_form_works(self):
        _store, request_id = self._seed()
        code, out, err = self._run([
            "export-bundle",
            f"--db={self.db_path}",
            "--tenant-id=tenant-a",
            f"--request-id={request_id}",
        ])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertEqual(json.loads(out)["request_id"], request_id)

    def test_repeat_export_is_stable(self):
        _store, request_id = self._seed()
        argv = [
            "export-bundle", "--db", self.db_path,
            "--tenant-id", "tenant-a", "--request-id", request_id,
        ]
        _c, first, _e = self._run(argv)
        _c, second, _e = self._run(argv)
        self.assertEqual(first, second)

    def test_unknown_request_is_not_found_exit_2(self):
        self._seed()
        code, out, err = self._run([
            "export-bundle", "--db", self.db_path,
            "--tenant-id", "tenant-a", "--request-id", "does-not-exist",
        ])
        self.assertEqual(code, 2)
        self.assertEqual(out, NOT_FOUND)
        self.assertEqual(err, "")

    def test_cross_tenant_request_is_not_found(self):
        _store, request_id = self._seed()
        code, out, err = self._run([
            "export-bundle", "--db", self.db_path,
            "--tenant-id", "tenant-b", "--request-id", request_id,
        ])
        self.assertEqual(code, 2)
        self.assertEqual(out, NOT_FOUND)
        self.assertEqual(err, "")

    def test_unanchored_chain_is_unavailable_exit_1(self):
        # A store that never held an anchor secret leaves the chain
        # un-anchored; the command cannot export it.
        store = RequestStore(self.db_path)
        request_id = store.submit("tenant-a", "subject-1", ["email"], "key-1")[
            "request_id"
        ]
        code, out, err = self._run([
            "export-bundle", "--db", self.db_path,
            "--tenant-id", "tenant-a", "--request-id", request_id,
        ])
        self.assertEqual(code, 1)
        self.assertEqual(out, BUNDLE_UNAVAILABLE)
        self.assertEqual(err, "")

    def test_damaged_evidence_is_unavailable(self):
        _store, request_id = self._seed()
        with sqlite3.connect(self.db_path) as raw:
            raw.execute(
                "UPDATE status_events SET status = 'failed' "
                "WHERE tenant_id = 'tenant-a' AND seq = 1"
            )
        code, out, err = self._run([
            "export-bundle", "--db", self.db_path,
            "--tenant-id", "tenant-a", "--request-id", request_id,
        ])
        self.assertEqual(code, 1)
        self.assertEqual(out, BUNDLE_UNAVAILABLE)
        self.assertEqual(err, "")

    def test_anchor_naming_unknown_generation_is_unavailable(self):
        # Forged/structural generation association: the anchor names a
        # generation the file does not record. This is structural damage
        # the exporter rejects even without holding the secrets.
        _store, request_id = self._seed()
        with sqlite3.connect(self.db_path) as raw:
            raw.execute("UPDATE audit_anchors SET key_generation = 9")
        code, out, err = self._run([
            "export-bundle", "--db", self.db_path,
            "--tenant-id", "tenant-a", "--request-id", request_id,
        ])
        self.assertEqual(code, 1)
        self.assertEqual(out, BUNDLE_UNAVAILABLE)
        self.assertEqual(err, "")

    def test_missing_generation_rows_is_unavailable(self):
        _store, request_id = self._seed()
        with sqlite3.connect(self.db_path) as raw:
            raw.execute("DELETE FROM anchor_key_generations")
        code, out, err = self._run([
            "export-bundle", "--db", self.db_path,
            "--tenant-id", "tenant-a", "--request-id", request_id,
        ])
        self.assertEqual(code, 1)
        self.assertEqual(out, BUNDLE_UNAVAILABLE)
        self.assertEqual(err, "")

    def test_missing_database_is_storage_unavailable_exit_3(self):
        missing = os.path.join(self.tmp, "a", "b", "ghost.db")
        code, out, err = self._run([
            "export-bundle", "--db", missing,
            "--tenant-id", "tenant-a", "--request-id", "whatever",
        ])
        self.assertEqual(code, 3)
        self.assertEqual(out, STORAGE_UNAVAILABLE)
        self.assertEqual(err, "")
        # The command never creates the file or its parent directories.
        self.assertFalse(os.path.exists(missing))
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "a")))

    def test_garbage_and_directory_are_storage_unavailable(self):
        garbage = os.path.join(self.tmp, "garbage.db")
        with open(garbage, "wb") as handle:
            handle.write(b"not a database" * 16)
        code, out, err = self._run([
            "export-bundle", "--db", garbage,
            "--tenant-id", "tenant-a", "--request-id", "x",
        ])
        self.assertEqual(code, 3)
        self.assertEqual(out, STORAGE_UNAVAILABLE)
        self.assertEqual(err, "")

        code, out, err = self._run([
            "export-bundle", "--db", self.tmp,
            "--tenant-id", "tenant-a", "--request-id", "x",
        ])
        self.assertEqual(code, 3)
        self.assertEqual(out, STORAGE_UNAVAILABLE)
        self.assertEqual(err, "")

    def test_export_needs_no_secret_across_rotation(self):
        store = self._store(secret=SECRET_A)
        request_id = store.submit("tenant-a", "subject-1", ["email"], "k")["request_id"]
        store.rotate_anchor_key(SECRET_A, SECRET_B)
        rotated = self._store(secret=SECRET_B, history={1: SECRET_A})
        rotated.transition("tenant-a", request_id, "processing")
        rotated.transition("tenant-a", request_id, "completed")
        expected = rotated.export_audit_bundle("tenant-a", request_id)
        code, out, err = self._run([
            "export-bundle", "--db", self.db_path,
            "--tenant-id", "tenant-a", "--request-id", request_id,
        ])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertEqual(out, expected)

    def test_export_is_strictly_read_only(self):
        _store, request_id = self._seed()
        before = self._all_tables()
        mtime = os.stat(self.db_path).st_mtime_ns
        argv = [
            "export-bundle", "--db", self.db_path,
            "--tenant-id", "tenant-a", "--request-id", request_id,
        ]
        self.assertEqual(self._run(argv)[0], 0)
        self.assertEqual(self._run(argv)[0], 0)
        self.assertEqual(before, self._all_tables())
        # No journal, WAL or shm sidecar is created by the read-only open.
        self.assertEqual(sorted(os.listdir(os.path.dirname(self.db_path))),
                         [os.path.basename(self.db_path)])
        self.assertEqual(os.stat(self.db_path).st_mtime_ns, mtime)

    def test_export_from_read_only_file_succeeds(self):
        _store, request_id = self._seed()
        expected = _store.export_audit_bundle("tenant-a", request_id)
        os.chmod(self.db_path, 0o444)
        try:
            code, out, err = self._run([
                "export-bundle", "--db", self.db_path,
                "--tenant-id", "tenant-a", "--request-id", request_id,
            ])
        finally:
            os.chmod(self.db_path, 0o644)
        self.assertEqual(code, 0)
        self.assertEqual(out, expected)
        self.assertEqual(err, "")

    def test_non_ascii_tenant_is_utf8_bytes(self):
        store, request_id = self._seed(tenant="租户-甲")
        expected = store.export_audit_bundle("租户-甲", request_id).encode("utf-8")
        code, out, err = self._run_proc([
            "export-bundle", "--db", self.db_path,
            "--tenant-id", "租户-甲", "--request-id", request_id,
        ])
        self.assertEqual(code, 0)
        self.assertEqual(err, b"")
        self.assertEqual(out, expected)


class ExportBundleInvalidInputTests(_CliCase):
    def _argv(self, **over):
        values = {
            "--db": self.db_path,
            "--tenant-id": "tenant-a",
            "--request-id": "request-1",
        }
        values.update(over)
        return ["export-bundle", *sum(([k, v] for k, v in values.items()), [])]

    def _assert_invalid(self, argv):
        code, out, err = self._run(argv)
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertEqual(err, INVALID_INPUT)
        # The fixed marker never carries a path or argument.
        self.assertNotIn(self.tmp, err)

    def test_missing_unknown_duplicate_and_empty_flags(self):
        base = ["--db", self.db_path, "--tenant-id", "tenant-a",
                "--request-id", "request-1"]
        self._assert_invalid(["export-bundle"])
        self._assert_invalid(["export-bundle", "--db", self.db_path])
        self._assert_invalid(["export-bundle", *base[:4]])
        self._assert_invalid(["export-bundle", *base, "--unknown", "x"])
        self._assert_invalid(["export-bundle", *base, "positional"])
        self._assert_invalid(["export-bundle", "--db", self.db_path,
                              "--db", self.db_path,
                              "--tenant-id", "tenant-a",
                              "--request-id", "request-1"])
        self._assert_invalid(["export-bundle", "--db", "",
                              "--tenant-id", "tenant-a",
                              "--request-id", "request-1"])
        self._assert_invalid(["export-bundle", f"--db={self.db_path}",
                              "--tenant-id=", "--request-id=request-1"])
        self._assert_invalid(["export-bundle", "--db", self.db_path,
                              "--tenant-id", "tenant-a", "--request-id"])
        self._assert_invalid(["export-bundle", "--database", self.db_path,
                              "--tenant-id", "tenant-a",
                              "--request-id", "request-1"])

    def test_empty_tenant_value_is_invalid(self):
        self._assert_invalid(self._argv(**{"--tenant-id": ""}))

    def test_error_never_prints_stack_or_path(self):
        self._seed()
        code, out, err = self._run([
            "export-bundle", "--db", self.db_path,
            "--tenant-id", "tenant-a", "--request-id", "x",
        ])
        self.assertEqual(code, 2)
        self.assertEqual(out, NOT_FOUND)
        self.assertNotIn("Traceback", out + err)
        self.assertNotIn(self.db_path, out + err)


class VerifyBundleTests(_CliCase):
    def test_trusted_bundle_exit_0(self):
        _store, request_id = self._seed()
        _c, bundle, _e = self._run([
            "export-bundle", "--db", self.db_path,
            "--tenant-id", "tenant-a", "--request-id", request_id,
        ])
        secrets_file = self._secrets_file({"1": SECRET_A})
        code, out, err = self._run(
            ["verify-bundle", "--secrets", secrets_file], bundle
        )
        self.assertEqual(code, 0)
        self.assertEqual(out, TRUSTED)
        self.assertEqual(err, "")

    def test_trusted_without_database(self):
        _store, request_id = self._seed()
        _c, bundle, _e = self._run([
            "export-bundle", "--db", self.db_path,
            "--tenant-id", "tenant-a", "--request-id", request_id,
        ])
        os.unlink(self.db_path)
        secrets_file = self._secrets_file({"1": SECRET_A})
        code, out, err = self._run(
            ["verify-bundle", "--secrets", secrets_file], bundle
        )
        self.assertEqual(code, 0)
        self.assertEqual(out, TRUSTED)

    def test_wrong_and_missing_secret_exit_1(self):
        _store, request_id = self._seed()
        _c, bundle, _e = self._run([
            "export-bundle", "--db", self.db_path,
            "--tenant-id", "tenant-a", "--request-id", request_id,
        ])
        for mapping in ({}, {"1": "wrong-secret"}, {"2": SECRET_A}):
            secrets_file = self._secrets_file(mapping)
            code, out, err = self._run(
                ["verify-bundle", "--secrets", secrets_file], bundle
            )
            self.assertEqual(code, 1, mapping)
            self.assertEqual(out, UNTRUSTED, mapping)
            self.assertEqual(err, "")

    def test_tampered_bundle_exit_1(self):
        _store, request_id = self._seed()
        _c, bundle, _e = self._run([
            "export-bundle", "--db", self.db_path,
            "--tenant-id", "tenant-a", "--request-id", request_id,
        ])
        payload = json.loads(bundle)
        payload["anchors"][0]["anchor_hmac"] = "0" * 64
        tampered = json.dumps(payload, separators=(",", ":")) + "\n"
        secrets_file = self._secrets_file({"1": SECRET_A})
        code, out, err = self._run(
            ["verify-bundle", "--secrets", secrets_file], tampered
        )
        self.assertEqual(code, 1)
        self.assertEqual(out, UNTRUSTED)

    def test_equivalent_form_and_proc_bytes(self):
        _store, request_id = self._seed()
        _c, bundle, _e = self._run([
            "export-bundle", "--db", self.db_path,
            "--tenant-id", "tenant-a", "--request-id", request_id,
        ])
        secrets_file = self._secrets_file({"1": SECRET_A})
        code, out, err = self._run_proc(
            ["verify-bundle", f"--secrets={secrets_file}"], bundle
        )
        self.assertEqual(code, 0)
        self.assertEqual(out, b'{"trusted":true}\n')
        self.assertEqual(err, b"")

    def test_output_never_contains_secret(self):
        _store, request_id = self._seed()
        _c, bundle, _e = self._run([
            "export-bundle", "--db", self.db_path,
            "--tenant-id", "tenant-a", "--request-id", request_id,
        ])
        secrets_file = self._secrets_file({"1": SECRET_A})
        code, out, err = self._run(
            ["verify-bundle", "--secrets", secrets_file], bundle
        )
        self.assertEqual(code, 0)
        self.assertNotIn(SECRET_A, out + err)


class BundleSecretsValidationTests(_CliCase):
    def setUp(self):
        super().setUp()
        _store, request_id = self._seed()
        _c, self.bundle, _e = self._run([
            "export-bundle", "--db", self.db_path,
            "--tenant-id", "tenant-a", "--request-id", request_id,
        ])

    def _secrets_raw(self, raw_bytes):
        path = os.path.join(self.tmp, "secrets.json")
        with open(path, "wb") as handle:
            handle.write(raw_bytes)
        return path

    def _assert_invalid(self, argv, stdin):
        code, out, err = self._run(argv, stdin)
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertEqual(err, INVALID_INPUT)
        self.assertNotIn("Traceback", err)

    def test_missing_flag_and_missing_file(self):
        self._assert_invalid(["verify-bundle"], self.bundle)
        self._assert_invalid(
            ["verify-bundle", "--secrets", os.path.join(self.tmp, "absent")],
            self.bundle,
        )
        self._assert_invalid(["diagnose-bundle"], self.bundle)

    def test_invalid_secret_files(self):
        cases = [
            b"",
            b"not json",
            b"[]",
            b'"string"',
            b"null",
            b'{"0":"x"}',
            b'{"-1":"x"}',
            b'{"01":"x"}',
            b'{"abc":"x"}',
            b'{"1":""}',
            b'{"1":null}',
            b'{"1":5}',
            b'{"1":"x","1":"y"}',
            b'[1,2]',
            b"\xff\xfe",  # invalid UTF-8
        ]
        for raw in cases:
            path = self._secrets_raw(raw)
            self._assert_invalid(
                ["verify-bundle", "--secrets", path], self.bundle
            )
            self._assert_invalid(
                ["diagnose-bundle", "--secrets", path], self.bundle
            )

    def test_empty_mapping_is_valid_but_fails_closed(self):
        path = self._secrets_file({})
        code, out, err = self._run(
            ["verify-bundle", "--secrets", path], self.bundle
        )
        self.assertEqual(code, 1)
        self.assertEqual(out, UNTRUSTED)

    def test_duplicate_flag_and_extra_args(self):
        path = self._secrets_file({"1": SECRET_A})
        self._assert_invalid(
            ["verify-bundle", "--secrets", path, "--secrets", path],
            self.bundle,
        )
        self._assert_invalid(
            ["verify-bundle", "--secrets", path, "extra"], self.bundle
        )
        self._assert_invalid(
            ["verify-bundle", "--secrets"], self.bundle
        )

    def test_secret_material_never_in_error(self):
        path = self._secrets_raw(b'{"1":"super-secret-value"')
        code, out, err = self._run(
            ["verify-bundle", "--secrets", path], self.bundle
        )
        self.assertEqual(code, 2)
        self.assertNotIn("super-secret-value", out + err)
        self.assertNotIn(path, out + err)


class BundleInputValidationTests(_CliCase):
    def setUp(self):
        super().setUp()
        _store, request_id = self._seed()
        _c, self.bundle, _e = self._run([
            "export-bundle", "--db", self.db_path,
            "--tenant-id", "tenant-a", "--request-id", request_id,
        ])
        self.secrets_file = self._secrets_file({"1": SECRET_A})
        self.payload = json.loads(self.bundle)

    def _render(self, payload):
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"

    def _assert_invalid(self, stdin, command="verify-bundle"):
        code, out, err = self._run(
            [command, "--secrets", self.secrets_file], stdin
        )
        self.assertEqual(code, 2, stdin)
        self.assertEqual(out, "")
        self.assertEqual(err, INVALID_INPUT)

    def test_malformed_presentations(self):
        bad_inputs = [
            "",
            "not json\n",
            self.bundle[:-1],          # missing trailing newline
            self.bundle + "\n",        # doubled newline
            json.dumps(self.payload, indent=2) + "\n",  # interior breaks
            self._render({}),
            self._render({"request_id": "x"}),
        ]
        payload = dict(self.payload)
        payload["extra"] = 1
        bad_inputs.append(self._render(payload))
        payload = json.loads(self.bundle)
        del payload["chain"]
        bad_inputs.append(self._render(payload))
        for stdin in bad_inputs:
            self._assert_invalid(stdin, "verify-bundle")
            self._assert_invalid(stdin, "diagnose-bundle")

    def test_diagnose_rejects_non_canonical_that_verify_accepts(self):
        # A reformatted-but-authentic bundle still authenticates for the
        # boolean verify entry, while diagnose requires canonical compact
        # JSON and reports invalid_input.
        pretty = json.dumps(self.payload) + "\n"  # introduces spaces
        code, out, err = self._run(
            ["verify-bundle", "--secrets", self.secrets_file], pretty
        )
        self.assertEqual(code, 0)
        self.assertEqual(out, TRUSTED)
        self._assert_invalid(pretty, "diagnose-bundle")


class DiagnoseBundleTests(_CliCase):
    def test_trusted_diagnosis_matches_storage_layer(self):
        _store, request_id = self._seed()
        _c, bundle, _e = self._run([
            "export-bundle", "--db", self.db_path,
            "--tenant-id", "tenant-a", "--request-id", request_id,
        ])
        secrets_file = self._secrets_file({"1": SECRET_A})
        expected = RequestStore.diagnose_audit_bundle(bundle, {1: SECRET_A})
        code, out, err = self._run(
            ["diagnose-bundle", "--secrets", secrets_file], bundle
        )
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertEqual(out, expected)
        self.assertEqual(out, '{"trusted":true,"reasons":[]}\n')

    def test_untrusted_diagnosis_exit_1_with_sorted_reasons(self):
        _store, request_id = self._seed()
        _c, bundle, _e = self._run([
            "export-bundle", "--db", self.db_path,
            "--tenant-id", "tenant-a", "--request-id", request_id,
        ])
        payload = json.loads(bundle)
        payload["anchors"][0]["anchor_hmac"] = "0" * 64
        tampered = json.dumps(payload, separators=(",", ":")) + "\n"
        secrets_file = self._secrets_file({"1": SECRET_A})
        expected = RequestStore.diagnose_audit_bundle(tampered, {1: SECRET_A})
        code, out, err = self._run(
            ["diagnose-bundle", "--secrets", secrets_file], tampered
        )
        self.assertEqual(code, 1)
        self.assertEqual(err, "")
        self.assertEqual(out, expected)
        result = json.loads(out)
        self.assertFalse(result["trusted"])
        self.assertEqual(result["reasons"], sorted(result["reasons"]))
        self.assertIn("anchor_auth_failed", result["reasons"])

    def test_missing_historical_secret_is_reasoned(self):
        _store, request_id = self._seed()
        _c, bundle, _e = self._run([
            "export-bundle", "--db", self.db_path,
            "--tenant-id", "tenant-a", "--request-id", request_id,
        ])
        secrets_file = self._secrets_file({})
        code, out, err = self._run(
            ["diagnose-bundle", "--secrets", secrets_file], bundle
        )
        self.assertEqual(code, 1)
        result = json.loads(out)
        self.assertFalse(result["trusted"])
        self.assertIn("anchor_key_missing", result["reasons"])

    def test_offline_diagnosis_after_database_removed(self):
        _store, request_id = self._seed()
        _c, bundle, _e = self._run([
            "export-bundle", "--db", self.db_path,
            "--tenant-id", "tenant-a", "--request-id", request_id,
        ])
        os.unlink(self.db_path)
        secrets_file = self._secrets_file({"1": SECRET_A})
        code, out, err = self._run(
            ["diagnose-bundle", "--secrets", secrets_file], bundle
        )
        self.assertEqual(code, 0)
        self.assertEqual(out, '{"trusted":true,"reasons":[]}\n')


class CommandSurfaceTests(_CliCase):
    def test_health_unchanged(self):
        code, out, err = self._run(["health"])
        self.assertEqual(code, 0)
        self.assertEqual(
            json.loads(out),
            {"service": "forgetting-evidence", "status": "ok"},
        )

    def test_unknown_command_and_usage_unchanged(self):
        for argv in ([], ["bogus"], ["health", "extra"], ["EXPORT-BUNDLE"]):
            code, out, err = self._run(argv)
            self.assertEqual(code, 2, argv)
            self.assertEqual(out, "")
            self.assertIn("usage", err)

    def test_bundle_commands_have_no_relation_to_serve(self):
        # serve-style positional arguments are not accepted by the new
        # named-flag commands.
        code, out, err = self._run([
            "export-bundle", self.db_path, "tenant-a", "request-1",
        ])
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertEqual(err, INVALID_INPUT)

    def test_no_evidence_files_are_written(self):
        _store, request_id = self._seed()
        secrets_file = self._secrets_file({"1": SECRET_A})
        argv_export = [
            "export-bundle", "--db", self.db_path,
            "--tenant-id", "tenant-a", "--request-id", request_id,
        ]
        _c, bundle, _e = self._run(argv_export)
        entries_before = set(os.listdir(self.tmp))
        self.assertEqual(self._run(
            ["verify-bundle", "--secrets", secrets_file], bundle)[0], 0)
        self.assertEqual(self._run(
            ["diagnose-bundle", "--secrets", secrets_file], bundle)[0], 0)
        # Offline commands create nothing in the working tree.
        self.assertEqual(set(os.listdir(self.tmp)), entries_before)


if __name__ == "__main__":
    unittest.main()
