import contextlib
import io
import json
import os
import sqlite3
import tempfile
import unittest

from forgetting_evidence.__main__ import main
from forgetting_evidence.requests import RequestStore


class EvidenceCommandTests(unittest.TestCase):
    """The read-only ``python -m forgetting_evidence evidence`` command."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "evidence.db")
        store = RequestStore(self.db_path)
        self.receipt = store.submit(
            "tenant-a", "subject-1", ["email"], "key-1"
        )
        self.request_id = self.receipt["request_id"]

    def tearDown(self):
        self._tmp.cleanup()

    def _run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["evidence", *argv])
        return code, out.getvalue(), err.getvalue()

    def _db_bytes(self):
        with open(self.db_path, "rb") as handle:
            return handle.read()

    def _raw(self):
        return sqlite3.connect(self.db_path)

    # -- success ---------------------------------------------------------

    def test_positional_success_outputs_compact_json_line(self):
        code, out, err = self._run_cli(
            self.db_path, "tenant-a", self.request_id
        )
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertTrue(out.endswith("\n"))
        self.assertEqual(out.count("\n"), 1)
        record = json.loads(out)
        self.assertEqual(
            list(record),
            ["request_id", "status", "event_count", "chain_hash", "verified"],
        )
        self.assertEqual(record["request_id"], self.request_id)
        self.assertEqual(record["status"], "accepted")
        self.assertEqual(record["event_count"], 1)
        self.assertRegex(record["chain_hash"], r"^[0-9a-f]{64}$")
        self.assertIs(record["verified"], True)
        self.assertEqual(out.strip(), json.dumps(record, separators=(",", ":")))

    def test_flag_style_and_equals_form_are_equivalent(self):
        expected = self._run_cli(self.db_path, "tenant-a", self.request_id)
        for argv in (
            ("--db", self.db_path, "--tenant-id", "tenant-a",
             "--request-id", self.request_id),
            (f"--db={self.db_path}", "--tenant-id=tenant-a",
             f"--request-id={self.request_id}"),
        ):
            with self.subTest(argv=argv):
                self.assertEqual(self._run_cli(*argv), expected)

    def test_evidence_tracks_committed_transitions(self):
        store = RequestStore(self.db_path)
        store.transition("tenant-a", self.request_id, "processing")
        store.transition("tenant-a", self.request_id, "completed")
        code, out, _err = self._run_cli(
            self.db_path, "tenant-a", self.request_id
        )
        self.assertEqual(code, 0)
        record = json.loads(out)
        self.assertEqual(record["status"], "completed")
        self.assertEqual(record["event_count"], 3)
        self.assertIs(record["verified"], True)
        rebuilt = RequestStore(self.db_path)
        self.assertEqual(
            record["chain_hash"],
            rebuilt.evidence("tenant-a", self.request_id)["chain_hash"],
        )

    def test_command_does_not_write_to_the_database(self):
        before = self._db_bytes()
        for _ in range(3):
            code, _out, _err = self._run_cli(
                self.db_path, "tenant-a", self.request_id
            )
            self.assertEqual(code, 0)
        self.assertEqual(self._db_bytes(), before)
        self.assertEqual(os.listdir(self._tmp.name), ["evidence.db"])

    def test_missing_database_is_not_created(self):
        missing = os.path.join(self._tmp.name, "no-such.db")
        code, _out, err = self._run_cli(
            missing, "tenant-a", self.request_id
        )
        self.assertEqual(code, 2)
        self.assertEqual(err.strip(), "evidence_failed")
        self.assertFalse(os.path.exists(missing))

    # -- tampering: still exit 0, verified false ------------------------

    def _tamper(self, sql, params=()):
        with self._raw() as conn:
            conn.execute(sql, params)

    def test_deleted_event_is_verified_false_success(self):
        store = RequestStore(self.db_path)
        store.transition("tenant-a", self.request_id, "processing")
        self._tamper(
            "DELETE FROM status_events WHERE request_id = ? AND seq = 1",
            (self.request_id,),
        )
        code, out, err = self._run_cli(
            self.db_path, "tenant-a", self.request_id
        )
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        record = json.loads(out)
        self.assertIs(record["verified"], False)
        # Persisted fields are still reported as stored.
        self.assertEqual(record["event_count"], 1)
        self.assertEqual(record["status"], "processing")

    def test_all_events_deleted_is_verified_false_success(self):
        self._tamper(
            "DELETE FROM status_events WHERE request_id = ?",
            (self.request_id,),
        )
        code, out, err = self._run_cli(
            self.db_path, "tenant-a", self.request_id
        )
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        record = json.loads(out)
        self.assertIs(record["verified"], False)
        self.assertEqual(record["event_count"], 0)

    def test_altered_event_is_verified_false_success(self):
        self._tamper(
            "UPDATE status_events SET status = 'failed' "
            "WHERE request_id = ? AND seq = 0",
            (self.request_id,),
        )
        code, out, _err = self._run_cli(
            self.db_path, "tenant-a", self.request_id
        )
        self.assertEqual(code, 0)
        self.assertIs(json.loads(out)["verified"], False)

    def test_inserted_event_is_verified_false_success(self):
        self._tamper(
            "INSERT INTO status_events "
            "(tenant_id, request_id, seq, status, occurred_at, chain_hash) "
            "VALUES ('tenant-a', ?, 1, 'processing', '2026-01-01T00:00:00Z', ?)",
            (self.request_id, "0" * 64),
        )
        code, out, _err = self._run_cli(
            self.db_path, "tenant-a", self.request_id
        )
        self.assertEqual(code, 0)
        record = json.loads(out)
        self.assertIs(record["verified"], False)
        self.assertEqual(record["event_count"], 2)

    def test_reordered_event_is_verified_false_success(self):
        store = RequestStore(self.db_path)
        store.transition("tenant-a", self.request_id, "processing")
        self._tamper(
            "UPDATE status_events SET seq = 5 "
            "WHERE request_id = ? AND seq = 1",
            (self.request_id,),
        )
        code, out, _err = self._run_cli(
            self.db_path, "tenant-a", self.request_id
        )
        self.assertEqual(code, 0)
        self.assertIs(json.loads(out)["verified"], False)

    def test_tampered_head_is_verified_false_success(self):
        forged = "a" * 64
        self._tamper(
            "UPDATE requests SET chain_hash = ? WHERE request_id = ?",
            (forged, self.request_id),
        )
        code, out, _err = self._run_cli(
            self.db_path, "tenant-a", self.request_id
        )
        self.assertEqual(code, 0)
        record = json.loads(out)
        self.assertIs(record["verified"], False)
        # The stored head is reported verbatim, never recomputed.
        self.assertEqual(record["chain_hash"], forged)

    def test_tampered_current_status_is_verified_false_success(self):
        self._tamper(
            "UPDATE requests SET status = 'failed' WHERE request_id = ?",
            (self.request_id,),
        )
        code, out, _err = self._run_cli(
            self.db_path, "tenant-a", self.request_id
        )
        self.assertEqual(code, 0)
        record = json.loads(out)
        self.assertIs(record["verified"], False)
        self.assertEqual(record["status"], "failed")

    def test_malformed_persisted_head_is_not_found(self):
        self._tamper(
            "UPDATE requests SET chain_hash = 'not-a-digest' "
            "WHERE request_id = ?",
            (self.request_id,),
        )
        code, out, err = self._run_cli(
            self.db_path, "tenant-a", self.request_id
        )
        self.assertEqual(code, 3)
        self.assertEqual(out, "")
        self.assertEqual(err.strip(), "evidence_not_found")

    def test_tampered_chain_does_not_change_across_repeat_reads(self):
        self._tamper(
            "UPDATE status_events SET occurred_at = occurred_at || 'X' "
            "WHERE request_id = ? AND seq = 0",
            (self.request_id,),
        )
        first = self._run_cli(self.db_path, "tenant-a", self.request_id)
        second = self._run_cli(self.db_path, "tenant-a", self.request_id)
        self.assertEqual(first, second)
        self.assertEqual(first[0], 0)
        self.assertIs(json.loads(first[1])["verified"], False)

    # -- usage errors ----------------------------------------------------

    def test_missing_duplicate_extra_mixed_or_empty_args_are_usage(self):
        cases = (
            (),
            (self.db_path,),
            (self.db_path, "tenant-a"),
            (self.db_path, "tenant-a", self.request_id, "extra"),
            # Mixed positional and flag styles.
            (self.db_path, "--tenant-id", "tenant-a",
             "--request-id", self.request_id),
            ("--db", self.db_path, "tenant-a", self.request_id),
            # Duplicated flags.
            ("--db", self.db_path, "--db", self.db_path,
             "--tenant-id", "tenant-a", "--request-id", self.request_id),
            ("--db", self.db_path, "--tenant-id", "tenant-a",
             "--tenant-id", "tenant-a", "--request-id", self.request_id),
            ("--db", self.db_path, "--tenant-id", "tenant-a",
             "--request-id", self.request_id, "--request-id",
             self.request_id),
            # Unknown flags.
            ("--db", self.db_path, "--tenant-id", "tenant-a",
             "--request-id", self.request_id, "--verbose"),
            ("--host", "x"),
            # Empty values in either style.
            ("", "tenant-a", self.request_id),
            (self.db_path, "", self.request_id),
            (self.db_path, "tenant-a", ""),
            ("--db=", "--tenant-id=tenant-a", "--request-id=x"),
            ("--db", self.db_path, "--tenant-id", "",
             "--request-id", self.request_id),
            ("--db", self.db_path, "--tenant-id", "tenant-a",
             "--request-id="),
            # A flag missing its value.
            ("--db", self.db_path, "--tenant-id", "tenant-a", "--request-id"),
        )
        for argv in cases:
            with self.subTest(argv=argv):
                code, out, err = self._run_cli(*argv)
                self.assertEqual(code, 2)
                self.assertEqual(out, "")
                self.assertEqual(err.strip(), "evidence_usage")

    # -- not found -------------------------------------------------------

    def test_unknown_malformed_and_cross_tenant_ids_are_not_found(self):
        for rid in ("does-not-exist", "not-a-uuid"):
            with self.subTest(rid=rid):
                code, out, err = self._run_cli(self.db_path, "tenant-a", rid)
                self.assertEqual(code, 3)
                self.assertEqual(out, "")
                self.assertEqual(err.strip(), "evidence_not_found")
        code, out, err = self._run_cli(
            self.db_path, "tenant-b", self.request_id
        )
        self.assertEqual(code, 3)
        self.assertEqual(out, "")
        self.assertEqual(err.strip(), "evidence_not_found")

    # -- storage failures ------------------------------------------------

    def test_corrupt_database_is_evidence_failed(self):
        with open(self.db_path, "wb") as handle:
            handle.write(b"this is not a sqlite database")
        code, out, err = self._run_cli(
            self.db_path, "tenant-a", self.request_id
        )
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertEqual(err.strip(), "evidence_failed")

    def test_directory_as_database_is_evidence_failed(self):
        code, out, err = self._run_cli(
            self._tmp.name, "tenant-a", self.request_id
        )
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertEqual(err.strip(), "evidence_failed")

    # -- output hygiene --------------------------------------------------

    def test_error_output_carries_no_details(self):
        missing = os.path.join(self._tmp.name, "absent.db")
        for argv in (
            (self.db_path, "tenant-b", self.request_id),
            (missing, "tenant-a", self.request_id),
        ):
            _code, out, err = self._run_cli(*argv)
            self.assertEqual(out, "")
            for sensitive in (
                self.db_path, missing, "tenant-a", "tenant-b",
                self.request_id, "subject-1", "email", "sqlite",
            ):
                self.assertNotIn(sensitive, err)

    def test_success_output_carries_no_sensitive_fields(self):
        code, out, _err = self._run_cli(
            self.db_path, "tenant-a", self.request_id
        )
        self.assertEqual(code, 0)
        for sensitive in ("tenant-a", "subject-1", "email", "key-1"):
            self.assertNotIn(sensitive, out)


if __name__ == "__main__":
    unittest.main()
