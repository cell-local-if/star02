"""Tests for verify_deletion_tombstones.

Covers the strictly read-only consistency check over the normalized
scopes, the tombstone ledger and the finish record: the compact JSON
report shape, the coverage ladder, every reason code, the validation
and corruption error mapping, the no-leak guarantees and the guarantee
that verification never changes the records it reads. The entry point
is deliberately not exposed over HTTP or the CLI.
"""

import hashlib
import json
import os
import sqlite3
import struct
import tempfile
import unittest

from forgetting_evidence.requests import (
    RequestNotFound,
    RequestStore,
)

_FIELDS = [
    "request_id",
    "verified",
    "coverage",
    "tombstone_count",
    "evidence_digest",
    "reasons",
]


def _digest(seed):
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


def _item(scope, operation, adapter="adapter-1", outcome="deleted", proof=None):
    return {
        "adapter_id": adapter,
        "scope": scope,
        "operation_id": operation,
        "outcome": outcome,
        "proof_digest": proof if proof is not None else _digest(operation),
    }


def _expected_digest(items):
    digest = hashlib.sha256()
    rows = sorted(
        (i["scope"], i["operation_id"], i["adapter_id"], i["outcome"], i["proof_digest"])
        for i in items
    )
    for row in rows:
        for field in row:
            encoded = field.encode("utf-8")
            digest.update(struct.pack(">Q", len(encoded)))
            digest.update(encoded)
    return digest.hexdigest()


class _StoreCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "evidence.db")

    def tearDown(self):
        self._tmp.cleanup()

    def _store(self):
        return RequestStore(self.db_path)

    def _submit(self, store, tenant="tenant-a", key="key-1", scopes=("email", "profile")):
        return store.submit(tenant, "subject-1", list(scopes), key)

    def _claimed(self, scopes=("email", "profile"), tenant="tenant-a", key="key-1"):
        store = self._store()
        receipt = self._submit(store, tenant=tenant, key=key, scopes=scopes)
        claim = store.claim_next(tenant, "worker-1", 60)
        return store, receipt, claim

    def _completed(self, scopes=("email", "profile")):
        """A request completed through the scoped finish with full coverage."""
        store, receipt, claim = self._claimed(scopes=scopes)
        rid = receipt["request_id"]
        token = claim["claim_token"]
        items = [_item(scope, f"op-{scope}") for scope in scopes]
        store.record_deletion_tombstones("tenant-a", rid, token, items)
        store.finish_scoped_claim("tenant-a", rid, token, "completed")
        return store, rid, items

    def _verify(self, store, rid, tenant="tenant-a"):
        line = store.verify_deletion_tombstones(tenant, rid)
        self.assertIsInstance(line, str)
        self.assertTrue(line.endswith("\n"))
        self.assertNotIn("\n", line[:-1])
        self.assertNotIn(", ", line)
        report = json.loads(line)
        self.assertEqual(list(report), _FIELDS)
        return report

    def _raw(self):
        conn = sqlite3.connect(self.db_path)
        conn.isolation_level = None
        return conn


class ReportShapeTest(_StoreCase):
    def test_verified_complete_roundtrip(self):
        store, rid, items = self._completed()
        report = self._verify(store, rid)
        self.assertEqual(report["request_id"], rid)
        self.assertIs(report["verified"], True)
        self.assertEqual(report["coverage"], "complete")
        self.assertEqual(report["tombstone_count"], 2)
        self.assertEqual(report["evidence_digest"], _expected_digest(items))
        self.assertEqual(report["reasons"], [])

    def test_verify_is_repeatable_and_read_only(self):
        store, rid, _ = self._completed()
        first = store.verify_deletion_tombstones("tenant-a", rid)
        second = store.verify_deletion_tombstones("tenant-a", rid)
        self.assertEqual(first, second)
        # The read changed nothing: the ledger, the finish record and
        # the status are exactly as the writes left them.
        got = store.get_deletion_tombstones("tenant-a", rid)
        self.assertEqual(len(got["tombstones"]), 2)
        self.assertEqual(store.get_status("tenant-a", rid)["status"], "completed")

    def test_verify_persists_across_rebuild(self):
        store, rid, _ = self._completed()
        first = store.verify_deletion_tombstones("tenant-a", rid)
        rebuilt = self._store()
        self.assertEqual(
            rebuilt.verify_deletion_tombstones("tenant-a", rid), first
        )

    def test_verify_in_memory_store(self):
        store = RequestStore(":memory:")
        receipt = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        claim = store.claim_next("tenant-a", "worker-1", 60)
        rid = receipt["request_id"]
        store.record_deletion_tombstones(
            "tenant-a", rid, claim["claim_token"], [_item("email", "op-1")]
        )
        store.finish_scoped_claim("tenant-a", rid, claim["claim_token"], "completed")
        report = json.loads(store.verify_deletion_tombstones("tenant-a", rid))
        self.assertIs(report["verified"], True)
        self.assertEqual(report["coverage"], "complete")


class CoverageTest(_StoreCase):
    def test_not_completed_statuses_are_not_applicable(self):
        # accepted (never claimed)
        store = self._store()
        receipt = self._submit(store)
        report = self._verify(store, receipt["request_id"])
        self.assertEqual(report["coverage"], "not_applicable")
        self.assertIs(report["verified"], False)
        self.assertEqual(report["tombstone_count"], 0)
        self.assertIsNone(report["evidence_digest"])
        self.assertEqual(report["reasons"], ["request_not_completed"])
        # processing (claimed, tombstones recorded, not finished)
        store, receipt, claim = self._claimed()
        rid = receipt["request_id"]
        store.record_deletion_tombstones(
            "tenant-a", rid, claim["claim_token"], [_item("email", "op-1")]
        )
        report = self._verify(store, rid)
        self.assertEqual(report["coverage"], "not_applicable")
        self.assertEqual(report["tombstone_count"], 1)
        self.assertIsNone(report["evidence_digest"])
        self.assertEqual(report["reasons"], ["request_not_completed"])
        # failed through the scoped finish
        store, receipt, claim = self._claimed(key="key-2")
        rid = receipt["request_id"]
        store.finish_scoped_claim("tenant-a", rid, claim["claim_token"], "failed")
        report = self._verify(store, rid)
        self.assertEqual(report["coverage"], "not_applicable")
        self.assertEqual(report["reasons"], ["request_not_completed"])
        self.assertIsNone(report["evidence_digest"])

    def test_completed_with_missing_tombstone_is_incomplete(self):
        # Completed through the plain finish, which checks no coverage.
        store, receipt, claim = self._claimed()
        rid = receipt["request_id"]
        store.record_deletion_tombstones(
            "tenant-a", rid, claim["claim_token"], [_item("email", "op-1")]
        )
        store.finish_claim("tenant-a", rid, claim["claim_token"], "completed")
        report = self._verify(store, rid)
        self.assertEqual(report["coverage"], "incomplete")
        self.assertIs(report["verified"], False)
        self.assertEqual(report["tombstone_count"], 1)
        self.assertIsNone(report["evidence_digest"])
        self.assertEqual(report["reasons"], ["scope_coverage_invalid"])

    def test_completed_with_duplicated_scope_is_incomplete(self):
        store, receipt, claim = self._claimed()
        rid = receipt["request_id"]
        token = claim["claim_token"]
        store.record_deletion_tombstones(
            "tenant-a", rid, token,
            [
                _item("email", "op-1"),
                _item("email", "op-2", adapter="adapter-2"),
            ],
        )
        store.finish_claim("tenant-a", rid, token, "completed")
        report = self._verify(store, rid)
        self.assertEqual(report["coverage"], "incomplete")
        self.assertEqual(report["tombstone_count"], 2)
        self.assertEqual(report["reasons"], ["scope_coverage_invalid"])

    def test_completed_with_superfluous_tombstone_is_incomplete(self):
        store, rid, items = self._completed()
        conn = self._raw()
        try:
            conn.execute(
                "INSERT INTO deletion_tombstones ("
                "tenant_id, request_id, scope, adapter_id, operation_id, "
                "outcome, proof_digest, recorded_at"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "tenant-a",
                    rid,
                    "unknown-scope",
                    "adapter-9",
                    "op-9",
                    "deleted",
                    _digest("op-9"),
                    "2026-01-01T00:00:00Z",
                ),
            )
        finally:
            conn.close()
        report = self._verify(store, rid)
        self.assertEqual(report["coverage"], "incomplete")
        self.assertEqual(report["tombstone_count"], 3)
        self.assertIsNone(report["evidence_digest"])
        # The foreign scope is both a coverage break and an invalid record.
        self.assertEqual(
            report["reasons"],
            ["scope_coverage_invalid", "tombstone_record_invalid"],
        )


class ReasonTest(_StoreCase):
    def test_tombstone_record_invalid(self):
        store, rid, _ = self._completed()
        conn = self._raw()
        try:
            conn.execute(
                "UPDATE deletion_tombstones SET outcome = 'purged' "
                "WHERE operation_id = 'op-email'"
            )
        finally:
            conn.close()
        report = self._verify(store, rid)
        # Coverage still holds: exactly one tombstone per scope.
        self.assertEqual(report["coverage"], "complete")
        self.assertIs(report["verified"], False)
        self.assertIsNotNone(report["evidence_digest"])
        self.assertEqual(
            report["reasons"],
            ["evidence_digest_mismatch", "tombstone_record_invalid"],
        )

    def test_tombstone_record_invalid_proof_digest(self):
        store, rid, _ = self._completed()
        conn = self._raw()
        try:
            conn.execute(
                "UPDATE deletion_tombstones SET proof_digest = ? "
                "WHERE operation_id = 'op-email'",
                ("zz" * 32,),
            )
        finally:
            conn.close()
        report = self._verify(store, rid)
        self.assertEqual(report["coverage"], "complete")
        self.assertIs(report["verified"], False)
        self.assertIn("tombstone_record_invalid", report["reasons"])

    def test_operation_id_invalid(self):
        store, rid, _ = self._completed()
        other = self._submit(store, key="key-2")
        conn = self._raw()
        try:
            # Simulate an out-of-band ledger that lost the global
            # operation-number uniqueness guard.
            conn.execute("DROP INDEX idx_deletion_tombstones_operation")
            conn.execute(
                "INSERT INTO deletion_tombstones ("
                "tenant_id, request_id, scope, adapter_id, operation_id, "
                "outcome, proof_digest, recorded_at"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "tenant-a",
                    other["request_id"],
                    "email",
                    "adapter-9",
                    "op-email",
                    "deleted",
                    _digest("op-email"),
                    "2026-01-01T00:00:00Z",
                ),
            )
        finally:
            conn.close()
        report = self._verify(store, rid)
        self.assertEqual(report["coverage"], "complete")
        self.assertIs(report["verified"], False)
        self.assertEqual(report["reasons"], ["operation_id_invalid"])
        # The digest still equals the settled commitment.
        self.assertIsNotNone(report["evidence_digest"])

    def test_evidence_digest_mismatch(self):
        store, rid, _ = self._completed()
        conn = self._raw()
        try:
            conn.execute(
                "UPDATE deletion_tombstone_finishes SET evidence_digest = ? "
                "WHERE request_id = ?",
                (_digest("altered"), rid),
            )
        finally:
            conn.close()
        report = self._verify(store, rid)
        self.assertEqual(report["coverage"], "complete")
        self.assertIs(report["verified"], False)
        self.assertEqual(report["reasons"], ["evidence_digest_mismatch"])
        # The reported digest is the recomputed one, not the ledger's.
        self.assertNotEqual(report["evidence_digest"], _digest("altered"))

    def test_completed_without_scoped_finish_record_mismatches(self):
        # Completed through the plain finish: full coverage but the
        # finish ledger holds no completed commitment to match.
        store, receipt, claim = self._claimed()
        rid = receipt["request_id"]
        token = claim["claim_token"]
        items = [_item(scope, f"op-{scope}") for scope in ("email", "profile")]
        store.record_deletion_tombstones("tenant-a", rid, token, items)
        store.finish_claim("tenant-a", rid, token, "completed")
        report = self._verify(store, rid)
        self.assertEqual(report["coverage"], "complete")
        self.assertEqual(report["evidence_digest"], _expected_digest(items))
        self.assertIs(report["verified"], False)
        self.assertEqual(report["reasons"], ["evidence_digest_mismatch"])

    def test_reasons_are_sorted_and_deduplicated(self):
        store, rid, _ = self._completed()
        conn = self._raw()
        try:
            conn.execute(
                "UPDATE deletion_tombstones SET outcome = 'purged' "
                "WHERE operation_id = 'op-email'"
            )
            conn.execute(
                "UPDATE deletion_tombstone_finishes SET evidence_digest = ? "
                "WHERE request_id = ?",
                (_digest("altered"), rid),
            )
        finally:
            conn.close()
        report = self._verify(store, rid)
        reasons = report["reasons"]
        self.assertEqual(reasons, sorted(set(reasons)))
        self.assertEqual(
            reasons, ["evidence_digest_mismatch", "tombstone_record_invalid"]
        )


class ValidationTest(_StoreCase):
    def test_invalid_tenant_raises_value_error(self):
        store, rid, _ = self._completed()
        for bad in ("", None, 1, ["tenant-a"]):
            with self.assertRaises(ValueError):
                store.verify_deletion_tombstones(bad, rid)

    def test_invalid_unknown_and_cross_tenant_ids_are_not_found(self):
        store, rid, _ = self._completed()
        for bad in ("", None, "missing", 1):
            with self.assertRaises(RequestNotFound):
                store.verify_deletion_tombstones("tenant-a", bad)
        with self.assertRaises(RequestNotFound):
            store.verify_deletion_tombstones("tenant-b", rid)


class CorruptionTest(_StoreCase):
    def test_corrupt_scopes_raise_fixed_oserror(self):
        store, rid, _ = self._completed()
        conn = self._raw()
        try:
            conn.execute(
                "UPDATE requests SET scopes_json = 'not-json' WHERE request_id = ?",
                (rid,),
            )
        finally:
            conn.close()
        with self.assertRaises(OSError) as caught:
            store.verify_deletion_tombstones("tenant-a", rid)
        self.assertEqual(
            str(caught.exception), "deletion_tombstone_verification_failed"
        )

    def test_corrupt_status_raises_fixed_oserror(self):
        store, rid, _ = self._completed()
        conn = self._raw()
        try:
            conn.execute(
                "UPDATE requests SET status = 'purged' WHERE request_id = ?",
                (rid,),
            )
        finally:
            conn.close()
        with self.assertRaises(OSError) as caught:
            store.verify_deletion_tombstones("tenant-a", rid)
        self.assertEqual(
            str(caught.exception), "deletion_tombstone_verification_failed"
        )

    def test_corrupt_finish_row_raises_fixed_oserror(self):
        store, rid, _ = self._completed()
        conn = self._raw()
        try:
            conn.execute(
                "UPDATE deletion_tombstone_finishes SET result = 'purged' "
                "WHERE request_id = ?",
                (rid,),
            )
        finally:
            conn.close()
        with self.assertRaises(OSError) as caught:
            store.verify_deletion_tombstones("tenant-a", rid)
        self.assertEqual(
            str(caught.exception), "deletion_tombstone_verification_failed"
        )

    def test_completed_finish_without_digest_raises_fixed_oserror(self):
        store, rid, _ = self._completed()
        conn = self._raw()
        try:
            conn.execute(
                "UPDATE deletion_tombstone_finishes SET evidence_digest = NULL "
                "WHERE request_id = ?",
                (rid,),
            )
        finally:
            conn.close()
        with self.assertRaises(OSError) as caught:
            store.verify_deletion_tombstones("tenant-a", rid)
        self.assertEqual(
            str(caught.exception), "deletion_tombstone_verification_failed"
        )

    def test_unreadable_store_raises_fixed_oserror(self):
        store, rid, _ = self._completed()
        conn = self._raw()
        try:
            conn.execute("DROP TABLE deletion_tombstones")
        finally:
            conn.close()
        with self.assertRaises(OSError) as caught:
            store.verify_deletion_tombstones("tenant-a", rid)
        self.assertEqual(
            str(caught.exception), "deletion_tombstone_verification_failed"
        )


class NoLeakTest(_StoreCase):
    def test_report_and_errors_carry_no_details(self):
        store, receipt, claim = self._claimed()
        rid = receipt["request_id"]
        token = claim["claim_token"]
        secrets = [
            "tenant-a",
            "subject-1",
            "worker-1",
            token,
            "email",
            "profile",
            "key-1",
            "adapter-1",
            "op-email",
            self.db_path,
        ]
        store.record_deletion_tombstones(
            "tenant-a", rid, token,
            [_item("email", "op-email"), _item("profile", "op-profile")],
        )
        store.finish_scoped_claim("tenant-a", rid, token, "completed")
        line = store.verify_deletion_tombstones("tenant-a", rid)
        for secret in secrets:
            self.assertNotIn(secret, line)
        # A failing report leaks nothing either.
        conn = sqlite3.connect(self.db_path)
        conn.isolation_level = None
        try:
            conn.execute(
                "UPDATE deletion_tombstones SET outcome = 'purged' "
                "WHERE operation_id = 'op-email'"
            )
        finally:
            conn.close()
        line = store.verify_deletion_tombstones("tenant-a", rid)
        for secret in secrets:
            self.assertNotIn(secret, line)
        # And neither does the fixed-text storage failure.
        conn = sqlite3.connect(self.db_path)
        conn.isolation_level = None
        try:
            conn.execute(
                "UPDATE requests SET scopes_json = 'not-json' WHERE request_id = ?",
                (rid,),
            )
        finally:
            conn.close()
        try:
            store.verify_deletion_tombstones("tenant-a", rid)
            self.fail("expected an exception")
        except OSError as exc:
            for secret in secrets:
                self.assertNotIn(secret, str(exc))


if __name__ == "__main__":
    unittest.main()
