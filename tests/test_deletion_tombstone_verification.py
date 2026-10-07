"""Sanity checks for verify_deletion_tombstones."""

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


class VerifyTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "evidence.db")

    def tearDown(self):
        self._tmp.cleanup()

    def _store(self):
        return RequestStore(self.db_path)

    def _claimed(self, scopes=("email", "profile"), tenant="tenant-a", key="key-1"):
        store = self._store()
        receipt = store.submit(tenant, "subject-1", list(scopes), key)
        claim = store.claim_next(tenant, "worker-1", 60)
        return store, receipt, claim

    def _completed(self, scopes=("email", "profile")):
        store, receipt, claim = self._claimed(scopes=scopes)
        rid = receipt["request_id"]
        token = claim["claim_token"]
        items = [_item(scope, f"op-{scope}") for scope in scopes]
        store.record_deletion_tombstones("tenant-a", rid, token, items)
        store.finish_scoped_claim("tenant-a", rid, token, "completed")
        return store, rid, items

    def _raw(self):
        conn = sqlite3.connect(self.db_path)
        conn.isolation_level = None
        return conn

    def _verify(self, store, rid, tenant="tenant-a"):
        text = store.verify_deletion_tombstones(tenant, rid)
        self.assertTrue(text.endswith("\n"))
        self.assertNotIn("\n", text[:-1])
        return json.loads(text)

    def test_complete_and_verified(self):
        store, rid, items = self._completed()
        got = self._verify(store, rid)
        self.assertEqual(
            list(got),
            ["request_id", "verified", "coverage", "tombstone_count",
             "evidence_digest", "reasons"],
        )
        self.assertEqual(got["request_id"], rid)
        self.assertIs(got["verified"], True)
        self.assertEqual(got["coverage"], "complete")
        self.assertEqual(got["tombstone_count"], 2)
        self.assertEqual(got["evidence_digest"], _expected_digest(items))
        self.assertEqual(got["reasons"], [])

    def test_not_completed_states(self):
        # Accepted, never claimed.
        store = self._store()
        receipt = store.submit("tenant-b", "subject-1", ["email"], "key-accepted")
        got = self._verify(store, receipt["request_id"], tenant="tenant-b")
        self.assertEqual(got["verified"], False)
        self.assertEqual(got["coverage"], "not_applicable")
        self.assertEqual(got["tombstone_count"], 0)
        self.assertIsNone(got["evidence_digest"])
        self.assertEqual(got["reasons"], ["request_not_completed"])
        # Processing with partial tombstones.
        store, receipt, claim = self._claimed(key="key-processing")
        rid = receipt["request_id"]
        store.record_deletion_tombstones(
            "tenant-a", rid, claim["claim_token"], [_item("email", "op-1")]
        )
        got = self._verify(store, rid)
        self.assertEqual(got["coverage"], "not_applicable")
        self.assertEqual(got["tombstone_count"], 1)
        self.assertEqual(got["reasons"], ["request_not_completed"])
        # Failed finish.
        store.finish_scoped_claim("tenant-a", rid, claim["claim_token"], "failed")
        got = self._verify(store, rid)
        self.assertEqual(got["coverage"], "not_applicable")
        self.assertEqual(got["reasons"], ["request_not_completed"])

    def test_missing_coverage_incomplete(self):
        store, rid, _ = self._completed()
        conn = self._raw()
        try:
            conn.execute(
                "DELETE FROM deletion_tombstones WHERE operation_id = 'op-email'"
            )
        finally:
            conn.close()
        got = self._verify(store, rid)
        self.assertEqual(got["verified"], False)
        self.assertEqual(got["coverage"], "incomplete")
        self.assertEqual(got["tombstone_count"], 1)
        self.assertIsNone(got["evidence_digest"])
        self.assertEqual(got["reasons"], ["scope_coverage_invalid"])

    def test_superfluous_coverage_incomplete(self):
        store, rid, _ = self._completed()
        conn = self._raw()
        try:
            conn.execute(
                "INSERT INTO deletion_tombstones (tenant_id, request_id, scope, "
                "adapter_id, operation_id, outcome, proof_digest, recorded_at) "
                "VALUES ('tenant-a', ?, 'extra', 'adapter-9', 'op-9', 'deleted', "
                "?, '2026-01-01T00:00:00Z')",
                (rid, _digest("op-9")),
            )
        finally:
            conn.close()
        got = self._verify(store, rid)
        self.assertEqual(got["coverage"], "incomplete")
        self.assertEqual(got["tombstone_count"], 3)
        self.assertEqual(got["reasons"], ["scope_coverage_invalid"])

    def test_digest_mismatch(self):
        store, rid, _ = self._completed()
        conn = self._raw()
        try:
            conn.execute(
                "UPDATE deletion_tombstone_finishes SET evidence_digest = ? "
                "WHERE request_id = ?",
                (_digest("tampered"), rid),
            )
        finally:
            conn.close()
        got = self._verify(store, rid)
        self.assertEqual(got["verified"], False)
        self.assertEqual(got["coverage"], "complete")
        self.assertIsNotNone(got["evidence_digest"])
        self.assertEqual(got["reasons"], ["evidence_digest_mismatch"])

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
        got = self._verify(store, rid)
        self.assertEqual(got["verified"], False)
        self.assertEqual(got["coverage"], "complete")
        self.assertEqual(
            got["reasons"],
            ["evidence_digest_mismatch", "tombstone_record_invalid"],
        )

    def test_operation_id_invalid_global_duplicate(self):
        store, rid, _ = self._completed()
        other = store.submit("tenant-b", "subject-2", ["email"], "key-b")
        conn = self._raw()
        try:
            conn.execute("DROP INDEX idx_deletion_tombstones_operation")
            conn.execute(
                "INSERT INTO deletion_tombstones (tenant_id, request_id, scope, "
                "adapter_id, operation_id, outcome, proof_digest, recorded_at) "
                "VALUES ('tenant-b', ?, 'email', 'adapter-1', 'op-email', "
                "'deleted', ?, '2026-01-01T00:00:00Z')",
                (other["request_id"], _digest("op-email")),
            )
        finally:
            conn.close()
        got = self._verify(store, rid)
        self.assertEqual(got["verified"], False)
        self.assertEqual(got["coverage"], "complete")
        self.assertEqual(got["reasons"], ["operation_id_invalid"])

    def test_argument_validation(self):
        store, rid, _ = self._completed()
        with self.assertRaises(ValueError):
            store.verify_deletion_tombstones("", rid)
        with self.assertRaises(ValueError):
            store.verify_deletion_tombstones(None, rid)
        with self.assertRaises(RequestNotFound):
            store.verify_deletion_tombstones("tenant-a", "")
        with self.assertRaises(RequestNotFound):
            store.verify_deletion_tombstones("tenant-a", None)
        with self.assertRaises(RequestNotFound):
            store.verify_deletion_tombstones("tenant-a", "missing")
        with self.assertRaises(RequestNotFound):
            store.verify_deletion_tombstones("tenant-b", rid)

    def test_structural_corruption_raises_fixed_oserror(self):
        store, rid, _ = self._completed()
        conn = self._raw()
        try:
            conn.execute("DROP TABLE deletion_tombstone_finishes")
        finally:
            conn.close()
        with self.assertRaises(OSError) as caught:
            store.verify_deletion_tombstones("tenant-a", rid)
        self.assertEqual(
            str(caught.exception), "deletion_tombstone_verification_failed"
        )

    def test_corrupt_scopes_raises_fixed_oserror(self):
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

    def test_corrupt_finish_result_raises_fixed_oserror(self):
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

    def test_unreadable_database_raises_fixed_oserror(self):
        store, rid, _ = self._completed()
        os.chmod(self.db_path, 0)
        try:
            with self.assertRaises(OSError) as caught:
                store.verify_deletion_tombstones("tenant-a", rid)
            self.assertEqual(
                str(caught.exception), "deletion_tombstone_verification_failed"
            )
        finally:
            os.chmod(self.db_path, 0o600)

    def test_verify_is_read_only(self):
        store, rid, items = self._completed()
        before_tombstones = store.get_deletion_tombstones("tenant-a", rid)
        before_status = store.get_status("tenant-a", rid)
        self._verify(store, rid)
        self.assertEqual(store.get_deletion_tombstones("tenant-a", rid), before_tombstones)
        self.assertEqual(store.get_status("tenant-a", rid), before_status)

    def test_no_leak_in_output_and_errors(self):
        store, rid, _ = self._completed()
        secrets = ["subject-1", "worker-1", "key-1", "tenant-a", "email", self.db_path]
        text = store.verify_deletion_tombstones("tenant-a", rid)
        for secret in secrets:
            self.assertNotIn(secret, text)
        conn = self._raw()
        try:
            conn.execute(
                "UPDATE requests SET scopes_json = 'not-json' WHERE request_id = ?",
                (rid,),
            )
        finally:
            conn.close()
        try:
            store.verify_deletion_tombstones("tenant-a", rid)
            self.fail("expected OSError")
        except OSError as exc:
            for secret in secrets:
                self.assertNotIn(secret, str(exc))


if __name__ == "__main__":
    unittest.main()
