"""Tests for the scoped deletion-tombstone ledger.

Covers record_deletion_tombstones / finish_scoped_claim /
get_deletion_tombstones on the storage layer only: lease-gated
registration, item validation, idempotent replay, operation-number and
outcome conflicts, coverage-gated completion, first-result replay,
persistence across rebuilds, corruption handling and the no-leak
guarantees. These entry points are deliberately not exposed over HTTP.
"""

import hashlib
import os
import sqlite3
import struct
import tempfile
import unittest

from forgetting_evidence.requests import (
    ClaimConflict,
    RequestNotFound,
    RequestStore,
    TombstoneConflict,
    TombstoneUnavailable,
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

    def _claim(self, store, tenant="tenant-a", lease_seconds=60):
        claim = store.claim_next(tenant, "worker-1", lease_seconds)
        self.assertIsNotNone(claim)
        return claim

    def _claimed(self, scopes=("email", "profile"), tenant="tenant-a", key="key-1"):
        store = self._store()
        receipt = self._submit(store, tenant=tenant, key=key, scopes=scopes)
        claim = store.claim_next(tenant, "worker-1", 60)
        return store, receipt, claim


class RecordTest(_StoreCase):
    def test_record_and_get_roundtrip(self):
        store, receipt, claim = self._claimed()
        items = [
            _item("profile", "op-2", adapter="adapter-b", outcome="absent"),
            _item("email", "op-1", adapter="adapter-a"),
        ]
        record = store.record_deletion_tombstones(
            "tenant-a", receipt["request_id"], claim["claim_token"], items
        )
        self.assertEqual(
            set(record), {"request_id", "recorded_at", "evidence_digest"}
        )
        self.assertEqual(record["request_id"], receipt["request_id"])
        self.assertEqual(record["evidence_digest"], _expected_digest(items))

        got = store.get_deletion_tombstones("tenant-a", receipt["request_id"])
        self.assertEqual(
            set(got), {"request_id", "tombstones", "recorded_at", "evidence_digest"}
        )
        # Ordered by normalized scope, then adapter_id.
        self.assertEqual(
            [(t["scope"], t["adapter_id"]) for t in got["tombstones"]],
            [("email", "adapter-a"), ("profile", "adapter-b")],
        )
        self.assertEqual(got["recorded_at"], record["recorded_at"])
        self.assertEqual(got["evidence_digest"], record["evidence_digest"])
        for entry in got["tombstones"]:
            self.assertEqual(
                set(entry),
                {
                    "adapter_id",
                    "scope",
                    "operation_id",
                    "outcome",
                    "proof_digest",
                    "recorded_at",
                },
            )

    def test_get_empty_ledger(self):
        store, receipt, _ = self._claimed()
        got = store.get_deletion_tombstones("tenant-a", receipt["request_id"])
        self.assertEqual(got["tombstones"], [])
        self.assertIsNone(got["recorded_at"])
        self.assertIsNone(got["evidence_digest"])

    def test_replay_same_list_returns_first_settlement(self):
        store, receipt, claim = self._claimed()
        items = [_item("email", "op-1"), _item("profile", "op-2")]
        first = store.record_deletion_tombstones(
            "tenant-a", receipt["request_id"], claim["claim_token"], items
        )
        second = store.record_deletion_tombstones(
            "tenant-a", receipt["request_id"], claim["claim_token"], items
        )
        self.assertEqual(second, first)
        got = store.get_deletion_tombstones("tenant-a", receipt["request_id"])
        self.assertEqual(len(got["tombstones"]), 2)

    def test_incremental_registration(self):
        store, receipt, claim = self._claimed()
        store.record_deletion_tombstones(
            "tenant-a", receipt["request_id"], claim["claim_token"],
            [_item("email", "op-1")],
        )
        second = store.record_deletion_tombstones(
            "tenant-a", receipt["request_id"], claim["claim_token"],
            [_item("profile", "op-2")],
        )
        got = store.get_deletion_tombstones("tenant-a", receipt["request_id"])
        self.assertEqual(len(got["tombstones"]), 2)
        self.assertEqual(
            got["evidence_digest"],
            _expected_digest([_item("email", "op-1"), _item("profile", "op-2")]),
        )
        self.assertLessEqual(got["recorded_at"], second["recorded_at"])

    def test_record_persists_across_rebuild(self):
        store, receipt, claim = self._claimed()
        record = store.record_deletion_tombstones(
            "tenant-a", receipt["request_id"], claim["claim_token"],
            [_item("email", "op-1"), _item("profile", "op-2")],
        )
        rebuilt = self._store()
        got = rebuilt.get_deletion_tombstones("tenant-a", receipt["request_id"])
        self.assertEqual(got["evidence_digest"], record["evidence_digest"])
        self.assertEqual(got["recorded_at"], record["recorded_at"])
        self.assertEqual(len(got["tombstones"]), 2)

    def test_record_validates_arguments(self):
        store, receipt, claim = self._claimed()
        rid = receipt["request_id"]
        token = claim["claim_token"]
        good = _item("email", "op-1")
        bad_calls = [
            ("", rid, token, [good]),
            (None, rid, token, [good]),
            ("tenant-a", rid, "", [good]),
            ("tenant-a", rid, None, [good]),
            ("tenant-a", rid, token, "email"),
            ("tenant-a", rid, token, []),
            ("tenant-a", rid, token, [dict(good, outcome="purged")]),
            ("tenant-a", rid, token, [dict(good, outcome=None)]),
            ("tenant-a", rid, token, [dict(good, proof_digest="zz" * 32)]),
            ("tenant-a", rid, token, [dict(good, proof_digest="A" * 64)]),
            ("tenant-a", rid, token, [dict(good, proof_digest="abc")]),
            ("tenant-a", rid, token, [dict(good, adapter_id="")]),
            ("tenant-a", rid, token, [dict(good, scope="")]),
            ("tenant-a", rid, token, [dict(good, operation_id="")]),
            ("tenant-a", rid, token, [dict(good, extra="x")]),
            ("tenant-a", rid, token, [{k: v for k, v in good.items() if k != "scope"}]),
            ("tenant-a", rid, token, ["not-a-mapping"]),
            # Duplicate (scope, adapter) or operation number within a list.
            ("tenant-a", rid, token, [good, dict(good)]),
            ("tenant-a", rid, token, [good, _item("profile", "op-1")]),
        ]
        for tenant, request_id, token_value, items in bad_calls:
            with self.assertRaises(ValueError):
                store.record_deletion_tombstones(tenant, request_id, token_value, items)
        # Nothing was written by any rejected call.
        got = store.get_deletion_tombstones("tenant-a", rid)
        self.assertEqual(got["tombstones"], [])

    def test_record_scope_must_match_request(self):
        store, receipt, claim = self._claimed()
        with self.assertRaises(ValueError):
            store.record_deletion_tombstones(
                "tenant-a", receipt["request_id"], claim["claim_token"],
                [_item("unknown-scope", "op-1")],
            )
        got = store.get_deletion_tombstones("tenant-a", receipt["request_id"])
        self.assertEqual(got["tombstones"], [])

    def test_operation_number_conflict_same_request(self):
        store, receipt, claim = self._claimed()
        rid = receipt["request_id"]
        token = claim["claim_token"]
        store.record_deletion_tombstones(
            "tenant-a", rid, token, [_item("email", "op-1")]
        )
        # Same operation number, different content.
        with self.assertRaises(TombstoneConflict):
            store.record_deletion_tombstones(
                "tenant-a", rid, token,
                [_item("email", "op-1", proof=_digest("other"))],
            )
        with self.assertRaises(TombstoneConflict):
            store.record_deletion_tombstones(
                "tenant-a", rid, token, [_item("profile", "op-1")]
            )
        got = store.get_deletion_tombstones("tenant-a", rid)
        self.assertEqual(len(got["tombstones"]), 1)

    def test_same_scope_contradictory_outcome_conflicts(self):
        store, receipt, claim = self._claimed()
        rid = receipt["request_id"]
        token = claim["claim_token"]
        store.record_deletion_tombstones(
            "tenant-a", rid, token, [_item("email", "op-1")]
        )
        with self.assertRaises(TombstoneConflict):
            store.record_deletion_tombstones(
                "tenant-a", rid, token,
                [_item("email", "op-2", outcome="absent")],
            )
        # A second adapter on the same scope is allowed to register...
        store.record_deletion_tombstones(
            "tenant-a", rid, token,
            [_item("email", "op-3", adapter="adapter-2")],
        )
        # ...but then contradicting that adapter's outcome conflicts.
        with self.assertRaises(TombstoneConflict):
            store.record_deletion_tombstones(
                "tenant-a", rid, token,
                [_item("email", "op-4", adapter="adapter-2", outcome="absent")],
            )

    def test_operation_number_reuse_across_requests_and_tenants(self):
        store = self._store()
        first = self._submit(store, tenant="tenant-a", key="key-1")
        second = self._submit(store, tenant="tenant-a", key="key-2")
        other_tenant = self._submit(store, tenant="tenant-b", key="key-3")
        claim_a1 = store.claim_next("tenant-a", "worker-1", 60)
        store.record_deletion_tombstones(
            "tenant-a", first["request_id"], claim_a1["claim_token"],
            [_item("email", "op-1"), _item("profile", "op-2")],
        )
        claim_a2 = store.claim_next("tenant-a", "worker-1", 60)
        with self.assertRaises(TombstoneConflict):
            store.record_deletion_tombstones(
                "tenant-a", second["request_id"], claim_a2["claim_token"],
                [_item("email", "op-1")],
            )
        claim_b = store.claim_next("tenant-b", "worker-1", 60)
        with self.assertRaises(TombstoneConflict):
            store.record_deletion_tombstones(
                "tenant-b", other_tenant["request_id"], claim_b["claim_token"],
                [_item("email", "op-1")],
            )
        # The losing registrations left no ledger behind.
        got = store.get_deletion_tombstones("tenant-a", second["request_id"])
        self.assertEqual(got["tombstones"], [])

    def test_record_requires_live_lease(self):
        store, receipt, claim = self._claimed()
        rid = receipt["request_id"]
        items = [_item("email", "op-1")]
        # No claim at all for this request id shape.
        with self.assertRaises(ClaimConflict):
            store.record_deletion_tombstones("tenant-a", rid, "wrong-token", items)
        # Unknown and cross-tenant ids are indistinguishable.
        with self.assertRaises(RequestNotFound):
            store.record_deletion_tombstones("tenant-a", "missing", "wrong-token", items)
        with self.assertRaises(RequestNotFound):
            store.record_deletion_tombstones("tenant-b", rid, "wrong-token", items)
        # A live credential presented against foreign coordinates is a
        # mismatched credential, exactly like finish_claim.
        with self.assertRaises(ClaimConflict):
            store.record_deletion_tombstones("tenant-a", "missing", claim["claim_token"], items)
        with self.assertRaises(ClaimConflict):
            store.record_deletion_tombstones("tenant-b", rid, claim["claim_token"], items)
        with self.assertRaises(RequestNotFound):
            store.record_deletion_tombstones("tenant-a", "", claim["claim_token"], items)
        with self.assertRaises(RequestNotFound):
            store.record_deletion_tombstones("tenant-a", None, claim["claim_token"], items)

    def test_record_after_expiry_conflicts(self):
        import time

        store = self._store()
        receipt = self._submit(store)
        claim = store.claim_next("tenant-a", "worker-1", 1)
        time.sleep(1.15)
        with self.assertRaises(ClaimConflict):
            store.record_deletion_tombstones(
                "tenant-a", receipt["request_id"], claim["claim_token"],
                [_item("email", "op-1")],
            )

    def test_record_after_finish_conflicts(self):
        store, receipt, claim = self._claimed()
        rid = receipt["request_id"]
        token = claim["claim_token"]
        store.record_deletion_tombstones(
            "tenant-a", rid, token,
            [_item("email", "op-1"), _item("profile", "op-2")],
        )
        store.finish_scoped_claim("tenant-a", rid, token, "completed")
        with self.assertRaises(ClaimConflict):
            store.record_deletion_tombstones(
                "tenant-a", rid, token, [_item("email", "op-3", adapter="adapter-2")]
            )


class FinishTest(_StoreCase):
    def _record_all(self, store, rid, token, scopes=("email", "profile")):
        items = [_item(scope, f"op-{scope}") for scope in scopes]
        store.record_deletion_tombstones("tenant-a", rid, token, items)
        return items

    def test_finish_completed_writes_terminal_state(self):
        store, receipt, claim = self._claimed()
        rid = receipt["request_id"]
        token = claim["claim_token"]
        items = self._record_all(store, rid, token)
        result = store.finish_scoped_claim("tenant-a", rid, token, "completed")
        self.assertEqual(
            result,
            {
                "request_id": rid,
                "status": "completed",
                "created_at": receipt["created_at"],
            },
        )
        self.assertEqual(
            store.get_status("tenant-a", rid)["status"], "completed"
        )
        log = store.get_execution_log("tenant-a", rid)
        self.assertEqual(log[-1]["result"], "completed")
        self.assertIsNotNone(log[-1]["completed_at"])
        got = store.get_deletion_tombstones("tenant-a", rid)
        self.assertEqual(got["evidence_digest"], _expected_digest(items))

    def test_finish_completed_requires_full_coverage(self):
        store, receipt, claim = self._claimed()
        rid = receipt["request_id"]
        token = claim["claim_token"]
        # No tombstones at all.
        with self.assertRaises(TombstoneUnavailable):
            store.finish_scoped_claim("tenant-a", rid, token, "completed")
        # Partial coverage.
        store.record_deletion_tombstones(
            "tenant-a", rid, token, [_item("email", "op-1")]
        )
        with self.assertRaises(TombstoneUnavailable):
            store.finish_scoped_claim("tenant-a", rid, token, "completed")
        # Duplicated coverage: two adapters on one scope, none on the other.
        store.record_deletion_tombstones(
            "tenant-a", rid, token, [_item("email", "op-2", adapter="adapter-2")]
        )
        with self.assertRaises(TombstoneUnavailable):
            store.finish_scoped_claim("tenant-a", rid, token, "completed")
        # Nothing was settled by the rejected finishes.
        self.assertEqual(store.get_status("tenant-a", rid)["status"], "processing")
        log = store.get_execution_log("tenant-a", rid)
        self.assertIsNone(log[-1]["result"])

    def test_finish_failed_needs_no_coverage(self):
        store, receipt, claim = self._claimed()
        rid = receipt["request_id"]
        token = claim["claim_token"]
        result = store.finish_scoped_claim("tenant-a", rid, token, "failed")
        self.assertEqual(result["status"], "failed")
        self.assertEqual(store.get_status("tenant-a", rid)["status"], "failed")
        got = store.get_deletion_tombstones("tenant-a", rid)
        self.assertIsNone(got["evidence_digest"])

    def test_finish_repeat_uses_first_result(self):
        store, receipt, claim = self._claimed()
        rid = receipt["request_id"]
        token = claim["claim_token"]
        first = store.finish_scoped_claim("tenant-a", rid, token, "failed")
        # A repeat -- even with a different result argument -- replays
        # the first settled result.
        second = store.finish_scoped_claim("tenant-a", rid, token, "completed")
        self.assertEqual(second, first)
        self.assertEqual(store.get_status("tenant-a", rid)["status"], "failed")

    def test_finish_completed_repeat_replays(self):
        store, receipt, claim = self._claimed()
        rid = receipt["request_id"]
        token = claim["claim_token"]
        self._record_all(store, rid, token)
        first = store.finish_scoped_claim("tenant-a", rid, token, "completed")
        second = store.finish_scoped_claim("tenant-a", rid, token, "completed")
        self.assertEqual(second, first)
        log = store.get_execution_log("tenant-a", rid)
        self.assertEqual(len(log), 1)

    def test_finish_validates_arguments(self):
        store, receipt, claim = self._claimed()
        rid = receipt["request_id"]
        token = claim["claim_token"]
        for bad in ("processing", "accepted", "", None, 1):
            with self.assertRaises(ValueError):
                store.finish_scoped_claim("tenant-a", rid, token, bad)
        with self.assertRaises(ValueError):
            store.finish_scoped_claim("", rid, token, "failed")
        with self.assertRaises(ValueError):
            store.finish_scoped_claim("tenant-a", rid, "", "failed")
        with self.assertRaises(RequestNotFound):
            store.finish_scoped_claim("tenant-b", rid, "wrong-token", "failed")
        with self.assertRaises(RequestNotFound):
            store.finish_scoped_claim("tenant-a", "missing", "wrong-token", "failed")
        with self.assertRaises(ClaimConflict):
            store.finish_scoped_claim("tenant-b", rid, token, "failed")
        with self.assertRaises(ClaimConflict):
            store.finish_scoped_claim("tenant-a", "missing", token, "failed")
        with self.assertRaises(ClaimConflict):
            store.finish_scoped_claim("tenant-a", rid, "wrong-token", "failed")

    def test_finish_after_expiry_conflicts(self):
        import time

        store = self._store()
        receipt = self._submit(store)
        claim = store.claim_next("tenant-a", "worker-1", 1)
        time.sleep(1.15)
        with self.assertRaises(ClaimConflict):
            store.finish_scoped_claim(
                "tenant-a", receipt["request_id"], claim["claim_token"], "failed"
            )

    def test_finish_without_claim_conflicts(self):
        store = self._store()
        receipt = self._submit(store)
        with self.assertRaises(ClaimConflict):
            store.finish_scoped_claim(
                "tenant-a", receipt["request_id"], "any-token", "failed"
            )

    def test_plain_finish_then_scoped_finish_conflicts(self):
        store, receipt, claim = self._claimed()
        rid = receipt["request_id"]
        store.finish_claim("tenant-a", rid, claim["claim_token"], "failed")
        with self.assertRaises(ClaimConflict):
            store.finish_scoped_claim(
                "tenant-a", rid, claim["claim_token"], "failed"
            )

    def test_scoped_finish_then_plain_finish_conflicts(self):
        store, receipt, claim = self._claimed()
        rid = receipt["request_id"]
        token = claim["claim_token"]
        store.finish_scoped_claim("tenant-a", rid, token, "failed")
        with self.assertRaises(ClaimConflict):
            store.finish_claim("tenant-a", rid, token, "completed")

    def test_scoped_finish_cannot_be_renewed_or_reclaimed(self):
        store, receipt, claim = self._claimed()
        rid = receipt["request_id"]
        token = claim["claim_token"]
        store.finish_scoped_claim("tenant-a", rid, token, "failed")
        with self.assertRaises(ClaimConflict):
            store.renew_lease("tenant-a", rid, token, 60)
        # The terminal request is never a claim candidate.
        self.assertIsNone(store.claim_next("tenant-a", "worker-2", 60))
        # Reconcile leaves the settled terminal record untouched.
        reconciled = store.reconcile_execution("tenant-a", rid)
        self.assertEqual(reconciled["status"], "failed")
        log = store.get_execution_log("tenant-a", rid)
        self.assertEqual(len(log), 1)
        self.assertEqual(log[0]["result"], "failed")


class GetTest(_StoreCase):
    def test_get_unknown_and_cross_tenant(self):
        store, receipt, _ = self._claimed()
        with self.assertRaises(RequestNotFound):
            store.get_deletion_tombstones("tenant-a", "missing")
        with self.assertRaises(RequestNotFound):
            store.get_deletion_tombstones("tenant-b", receipt["request_id"])
        with self.assertRaises(RequestNotFound):
            store.get_deletion_tombstones("tenant-a", "")
        with self.assertRaises(ValueError):
            store.get_deletion_tombstones("", receipt["request_id"])
        with self.assertRaises(ValueError):
            store.get_deletion_tombstones(None, receipt["request_id"])

    def test_get_is_partitioned_per_tenant(self):
        store = self._store()
        one = self._submit(store, tenant="tenant-a", key="key-1")
        two = self._submit(store, tenant="tenant-b", key="key-2")
        claim_a = store.claim_next("tenant-a", "worker-1", 60)
        store.record_deletion_tombstones(
            "tenant-a", one["request_id"], claim_a["claim_token"],
            [_item("email", "op-1"), _item("profile", "op-2")],
        )
        got = store.get_deletion_tombstones("tenant-b", two["request_id"])
        self.assertEqual(got["tombstones"], [])


class CorruptionTest(_StoreCase):
    def _raw(self):
        conn = sqlite3.connect(self.db_path)
        conn.isolation_level = None
        return conn

    def test_corrupt_tombstone_row_raises_fixed_oserror(self):
        store, receipt, claim = self._claimed()
        rid = receipt["request_id"]
        store.record_deletion_tombstones(
            "tenant-a", rid, claim["claim_token"], [_item("email", "op-1")]
        )
        conn = self._raw()
        try:
            conn.execute(
                "UPDATE deletion_tombstones SET outcome = 'purged' "
                "WHERE operation_id = 'op-1'"
            )
        finally:
            conn.close()
        for call in (
            lambda: store.get_deletion_tombstones("tenant-a", rid),
            lambda: store.finish_scoped_claim(
                "tenant-a", rid, claim["claim_token"], "completed"
            ),
        ):
            with self.assertRaises(OSError) as caught:
                call()
            self.assertEqual(str(caught.exception), "deletion_tombstone_failed")

    def test_corrupt_finish_row_raises_fixed_oserror(self):
        store, receipt, claim = self._claimed()
        rid = receipt["request_id"]
        token = claim["claim_token"]
        store.finish_scoped_claim("tenant-a", rid, token, "failed")
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
            store.finish_scoped_claim("tenant-a", rid, token, "failed")
        self.assertEqual(str(caught.exception), "deletion_tombstone_failed")

    def test_interrupted_commit_leaves_no_partial_ledger(self):
        store, receipt, claim = self._claimed()
        rid = receipt["request_id"]
        token = claim["claim_token"]
        store.record_deletion_tombstones(
            "tenant-a", rid, token, [_item("email", "op-1")]
        )
        # A conflicting second call must leave the first ledger intact.
        with self.assertRaises(TombstoneConflict):
            store.record_deletion_tombstones(
                "tenant-a", rid, token,
                [_item("profile", "op-2"), _item("email", "op-1", proof=_digest("x"))],
            )
        got = store.get_deletion_tombstones("tenant-a", rid)
        self.assertEqual(len(got["tombstones"]), 1)
        self.assertEqual(got["tombstones"][0]["operation_id"], "op-1")


class NoLeakTest(_StoreCase):
    def test_error_messages_carry_no_details(self):
        store, receipt, claim = self._claimed()
        rid = receipt["request_id"]
        token = claim["claim_token"]
        secrets = ["tenant-a", "subject-1", "worker-1", token, "email", "key-1"]
        raisers = []
        store.record_deletion_tombstones(
            "tenant-a", rid, token, [_item("email", "op-1")]
        )

        def conflict():
            store.record_deletion_tombstones(
                "tenant-a", rid, token, [_item("email", "op-1", proof=_digest("z"))]
            )

        def unavailable():
            store.finish_scoped_claim("tenant-a", rid, token, "completed")

        def claim_conflict():
            store.record_deletion_tombstones(
                "tenant-a", rid, "wrong-token", [_item("profile", "op-9")]
            )

        for raiser in (conflict, unavailable, claim_conflict):
            try:
                raiser()
                self.fail("expected an exception")
            except (TombstoneConflict, TombstoneUnavailable, ClaimConflict) as exc:
                message = str(exc)
                for secret in secrets:
                    self.assertNotIn(secret, message)


if __name__ == "__main__":
    unittest.main()
