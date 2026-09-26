"""Tests for storage-layer lease renewal.

Covers RequestStore.renew_lease only: expiry extension and its fixed
two-field result, persistence across rebuilds, untouched status /
attempt / audit / receipt / inspection state, sequential and concurrent
renewal semantics, interaction with claim_next / finish_claim /
reconcile_execution, the ValueError / RequestNotFound / ClaimConflict /
OSError error contract and the no-leak guarantees. The capability is
deliberately not exposed over HTTP.
"""

import logging
import os
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from forgetting_evidence.requests import (
    ClaimConflict,
    RequestNotFound,
    RequestStore,
)


def _parse_utc(value):
    # RFC 3339 with trailing Z.
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _wait_for_expiry(seconds=1.15):
    import time

    time.sleep(seconds)


class _StoreCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "evidence.db")

    def tearDown(self):
        self._tmp.cleanup()

    def _store(self):
        return RequestStore(self.db_path)

    def _submit(self, store=None, tenant="tenant-a", key="key-1", subject="subject-1"):
        store = store if store is not None else RequestStore(self.db_path)
        return store.submit(tenant, subject, ["email"], key)

    def _claimed(self, store=None, tenant="tenant-a", lease=3600):
        store = store if store is not None else self._store()
        receipt = self._submit(store, tenant=tenant)
        claim = store.claim_next(tenant, "worker-1", lease)
        self.assertIsNotNone(claim)
        self.assertEqual(claim["request_id"], receipt["request_id"])
        return store, receipt, claim


class RenewLeaseTests(_StoreCase):
    def test_renew_shape_and_extends_expiry(self):
        store, receipt, claim = self._claimed(lease=60)
        renewed = store.renew_lease(
            "tenant-a", receipt["request_id"], claim["claim_token"], 3600
        )
        self.assertEqual(list(renewed), ["request_id", "lease_expires_at"])
        self.assertEqual(set(renewed), {"request_id", "lease_expires_at"})
        self.assertEqual(renewed["request_id"], receipt["request_id"])
        expires = _parse_utc(renewed["lease_expires_at"])
        self.assertEqual(expires.utcoffset().total_seconds(), 0)
        self.assertGreater(renewed["lease_expires_at"], claim["lease_expires_at"])
        # Strings only: no float, negative zero or non-finite value.
        self.assertTrue(all(isinstance(v, str) for v in renewed.values()))

    def test_renew_persists_across_rebuild(self):
        store, receipt, claim = self._claimed(lease=60)
        renewed = store.renew_lease(
            "tenant-a", receipt["request_id"], claim["claim_token"], 3600
        )
        rebuilt = self._store()
        log = rebuilt.get_execution_log("tenant-a", receipt["request_id"])
        self.assertEqual(len(log), 1)
        self.assertEqual(log[0]["lease_expires_at"], renewed["lease_expires_at"])
        self.assertIsNone(log[0]["result"])
        self.assertIsNone(log[0]["completed_at"])

    def test_renew_leaves_status_attempts_and_audit_untouched(self):
        store, receipt, claim = self._claimed(lease=60)
        before_events = store.audit("tenant-a", receipt["request_id"])
        store.renew_lease("tenant-a", receipt["request_id"], claim["claim_token"], 3600)
        self.assertEqual(
            store.get_status("tenant-a", receipt["request_id"])["status"],
            "processing",
        )
        log = store.get_execution_log("tenant-a", receipt["request_id"])
        self.assertEqual([a["attempt_number"] for a in log], [1])
        after_events = store.audit("tenant-a", receipt["request_id"])
        self.assertEqual(
            [e["status"] for e in after_events], ["accepted", "processing"]
        )
        self.assertEqual(after_events, before_events)
        self.assertTrue(store.verify_evidence("tenant-a", receipt["request_id"]))

    def test_sequential_renewals_produce_fresh_expiries(self):
        store, receipt, claim = self._claimed(lease=60)
        first = store.renew_lease(
            "tenant-a", receipt["request_id"], claim["claim_token"], 600
        )
        second = store.renew_lease(
            "tenant-a", receipt["request_id"], claim["claim_token"], 600
        )
        self.assertGreater(second["lease_expires_at"], first["lease_expires_at"])
        log = self._store().get_execution_log("tenant-a", receipt["request_id"])
        self.assertEqual(log[0]["lease_expires_at"], second["lease_expires_at"])

    def test_renew_never_shortens_the_lease(self):
        store, receipt, claim = self._claimed(lease=3600)
        renewed = store.renew_lease(
            "tenant-a", receipt["request_id"], claim["claim_token"], 1
        )
        self.assertEqual(renewed["lease_expires_at"], claim["lease_expires_at"])

    def test_concurrent_renewals_commit_one_expiry(self):
        store, receipt, claim = self._claimed(lease=60)
        token = claim["claim_token"]
        request_id = receipt["request_id"]
        barrier = threading.Barrier(32)

        def renew(_index):
            barrier.wait()
            return store.renew_lease("tenant-a", request_id, token, 3600)

        with ThreadPoolExecutor(max_workers=32) as pool:
            results = list(pool.map(renew, range(32)))
        # Every competing caller observes the same single committed expiry.
        self.assertEqual(len({r["lease_expires_at"] for r in results}), 1)
        log = self._store().get_execution_log("tenant-a", request_id)
        self.assertEqual(len(log), 1)
        self.assertEqual(log[0]["lease_expires_at"], results[0]["lease_expires_at"])

    def test_claim_next_does_not_dispatch_before_new_expiry(self):
        store, receipt, claim = self._claimed(lease=1)
        store.renew_lease("tenant-a", receipt["request_id"], claim["claim_token"], 3600)
        _wait_for_expiry()
        # The original one-second lease has lapsed, but the renewed lease
        # still holds: no second attempt is dispatched.
        self.assertIsNone(store.claim_next("tenant-a", "worker-2", 60))
        log = store.get_execution_log("tenant-a", receipt["request_id"])
        self.assertEqual([a["attempt_number"] for a in log], [1])

    def test_finish_works_with_the_renewed_lease(self):
        store, receipt, claim = self._claimed(lease=1)
        renewed = store.renew_lease(
            "tenant-a", receipt["request_id"], claim["claim_token"], 3600
        )
        _wait_for_expiry()
        # Past the original expiry the renewed token still finishes.
        record = store.finish_claim(
            "tenant-a", receipt["request_id"], claim["claim_token"], "completed"
        )
        self.assertEqual(record["status"], "completed")
        self.assertEqual(
            store.get_status("tenant-a", receipt["request_id"])["status"],
            "completed",
        )
        events = store.audit("tenant-a", receipt["request_id"])
        self.assertEqual(
            [e["status"] for e in events], ["accepted", "processing", "completed"]
        )
        self.assertTrue(store.verify_evidence("tenant-a", receipt["request_id"]))
        log = store.get_execution_log("tenant-a", receipt["request_id"])
        self.assertEqual(log[0]["lease_expires_at"], renewed["lease_expires_at"])
        self.assertEqual(log[0]["result"], "completed")

    def test_reconcile_keeps_processing_while_renewed_lease_live(self):
        store, receipt, claim = self._claimed(lease=1)
        store.renew_lease("tenant-a", receipt["request_id"], claim["claim_token"], 3600)
        _wait_for_expiry()
        record = store.reconcile_execution("tenant-a", receipt["request_id"])
        self.assertEqual(record["status"], "processing")
        log = store.get_execution_log("tenant-a", receipt["request_id"])
        self.assertEqual(len(log), 1)
        self.assertIsNone(log[0]["result"])
        # The live token is not released by the reconciliation.
        record = store.finish_claim(
            "tenant-a", receipt["request_id"], claim["claim_token"], "completed"
        )
        self.assertEqual(record["status"], "completed")

    def test_expired_unrenewed_lease_reconciles_and_late_renew_conflicts(self):
        store, receipt, claim = self._claimed(lease=1)
        _wait_for_expiry()
        record = store.reconcile_execution("tenant-a", receipt["request_id"])
        self.assertEqual(record["status"], "failed")
        # A late renewal must not resurrect the compensated attempt.
        with self.assertRaises(ClaimConflict):
            store.renew_lease(
                "tenant-a", receipt["request_id"], claim["claim_token"], 60
            )
        self.assertEqual(
            store.get_status("tenant-a", receipt["request_id"])["status"], "failed"
        )

    def test_renew_after_expiry_without_reconcile_conflicts(self):
        store, receipt, claim = self._claimed(lease=1)
        _wait_for_expiry()
        with self.assertRaises(ClaimConflict):
            store.renew_lease(
                "tenant-a", receipt["request_id"], claim["claim_token"], 60
            )
        # Nothing changed: the dead lease is still there for reconcile.
        self.assertEqual(
            store.get_status("tenant-a", receipt["request_id"])["status"],
            "processing",
        )
        record = store.reconcile_execution("tenant-a", receipt["request_id"])
        self.assertEqual(record["status"], "failed")


class RenewValidationTests(_StoreCase):
    def test_invalid_tenant_raises_valueerror_without_writing(self):
        store, receipt, claim = self._claimed()
        for bad in ("", None, 123, b"tenant-a"):
            with self.assertRaises(ValueError):
                store.renew_lease(bad, receipt["request_id"], claim["claim_token"], 60)
        self.assertEqual(
            store.get_execution_log("tenant-a", receipt["request_id"])[0][
                "lease_expires_at"
            ],
            claim["lease_expires_at"],
        )

    def test_invalid_lease_seconds_raises_valueerror_without_writing(self):
        store, receipt, claim = self._claimed()
        for bad in (None, "60", True, False, 60.0, 0, -1, 3601):
            with self.assertRaises(ValueError):
                store.renew_lease(
                    "tenant-a", receipt["request_id"], claim["claim_token"], bad
                )
        self.assertEqual(
            store.get_execution_log("tenant-a", receipt["request_id"])[0][
                "lease_expires_at"
            ],
            claim["lease_expires_at"],
        )

    def test_unknown_and_cross_tenant_ids_raise_not_found(self):
        store, receipt, claim = self._claimed()
        with self.assertRaises(RequestNotFound):
            store.renew_lease("tenant-a", "no-such-request", claim["claim_token"], 60)
        with self.assertRaises(RequestNotFound):
            store.renew_lease(
                "tenant-b", receipt["request_id"], claim["claim_token"], 60
            )
        for bad in ("", None, 123):
            with self.assertRaises(RequestNotFound):
                store.renew_lease("tenant-a", bad, claim["claim_token"], 60)

    def test_request_id_checked_before_credential(self):
        store, receipt, claim = self._claimed()
        # An unknown id wins over an equally invalid credential.
        with self.assertRaises(RequestNotFound):
            store.renew_lease("tenant-a", "no-such-request", None, 60)
        with self.assertRaises(RequestNotFound):
            store.renew_lease("tenant-a", "no-such-request", "no-such-token", 60)

    def test_bad_credential_shape_raises_claim_conflict(self):
        store, receipt, claim = self._claimed()
        for bad in (None, "", 123, b"token"):
            with self.assertRaises(ClaimConflict):
                store.renew_lease("tenant-a", receipt["request_id"], bad, 60)

    def test_unknown_released_and_foreign_tokens_conflict(self):
        store, receipt, claim = self._claimed()
        # Unknown token.
        with self.assertRaises(ClaimConflict):
            store.renew_lease("tenant-a", receipt["request_id"], "no-such-token", 60)
        # Foreign token: a second request's credential names another lease.
        other = self._submit(store, key="key-2", subject="subject-2")
        other_claim = store.claim_next("tenant-a", "worker-2", 60)
        self.assertEqual(other_claim["request_id"], other["request_id"])
        with self.assertRaises(ClaimConflict):
            store.renew_lease(
                "tenant-a", receipt["request_id"], other_claim["claim_token"], 60
            )
        # Released token: finishing releases the credential for good.
        store.finish_claim(
            "tenant-a", receipt["request_id"], claim["claim_token"], "completed"
        )
        with self.assertRaises(ClaimConflict):
            store.renew_lease(
                "tenant-a", receipt["request_id"], claim["claim_token"], 60
            )

    def test_non_processing_target_conflicts_without_change(self):
        store = self._store()
        receipt = self._submit(store)
        # accepted: no lease exists to renew.
        with self.assertRaises(ClaimConflict):
            store.renew_lease("tenant-a", receipt["request_id"], "any-token", 60)
        self.assertEqual(
            store.get_status("tenant-a", receipt["request_id"])["status"], "accepted"
        )

    def test_failed_renewal_writes_nothing(self):
        store, receipt, claim = self._claimed()
        with self.assertRaises(ClaimConflict):
            store.renew_lease("tenant-a", receipt["request_id"], "bad-token", 60)
        log = store.get_execution_log("tenant-a", receipt["request_id"])
        self.assertEqual(log[0]["lease_expires_at"], claim["lease_expires_at"])
        self.assertEqual(
            [e["status"] for e in store.audit("tenant-a", receipt["request_id"])],
            ["accepted", "processing"],
        )


class RenewNoLeakTests(_StoreCase):
    def test_token_never_in_result_exception_or_log(self):
        store, receipt, claim = self._claimed()
        token = claim["claim_token"]
        logger = logging.getLogger("forgetting_evidence.requests")
        with self.assertLogs(logger, level="INFO") as captured:
            renewed = store.renew_lease(
                "tenant-a", receipt["request_id"], token, 3600
            )
        self.assertNotIn(token, repr(renewed))
        self.assertNotIn(token, "\n".join(captured.output))
        try:
            store.renew_lease("tenant-a", receipt["request_id"], token + "x", 60)
        except ClaimConflict as exc:
            self.assertNotIn(token, str(exc))
            self.assertEqual(str(exc), "claim conflict")
        else:
            self.fail("expected ClaimConflict")

    def test_token_never_persisted_in_plaintext(self):
        store, receipt, claim = self._claimed()
        token = claim["claim_token"]
        store.renew_lease("tenant-a", receipt["request_id"], token, 3600)
        with sqlite3.connect(self.db_path) as conn:
            for table in ("claim_tokens", "claim_attempts", "requests"):
                rows = conn.execute(f"SELECT * FROM {table}").fetchall()
                for row in rows:
                    self.assertNotIn(token, repr(row))


class RenewStorageFailureTests(_StoreCase):
    def test_corrupt_lease_record_raises_fixed_oserror(self):
        store, receipt, claim = self._claimed()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE claim_attempts SET lease_expires_at = '' "
                "WHERE tenant_id = 'tenant-a' AND request_id = ?",
                (receipt["request_id"],),
            )
        with self.assertRaises(OSError) as ctx:
            store.renew_lease(
                "tenant-a", receipt["request_id"], claim["claim_token"], 60
            )
        self.assertEqual(str(ctx.exception), "request store is unavailable")
        self.assertNotIn(claim["claim_token"], str(ctx.exception))

    def test_unwritable_store_raises_fixed_oserror(self):
        store, receipt, claim = self._claimed(lease=60)
        os.chmod(self.db_path, 0o444)
        try:
            with self.assertRaises(OSError) as ctx:
                store.renew_lease(
                    "tenant-a", receipt["request_id"], claim["claim_token"], 3600
                )
            self.assertEqual(str(ctx.exception), "request store is unavailable")
        finally:
            os.chmod(self.db_path, 0o644)


if __name__ == "__main__":
    unittest.main()
