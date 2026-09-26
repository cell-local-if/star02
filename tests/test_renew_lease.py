"""Tests for execution lease renewal (RequestStore.renew_lease).

Storage-layer only, never routed over HTTP: a renewal extends the current
live lease's expiry and changes nothing else -- not the request status,
the attempt sequence, the audit timeline, receipts or inspection
bookkeeping. Covers the result shape and field order, commit-time expiry
computation, consecutive and concurrent renewals, interaction with the
existing claim/finish/reconcile entries, validation and conflict
semantics, persistence across rebuilds, storage-failure mapping and the
no-leak guarantees for the claim token.
"""

import http.client
import io
import logging
import os
import sqlite3
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from forgetting_evidence import httpapi
from forgetting_evidence.httpapi import build_server
from forgetting_evidence.requests import (
    ClaimConflict,
    RequestNotFound,
    RequestStore,
)


def _parse_utc(value):
    # RFC 3339 with trailing Z.
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _utcnow():
    return datetime.now(timezone.utc)


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

    def _claim(self, store=None, tenant="tenant-a", key="key-1", lease=3600):
        store = store if store is not None else self._store()
        receipt = self._submit(store, tenant=tenant, key=key)
        claim = store.claim_next(tenant, "worker-1", lease)
        self.assertIsNotNone(claim)
        return receipt, claim


class RenewLeaseShapeTests(_StoreCase):
    def test_result_shape_order_and_types(self):
        store = self._store()
        receipt, claim = self._claim(store)
        renewed = store.renew_lease(
            "tenant-a", receipt["request_id"], claim["claim_token"], 300
        )
        self.assertEqual(list(renewed), ["request_id", "lease_expires_at"])
        self.assertEqual(set(renewed), {"request_id", "lease_expires_at"})
        self.assertEqual(renewed["request_id"], receipt["request_id"])
        self.assertIsInstance(renewed["lease_expires_at"], str)
        expires = _parse_utc(renewed["lease_expires_at"])
        self.assertEqual(expires.utcoffset().total_seconds(), 0)

    def test_expiry_is_computed_from_commit_time(self):
        store = self._store()
        receipt, claim = self._claim(store, lease=60)
        before = _utcnow()
        renewed = store.renew_lease(
            "tenant-a", receipt["request_id"], claim["claim_token"], 900
        )
        after = _utcnow()
        expires = _parse_utc(renewed["lease_expires_at"])
        # The new expiry is the commit time plus the requested seconds,
        # never the old expiry carried forward.
        old_expiry = _parse_utc(claim["lease_expires_at"])
        self.assertGreater(expires, old_expiry)
        self.assertGreaterEqual(
            (expires - before).total_seconds(), 900 - 1
        )
        self.assertLessEqual((expires - after).total_seconds(), 900 + 1)

    def test_consecutive_renewals_each_produce_a_fresh_expiry(self):
        store = self._store()
        receipt, claim = self._claim(store)
        first = store.renew_lease(
            "tenant-a", receipt["request_id"], claim["claim_token"], 600
        )
        second = store.renew_lease(
            "tenant-a", receipt["request_id"], claim["claim_token"], 600
        )
        self.assertGreater(
            _parse_utc(second["lease_expires_at"]),
            _parse_utc(first["lease_expires_at"]),
        )
        # The persisted record matches the last returned value.
        log = store.get_execution_log("tenant-a", receipt["request_id"])
        self.assertEqual(log[0]["lease_expires_at"], second["lease_expires_at"])

    def test_renewal_persists_across_rebuild(self):
        store = self._store()
        receipt, claim = self._claim(store)
        renewed = store.renew_lease(
            "tenant-a", receipt["request_id"], claim["claim_token"], 1800
        )
        rebuilt = self._store()
        log = rebuilt.get_execution_log("tenant-a", receipt["request_id"])
        self.assertEqual(log[0]["lease_expires_at"], renewed["lease_expires_at"])

    def test_renewal_changes_nothing_but_the_expiry(self):
        store = self._store()
        receipt, claim = self._claim(store)
        before_log = store.get_execution_log("tenant-a", receipt["request_id"])
        before_events = store.audit("tenant-a", receipt["request_id"])
        renewed = store.renew_lease(
            "tenant-a", receipt["request_id"], claim["claim_token"], 300
        )
        # Status, acceptance record and timeline are untouched.
        self.assertEqual(
            store.get_status("tenant-a", receipt["request_id"])["status"],
            "processing",
        )
        self.assertEqual(store.get("tenant-a", receipt["request_id"]), receipt)
        self.assertEqual(store.audit("tenant-a", receipt["request_id"]), before_events)
        # Exactly one attempt, only its expiry moved.
        after_log = store.get_execution_log("tenant-a", receipt["request_id"])
        self.assertEqual(len(after_log), 1)
        entry = after_log[0]
        self.assertEqual(entry["attempt_number"], before_log[0]["attempt_number"])
        self.assertEqual(entry["claimed_at"], before_log[0]["claimed_at"])
        self.assertIsNone(entry["result"])
        self.assertIsNone(entry["completed_at"])
        self.assertEqual(entry["lease_expires_at"], renewed["lease_expires_at"])
        self.assertTrue(store.verify_evidence("tenant-a", receipt["request_id"]))


class RenewLeaseInteractionTests(_StoreCase):
    def test_renewed_token_still_finishes(self):
        store = self._store()
        receipt, claim = self._claim(store)
        store.renew_lease("tenant-a", receipt["request_id"], claim["claim_token"], 300)
        record = store.finish_claim(
            "tenant-a", receipt["request_id"], claim["claim_token"], "completed"
        )
        self.assertEqual(record["status"], "completed")
        log = store.get_execution_log("tenant-a", receipt["request_id"])
        self.assertEqual(log[0]["result"], "completed")
        self.assertEqual(
            [event["status"] for event in store.audit("tenant-a", receipt["request_id"])],
            ["accepted", "processing", "completed"],
        )

    def test_renewed_lease_blocks_reclaim_and_reconcile(self):
        store = self._store()
        receipt, claim = self._claim(store, lease=1)
        renewed = store.renew_lease(
            "tenant-a", receipt["request_id"], claim["claim_token"], 3600
        )
        # The extended lease keeps the request out of the claim candidates.
        self.assertIsNone(store.claim_next("tenant-a", "worker-2", 60))
        # Reconcile keeps the live lease: no terminal result, no new attempt.
        record = store.reconcile_execution("tenant-a", receipt["request_id"])
        self.assertEqual(record["status"], "processing")
        log = store.get_execution_log("tenant-a", receipt["request_id"])
        self.assertEqual(len(log), 1)
        self.assertIsNone(log[0]["result"])
        self.assertEqual(log[0]["lease_expires_at"], renewed["lease_expires_at"])

    def test_expired_lease_cannot_be_renewed(self):
        store = self._store()
        receipt, claim = self._claim(store, lease=1)
        time.sleep(1.15)
        with self.assertRaises(ClaimConflict):
            store.renew_lease(
                "tenant-a", receipt["request_id"], claim["claim_token"], 60
            )
        # The failed renewal changed nothing: reconcile still converges.
        record = store.reconcile_execution("tenant-a", receipt["request_id"])
        self.assertEqual(record["status"], "failed")

    def test_late_renewal_after_compensation_does_not_resurrect(self):
        store = self._store()
        receipt, claim = self._claim(store, lease=1)
        time.sleep(1.15)
        record = store.reconcile_execution("tenant-a", receipt["request_id"])
        self.assertEqual(record["status"], "failed")
        with self.assertRaises(ClaimConflict):
            store.renew_lease(
                "tenant-a", receipt["request_id"], claim["claim_token"], 60
            )
        self.assertEqual(
            store.get_status("tenant-a", receipt["request_id"])["status"], "failed"
        )
        log = store.get_execution_log("tenant-a", receipt["request_id"])
        self.assertEqual(len(log), 1)
        self.assertEqual(log[0]["result"], "failed")

    def test_old_token_cannot_renew_after_reclaim(self):
        store = self._store()
        receipt, claim = self._claim(store, lease=1)
        time.sleep(1.15)
        second = store.claim_next("tenant-a", "worker-2", 3600)
        self.assertIsNotNone(second)
        with self.assertRaises(ClaimConflict):
            store.renew_lease(
                "tenant-a", receipt["request_id"], claim["claim_token"], 60
            )
        # The new holder can renew its own lease.
        renewed = store.renew_lease(
            "tenant-a", receipt["request_id"], second["claim_token"], 300
        )
        self.assertEqual(renewed["request_id"], receipt["request_id"])
        log = store.get_execution_log("tenant-a", receipt["request_id"])
        self.assertEqual(len(log), 2)
        self.assertEqual(log[1]["lease_expires_at"], renewed["lease_expires_at"])


class RenewLeaseValidationTests(_StoreCase):
    def _unchanged(self, store, request_id):
        self.assertEqual(
            store.get_status("tenant-a", request_id)["status"], "processing"
        )
        log = store.get_execution_log("tenant-a", request_id)
        self.assertEqual(len(log), 1)
        self.assertIsNone(log[0]["result"])

    def test_invalid_tenant_and_seconds_raise_value_error_without_writing(self):
        store = self._store()
        receipt, claim = self._claim(store)
        request_id = receipt["request_id"]
        token = claim["claim_token"]
        for bad_tenant in (None, "", 123, b"tenant-a"):
            with self.assertRaises(ValueError, msg=repr(bad_tenant)):
                store.renew_lease(bad_tenant, request_id, token, 60)
        for bad_seconds in (None, "60", 1.5, 60.0, True, False, 0, -1, 3601):
            with self.assertRaises(ValueError, msg=repr(bad_seconds)):
                store.renew_lease("tenant-a", request_id, token, bad_seconds)
        self._unchanged(store, request_id)

    def test_request_id_errors_precede_credential_checks(self):
        store = self._store()
        receipt, claim = self._claim(store)
        token = claim["claim_token"]
        # Malformed ids raise RequestNotFound during validation.
        for bad_id in (None, "", 123, b"x"):
            with self.assertRaises(RequestNotFound, msg=repr(bad_id)):
                store.renew_lease("tenant-a", bad_id, token, 60)
        # Unknown and cross-tenant ids raise RequestNotFound even when the
        # credential itself is also invalid (not-found wins the precedence).
        for bad_token in (None, "", 123, "no-such-token"):
            with self.assertRaises(RequestNotFound, msg=repr(bad_token)):
                store.renew_lease(
                    "tenant-a", "00000000-0000-0000-0000-000000000000", bad_token, 60
                )
            with self.assertRaises(RequestNotFound, msg=repr(bad_token)):
                store.renew_lease("tenant-b", receipt["request_id"], bad_token, 60)
        self._unchanged(store, receipt["request_id"])

    def test_credential_errors_are_claim_conflict_without_writing(self):
        store = self._store()
        receipt, claim = self._claim(store)
        request_id = receipt["request_id"]
        # Not a non-empty string, unknown, and cross-request tokens.
        other_receipt, other_claim = self._claim(store, key="key-2")
        for bad_token in (None, "", 123, "no-such-token", other_claim["claim_token"]):
            with self.assertRaises(ClaimConflict, msg=repr(bad_token)):
                store.renew_lease("tenant-a", request_id, bad_token, 60)
        # A released token (finished lease) cannot renew.
        store.finish_claim("tenant-a", request_id, claim["claim_token"], "completed")
        with self.assertRaises(ClaimConflict):
            store.renew_lease("tenant-a", request_id, claim["claim_token"], 60)
        log = store.get_execution_log("tenant-a", request_id)
        self.assertEqual(len(log), 1)
        self.assertEqual(log[0]["result"], "completed")

    def test_non_processing_target_conflicts(self):
        store = self._store()
        receipt, claim = self._claim(store, key="key-claimed")
        # Accepted request (never claimed): a foreign valid token conflicts.
        accepted = self._submit(store, key="key-accepted")
        with self.assertRaises(ClaimConflict):
            store.renew_lease(
                "tenant-a", accepted["request_id"], claim["claim_token"], 60
            )
        # Terminally failed request conflicts as well.
        store.finish_claim(
            "tenant-a", receipt["request_id"], claim["claim_token"], "failed"
        )
        with self.assertRaises(ClaimConflict):
            store.renew_lease(
                "tenant-a", receipt["request_id"], claim["claim_token"], 60
            )
        self.assertEqual(
            store.get_status("tenant-a", accepted["request_id"])["status"], "accepted"
        )

    def test_conflict_text_leaks_no_detail(self):
        store = self._store()
        receipt, claim = self._claim(store)
        try:
            store.renew_lease("tenant-a", receipt["request_id"], "nope", 60)
        except ClaimConflict as exc:
            message = str(exc)
        else:
            self.fail("expected ClaimConflict")
        self.assertEqual(message, "claim conflict")
        self.assertNotIn(receipt["request_id"], message)
        self.assertNotIn(claim["claim_token"], message)


class RenewLeaseConcurrencyTests(_StoreCase):
    def test_concurrent_renewals_commit_one_expiry_and_agree(self):
        # Distinct store instances share the file so the database write
        # lock (not the in-process lock) decides the race.
        stores = [self._store() for _ in range(8)]
        receipt, claim = self._claim(stores[0])
        barrier = threading.Barrier(len(stores))

        def renew(store):
            barrier.wait()
            return store.renew_lease(
                "tenant-a", receipt["request_id"], claim["claim_token"], 600
            )

        with ThreadPoolExecutor(max_workers=len(stores)) as pool:
            results = list(pool.map(renew, stores))
        # Exactly one new expiry was committed; every competitor observed it.
        expiries = {result["lease_expires_at"] for result in results}
        self.assertEqual(len(expiries), 1)
        for result in results:
            self.assertEqual(list(result), ["request_id", "lease_expires_at"])
            self.assertEqual(result["request_id"], receipt["request_id"])
        log = stores[0].get_execution_log("tenant-a", receipt["request_id"])
        self.assertEqual(len(log), 1)
        self.assertEqual(log[0]["lease_expires_at"], expiries.pop())
        # The single lease is still live and finishable by the same token.
        record = stores[0].finish_claim(
            "tenant-a", receipt["request_id"], claim["claim_token"], "completed"
        )
        self.assertEqual(record["status"], "completed")

    def test_concurrent_renew_and_finish_have_one_outcome(self):
        stores = [self._store() for _ in range(8)]
        receipt, claim = self._claim(stores[0])
        barrier = threading.Barrier(len(stores))

        def run(pair):
            index, store = pair
            barrier.wait()
            try:
                if index % 2 == 0:
                    store.renew_lease(
                        "tenant-a", receipt["request_id"], claim["claim_token"], 600
                    )
                    return "renewed"
                store.finish_claim(
                    "tenant-a", receipt["request_id"], claim["claim_token"], "completed"
                )
                return "finished"
            except ClaimConflict:
                return "conflict"

        with ThreadPoolExecutor(max_workers=len(stores)) as pool:
            outcomes = list(pool.map(run, enumerate(stores)))
        # Whatever the interleaving, the request ends in a consistent
        # state: either finished exactly once, or renewed and still live.
        self.assertLessEqual(outcomes.count("finished"), 1)
        status = stores[0].get_status("tenant-a", receipt["request_id"])["status"]
        if outcomes.count("finished") == 1:
            self.assertEqual(status, "completed")
        else:
            self.assertEqual(status, "processing")


class RenewLeaseLeakTests(_StoreCase):
    def test_token_never_returned_persisted_or_logged(self):
        store = self._store()
        receipt, claim = self._claim(store)
        token = claim["claim_token"]
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        logger = logging.getLogger("forgetting_evidence.requests")
        logger.addHandler(handler)
        old_level = logger.level
        logger.setLevel(logging.INFO)
        try:
            renewed = store.renew_lease(
                "tenant-a", receipt["request_id"], token, 300
            )
        finally:
            logger.removeHandler(handler)
            logger.setLevel(old_level)
        # Not in the return value, the logs or any later read model.
        self.assertNotIn(token, repr(renewed))
        self.assertNotIn(token, stream.getvalue())
        self.assertNotIn(
            token,
            repr(store.get_execution_log("tenant-a", receipt["request_id"])),
        )
        # Still only a hash of the credential is persisted.
        with sqlite3.connect(self.db_path) as conn:
            for table in ("requests", "status_events", "claim_attempts", "claim_tokens"):
                rows = conn.execute(f"SELECT * FROM {table}").fetchall()
                self.assertNotIn(token, repr(rows))


class RenewLeaseStorageErrorTests(_StoreCase):
    def _fixed_message(self, ctx):
        self.assertEqual(str(ctx.exception), "request store is unavailable")
        self.assertNotIn("sqlite", str(ctx.exception).lower())
        self.assertNotIn(self.db_path, str(ctx.exception))

    def test_corrupt_file_is_os_error(self):
        store = self._store()
        receipt, claim = self._claim(store)
        with open(self.db_path, "wb") as handle:
            handle.write(b"not a sqlite database")
        with self.assertRaises(OSError) as ctx:
            store.renew_lease(
                "tenant-a", receipt["request_id"], claim["claim_token"], 60
            )
        self._fixed_message(ctx)

    def test_damaged_lease_table_is_os_error_and_writes_nothing(self):
        store = self._store()
        receipt, claim = self._claim(store)
        with sqlite3.connect(self.db_path) as raw:
            raw.execute("DROP TABLE claim_attempts")
        with self.assertRaises(OSError) as ctx:
            store.renew_lease(
                "tenant-a", receipt["request_id"], claim["claim_token"], 60
            )
        self._fixed_message(ctx)
        # The request state is untouched by the failed renewal.
        with sqlite3.connect(self.db_path) as raw:
            self.assertEqual(
                raw.execute(
                    "SELECT status FROM requests WHERE request_id = ?",
                    (receipt["request_id"],),
                ).fetchone()[0],
                "processing",
            )

    def test_corrupt_lease_record_is_os_error(self):
        store = self._store()
        receipt, claim = self._claim(store)
        # Damage the lease row out of band: expiry is no longer a string
        # (a blob survives the column's TEXT affinity untouched).
        with sqlite3.connect(self.db_path) as raw:
            raw.execute(
                "UPDATE claim_attempts SET lease_expires_at = x'0132' "
                "WHERE tenant_id = 'tenant-a' AND request_id = ?",
                (receipt["request_id"],),
            )
        with self.assertRaises(OSError) as ctx:
            store.renew_lease(
                "tenant-a", receipt["request_id"], claim["claim_token"], 60
            )
        self._fixed_message(ctx)


class RenewLeaseDeferredTests(_StoreCase):
    def test_renewal_is_proxied(self):
        store = httpapi.DeferredRequestStore(self.db_path)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        claim = store.claim_next("tenant-a", "worker-1", 60)
        renewed = store.renew_lease(
            "tenant-a", receipt["request_id"], claim["claim_token"], 300
        )
        self.assertEqual(renewed["request_id"], receipt["request_id"])
        log = store.get_execution_log("tenant-a", receipt["request_id"])
        self.assertEqual(log[0]["lease_expires_at"], renewed["lease_expires_at"])

    def test_unavailable_storage_is_reported_consistently(self):
        blocker = os.path.join(self._tmp.name, "a-file")
        with open(blocker, "wb") as handle:
            handle.write(b"x")
        impossible = os.path.join(blocker, "nested", "evidence.db")
        store = httpapi.DeferredRequestStore(impossible)
        with self.assertRaises(httpapi._StorageUnavailable):
            store.renew_lease("tenant-a", "rid", "token", 60)


class RenewLeaseHttpSurfaceTests(_StoreCase):
    """Lease renewal must not gain an HTTP entry point."""

    def test_no_renewal_route_is_exposed(self):
        store = self._store()
        server = build_server(store, "127.0.0.1", 0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_address[1]
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            try:
                conn.request("POST", "/renewals", body="{}")
                resp = conn.getresponse()
                resp.read()
                self.assertEqual(resp.status, 404, resp.status)
                conn.request("POST", "/requests/renew", body="{}")
                resp = conn.getresponse()
                resp.read()
                self.assertEqual(resp.status, 405, resp.status)
            finally:
                conn.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
