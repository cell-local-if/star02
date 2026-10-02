"""Tests for the secure execution-lease handover (RequestStore.transfer_claim).

Storage-layer only, never routed over HTTP and exposed by no health
command: a handover atomically swaps the current live lease's
single-use credential for a fresh unpredictable one and moves the same
execution attempt's expiry to the handover's commit time plus the
requested seconds. It creates no attempt and changes neither status,
times, the attempt sequence, the audit timeline, anchors, receipts,
tombstones nor any query -- the execution log afterwards reflects only
the new expiry. Covers the result shape and field order, commit-time
expiry computation, credential rotation and its reuse with the existing
lease entries, validation and precedence, the concurrency guarantees
(transfer/transfer and transfer/finish), persistence across rebuilds,
storage-failure mapping and the no-leak guarantees for both tokens.
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


class TransferClaimShapeTests(_StoreCase):
    def test_result_shape_order_and_types(self):
        store = self._store()
        receipt, claim = self._claim(store)
        handed = store.transfer_claim(
            "tenant-a", receipt["request_id"], claim["claim_token"], 300
        )
        self.assertEqual(
            list(handed),
            ["request_id", "claim_token", "lease_expires_at"],
        )
        self.assertEqual(
            set(handed),
            {"request_id", "claim_token", "lease_expires_at"},
        )
        self.assertEqual(handed["request_id"], receipt["request_id"])
        self.assertIsInstance(handed["claim_token"], str)
        self.assertTrue(handed["claim_token"])
        self.assertNotEqual(handed["claim_token"], claim["claim_token"])
        self.assertIsInstance(handed["lease_expires_at"], str)
        expires = _parse_utc(handed["lease_expires_at"])
        self.assertEqual(expires.utcoffset().total_seconds(), 0)

    def test_expiry_is_commit_time_plus_seconds_not_extension(self):
        store = self._store()
        receipt, claim = self._claim(store, lease=3600)
        before = _utcnow()
        # A short handover shrinks the expiry: it is computed from the
        # commit time, never carried forward from the old lease.
        handed = store.transfer_claim(
            "tenant-a", receipt["request_id"], claim["claim_token"], 1
        )
        after = _utcnow()
        new_expiry = _parse_utc(handed["lease_expires_at"])
        old_expiry = _parse_utc(claim["lease_expires_at"])
        self.assertLess(new_expiry, old_expiry)
        self.assertGreaterEqual((new_expiry - before).total_seconds(), 0)
        self.assertLessEqual((new_expiry - after).total_seconds(), 2)
        # A second handover computes a fresh expiry from its own commit.
        before = _utcnow()
        again = store.transfer_claim(
            "tenant-a",
            receipt["request_id"],
            handed["claim_token"],
            900,
        )
        after = _utcnow()
        again_expiry = _parse_utc(again["lease_expires_at"])
        self.assertGreaterEqual((again_expiry - before).total_seconds(), 900 - 1)
        self.assertLessEqual((again_expiry - after).total_seconds(), 900 + 1)
        self.assertNotEqual(again["claim_token"], handed["claim_token"])

    def test_handover_persists_across_rebuild(self):
        store = self._store()
        receipt, claim = self._claim(store)
        handed = store.transfer_claim(
            "tenant-a", receipt["request_id"], claim["claim_token"], 1800
        )
        rebuilt = self._store()
        # The new credential survives a restart and the old one is gone.
        record = rebuilt.finish_claim(
            "tenant-a", receipt["request_id"], handed["claim_token"], "completed"
        )
        self.assertEqual(record["status"], "completed")
        log = rebuilt.get_execution_log("tenant-a", receipt["request_id"])
        self.assertEqual(log[0]["lease_expires_at"], handed["lease_expires_at"])

    def test_handover_changes_nothing_but_the_expiry_and_credential(self):
        store = self._store()
        receipt, claim = self._claim(store)
        before_log = store.get_execution_log("tenant-a", receipt["request_id"])
        before_events = store.audit("tenant-a", receipt["request_id"])
        handed = store.transfer_claim(
            "tenant-a", receipt["request_id"], claim["claim_token"], 300
        )
        # Status, acceptance record and timeline are untouched.
        self.assertEqual(
            store.get_status("tenant-a", receipt["request_id"])["status"],
            "processing",
        )
        self.assertEqual(store.get("tenant-a", receipt["request_id"]), receipt)
        self.assertEqual(store.audit("tenant-a", receipt["request_id"]), before_events)
        # Exactly one attempt: same number and claimed_at, only the expiry
        # moved, and no terminal result appeared.
        after_log = store.get_execution_log("tenant-a", receipt["request_id"])
        self.assertEqual(len(after_log), 1)
        entry = after_log[0]
        self.assertEqual(entry["attempt_number"], before_log[0]["attempt_number"])
        self.assertEqual(entry["claimed_at"], before_log[0]["claimed_at"])
        self.assertIsNone(entry["result"])
        self.assertIsNone(entry["completed_at"])
        self.assertEqual(entry["lease_expires_at"], handed["lease_expires_at"])
        self.assertTrue(store.verify_evidence("tenant-a", receipt["request_id"]))


class TransferClaimCredentialTests(_StoreCase):
    def test_new_token_works_with_renew_finish_and_another_transfer(self):
        store = self._store()
        receipt, claim = self._claim(store)
        handed = store.transfer_claim(
            "tenant-a", receipt["request_id"], claim["claim_token"], 600
        )
        # The new credential renews the same attempt.
        renewed = store.renew_lease(
            "tenant-a", receipt["request_id"], handed["claim_token"], 900
        )
        self.assertEqual(renewed["request_id"], receipt["request_id"])
        # The renewed credential hands over again.
        again = store.transfer_claim(
            "tenant-a", receipt["request_id"], handed["claim_token"], 600
        )
        # The second new credential finishes the lease.
        record = store.finish_claim(
            "tenant-a", receipt["request_id"], again["claim_token"], "completed"
        )
        self.assertEqual(record["status"], "completed")
        log = store.get_execution_log("tenant-a", receipt["request_id"])
        self.assertEqual(len(log), 1)
        self.assertEqual(log[0]["result"], "completed")
        self.assertEqual(
            [event["status"] for event in store.audit("tenant-a", receipt["request_id"])],
            ["accepted", "processing", "completed"],
        )

    def test_old_credential_is_dead_immediately_after_commit(self):
        store = self._store()
        receipt, claim = self._claim(store)
        handed = store.transfer_claim(
            "tenant-a", receipt["request_id"], claim["claim_token"], 3600
        )
        self.assertTrue(handed["claim_token"])
        for operation in ("renew", "transfer", "finish"):
            with self.assertRaises(ClaimConflict, msg=operation):
                if operation == "renew":
                    store.renew_lease(
                        "tenant-a", receipt["request_id"], claim["claim_token"], 60
                    )
                elif operation == "transfer":
                    store.transfer_claim(
                        "tenant-a", receipt["request_id"], claim["claim_token"], 60
                    )
                else:
                    store.finish_claim(
                        "tenant-a",
                        receipt["request_id"],
                        claim["claim_token"],
                        "completed",
                    )
        # The lease is still live and held solely by the new credential.
        self.assertEqual(
            store.get_status("tenant-a", receipt["request_id"])["status"],
            "processing",
        )
        self.assertIsNone(store.claim_next("tenant-a", "worker-2", 60))

    def test_handed_live_lease_blocks_reclaim_and_reconcile(self):
        store = self._store()
        receipt, claim = self._claim(store, lease=1)
        handed = store.transfer_claim(
            "tenant-a", receipt["request_id"], claim["claim_token"], 3600
        )
        self.assertIsNone(store.claim_next("tenant-a", "worker-2", 60))
        record = store.reconcile_execution("tenant-a", receipt["request_id"])
        self.assertEqual(record["status"], "processing")
        log = store.get_execution_log("tenant-a", receipt["request_id"])
        self.assertEqual(len(log), 1)
        self.assertIsNone(log[0]["result"])
        self.assertEqual(log[0]["lease_expires_at"], handed["lease_expires_at"])

    def test_expired_lease_cannot_be_handed_over(self):
        store = self._store()
        receipt, claim = self._claim(store, lease=1)
        time.sleep(1.15)
        with self.assertRaises(ClaimConflict):
            store.transfer_claim(
                "tenant-a", receipt["request_id"], claim["claim_token"], 60
            )
        # The failed handover changed nothing: reconcile converges.
        record = store.reconcile_execution("tenant-a", receipt["request_id"])
        self.assertEqual(record["status"], "failed")

    def test_late_handover_after_compensation_does_not_resurrect(self):
        store = self._store()
        receipt, claim = self._claim(store, lease=1)
        time.sleep(1.15)
        record = store.reconcile_execution("tenant-a", receipt["request_id"])
        self.assertEqual(record["status"], "failed")
        with self.assertRaises(ClaimConflict):
            store.transfer_claim(
                "tenant-a", receipt["request_id"], claim["claim_token"], 60
            )
        self.assertEqual(
            store.get_status("tenant-a", receipt["request_id"])["status"], "failed"
        )
        log = store.get_execution_log("tenant-a", receipt["request_id"])
        self.assertEqual(len(log), 1)
        self.assertEqual(log[0]["result"], "failed")

    def test_old_token_cannot_hand_over_after_reclaim(self):
        store = self._store()
        receipt, claim = self._claim(store, lease=1)
        time.sleep(1.15)
        second = store.claim_next("tenant-a", "worker-2", 3600)
        self.assertIsNotNone(second)
        with self.assertRaises(ClaimConflict):
            store.transfer_claim(
                "tenant-a", receipt["request_id"], claim["claim_token"], 60
            )
        # The new holder can hand over its own lease.
        handed = store.transfer_claim(
            "tenant-a", receipt["request_id"], second["claim_token"], 300
        )
        self.assertEqual(handed["request_id"], receipt["request_id"])
        log = store.get_execution_log("tenant-a", receipt["request_id"])
        self.assertEqual(len(log), 2)
        self.assertEqual(log[1]["lease_expires_at"], handed["lease_expires_at"])
        self.assertIsNone(log[1]["result"])


class TransferClaimValidationTests(_StoreCase):
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
                store.transfer_claim(bad_tenant, request_id, token, 60)
        for bad_seconds in (None, "60", 1.5, 60.0, True, False, 0, -1, 3601):
            with self.assertRaises(ValueError, msg=repr(bad_seconds)):
                store.transfer_claim("tenant-a", request_id, token, bad_seconds)
        self._unchanged(store, request_id)

    def test_request_id_errors_precede_credential_checks(self):
        store = self._store()
        receipt, claim = self._claim(store)
        token = claim["claim_token"]
        # Malformed ids raise RequestNotFound during validation.
        for bad_id in (None, "", 123, b"x"):
            with self.assertRaises(RequestNotFound, msg=repr(bad_id)):
                store.transfer_claim("tenant-a", bad_id, token, 60)
        # Unknown and cross-tenant ids raise RequestNotFound even when the
        # credential itself is also invalid (not-found wins precedence).
        for bad_token in (None, "", 123, "no-such-token"):
            with self.assertRaises(RequestNotFound, msg=repr(bad_token)):
                store.transfer_claim(
                    "tenant-a", "00000000-0000-0000-0000-000000000000",
                    bad_token, 60,
                )
            with self.assertRaises(RequestNotFound, msg=repr(bad_token)):
                store.transfer_claim("tenant-b", receipt["request_id"], bad_token, 60)
        self._unchanged(store, receipt["request_id"])

    def test_credential_errors_are_claim_conflict_without_writing(self):
        store = self._store()
        receipt, claim = self._claim(store)
        request_id = receipt["request_id"]
        other_receipt, other_claim = self._claim(store, key="key-2")
        for bad_token in (
            None, "", 123, "no-such-token", other_claim["claim_token"]
        ):
            with self.assertRaises(ClaimConflict, msg=repr(bad_token)):
                store.transfer_claim("tenant-a", request_id, bad_token, 60)
        # A live foreign-tenant credential used against this tenant's
        # coordinates is a conflict, while naming the foreign request id
        # itself is not-found (precedence).
        foreign_receipt, foreign_claim = self._claim(
            store, tenant="tenant-b", key="key-b"
        )
        with self.assertRaises(ClaimConflict):
            store.transfer_claim(
                "tenant-a", request_id, foreign_claim["claim_token"], 60
            )
        with self.assertRaises(RequestNotFound):
            store.transfer_claim(
                "tenant-a",
                foreign_receipt["request_id"],
                foreign_claim["claim_token"],
                60,
            )
        # A released token (finished lease) cannot hand over.
        store.finish_claim("tenant-a", request_id, claim["claim_token"], "completed")
        with self.assertRaises(ClaimConflict):
            store.transfer_claim("tenant-a", request_id, claim["claim_token"], 60)
        log = store.get_execution_log("tenant-a", request_id)
        self.assertEqual(len(log), 1)
        self.assertEqual(log[0]["result"], "completed")

    def test_non_processing_target_conflicts(self):
        store = self._store()
        receipt, claim = self._claim(store, key="key-claimed")
        # Accepted request (never claimed): a foreign valid token conflicts.
        accepted = self._submit(store, key="key-accepted")
        with self.assertRaises(ClaimConflict):
            store.transfer_claim(
                "tenant-a", accepted["request_id"], claim["claim_token"], 60
            )
        # A terminally finished request conflicts as well.
        store.finish_claim(
            "tenant-a", receipt["request_id"], claim["claim_token"], "failed"
        )
        with self.assertRaises(ClaimConflict):
            store.transfer_claim(
                "tenant-a", receipt["request_id"], claim["claim_token"], 60
            )
        self.assertEqual(
            store.get_status("tenant-a", accepted["request_id"])["status"], "accepted"
        )

    def test_conflict_text_leaks_no_detail(self):
        store = self._store()
        receipt, claim = self._claim(store)
        try:
            store.transfer_claim("tenant-a", receipt["request_id"], "nope", 60)
        except ClaimConflict as exc:
            message = str(exc)
        else:
            self.fail("expected ClaimConflict")
        self.assertEqual(message, "claim conflict")
        self.assertNotIn(receipt["request_id"], message)
        self.assertNotIn(claim["claim_token"], message)


class TransferClaimConcurrencyTests(_StoreCase):
    def test_concurrent_transfers_of_one_credential_have_one_winner(self):
        stores = [self._store() for _ in range(8)]
        receipt, claim = self._claim(stores[0])
        barrier = threading.Barrier(len(stores))

        def hand_over(store):
            barrier.wait()
            try:
                return (
                    "ok",
                    store.transfer_claim(
                        "tenant-a",
                        receipt["request_id"],
                        claim["claim_token"],
                        600,
                    ),
                )
            except ClaimConflict:
                return ("conflict", None)

        with ThreadPoolExecutor(max_workers=len(stores)) as pool:
            results = list(pool.map(hand_over, stores))
        winners = [result for outcome, result in results if outcome == "ok"]
        self.assertEqual(len(winners), 1)
        winner = winners[0]
        self.assertEqual(
            list(winner), ["request_id", "claim_token", "lease_expires_at"]
        )
        self.assertEqual(winner["request_id"], receipt["request_id"])
        # The one committed credential finishes the lease; the old one and
        # every loser-observed state is dead.
        record = stores[0].finish_claim(
            "tenant-a", receipt["request_id"], winner["claim_token"], "completed"
        )
        self.assertEqual(record["status"], "completed")
        log = stores[0].get_execution_log("tenant-a", receipt["request_id"])
        # No handover ever creates an attempt: exactly one attempt exists.
        self.assertEqual(len(log), 1)

    def test_concurrent_transfer_and_finish_have_one_outcome(self):
        stores = [self._store() for _ in range(8)]
        receipt, claim = self._claim(stores[0])
        barrier = threading.Barrier(len(stores))

        def run(pair):
            index, store = pair
            barrier.wait()
            try:
                if index % 2 == 0:
                    store.transfer_claim(
                        "tenant-a",
                        receipt["request_id"],
                        claim["claim_token"],
                        600,
                    )
                    return "transferred"
                store.finish_claim(
                    "tenant-a",
                    receipt["request_id"],
                    claim["claim_token"],
                    "completed",
                )
                return "finished"
            except ClaimConflict:
                return "conflict"

        with ThreadPoolExecutor(max_workers=len(stores)) as pool:
            outcomes = list(pool.map(run, enumerate(stores)))
        # Commit order alone decides: at most one operation overall wins.
        self.assertLessEqual(
            outcomes.count("finished") + outcomes.count("transferred"), 1
        )
        status = stores[0].get_status("tenant-a", receipt["request_id"])["status"]
        log = stores[0].get_execution_log("tenant-a", receipt["request_id"])
        self.assertEqual(len(log), 1)
        if outcomes.count("finished") == 1:
            self.assertEqual(status, "completed")
            self.assertEqual(log[0]["result"], "completed")
        else:
            self.assertEqual(status, "processing")
            self.assertIsNone(log[0]["result"])
            # A transfer winner exists exactly when the request stayed live;
            # its new credential (not the old one) can finish.
            if outcomes.count("transferred") == 1:
                with self.assertRaises(ClaimConflict):
                    stores[0].finish_claim(
                        "tenant-a",
                        receipt["request_id"],
                        claim["claim_token"],
                        "completed",
                    )


class TransferClaimLeakTests(_StoreCase):
    def test_neither_token_is_persisted_or_logged(self):
        store = self._store()
        receipt, claim = self._claim(store)
        old_token = claim["claim_token"]
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        logger = logging.getLogger("forgetting_evidence.requests")
        logger.addHandler(handler)
        old_level = logger.level
        logger.setLevel(logging.INFO)
        try:
            handed = store.transfer_claim(
                "tenant-a", receipt["request_id"], old_token, 300
            )
        finally:
            logger.removeHandler(handler)
            logger.setLevel(old_level)
        new_token = handed["claim_token"]
        # The new credential appears once, in the return value only; the
        # old one appears nowhere afterwards.
        self.assertEqual(
            repr(handed).count(new_token), 1, repr(handed)
        )
        log_text = stream.getvalue()
        self.assertNotIn(old_token, log_text)
        self.assertNotIn(new_token, log_text)
        self.assertNotIn("worker-1", log_text)
        # Neither secret reaches any later read model.
        read_models = repr(
            store.get_execution_log("tenant-a", receipt["request_id"])
        ) + repr(store.audit("tenant-a", receipt["request_id"]))
        self.assertNotIn(old_token, read_models)
        self.assertNotIn(new_token, read_models)
        with sqlite3.connect(self.db_path) as conn:
            for table in (
                "requests",
                "status_events",
                "claim_attempts",
                "claim_tokens",
            ):
                rows = conn.execute(f"SELECT * FROM {table}").fetchall()
                blob = repr(rows)
                self.assertNotIn(old_token, blob)
                self.assertNotIn(new_token, blob)
            # Exactly one credential row, on the same attempt, holding only
            # the new token's hash.
            rows = conn.execute(
                "SELECT attempt_number, token_hash FROM claim_tokens"
            ).fetchall()
            self.assertEqual(len(rows), 1)
            import hashlib

            self.assertEqual(
                rows[0][1],
                hashlib.sha256(new_token.encode("utf-8")).hexdigest(),
            )
            self.assertNotEqual(
                rows[0][1],
                hashlib.sha256(old_token.encode("utf-8")).hexdigest(),
            )
            self.assertEqual(rows[0][0], 1)


class TransferClaimStorageErrorTests(_StoreCase):
    def _assert_fixed_text(self, ctx, claim):
        self.assertEqual(str(ctx.exception), "execution_lease_transfer_failed")
        self.assertNotIn("sqlite", str(ctx.exception).lower())
        self.assertNotIn(self.db_path, str(ctx.exception))
        self.assertNotIn(claim["claim_token"], str(ctx.exception))

    def test_corrupt_file_is_fixed_text_os_error(self):
        store = self._store()
        receipt, claim = self._claim(store)
        with open(self.db_path, "wb") as handle:
            handle.write(b"not a sqlite database")
        with self.assertRaises(OSError) as ctx:
            store.transfer_claim(
                "tenant-a", receipt["request_id"], claim["claim_token"], 60
            )
        self._assert_fixed_text(ctx, claim)

    def test_damaged_lease_table_is_os_error_and_writes_nothing(self):
        store = self._store()
        receipt, claim = self._claim(store)
        with sqlite3.connect(self.db_path) as raw:
            raw.execute("DROP TABLE claim_attempts")
        with self.assertRaises(OSError) as ctx:
            store.transfer_claim(
                "tenant-a", receipt["request_id"], claim["claim_token"], 60
            )
        self._assert_fixed_text(ctx, claim)
        # The old credential row is untouched by the failed handover.
        with sqlite3.connect(self.db_path) as raw:
            self.assertEqual(
                raw.execute(
                    "SELECT status FROM requests WHERE request_id = ?",
                    (receipt["request_id"],),
                ).fetchone()[0],
                "processing",
            )
            self.assertEqual(
                raw.execute("SELECT COUNT(*) FROM claim_tokens").fetchone()[0], 1
            )

    def test_corrupt_lease_record_is_os_error(self):
        store = self._store()
        receipt, claim = self._claim(store)
        with sqlite3.connect(self.db_path) as raw:
            raw.execute(
                "UPDATE claim_attempts SET lease_expires_at = x'0132' "
                "WHERE tenant_id = 'tenant-a' AND request_id = ?",
                (receipt["request_id"],),
            )
        with self.assertRaises(OSError) as ctx:
            store.transfer_claim(
                "tenant-a", receipt["request_id"], claim["claim_token"], 60
            )
        self._assert_fixed_text(ctx, claim)

    def test_dangling_token_is_a_conflict_like_renewal(self):
        store = self._store()
        receipt, claim = self._claim(store)
        with sqlite3.connect(self.db_path) as raw:
            # Out-of-band corruption: a credential without its attempt. It
            # is resolved exactly like renew_lease resolves it -- a
            # detail-free conflict, never a usable handover.
            raw.execute(
                "DELETE FROM claim_attempts WHERE tenant_id = 'tenant-a' "
                "AND request_id = ?",
                (receipt["request_id"],),
            )
        with self.assertRaises(ClaimConflict):
            store.transfer_claim(
                "tenant-a", receipt["request_id"], claim["claim_token"], 60
            )
        with sqlite3.connect(self.db_path) as raw:
            self.assertEqual(
                raw.execute("SELECT COUNT(*) FROM claim_tokens").fetchone()[0], 1
            )


class TransferClaimDeferredTests(_StoreCase):
    def test_transfer_is_proxied(self):
        store = httpapi.DeferredRequestStore(self.db_path)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        claim = store.claim_next("tenant-a", "worker-1", 60)
        handed = store.transfer_claim(
            "tenant-a", receipt["request_id"], claim["claim_token"], 300
        )
        self.assertEqual(handed["request_id"], receipt["request_id"])
        log = store.get_execution_log("tenant-a", receipt["request_id"])
        self.assertEqual(log[0]["lease_expires_at"], handed["lease_expires_at"])
        record = store.finish_claim(
            "tenant-a",
            receipt["request_id"],
            handed["claim_token"],
            "completed",
        )
        self.assertEqual(record["status"], "completed")

    def test_unavailable_storage_is_reported_consistently(self):
        blocker = os.path.join(self._tmp.name, "a-file")
        with open(blocker, "wb") as handle:
            handle.write(b"x")
        impossible = os.path.join(blocker, "nested", "evidence.db")
        store = httpapi.DeferredRequestStore(impossible)
        with self.assertRaises(httpapi._StorageUnavailable):
            store.transfer_claim("tenant-a", "rid", "token", 60)


class TransferClaimHttpSurfaceTests(_StoreCase):
    """The lease handover must not gain an HTTP entry point."""

    def test_no_transfer_route_is_exposed(self):
        store = self._store()
        server = build_server(store, "127.0.0.1", 0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_address[1]
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            try:
                conn.request("POST", "/transfers", body="{}")
                resp = conn.getresponse()
                resp.read()
                self.assertEqual(resp.status, 404, resp.status)
                conn.request("POST", "/requests/transfer", body="{}")
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
