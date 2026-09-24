"""Tests for execution reconciliation and the tightened claim boundary.

Covers RequestStore.reconcile_execution on the storage layer only:
accepted no-op, terminal idempotency, live-lease preservation, expiry and
no-lease compensation, multi-terminal attempt normalisation, processing
rows with no interpretable lease/attempt, validation/not-found/conflict
semantics, corruption mapping, atomic concurrent settlement, evidence
chain integrity and the no-leak guarantees. Also pins that processing
requests without an interpretable open, expired lease are never
re-claimed and are left for reconciliation. This entry point is not
exposed over HTTP.
"""

import io
import logging
import os
import sqlite3
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from forgetting_evidence import httpapi
from forgetting_evidence.requests import ClaimConflict, RequestNotFound, RequestStore


def _parse_utc(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _wait_for_expiry(seconds=1.15):
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

    def _raw(self, fn):
        with sqlite3.connect(self.db_path) as conn:
            return fn(conn)

    def _set_attempt(self, number, claimed, expires, result, completed):
        def _fn(conn):
            conn.execute(
                "UPDATE claim_attempts SET claimed_at = ?, lease_expires_at = ?, "
                "result = ?, completed_at = ? WHERE attempt_number = ?",
                (claimed, expires, result, completed, number),
            )
        self._raw(_fn)

    def _insert_attempt(self, number, claimed, expires, result, completed,
                        tenant="tenant-a", request_id=None):
        request_id = request_id if request_id is not None else self.rid

        def _fn(conn):
            conn.execute(
                "INSERT INTO claim_attempts (tenant_id, request_id, attempt_number, "
                "claimed_at, lease_expires_at, result, completed_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (tenant, request_id, number, claimed, expires, result, completed),
            )
        self._raw(_fn)

    @property
    def rid(self):
        if not hasattr(self, "_rid"):
            store = self._store()
            self._rid = self._submit(store)["request_id"]
        return self._rid


class AcceptedNoAttemptTests(_StoreCase):
    def test_reconcile_accepted_with_no_attempt_is_pure_read(self):
        store = self._store()
        receipt = self._submit(store)
        before = store.reconcile_execution("tenant-a", receipt["request_id"])
        self.assertEqual(before, receipt)
        self.assertEqual(before["status"], "accepted")
        # Nothing was created: no attempts, tokens or extra events.
        self.assertEqual(store.get_execution_log("tenant-a", receipt["request_id"]), [])
        self.assertEqual(
            [e["status"] for e in store.audit("tenant-a", receipt["request_id"])],
            ["accepted"],
        )
        with sqlite3.connect(self.db_path) as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM claim_attempts").fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT count(*) FROM claim_tokens").fetchone()[0], 0)
        # Repeat is identical.
        self.assertEqual(
            store.reconcile_execution("tenant-a", receipt["request_id"]), receipt
        )

    def test_reconcile_accepted_does_not_consume_claimability(self):
        store = self._store()
        receipt = self._submit(store)
        store.reconcile_execution("tenant-a", receipt["request_id"])
        claim = store.claim_next("tenant-a", "w", 60)
        self.assertIsNotNone(claim)
        self.assertEqual(claim["request_id"], receipt["request_id"])


class LiveLeaseTests(_StoreCase):
    def test_live_lease_is_preserved(self):
        store = self._store()
        receipt = self._submit(store)
        claim = store.claim_next("tenant-a", "w", 3600)
        rec = store.reconcile_execution("tenant-a", receipt["request_id"])
        self.assertEqual(rec["status"], "processing")
        self.assertEqual(rec["created_at"], receipt["created_at"])
        # No terminal written early, no new attempt, no new event.
        log = store.get_execution_log("tenant-a", receipt["request_id"])
        self.assertEqual(len(log), 1)
        self.assertIsNone(log[0]["result"])
        self.assertEqual(
            [e["status"] for e in store.audit("tenant-a", receipt["request_id"])],
            ["accepted", "processing"],
        )
        # The live credential is untouched: the same holder finishes later.
        done = store.finish_claim(
            "tenant-a", receipt["request_id"], claim["claim_token"], "completed"
        )
        self.assertEqual(done["status"], "completed")

    def test_live_latest_lease_protects_even_with_abandoned_prior_attempt(self):
        store = self._store()
        receipt = self._submit(store)
        store.claim_next("tenant-a", "w", 1)
        _wait_for_expiry()
        current = store.claim_next("tenant-a", "w", 3600)  # attempt 2 live
        rec = store.reconcile_execution("tenant-a", receipt["request_id"])
        self.assertEqual(rec["status"], "processing")
        log = store.get_execution_log("tenant-a", receipt["request_id"])
        # The expired first attempt is left as-is while a live lease runs.
        self.assertIsNone(log[0]["result"])
        self.assertIsNone(log[1]["result"])
        store.finish_claim(
            "tenant-a", receipt["request_id"], current["claim_token"], "completed"
        )


class ExpiredLeaseCompensationTests(_StoreCase):
    def test_expired_lease_compensates_open_attempt_to_failed(self):
        store = self._store()
        receipt = self._submit(store)
        claim = store.claim_next("tenant-a", "w", 1)
        _wait_for_expiry()
        rec = store.reconcile_execution("tenant-a", receipt["request_id"])
        self.assertEqual(rec["status"], "failed")
        self.assertEqual(
            list(rec), ["request_id", "status", "created_at"]
        )
        self.assertEqual(store.get_status("tenant-a", receipt["request_id"])["status"], "failed")
        entry = store.get_execution_log("tenant-a", receipt["request_id"])[0]
        self.assertEqual(entry["result"], "failed")
        stamp = entry["completed_at"]
        self.assertIsInstance(stamp, str)
        self.assertEqual(_parse_utc(stamp).utcoffset().total_seconds(), 0)
        # A normal chained convergence event was written.
        self.assertEqual(
            [e["status"] for e in store.audit("tenant-a", receipt["request_id"])],
            ["accepted", "processing", "failed"],
        )
        self.assertTrue(store.verify_evidence("tenant-a", receipt["request_id"]))
        # The stale credential was released.
        with self.assertRaises(ClaimConflict):
            store.finish_claim(
                "tenant-a", receipt["request_id"], claim["claim_token"], "completed"
            )

    def test_repeated_reconcile_is_idempotent(self):
        store = self._store()
        receipt = self._submit(store)
        store.claim_next("tenant-a", "w", 1)
        _wait_for_expiry()
        first = store.reconcile_execution("tenant-a", receipt["request_id"])
        stamp = store.get_execution_log("tenant-a", receipt["request_id"])[0]["completed_at"]
        time.sleep(0.01)
        second = store.reconcile_execution("tenant-a", receipt["request_id"])
        self.assertEqual(second, first)
        entry = store.get_execution_log("tenant-a", receipt["request_id"])[0]
        # Completion time is written exactly once and never re-stamped.
        self.assertEqual(entry["completed_at"], stamp)
        # No duplicate convergence event.
        self.assertEqual(len(store.audit("tenant-a", receipt["request_id"])), 3)

    def test_multiple_open_attempts_share_one_completion_time(self):
        store = self._store()
        receipt = self._submit(store)
        store.claim_next("tenant-a", "w", 1)
        _wait_for_expiry()
        store.claim_next("tenant-a", "w", 1)
        _wait_for_expiry()
        rec = store.reconcile_execution("tenant-a", receipt["request_id"])
        self.assertEqual(rec["status"], "failed")
        log = store.get_execution_log("tenant-a", receipt["request_id"])
        self.assertEqual([a["attempt_number"] for a in log], [1, 2])
        self.assertEqual([a["result"] for a in log], ["failed", "failed"])
        self.assertEqual(log[0]["completed_at"], log[1]["completed_at"])
        self.assertTrue(store.verify_evidence("tenant-a", receipt["request_id"]))
        with sqlite3.connect(self.db_path) as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM claim_tokens").fetchone()[0], 0)

    def test_open_attempt_with_no_token_is_compensated(self):
        store = self._store()
        receipt = self._submit(store)
        store.claim_next("tenant-a", "w", 1)
        _wait_for_expiry()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM claim_tokens")
        rec = store.reconcile_execution("tenant-a", receipt["request_id"])
        self.assertEqual(rec["status"], "failed")
        self.assertEqual(
            store.get_execution_log("tenant-a", receipt["request_id"])[0]["result"],
            "failed",
        )


class TerminalReconcileTests(_StoreCase):
    def test_completed_and_failed_are_idempotent(self):
        for result in ("completed", "failed"):
            with self.subTest(result=result):
                store = self._store()
                receipt = self._submit(store, key=f"k-{result}")
                claim = store.claim_next("tenant-a", "w", 60)
                store.finish_claim(
                    "tenant-a", receipt["request_id"], claim["claim_token"], result
                )
                record = store.get_status("tenant-a", receipt["request_id"])
                again = store.reconcile_execution("tenant-a", receipt["request_id"])
                self.assertEqual(again, record)
                self.assertEqual(len(store.audit("tenant-a", receipt["request_id"])), 3)

    def test_multiple_terminals_keep_earliest_completed(self):
        store = self._store()
        receipt = self._submit(store)
        claim = store.claim_next("tenant-a", "w", 60)
        store.finish_claim(
            "tenant-a", receipt["request_id"], claim["claim_token"], "completed"
        )
        # An out-of-band later terminal on a dense, later attempt.
        self._insert_attempt(
            2,
            "2027-01-01T00:00:00.000000Z",
            "2027-01-01T00:30:00.000000Z",
            "completed",
            "2027-01-01T01:00:00.000000Z",
            request_id=receipt["request_id"],
        )
        rec = store.reconcile_execution("tenant-a", receipt["request_id"])
        self.assertEqual(rec["status"], "completed")
        log = store.get_execution_log("tenant-a", receipt["request_id"])
        self.assertEqual(log[0]["result"], "completed")
        # The duplicate later terminal is recorded failed but keeps its time.
        self.assertEqual(log[1]["result"], "failed")
        self.assertEqual(log[1]["completed_at"], "2027-01-01T01:00:00.000000Z")
        # Request status/chain never moved.
        self.assertEqual(
            [e["status"] for e in store.audit("tenant-a", receipt["request_id"])],
            ["accepted", "processing", "completed"],
        )
        self.assertTrue(store.verify_evidence("tenant-a", receipt["request_id"]))
        # Idempotent afterwards.
        self.assertEqual(
            store.reconcile_execution("tenant-a", receipt["request_id"]), rec
        )

    def test_multiple_terminals_keep_earliest_failed(self):
        store = self._store()
        receipt = self._submit(store)
        claim = store.claim_next("tenant-a", "w", 60)
        store.finish_claim(
            "tenant-a", receipt["request_id"], claim["claim_token"], "failed"
        )
        self._insert_attempt(
            2,
            "2027-01-01T00:00:00.000000Z",
            "2027-01-01T00:30:00.000000Z",
            "completed",
            "2027-01-01T01:00:00.000000Z",
            request_id=receipt["request_id"],
        )
        rec = store.reconcile_execution("tenant-a", receipt["request_id"])
        self.assertEqual(rec["status"], "failed")
        log = store.get_execution_log("tenant-a", receipt["request_id"])
        self.assertEqual([a["result"] for a in log], ["failed", "failed"])

    def test_terminal_request_with_stray_open_attempt_compensates_it(self):
        store = self._store()
        receipt = self._submit(store)
        claim = store.claim_next("tenant-a", "w", 60)
        store.finish_claim(
            "tenant-a", receipt["request_id"], claim["claim_token"], "completed"
        )
        # An abandoned later lease recorded out of band, still open.
        self._insert_attempt(
            2,
            "2027-01-01T00:00:00.000000Z",
            "2027-01-01T00:30:00.000000Z",
            None,
            None,
            request_id=receipt["request_id"],
        )
        rec = store.reconcile_execution("tenant-a", receipt["request_id"])
        self.assertEqual(rec["status"], "completed")
        log = store.get_execution_log("tenant-a", receipt["request_id"])
        self.assertEqual(log[0]["result"], "completed")
        self.assertEqual(log[1]["result"], "failed")
        self.assertIsNotNone(log[1]["completed_at"])
        stamp = log[1]["completed_at"]
        # Settled once: no re-stamp, status/chain unchanged.
        self.assertEqual(
            store.reconcile_execution("tenant-a", receipt["request_id"])["status"],
            "completed",
        )
        self.assertEqual(
            store.get_execution_log("tenant-a", receipt["request_id"])[1]["completed_at"],
            stamp,
        )


class ProcessingWithoutInterpretableLeaseTests(_StoreCase):
    def test_processing_with_no_attempt_is_not_claimable_but_converges(self):
        store = self._store()
        receipt = self._submit(store)
        store.claim_next("tenant-a", "w", 60)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM claim_attempts")
            conn.execute("DELETE FROM claim_tokens")
        # No lease/attempt to interpret: never re-leased.
        self.assertIsNone(store.claim_next("tenant-a", "w", 60))
        rec = store.reconcile_execution("tenant-a", receipt["request_id"])
        self.assertEqual(rec["status"], "failed")
        self.assertEqual(store.get_execution_log("tenant-a", receipt["request_id"]), [])
        self.assertTrue(store.verify_evidence("tenant-a", receipt["request_id"]))
        self.assertEqual(
            [e["status"] for e in store.audit("tenant-a", receipt["request_id"])],
            ["accepted", "processing", "failed"],
        )

    def test_processing_with_garbled_lease_is_not_claimable_but_converges(self):
        store = self._store()
        receipt = self._submit(store)
        store.claim_next("tenant-a", "w", 60)
        self._set_attempt(1, "2026-01-01T00:00:00.000000Z", "garbled", None, None)
        self.assertIsNone(store.claim_next("tenant-a", "w", 60))
        rec = store.reconcile_execution("tenant-a", receipt["request_id"])
        self.assertEqual(rec["status"], "failed")
        self.assertEqual(
            store.get_execution_log("tenant-a", receipt["request_id"])[0]["result"],
            "failed",
        )

    def test_processing_with_finished_latest_attempt_is_not_claimable(self):
        store = self._store()
        receipt = self._submit(store)
        store.claim_next("tenant-a", "w", 60)
        # Out-of-band: the attempt is finished while status stays processing.
        self._set_attempt(
            1,
            "2026-01-01T00:00:00.000000Z",
            "2026-01-01T01:00:00.000000Z",
            "failed",
            "2026-01-01T00:30:00.000000Z",
        )
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM claim_tokens")
        self.assertIsNone(store.claim_next("tenant-a", "w", 60))
        rec = store.reconcile_execution("tenant-a", receipt["request_id"])
        self.assertEqual(rec["status"], "failed")

    def test_expired_processing_is_still_reclaimable(self):
        # The tightened boundary must keep the legitimate reclaim path:
        # an open latest attempt with an interpretable expired lease.
        store = self._store()
        receipt = self._submit(store)
        store.claim_next("tenant-a", "w", 1)
        _wait_for_expiry()
        claim = store.claim_next("tenant-a", "w", 60)
        self.assertIsNotNone(claim)
        self.assertEqual(claim["request_id"], receipt["request_id"])
        self.assertEqual(
            [a["attempt_number"] for a in
             store.get_execution_log("tenant-a", receipt["request_id"])],
            [1, 2],
        )


class ReconcileValidationTests(_StoreCase):
    def test_tenant_validation_does_not_write(self):
        store = self._store()
        receipt = self._submit(store)
        store.claim_next("tenant-a", "w", 1)
        for bad in ("", None, 7, b"t", ["t"], True):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    store.reconcile_execution(bad, receipt["request_id"])
        # Still processing with its open attempt: validation wrote nothing.
        self.assertEqual(
            store.get_status("tenant-a", receipt["request_id"])["status"],
            "processing",
        )

    def test_request_id_is_uniformly_not_found(self):
        store = self._store()
        receipt = self._submit(store)
        store.claim_next("tenant-a", "w", 60)
        for bad in ("", None, 7, b"x", ["x"], "not-a-uuid",
                    "00000000-0000-4000-8000-000000000000"):
            with self.subTest(bad=bad):
                with self.assertRaises(RequestNotFound):
                    store.reconcile_execution("tenant-a", bad)
        with self.assertRaises(RequestNotFound):
            store.reconcile_execution("tenant-b", receipt["request_id"])

    def test_accepted_direct_failed_request_without_attempts(self):
        # accepted -> failed through the status machine yields a terminal
        # request with no attempts; reconcile is an idempotent read.
        store = self._store()
        receipt = self._submit(store)
        record = store.transition("tenant-a", receipt["request_id"], "failed")
        self.assertEqual(record["status"], "failed")
        again = store.reconcile_execution("tenant-a", receipt["request_id"])
        self.assertEqual(again, record)
        self.assertEqual(store.get_execution_log("tenant-a", receipt["request_id"]), [])


class ReconcileStorageErrorTests(_StoreCase):
    def _fixed_message(self, ctx):
        self.assertEqual(str(ctx.exception), "request store is unavailable")
        self.assertNotIn("sqlite", str(ctx.exception).lower())
        self.assertNotIn(self.db_path, str(ctx.exception))

    def test_corrupt_attempt_result_is_os_error_and_writes_nothing(self):
        store = self._store()
        receipt = self._submit(store)
        store.claim_next("tenant-a", "w", 60)
        with sqlite3.connect(self.db_path) as conn:
            # Disable the result CHECK-less schema and plant a bad value.
            conn.execute(
                "UPDATE claim_attempts SET result = 'bogus', completed_at = 'x' "
                "WHERE attempt_number = 1"
            )
        with self.assertRaises(OSError) as ctx:
            store.reconcile_execution("tenant-a", receipt["request_id"])
        self._fixed_message(ctx)
        # No half result: still processing, the row untouched.
        self.assertEqual(
            store.get_status("tenant-a", receipt["request_id"])["status"], "processing"
        )

    def test_non_dense_attempt_sequence_is_os_error(self):
        store = self._store()
        receipt = self._submit(store)
        store.claim_next("tenant-a", "w", 60)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE claim_attempts SET attempt_number = 3 WHERE attempt_number = 1"
            )
        with self.assertRaises(OSError):
            store.reconcile_execution("tenant-a", receipt["request_id"])

    def test_compensation_commit_failure_rolls_back(self):
        store = self._store()
        receipt = self._submit(store)
        store.claim_next("tenant-a", "w", 1)
        _wait_for_expiry()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DROP TABLE claim_tokens")
        with self.assertRaises(OSError):
            store.reconcile_execution("tenant-a", receipt["request_id"])
        # The attempt update was rolled back with the failed token release.
        with sqlite3.connect(self.db_path) as conn:
            self.assertEqual(
                conn.execute(
                    "SELECT status FROM requests WHERE request_id = ?",
                    (receipt["request_id"],),
                ).fetchone()[0],
                "processing",
            )
            self.assertEqual(
                conn.execute(
                    "SELECT result FROM claim_attempts WHERE request_id = ?",
                    (receipt["request_id"],),
                ).fetchone()[0],
                None,
            )

    def test_dropped_table_is_os_error(self):
        store = self._store()
        receipt = self._submit(store)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DROP TABLE claim_attempts")
        with self.assertRaises(OSError) as ctx:
            store.reconcile_execution("tenant-a", receipt["request_id"])
        self._fixed_message(ctx)


class ReconcileConcurrencyTests(_StoreCase):
    def test_concurrent_reconcile_settles_once(self):
        store = self._store()
        receipt = self._submit(store)
        store.claim_next("tenant-a", "w", 1)
        _wait_for_expiry()

        def reconcile(_):
            return store.reconcile_execution("tenant-a", receipt["request_id"])

        with ThreadPoolExecutor(max_workers=16) as pool:
            results = list(pool.map(reconcile, range(32)))
        self.assertTrue(all(r["status"] == "failed" for r in results))
        # Exactly one convergence event and one settled attempt.
        self.assertEqual(
            [e["status"] for e in store.audit("tenant-a", receipt["request_id"])],
            ["accepted", "processing", "failed"],
        )
        self.assertEqual(
            store.get_execution_log("tenant-a", receipt["request_id"])[0]["result"],
            "failed",
        )
        self.assertTrue(store.verify_evidence("tenant-a", receipt["request_id"]))

    def test_concurrent_claim_and_reconcile_leave_consistent_state(self):
        store = self._store()
        receipt = self._submit(store)
        store.claim_next("tenant-a", "w", 1)
        _wait_for_expiry()

        def claim(_):
            return store.claim_next("tenant-a", "worker", 60)

        def reconcile(_):
            try:
                return store.reconcile_execution("tenant-a", receipt["request_id"])
            except OSError:
                return None

        with ThreadPoolExecutor(max_workers=16) as pool:
            claims = list(pool.map(claim, range(16)))
            reconciles = list(pool.map(reconcile, range(16)))
        winners = [c for c in claims if c is not None]
        status = store.get_status("tenant-a", receipt["request_id"])["status"]
        self.assertIn(status, ("processing", "failed"))
        with sqlite3.connect(self.db_path) as conn:
            tokens = conn.execute(
                "SELECT count(*) FROM claim_tokens WHERE request_id = ?",
                (receipt["request_id"],),
            ).fetchone()[0]
        if status == "failed":
            # Reconciliation won: no live credential, no successful reclaim.
            self.assertEqual(tokens, 0)
            self.assertEqual(winners, [])
            self.assertTrue(all(r and r["status"] == "failed" for r in reconciles))
        else:
            # A reclaim won: exactly one live lease, and every reconcile saw
            # the live lease as still in progress (or the reclaim committed
            # first); no failed convergence event exists.
            self.assertEqual(tokens, 1)
            self.assertEqual(len(winners), 1)
        self.assertTrue(store.verify_evidence("tenant-a", receipt["request_id"]))


class ReconcileNoLeakTests(_StoreCase):
    def test_logs_never_contain_tenant_worker_or_token(self):
        store = self._store()
        secret_tenant = "tenant-SECRET"
        receipt = self._submit(store, tenant=secret_tenant, key="k")
        claim = store.claim_next(secret_tenant, "worker-SECRET", 1)
        _wait_for_expiry()
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        logger = logging.getLogger("forgetting_evidence.requests")
        logger.addHandler(handler)
        old_level = logger.level
        logger.setLevel(logging.INFO)
        try:
            store.reconcile_execution(secret_tenant, receipt["request_id"])
        finally:
            logger.removeHandler(handler)
            logger.setLevel(old_level)
        emitted = stream.getvalue()
        self.assertNotIn(secret_tenant, emitted)
        self.assertNotIn("worker-SECRET", emitted)
        self.assertNotIn(claim["claim_token"], emitted)

    def test_storage_error_text_leaks_nothing(self):
        store = self._store()
        receipt = self._submit(store)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DROP TABLE claim_attempts")
        try:
            store.reconcile_execution("tenant-a", receipt["request_id"])
        except OSError as exc:
            message = str(exc)
        else:
            self.fail("expected OSError")
        self.assertEqual(message, "request store is unavailable")
        self.assertNotIn(self.db_path, message)


class DeferredReconcileTests(_StoreCase):
    def test_reconcile_is_proxied(self):
        store = httpapi.DeferredRequestStore(self.db_path)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        rec = store.reconcile_execution("tenant-a", receipt["request_id"])
        self.assertEqual(rec, receipt)

    def test_unavailable_storage_is_reported_consistently(self):
        blocker = os.path.join(self._tmp.name, "a-file")
        with open(blocker, "wb") as handle:
            handle.write(b"x")
        impossible = os.path.join(blocker, "nested", "evidence.db")
        store = httpapi.DeferredRequestStore(impossible)
        with self.assertRaises(httpapi._StorageUnavailable):
            store.reconcile_execution("tenant-a", "rid")


if __name__ == "__main__":
    unittest.main()
