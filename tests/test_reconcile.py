"""Tests for execution-result reconciliation and the claim boundary.

Covers reconcile_execution on the storage layer only: read-only
behaviour for accepted/live-lease/terminal requests, expiry-driven
compensation of abandoned attempts, earliest-terminal-wins convergence
for execution records carrying several terminal rows, idempotency of
repeat reconciliation, validation/not-found/corruption semantics,
atomicity and persistence, plus the tightened claim_next boundary that
refuses processing requests without an explainable expired lease. These
entry points are deliberately not exposed over HTTP.
"""

import os
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from forgetting_evidence import httpapi
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


class ReconcileAcceptedTests(_StoreCase):
    def test_accepted_without_attempts_returns_current_state_and_writes_nothing(self):
        store = self._store()
        receipt = self._submit(store)
        before = store.get_status("tenant-a", receipt["request_id"])
        record = store.reconcile_execution("tenant-a", receipt["request_id"])
        self.assertEqual(
            list(record), ["request_id", "status", "created_at"]
        )
        self.assertEqual(record, before)
        self.assertEqual(record["status"], "accepted")
        # No attempt, no receipt, no event and no token was created.
        self.assertEqual(
            store.get_execution_log("tenant-a", receipt["request_id"]), []
        )
        self.assertEqual(
            [e["status"] for e in store.audit("tenant-a", receipt["request_id"])],
            ["accepted"],
        )
        self.assertEqual(store.get("tenant-a", receipt["request_id"]), receipt)
        with sqlite3.connect(self.db_path) as raw:
            self.assertEqual(
                raw.execute("SELECT count(*) FROM claim_attempts").fetchone()[0], 0
            )
            self.assertEqual(
                raw.execute("SELECT count(*) FROM claim_tokens").fetchone()[0], 0
            )

    def test_repeated_reconcile_on_accepted_is_identically_read_only(self):
        store = self._store()
        receipt = self._submit(store)
        for _ in range(3):
            record = store.reconcile_execution("tenant-a", receipt["request_id"])
            self.assertEqual(record["status"], "accepted")
            self.assertEqual(record["created_at"], receipt["created_at"])
        self.assertEqual(
            [e["status"] for e in store.audit("tenant-a", receipt["request_id"])],
            ["accepted"],
        )


class ReconcileLiveLeaseTests(_StoreCase):
    def test_live_lease_keeps_in_progress_attempt(self):
        store = self._store()
        receipt = self._submit(store)
        claim = store.claim_next("tenant-a", "worker-1", 3600)
        record = store.reconcile_execution("tenant-a", receipt["request_id"])
        self.assertEqual(record["status"], "processing")
        self.assertEqual(record["created_at"], receipt["created_at"])
        # No terminal written early, no new attempt generated.
        log = store.get_execution_log("tenant-a", receipt["request_id"])
        self.assertEqual(len(log), 1)
        self.assertIsNone(log[0]["result"])
        self.assertIsNone(log[0]["completed_at"])
        self.assertEqual(
            [e["status"] for e in store.audit("tenant-a", receipt["request_id"])],
            ["accepted", "processing"],
        )
        # The live credential still works after a no-op reconcile.
        done = store.finish_claim(
            "tenant-a", receipt["request_id"], claim["claim_token"], "completed"
        )
        self.assertEqual(done["status"], "completed")

    def test_live_lease_survives_repeated_reconcile(self):
        store = self._store()
        receipt = self._submit(store)
        claim = store.claim_next("tenant-a", "worker-1", 3600)
        for _ in range(3):
            self.assertEqual(
                store.reconcile_execution(
                    "tenant-a", receipt["request_id"]
                )["status"],
                "processing",
            )
        self.assertEqual(
            len(store.get_execution_log("tenant-a", receipt["request_id"])), 1
        )
        self.assertTrue(store.verify_evidence("tenant-a", receipt["request_id"]))
        # Credential not released by reconcile.
        self.assertEqual(
            store.finish_claim(
                "tenant-a", receipt["request_id"], claim["claim_token"], "failed"
            )["status"],
            "failed",
        )


class ReconcileCompensationTests(_StoreCase):
    def test_expired_open_attempt_is_compensated_to_failed_atomically(self):
        store = self._store()
        receipt = self._submit(store)
        claim = store.claim_next("tenant-a", "worker-1", 1)
        _wait_for_expiry()
        record = store.reconcile_execution("tenant-a", receipt["request_id"])
        self.assertEqual(record["request_id"], receipt["request_id"])
        self.assertEqual(record["status"], "failed")
        self.assertEqual(record["created_at"], receipt["created_at"])
        # The abandoned attempt is compensated exactly once.
        entry = store.get_execution_log("tenant-a", receipt["request_id"])[0]
        self.assertEqual(entry["result"], "failed")
        completed_at = entry["completed_at"]
        self.assertIsInstance(completed_at, str)
        self.assertEqual(
            _parse_utc(completed_at).utcoffset().total_seconds(), 0
        )
        # The compensation event shares the completion instant.
        timeline = store.audit("tenant-a", receipt["request_id"])
        self.assertEqual(
            [e["status"] for e in timeline],
            ["accepted", "processing", "failed"],
        )
        self.assertEqual(timeline[-1]["occurred_at"], completed_at)
        # The dead credential was released with the compensation.
        with self.assertRaises(ClaimConflict):
            store.finish_claim(
                "tenant-a", receipt["request_id"], claim["claim_token"], "completed"
            )
        self.assertTrue(store.verify_evidence("tenant-a", receipt["request_id"]))
        with sqlite3.connect(self.db_path) as raw:
            self.assertEqual(
                raw.execute("SELECT count(*) FROM claim_tokens").fetchone()[0], 0
            )

    def test_compensation_completion_time_is_written_once(self):
        store = self._store()
        receipt = self._submit(store)
        store.claim_next("tenant-a", "worker-1", 1)
        _wait_for_expiry()
        first = store.reconcile_execution("tenant-a", receipt["request_id"])
        stamped = store.get_execution_log(
            "tenant-a", receipt["request_id"]
        )[0]["completed_at"]
        # A second reconcile is now a terminal no-op and must never
        # restamp the attempt.
        second = store.reconcile_execution("tenant-a", receipt["request_id"])
        self.assertEqual(second, first)
        self.assertEqual(
            store.get_execution_log("tenant-a", receipt["request_id"])[0][
                "completed_at"
            ],
            stamped,
        )
        self.assertEqual(
            [e["status"] for e in store.audit("tenant-a", receipt["request_id"])],
            ["accepted", "processing", "failed"],
        )

    def test_all_abandoned_attempts_are_compensated_together(self):
        store = self._store()
        receipt = self._submit(store)
        store.claim_next("tenant-a", "worker-1", 1)
        _wait_for_expiry()
        store.claim_next("tenant-a", "worker-2", 1)
        _wait_for_expiry()
        record = store.reconcile_execution("tenant-a", receipt["request_id"])
        self.assertEqual(record["status"], "failed")
        log = store.get_execution_log("tenant-a", receipt["request_id"])
        self.assertEqual([a["attempt_number"] for a in log], [1, 2])
        self.assertEqual([a["result"] for a in log], ["failed", "failed"])
        stamps = {a["completed_at"] for a in log}
        self.assertEqual(len(stamps), 1)
        self.assertEqual(
            [e["status"] for e in store.audit("tenant-a", receipt["request_id"])],
            ["accepted", "processing", "failed"],
        )

    def test_open_attempt_without_any_live_credential_is_compensated(self):
        store = self._store()
        receipt = self._submit(store)
        claim = store.claim_next("tenant-a", "worker-1", 1)
        _wait_for_expiry()
        # Remove the credential out of band: an open attempt with a result
        # of NULL and no lease row must still converge.
        with sqlite3.connect(self.db_path) as raw:
            raw.execute("DELETE FROM claim_tokens")
        # The stale token can no longer finish anything.
        with self.assertRaises(ClaimConflict):
            store.finish_claim(
                "tenant-a", receipt["request_id"], claim["claim_token"], "completed"
            )
        record = store.reconcile_execution("tenant-a", receipt["request_id"])
        self.assertEqual(record["status"], "failed")
        self.assertEqual(
            store.get_execution_log("tenant-a", receipt["request_id"])[0][
                "result"
            ],
            "failed",
        )


class ReconcileTerminalIdempotencyTests(_StoreCase):
    def test_terminal_reconcile_is_idempotent_for_completed_and_failed(self):
        for result in ("completed", "failed"):
            store = self._store()
            receipt = self._submit(store, key=f"key-{result}")
            claim = store.claim_next("tenant-a", "w", 60)
            first = store.finish_claim(
                "tenant-a", receipt["request_id"], claim["claim_token"], result
            )
            timeline_before = store.audit("tenant-a", receipt["request_id"])
            log_before = store.get_execution_log(
                "tenant-a", receipt["request_id"]
            )
            for _ in range(2):
                again = store.reconcile_execution(
                    "tenant-a", receipt["request_id"]
                )
                self.assertEqual(again, first)
                self.assertEqual(
                    store.audit("tenant-a", receipt["request_id"]),
                    timeline_before,
                )
                self.assertEqual(
                    store.get_execution_log("tenant-a", receipt["request_id"]),
                    log_before,
                )

    def test_multiple_terminals_on_processing_keep_earliest_completion(self):
        store = self._store()
        receipt = self._submit(store)
        store.claim_next("tenant-a", "w", 1)
        _wait_for_expiry()
        store.claim_next("tenant-a", "w", 1)
        _wait_for_expiry()
        # Two terminal attempts while the request is still processing:
        # the later *attempt* carries the earlier completion time, so the
        # earliest completion -- not the lowest sequence -- must win.
        with sqlite3.connect(self.db_path) as raw:
            raw.execute(
                "UPDATE claim_attempts SET result = 'completed', "
                "completed_at = ? WHERE attempt_number = 1",
                ("2026-02-01T00:00:00.000000Z",),
            )
            raw.execute(
                "UPDATE claim_attempts SET result = 'completed', "
                "completed_at = ? WHERE attempt_number = 2",
                ("2026-01-01T00:00:00.000000Z",),
            )
        record = store.reconcile_execution("tenant-a", receipt["request_id"])
        self.assertEqual(record["status"], "completed")
        log = store.get_execution_log("tenant-a", receipt["request_id"])
        # Attempt 2 owns the earliest completion and keeps it; attempt 1
        # is a later duplicate terminal and is recorded as failed without
        # losing its original completion time.
        self.assertEqual(log[0]["result"], "failed")
        self.assertEqual(
            log[0]["completed_at"], "2026-02-01T00:00:00.000000Z"
        )
        self.assertEqual(log[1]["result"], "completed")
        self.assertEqual(
            log[1]["completed_at"], "2026-01-01T00:00:00.000000Z"
        )
        self.assertEqual(
            [e["status"] for e in store.audit("tenant-a", receipt["request_id"])],
            ["accepted", "processing", "completed"],
        )
        # Repeating reconcile changes neither status nor attempts.
        again = store.reconcile_execution("tenant-a", receipt["request_id"])
        self.assertEqual(again["status"], "completed")
        self.assertEqual(
            [a["result"] for a in store.get_execution_log(
                "tenant-a", receipt["request_id"]
            )],
            ["failed", "completed"],
        )

    def test_earliest_failed_sets_failed_and_downgrades_later_completed(self):
        store = self._store()
        receipt = self._submit(store)
        store.claim_next("tenant-a", "w", 1)
        _wait_for_expiry()
        store.claim_next("tenant-a", "w", 1)
        _wait_for_expiry()
        with sqlite3.connect(self.db_path) as raw:
            raw.execute(
                "UPDATE claim_attempts SET result = 'failed', "
                "completed_at = ? WHERE attempt_number = 1",
                ("2026-01-01T00:00:00.000000Z",),
            )
            raw.execute(
                "UPDATE claim_attempts SET result = 'completed', "
                "completed_at = ? WHERE attempt_number = 2",
                ("2026-02-01T00:00:00.000000Z",),
            )
        record = store.reconcile_execution("tenant-a", receipt["request_id"])
        self.assertEqual(record["status"], "failed")
        log = store.get_execution_log("tenant-a", receipt["request_id"])
        self.assertEqual([a["result"] for a in log], ["failed", "failed"])

    def test_terminal_request_with_duplicate_completed_is_repaired_not_moved(self):
        store = self._store()
        receipt = self._submit(store)
        claim = store.claim_next("tenant-a", "w", 1)
        store.finish_claim(
            "tenant-a", receipt["request_id"], claim["claim_token"], "completed"
        )
        _wait_for_expiry()
        # A successor attempt existed and was marked completed out of band
        # while the request itself stays completed. Its completion is later
        # than the genuine first finish, so it is the duplicate terminal.
        with sqlite3.connect(self.db_path) as raw:
            raw.execute(
                "INSERT INTO claim_attempts ("
                "tenant_id, request_id, attempt_number, claimed_at, "
                "lease_expires_at, result, completed_at"
                ") VALUES (?, ?, 2, ?, ?, 'completed', ?)",
                (
                    "tenant-a",
                    receipt["request_id"],
                    "2027-01-01T00:00:00.000000Z",
                    "2027-01-01T00:00:01.000000Z",
                    "2027-01-02T00:00:00.000000Z",
                ),
            )
        record = store.reconcile_execution("tenant-a", receipt["request_id"])
        self.assertEqual(record["status"], "completed")
        log = store.get_execution_log("tenant-a", receipt["request_id"])
        self.assertEqual([a["result"] for a in log], ["completed", "failed"])
        # The request row and timeline were never altered by the repair.
        self.assertEqual(
            [e["status"] for e in store.audit("tenant-a", receipt["request_id"])],
            ["accepted", "processing", "completed"],
        )
        self.assertTrue(store.verify_evidence("tenant-a", receipt["request_id"]))

    def test_open_attempt_compensated_alongside_earliest_terminal(self):
        store = self._store()
        receipt = self._submit(store)
        store.claim_next("tenant-a", "w", 1)
        _wait_for_expiry()
        store.claim_next("tenant-a", "w", 1)
        _wait_for_expiry()
        with sqlite3.connect(self.db_path) as raw:
            raw.execute(
                "UPDATE claim_attempts SET result = 'completed', "
                "completed_at = ? WHERE attempt_number = 1",
                ("2026-01-01T00:00:00.000000Z",),
            )
        # Attempt 2 is open; it is compensated failed while the request
        # converges on the earliest existing completion.
        record = store.reconcile_execution("tenant-a", receipt["request_id"])
        self.assertEqual(record["status"], "completed")
        log = store.get_execution_log("tenant-a", receipt["request_id"])
        self.assertEqual([a["result"] for a in log], ["completed", "failed"])
        self.assertIsNotNone(log[1]["completed_at"])


class ClaimBoundaryTests(_StoreCase):
    def test_processing_without_attempts_is_not_claimed(self):
        store = self._store()
        receipt = self._submit(store)
        # Enter processing through the status machine alone: no lease and
        # no attempt explain this processing row.
        store.transition("tenant-a", receipt["request_id"], "processing")
        for worker in ("worker-1", "worker-2"):
            self.assertIsNone(store.claim_next("tenant-a", worker, 3600))
        # The rejected claims created nothing.
        self.assertEqual(
            store.get_execution_log("tenant-a", receipt["request_id"]), []
        )
        with sqlite3.connect(self.db_path) as raw:
            self.assertEqual(
                raw.execute("SELECT count(*) FROM claim_tokens").fetchone()[0], 0
            )
        # Reconciliation is what converges such a record.
        record = store.reconcile_execution("tenant-a", receipt["request_id"])
        self.assertEqual(record["status"], "failed")
        # And a failed request is still not claimable afterwards.
        self.assertIsNone(store.claim_next("tenant-a", "worker-1", 3600))

    def test_unexplainable_processing_does_not_block_other_candidates(self):
        store = self._store()
        stuck = self._submit(store, key="k1")
        store.transition("tenant-a", stuck["request_id"], "processing")
        ready = self._submit(store, key="k2")
        claim = store.claim_next("tenant-a", "w", 60)
        self.assertIsNotNone(claim)
        self.assertEqual(claim["request_id"], ready["request_id"])

    def test_processing_with_expired_attempt_still_reclaims_with_new_attempt(self):
        store = self._store()
        receipt = self._submit(store)
        first = store.claim_next("tenant-a", "worker-1", 1)
        _wait_for_expiry()
        second = store.claim_next("tenant-a", "worker-2", 60)
        self.assertIsNotNone(second)
        self.assertEqual(second["request_id"], receipt["request_id"])
        self.assertNotEqual(first["claim_token"], second["claim_token"])
        self.assertEqual(
            [
                a["attempt_number"]
                for a in store.get_execution_log("tenant-a", receipt["request_id"])
            ],
            [1, 2],
        )

    def test_processing_whose_latest_attempt_is_finished_is_not_claimed(self):
        store = self._store()
        receipt = self._submit(store)
        store.claim_next("tenant-a", "w", 1)
        _wait_for_expiry()
        # Mark the only attempt terminal out of band while the request row
        # stays processing: the status/result pair has no explainable open
        # lease, so it must not be claimed.
        with sqlite3.connect(self.db_path) as raw:
            raw.execute(
                "UPDATE claim_attempts SET result = 'failed', "
                "completed_at = ?",
                ("2026-01-01T00:00:00.000000Z",),
            )
        self.assertIsNone(store.claim_next("tenant-a", "w", 3600))
        self.assertEqual(
            len(store.get_execution_log("tenant-a", receipt["request_id"])), 1
        )
        # Reconcile converges the inconsistent status onto the terminal.
        record = store.reconcile_execution("tenant-a", receipt["request_id"])
        self.assertEqual(record["status"], "failed")
        self.assertIsNone(store.claim_next("tenant-a", "w", 3600))

    def test_concurrent_claims_never_take_unexplainable_processing(self):
        store = self._store()
        receipt = self._submit(store)
        store.transition("tenant-a", receipt["request_id"], "processing")

        def claim(index):
            return store.claim_next("tenant-a", f"worker-{index}", 3600)

        with ThreadPoolExecutor(max_workers=16) as pool:
            results = list(pool.map(claim, range(32)))
        self.assertTrue(all(result is None for result in results))
        with sqlite3.connect(self.db_path) as raw:
            self.assertEqual(
                raw.execute("SELECT count(*) FROM claim_attempts").fetchone()[0], 0
            )
            self.assertEqual(
                raw.execute("SELECT count(*) FROM claim_tokens").fetchone()[0], 0
            )
            self.assertEqual(
                raw.execute("SELECT status FROM requests").fetchone()[0],
                "processing",
            )


class ReconcileValidationTests(_StoreCase):
    def test_bad_tenant_is_value_error_without_writes(self):
        store = self._store()
        receipt = self._submit(store)
        store.claim_next("tenant-a", "w", 1)
        _wait_for_expiry()
        for bad in ("", None, 7, b"t", ["t"], True):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    store.reconcile_execution(bad, receipt["request_id"])
        # The expired processing request was left exactly as it was.
        self.assertEqual(
            store.get_status("tenant-a", receipt["request_id"])["status"],
            "processing",
        )
        entry = store.get_execution_log("tenant-a", receipt["request_id"])[0]
        self.assertIsNone(entry["result"])
        self.assertIsNone(entry["completed_at"])
        self.assertEqual(
            [e["status"] for e in store.audit("tenant-a", receipt["request_id"])],
            ["accepted", "processing"],
        )

    def test_bad_unknown_and_cross_tenant_request_ids_are_not_found(self):
        store = self._store()
        receipt = self._submit(store)
        for bad in ("", None, 7, b"x", ["x"], "not-a-uuid"):
            with self.subTest(bad=bad):
                with self.assertRaises(RequestNotFound):
                    store.reconcile_execution("tenant-a", bad)
        with self.assertRaises(RequestNotFound):
            store.reconcile_execution("tenant-a", "does-not-exist")
        with self.assertRaises(RequestNotFound):
            store.reconcile_execution("tenant-b", receipt["request_id"])


class ReconcileCorruptionTests(_StoreCase):
    def _fixed_message(self, ctx):
        self.assertEqual(str(ctx.exception), "request store is unavailable")
        self.assertNotIn("sqlite", str(ctx.exception).lower())
        self.assertNotIn(self.db_path, str(ctx.exception))

    def _expired_processing(self):
        store = self._store()
        receipt = self._submit(store)
        store.claim_next("tenant-a", "w", 1)
        _wait_for_expiry()
        return store, receipt

    def test_unknown_result_text_is_os_error_and_converges_nothing(self):
        store, receipt = self._expired_processing()
        with sqlite3.connect(self.db_path) as raw:
            raw.execute(
                "UPDATE claim_attempts SET result = 'bogus'",
            )
        with self.assertRaises(OSError) as ctx:
            store.reconcile_execution("tenant-a", receipt["request_id"])
        self._fixed_message(ctx)
        self.assertEqual(
            store.get_status("tenant-a", receipt["request_id"])["status"],
            "processing",
        )

    def test_split_result_and_completion_is_os_error(self):
        store, receipt = self._expired_processing()
        with sqlite3.connect(self.db_path) as raw:
            raw.execute(
                "UPDATE claim_attempts SET result = 'completed'",
            )
        with self.assertRaises(OSError):
            store.reconcile_execution("tenant-a", receipt["request_id"])
        self.assertEqual(
            store.get_status("tenant-a", receipt["request_id"])["status"],
            "processing",
        )

    def test_gapped_attempt_sequence_is_os_error(self):
        store, receipt = self._expired_processing()
        with sqlite3.connect(self.db_path) as raw:
            raw.execute(
                "UPDATE claim_attempts SET attempt_number = 2",
            )
        with self.assertRaises(OSError):
            store.reconcile_execution("tenant-a", receipt["request_id"])

    def test_missing_attempt_table_is_os_error(self):
        store, receipt = self._expired_processing()
        with sqlite3.connect(self.db_path) as raw:
            raw.execute("DROP TABLE claim_attempts")
        with self.assertRaises(OSError) as ctx:
            store.reconcile_execution("tenant-a", receipt["request_id"])
        self._fixed_message(ctx)

    def test_corrupt_file_is_os_error(self):
        store, receipt = self._expired_processing()
        with open(self.db_path, "wb") as handle:
            handle.write(b"not a sqlite database")
        with self.assertRaises(OSError) as ctx:
            store.reconcile_execution("tenant-a", receipt["request_id"])
        self._fixed_message(ctx)


class ReconcilePersistenceTests(_StoreCase):
    def test_compensation_survives_rebuild(self):
        first = self._store()
        receipt = first.submit("tenant-a", "subject-1", ["email"], "key-1")
        first.claim_next("tenant-a", "worker-1", 1)
        _wait_for_expiry()
        rebuilt = self._store()
        record = rebuilt.reconcile_execution("tenant-a", receipt["request_id"])
        self.assertEqual(record["status"], "failed")
        again = self._store().reconcile_execution(
            "tenant-a", receipt["request_id"]
        )
        self.assertEqual(again, record)
        self.assertTrue(rebuilt.verify_evidence("tenant-a", receipt["request_id"]))
        entry = rebuilt.get_execution_log("tenant-a", receipt["request_id"])[0]
        self.assertEqual(entry["result"], "failed")


class ReconcileConcurrencyTests(_StoreCase):
    def test_concurrent_reconcile_converges_exactly_once(self):
        store = self._store()
        receipt = self._submit(store)
        store.claim_next("tenant-a", "w", 1)
        _wait_for_expiry()

        def reconcile(_index):
            return store.reconcile_execution("tenant-a", receipt["request_id"])

        with ThreadPoolExecutor(max_workers=16) as pool:
            records = list(pool.map(reconcile, range(32)))
        self.assertTrue(all(r["status"] == "failed" for r in records))
        self.assertEqual(
            [e["status"] for e in store.audit("tenant-a", receipt["request_id"])],
            ["accepted", "processing", "failed"],
        )
        entry = store.get_execution_log("tenant-a", receipt["request_id"])[0]
        self.assertEqual(entry["result"], "failed")
        self.assertTrue(store.verify_evidence("tenant-a", receipt["request_id"]))

    def test_reconcile_and_finish_race_to_one_committed_outcome(self):
        store = self._store()
        receipt = self._submit(store)
        claim = store.claim_next("tenant-a", "w", 1)
        _wait_for_expiry()

        outcomes = []

        def reconcile():
            try:
                outcomes.append(
                    store.reconcile_execution("tenant-a", receipt["request_id"])
                )
            except Exception:  # pragma: no cover - never expected
                outcomes.append(None)

        def finish():
            try:
                outcomes.append(
                    store.finish_claim(
                        "tenant-a",
                        receipt["request_id"],
                        claim["claim_token"],
                        "completed",
                    )
                )
            except ClaimConflict:
                # The lease expired before finish won; reconcile converged
                # the request instead.
                pass

        with ThreadPoolExecutor(max_workers=2) as pool:
            list(pool.map(lambda fn: fn(), (reconcile, finish)))
        final = store.get_status("tenant-a", receipt["request_id"])["status"]
        self.assertIn(final, ("completed", "failed"))
        self.assertEqual(len(outcomes), 1)
        self.assertEqual(outcomes[0]["status"], final)
        self.assertTrue(store.verify_evidence("tenant-a", receipt["request_id"]))


class DeferredReconcileTests(_StoreCase):
    def test_reconcile_is_proxied(self):
        store = httpapi.DeferredRequestStore(self.db_path)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        store.claim_next("tenant-a", "worker-1", 1)
        _wait_for_expiry()
        record = store.reconcile_execution("tenant-a", receipt["request_id"])
        self.assertEqual(record["status"], "failed")

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
