import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

from forgetting_evidence.requests import (
    ClaimConflict,
    RequestNotFound,
    RequestStore,
)

SRC_DIR = str(Path(__file__).resolve().parents[1] / "src")


def _parse_utc(value):
    # RFC 3339 with trailing Z.
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class ClaimNextTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "evidence.db")

    def tearDown(self):
        self._tmp.cleanup()

    def _store(self):
        return RequestStore(self.db_path)

    def _submit(self, store, tenant="tenant-a", key="key-1", subject="subject-1"):
        return store.submit(tenant, subject, ["email"], key)

    def _raw(self):
        return sqlite3.connect(self.db_path)

    # --- empty store / receipt shape -----------------------------------

    def test_claim_empty_store_returns_none(self):
        store = self._store()
        self.assertIsNone(store.claim_next("tenant-a", "worker-1", 60))

    def test_claim_returns_exactly_three_fields(self):
        store = self._store()
        receipt = self._submit(store)
        claim = store.claim_next("tenant-a", "worker-1", 60)
        self.assertEqual(
            set(claim), {"request_id", "claim_token", "lease_expires_at"}
        )
        self.assertEqual(claim["request_id"], receipt["request_id"])
        self.assertIsInstance(claim["claim_token"], str)
        self.assertGreaterEqual(len(claim["claim_token"]), 32)
        parsed = _parse_utc(claim["lease_expires_at"])
        self.assertEqual(parsed.utcoffset().total_seconds(), 0)

    def test_lease_duration_bounds_are_honoured(self):
        store = self._store()
        first = self._submit(store, key="k1")
        c1 = store.claim_next("tenant-a", "w", 1)
        # The 1s lower bound: expiry is exactly the configured span after
        # the grant instant stored on the lease row (both come from one
        # clock read, so acceptance-to-claim latency never enters it).
        with self._raw() as conn:
            claimed_at, expires_at = conn.execute(
                "SELECT claimed_at, expires_at FROM request_leases "
                "WHERE claim_token = ?",
                (c1["claim_token"],),
            ).fetchone()
        span = _parse_utc(expires_at) - _parse_utc(claimed_at)
        self.assertGreaterEqual(span.total_seconds(), 1.0 - 0.001)
        self.assertLessEqual(span.total_seconds(), 1.0 + 0.001)
        # First request is leased; the next grant therefore takes k2, and
        # the 3600s upper bound is persisted verbatim.
        second = self._submit(store, key="k2")
        c2 = store.claim_next("tenant-a", "w", 3600)
        self.assertEqual(c2["request_id"], second["request_id"])
        self.assertEqual(expires_at, c1["lease_expires_at"])
        with self._raw() as conn:
            row = conn.execute(
                "SELECT claimed_at, expires_at FROM request_leases "
                "WHERE claim_token = ?",
                (c2["claim_token"],),
            ).fetchone()
        span_two = _parse_utc(row[1]) - _parse_utc(row[0])
        self.assertEqual(span_two.total_seconds(), 3600.0)
        self.assertEqual(row[1], c2["lease_expires_at"])

    # --- validation ----------------------------------------------------

    def test_invalid_identifiers_raise_value_error_without_writes(self):
        store = self._store()
        self._submit(store)
        bad_values = ["", None, 7, b"worker", ["worker"]]
        for bad in bad_values:
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    store.claim_next(bad, "worker-1", 60)
                with self.assertRaises(ValueError):
                    store.claim_next("tenant-a", bad, 60)
        with self._raw() as conn:
            self.assertEqual(
                conn.execute("SELECT count(*) FROM request_leases").fetchone()[0], 0
            )
            self.assertEqual(
                conn.execute(
                    "SELECT status FROM requests"
                ).fetchone()[0],
                "accepted",
            )

    def test_invalid_lease_seconds_raise_value_error_without_writes(self):
        store = self._store()
        self._submit(store)
        bad_seconds = [0, -1, 3601, 10_000, 1.5, 3600.0, "60", None, True, False, [], {}]
        for bad in bad_seconds:
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    store.claim_next("tenant-a", "worker-1", bad)
        with self._raw() as conn:
            self.assertEqual(
                conn.execute("SELECT count(*) FROM request_leases").fetchone()[0], 0
            )
            self.assertEqual(
                conn.execute("SELECT count(*) FROM status_events").fetchone()[0], 1
            )
            self.assertEqual(
                conn.execute("SELECT status FROM requests").fetchone()[0],
                "accepted",
            )

    # --- selection / ordering ------------------------------------------

    def test_claims_in_acceptance_order(self):
        store = self._store()
        receipts = [
            self._submit(store, key=f"key-{i}") for i in range(4)
        ]
        claimed = []
        for _ in range(4):
            claim = store.claim_next("tenant-a", "worker-1", 3600)
            self.assertIsNotNone(claim)
            claimed.append(claim["request_id"])
        self.assertEqual(claimed, [r["request_id"] for r in receipts])
        # Everything leased: nothing left.
        self.assertIsNone(store.claim_next("tenant-a", "worker-1", 3600))

    def test_ordering_tie_breaks_by_request_id(self):
        store = self._store()
        one = self._submit(store, key="key-1")
        two = self._submit(store, key="key-2")
        # Force identical acceptance times; created_at is not part of the
        # chain preimage, so the evidence remains intact.
        with self._raw() as conn:
            conn.execute(
                "UPDATE requests SET created_at = '2026-01-01T00:00:00Z'"
            )
        expected = sorted([one["request_id"], two["request_id"]])
        first = store.claim_next("tenant-a", "w", 3600)
        self.assertEqual(first["request_id"], expected[0])

    def test_active_lease_blocks_reclaim_while_unexpired(self):
        store = self._store()
        self._submit(store)
        first = store.claim_next("tenant-a", "worker-1", 3600)
        # Another worker immediately finds nothing claimable.
        self.assertIsNone(store.claim_next("tenant-a", "worker-2", 3600))
        other = self._submit(store, key="key-2")
        second = store.claim_next("tenant-a", "worker-2", 3600)
        self.assertEqual(second["request_id"], other["request_id"])
        self.assertNotEqual(first["claim_token"], second["claim_token"])
        with self._raw() as conn:
            counts = dict(
                conn.execute(
                    "SELECT request_id, count(*) FROM request_leases "
                    "GROUP BY request_id"
                ).fetchall()
            )
        self.assertEqual(counts[first["request_id"]], 1)

    def test_claim_scoped_per_tenant(self):
        store = self._store()
        a = self._submit(store, tenant="tenant-a", key="ka")
        b = self._submit(store, tenant="tenant-b", key="kb")
        claim_a = store.claim_next("tenant-a", "w", 3600)
        claim_b = store.claim_next("tenant-b", "w", 3600)
        self.assertEqual(claim_a["request_id"], a["request_id"])
        self.assertEqual(claim_b["request_id"], b["request_id"])
        self.assertIsNone(store.claim_next("tenant-a", "w", 3600))
        self.assertIsNone(store.claim_next("tenant-b", "w", 3600))
        # Tenant with no requests at all.
        self.assertIsNone(store.claim_next("tenant-c", "w", 3600))

    def test_terminal_requests_are_never_claimable(self):
        store = self._store()
        failed = self._submit(store, key="k-failed")
        store.transition("tenant-a", failed["request_id"], "failed")
        claimed = self._submit(store, key="k-claimed")
        picked = store.claim_next("tenant-a", "w", 3600)
        self.assertEqual(picked["request_id"], claimed["request_id"])
        self.assertIsNone(store.claim_next("tenant-a", "w", 3600))
        store.finish_claim("tenant-a", picked["claim_token"], "completed")
        self.assertIsNone(store.claim_next("tenant-a", "w", 3600))

    def test_processing_without_any_lease_is_not_claimable(self):
        # A legacy/manual processing move carries no lease row; an empty
        # subquery result must not read as "expired".
        store = self._store()
        receipt = self._submit(store)
        store.transition("tenant-a", receipt["request_id"], "processing")
        self.assertIsNone(store.claim_next("tenant-a", "w", 3600))

    # --- first claim effects -------------------------------------------

    def test_first_claim_migrates_to_processing_with_one_event(self):
        store = self._store()
        receipt = self._submit(store)
        claim = store.claim_next("tenant-a", "worker-1", 3600)
        self.assertEqual(
            store.get("tenant-a", receipt["request_id"])["status"], "processing"
        )
        events = store.audit("tenant-a", receipt["request_id"])
        self.assertEqual(
            [e["status"] for e in events], ["accepted", "processing"]
        )
        self.assertTrue(store.verify_evidence("tenant-a", receipt["request_id"]))
        ev = store.evidence("tenant-a", receipt["request_id"])
        self.assertEqual(ev["event_count"], 2)
        self.assertEqual(ev["status"], "processing")
        # The worker and timestamps are persisted, not returned.
        with self._raw() as conn:
            row = conn.execute(
                "SELECT worker_id, claimed_at, expires_at FROM request_leases "
                "WHERE claim_token = ?",
                (claim["claim_token"],),
            ).fetchone()
        self.assertEqual(row[0], "worker-1")
        self.assertTrue(row[1])
        self.assertEqual(row[2], claim["lease_expires_at"])

    def test_expired_reclaim_issues_new_token_without_status_event(self):
        store = self._store()
        receipt = self._submit(store)
        first = store.claim_next("tenant-a", "worker-1", 1)
        # Age the lease past expiry out of band.
        with self._raw() as conn:
            conn.execute(
                "UPDATE request_leases SET expires_at = '2000-01-01T00:00:00Z'"
            )
        second = store.claim_next("tenant-a", "worker-2", 3600)
        self.assertIsNotNone(second)
        self.assertEqual(second["request_id"], receipt["request_id"])
        self.assertNotEqual(first["claim_token"], second["claim_token"])
        self.assertEqual(
            store.get("tenant-a", receipt["request_id"])["status"], "processing"
        )
        events = store.audit("tenant-a", receipt["request_id"])
        self.assertEqual(
            [e["status"] for e in events], ["accepted", "processing"]
        )
        self.assertEqual(
            store.evidence("tenant-a", receipt["request_id"])["event_count"], 2
        )
        self.assertTrue(store.verify_evidence("tenant-a", receipt["request_id"]))
        with self._raw() as conn:
            workers = [
                row[0]
                for row in conn.execute(
                    "SELECT worker_id FROM request_leases "
                    "WHERE request_id = ? ORDER BY rowid",
                    (receipt["request_id"],),
                )
            ]
        self.assertEqual(workers, ["worker-1", "worker-2"])

    # --- persistence ---------------------------------------------------

    def test_lease_persists_across_store_rebuild(self):
        first_store = self._store()
        receipt = self._submit(first_store)
        claim = first_store.claim_next("tenant-a", "worker-1", 3600)
        rebuilt = self._store()
        # The live lease still blocks another grant after a rebuild.
        self.assertIsNone(rebuilt.claim_next("tenant-a", "worker-2", 3600))
        # And the original token completes the work on the new instance.
        done = rebuilt.finish_claim("tenant-a", claim["claim_token"], "completed")
        self.assertEqual(done["request_id"], receipt["request_id"])
        self.assertEqual(done["status"], "completed")
        self.assertTrue(rebuilt.verify_evidence("tenant-a", receipt["request_id"]))

    # --- concurrency ---------------------------------------------------

    def test_concurrent_claims_each_request_claimed_once(self):
        store = self._store()
        for i in range(20):
            self._submit(store, key=f"key-{i}")

        def claim(_):
            return store.claim_next("tenant-a", f"worker-{_ % 8}", 3600)

        with ThreadPoolExecutor(max_workers=16) as pool:
            results = list(pool.map(claim, range(40)))
        granted = [r for r in results if r is not None]
        self.assertEqual(len(granted), 20)
        self.assertEqual(len({r["request_id"] for r in granted}), 20)
        self.assertEqual(results.count(None), 20)
        with self._raw() as conn:
            per_request = dict(
                conn.execute(
                    "SELECT request_id, count(*) FROM request_leases "
                    "GROUP BY request_id"
                ).fetchall()
            )
            statuses = dict(
                conn.execute("SELECT request_id, status FROM requests").fetchall()
            )
        self.assertEqual(len(per_request), 20)
        self.assertTrue(all(count == 1 for count in per_request.values()))
        self.assertTrue(all(s == "processing" for s in statuses.values()))

    def test_concurrent_claims_from_separate_processes(self):
        store = self._store()
        for i in range(10):
            self._submit(store, tenant="tenant-proc", key=f"key-{i}")

        env = dict(os.environ, PYTHONPATH=SRC_DIR)
        script = (
            "import json, sys; "
            "from forgetting_evidence.requests import RequestStore; "
            "store = RequestStore(sys.argv[1]); "
            "claim = store.claim_next('tenant-proc', 'proc-worker', 3600); "
            "print(json.dumps(claim))"
        )
        procs = [
            subprocess.Popen(
                [sys.executable, "-c", script, self.db_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
            )
            for _ in range(20)
        ]
        results = []
        for proc in procs:
            out, err = proc.communicate(timeout=60)
            self.assertEqual(proc.returncode, 0, err.decode())
            results.append(json.loads(out.decode()))
        granted = [r for r in results if r is not None]
        self.assertEqual(len(granted), 10)
        self.assertEqual(len({r["request_id"] for r in granted}), 10)
        with self._raw() as conn:
            rows = conn.execute(
                "SELECT request_id, count(*), "
                "(SELECT status FROM requests r WHERE r.request_id = l.request_id) "
                "FROM request_leases l GROUP BY request_id"
            ).fetchall()
        self.assertEqual(len(rows), 10)
        self.assertTrue(all(count == 1 for _, count, _ in rows))
        self.assertTrue(all(status == "processing" for _, _, status in rows))


class FinishClaimTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "evidence.db")

    def tearDown(self):
        self._tmp.cleanup()

    def _store(self):
        return RequestStore(self.db_path)

    def _raw(self):
        return sqlite3.connect(self.db_path)

    def _claimed(self, target_status_event=None, lease_seconds=3600,
                 tenant="tenant-a", key="key-1"):
        store = self._store()
        receipt = store.submit(tenant, "subject-1", ["email"], key)
        claim = store.claim_next(tenant, "worker-1", lease_seconds)
        return store, receipt, claim

    # --- validation ----------------------------------------------------

    def test_invalid_arguments_raise_value_error_without_writes(self):
        store, receipt, claim = self._claimed()
        bad_ids = ["", None, 7, b"x", ["x"]]
        for bad in bad_ids:
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    store.finish_claim(bad, claim["claim_token"], "completed")
                with self.assertRaises(ValueError):
                    store.finish_claim("tenant-a", bad, "completed")
        bad_targets = ["", "processing", "accepted", "failed ", "COMPLETED",
                       None, True, 7, "cancelled"]
        for bad in bad_targets:
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    store.finish_claim("tenant-a", claim["claim_token"], bad)
        with self._raw() as conn:
            self.assertEqual(
                conn.execute(
                    "SELECT status FROM requests WHERE request_id = ?",
                    (receipt["request_id"],),
                ).fetchone()[0],
                "processing",
            )
            self.assertEqual(
                conn.execute("SELECT count(*) FROM status_events").fetchone()[0], 2
            )

    # --- not found classification --------------------------------------

    def test_unknown_token_raises_not_found(self):
        store, _, _ = self._claimed()
        with self.assertRaises(RequestNotFound):
            store.finish_claim("tenant-a", "token-that-was-never-granted", "completed")

    def test_cross_tenant_token_raises_not_found(self):
        store, receipt, claim = self._claimed(tenant="tenant-a")
        with self.assertRaises(RequestNotFound):
            store.finish_claim("tenant-b", claim["claim_token"], "completed")
        # The request is untouched.
        self.assertEqual(
            store.get("tenant-a", receipt["request_id"])["status"], "processing"
        )
        with self._raw() as conn:
            self.assertEqual(
                conn.execute("SELECT count(*) FROM status_events").fetchone()[0], 2
            )

    # --- success -------------------------------------------------------

    def test_finish_completed_returns_status_receipt(self):
        store, receipt, claim = self._claimed()
        done = store.finish_claim(
            "tenant-a", claim["claim_token"], "completed"
        )
        self.assertEqual(set(done), {"request_id", "status", "created_at"})
        self.assertEqual(done["request_id"], receipt["request_id"])
        self.assertEqual(done["status"], "completed")
        self.assertEqual(done["created_at"], receipt["created_at"])
        self.assertEqual(store.get("tenant-a", receipt["request_id"]), done)
        self.assertEqual(
            [e["status"] for e in store.audit("tenant-a", receipt["request_id"])],
            ["accepted", "processing", "completed"],
        )
        self.assertTrue(store.verify_evidence("tenant-a", receipt["request_id"]))
        self.assertEqual(
            store.evidence("tenant-a", receipt["request_id"])["event_count"], 3
        )

    def test_finish_failed(self):
        store, receipt, claim = self._claimed()
        done = store.finish_claim("tenant-a", claim["claim_token"], "failed")
        self.assertEqual(done["status"], "failed")
        self.assertEqual(
            [e["status"] for e in store.audit("tenant-a", receipt["request_id"])],
            ["accepted", "processing", "failed"],
        )
        self.assertTrue(store.verify_evidence("tenant-a", receipt["request_id"]))

    # --- conflict classification ---------------------------------------

    def test_replay_of_consumed_token_raises_conflict(self):
        store, receipt, claim = self._claimed()
        store.finish_claim("tenant-a", claim["claim_token"], "completed")
        with self.assertRaises(ClaimConflict):
            store.finish_claim("tenant-a", claim["claim_token"], "completed")
        with self.assertRaises(ClaimConflict):
            store.finish_claim("tenant-a", claim["claim_token"], "failed")
        self.assertEqual(
            [e["status"] for e in store.audit("tenant-a", receipt["request_id"])],
            ["accepted", "processing", "completed"],
        )

    def test_expired_token_raises_conflict_and_request_is_reclaimable(self):
        store, receipt, claim = self._claimed(lease_seconds=1)
        with self._raw() as conn:
            conn.execute(
                "UPDATE request_leases SET expires_at = '2000-01-01T00:00:00Z'"
            )
        with self.assertRaises(ClaimConflict):
            store.finish_claim("tenant-a", claim["claim_token"], "completed")
        self.assertEqual(
            store.get("tenant-a", receipt["request_id"])["status"], "processing"
        )
        # A fresh worker takes the expired request over.
        new_claim = store.claim_next("tenant-a", "worker-2", 3600)
        self.assertEqual(new_claim["request_id"], receipt["request_id"])
        # The superseded token still cannot finish.
        with self.assertRaises(ClaimConflict):
            store.finish_claim("tenant-a", claim["claim_token"], "completed")
        done = store.finish_claim(
            "tenant-a", new_claim["claim_token"], "completed"
        )
        self.assertEqual(done["status"], "completed")
        self.assertEqual(
            [e["status"] for e in store.audit("tenant-a", receipt["request_id"])],
            ["accepted", "processing", "completed"],
        )
        self.assertTrue(store.verify_evidence("tenant-a", receipt["request_id"]))

    def test_superseded_token_raises_conflict(self):
        store, _, claim_one = self._claimed(lease_seconds=1)
        with self._raw() as conn:
            conn.execute(
                "UPDATE request_leases SET expires_at = '2000-01-01T00:00:00Z'"
            )
        claim_two = store.claim_next("tenant-a", "worker-2", 3600)
        with self.assertRaises(ClaimConflict):
            store.finish_claim("tenant-a", claim_one["claim_token"], "completed")
        # Only the current token can finish, once.
        done = store.finish_claim(
            "tenant-a", claim_two["claim_token"], "failed"
        )
        self.assertEqual(done["status"], "failed")
        with self.assertRaises(ClaimConflict):
            store.finish_claim("tenant-a", claim_two["claim_token"], "failed")

    def test_token_after_manual_transition_raises_conflict(self):
        store, receipt, claim = self._claimed()
        # A direct, legal processing -> failed move outruns the lease.
        store.transition("tenant-a", receipt["request_id"], "failed")
        with self.assertRaises(ClaimConflict):
            store.finish_claim("tenant-a", claim["claim_token"], "completed")
        self.assertEqual(
            store.get("tenant-a", receipt["request_id"])["status"], "failed"
        )

    def test_conflicts_and_not_found_perform_no_write(self):
        store, receipt, claim = self._claimed(lease_seconds=1)
        with self._raw() as conn:
            conn.execute(
                "UPDATE request_leases SET expires_at = '2000-01-01T00:00:00Z'"
            )
        with self.assertRaises(ClaimConflict):
            store.finish_claim("tenant-a", claim["claim_token"], "completed")
        with self.assertRaises(RequestNotFound):
            store.finish_claim("tenant-a", "never-granted", "completed")
        with self._raw() as conn:
            self.assertEqual(
                conn.execute("SELECT count(*) FROM status_events").fetchone()[0], 2
            )
            self.assertEqual(
                conn.execute("SELECT count(*) FROM request_leases").fetchone()[0], 1
            )
            self.assertEqual(
                conn.execute(
                    "SELECT status FROM requests WHERE request_id = ?",
                    (receipt["request_id"],),
                ).fetchone()[0],
                "processing",
            )

    def test_finish_after_rebuild(self):
        store, receipt, claim = self._claimed()
        rebuilt = self._store()
        done = rebuilt.finish_claim("tenant-a", claim["claim_token"], "completed")
        self.assertEqual(done["request_id"], receipt["request_id"])
        self.assertTrue(rebuilt.verify_evidence("tenant-a", receipt["request_id"]))

    # --- privacy -------------------------------------------------------

    def test_errors_and_logs_do_not_leak_token_or_worker(self):
        store, _, claim = self._claimed(lease_seconds=1)
        secret_worker = "worker-1"
        with self._raw() as conn:
            conn.execute(
                "UPDATE request_leases SET expires_at = '2000-01-01T00:00:00Z'"
            )
        try:
            store.finish_claim("tenant-a", claim["claim_token"], "completed")
        except ClaimConflict as exc:
            message = str(exc)
        else:
            self.fail("expected ClaimConflict")
        self.assertNotIn(claim["claim_token"], message)
        self.assertNotIn(secret_worker, message)

        import io
        import logging

        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        logger = logging.getLogger("forgetting_evidence.requests")
        logger.addHandler(handler)
        old_level = logger.level
        logger.setLevel(logging.INFO)
        try:
            new_claim = store.claim_next("tenant-a", secret_worker, 3600)
            store.finish_claim("tenant-a", new_claim["claim_token"], "failed")
        finally:
            logger.removeHandler(handler)
            logger.setLevel(old_level)
        logs = stream.getvalue()
        self.assertNotIn(new_claim["claim_token"], logs)
        self.assertNotIn(secret_worker, logs)


if __name__ == "__main__":
    unittest.main()
