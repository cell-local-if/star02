import json
import os
import sqlite3
import tempfile
import time
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


class ClaimNextTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "evidence.db")
        self.store = RequestStore(self.db_path)

    def tearDown(self):
        self._tmp.cleanup()

    def _submit(self, tenant="tenant-a", key="key-1", subject="subject-1"):
        return self.store.submit(tenant, subject, ["email"], key)

    def test_no_candidate_returns_none(self):
        self.assertIsNone(self.store.claim_next("tenant-a", "worker-1", 60))
        # A request belonging to another tenant is not a candidate.
        receipt = self._submit(tenant="tenant-b", key="k-b")
        self.assertIsNone(self.store.claim_next("tenant-a", "worker-1", 60))
        claimed = self.store.claim_next("tenant-b", "worker-1", 60)
        self.assertEqual(claimed["request_id"], receipt["request_id"])

    def test_claim_receipt_shape(self):
        receipt = self._submit()
        claim = self.store.claim_next("tenant-a", "worker-1", 60)
        self.assertEqual(
            set(claim), {"request_id", "claim_token", "lease_expires_at"}
        )
        self.assertEqual(claim["request_id"], receipt["request_id"])
        self.assertIsInstance(claim["claim_token"], str)
        self.assertTrue(claim["claim_token"])
        # Tokens are high-entropy (url-safe 32 random bytes -> ~43 chars).
        self.assertGreaterEqual(len(claim["claim_token"]), 40)
        parsed = _parse_utc(claim["lease_expires_at"])
        self.assertEqual(parsed.utcoffset().total_seconds(), 0)
        # Claiming moves the request to processing.
        self.assertEqual(
            self.store.get_status("tenant-a", receipt["request_id"])["status"],
            "processing",
        )
        # The frozen acceptance receipt and acceptance time never change.
        frozen = self.store.get("tenant-a", receipt["request_id"])
        self.assertEqual(frozen, receipt)

    def test_claim_ordering_by_acceptance_time_then_id(self):
        r1 = self._submit(key="k1")
        r2 = self._submit(key="k2")
        r3 = self._submit(key="k3")
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE requests SET created_at = '2026-01-03T00:00:00Z' "
                "WHERE request_id = ?",
                (r1["request_id"],),
            )
            conn.execute(
                "UPDATE requests SET created_at = '2026-01-01T00:00:00Z' "
                "WHERE request_id = ?",
                (r2["request_id"],),
            )
            conn.execute(
                "UPDATE requests SET created_at = '2026-01-02T00:00:00Z' "
                "WHERE request_id = ?",
                (r3["request_id"],),
            )
        first = self.store.claim_next("tenant-a", "w", 3600)
        second = self.store.claim_next("tenant-a", "w", 3600)
        third = self.store.claim_next("tenant-a", "w", 3600)
        self.assertEqual(
            [c["request_id"] for c in (first, second, third)],
            [r2["request_id"], r3["request_id"], r1["request_id"]],
        )

    def test_claim_ordering_tie_breaks_by_request_id(self):
        r1 = self._submit(key="k1")
        r2 = self._submit(key="k2")
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE requests SET created_at = '2026-01-01T00:00:00Z'"
            )
        first = self.store.claim_next("tenant-a", "w", 3600)
        second = self.store.claim_next("tenant-a", "w", 3600)
        ordered = sorted([r1["request_id"], r2["request_id"]])
        self.assertEqual(
            [c["request_id"] for c in (first, second)], ordered
        )

    def test_only_one_active_lease_per_request(self):
        self._submit()
        first = self.store.claim_next("tenant-a", "worker-1", 3600)
        # While the lease is live no other worker can hold the request.
        self.assertIsNone(self.store.claim_next("tenant-a", "worker-2", 3600))
        self.assertIsNone(self.store.claim_next("tenant-a", "worker-1", 3600))
        self.assertEqual(first["request_id"], first["request_id"])

    def test_invalid_arguments_raise_value_error_without_writes(self):
        self._submit()
        bad_tenants = ("", None, 7, b"t", ["t"])
        bad_workers = ("", None, 7, b"w", ["w"])
        bad_leases = (0, -1, 3601, 1.0, 60.0, True, False, "60", None, [60])
        for bad in bad_tenants:
            with self.assertRaises(ValueError):
                self.store.claim_next(bad, "worker-1", 60)
        for bad in bad_workers:
            with self.assertRaises(ValueError):
                self.store.claim_next("tenant-a", bad, 60)
        for bad in bad_leases:
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    self.store.claim_next("tenant-a", "worker-1", bad)
        with sqlite3.connect(self.db_path) as conn:
            self.assertEqual(
                conn.execute("SELECT count(*) FROM execution_attempts").fetchone()[0],
                0,
            )
            self.assertEqual(
                conn.execute(
                    "SELECT count(*) FROM requests WHERE status != 'accepted'"
                ).fetchone()[0],
                0,
            )

    def test_lease_bounds_one_and_3600_are_valid(self):
        self._submit(key="k1")
        claim = self.store.claim_next("tenant-a", "w", 1)
        self.assertIsNotNone(claim)
        time.sleep(1.05)
        self._submit(key="k2")
        claim = self.store.claim_next("tenant-a", "w", 3600)
        self.assertIsNotNone(claim)


class LeaseExpiryReclaimTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "evidence.db")
        self.store = RequestStore(self.db_path)
        self.receipt = self.store.submit(
            "tenant-a", "subject-1", ["email"], "key-1"
        )
        self.rid = self.receipt["request_id"]

    def tearDown(self):
        self._tmp.cleanup()

    def test_expired_lease_is_reclaimed_as_new_attempt(self):
        first = self.store.claim_next("tenant-a", "worker-1", 1)
        time.sleep(1.05)
        second = self.store.claim_next("tenant-a", "worker-2", 3600)
        self.assertIsNotNone(second)
        self.assertEqual(second["request_id"], self.rid)
        self.assertNotEqual(first["claim_token"], second["claim_token"])
        # Re-claim changes neither first acceptance time, id nor status.
        status = self.store.get_status("tenant-a", self.rid)
        self.assertEqual(status["status"], "processing")
        self.assertEqual(status["created_at"], self.receipt["created_at"])
        self.assertEqual(status["request_id"], self.rid)
        # Only one processing transition ever reached the timeline.
        self.assertEqual(
            [e["status"] for e in self.store.audit("tenant-a", self.rid)],
            ["accepted", "processing"],
        )

    def test_old_token_released_after_reclaim(self):
        first = self.store.claim_next("tenant-a", "worker-1", 1)
        time.sleep(1.05)
        second = self.store.claim_next("tenant-a", "worker-2", 3600)
        with self.assertRaises(ClaimConflict):
            self.store.finish_claim(
                "tenant-a", self.rid, first["claim_token"], "completed"
            )
        # The released claim left no terminal state behind.
        self.assertEqual(
            self.store.get_status("tenant-a", self.rid)["status"], "processing"
        )
        finished = self.store.finish_claim(
            "tenant-a", self.rid, second["claim_token"], "completed"
        )
        self.assertEqual(finished["status"], "completed")

    def test_expired_token_finishing_before_reclaim_conflicts(self):
        claim = self.store.claim_next("tenant-a", "worker-1", 1)
        time.sleep(1.05)
        with self.assertRaises(ClaimConflict):
            self.store.finish_claim(
                "tenant-a", self.rid, claim["claim_token"], "completed"
            )
        self.assertEqual(
            self.store.get_status("tenant-a", self.rid)["status"], "processing"
        )


class FinishClaimTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "evidence.db")
        self.store = RequestStore(self.db_path)

    def tearDown(self):
        self._tmp.cleanup()

    def _claimed(self, tenant="tenant-a", key="key-1", lease=3600):
        receipt = self.store.submit(tenant, "subject-1", ["email"], key)
        claim = self.store.claim_next(tenant, "worker-1", lease)
        return receipt, claim

    def test_finish_completed_receipt_shape(self):
        receipt, claim = self._claimed()
        done = self.store.finish_claim(
            "tenant-a", receipt["request_id"], claim["claim_token"], "completed"
        )
        self.assertEqual(set(done), {"request_id", "status", "created_at"})
        self.assertEqual(done["request_id"], receipt["request_id"])
        self.assertEqual(done["status"], "completed")
        self.assertEqual(done["created_at"], receipt["created_at"])
        self.assertEqual(
            self.store.get_status("tenant-a", receipt["request_id"])["status"],
            "completed",
        )
        self.assertEqual(
            [e["status"] for e in self.store.audit("tenant-a", receipt["request_id"])],
            ["accepted", "processing", "completed"],
        )
        self.assertTrue(
            self.store.verify_evidence("tenant-a", receipt["request_id"])
        )

    def test_finish_failed(self):
        receipt, claim = self._claimed(key="k2")
        done = self.store.finish_claim(
            "tenant-a", receipt["request_id"], claim["claim_token"], "failed"
        )
        self.assertEqual(done["status"], "failed")
        self.assertTrue(
            self.store.verify_evidence("tenant-a", receipt["request_id"])
        )

    def test_unknown_malformed_and_foreign_tokens_conflict(self):
        receipt, claim = self._claimed()
        rid = receipt["request_id"]
        other, other_claim = self._claimed(key="key-2")
        for bad_token in ("does-not-exist", "x" * 43, other_claim["claim_token"]):
            with self.subTest(bad_token=bad_token):
                with self.assertRaises(ClaimConflict):
                    self.store.finish_claim(
                        "tenant-a", rid, bad_token, "completed"
                    )
        # A token minted for another tenant's claim also conflicts; it
        # must not be reported as a missing request.
        foreign = self.store.submit(
            "tenant-b", "subject-1", ["email"], "key-b"
        )
        foreign_claim = self.store.claim_next("tenant-b", "worker-b", 3600)
        with self.assertRaises(ClaimConflict):
            self.store.finish_claim(
                "tenant-a", foreign["request_id"],
                foreign_claim["claim_token"], "completed",
            )
        # Neither conflict moved any state.
        self.assertEqual(
            self.store.get_status("tenant-a", rid)["status"], "processing"
        )
        self.assertEqual(
            self.store.get_status("tenant-b", foreign["request_id"])["status"],
            "processing",
        )

    def test_token_reuse_after_terminal_conflicts(self):
        receipt, claim = self._claimed()
        rid = receipt["request_id"]
        token = claim["claim_token"]
        self.store.finish_claim("tenant-a", rid, token, "completed")
        with self.assertRaises(ClaimConflict):
            self.store.finish_claim("tenant-a", rid, token, "failed")
        self.assertEqual(
            self.store.get_status("tenant-a", rid)["status"], "completed"
        )

    def test_finish_validation_domains(self):
        receipt, claim = self._claimed()
        rid = receipt["request_id"]
        token = claim["claim_token"]
        for bad_tenant in ("", None, 7, b"t"):
            with self.assertRaises(ValueError):
                self.store.finish_claim(bad_tenant, rid, token, "completed")
        for bad_token in ("", None, 7, b"t", ["t"]):
            with self.assertRaises(ValueError):
                self.store.finish_claim("tenant-a", rid, bad_token, "completed")
        for bad_result in ("", None, 7, "done", "COMPLETED", "accepted"):
            with self.subTest(bad_result=bad_result):
                with self.assertRaises(ValueError):
                    self.store.finish_claim("tenant-a", rid, token, bad_result)
        # Invalid calls performed no write.
        self.assertEqual(
            self.store.get_status("tenant-a", rid)["status"], "processing"
        )

    def test_finish_unknown_and_malformed_id_is_not_found(self):
        _, claim = self._claimed()
        for bad_id in ("", None, 7, b"x", ["x"], "not-a-uuid", "does-not-exist"):
            with self.subTest(bad_id=bad_id):
                with self.assertRaises(RequestNotFound):
                    self.store.finish_claim(
                        "tenant-a", bad_id, claim["claim_token"], "completed"
                    )

    def test_concurrent_finish_race_single_terminal(self):
        receipt, claim = self._claimed()
        rid = receipt["request_id"]
        token = claim["claim_token"]

        def finish():
            try:
                return self.store.finish_claim(
                    "tenant-a", rid, token, "completed"
                )
            except ClaimConflict:
                return "conflict"
            except OSError:
                return "storage"

        with ThreadPoolExecutor(max_workers=16) as pool:
            outcomes = list(pool.map(lambda _: finish(), range(32)))
        winners = [o for o in outcomes if isinstance(o, dict)]
        self.assertEqual(len(winners), 1)
        self.assertNotIn("storage", outcomes)
        self.assertEqual(
            self.store.get_status("tenant-a", rid)["status"], "completed"
        )
        with sqlite3.connect(self.db_path) as conn:
            terminal_events = conn.execute(
                "SELECT count(*) FROM status_events "
                "WHERE request_id = ? AND status IN ('completed', 'failed')",
                (rid,),
            ).fetchone()[0]
            finished_attempts = conn.execute(
                "SELECT count(*) FROM execution_attempts "
                "WHERE request_id = ? AND result IS NOT NULL",
                (rid,),
            ).fetchone()[0]
        self.assertEqual(terminal_events, 1)
        self.assertEqual(finished_attempts, 1)


class ExecutionLogTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "evidence.db")
        self.store = RequestStore(self.db_path)

    def tearDown(self):
        self._tmp.cleanup()

    def test_log_fields_shapes_and_types(self):
        receipt = self.store.submit("tenant-a", "subject-1", ["email"], "k1")
        rid = receipt["request_id"]
        claim = self.store.claim_next("tenant-a", "worker-1", 1)
        log = self.store.get_execution_log("tenant-a", rid)
        self.assertEqual(len(log), 1)
        entry = log[0]
        self.assertEqual(
            set(entry),
            {
                "attempt_no",
                "claimed_at",
                "lease_expires_at",
                "result",
                "finished_at",
            },
        )
        self.assertEqual(entry["attempt_no"], 1)
        self.assertIsInstance(entry["attempt_no"], int)
        self.assertNotIsInstance(entry["attempt_no"], bool)
        for field in ("claimed_at", "lease_expires_at"):
            self.assertIsInstance(entry[field], str)
            self.assertEqual(
                _parse_utc(entry[field]).utcoffset().total_seconds(), 0
            )
        # In-progress attempt carries neither result nor completion time.
        self.assertIsNone(entry["result"])
        self.assertIsNone(entry["finished_at"])
        # Values are only strings, integers and None; JSON round-trips
        # without floats or non-finite numbers.
        rendered = json.dumps(log)
        for token in ("NaN", "Infinity", "-0.0", "e+", "E+"):
            self.assertNotIn(token, rendered)
        json.loads(rendered)
        # No worker or claim token in the record.
        self.assertNotIn("worker", repr(entry))
        self.assertNotIn(claim["claim_token"], rendered)

    def test_attempt_numbering_and_terminal_record(self):
        receipt = self.store.submit("tenant-a", "subject-1", ["email"], "k1")
        rid = receipt["request_id"]
        first = self.store.claim_next("tenant-a", "worker-1", 1)
        time.sleep(1.05)
        second = self.store.claim_next("tenant-a", "worker-2", 3600)
        self.store.finish_claim(
            "tenant-a", rid, second["claim_token"], "failed"
        )
        log = self.store.get_execution_log("tenant-a", rid)
        self.assertEqual([e["attempt_no"] for e in log], [1, 2])
        # The superseded first attempt stays open-shaped forever.
        self.assertIsNone(log[0]["result"])
        self.assertIsNone(log[0]["finished_at"])
        # Only the final attempt records the terminal result.
        self.assertEqual(log[1]["result"], "failed")
        self.assertIsInstance(log[1]["finished_at"], str)
        self.assertEqual(
            _parse_utc(log[1]["finished_at"]).utcoffset().total_seconds(), 0
        )
        # Neither token is present, even in raw returned values.
        rendered = repr(log)
        self.assertNotIn(first["claim_token"], rendered)
        self.assertNotIn(second["claim_token"], rendered)

    def test_log_missing_invalid_and_cross_tenant(self):
        receipt = self.store.submit("tenant-a", "subject-1", ["email"], "k1")
        self.store.claim_next("tenant-a", "worker-1", 3600)
        rid = receipt["request_id"]
        for bad_id in ("", None, 7, b"x", ["x"], "not-a-uuid", "does-not-exist"):
            with self.subTest(bad_id=bad_id):
                with self.assertRaises(RequestNotFound):
                    self.store.get_execution_log("tenant-a", bad_id)
        with self.assertRaises(RequestNotFound):
            self.store.get_execution_log("tenant-b", rid)
        for bad_tenant in ("", None, 7):
            with self.assertRaises(ValueError):
                self.store.get_execution_log(bad_tenant, rid)

    def test_request_without_attempts_has_empty_log(self):
        receipt = self.store.submit("tenant-a", "subject-1", ["email"], "k1")
        self.assertEqual(
            self.store.get_execution_log(
                "tenant-a", receipt["request_id"]
            ),
            [],
        )

    def test_log_never_mentions_worker_or_token(self):
        secret_worker = "worker-SECRET"
        receipt = self.store.submit("tenant-a", "subject-1", ["email"], "k1")
        claim = self.store.claim_next("tenant-a", secret_worker, 3600)
        self.store.finish_claim(
            "tenant-a", receipt["request_id"], claim["claim_token"], "completed"
        )
        rendered = repr(
            self.store.get_execution_log("tenant-a", receipt["request_id"])
        )
        self.assertNotIn(secret_worker, rendered)
        self.assertNotIn(claim["claim_token"], rendered)


class PersistenceTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "evidence.db")

    def tearDown(self):
        self._tmp.cleanup()

    def test_lease_token_and_attempts_survive_restart(self):
        store = RequestStore(self.db_path)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "k1")
        claim = store.claim_next("tenant-a", "worker-1", 3600)
        log_before = store.get_execution_log(
            "tenant-a", receipt["request_id"]
        )
        rebuilt = RequestStore(self.db_path)
        # The lease is still live and its token still finishes the claim.
        done = rebuilt.finish_claim(
            "tenant-a", receipt["request_id"], claim["claim_token"], "completed"
        )
        self.assertEqual(done["status"], "completed")
        log = rebuilt.get_execution_log("tenant-a", receipt["request_id"])
        self.assertEqual(len(log), 1)
        self.assertEqual(log[0]["attempt_no"], 1)
        self.assertEqual(log[0]["claimed_at"], log_before[0]["claimed_at"])
        self.assertEqual(
            log[0]["lease_expires_at"], log_before[0]["lease_expires_at"]
        )
        self.assertEqual(log[0]["result"], "completed")
        self.assertIsInstance(log[0]["finished_at"], str)
        self.assertTrue(
            rebuilt.verify_evidence("tenant-a", receipt["request_id"])
        )

    def test_expired_reclaim_after_restart(self):
        store = RequestStore(self.db_path)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "k1")
        first = store.claim_next("tenant-a", "worker-1", 1)
        time.sleep(1.05)
        rebuilt = RequestStore(self.db_path)
        second = rebuilt.claim_next("tenant-a", "worker-2", 3600)
        self.assertIsNotNone(second)
        self.assertNotEqual(first["claim_token"], second["claim_token"])
        with self.assertRaises(ClaimConflict):
            rebuilt.finish_claim(
                "tenant-a", receipt["request_id"],
                first["claim_token"], "completed",
            )
        done = rebuilt.finish_claim(
            "tenant-a", receipt["request_id"],
            second["claim_token"], "completed",
        )
        self.assertEqual(done["status"], "completed")
        self.assertEqual(
            [e["attempt_no"] for e in rebuilt.get_execution_log(
                "tenant-a", receipt["request_id"]
            )],
            [1, 2],
        )

    def test_pre_execution_schema_is_upgraded(self):
        # A database written by a version without lease/attempt tables
        # must accept claims after transparent upgrade.
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "CREATE TABLE requests ("
                "request_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, "
                "idempotency_key TEXT NOT NULL, subject_id TEXT NOT NULL, "
                "scopes_json TEXT NOT NULL, status TEXT NOT NULL, "
                "created_at TEXT NOT NULL, chain_hash TEXT NOT NULL)"
            )
            conn.execute(
                "CREATE UNIQUE INDEX idx_requests_tenant_idempotency "
                "ON requests(tenant_id, idempotency_key)"
            )
            conn.execute(
                "CREATE TABLE status_events ("
                "tenant_id TEXT NOT NULL, request_id TEXT NOT NULL, "
                "seq INTEGER NOT NULL, status TEXT NOT NULL, "
                "occurred_at TEXT NOT NULL, chain_hash TEXT NOT NULL, "
                "PRIMARY KEY (tenant_id, request_id, seq))"
            )
            import hashlib
            import struct

            digest = hashlib.sha256()
            values = (
                "tenant-a", "rid-1", "0", "accepted",
                "2026-01-01T00:00:00Z",
                hashlib.sha256(b"").hexdigest(),
            )
            for value in values:
                raw = value.encode()
                digest.update(struct.pack(">Q", len(raw)))
                digest.update(raw)
            genesis = digest.hexdigest()
            conn.execute(
                "INSERT INTO requests VALUES ("
                "'rid-1', 'tenant-a', 'k1', 's1', '[\"email\"]', 'accepted', "
                "'2026-01-01T00:00:00Z', ?)",
                (genesis,),
            )
            conn.execute(
                "INSERT INTO status_events VALUES ("
                "'tenant-a', 'rid-1', 0, 'accepted', "
                "'2026-01-01T00:00:00Z', ?)",
                (genesis,),
            )
        store = RequestStore(self.db_path)
        claim = store.claim_next("tenant-a", "worker-1", 3600)
        self.assertEqual(claim["request_id"], "rid-1")
        done = store.finish_claim(
            "tenant-a", "rid-1", claim["claim_token"], "completed"
        )
        self.assertEqual(done["status"], "completed")
        self.assertTrue(store.verify_evidence("tenant-a", "rid-1"))


class ConcurrencyTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "evidence.db")
        self.store = RequestStore(self.db_path)

    def tearDown(self):
        self._tmp.cleanup()

    def test_single_candidate_claimed_once(self):
        receipt = self.store.submit("tenant-a", "subject-1", ["email"], "k1")

        def claim():
            try:
                return self.store.claim_next("tenant-a", "worker-x", 3600)
            except OSError:
                return "storage"

        with ThreadPoolExecutor(max_workers=32) as pool:
            outcomes = list(pool.map(lambda _: claim(), range(64)))
        winners = [o for o in outcomes if isinstance(o, dict)]
        self.assertEqual(len(winners), 1)
        self.assertNotIn("storage", outcomes)
        with sqlite3.connect(self.db_path) as conn:
            attempts = conn.execute(
                "SELECT count(*) FROM execution_attempts "
                "WHERE request_id = ?",
                (receipt["request_id"],),
            ).fetchone()[0]
        self.assertEqual(attempts, 1)

    def test_n_candidates_get_at_most_n_active_leases(self):
        count = 8
        rids = []
        for i in range(count):
            rids.append(
                self.store.submit(
                    "tenant-a", "subject-1", ["email"], f"k{i}"
                )["request_id"]
            )

        def claim():
            try:
                return self.store.claim_next("tenant-a", "worker-x", 3600)
            except OSError:
                return "storage"

        with ThreadPoolExecutor(max_workers=32) as pool:
            outcomes = list(pool.map(lambda _: claim(), range(count * 8)))
        self.assertNotIn("storage", outcomes)
        winners = [o for o in outcomes if isinstance(o, dict)]
        self.assertEqual(len(winners), count)
        claimed_ids = [w["request_id"] for w in winners]
        self.assertEqual(sorted(claimed_ids), sorted(rids))
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT request_id, count(*) FROM execution_attempts "
                "GROUP BY request_id"
            ).fetchall()
        self.assertEqual(len(rows), count)
        self.assertTrue(all(n == 1 for _, n in rows))

    def test_expired_request_reclaimed_once_under_contention(self):
        receipt = self.store.submit("tenant-a", "subject-1", ["email"], "k1")
        self.store.claim_next("tenant-a", "worker-1", 1)
        time.sleep(1.05)

        def claim():
            try:
                return self.store.claim_next("tenant-a", "worker-x", 3600)
            except OSError:
                return "storage"

        with ThreadPoolExecutor(max_workers=32) as pool:
            outcomes = list(pool.map(lambda _: claim(), range(64)))
        winners = [o for o in outcomes if isinstance(o, dict)]
        self.assertEqual(len(winners), 1)
        self.assertNotIn("storage", outcomes)
        with sqlite3.connect(self.db_path) as conn:
            attempts = conn.execute(
                "SELECT count(*) FROM execution_attempts WHERE request_id = ?",
                (receipt["request_id"],),
            ).fetchone()[0]
        self.assertEqual(attempts, 2)


class StorageFailureTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "evidence.db")

    def tearDown(self):
        self._tmp.cleanup()

    def _prepared(self):
        store = RequestStore(self.db_path)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "k1")
        claim = store.claim_next("tenant-a", "worker-1", 3600)
        return store, receipt, claim

    def test_corrupt_database_raises_fixed_oserror(self):
        store, _, _ = self._prepared()
        with open(self.db_path, "wb") as handle:
            handle.write(b"not a database")
        for call in (
            lambda: store.claim_next("tenant-a", "worker-1", 60),
            lambda: store.finish_claim(
                "tenant-a", "rid", "t" * 43, "completed"
            ),
            lambda: store.get_execution_log("tenant-a", "rid"),
        ):
            with self.assertRaises(OSError) as ctx:
                call()
            self.assertEqual(str(ctx.exception), "request store is unavailable")

    def test_corrupt_attempt_row_is_oserror(self):
        store, receipt, _ = self._prepared()
        with sqlite3.connect(self.db_path) as conn:
            # INTEGER affinity stores a non-numeric string as text, so
            # this bypasses SQL-level validation while corrupting the
            # persisted shape the store expects.
            conn.execute(
                "UPDATE execution_attempts SET attempt_no = 'x' "
                "WHERE request_id = ?",
                (receipt["request_id"],),
            )
        with self.assertRaises(OSError) as ctx:
            store.get_execution_log("tenant-a", receipt["request_id"])
        self.assertEqual(str(ctx.exception), "request store is unavailable")

    def test_errors_do_not_leak_worker_token_or_path(self):
        store, receipt, claim = self._prepared()
        secret_worker = "worker-SECRET"
        # A claim after corrupting nothing still must not log the worker;
        # exercise the conflict text with a random token instead.
        try:
            store.finish_claim(
                "tenant-a", receipt["request_id"], "token-SECRET", "completed"
            )
        except ClaimConflict as exc:
            message = str(exc)
        else:
            self.fail("expected ClaimConflict")
        self.assertNotIn(secret_worker, message)
        self.assertNotIn("token-SECRET", message)
        self.assertNotIn(self.db_path, message)

        with open(self.db_path, "wb") as handle:
            handle.write(b"garbage")
        try:
            store.claim_next("tenant-a", secret_worker, 60)
        except OSError as exc:
            message = str(exc)
        else:
            self.fail("expected OSError")
        self.assertNotIn(secret_worker, message)
        self.assertNotIn(self.db_path, message)
        self.assertNotIn("sqlite", message.lower())


if __name__ == "__main__":
    unittest.main()
