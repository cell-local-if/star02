import io
import logging
import os
import re
import sqlite3
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from forgetting_evidence.requests import (
    ClaimConflict,
    InvalidStatusTransition,
    RequestNotFound,
    RequestStore,
)

HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _parse_utc(value):
    # RFC 3339 with trailing Z.
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class ClaimLeaseTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "evidence.db")

    def tearDown(self):
        self._tmp.cleanup()

    def _store(self):
        return RequestStore(self.db_path)

    def _submit(self, store, tenant="tenant-a", key="key-1"):
        return store.submit(tenant, "subject-1", ["email"], key)

    # -- validation -------------------------------------------------------

    def test_claim_validates_identifiers_without_writes(self):
        store = self._store()
        self._submit(store)
        for bad in ("", None, 7, b"worker", ["worker"]):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    store.claim_next(bad, "worker-1", 10)
                with self.assertRaises(ValueError):
                    store.claim_next("tenant-a", bad, 10)
        with sqlite3.connect(self.db_path) as conn:
            self.assertEqual(
                conn.execute("SELECT count(*) FROM request_claims").fetchone()[0], 0
            )
            # The accepted request was never moved.
            self.assertEqual(
                conn.execute(
                    "SELECT count(*) FROM requests WHERE status='accepted'"
                ).fetchone()[0],
                1,
            )

    def test_claim_validates_lease_seconds(self):
        store = self._store()
        self._submit(store)
        for bad in (0, -1, 3601, -3600, 1.0, "10", None, [10], True, False):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    store.claim_next("tenant-a", "worker-1", bad)
        with sqlite3.connect(self.db_path) as conn:
            self.assertEqual(
                conn.execute("SELECT count(*) FROM request_claims").fetchone()[0], 0
            )
        # Both boundaries are accepted.
        self.assertIsNotNone(store.claim_next("tenant-a", "worker-1", 1))

    def test_finish_validates_arguments_without_writes(self):
        store = self._store()
        receipt = self._submit(store)
        claim = store.claim_next("tenant-a", "worker-1", 100)
        bad_values = ("", None, 7, b"x", ["x"])
        for bad in bad_values:
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    store.finish_claim(bad, claim["claim_token"], "completed")
                with self.assertRaises(ValueError):
                    store.finish_claim("tenant-a", bad, "completed")
        for bad, expected in (
            ("", ValueError),
            (None, ValueError),
            ("cancelled", InvalidStatusTransition),
            ("PROCESSING", InvalidStatusTransition),
            ("accepted", InvalidStatusTransition),
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(expected):
                    store.finish_claim("tenant-a", claim["claim_token"], bad)
        with sqlite3.connect(self.db_path) as conn:
            self.assertEqual(
                conn.execute(
                    "SELECT status FROM requests WHERE request_id=?",
                    (receipt["request_id"],),
                ).fetchone()[0],
                "processing",
            )
            self.assertEqual(
                conn.execute(
                    "SELECT count(*) FROM request_claims WHERE finished_at IS NOT NULL"
                ).fetchone()[0],
                0,
            )

    # -- claim_next -------------------------------------------------------

    def test_claim_next_none_when_no_candidate(self):
        store = self._store()
        self.assertIsNone(store.claim_next("tenant-a", "worker-1", 10))
        # An unknown tenant is indistinguishable from an empty queue.
        self.assertIsNone(store.claim_next("tenant-b", "worker-1", 10))

    def test_claim_returns_only_contract_fields(self):
        store = self._store()
        receipt = self._submit(store)
        before = datetime.now().astimezone()
        claim = store.claim_next("tenant-a", "worker-1", 3600)
        after = datetime.now().astimezone()
        self.assertEqual(
            set(claim), {"request_id", "claim_token", "lease_expires_at"}
        )
        self.assertEqual(claim["request_id"], receipt["request_id"])
        self.assertRegex(claim["claim_token"], HEX64)
        expires = _parse_utc(claim["lease_expires_at"])
        self.assertEqual(expires.utcoffset().total_seconds(), 0)
        # The deadline really is ~lease_seconds past the claim instant.
        leased = expires - timedelta(seconds=3600)
        self.assertTrue(
            before.astimezone(timezone.utc)
            <= leased
            <= after.astimezone(timezone.utc)
        )

    def test_first_claim_moves_to_processing_and_chains_event(self):
        store = self._store()
        receipt = self._submit(store)
        claim = store.claim_next("tenant-a", "worker-1", 60)
        self.assertEqual(
            store.get("tenant-a", receipt["request_id"])["status"], "processing"
        )
        self.assertEqual(
            [e["status"] for e in store.audit("tenant-a", receipt["request_id"])],
            ["accepted", "processing"],
        )
        # Final timeline entry agrees with the authoritative status and the
        # appended audit evidence still verifies end to end.
        events = store.audit("tenant-a", receipt["request_id"])
        self.assertEqual(events[-1]["status"], "processing")
        self.assertTrue(store.verify_evidence("tenant-a", receipt["request_id"]))
        evidence = store.evidence("tenant-a", receipt["request_id"])
        self.assertEqual(evidence["event_count"], 2)
        # Token is a bearer secret returned once.
        self.assertNotIn("claim_token", store.get("tenant-a", receipt["request_id"]))

    def test_claims_drain_in_acceptance_order(self):
        store = self._store()
        receipts = [self._submit(store, key=f"key-{i}") for i in range(5)]
        claimed = []
        for _ in range(5):
            claim = store.claim_next("tenant-a", "worker-1", 60)
            self.assertIsNotNone(claim)
            claimed.append(claim["request_id"])
            store.finish_claim("tenant-a", claim["claim_token"], "completed")
        self.assertEqual(claimed, [r["request_id"] for r in receipts])
        self.assertIsNone(store.claim_next("tenant-a", "worker-1", 60))

    def test_ordering_falls_back_to_request_id(self):
        store = self._store()
        ids = [self._submit(store, key=f"key-{i}")["request_id"] for i in range(5)]
        # Force identical acceptance times; the request id is the tiebreak.
        stamp = "2026-01-01T00:00:00.000000Z"
        with sqlite3.connect(self.db_path) as conn:
            conn.executemany(
                "UPDATE requests SET created_at=? WHERE request_id=?",
                [(stamp, rid) for rid in ids],
            )
            conn.commit()
        claimed = []
        for _ in range(5):
            claim = store.claim_next("tenant-a", "worker-1", 60)
            claimed.append(claim["request_id"])
            store.finish_claim("tenant-a", claim["claim_token"], "completed")
        self.assertEqual(claimed, sorted(ids))

    def test_only_one_live_lease_per_request(self):
        store = self._store()
        one = self._submit(store, key="key-1")
        two = self._submit(store, key="key-2")
        first = store.claim_next("tenant-a", "worker-1", 3600)
        self.assertEqual(first["request_id"], one["request_id"])
        # The held request is not handed out again; the worker moves on.
        second = store.claim_next("tenant-a", "worker-2", 3600)
        self.assertEqual(second["request_id"], two["request_id"])
        self.assertIsNone(store.claim_next("tenant-a", "worker-3", 3600))
        # Database-level invariant: a second live lease row for the same
        # request cannot be inserted, even out of band.
        with sqlite3.connect(self.db_path) as conn:
            with self.assertRaises(sqlite3.IntegrityError):
                conn.execute(
                    "INSERT INTO request_claims ("
                    "tenant_id, request_id, lease_epoch, claim_token_hash, "
                    "worker_id, leased_at, lease_expires_at, finished_at"
                    ") VALUES ('tenant-a', ?, 99, 'ab', 'w', ?, ?, NULL)",
                    (one["request_id"], stamp2026(), stamp2026()),
                )

    def test_expired_lease_is_reclaimable_without_status_event(self):
        store = self._store()
        receipt = self._submit(store)
        first = store.claim_next("tenant-a", "worker-1", 1)
        self.assertTrue(first["lease_expires_at"].endswith("Z"))
        time.sleep(1.1)
        second = store.claim_next("tenant-a", "worker-2", 3600)
        self.assertIsNotNone(second)
        self.assertEqual(second["request_id"], receipt["request_id"])
        self.assertNotEqual(second["claim_token"], first["claim_token"])
        self.assertTrue(HEX64.fullmatch(second["claim_token"]))
        # Still exactly one processing event: reclaim adds no status event.
        self.assertEqual(
            [e["status"] for e in store.audit("tenant-a", receipt["request_id"])],
            ["accepted", "processing"],
        )
        self.assertTrue(store.verify_evidence("tenant-a", receipt["request_id"]))
        # The old lease is closed and a new epoch opened.
        with sqlite3.connect(self.db_path) as conn:
            epochs = [
                row[0]
                for row in conn.execute(
                    "SELECT lease_epoch FROM request_claims "
                    "WHERE request_id=? ORDER BY lease_epoch",
                    (receipt["request_id"],),
                )
            ]
            live = conn.execute(
                "SELECT count(*) FROM request_claims "
                "WHERE request_id=? AND finished_at IS NULL",
                (receipt["request_id"],),
            ).fetchone()[0]
        self.assertEqual(epochs, [0, 1])
        self.assertEqual(live, 1)

    def test_expired_processing_precedes_newer_accepted(self):
        store = self._store()
        old = self._submit(store, key="old")
        held = store.claim_next("tenant-a", "worker-1", 1)
        time.sleep(1.1)
        new = self._submit(store, key="new")
        nxt = store.claim_next("tenant-a", "worker-2", 3600)
        self.assertEqual(nxt["request_id"], old["request_id"])
        store.finish_claim("tenant-a", nxt["claim_token"], "completed")
        after = store.claim_next("tenant-a", "worker-2", 3600)
        self.assertEqual(after["request_id"], new["request_id"])

    def test_manually_transitioned_processing_is_not_claimable(self):
        # transition() remains an independent public path; a processing
        # request that never held a lease has no expired lease to reclaim.
        store = self._store()
        receipt = self._submit(store)
        store.transition("tenant-a", receipt["request_id"], "processing")
        self.assertIsNone(store.claim_next("tenant-a", "worker-1", 1))

    def test_queues_are_partitioned_per_tenant(self):
        store = self._store()
        a = self._submit(store, tenant="tenant-a", key="a")
        b = self._submit(store, tenant="tenant-b", key="b")
        claim_a = store.claim_next("tenant-a", "w-a", 3600)
        claim_b = store.claim_next("tenant-b", "w-b", 3600)
        self.assertEqual(claim_a["request_id"], a["request_id"])
        self.assertEqual(claim_b["request_id"], b["request_id"])
        self.assertIsNone(store.claim_next("tenant-a", "w", 3600))
        self.assertIsNone(store.claim_next("tenant-b", "w", 3600))

    def test_lease_persists_across_store_rebuild(self):
        first = self._store()
        receipt = self._submit(first)
        claim = first.claim_next("tenant-a", "worker-1", 3600)
        rebuilt = RequestStore(self.db_path)
        # A live lease honoured by a different store instance/process.
        self.assertIsNone(rebuilt.claim_next("tenant-a", "worker-2", 3600))
        done = rebuilt.finish_claim("tenant-a", claim["claim_token"], "completed")
        self.assertEqual(done["status"], "completed")
        self.assertEqual(done["created_at"], receipt["created_at"])

    # -- finish_claim -----------------------------------------------------

    def test_finish_completed_and_failed(self):
        store = self._store()
        one = self._submit(store, key="key-1")
        two = self._submit(store, key="key-2")
        c1 = store.claim_next("tenant-a", "w", 60)
        c2 = store.claim_next("tenant-a", "w", 60)
        done = store.finish_claim("tenant-a", c1["claim_token"], "completed")
        failed = store.finish_claim("tenant-a", c2["claim_token"], "failed")
        self.assertEqual(set(done), {"request_id", "status", "created_at"})
        self.assertEqual(
            done,
            {"request_id": one["request_id"], "status": "completed",
             "created_at": one["created_at"]},
        )
        self.assertEqual(failed["status"], "failed")
        self.assertEqual(store.get("tenant-a", one["request_id"]), done)
        self.assertEqual(
            [e["status"] for e in store.audit("tenant-a", one["request_id"])],
            ["accepted", "processing", "completed"],
        )
        self.assertEqual(
            [e["status"] for e in store.audit("tenant-a", two["request_id"])],
            ["accepted", "processing", "failed"],
        )
        for receipt in (one, two):
            self.assertTrue(store.verify_evidence("tenant-a", receipt["request_id"]))
        # Finished requests never rejoin the queue.
        self.assertIsNone(store.claim_next("tenant-a", "w", 60))

    def test_unknown_token_raises_not_found(self):
        store = self._store()
        self._submit(store)
        with self.assertRaises(RequestNotFound):
            store.finish_claim("tenant-a", "0" * 64, "completed")

    def test_cross_tenant_token_raises_not_found_and_stays_usable(self):
        store = self._store()
        receipt = self._submit(store, tenant="tenant-a")
        claim = store.claim_next("tenant-a", "w-a", 3600)
        with self.assertRaises(RequestNotFound):
            store.finish_claim("tenant-b", claim["claim_token"], "completed")
        # The foreign presentation neither moved the request nor spent the
        # owner's token.
        self.assertEqual(
            store.get("tenant-a", receipt["request_id"])["status"], "processing"
        )
        done = store.finish_claim("tenant-a", claim["claim_token"], "completed")
        self.assertEqual(done["status"], "completed")

    def test_expired_token_conflicts_without_writes(self):
        store = self._store()
        receipt = self._submit(store)
        claim = store.claim_next("tenant-a", "w", 1)
        time.sleep(1.1)
        with self.assertRaises(ClaimConflict):
            store.finish_claim("tenant-a", claim["claim_token"], "completed")
        self.assertEqual(
            store.get("tenant-a", receipt["request_id"])["status"], "processing"
        )
        self.assertEqual(
            [e["status"] for e in store.audit("tenant-a", receipt["request_id"])],
            ["accepted", "processing"],
        )
        with sqlite3.connect(self.db_path) as conn:
            self.assertEqual(
                conn.execute(
                    "SELECT count(*) FROM request_claims WHERE finished_at IS NOT NULL"
                ).fetchone()[0],
                0,
            )

    def test_superseded_token_conflicts(self):
        store = self._store()
        self._submit(store)
        first = store.claim_next("tenant-a", "w1", 1)
        time.sleep(1.1)
        second = store.claim_next("tenant-a", "w2", 3600)
        with self.assertRaises(ClaimConflict):
            store.finish_claim("tenant-a", first["claim_token"], "completed")
        # Only the current lease completes.
        done = store.finish_claim("tenant-a", second["claim_token"], "completed")
        self.assertEqual(done["status"], "completed")

    def test_spent_token_conflicts(self):
        store = self._store()
        self._submit(store)
        claim = store.claim_next("tenant-a", "w", 3600)
        store.finish_claim("tenant-a", claim["claim_token"], "completed")
        with self.assertRaises(ClaimConflict):
            store.finish_claim("tenant-a", claim["claim_token"], "failed")

    def test_in_memory_store_supports_claims(self):
        store = RequestStore(":memory:")
        receipt = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        claim = store.claim_next("tenant-a", "w", 60)
        self.assertEqual(claim["request_id"], receipt["request_id"])
        self.assertIsNone(store.claim_next("tenant-a", "w", 60))
        self.assertEqual(
            store.finish_claim("tenant-a", claim["claim_token"], "failed")["status"],
            "failed",
        )

    # -- concurrency ------------------------------------------------------

    def test_concurrent_claimers_get_disjoint_requests(self):
        store = self._store()
        n = 40
        for i in range(n):
            self._submit(store, key=f"key-{i}")
        claims = []

        def claim_until_empty(_):
            local = []
            while True:
                claim = store.claim_next("tenant-a", "worker", 3600)
                if claim is None:
                    break
                local.append(claim)
            claims.extend(local)
            return local

        with ThreadPoolExecutor(max_workers=16) as pool:
            list(pool.map(claim_until_empty, range(16)))
        ids = [c["request_id"] for c in claims]
        self.assertEqual(len(ids), n)
        self.assertEqual(len(set(ids)), n)
        # Every request holds exactly one live lease.
        with sqlite3.connect(self.db_path) as conn:
            dupes = conn.execute(
                "SELECT count(*) FROM ("
                "SELECT tenant_id, request_id FROM request_claims "
                "WHERE finished_at IS NULL "
                "GROUP BY tenant_id, request_id HAVING count(*) > 1)"
            ).fetchone()[0]
            live = conn.execute(
                "SELECT count(*) FROM request_claims WHERE finished_at IS NULL"
            ).fetchone()[0]
        self.assertEqual(dupes, 0)
        self.assertEqual(live, n)

    def test_concurrent_claim_and_finish_completes_each_once(self):
        store = self._store()
        n = 40
        for i in range(n):
            self._submit(store, key=f"key-{i}")

        def work(_):
            count = 0
            while True:
                claim = store.claim_next("tenant-a", "worker", 3600)
                if claim is None:
                    return count
                store.finish_claim("tenant-a", claim["claim_token"], "completed")
                count += 1

        with ThreadPoolExecutor(max_workers=16) as pool:
            counts = list(pool.map(work, range(16)))
        self.assertEqual(sum(counts), n)
        with sqlite3.connect(self.db_path) as conn:
            self.assertEqual(
                conn.execute(
                    "SELECT count(*) FROM requests WHERE status='completed'"
                ).fetchone()[0],
                n,
            )
            self.assertEqual(
                conn.execute(
                    "SELECT count(*) FROM request_claims WHERE finished_at IS NULL"
                ).fetchone()[0],
                0,
            )

    # -- secrecy ----------------------------------------------------------

    def test_raw_token_never_stored_at_rest(self):
        store = self._store()
        self._submit(store)
        claim = store.claim_next("tenant-a", "worker-SECRET", 60)
        token = claim["claim_token"]
        with sqlite3.connect(self.db_path) as conn:
            stored = [
                row[0]
                for row in conn.execute("SELECT claim_token_hash FROM request_claims")
            ]
        self.assertEqual(len(stored), 1)
        self.assertNotEqual(stored[0], token)
        self.assertRegex(stored[0], HEX64)

    def test_errors_and_logs_do_not_leak_claim_secrets(self):
        store = self._store()
        self._submit(store)
        claim = store.claim_next("tenant-a", "worker-SECRET", 1)
        token = claim["claim_token"]
        time.sleep(1.1)
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        logger = logging.getLogger("forgetting_evidence.requests")
        logger.addHandler(handler)
        old_level = logger.level
        logger.setLevel(logging.INFO)
        try:
            with self.assertRaises(ClaimConflict):
                store.finish_claim("tenant-a", token, "completed")
            with self.assertRaises(RequestNotFound):
                store.finish_claim("tenant-b", token, "completed")
        finally:
            logger.removeHandler(handler)
            logger.setLevel(old_level)
        logs = stream.getvalue()
        self.assertNotIn(token, logs)
        self.assertNotIn("worker-SECRET", logs)
        self.assertNotIn(token, str(ClaimConflict("claim is not active")) or "")

    def test_expired_reclaim_works_across_rebuilt_store(self):
        first = self._store()
        receipt = self._submit(first)
        first.claim_next("tenant-a", "w1", 1)
        time.sleep(1.1)
        rebuilt = RequestStore(self.db_path)
        claim = rebuilt.claim_next("tenant-a", "w2", 3600)
        self.assertIsNotNone(claim)
        self.assertEqual(claim["request_id"], receipt["request_id"])
        self.assertEqual(
            rebuilt.finish_claim("tenant-a", claim["claim_token"], "completed")[
                "status"
            ],
            "completed",
        )


def stamp2026():
    return "2026-01-02T00:00:00.000000Z"


if __name__ == "__main__":
    unittest.main()
