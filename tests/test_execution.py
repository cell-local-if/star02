"""Tests for the deletion-execution orchestration chain.

Covers claim_next / finish_claim / get_execution_log on the storage layer
only: leasing and the processing transition, expiry-driven reclaims,
attempt sequencing, terminal results, conflict/validation/not-found
semantics, persistence across rebuilds, concurrent exclusivity, evidence
chain integrity and the no-leak guarantees. These entry points are
deliberately not exposed over HTTP.
"""

import http.client
import io
import logging
import os
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from forgetting_evidence import httpapi
from forgetting_evidence.httpapi import build_server
from forgetting_evidence.requests import (
    ClaimConflict,
    RequestNotFound,
    RequestStore,
)

from forgetting_evidence.requests import (
    _GENESIS_PREDECESSOR,
    _chain_hash,
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


class ClaimNextTests(_StoreCase):
    def test_claim_shape_and_enters_processing(self):
        store = self._store()
        receipt = self._submit(store)
        claim = store.claim_next("tenant-a", "worker-1", 60)
        self.assertIsNotNone(claim)
        self.assertEqual(
            list(claim), ["request_id", "claim_token", "lease_expires_at"]
        )
        self.assertEqual(set(claim), {"request_id", "claim_token", "lease_expires_at"})
        self.assertEqual(claim["request_id"], receipt["request_id"])
        self.assertIsInstance(claim["claim_token"], str)
        self.assertGreaterEqual(len(claim["claim_token"]), 40)
        expires = _parse_utc(claim["lease_expires_at"])
        self.assertEqual(expires.utcoffset().total_seconds(), 0)
        # The first claim moves accepted -> processing.
        self.assertEqual(
            store.get_status("tenant-a", receipt["request_id"])["status"],
            "processing",
        )
        # The acceptance receipt and acceptance time are untouched.
        self.assertEqual(store.get("tenant-a", receipt["request_id"]), receipt)

    def test_lease_duration_is_honoured_at_the_boundaries(self):
        store = self._store()
        self._submit(store, key="k1")
        one = store.claim_next("tenant-a", "w", 1)
        self.assertIsNotNone(one)
        self._submit(store, key="k2")
        max_lease = store.claim_next("tenant-a", "w", 3600)
        self.assertIsNotNone(max_lease)
        log1 = store.get_execution_log("tenant-a", one["request_id"])[0]
        delta = _parse_utc(log1["lease_expires_at"]) - _parse_utc(log1["claimed_at"])
        self.assertEqual(delta.total_seconds(), 1.0)
        log2 = store.get_execution_log("tenant-a", max_lease["request_id"])[0]
        delta = _parse_utc(log2["lease_expires_at"]) - _parse_utc(log2["claimed_at"])
        self.assertEqual(delta.total_seconds(), 3600.0)

    def test_claims_drain_oldest_accepted_first(self):
        store = self._store()
        first = self._submit(store, key="k1")
        second = self._submit(store, key="k2")
        third = self._submit(store, key="k3")
        order = []
        for _ in range(3):
            claim = store.claim_next("tenant-a", "worker", 60)
            self.assertIsNotNone(claim)
            order.append(claim["request_id"])
        self.assertEqual(order, [first["request_id"], second["request_id"], third["request_id"]])

    def test_acceptance_time_tie_breaks_by_request_id(self):
        # Two rows accepted at the identical instant must come out in
        # ascending request_id order (white-box insert with a valid genesis).
        created_at = "2026-01-01T00:00:00.000000Z"
        low, high = "aaa-0002", "zzz-0001"
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        with sqlite3.connect(self.db_path) as raw:
            raw.execute(
                "CREATE TABLE IF NOT EXISTS requests ("
                "request_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, "
                "idempotency_key TEXT NOT NULL, subject_id TEXT NOT NULL, "
                "scopes_json TEXT NOT NULL, status TEXT NOT NULL, "
                "created_at TEXT NOT NULL, chain_hash TEXT NOT NULL)"
            )
            raw.execute(
                "CREATE TABLE IF NOT EXISTS status_events ("
                "tenant_id TEXT NOT NULL, request_id TEXT NOT NULL, "
                "seq INTEGER NOT NULL, status TEXT NOT NULL, "
                "occurred_at TEXT NOT NULL, chain_hash TEXT NOT NULL, "
                "PRIMARY KEY (tenant_id, request_id, seq))"
            )
            for rid in (low, high):
                genesis = _chain_hash(
                    "tenant-a", rid, 0, "accepted", created_at, _GENESIS_PREDECESSOR
                )
                raw.execute(
                    "INSERT INTO requests VALUES (?, 'tenant-a', ?, 's', '[]', "
                    "'accepted', ?, ?)",
                    (rid, f"key-{rid}", created_at, genesis),
                )
                raw.execute(
                    "INSERT INTO status_events VALUES (?, ?, 0, 'accepted', ?, ?)",
                    ("tenant-a", rid, created_at, genesis),
                )
        store = self._store()
        first = store.claim_next("tenant-a", "w", 60)
        second = store.claim_next("tenant-a", "w", 60)
        self.assertEqual([first["request_id"], second["request_id"]], [low, high])

    def test_no_candidate_returns_none(self):
        store = self._store()
        self.assertIsNone(store.claim_next("tenant-a", "worker", 60))
        self._submit(store)
        self.assertIsNotNone(store.claim_next("tenant-a", "worker", 60))
        # The only request is now processing with a live lease.
        self.assertIsNone(store.claim_next("tenant-a", "worker", 60))

    def test_claims_are_partitioned_per_tenant(self):
        store = self._store()
        a = self._submit(store, tenant="tenant-a", key="ka")
        b = self._submit(store, tenant="tenant-b", key="kb")
        claim_a = store.claim_next("tenant-a", "wa", 60)
        claim_b = store.claim_next("tenant-b", "wb", 60)
        self.assertEqual(claim_a["request_id"], a["request_id"])
        self.assertEqual(claim_b["request_id"], b["request_id"])
        # Each tenant independently has nothing left to claim.
        self.assertIsNone(store.claim_next("tenant-a", "wa", 60))
        self.assertIsNone(store.claim_next("tenant-b", "wb", 60))

    def test_claim_tokens_are_unpredictable_and_distinct(self):
        store = self._store()
        self._submit(store, key="k1")
        self._submit(store, key="k2")
        first = store.claim_next("tenant-a", "worker", 60)
        second = store.claim_next("tenant-a", "worker", 60)
        self.assertNotEqual(first["claim_token"], second["claim_token"])
        for claim in (first, second):
            token = claim["claim_token"]
            # URL-safe opaque secret, never a request or worker identifier.
            self.assertRegex(token, r"^[A-Za-z0-9_-]+$")
            self.assertNotEqual(token, claim["request_id"])
            self.assertNotEqual(token, "worker")


class ExpiryReclaimTests(_StoreCase):
    def test_live_lease_is_not_reclaimed(self):
        store = self._store()
        receipt = self._submit(store)
        store.claim_next("tenant-a", "worker-1", 3600)
        # Even a different worker cannot take a live lease.
        self.assertIsNone(store.claim_next("tenant-a", "worker-2", 3600))
        self.assertEqual(
            store.get_status("tenant-a", receipt["request_id"])["status"],
            "processing",
        )

    def test_expired_lease_is_reclaimed_as_next_attempt(self):
        store = self._store()
        receipt = self._submit(store)
        first = store.claim_next("tenant-a", "worker-1", 1)
        self.assertIsNone(store.claim_next("tenant-a", "worker-2", 1))
        _wait_for_expiry()
        second = store.claim_next("tenant-a", "worker-2", 60)
        self.assertIsNotNone(second)
        self.assertEqual(second["request_id"], receipt["request_id"])
        # Reclaim issues a fresh credential.
        self.assertNotEqual(first["claim_token"], second["claim_token"])
        # No status rewrite: stays processing, same id, same acceptance time.
        status = store.get_status("tenant-a", receipt["request_id"])
        self.assertEqual(status["status"], "processing")
        self.assertEqual(status["created_at"], receipt["created_at"])
        # The audit timeline gains no second processing event.
        self.assertEqual(
            [e["status"] for e in store.audit("tenant-a", receipt["request_id"])],
            ["accepted", "processing"],
        )
        numbers = [
            a["attempt_number"]
            for a in store.get_execution_log("tenant-a", receipt["request_id"])
        ]
        self.assertEqual(numbers, [1, 2])

    def test_old_token_cannot_finish_after_reclaim(self):
        store = self._store()
        receipt = self._submit(store)
        stale = store.claim_next("tenant-a", "worker-1", 1)
        _wait_for_expiry()
        current = store.claim_next("tenant-a", "worker-2", 60)
        with self.assertRaises(ClaimConflict):
            store.finish_claim(
                "tenant-a", receipt["request_id"], stale["claim_token"], "completed"
            )
        # The successor token still works and reaches a terminal state.
        done = store.finish_claim(
            "tenant-a", receipt["request_id"], current["claim_token"], "completed"
        )
        self.assertEqual(done["status"], "completed")

    def test_expired_processing_competes_by_acceptance_time(self):
        store = self._store()
        older = self._submit(store, key="k1")
        old_claim = store.claim_next("tenant-a", "w", 1)
        # A newer request arrives while the older one is processing.
        newer = self._submit(store, key="k2")
        _wait_for_expiry()
        # The expired, older request wins over the newer accepted one.
        reclaim = store.claim_next("tenant-a", "w", 60)
        self.assertEqual(reclaim["request_id"], older["request_id"])
        # Then the newer accepted request is claimed.
        after = store.claim_next("tenant-a", "w", 60)
        self.assertEqual(after["request_id"], newer["request_id"])
        # The abandoned first attempt is still recorded, open.
        log = store.get_execution_log("tenant-a", older["request_id"])
        self.assertEqual(log[0]["attempt_number"], 1)
        self.assertIsNone(log[0]["result"])
        self.assertEqual(log[1]["attempt_number"], 2)

    def test_terminal_request_is_never_reclaimed(self):
        store = self._store()
        receipt = self._submit(store)
        claim = store.claim_next("tenant-a", "w", 1)
        store.finish_claim("tenant-a", receipt["request_id"], claim["claim_token"], "completed")
        self._submit(store, key="k2")
        _wait_for_expiry()
        # The completed request never reappears; the new accepted one wins.
        nxt = store.claim_next("tenant-a", "w", 1)
        self.assertIsNotNone(nxt)
        self.assertNotEqual(nxt["request_id"], receipt["request_id"])


class FinishClaimTests(_StoreCase):
    def test_finish_completed_and_failed(self):
        for result in ("completed", "failed"):
            store = self._store()
            receipt = self._submit(store, key=f"key-{result}")
            claim = store.claim_next("tenant-a", "w", 60)
            record = store.finish_claim(
                "tenant-a", receipt["request_id"], claim["claim_token"], result
            )
            self.assertEqual(
                list(record), ["request_id", "status", "created_at"]
            )
            self.assertEqual(record["request_id"], receipt["request_id"])
            self.assertEqual(record["status"], result)
            self.assertEqual(record["created_at"], receipt["created_at"])
            self.assertEqual(
                store.get_status("tenant-a", receipt["request_id"])["status"], result
            )

    def test_finish_is_single_use(self):
        store = self._store()
        receipt = self._submit(store)
        claim = store.claim_next("tenant-a", "w", 60)
        store.finish_claim(
            "tenant-a", receipt["request_id"], claim["claim_token"], "completed"
        )
        # The released token cannot finish again.
        with self.assertRaises(ClaimConflict):
            store.finish_claim(
                "tenant-a", receipt["request_id"], claim["claim_token"], "failed"
            )
        # State stays at the first terminal result.
        self.assertEqual(
            store.get_status("tenant-a", receipt["request_id"])["status"], "completed"
        )

    def test_finish_without_a_claim_conflicts(self):
        store = self._store()
        receipt = self._submit(store)
        with self.assertRaises(ClaimConflict):
            store.finish_claim(
                "tenant-a", receipt["request_id"], "never-issued-token", "completed"
            )
        self.assertEqual(
            store.get_status("tenant-a", receipt["request_id"])["status"], "accepted"
        )

    def test_finish_after_expiry_conflicts_and_state_unchanged(self):
        store = self._store()
        receipt = self._submit(store)
        claim = store.claim_next("tenant-a", "w", 1)
        _wait_for_expiry()
        with self.assertRaises(ClaimConflict):
            store.finish_claim(
                "tenant-a", receipt["request_id"], claim["claim_token"], "completed"
            )
        self.assertEqual(
            store.get_status("tenant-a", receipt["request_id"])["status"], "processing"
        )


class ExecutionLogTests(_StoreCase):
    def test_open_attempt_shape(self):
        store = self._store()
        receipt = self._submit(store)
        store.claim_next("tenant-a", "w", 60)
        log = store.get_execution_log("tenant-a", receipt["request_id"])
        self.assertEqual(len(log), 1)
        entry = log[0]
        self.assertEqual(
            list(entry),
            [
                "attempt_number",
                "claimed_at",
                "lease_expires_at",
                "result",
                "completed_at",
            ],
        )
        self.assertEqual(entry["attempt_number"], 1)
        self.assertIsInstance(entry["attempt_number"], int)
        self.assertNotIsInstance(entry["attempt_number"], bool)
        for key in ("claimed_at", "lease_expires_at"):
            self.assertIsInstance(entry[key], str)
            self.assertEqual(_parse_utc(entry[key]).utcoffset().total_seconds(), 0)
        # In progress: result and completion time are null.
        self.assertIsNone(entry["result"])
        self.assertIsNone(entry["completed_at"])
        # Only str/int/None ever appear -- never float, bool or bytes.
        for value in entry.values():
            self.assertIsInstance(value, (str, int, type(None)))
            self.assertNotIsInstance(value, bool)
            self.assertNotIsInstance(value, float)

    def test_finished_attempt_records_only_terminal(self):
        store = self._store()
        receipt = self._submit(store)
        claim = store.claim_next("tenant-a", "w", 60)
        store.finish_claim(
            "tenant-a", receipt["request_id"], claim["claim_token"], "failed"
        )
        entry = store.get_execution_log("tenant-a", receipt["request_id"])[0]
        self.assertEqual(entry["attempt_number"], 1)
        self.assertEqual(entry["result"], "failed")
        self.assertIsInstance(entry["completed_at"], str)
        self.assertEqual(_parse_utc(entry["completed_at"]).utcoffset().total_seconds(), 0)
        # The recorded result is the terminal status, never "processing".
        self.assertIn(entry["result"], ("completed", "failed"))
        # No credential or worker field is present.
        rendered = repr(entry)
        self.assertNotIn(claim["claim_token"], rendered)
        self.assertNotIn("worker", rendered)

    def test_attempt_numbers_increment_from_one(self):
        store = self._store()
        receipt = self._submit(store)
        for expected in (1, 2, 3):
            claim = store.claim_next("tenant-a", "w", 1)
            numbers = [
                a["attempt_number"]
                for a in store.get_execution_log("tenant-a", receipt["request_id"])
            ]
            self.assertEqual(numbers, list(range(1, expected + 1)))
            if expected < 3:
                _wait_for_expiry()
        # Finish the last attempt; earlier abandoned attempts stay open.
        store.finish_claim("tenant-a", receipt["request_id"], claim["claim_token"], "completed")
        log = store.get_execution_log("tenant-a", receipt["request_id"])
        self.assertEqual([a["result"] for a in log], [None, None, "completed"])
        self.assertEqual([a["completed_at"] is None for a in log], [True, True, False])

    def test_log_is_partitioned_per_tenant_and_request(self):
        store = self._store()
        one = self._submit(store, key="k1")
        two = self._submit(store, key="k2")
        store.claim_next("tenant-a", "w", 60)
        store.claim_next("tenant-a", "w", 60)
        log_one = store.get_execution_log("tenant-a", one["request_id"])
        log_two = store.get_execution_log("tenant-a", two["request_id"])
        self.assertEqual(len(log_one), 1)
        self.assertEqual(len(log_two), 1)
        # Entries never carry the request id, worker or credential fields.
        for entry in (log_one[0], log_two[0]):
            self.assertNotIn("request_id", entry)
            self.assertNotIn("worker_id", entry)
            self.assertNotIn("claim_token", entry)

    def test_log_missing_invalid_and_cross_tenant(self):
        store = self._store()
        receipt = self._submit(store)
        store.claim_next("tenant-a", "w", 60)
        for bad in ("", None, 7, b"x", ["x"], "not-a-uuid"):
            with self.subTest(bad=bad):
                with self.assertRaises(RequestNotFound):
                    store.get_execution_log("tenant-a", bad)
        with self.assertRaises(RequestNotFound):
            store.get_execution_log("tenant-a", "does-not-exist")
        with self.assertRaises(RequestNotFound):
            store.get_execution_log("tenant-b", receipt["request_id"])
        for bad in ("", None, 7):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    store.get_execution_log(bad, receipt["request_id"])


class ExecutionValidationTests(_StoreCase):
    def test_claim_next_validates_arguments_without_writing(self):
        store = self._store()
        receipt = self._submit(store)
        for bad in ("", None, 7, b"t", ["t"], True):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    store.claim_next(bad, "worker", 60)
                with self.assertRaises(ValueError):
                    store.claim_next("tenant-a", bad, 60)
        # Lease must be a non-boolean integer in 1..3600.
        for bad in (0, -1, 3601, 10_000, 1.0, 0.5, True, False, "60", None, [60]):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    store.claim_next("tenant-a", "worker", bad)
        # Every rejected call left the request unclaimed and unmodified:
        # no attempt rows exist and the request is still accepted.
        self.assertEqual(
            store.get_status("tenant-a", receipt["request_id"])["status"],
            "accepted",
        )
        with sqlite3.connect(self.db_path) as conn:
            self.assertEqual(
                conn.execute("SELECT count(*) FROM claim_attempts").fetchone()[0], 0
            )
            self.assertEqual(
                conn.execute("SELECT status FROM requests").fetchone()[0],
                "accepted",
            )
        # The candidate was never consumed: a valid call now claims it.
        self.assertIsNotNone(store.claim_next("tenant-a", "worker", 60))

    def test_finish_validates_result_without_writing(self):
        store = self._store()
        receipt = self._submit(store)
        claim = store.claim_next("tenant-a", "w", 60)
        for bad in ("cancelled", "PROCESSING", "accepted", " done", "", None, 7, True):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    store.finish_claim(
                        "tenant-a", receipt["request_id"], claim["claim_token"], bad
                    )
        for bad in (None, 7, b"token", ["token"], ""):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    store.finish_claim("tenant-a", receipt["request_id"], bad, "completed")
        # No result recorded and the request is still processing.
        entry = store.get_execution_log("tenant-a", receipt["request_id"])[0]
        self.assertIsNone(entry["result"])
        self.assertEqual(
            store.get_status("tenant-a", receipt["request_id"])["status"], "processing"
        )

    def test_nonempty_unknown_token_string_is_conflict_not_value_error(self):
        store = self._store()
        receipt = self._submit(store)
        store.claim_next("tenant-a", "w", 60)
        for token in ("no-such-token", "deadbeef", "a" * 43):
            with self.subTest(token=token):
                with self.assertRaises(ClaimConflict):
                    store.finish_claim(
                        "tenant-a", receipt["request_id"], token, "completed"
                    )


class ClaimConflictAccessTests(_StoreCase):
    def test_foreign_and_misrouted_tokens_conflict_without_change(self):
        store = self._store()
        a = self._submit(store, tenant="tenant-a", key="ka")
        b = self._submit(store, tenant="tenant-b", key="kb")
        claim_a = store.claim_next("tenant-a", "wa", 60)
        claim_b = store.claim_next("tenant-b", "wb", 60)
        # Cross-tenant use of a live credential.
        with self.assertRaises(ClaimConflict):
            store.finish_claim("tenant-b", b["request_id"], claim_a["claim_token"], "completed")
        with self.assertRaises(ClaimConflict):
            store.finish_claim("tenant-a", a["request_id"], claim_b["claim_token"], "completed")
        # Real credential presented against the wrong (or unknown) request id.
        with self.assertRaises(ClaimConflict):
            store.finish_claim(
                "tenant-a", b["request_id"], claim_a["claim_token"], "completed"
            )
        with self.assertRaises(ClaimConflict):
            store.finish_claim(
                "tenant-a",
                "00000000-0000-4000-8000-000000000000",
                claim_a["claim_token"],
                "completed",
            )
        # Nothing moved.
        self.assertEqual(store.get_status("tenant-a", a["request_id"])["status"], "processing")
        self.assertEqual(store.get_status("tenant-b", b["request_id"])["status"], "processing")

    def test_conflict_text_leaks_no_detail(self):
        store = self._store()
        receipt = self._submit(store)
        store.claim_next("tenant-a", "w", 60)
        try:
            store.finish_claim("tenant-a", receipt["request_id"], "nope", "completed")
        except ClaimConflict as exc:
            message = str(exc)
        else:
            self.fail("expected ClaimConflict")
        self.assertEqual(message, "claim conflict")
        self.assertNotIn(receipt["request_id"], message)


class ExecutionPersistenceTests(_StoreCase):
    def test_open_lease_and_log_survive_restart(self):
        first = self._store()
        receipt = first.submit("tenant-a", "subject-1", ["email"], "key-1")
        claim = first.claim_next("tenant-a", "worker-1", 3600)
        rebuilt = self._store()
        # The lease is still live after a rebuild and can be finished.
        record = rebuilt.finish_claim(
            "tenant-a", receipt["request_id"], claim["claim_token"], "completed"
        )
        self.assertEqual(record["status"], "completed")
        entry = rebuilt.get_execution_log("tenant-a", receipt["request_id"])[0]
        self.assertEqual(entry["attempt_number"], 1)
        self.assertEqual(entry["result"], "completed")
        self.assertTrue(rebuilt.verify_evidence("tenant-a", receipt["request_id"]))

    def test_expired_reclaim_after_restart(self):
        first = self._store()
        receipt = first.submit("tenant-a", "subject-1", ["email"], "key-1")
        first.claim_next("tenant-a", "worker-1", 1)
        rebuilt = self._store()
        _wait_for_expiry()
        claim = rebuilt.claim_next("tenant-a", "worker-2", 60)
        self.assertEqual(claim["request_id"], receipt["request_id"])
        self.assertEqual(
            [a["attempt_number"] for a in rebuilt.get_execution_log("tenant-a", receipt["request_id"])],
            [1, 2],
        )


class ExecutionConcurrencyTests(_StoreCase):
    def test_concurrent_claims_never_double_lease_one_request(self):
        store = self._store()
        self._submit(store)

        def claim(index):
            return store.claim_next("tenant-a", f"worker-{index}", 3600)

        with ThreadPoolExecutor(max_workers=16) as pool:
            results = list(pool.map(claim, range(32)))
        winners = [r for r in results if r is not None]
        self.assertEqual(len(winners), 1)
        with sqlite3.connect(self.db_path) as conn:
            self.assertEqual(
                conn.execute("SELECT count(*) FROM claim_tokens").fetchone()[0], 1
            )
            self.assertEqual(
                conn.execute("SELECT count(*) FROM claim_attempts").fetchone()[0], 1
            )

    def test_concurrent_claims_give_each_request_one_holder(self):
        store = self._store()
        for index in range(40):
            self._submit(store, key=f"key-{index}", subject=f"subject-{index}")

        def claim(index):
            return store.claim_next("tenant-a", f"worker-{index}", 3600)

        with ThreadPoolExecutor(max_workers=16) as pool:
            results = list(pool.map(claim, range(40)))
        winners = [r for r in results if r is not None]
        self.assertEqual(len(winners), 40)
        self.assertEqual(len({w["request_id"] for w in winners}), 40)
        self.assertIsNone(store.claim_next("tenant-a", "worker", 3600))

    def test_concurrent_finish_has_one_deterministic_winner(self):
        store = self._store()
        receipt = self._submit(store)
        claim = store.claim_next("tenant-a", "w", 3600)

        def finish(result):
            try:
                return store.finish_claim(
                    "tenant-a", receipt["request_id"], claim["claim_token"], result
                )
            except ClaimConflict:
                return None

        with ThreadPoolExecutor(max_workers=16) as pool:
            outcomes = list(pool.map(finish, ("completed", "failed") * 16))
        records = [o for o in outcomes if o is not None]
        self.assertEqual(len(records), 1)
        final = store.get_status("tenant-a", receipt["request_id"])["status"]
        self.assertIn(final, ("completed", "failed"))
        self.assertEqual(records[0]["status"], final)
        self.assertTrue(store.verify_evidence("tenant-a", receipt["request_id"]))
        # Exactly one terminal event and one finished attempt row.
        self.assertEqual(
            [e["status"] for e in store.audit("tenant-a", receipt["request_id"])],
            ["accepted", "processing", final],
        )


class ExecutionEvidenceTests(_StoreCase):
    def test_chain_verifies_through_claim_and_finish(self):
        store = self._store()
        receipt = self._submit(store)
        claim = store.claim_next("tenant-a", "w", 1)
        self.assertTrue(store.verify_evidence("tenant-a", receipt["request_id"]))
        _wait_for_expiry()
        claim = store.claim_next("tenant-a", "w", 60)  # reclaim adds no event
        self.assertTrue(store.verify_evidence("tenant-a", receipt["request_id"]))
        store.finish_claim("tenant-a", receipt["request_id"], claim["claim_token"], "failed")
        self.assertTrue(store.verify_evidence("tenant-a", receipt["request_id"]))
        evidence = store.evidence("tenant-a", receipt["request_id"])
        self.assertEqual(evidence["status"], "failed")
        self.assertEqual(evidence["event_count"], 3)


class ExecutionNoLeakTests(_StoreCase):
    def test_worker_and_token_never_persisted_or_returned(self):
        worker_secret = "worker-SECRET"
        store = self._store()
        receipt = self._submit(store)
        claim = store.claim_next("tenant-a", worker_secret, 60)
        token = claim["claim_token"]
        # Not present in any persisted table (only a hash is stored).
        with sqlite3.connect(self.db_path) as conn:
            for table in ("requests", "status_events", "claim_attempts", "claim_tokens"):
                rows = conn.execute(f"SELECT * FROM {table}").fetchall()
                rendered = repr(rows)
                self.assertNotIn(worker_secret, rendered)
            token_rows = conn.execute("SELECT token_hash FROM claim_tokens").fetchall()
        self.assertEqual(len(token_rows), 1)
        self.assertNotEqual(token_rows[0][0], token)
        # Absent from every execution return value.
        surfaces = [
            repr(claim),
            repr(store.get_execution_log("tenant-a", receipt["request_id"])),
        ]
        for surface in surfaces:
            self.assertNotIn(worker_secret, surface)
        # The raw credential is never echoed back after acquisition.
        store.finish_claim("tenant-a", receipt["request_id"], token, "completed")
        self.assertNotIn(
            token,
            repr(store.get_execution_log("tenant-a", receipt["request_id"])),
        )

    def test_logs_do_not_leak_worker_or_token(self):
        store = self._store()
        receipt = self._submit(store)
        claim = store.claim_next("tenant-a", "worker-SECRETLOG", 60)
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        logger = logging.getLogger("forgetting_evidence.requests")
        logger.addHandler(handler)
        old_level = logger.level
        logger.setLevel(logging.INFO)
        try:
            store.finish_claim(
                "tenant-a", receipt["request_id"], claim["claim_token"], "completed"
            )
        finally:
            logger.removeHandler(handler)
            logger.setLevel(old_level)
        emitted = stream.getvalue()
        self.assertNotIn("worker-SECRETLOG", emitted)
        self.assertNotIn(claim["claim_token"], emitted)


class ExecutionStorageErrorTests(_StoreCase):
    def _fixed_message(self, ctx):
        self.assertEqual(str(ctx.exception), "request store is unavailable")
        self.assertNotIn("sqlite", str(ctx.exception).lower())
        self.assertNotIn(self.db_path, str(ctx.exception))

    def test_damaged_schema_maps_to_os_error_and_writes_nothing(self):
        store = self._store()
        receipt = self._submit(store)
        # Damage the database out of band: remove the attempts table so any
        # claim/finish/log statement fails.
        with sqlite3.connect(self.db_path) as raw:
            raw.execute("DROP TABLE claim_attempts")
        with self.assertRaises(OSError) as ctx:
            store.claim_next("tenant-a", "w", 60)
        self._fixed_message(ctx)
        with self.assertRaises(OSError):
            store.get_execution_log("tenant-a", receipt["request_id"])
        # The failed claim rolled back fully: no processing state or event.
        with sqlite3.connect(self.db_path) as raw:
            self.assertEqual(
                raw.execute(
                    "SELECT status FROM requests WHERE request_id = ?",
                    (receipt["request_id"],),
                ).fetchone()[0],
                "accepted",
            )
            self.assertEqual(
                raw.execute(
                    "SELECT count(*) FROM status_events WHERE request_id = ?",
                    (receipt["request_id"],),
                ).fetchone()[0],
                1,
            )

    def test_corrupt_file_is_os_error_for_execution_calls(self):
        store = self._store()
        self._submit(store)
        with open(self.db_path, "wb") as handle:
            handle.write(b"not a sqlite database")
        with self.assertRaises(OSError) as ctx:
            store.claim_next("tenant-a", "w", 60)
        self._fixed_message(ctx)


class DeferredExecutionTests(_StoreCase):
    def test_execution_methods_are_proxied(self):
        store = httpapi.DeferredRequestStore(self.db_path)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        claim = store.claim_next("tenant-a", "worker-1", 60)
        self.assertEqual(claim["request_id"], receipt["request_id"])
        record = store.finish_claim(
            "tenant-a", receipt["request_id"], claim["claim_token"], "completed"
        )
        self.assertEqual(record["status"], "completed")
        log = store.get_execution_log("tenant-a", receipt["request_id"])
        self.assertEqual(log[0]["result"], "completed")

    def test_unavailable_storage_is_reported_consistently(self):
        blocker = os.path.join(self._tmp.name, "a-file")
        with open(blocker, "wb") as handle:
            handle.write(b"x")
        impossible = os.path.join(blocker, "nested", "evidence.db")
        store = httpapi.DeferredRequestStore(impossible)
        for call in (
            lambda: store.claim_next("tenant-a", "w", 60),
            lambda: store.finish_claim("tenant-a", "rid", "token", "completed"),
            lambda: store.get_execution_log("tenant-a", "rid"),
        ):
            with self.assertRaises(httpapi._StorageUnavailable):
                call()


class ExecutionHttpSurfaceTests(_StoreCase):
    """Execution orchestration must not gain an HTTP entry point."""

    def test_no_execution_routes_are_exposed(self):
        store = self._store()
        server = build_server(store, "127.0.0.1", 0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_address[1]
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            try:
                # Unknown collection-style paths are 404...
                for method, path in (
                    ("POST", "/claims"),
                    ("GET", "/execution-log"),
                ):
                    conn.request(method, path, body="{}")
                    resp = conn.getresponse()
                    resp.read()
                    self.assertEqual(resp.status, 404, (method, path, resp.status))
                # ...while an item-shaped sub-path is 405; either way no
                # execution entry point exists.
                conn.request("POST", "/requests/claim", body="{}")
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
