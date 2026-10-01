"""Tests for RequestStore.claim_next_global, the cross-tenant fair claim.

Covers the shared-worker-pool entry point on the storage layer only:
the fair tenant ordering (fewest live leases, then oldest acceptance
time and request id), single-transaction settlement, attempt sequencing
and token supersession on reclaim, interoperability with the per-tenant
renew/finish/reconcile/log entries, validation and fixed-text storage
failures, persistence across rebuilds, concurrent exclusivity and the
no-leak guarantees. No HTTP route is added for it.
"""

import io
import logging
import os
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from forgetting_evidence import httpapi
from forgetting_evidence.requests import (
    ClaimConflict,
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


class ClaimNextGlobalShapeTests(_StoreCase):
    def test_shape_and_enters_processing(self):
        store = self._store()
        receipt = self._submit(store)
        claim = store.claim_next_global("worker-1", 60)
        self.assertIsNotNone(claim)
        self.assertEqual(
            list(claim),
            ["tenant_id", "request_id", "claim_token", "lease_expires_at"],
        )
        self.assertEqual(claim["tenant_id"], "tenant-a")
        self.assertEqual(claim["request_id"], receipt["request_id"])
        self.assertIsInstance(claim["claim_token"], str)
        self.assertGreaterEqual(len(claim["claim_token"]), 40)
        expires = _parse_utc(claim["lease_expires_at"])
        self.assertEqual(expires.utcoffset().total_seconds(), 0)
        # The first claim moves accepted -> processing with attempt 1.
        self.assertEqual(
            store.get_status("tenant-a", receipt["request_id"])["status"],
            "processing",
        )
        log = store.get_execution_log("tenant-a", receipt["request_id"])
        self.assertEqual([entry["attempt_number"] for entry in log], [1])
        # The acceptance receipt and acceptance time are untouched.
        self.assertEqual(store.get("tenant-a", receipt["request_id"]), receipt)

    def test_no_candidate_returns_none(self):
        store = self._store()
        self.assertIsNone(store.claim_next_global("worker", 60))
        self._submit(store)
        self.assertIsNotNone(store.claim_next_global("worker", 60))
        # The only request is now processing with a live lease.
        self.assertIsNone(store.claim_next_global("worker", 60))

    def test_lease_duration_is_honoured(self):
        store = self._store()
        self._submit(store, key="k1")
        claim = store.claim_next_global("w", 1)
        self.assertIsNotNone(claim)
        log = store.get_execution_log("tenant-a", claim["request_id"])[0]
        delta = _parse_utc(log["lease_expires_at"]) - _parse_utc(log["claimed_at"])
        self.assertEqual(delta.total_seconds(), 1.0)

    def test_terminal_request_is_never_a_candidate(self):
        store = self._store()
        receipt = self._submit(store)
        claim = store.claim_next_global("w", 60)
        store.finish_claim(
            "tenant-a", receipt["request_id"], claim["claim_token"], "completed"
        )
        self.assertIsNone(store.claim_next_global("w", 60))


class ClaimNextGlobalFairnessTests(_StoreCase):
    def test_fewest_live_leases_wins_then_tie_by_acceptance(self):
        store = self._store()
        r1 = self._submit(store, tenant="tenant-a", key="a1")
        r2 = self._submit(store, tenant="tenant-a", key="a2")
        r3 = self._submit(store, tenant="tenant-b", key="b1")
        # All tenants at zero live leases: the oldest candidate overall.
        first = store.claim_next_global("w", 60)
        self.assertEqual(
            (first["tenant_id"], first["request_id"]),
            ("tenant-a", r1["request_id"]),
        )
        # tenant-a now holds one live lease; tenant-b has none, so the
        # older tenant-a candidate must wait behind tenant-b's request.
        second = store.claim_next_global("w", 60)
        self.assertEqual(
            (second["tenant_id"], second["request_id"]),
            ("tenant-b", r3["request_id"]),
        )
        # Back to a tie at one live lease each: oldest acceptance wins.
        third = store.claim_next_global("w", 60)
        self.assertEqual(
            (third["tenant_id"], third["request_id"]),
            ("tenant-a", r2["request_id"]),
        )
        self.assertIsNone(store.claim_next_global("w", 60))

    def test_finishing_frees_capacity_for_the_tenant(self):
        store = self._store()
        r1 = self._submit(store, tenant="tenant-a", key="a1")
        r2 = self._submit(store, tenant="tenant-a", key="a2")
        self._submit(store, tenant="tenant-b", key="b1")
        first = store.claim_next_global("w", 60)
        self.assertEqual(first["request_id"], r1["request_id"])
        # Finishing releases tenant-a's live lease, so tenant-a is again
        # the least-loaded tenant and its older candidate wins over b's.
        store.finish_claim("tenant-a", r1["request_id"], first["claim_token"], "completed")
        second = store.claim_next_global("w", 60)
        self.assertEqual(
            (second["tenant_id"], second["request_id"]),
            ("tenant-a", r2["request_id"]),
        )

    def test_expired_lease_does_not_count_as_live(self):
        store = self._store()
        r1 = self._submit(store, tenant="tenant-a", key="a1")
        claim = store.claim_next_global("w", 1)
        self.assertEqual(claim["request_id"], r1["request_id"])
        _wait_for_expiry()
        # tenant-a's lease lapsed, so it is back to zero live leases and
        # its expired request competes again by acceptance time.
        r2 = self._submit(store, tenant="tenant-b", key="b1")
        reclaim = store.claim_next_global("w", 60)
        self.assertEqual(
            (reclaim["tenant_id"], reclaim["request_id"]),
            ("tenant-a", r1["request_id"]),
        )
        # The reclaim is attempt 2 on the same request; acceptance time,
        # request id and the status timeline are unchanged.
        log = store.get_execution_log("tenant-a", r1["request_id"])
        self.assertEqual([entry["attempt_number"] for entry in log], [1, 2])
        self.assertEqual(store.get("tenant-a", r1["request_id"]), r1)
        with sqlite3.connect(self.db_path) as raw:
            events = raw.execute(
                "SELECT status FROM status_events "
                "WHERE tenant_id = 'tenant-a' AND request_id = ? ORDER BY seq",
                (r1["request_id"],),
            ).fetchall()
        self.assertEqual([row[0] for row in events], ["accepted", "processing"])
        # The next claim now goes to tenant-b, which has no live lease.
        following = store.claim_next_global("w", 60)
        self.assertEqual(
            (following["tenant_id"], following["request_id"]),
            ("tenant-b", r2["request_id"]),
        )

    def test_old_token_cannot_finish_after_global_reclaim(self):
        store = self._store()
        receipt = self._submit(store)
        first = store.claim_next_global("w", 1)
        _wait_for_expiry()
        second = store.claim_next_global("w", 60)
        self.assertEqual(second["request_id"], receipt["request_id"])
        self.assertNotEqual(first["claim_token"], second["claim_token"])
        with self.assertRaises(ClaimConflict):
            store.finish_claim(
                "tenant-a", receipt["request_id"], first["claim_token"], "completed"
            )
        record = store.finish_claim(
            "tenant-a", receipt["request_id"], second["claim_token"], "completed"
        )
        self.assertEqual(record["status"], "completed")

    def test_acceptance_tie_breaks_by_request_id_across_tenants(self):
        # Two tenants, candidates accepted at the identical instant:
        # ascending request id decides (white-box insert with a valid
        # genesis for each tenant).
        created_at = "2026-01-01T00:00:00.000000Z"
        rows = [("tenant-b", "mmm-0002"), ("tenant-a", "aaa-0001")]
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
            for tenant, rid in rows:
                genesis = _chain_hash(
                    tenant, rid, 0, "accepted", created_at, _GENESIS_PREDECESSOR
                )
                raw.execute(
                    "INSERT INTO requests VALUES (?, ?, ?, 's', '[]', "
                    "'accepted', ?, ?)",
                    (rid, tenant, f"key-{rid}", created_at, genesis),
                )
                raw.execute(
                    "INSERT INTO status_events VALUES (?, ?, 0, 'accepted', ?, ?)",
                    (tenant, rid, created_at, genesis),
                )
        store = self._store()
        first = store.claim_next_global("w", 60)
        second = store.claim_next_global("w", 60)
        self.assertEqual(
            (first["tenant_id"], first["request_id"]), ("tenant-a", "aaa-0001")
        )
        self.assertEqual(
            (second["tenant_id"], second["request_id"]), ("tenant-b", "mmm-0002")
        )


class ClaimNextGlobalInteropTests(_StoreCase):
    def test_result_works_with_renew_finish_and_log(self):
        store = self._store()
        receipt = self._submit(store, tenant="tenant-b")
        claim = store.claim_next_global("w", 60)
        tenant_id, request_id = claim["tenant_id"], claim["request_id"]
        renewed = store.renew_lease(
            tenant_id, request_id, claim["claim_token"], 120
        )
        self.assertEqual(set(renewed), {"request_id", "lease_expires_at"})
        self.assertEqual(renewed["request_id"], request_id)
        record = store.finish_claim(
            tenant_id, request_id, claim["claim_token"], "failed"
        )
        self.assertEqual(record["status"], "failed")
        log = store.get_execution_log(tenant_id, request_id)
        self.assertEqual(len(log), 1)
        self.assertEqual(log[0]["result"], "failed")
        self.assertIsNotNone(log[0]["completed_at"])
        # Reconciliation accepts the converged request without complaint.
        store.reconcile_execution(tenant_id, request_id)
        self.assertEqual(receipt["request_id"], request_id)

    def test_per_tenant_and_global_claims_share_one_lease_space(self):
        store = self._store()
        r1 = self._submit(store, tenant="tenant-a", key="a1")
        r2 = self._submit(store, tenant="tenant-a", key="a2")
        # A per-tenant claim takes r1; the global pool must not re-lease it.
        store.claim_next("tenant-a", "w", 60)
        claim = store.claim_next_global("w", 60)
        self.assertEqual(claim["request_id"], r2["request_id"])
        self.assertNotEqual(claim["request_id"], r1["request_id"])
        self.assertIsNone(store.claim_next_global("w", 60))
        # And a global claim blocks the per-tenant path symmetrically.
        self.assertIsNone(store.claim_next("tenant-a", "w", 60))


class ClaimNextGlobalValidationTests(_StoreCase):
    def test_validates_arguments_without_writing(self):
        store = self._store()
        receipt = self._submit(store)
        for worker_id in ("", None, 123, 1.5, True, ["w"]):
            with self.assertRaises(ValueError, msg=repr(worker_id)):
                store.claim_next_global(worker_id, 60)
        for lease in (0, -1, 3601, "60", 1.5, True, None):
            with self.assertRaises(ValueError, msg=repr(lease)):
                store.claim_next_global("worker", lease)
        # Nothing was claimed or transitioned by the rejected calls.
        self.assertEqual(
            store.get_status("tenant-a", receipt["request_id"])["status"],
            "accepted",
        )
        claim = store.claim_next_global("worker", 60)
        self.assertEqual(claim["request_id"], receipt["request_id"])
        log = store.get_execution_log("tenant-a", receipt["request_id"])
        self.assertEqual(len(log), 1)


class ClaimNextGlobalConcurrencyTests(_StoreCase):
    def test_concurrent_claims_never_double_lease_one_request(self):
        store = self._store()
        self._submit(store)
        with ThreadPoolExecutor(max_workers=8) as pool:
            claims = list(
                pool.map(lambda _: store.claim_next_global("w", 60), range(8))
            )
        winners = [c for c in claims if c is not None]
        self.assertEqual(len(winners), 1)

    def test_concurrent_claims_give_each_request_one_holder(self):
        store = self._store()
        receipts = [
            self._submit(store, tenant=tenant, key=f"k{i}")
            for i, tenant in enumerate(
                ["tenant-a", "tenant-a", "tenant-b", "tenant-c", "tenant-c"]
            )
        ]
        with ThreadPoolExecutor(max_workers=8) as pool:
            claims = list(
                pool.map(lambda _: store.claim_next_global("w", 60), range(12))
            )
        winners = [c for c in claims if c is not None]
        claimed_ids = [c["request_id"] for c in winners]
        self.assertEqual(len(claimed_ids), len(set(claimed_ids)))
        self.assertEqual(
            set(claimed_ids), {receipt["request_id"] for receipt in receipts}
        )
        # Every winner carries the real owning tenant of its request.
        by_id = {receipt["request_id"]: receipt for receipt in receipts}
        for claim in winners:
            self.assertIn(claim["tenant_id"], {"tenant-a", "tenant-b", "tenant-c"})
            self.assertIn(claim["request_id"], by_id)


class ClaimNextGlobalPersistenceTests(_StoreCase):
    def test_fair_order_survives_rebuild(self):
        r1 = self._submit(tenant="tenant-a", key="a1")
        r2 = self._submit(tenant="tenant-b", key="b1")
        store = self._store()
        first = store.claim_next_global("w", 60)
        self.assertEqual(
            (first["tenant_id"], first["request_id"]),
            ("tenant-a", r1["request_id"]),
        )
        # A rebuilt store recomputes live-lease counts from the persisted
        # attempts: tenant-a still holds one lease, tenant-b none.
        rebuilt = self._store()
        second = rebuilt.claim_next_global("w", 60)
        self.assertEqual(
            (second["tenant_id"], second["request_id"]),
            ("tenant-b", r2["request_id"]),
        )
        self.assertIsNone(self._store().claim_next_global("w", 60))

    def test_expired_reclaim_after_restart(self):
        receipt = self._submit()
        store = self._store()
        store.claim_next_global("w", 1)
        _wait_for_expiry()
        rebuilt = self._store()
        claim = rebuilt.claim_next_global("w", 60)
        self.assertEqual(claim["request_id"], receipt["request_id"])
        log = rebuilt.get_execution_log("tenant-a", receipt["request_id"])
        self.assertEqual([entry["attempt_number"] for entry in log], [1, 2])


class ClaimNextGlobalNoLeakTests(_StoreCase):
    def test_worker_and_token_never_persisted_or_returned(self):
        worker_secret = "worker-SECRET"
        store = self._store()
        receipt = self._submit(store)
        claim = store.claim_next_global(worker_secret, 60)
        token = claim["claim_token"]
        with sqlite3.connect(self.db_path) as conn:
            for table in ("requests", "status_events", "claim_attempts", "claim_tokens"):
                rows = conn.execute(f"SELECT * FROM {table}").fetchall()
                self.assertNotIn(worker_secret, repr(rows))
            token_rows = conn.execute("SELECT token_hash FROM claim_tokens").fetchall()
        self.assertEqual(len(token_rows), 1)
        self.assertNotEqual(token_rows[0][0], token)
        surfaces = [
            repr(claim),
            repr(store.get_execution_log("tenant-a", receipt["request_id"])),
        ]
        for surface in surfaces:
            self.assertNotIn(worker_secret, surface)
        store.finish_claim("tenant-a", receipt["request_id"], token, "completed")
        self.assertNotIn(
            token,
            repr(store.get_execution_log("tenant-a", receipt["request_id"])),
        )

    def test_logs_do_not_leak_worker_or_token(self):
        store = self._store()
        receipt = self._submit(store)
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        logger = logging.getLogger("forgetting_evidence.requests")
        logger.addHandler(handler)
        old_level = logger.level
        logger.setLevel(logging.INFO)
        try:
            claim = store.claim_next_global("worker-SECRETLOG", 60)
            store.finish_claim(
                "tenant-a", receipt["request_id"], claim["claim_token"], "completed"
            )
        finally:
            logger.removeHandler(handler)
            logger.setLevel(old_level)
        emitted = stream.getvalue()
        self.assertNotIn("worker-SECRETLOG", emitted)
        self.assertNotIn(claim["claim_token"], emitted)


class ClaimNextGlobalStorageErrorTests(_StoreCase):
    def _fixed_message(self, ctx):
        self.assertEqual(str(ctx.exception), "request store is unavailable")
        self.assertNotIn("sqlite", str(ctx.exception).lower())
        self.assertNotIn(self.db_path, str(ctx.exception))

    def test_damaged_schema_maps_to_os_error_and_writes_nothing(self):
        store = self._store()
        receipt = self._submit(store)
        # Damage the database out of band: remove the attempts table so
        # the claim statement fails mid-transaction.
        with sqlite3.connect(self.db_path) as raw:
            raw.execute("DROP TABLE claim_attempts")
        with self.assertRaises(OSError) as ctx:
            store.claim_next_global("w", 60)
        self._fixed_message(ctx)
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

    def test_corrupt_file_is_os_error(self):
        store = self._store()
        self._submit(store)
        with open(self.db_path, "wb") as handle:
            handle.write(b"not a sqlite database")
        with self.assertRaises(OSError) as ctx:
            store.claim_next_global("w", 60)
        self._fixed_message(ctx)


class ClaimNextGlobalProxyTests(_StoreCase):
    def test_claim_next_global_is_proxied(self):
        store = httpapi.DeferredRequestStore(self.db_path)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        claim = store.claim_next_global("worker-1", 60)
        self.assertEqual(claim["tenant_id"], "tenant-a")
        self.assertEqual(claim["request_id"], receipt["request_id"])
        record = store.finish_claim(
            "tenant-a", receipt["request_id"], claim["claim_token"], "completed"
        )
        self.assertEqual(record["status"], "completed")


if __name__ == "__main__":
    unittest.main()
