"""Tests for the recoverable execution-lease migration.

Covers RequestStore.migrate_execution_leases on the storage layer only:
the fixed compact-JSON-line shape, stable acceptance-order pagination,
durable cursor resume across retries and rebuilds, recovery of legacy
attempt rows and the single still-live credential hash, preservation of
request status/times/results, idempotent re-migration (one upgrade per
request), single-winner same-cursor concurrency with empty competing
pages, empty-sweep stable progress, tenant/cursor/limit validation
without writes, fixed-text OSError on corrupt legacy records or storage
faults with no half-settled page, unchanged claim candidates and
reconcile/renew behaviour after the upgrade, and the no-leak guarantees.
This entry point is deliberately not exposed over HTTP.
"""

import hashlib
import io
import json
import logging
import os
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor

from forgetting_evidence import httpapi
from forgetting_evidence.requests import (
    RequestStore,
    _decode_cursor,
    _encode_cursor,
)

_PREFIX = "em1."
_EXPIRED_WINDOW = (
    "1999-12-31T00:00:00.000000Z",
    "2000-01-01T00:00:00.000000Z",
)


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

    def _submit_many(self, store, count, tenant="tenant-a"):
        return [
            store.submit(tenant, f"subject-{i}", ["email"], f"key-{i}")["request_id"]
            for i in range(count)
        ]

    def _archive_to_legacy(self, expiry_overrides=None, keep_tokens=False):
        """Move every current attempt (and token hash) into the legacy table.

        The request rows, their status and their audit events stay in
        place; only the current lease bookkeeping is archived, so the
        migration has something to recover. ``expiry_overrides`` maps a
        request id to ``(claimed_at, lease_expires_at)`` to synthesize an
        expired or otherwise-dated legacy window. With ``keep_tokens``
        the current credential rows survive (the legacy attempts are
        then already fully represented by current bookkeeping).
        """
        dummy = hashlib.sha256(b"legacy-placeholder").hexdigest()
        with sqlite3.connect(self.db_path) as raw:
            attempts = raw.execute(
                "SELECT tenant_id, request_id, attempt_number, claimed_at, "
                "lease_expires_at, result, completed_at FROM claim_attempts"
            ).fetchall()
            tokens = {
                (row[0], row[1]): (row[2], row[3])
                for row in raw.execute(
                    "SELECT tenant_id, request_id, attempt_number, token_hash "
                    "FROM claim_tokens"
                )
            }
            for tenant_id, request_id, number, claimed_at, expires_at, result, completed_at in attempts:
                if expiry_overrides and request_id in expiry_overrides:
                    claimed_at, expires_at = expiry_overrides[request_id]
                token_number, token_hash = tokens.get(
                    (tenant_id, request_id), (number, dummy)
                )
                # Only the attempt that last held the lease carries its
                # real hash; superseded attempts keep a well-formed dummy.
                hash_value = token_hash if number == token_number else dummy
                raw.execute(
                    "INSERT INTO legacy_execution_leases ("
                    "tenant_id, request_id, attempt_number, claimed_at, "
                    "lease_expires_at, token_hash, result, completed_at"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        tenant_id,
                        request_id,
                        number,
                        claimed_at,
                        expires_at,
                        hash_value,
                        result,
                        completed_at,
                    ),
                )
            if not keep_tokens:
                # Archiving genuinely removes the current lease
                # bookkeeping; the migration must recover it.
                raw.execute("DELETE FROM claim_attempts")
                raw.execute("DELETE FROM claim_tokens")
            # With keep_tokens the current attempt rows and live
            # credential survive alongside the legacy copy, so the
            # upgrade finds the record fully present and writes nothing.

    def _migrate(self, store, *args):
        return json.loads(store.migrate_execution_leases(*args))


class MigrationShapeTests(_StoreCase):
    def test_line_is_compact_json_with_exactly_one_trailing_newline(self):
        store = self._store()
        line = store.migrate_execution_leases("tenant-a")
        self.assertTrue(line.endswith("\n"))
        self.assertEqual(len(line) - len(line.rstrip("\n")), 1)
        self.assertNotIn(" ", line)
        # Field order is fixed and items are empty for a tenant with no
        # legacy records.
        self.assertEqual(
            list(json.loads(line)),
            ["batch_id", "next_cursor", "finished", "items"],
        )

    def test_empty_tenant_finishes_with_empty_items_and_persists_batch(self):
        store = self._store()
        result = self._migrate(store, "tenant-a")
        self.assertTrue(result["batch_id"])
        self.assertIsNone(result["next_cursor"])
        self.assertIs(result["finished"], True)
        self.assertEqual(result["items"], [])
        # The empty batch still keeps durable, stable progress.
        with sqlite3.connect(self.db_path) as raw:
            row = raw.execute(
                "SELECT tenant_id, finished FROM lease_migration_batches "
                "WHERE batch_id = ?",
                (result["batch_id"],),
            ).fetchone()
        self.assertEqual(row, ("tenant-a", 1))

    def test_non_legacy_requests_are_not_items(self):
        store = self._store()
        # Processing (live lease), completed and accepted requests
        # without a legacy record are all out of scope for the migration.
        processing_receipt = self._submit(store, key="k1")
        processing_claim = store.claim_next("tenant-a", "worker", 3600)
        self.assertEqual(
            processing_claim["request_id"], processing_receipt["request_id"]
        )
        completed_receipt = self._submit(store, key="k2")
        completed_claim = store.claim_next("tenant-a", "worker", 3600)
        self.assertEqual(
            completed_claim["request_id"], completed_receipt["request_id"]
        )
        store.finish_claim(
            "tenant-a",
            completed_receipt["request_id"],
            completed_claim["claim_token"],
            "completed",
        )
        accepted_receipt = self._submit(store, key="k3")
        result = self._migrate(store, "tenant-a", None, 10)
        self.assertEqual(result["items"], [])
        self.assertIs(result["finished"], True)
        # Nothing about the non-legacy requests changed.
        self.assertEqual(
            store.get_status("tenant-a", processing_receipt["request_id"])["status"],
            "processing",
        )
        self.assertEqual(
            store.get_status("tenant-a", completed_receipt["request_id"])["status"],
            "completed",
        )
        self.assertEqual(
            store.get_status("tenant-a", accepted_receipt["request_id"])["status"],
            "accepted",
        )
        # The current live lease still works.
        self.assertEqual(
            store.finish_claim(
                "tenant-a",
                processing_receipt["request_id"],
                processing_claim["claim_token"],
                "completed",
            )["status"],
            "completed",
        )

    def test_item_fields_and_types(self):
        store = self._store()
        receipt = self._submit(store)
        claim = store.claim_next("tenant-a", "worker", 3600)
        self._archive_to_legacy()
        store = self._store()
        result = self._migrate(store, "tenant-a")
        self.assertEqual(len(result["items"]), 1)
        item = result["items"][0]
        self.assertEqual(list(item), ["request_id", "attempt_number", "outcome"])
        self.assertEqual(item["request_id"], receipt["request_id"])
        self.assertIsInstance(item["attempt_number"], int)
        self.assertNotIsInstance(item["attempt_number"], bool)
        self.assertEqual(item["attempt_number"], 1)
        self.assertEqual(item["outcome"], "upgraded")
        # No worker or credential ever appears.
        self.assertNotIn("worker", item)
        self.assertNotIn("claim_token", item)
        self.assertNotIn(claim["claim_token"], json.dumps(result))


class MigrationPaginationTests(_StoreCase):
    def test_pagination_resumes_with_same_batch_and_stable_order(self):
        store = self._store()
        ids = self._submit_many(store, 5)
        claims = [store.claim_next("tenant-a", "worker", 3600) for _ in range(5)]
        self.assertEqual([c["request_id"] for c in claims], ids)
        self._archive_to_legacy()
        store = self._store()

        first = self._migrate(store, "tenant-a", None, 2)
        self.assertEqual([i["request_id"] for i in first["items"]], ids[:2])
        self.assertFalse(first["finished"])
        self.assertTrue(first["next_cursor"])
        batch_id = first["batch_id"]

        second = self._migrate(store, "tenant-a", first["next_cursor"], 2)
        self.assertEqual(second["batch_id"], batch_id)
        self.assertEqual([i["request_id"] for i in second["items"]], ids[2:4])
        self.assertFalse(second["finished"])

        third = self._migrate(store, "tenant-a", second["next_cursor"], 2)
        self.assertEqual(third["batch_id"], batch_id)
        self.assertEqual([i["request_id"] for i in third["items"]], ids[4:])
        self.assertTrue(third["finished"])
        self.assertIsNone(third["next_cursor"])
        for page in (first, second, third):
            for item in page["items"]:
                self.assertEqual(item["attempt_number"], 1)
                self.assertEqual(item["outcome"], "upgraded")

    def test_order_ties_break_by_request_id(self):
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
            raw.execute(
                "CREATE TABLE IF NOT EXISTS legacy_execution_leases ("
                "tenant_id TEXT NOT NULL, request_id TEXT NOT NULL, "
                "attempt_number INTEGER NOT NULL, claimed_at TEXT NOT NULL, "
                "lease_expires_at TEXT NOT NULL, token_hash TEXT NOT NULL, "
                "result TEXT, completed_at TEXT, "
                "PRIMARY KEY (tenant_id, request_id, attempt_number))"
            )
            from forgetting_evidence.requests import (
                _GENESIS_PREDECESSOR,
                _chain_hash,
            )

            token_hash = hashlib.sha256(b"tok").hexdigest()
            for rid in (low, high):
                genesis = _chain_hash(
                    "tenant-a", rid, 0, "accepted", created_at, _GENESIS_PREDECESSOR
                )
                processing = _chain_hash(
                    "tenant-a", rid, 1, "processing", created_at, genesis
                )
                raw.execute(
                    "INSERT INTO requests VALUES (?, 'tenant-a', ?, 's', '[]', "
                    "'processing', ?, ?)",
                    (rid, f"key-{rid}", created_at, processing),
                )
                raw.execute(
                    "INSERT INTO status_events VALUES (?, ?, 0, 'accepted', ?, ?)",
                    ("tenant-a", rid, created_at, genesis),
                )
                raw.execute(
                    "INSERT INTO status_events VALUES (?, ?, 1, 'processing', ?, ?)",
                    ("tenant-a", rid, created_at, processing),
                )
                raw.execute(
                    "INSERT INTO legacy_execution_leases VALUES ("
                    "'tenant-a', ?, 1, ?, ?, ?, NULL, NULL)",
                    (rid, created_at, "2999-01-01T00:00:00.000000Z", token_hash),
                )
        store = self._store()
        result = self._migrate(store, "tenant-a")
        self.assertEqual(
            [i["request_id"] for i in result["items"]], [low, high]
        )

    def test_resume_survives_rebuild(self):
        store = self._store()
        ids = self._submit_many(store, 3)
        for _ in range(3):
            store.claim_next("tenant-a", "worker", 3600)
        self._archive_to_legacy()
        first = self._migrate(RequestStore(self.db_path), "tenant-a", None, 1)
        second = self._migrate(
            RequestStore(self.db_path), "tenant-a", first["next_cursor"], 10
        )
        self.assertEqual(second["batch_id"], first["batch_id"])
        self.assertEqual(
            [i["request_id"] for i in second["items"]], ids[1:]
        )
        self.assertTrue(second["finished"])


class MigrationRecoveryTests(_StoreCase):
    def test_live_lease_is_recovered_with_its_credential(self):
        store = self._store()
        receipt = self._submit(store)
        claim = store.claim_next("tenant-a", "worker", 3600)
        original_token = claim["claim_token"]
        self._archive_to_legacy()
        store = self._store()
        result = self._migrate(store, "tenant-a")
        self.assertEqual(result["items"][0]["outcome"], "upgraded")
        with sqlite3.connect(self.db_path) as raw:
            token_rows = raw.execute(
                "SELECT attempt_number, token_hash FROM claim_tokens "
                "WHERE request_id = ?",
                (receipt["request_id"],),
            ).fetchall()
            attempts = raw.execute(
                "SELECT attempt_number, claimed_at, lease_expires_at, result, "
                "completed_at FROM claim_attempts WHERE request_id = ? "
                "ORDER BY attempt_number",
                (receipt["request_id"],),
            ).fetchall()
        self.assertEqual(len(token_rows), 1)
        self.assertEqual(token_rows[0][0], 1)
        self.assertEqual(
            token_rows[0][1],
            hashlib.sha256(original_token.encode("utf-8")).hexdigest(),
        )
        self.assertEqual(len(attempts), 1)
        self.assertEqual(attempts[0][0], 1)
        self.assertEqual(attempts[0][2], claim["lease_expires_at"])
        self.assertIsNone(attempts[0][3])
        # The recovered credential finishes the recovered live lease.
        record = store.finish_claim(
            "tenant-a", receipt["request_id"], original_token, "completed"
        )
        self.assertEqual(record["status"], "completed")

    def test_expired_legacy_lease_recovers_no_token_and_keeps_processing(self):
        store = self._store()
        receipt = self._submit(store)
        claim = store.claim_next("tenant-a", "worker", 3600)
        self._archive_to_legacy(
            {receipt["request_id"]: _EXPIRED_WINDOW}
        )
        store = self._store()
        result = self._migrate(store, "tenant-a")
        self.assertEqual(result["items"][0]["outcome"], "upgraded")
        self.assertEqual(
            store.get_status("tenant-a", receipt["request_id"])["status"],
            "processing",
        )
        with sqlite3.connect(self.db_path) as raw:
            self.assertEqual(
                raw.execute(
                    "SELECT count(*) FROM claim_tokens WHERE request_id = ?",
                    (receipt["request_id"],),
                ).fetchone()[0],
                0,
            )
        # The expired credential cannot finish; reconcile converges it.
        from forgetting_evidence.requests import ClaimConflict

        with self.assertRaises(ClaimConflict):
            store.finish_claim(
                "tenant-a", receipt["request_id"], claim["claim_token"], "completed"
            )
        self.assertEqual(
            store.reconcile_execution("tenant-a", receipt["request_id"])["status"],
            "failed",
        )

    def test_terminal_request_keeps_status_times_and_attempt_result(self):
        store = self._store()
        receipt = self._submit(store)
        claim = store.claim_next("tenant-a", "worker", 3600)
        store.finish_claim(
            "tenant-a", receipt["request_id"], claim["claim_token"], "completed"
        )
        before = store.get_execution_log("tenant-a", receipt["request_id"])
        self._archive_to_legacy()
        store = self._store()
        result = self._migrate(store, "tenant-a")
        self.assertEqual(result["items"][0]["outcome"], "upgraded")
        after = store.get_execution_log("tenant-a", receipt["request_id"])
        self.assertEqual(before, after)
        self.assertEqual(
            store.get_status("tenant-a", receipt["request_id"])["status"],
            "completed",
        )
        with sqlite3.connect(self.db_path) as raw:
            self.assertEqual(
                raw.execute(
                    "SELECT count(*) FROM claim_tokens WHERE request_id = ?",
                    (receipt["request_id"],),
                ).fetchone()[0],
                0,
            )

    def test_multi_attempt_history_preserved_and_latest_live_recovered(self):
        store = self._store()
        receipt = self._submit(store)
        first = store.claim_next("tenant-a", "worker-1", 1)
        _wait_for_expiry()
        second = store.claim_next("tenant-a", "worker-2", 3600)
        self.assertEqual(second["request_id"], receipt["request_id"])
        self._archive_to_legacy()
        store = self._store()
        result = self._migrate(store, "tenant-a")
        item = result["items"][0]
        self.assertEqual(item["attempt_number"], 2)
        numbers = [
            row["attempt_number"]
            for row in store.get_execution_log(
                "tenant-a", receipt["request_id"]
            )
        ]
        self.assertEqual(numbers, [1, 2])
        # The latest (live) credential is the one that works.
        from forgetting_evidence.requests import ClaimConflict

        with self.assertRaises(ClaimConflict):
            store.finish_claim(
                "tenant-a", receipt["request_id"], first["claim_token"], "completed"
            )
        record = store.finish_claim(
            "tenant-a", receipt["request_id"], second["claim_token"], "failed"
        )
        self.assertEqual(record["status"], "failed")

    def test_expired_reclaim_after_upgrade_generates_incrementing_attempt(self):
        store = self._store()
        receipt = self._submit(store)
        store.claim_next("tenant-a", "worker", 3600)
        self._archive_to_legacy(
            {receipt["request_id"]: _EXPIRED_WINDOW}
        )
        store = self._store()
        self._migrate(store, "tenant-a")
        reclaim = store.claim_next("tenant-a", "worker", 3600)
        self.assertIsNotNone(reclaim)
        self.assertEqual(reclaim["request_id"], receipt["request_id"])
        self.assertEqual(
            [a["attempt_number"] for a in store.get_execution_log(
                "tenant-a", receipt["request_id"]
            )],
            [1, 2],
        )

    def test_recovered_live_lease_reclaim_after_expiry_increments(self):
        store = self._store()
        receipt = self._submit(store)
        original = store.claim_next("tenant-a", "worker-1", 1)
        self._archive_to_legacy()
        store = self._store()
        self._migrate(store, "tenant-a")
        # The recovered lease is still live and not reclaimable yet.
        self.assertIsNone(store.claim_next("tenant-a", "worker-2", 3600))
        _wait_for_expiry()
        reclaim = store.claim_next("tenant-a", "worker-2", 3600)
        self.assertEqual(reclaim["request_id"], receipt["request_id"])
        self.assertNotEqual(reclaim["claim_token"], original["claim_token"])
        self.assertEqual(
            [a["attempt_number"] for a in store.get_execution_log(
                "tenant-a", receipt["request_id"]
            )],
            [1, 2],
        )
        from forgetting_evidence.requests import ClaimConflict

        with self.assertRaises(ClaimConflict):
            store.finish_claim(
                "tenant-a", receipt["request_id"], original["claim_token"], "completed"
            )

    def test_existing_live_lease_is_not_duplicated(self):
        store = self._store()
        receipt = self._submit(store)
        claim = store.claim_next("tenant-a", "worker", 3600)
        # Archive the attempts into legacy form but keep the current
        # credential row: the legacy history is already fully present, so
        # the upgrade writes no second lease.
        self._archive_to_legacy(keep_tokens=True)
        store = self._store()
        result = self._migrate(store, "tenant-a")
        self.assertEqual(result["items"][0]["outcome"], "present")
        with sqlite3.connect(self.db_path) as raw:
            holders = raw.execute(
                "SELECT count(*) FROM claim_tokens WHERE request_id = ?",
                (receipt["request_id"],),
            ).fetchone()[0]
            attempts = raw.execute(
                "SELECT count(*) FROM claim_attempts WHERE request_id = ?",
                (receipt["request_id"],),
            ).fetchone()[0]
        self.assertEqual(holders, 1)
        self.assertEqual(attempts, 1)
        # The original live credential keeps working unchanged.
        self.assertEqual(
            store.finish_claim(
                "tenant-a", receipt["request_id"], claim["claim_token"], "completed"
            )["status"],
            "completed",
        )

    def test_rebuild_after_upgrade_keeps_lease_state(self):
        first = self._store()
        receipt = first.submit("tenant-a", "subject-1", ["email"], "key-1")
        claim = first.claim_next("tenant-a", "worker", 3600)
        self._archive_to_legacy()
        migrator = RequestStore(self.db_path)
        self._migrate(migrator, "tenant-a")
        rebuilt = RequestStore(self.db_path)
        self.assertEqual(
            rebuilt.finish_claim(
                "tenant-a", receipt["request_id"], claim["claim_token"], "completed"
            )["status"],
            "completed",
        )
        self.assertTrue(
            rebuilt.verify_evidence("tenant-a", receipt["request_id"])
        )


class MigrationIdempotencyTests(_StoreCase):
    def test_repeat_migration_is_empty_finished_and_writes_once(self):
        store = self._store()
        ids = self._submit_many(store, 3)
        for _ in range(3):
            store.claim_next("tenant-a", "worker", 3600)
        self._archive_to_legacy()
        store = self._store()
        first = self._migrate(store, "tenant-a", None, 2)
        cursor = first["next_cursor"]
        second = self._migrate(store, "tenant-a", cursor, 2)
        self.assertEqual(len(second["items"]), 1)
        # Replaying an already-continued cursor returns the committed
        # progress with an empty page.
        replay = self._migrate(store, "tenant-a", cursor, 2)
        self.assertEqual(replay["batch_id"], first["batch_id"])
        self.assertEqual(replay["items"], [])
        self.assertTrue(replay["finished"])
        # A brand new batch finds nothing left to upgrade.
        third = self._migrate(store, "tenant-a")
        self.assertNotEqual(third["batch_id"], first["batch_id"])
        self.assertEqual(third["items"], [])
        self.assertTrue(third["finished"])
        with sqlite3.connect(self.db_path) as raw:
            self.assertEqual(
                raw.execute("SELECT count(*) FROM lease_migration_items").fetchone()[0],
                3,
            )
            # Exactly one recovered attempt row per request.
            self.assertEqual(
                raw.execute(
                    "SELECT count(*) FROM claim_attempts WHERE tenant_id = 'tenant-a'"
                ).fetchone()[0],
                3,
            )
            self.assertEqual(
                raw.execute(
                    "SELECT count(DISTINCT request_id) FROM claim_attempts "
                    "WHERE tenant_id = 'tenant-a'"
                ).fetchone()[0],
                3,
            )

    def test_upgrade_does_not_change_audit_chain_or_receipt_eligibility(self):
        store = self._store()
        receipt = self._submit(store)
        claim = store.claim_next("tenant-a", "worker", 3600)
        store.finish_claim(
            "tenant-a", receipt["request_id"], claim["claim_token"], "completed"
        )
        events_before = store.audit("tenant-a", receipt["request_id"])
        self._archive_to_legacy()
        store = self._store()
        self._migrate(store, "tenant-a")
        self.assertEqual(
            store.audit("tenant-a", receipt["request_id"]), events_before
        )
        self.assertTrue(
            store.verify_evidence("tenant-a", receipt["request_id"])
        )
        # The completed request can still obtain its receipt.
        text = store.generate_receipt(
            "tenant-a", receipt["request_id"], "receipt-key"
        )
        self.assertTrue(text.endswith("\n"))
        self.assertTrue(store.verify_receipt(text, "receipt-key"))


class MigrationConcurrencyTests(_StoreCase):
    def test_same_cursor_has_one_winner_and_empty_competing_pages(self):
        store = self._store()
        for index in range(8):
            self._submit(store, key=f"k{index}")
        for _ in range(8):
            store.claim_next("tenant-a", "worker", 3600)
        self._archive_to_legacy()
        first = self._migrate(RequestStore(self.db_path), "tenant-a", None, 4)
        self.assertFalse(first["finished"])
        self.assertEqual(len(first["items"]), 4)
        cursor = first["next_cursor"]

        def continue_page(_):
            return json.loads(
                RequestStore(self.db_path).migrate_execution_leases(
                    "tenant-a", cursor, 4
                )
            )

        with ThreadPoolExecutor(max_workers=8) as pool:
            pages = list(pool.map(continue_page, range(16)))
        winners = [page for page in pages if page["items"]]
        losers = [page for page in pages if not page["items"]]
        self.assertEqual(len(winners), 1)
        winner = winners[0]
        self.assertEqual(len(winner["items"]), 4)
        self.assertTrue(winner["finished"])
        self.assertIsNone(winner["next_cursor"])
        for loser in losers:
            self.assertEqual(loser["batch_id"], first["batch_id"])
            self.assertTrue(loser["finished"])
            self.assertIsNone(loser["next_cursor"])
        with sqlite3.connect(self.db_path) as raw:
            self.assertEqual(
                raw.execute("SELECT count(*) FROM lease_migration_items").fetchone()[0],
                8,
            )
            self.assertEqual(
                raw.execute(
                    "SELECT count(*) FROM claim_attempts WHERE tenant_id = 'tenant-a'"
                ).fetchone()[0],
                8,
            )

    def test_renewal_after_upgrade_still_commits_one_expiry(self):
        store = self._store()
        receipt = self._submit(store)
        claim = store.claim_next("tenant-a", "worker", 3600)
        token = claim["claim_token"]
        self._archive_to_legacy()
        store = self._store()
        self._migrate(store, "tenant-a")
        # Distinct store instances share the file so the database write
        # lock (not the in-process lock) decides the genuine race; the
        # barrier makes the renewals concurrent rather than sequential.
        stores = [RequestStore(self.db_path) for _ in range(8)]
        barrier = threading.Barrier(len(stores))

        def renew(pair):
            index, instance = pair
            barrier.wait()
            return instance.renew_lease(
                "tenant-a", receipt["request_id"], token, 600
            )

        with ThreadPoolExecutor(max_workers=len(stores)) as pool:
            results = list(pool.map(renew, enumerate(stores)))
        expiries = {r["lease_expires_at"] for r in results}
        self.assertEqual(len(expiries), 1)
        # The renewed credential still finishes the lease.
        self.assertEqual(
            stores[0].finish_claim(
                "tenant-a", receipt["request_id"], token, "completed"
            )["status"],
            "completed",
        )


class MigrationValidationTests(_StoreCase):
    def test_invalid_tenant_is_value_error_without_writes(self):
        store = self._store()
        for bad in ("", None, 7, b"t", ["t"], True):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    store.migrate_execution_leases(bad)
        with sqlite3.connect(self.db_path) as raw:
            self.assertEqual(
                raw.execute("SELECT count(*) FROM lease_migration_batches").fetchone()[0],
                0,
            )

    def test_invalid_limit_is_value_error_without_writes(self):
        store = self._store()
        receipt = self._submit(store)
        store.claim_next("tenant-a", "worker", 3600)
        self._archive_to_legacy()
        for bad in (0, -1, 1001, 10_000, 1.0, 0.5, True, False, "5", [5]):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    store.migrate_execution_leases("tenant-a", None, bad)
        with sqlite3.connect(self.db_path) as raw:
            self.assertEqual(
                raw.execute("SELECT count(*) FROM claim_attempts").fetchone()[0],
                0,
            )
            self.assertEqual(
                raw.execute("SELECT count(*) FROM lease_migration_items").fetchone()[0],
                0,
            )

    def test_invalid_cursor_is_value_error_without_writes(self):
        store = self._store()
        for bad in (
            "",
            "x",
            "rc1.aaaa",
            "ai1.aaaa",
            7,
            b"em1.x",
            "em1.@@@@",
            "em1." + "A" * 8,
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    store.migrate_execution_leases("tenant-a", bad)
        # A well-enveloped cursor naming an unknown batch is invalid too.
        unknown = _encode_cursor("does-not-exist", 0, _PREFIX)
        with self.assertRaises(ValueError):
            store.migrate_execution_leases("tenant-a", unknown)
        # The migration cursor is rejected by the other batch entries.
        self._submit(store, tenant="tenant-a", key="k")
        with self.assertRaises(ValueError):
            store.reconcile_batch("tenant-a", unknown)
        with self.assertRaises(ValueError):
            store.audit_inspection("tenant-a", unknown)

    def test_cross_tenant_cursor_is_value_error(self):
        store = self._store()
        batch = self._migrate(store, "tenant-x")
        cursor = _encode_cursor(batch["batch_id"], 0, _PREFIX)
        with self.assertRaises(ValueError):
            store.migrate_execution_leases("tenant-y", cursor)
        with sqlite3.connect(self.db_path) as raw:
            rows = raw.execute(
                "SELECT tenant_id FROM lease_migration_batches"
            ).fetchall()
        self.assertEqual(rows, [("tenant-x",)])

    def test_cursor_round_trips_through_its_prefix(self):
        encoded = _encode_cursor("batch-id", 3, _PREFIX)
        self.assertTrue(encoded.startswith(_PREFIX))
        self.assertEqual(_decode_cursor(encoded, _PREFIX), ("batch-id", 3))


class MigrationCorruptionTests(_StoreCase):
    def _one_legacy(self):
        store = self._store()
        self._submit(store)
        store.claim_next("tenant-a", "worker", 3600)
        self._archive_to_legacy()

    def _assert_fixed_failure(self):
        store = self._store()
        with self.assertRaises(OSError) as ctx:
            store.migrate_execution_leases("tenant-a")
        self.assertEqual(str(ctx.exception), "execution_lease_migration_failed")
        self.assertNotIn("sqlite", str(ctx.exception).lower())
        self.assertNotIn(self.db_path, str(ctx.exception))
        with sqlite3.connect(self.db_path) as raw:
            # The whole page (including the batch row) rolled back.
            self.assertEqual(
                raw.execute("SELECT count(*) FROM lease_migration_batches").fetchone()[0],
                0,
            )
            self.assertEqual(
                raw.execute("SELECT count(*) FROM lease_migration_items").fetchone()[0],
                0,
            )
            self.assertEqual(
                raw.execute("SELECT count(*) FROM claim_attempts").fetchone()[0],
                0,
            )

    def test_malformed_timestamp_is_fixed_oserror(self):
        self._one_legacy()
        with sqlite3.connect(self.db_path) as raw:
            raw.execute(
                "UPDATE legacy_execution_leases SET lease_expires_at = 'nope'"
            )
        self._assert_fixed_failure()

    def test_impossible_lease_window_is_fixed_oserror(self):
        self._one_legacy()
        with sqlite3.connect(self.db_path) as raw:
            raw.execute(
                "UPDATE legacy_execution_leases SET claimed_at = '2026-01-02T00:00:00.000000Z', "
                "lease_expires_at = '2026-01-01T00:00:00.000000Z'"
            )
        self._assert_fixed_failure()

    def test_malformed_token_hash_is_fixed_oserror(self):
        self._one_legacy()
        with sqlite3.connect(self.db_path) as raw:
            raw.execute(
                "UPDATE legacy_execution_leases SET token_hash = 'deadbeef'"
            )
        self._assert_fixed_failure()

    def test_split_result_completion_pair_is_fixed_oserror(self):
        self._one_legacy()
        with sqlite3.connect(self.db_path) as raw:
            raw.execute(
                "UPDATE legacy_execution_leases SET result = 'completed'"
            )
        self._assert_fixed_failure()

    def test_unknown_result_is_fixed_oserror(self):
        self._one_legacy()
        with sqlite3.connect(self.db_path) as raw:
            raw.execute(
                "UPDATE legacy_execution_leases "
                "SET result = 'cancelled', completed_at = '2026-01-01T00:00:00.000000Z'"
            )
        self._assert_fixed_failure()

    def test_non_contiguous_attempt_sequence_is_fixed_oserror(self):
        self._one_legacy()
        with sqlite3.connect(self.db_path) as raw:
            raw.execute(
                "UPDATE legacy_execution_leases SET attempt_number = 2"
            )
        self._assert_fixed_failure()

    def test_legacy_record_under_accepted_request_is_fixed_oserror(self):
        store = self._store()
        receipt = self._submit(store)
        # Insert a legacy lease without ever claiming the accepted request.
        with sqlite3.connect(self.db_path) as raw:
            raw.execute(
                "INSERT INTO legacy_execution_leases ("
                "tenant_id, request_id, attempt_number, claimed_at, "
                "lease_expires_at, token_hash, result, completed_at"
                ") VALUES ('tenant-a', ?, 1, '2026-01-01T00:00:00.000000Z', "
                "'2999-01-01T00:00:00.000000Z', ?, NULL, NULL)",
                (
                    receipt["request_id"],
                    hashlib.sha256(b"t").hexdigest(),
                ),
            )
        self._assert_fixed_failure()

    def test_legacy_row_contradicting_current_row_is_fixed_oserror(self):
        store = self._store()
        receipt = self._submit(store)
        store.claim_next("tenant-a", "worker", 3600)
        self._archive_to_legacy()
        # Recreate a divergent current attempt row.
        with sqlite3.connect(self.db_path) as raw:
            raw.execute(
                "INSERT INTO claim_attempts ("
                "tenant_id, request_id, attempt_number, claimed_at, "
                "lease_expires_at, result, completed_at"
                ") VALUES ('tenant-a', ?, 1, '2026-01-01T00:00:00.000000Z', "
                "'2026-01-01T00:01:00.000000Z', NULL, NULL)",
                (receipt["request_id"],),
            )
        store = self._store()
        with self.assertRaises(OSError) as ctx:
            store.migrate_execution_leases("tenant-a")
        self.assertEqual(str(ctx.exception), "execution_lease_migration_failed")
        with sqlite3.connect(self.db_path) as raw:
            # No migration bookkeeping landed; the divergent current row
            # is left exactly as it stood, never overwritten.
            self.assertEqual(
                raw.execute("SELECT count(*) FROM lease_migration_batches").fetchone()[0],
                0,
            )
            self.assertEqual(
                raw.execute("SELECT count(*) FROM lease_migration_items").fetchone()[0],
                0,
            )
            self.assertEqual(
                raw.execute(
                    "SELECT lease_expires_at FROM claim_attempts "
                    "WHERE tenant_id = 'tenant-a' AND attempt_number = 1"
                ).fetchone()[0],
                "2026-01-01T00:01:00.000000Z",
            )

    def test_unreadable_store_is_fixed_oserror(self):
        store = self._store()
        self._submit(store)
        store.claim_next("tenant-a", "worker", 3600)
        self._archive_to_legacy()
        with open(self.db_path, "wb") as handle:
            handle.write(b"not a sqlite database")
        with self.assertRaises(OSError) as ctx:
            store.migrate_execution_leases("tenant-a")
        self.assertEqual(str(ctx.exception), "execution_lease_migration_failed")


class MigrationNoLeakTests(_StoreCase):
    def test_response_never_contains_subject_scope_or_credential(self):
        store = self._store()
        secret_subject = "subject-SECRET"
        receipt = self._submit(store, subject=secret_subject)
        claim = store.claim_next("tenant-a", "worker-SECRET", 3600)
        self._archive_to_legacy()
        store = self._store()
        line = store.migrate_execution_leases("tenant-a")
        self.assertNotIn(secret_subject, line)
        self.assertNotIn("worker-SECRET", line)
        self.assertNotIn(claim["claim_token"], line)
        self.assertNotIn("SELECT", line.upper())
        self.assertNotIn(self.db_path, line)

    def test_logs_never_contain_subject_worker_or_credential(self):
        store = self._store()
        self._submit(store, subject="subject-LOGSECRET")
        claim = store.claim_next("tenant-a", "worker-LOGSECRET", 3600)
        self._archive_to_legacy()
        store = self._store()
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        logger = logging.getLogger("forgetting_evidence.requests")
        logger.addHandler(handler)
        old_level = logger.level
        logger.setLevel(logging.INFO)
        try:
            store.migrate_execution_leases("tenant-a")
        finally:
            logger.removeHandler(handler)
            logger.setLevel(old_level)
        emitted = stream.getvalue()
        self.assertNotIn("subject-LOGSECRET", emitted)
        self.assertNotIn("worker-LOGSECRET", emitted)
        self.assertNotIn(claim["claim_token"], emitted)
        self.assertNotIn(self.db_path, emitted)

    def test_no_credential_material_is_persisted(self):
        store = self._store()
        receipt = self._submit(store)
        claim = store.claim_next("tenant-a", "worker", 3600)
        token = claim["claim_token"]
        self._archive_to_legacy()
        store = self._store()
        store.migrate_execution_leases("tenant-a")
        with sqlite3.connect(self.db_path) as raw:
            for table in ("legacy_execution_leases", "claim_tokens"):
                rendered = repr(
                    raw.execute(f"SELECT * FROM {table}").fetchall()
                )
                self.assertNotIn(token, rendered)


class DeferredMigrationTests(_StoreCase):
    def test_migration_is_proxied_but_not_http_routed(self):
        store = self._store()
        receipt = self._submit(store)
        claim = store.claim_next("tenant-a", "worker", 3600)
        self._archive_to_legacy()
        deferred = httpapi.DeferredRequestStore(self.db_path)
        line = deferred.migrate_execution_leases("tenant-a")
        result = json.loads(line)
        self.assertTrue(result["finished"])
        self.assertEqual(
            result["items"][0]["request_id"], receipt["request_id"]
        )
        # The recovered lease is usable through the proxy's other calls.
        record = deferred.finish_claim(
            "tenant-a", receipt["request_id"], claim["claim_token"], "completed"
        )
        self.assertEqual(record["status"], "completed")


if __name__ == "__main__":
    unittest.main()
