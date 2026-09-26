"""Tests for the recoverable execution-lease migration.

Covers RequestStore.migrate_execution_leases on the storage layer only:
the fixed compact JSON line shape, the one-time bookkeeping upgrade of
legacy execution_leases rows (verbatim times and results, a single
recoverable live credential), resumable stable pagination across
retries, restarts and concurrent same-cursor calls, the idempotent
``current`` replay, the no-second-lease boundary (expired/terminal/
credential-less histories stay with reconcile), validation of
tenant/cursor/limit without writes, the fixed-text
``execution_lease_migration_failed`` OSError on damaged legacy rows with
whole-page rollback, and the no-leak/no-HTTP-surface guarantees. This
entry point is deliberately not exposed over HTTP.
"""

import hashlib
import json
import os
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from forgetting_evidence import httpapi
from forgetting_evidence.requests import (
    ClaimConflict,
    RequestStore,
    _encode_cursor,
    _LEASE_MIGRATION_CURSOR_PREFIX,
)

LEGACY_DDL = (
    "CREATE TABLE IF NOT EXISTS execution_leases ("
    "tenant_id TEXT NOT NULL, request_id TEXT NOT NULL, "
    "attempt_number INTEGER NOT NULL, claimed_at TEXT NOT NULL, "
    "lease_expires_at TEXT NOT NULL, result TEXT, completed_at TEXT, "
    "claim_hash TEXT, "
    "PRIMARY KEY (tenant_id, request_id, attempt_number))"
)


def _rfc(offset_seconds):
    return (
        datetime.now(timezone.utc) + timedelta(seconds=offset_seconds)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")


class _StoreCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "evidence.db")

    def tearDown(self):
        self._tmp.cleanup()

    def _store(self, *args, **kwargs):
        return RequestStore(self.db_path, *args, **kwargs)

    def _submit(self, store, tenant="tenant-a", key="key-1", subject="subject-1"):
        return store.submit(tenant, subject, ["email"], key)

    def _submit_many(self, store, count, tenant="tenant-a"):
        return [
            store.submit(tenant, f"subject-{i}", ["email"], f"key-{i}")[
                "request_id"
            ]
            for i in range(count)
        ]

    def _legacy_table(self):
        with sqlite3.connect(self.db_path) as raw:
            raw.execute(LEGACY_DDL)

    def _insert_legacy(
        self,
        tenant,
        request_id,
        attempt_number,
        claimed_at,
        lease_expires_at,
        result=None,
        completed_at=None,
        claim_hash=...,
    ):
        if claim_hash is ...:
            claim_hash = None
        with sqlite3.connect(self.db_path) as raw:
            raw.execute(
                "INSERT INTO execution_leases VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    tenant,
                    request_id,
                    attempt_number,
                    claimed_at,
                    lease_expires_at,
                    result,
                    completed_at,
                    claim_hash,
                ),
            )

    def _move_live_claim_to_legacy(self, store, request_id, claim, tenant="tenant-a"):
        """Relocate a current live claim's bookkeeping into the legacy table."""
        token_hash = hashlib.sha256(
            claim["claim_token"].encode("utf-8")
        ).hexdigest()
        with sqlite3.connect(self.db_path) as raw:
            raw.execute(LEGACY_DDL)
            rows = raw.execute(
                "SELECT attempt_number, claimed_at, lease_expires_at, result, "
                "completed_at FROM claim_attempts WHERE request_id = ?",
                (request_id,),
            ).fetchall()
            for attempt_number, claimed_at, expires, result, completed in rows:
                raw.execute(
                    "INSERT INTO execution_leases VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        tenant,
                        request_id,
                        attempt_number,
                        claimed_at,
                        expires,
                        result,
                        completed,
                        token_hash if attempt_number == rows[-1][0] else None,
                    ),
                )
            raw.execute(
                "DELETE FROM claim_attempts WHERE request_id = ?", (request_id,)
            )
            raw.execute(
                "DELETE FROM claim_tokens WHERE request_id = ?", (request_id,)
            )

    def _parse(self, text):
        self.assertTrue(text.endswith("\n"))
        self.assertFalse(text.endswith("\n\n"))
        # Compact JSON: no insignificant whitespace.
        self.assertNotIn(", ", text)
        self.assertNotIn(": ", text)
        return json.loads(text)


class LeaseMigrationShapeTests(_StoreCase):
    def test_empty_tenant_finishes_with_empty_items_and_one_newline(self):
        store = self._store()
        text = store.migrate_execution_leases("tenant-a")
        doc = self._parse(text)
        self.assertEqual(
            list(doc), ["batch_id", "next_cursor", "finished", "items"]
        )
        self.assertIsInstance(doc["batch_id"], str)
        self.assertTrue(doc["batch_id"])
        self.assertIsNone(doc["next_cursor"])
        self.assertIs(doc["finished"], True)
        self.assertEqual(doc["items"], [])

    def test_no_legacy_table_is_a_clean_empty_finish(self):
        # A current-version database has no legacy table at all: the
        # migration finishes with nothing to upgrade rather than failing.
        store = self._store()
        self._submit(store)
        doc = self._parse(store.migrate_execution_leases("tenant-a"))
        self.assertIs(doc["finished"], True)
        self.assertEqual(doc["items"], [])
        with sqlite3.connect(self.db_path) as raw:
            self.assertEqual(
                raw.execute("SELECT count(*) FROM claim_attempts").fetchone()[0], 0
            )

    def test_item_shape_carries_no_worker_or_credential(self):
        store = self._store()
        receipt = self._submit(store)
        claim = store.claim_next("tenant-a", "worker-1", 3600)
        self._move_live_claim_to_legacy(store, receipt["request_id"], claim)
        doc = self._parse(store.migrate_execution_leases("tenant-a"))
        (item,) = doc["items"]
        self.assertEqual(set(item), {"request_id", "attempt_number", "outcome"})
        self.assertEqual(item["request_id"], receipt["request_id"])
        self.assertEqual(item["attempt_number"], 1)
        self.assertEqual(item["outcome"], "upgraded")
        self.assertNotIn("claim_token", json.dumps(doc))
        self.assertNotIn("worker", json.dumps(doc))
        self.assertNotIn(claim["claim_token"], store.migrate_execution_leases("tenant-a"))


class LeaseMigrationUpgradeTests(_StoreCase):
    def test_live_legacy_lease_is_recovered_verbatim_and_usable(self):
        store = self._store()
        receipt = self._submit(store)
        claim = store.claim_next("tenant-a", "worker-1", 3600)
        before_expiry = claim["lease_expires_at"]
        self._move_live_claim_to_legacy(store, receipt["request_id"], claim)

        doc = self._parse(store.migrate_execution_leases("tenant-a"))
        self.assertEqual(doc["items"][0]["outcome"], "upgraded")

        # The attempt history comes across verbatim; only the single live
        # credential is made usable again.
        log = store.get_execution_log("tenant-a", receipt["request_id"])
        self.assertEqual(len(log), 1)
        self.assertEqual(log[0]["attempt_number"], 1)
        self.assertEqual(log[0]["result"], None)
        self.assertEqual(log[0]["completed_at"], None)
        self.assertEqual(log[0]["lease_expires_at"], before_expiry)
        renewed = store.renew_lease(
            "tenant-a", receipt["request_id"], claim["claim_token"], 300
        )
        self.assertEqual(renewed["request_id"], receipt["request_id"])
        record = store.finish_claim(
            "tenant-a", receipt["request_id"], claim["claim_token"], "completed"
        )
        self.assertEqual(record["status"], "completed")

    def test_rebuilt_instance_keeps_the_same_lease_state(self):
        first = self._store()
        receipt = self._submit(first)
        claim = first.claim_next("tenant-a", "worker-1", 3600)
        self._move_live_claim_to_legacy(first, receipt["request_id"], claim)
        self._parse(first.migrate_execution_leases("tenant-a"))

        rebuilt = self._store()
        renewed = rebuilt.renew_lease(
            "tenant-a", receipt["request_id"], claim["claim_token"], 600
        )
        self.assertEqual(renewed["request_id"], receipt["request_id"])
        self.assertEqual(
            rebuilt.get_execution_log("tenant-a", receipt["request_id"])[0][
                "attempt_number"
            ],
            1,
        )

    def test_expired_legacy_lease_is_history_only_and_reclaim_increments(self):
        store = self._store()
        receipt = self._submit(store)
        claimed_at = _rfc(-3600)
        expired_at = _rfc(-1)
        self._legacy_table()
        self._insert_legacy(
            "tenant-a",
            receipt["request_id"],
            1,
            claimed_at,
            expired_at,
            claim_hash=None,
        )
        # The request is processing with an expired open legacy lease.
        with sqlite3.connect(self.db_path) as raw:
            raw.execute(
                "UPDATE requests SET status = 'processing' WHERE request_id = ?",
                (receipt["request_id"],),
            )
        self._parse(store.migrate_execution_leases("tenant-a"))
        # No live credential is ever restored for an expired lease.
        with sqlite3.connect(self.db_path) as raw:
            self.assertEqual(
                raw.execute(
                    "SELECT count(*) FROM claim_tokens WHERE request_id = ?",
                    (receipt["request_id"],),
                ).fetchone()[0],
                0,
            )
        # Existing reconcile convergence takes over, exactly as before.
        record = store.reconcile_execution("tenant-a", receipt["request_id"])
        self.assertEqual(record["status"], "failed")
        log = store.get_execution_log("tenant-a", receipt["request_id"])
        self.assertEqual(log[0]["claimed_at"], claimed_at)
        self.assertEqual(log[0]["lease_expires_at"], expired_at)
        self.assertEqual(log[0]["result"], "failed")

    def test_open_unexpired_lease_without_retained_hash_is_not_revived(self):
        store = self._store()
        receipt = self._submit(store)
        claim = store.claim_next("tenant-a", "worker-1", 3600)
        self._move_live_claim_to_legacy(store, receipt["request_id"], claim)
        with sqlite3.connect(self.db_path) as raw:
            raw.execute(
                "UPDATE execution_leases SET claim_hash = NULL WHERE request_id = ?",
                (receipt["request_id"],),
            )
        self._parse(store.migrate_execution_leases("tenant-a"))
        with self.assertRaises(ClaimConflict):
            store.renew_lease(
                "tenant-a", receipt["request_id"], claim["claim_token"], 60
            )
        with sqlite3.connect(self.db_path) as raw:
            self.assertEqual(
                raw.execute(
                    "SELECT count(*) FROM claim_tokens WHERE request_id = ?",
                    (receipt["request_id"],),
                ).fetchone()[0],
                0,
            )

    def test_terminal_legacy_attempts_are_copied_verbatim_and_unlock_receipt(self):
        store = self._store()
        receipt = self._submit(store)
        claimed_at = _rfc(-7200)
        expired_at = _rfc(-3600)
        completed_at = _rfc(-1800)
        self._legacy_table()
        self._insert_legacy(
            "tenant-a",
            receipt["request_id"],
            1,
            claimed_at,
            expired_at,
            result="completed",
            completed_at=completed_at,
            claim_hash=None,
        )
        with sqlite3.connect(self.db_path) as raw:
            raw.execute(
                "UPDATE requests SET status = 'completed' WHERE request_id = ?",
                (receipt["request_id"],),
            )
        self._parse(store.migrate_execution_leases("tenant-a"))
        log = store.get_execution_log("tenant-a", receipt["request_id"])
        self.assertEqual(
            (
                log[0]["attempt_number"],
                log[0]["claimed_at"],
                log[0]["lease_expires_at"],
                log[0]["result"],
                log[0]["completed_at"],
            ),
            (1, claimed_at, expired_at, "completed", completed_at),
        )
        self.assertEqual(
            store.get_status("tenant-a", receipt["request_id"])["status"], "completed"
        )
        text = store.generate_receipt("tenant-a", receipt["request_id"], "key")
        self.assertTrue(store.verify_receipt(text, "key"))

    def test_multi_attempt_history_keeps_incrementing_after_migration(self):
        store = self._store()
        receipt = self._submit(store)
        self._legacy_table()
        self._insert_legacy(
            "tenant-a", receipt["request_id"], 1, _rfc(-7200), _rfc(-3600)
        )
        self._insert_legacy(
            "tenant-a", receipt["request_id"], 2, _rfc(-1800), _rfc(-900)
        )
        with sqlite3.connect(self.db_path) as raw:
            raw.execute(
                "UPDATE requests SET status = 'processing' WHERE request_id = ?",
                (receipt["request_id"],),
            )
        doc = self._parse(store.migrate_execution_leases("tenant-a"))
        self.assertEqual(doc["items"][0]["attempt_number"], 2)
        # Both expired, no live credential: an expired reclaim starts the
        # next sequential attempt rather than reusing an old number.
        claim = store.claim_next("tenant-a", "worker-2", 3600)
        self.assertIsNotNone(claim)
        self.assertEqual(claim["request_id"], receipt["request_id"])
        self.assertEqual(
            [a["attempt_number"] for a in store.get_execution_log(
                "tenant-a", receipt["request_id"]
            )],
            [1, 2, 3],
        )

    def test_migration_does_not_create_a_second_live_lease(self):
        store = self._store()
        ids = self._submit_many(store, 2)
        live = store.claim_next("tenant-a", "worker-1", 3600)
        self.assertEqual(live["request_id"], ids[0])
        self._move_live_claim_to_legacy(store, ids[0], live)
        self._parse(store.migrate_execution_leases("tenant-a"))
        # The recovered live lease keeps the request out of the claim
        # candidate set: the next claim goes to the other request, never a
        # second concurrent lease for the migrated one.
        again = store.claim_next("tenant-a", "worker-2", 3600)
        self.assertEqual(again["request_id"], ids[1])
        self.assertIsNone(store.claim_next("tenant-a", "worker-3", 3600))

    def test_status_events_and_acceptance_record_are_untouched(self):
        store = self._store()
        receipt = self._submit(store)
        claim = store.claim_next("tenant-a", "worker-1", 3600)
        self._move_live_claim_to_legacy(store, receipt["request_id"], claim)
        with sqlite3.connect(self.db_path) as raw:
            events_before = raw.execute(
                "SELECT seq, status, occurred_at FROM status_events "
                "WHERE request_id = ? ORDER BY seq",
                (receipt["request_id"],),
            ).fetchall()
            created_before = raw.execute(
                "SELECT created_at, status FROM requests WHERE request_id = ?",
                (receipt["request_id"],),
            ).fetchone()
        self._parse(store.migrate_execution_leases("tenant-a"))
        with sqlite3.connect(self.db_path) as raw:
            events_after = raw.execute(
                "SELECT seq, status, occurred_at FROM status_events "
                "WHERE request_id = ? ORDER BY seq",
                (receipt["request_id"],),
            ).fetchall()
            created_after = raw.execute(
                "SELECT created_at, status FROM requests WHERE request_id = ?",
                (receipt["request_id"],),
            ).fetchone()
        self.assertEqual(events_before, events_after)
        self.assertEqual(created_before, created_after)


class LeaseMigrationPaginationTests(_StoreCase):
    def _legacy_requests(self, count):
        store = self._store()
        ids = self._submit_many(store, count)
        for request_id in ids:
            claim = store.claim_next("tenant-a", "worker-1", 3600)
            self.assertEqual(claim["request_id"], request_id)
            self._move_live_claim_to_legacy(store, request_id, claim)
        return store, ids

    def test_pages_follow_stable_acceptance_order_and_keep_batch_id(self):
        store, ids = self._legacy_requests(4)
        first = self._parse(store.migrate_execution_leases("tenant-a", limit=2))
        self.assertEqual([i["request_id"] for i in first["items"]], ids[:2])
        self.assertFalse(first["finished"])
        self.assertIsNotNone(first["next_cursor"])
        second = self._parse(
            store.migrate_execution_leases(
                "tenant-a", first["next_cursor"], limit=2
            )
        )
        self.assertEqual(second["batch_id"], first["batch_id"])
        self.assertEqual([i["request_id"] for i in second["items"]], ids[2:])
        self.assertTrue(second["finished"])
        self.assertIsNone(second["next_cursor"])

    def test_resume_continues_from_persisted_position_after_restart(self):
        first_store, ids = self._legacy_requests(3)
        page = self._parse(
            first_store.migrate_execution_leases("tenant-a", limit=1)
        )
        rebuilt = self._store()
        resumed = self._parse(
            rebuilt.migrate_execution_leases("tenant-a", page["next_cursor"], 10)
        )
        self.assertEqual(resumed["batch_id"], page["batch_id"])
        self.assertEqual([i["request_id"] for i in resumed["items"]], ids[1:])
        self.assertTrue(resumed["finished"])

    def test_empty_finished_batch_keeps_durable_progress(self):
        store = self._store()
        first = self._parse(store.migrate_execution_leases("tenant-a"))
        # The empty batch is durable: resuming it replays the same
        # finished, empty progress with the same batch identifier.
        cursor = _encode_cursor(first["batch_id"], 0, _LEASE_MIGRATION_CURSOR_PREFIX)
        replay = self._parse(store.migrate_execution_leases("tenant-a", cursor))
        self.assertEqual(replay["batch_id"], first["batch_id"])
        self.assertEqual(replay["items"], [])
        self.assertTrue(replay["finished"])
        self.assertIsNone(replay["next_cursor"])


class LeaseMigrationIdempotencyTests(_StoreCase):
    def test_repeat_migration_reports_current_and_rewrites_nothing(self):
        store = self._store()
        receipt = self._submit(store)
        claim = store.claim_next("tenant-a", "worker-1", 3600)
        self._move_live_claim_to_legacy(store, receipt["request_id"], claim)
        self._parse(store.migrate_execution_leases("tenant-a"))
        with sqlite3.connect(self.db_path) as raw:
            attempts = raw.execute(
                "SELECT attempt_number, claimed_at, lease_expires_at, result, "
                "completed_at FROM claim_attempts WHERE request_id = ?",
                (receipt["request_id"],),
            ).fetchall()
        again = self._parse(store.migrate_execution_leases("tenant-a"))
        self.assertEqual(
            [(i["request_id"], i["outcome"]) for i in again["items"]],
            [(receipt["request_id"], "current")],
        )
        with sqlite3.connect(self.db_path) as raw:
            self.assertEqual(
                raw.execute(
                    "SELECT count(*) FROM claim_attempts WHERE request_id = ?",
                    (receipt["request_id"],),
                ).fetchone()[0],
                1,
            )
            self.assertEqual(
                raw.execute(
                    "SELECT attempt_number, claimed_at, lease_expires_at, result, "
                    "completed_at FROM claim_attempts WHERE request_id = ?",
                    (receipt["request_id"],),
                ).fetchall(),
                attempts,
            )

    def test_request_since_leased_by_current_version_is_current(self):
        store = self._store()
        receipt = self._submit(store)
        claim = store.claim_next("tenant-a", "worker-1", 3600)
        # The current version already holds this request's attempt
        # bookkeeping; a stale legacy row for the same request must be
        # ignored rather than copied alongside it.
        self._legacy_table()
        self._insert_legacy(
            "tenant-a",
            receipt["request_id"],
            1,
            _rfc(-7200),
            _rfc(-3600),
        )
        doc = self._parse(store.migrate_execution_leases("tenant-a"))
        self.assertEqual(doc["items"][0]["outcome"], "current")
        self.assertEqual(doc["items"][0]["attempt_number"], 1)
        with sqlite3.connect(self.db_path) as raw:
            # Exactly the one current attempt; the legacy row was never
            # copied, and the live credential still works.
            self.assertEqual(
                raw.execute(
                    "SELECT count(*) FROM claim_attempts WHERE request_id = ?",
                    (receipt["request_id"],),
                ).fetchone()[0],
                1,
            )
        renewed = store.renew_lease(
            "tenant-a", receipt["request_id"], claim["claim_token"], 60
        )
        self.assertEqual(renewed["request_id"], receipt["request_id"])

    def test_same_cursor_replay_returns_empty_items(self):
        store = self._store()
        ids = self._submit_many(store, 3)
        for request_id in ids:
            claim = store.claim_next("tenant-a", "worker-1", 3600)
            self._move_live_claim_to_legacy(store, request_id, claim)
        first = self._parse(store.migrate_execution_leases("tenant-a", limit=2))
        cursor = first["next_cursor"]
        second = self._parse(store.migrate_execution_leases("tenant-a", cursor, 10))
        self.assertEqual([i["request_id"] for i in second["items"]], ids[2:])
        # Replaying the now-finished cursor reports nothing twice.
        replay = self._parse(store.migrate_execution_leases("tenant-a", cursor, 10))
        self.assertEqual(replay["items"], [])
        self.assertTrue(replay["finished"])
        self.assertEqual(replay["batch_id"], first["batch_id"])

    def test_each_request_upgraded_once_across_batches(self):
        store = self._store()
        receipt = self._submit(store)
        claim = store.claim_next("tenant-a", "worker-1", 3600)
        self._move_live_claim_to_legacy(store, receipt["request_id"], claim)
        for _ in range(3):
            self._parse(store.migrate_execution_leases("tenant-a"))
        with sqlite3.connect(self.db_path) as raw:
            self.assertEqual(
                raw.execute(
                    "SELECT count(*) FROM claim_attempts WHERE request_id = ?",
                    (receipt["request_id"],),
                ).fetchone()[0],
                1,
            )


class LeaseMigrationConcurrencyTests(_StoreCase):
    def test_same_cursor_has_one_winner_and_empty_competitors(self):
        setup = self._store()
        ids = self._submit_many(setup, 3)
        for request_id in ids:
            claim = setup.claim_next("tenant-a", "worker-1", 3600)
            self._move_live_claim_to_legacy(setup, request_id, claim)
        first = self._parse(setup.migrate_execution_leases("tenant-a", limit=2))
        cursor = first["next_cursor"]

        results = []
        barrier = threading.Barrier(2)

        def run():
            store = self._store()
            barrier.wait()
            return store.migrate_execution_leases("tenant-a", cursor, 10)

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = [self._parse(text) for text in executor.map(lambda _: run(), range(2))]
        item_counts = sorted(len(doc["items"]) for doc in results)
        self.assertEqual(item_counts, [0, 1])
        self.assertEqual(results[0]["batch_id"], results[1]["batch_id"])
        self.assertEqual(results[0]["batch_id"], first["batch_id"])
        winner = results[0] if results[0]["items"] else results[1]
        loser = results[1] if results[0]["items"] else results[0]
        self.assertEqual(winner["items"][0]["request_id"], ids[2])
        self.assertEqual(winner["items"][0]["outcome"], "upgraded")
        self.assertTrue(winner["finished"])
        self.assertIsNone(winner["next_cursor"])
        self.assertEqual(loser["items"], [])
        self.assertTrue(loser["finished"])
        self.assertIsNone(loser["next_cursor"])
        # The page landed exactly once.
        with sqlite3.connect(self.db_path) as raw:
            self.assertEqual(
                raw.execute(
                    "SELECT count(*) FROM claim_attempts WHERE tenant_id = 'tenant-a'"
                ).fetchone()[0],
                3,
            )
            self.assertEqual(
                raw.execute(
                    "SELECT count(*) FROM execution_lease_migration_items "
                    "WHERE batch_id = ?",
                    (first["batch_id"],),
                ).fetchone()[0],
                3,
            )

    def test_two_fresh_calls_each_create_their_own_batch(self):
        # Without a cursor there is no shared continuation: two
        # simultaneous first calls are independent batches (the second
        # then observes the first's upgrade as ``current``), matching the
        # inspection sweep's semantics.
        setup = self._store()
        receipt = self._submit(setup)
        claim = setup.claim_next("tenant-a", "worker-1", 3600)
        self._move_live_claim_to_legacy(setup, receipt["request_id"], claim)
        a, b = self._store(), self._store()
        with ThreadPoolExecutor(max_workers=2) as executor:
            docs = [
                self._parse(text)
                for text in executor.map(
                    lambda store: store.migrate_execution_leases("tenant-a"),
                    [a, b],
                )
            ]
        self.assertNotEqual(docs[0]["batch_id"], docs[1]["batch_id"])
        self.assertEqual(
            sorted(doc["items"][0]["outcome"] for doc in docs),
            ["current", "upgraded"],
        )


class LeaseMigrationValidationTests(_StoreCase):
    def test_invalid_tenant_raises_value_error_without_writes(self):
        store = self._store()
        for bad_tenant in ("", None, 123, True, ["tenant-a"]):
            with self.assertRaises(ValueError):
                store.migrate_execution_leases(bad_tenant)
        with sqlite3.connect(self.db_path) as raw:
            self.assertEqual(
                raw.execute(
                    "SELECT count(*) FROM execution_lease_migration_batches"
                ).fetchone()[0],
                0,
            )

    def test_invalid_limit_raises_value_error_without_writes(self):
        store = self._store()
        for bad_limit in (0, -1, 1001, 1.5, True, "100", [10]):
            with self.assertRaises(ValueError):
                store.migrate_execution_leases("tenant-a", None, bad_limit)
        with sqlite3.connect(self.db_path) as raw:
            self.assertEqual(
                raw.execute(
                    "SELECT count(*) FROM execution_lease_migration_batches"
                ).fetchone()[0],
                0,
            )

    def test_malformed_and_foreign_prefix_cursors_raise_value_error(self):
        store = self._store()
        self._submit(store)
        for bad_cursor in (
            "",
            "garbage",
            123,
            True,
            "rc1.xxxx",
            "ai1.xxxx",
            _encode_cursor("missing-batch", 0),
        ):
            with self.assertRaises(ValueError):
                store.migrate_execution_leases("tenant-a", bad_cursor)

    def test_unknown_and_cross_tenant_cursor_raise_value_error(self):
        store = self._store()
        receipt = self._submit(store, tenant="tenant-a", key="ka")
        self._submit(store, tenant="tenant-b", key="kb")
        claim = store.claim_next("tenant-a", "worker-1", 3600)
        self._move_live_claim_to_legacy(store, receipt["request_id"], claim)
        first = self._parse(store.migrate_execution_leases("tenant-a"))
        # A finished batch cursor reused from another tenant must not
        # reveal that the batch exists.
        cursor = _encode_cursor(
            first["batch_id"], 1, _LEASE_MIGRATION_CURSOR_PREFIX
        )
        with self.assertRaises(ValueError):
            store.migrate_execution_leases("tenant-b", cursor)
        with self.assertRaises(ValueError):
            store.migrate_execution_leases(
                "tenant-b",
                _encode_cursor(
                    "00000000-0000-0000-0000-000000000000",
                    0,
                    _LEASE_MIGRATION_CURSOR_PREFIX,
                ),
            )


class LeaseMigrationStorageFailureTests(_StoreCase):
    def _assert_fixed_text(self, ctx):
        self.assertEqual(str(ctx.exception), "execution_lease_migration_failed")
        self.assertNotIn("sqlite", str(ctx.exception).lower())
        self.assertNotIn(self.db_path, str(ctx.exception))

    def test_damaged_legacy_row_is_os_error(self):
        store = self._store()
        receipt = self._submit(store)
        self._legacy_table()
        self._insert_legacy(
            "tenant-a",
            receipt["request_id"],
            1,
            "not-a-timestamp",
            _rfc(3600),
        )
        with sqlite3.connect(self.db_path) as raw:
            raw.execute(
                "UPDATE requests SET status = 'processing' WHERE request_id = ?",
                (receipt["request_id"],),
            )
            raw.execute(
                "UPDATE execution_leases SET claimed_at = x'0102' "
                "WHERE request_id = ?",
                (receipt["request_id"],),
            )
        with self.assertRaises(OSError) as ctx:
            store.migrate_execution_leases("tenant-a")
        self._assert_fixed_text(ctx)

    def test_bad_claim_hash_is_os_error(self):
        store = self._store()
        receipt = self._submit(store)
        self._legacy_table()
        self._insert_legacy(
            "tenant-a",
            receipt["request_id"],
            1,
            _rfc(-10),
            _rfc(3600),
            claim_hash="not-a-sha256-hex",
        )
        with sqlite3.connect(self.db_path) as raw:
            raw.execute(
                "UPDATE requests SET status = 'processing' WHERE request_id = ?",
                (receipt["request_id"],),
            )
        with self.assertRaises(OSError) as ctx:
            store.migrate_execution_leases("tenant-a")
        self._assert_fixed_text(ctx)

    def test_split_result_pair_is_os_error(self):
        store = self._store()
        receipt = self._submit(store)
        self._legacy_table()
        self._insert_legacy(
            "tenant-a",
            receipt["request_id"],
            1,
            _rfc(-10),
            _rfc(3600),
            result="completed",
            completed_at=None,
        )
        with self.assertRaises(OSError) as ctx:
            store.migrate_execution_leases("tenant-a")
        self._assert_fixed_text(ctx)

    def test_two_simultaneously_live_legacy_attempts_is_os_error(self):
        store = self._store()
        receipt = self._submit(store)
        self._legacy_table()
        self._insert_legacy(
            "tenant-a",
            receipt["request_id"],
            1,
            _rfc(-100),
            _rfc(3600),
            claim_hash=hashlib.sha256(b"a").hexdigest(),
        )
        self._insert_legacy(
            "tenant-a",
            receipt["request_id"],
            2,
            _rfc(-50),
            _rfc(3600),
            claim_hash=hashlib.sha256(b"b").hexdigest(),
        )
        with sqlite3.connect(self.db_path) as raw:
            raw.execute(
                "UPDATE requests SET status = 'processing' WHERE request_id = ?",
                (receipt["request_id"],),
            )
        with self.assertRaises(OSError) as ctx:
            store.migrate_execution_leases("tenant-a")
        self._assert_fixed_text(ctx)
        with sqlite3.connect(self.db_path) as raw:
            self.assertEqual(
                raw.execute(
                    "SELECT count(*) FROM claim_attempts WHERE request_id = ?",
                    (receipt["request_id"],),
                ).fetchone()[0],
                0,
            )

    def test_failed_page_leaves_no_half_page_and_resume_redoing_only_it(self):
        store = self._store()
        good = self._submit(store, key="k-good")["request_id"]
        bad = self._submit(store, key="k-bad")["request_id"]
        self._legacy_table()
        for request_id, offset in ((good, 1), (bad, 2)):
            self._insert_legacy(
                "tenant-a",
                request_id,
                1,
                _rfc(-100 + offset),
                _rfc(3600),
                claim_hash=hashlib.sha256(b"x").hexdigest(),
            )
            with sqlite3.connect(self.db_path) as raw:
                raw.execute(
                    "UPDATE requests SET status = 'processing' WHERE request_id = ?",
                    (request_id,),
                )
        # Damage the second candidate; a single page covering both must
        # roll back as a whole -- no batch row, no item, no copied attempt.
        with sqlite3.connect(self.db_path) as raw:
            raw.execute(
                "UPDATE execution_leases SET attempt_number = 2 "
                "WHERE request_id = ?",
                (bad,),
            )
        with self.assertRaises(OSError) as ctx:
            store.migrate_execution_leases("tenant-a", limit=10)
        self._assert_fixed_text(ctx)
        with sqlite3.connect(self.db_path) as raw:
            self.assertEqual(
                raw.execute("SELECT count(*) FROM claim_attempts").fetchone()[0], 0
            )
            self.assertEqual(
                raw.execute("SELECT count(*) FROM claim_tokens").fetchone()[0], 0
            )
            self.assertEqual(
                raw.execute(
                    "SELECT count(*) FROM execution_lease_migration_items"
                ).fetchone()[0],
                0,
            )
        # Repair the damage; the next call upgrades both requests, with no
        # half page to undo.
        with sqlite3.connect(self.db_path) as raw:
            raw.execute(
                "UPDATE execution_leases SET attempt_number = 1 WHERE request_id = ?",
                (bad,),
            )
        doc = self._parse(store.migrate_execution_leases("tenant-a", limit=10))
        self.assertEqual(
            [i["request_id"] for i in doc["items"]], [good, bad]
        )
        self.assertTrue(all(i["outcome"] == "upgraded" for i in doc["items"]))

    def test_unopenable_file_is_os_error(self):
        # Hold an already-initialised instance, then corrupt the file out
        # of band so the migration call -- not construction -- fails.
        store = self._store()
        with open(self.db_path, "wb") as handle:
            handle.write(b"not a sqlite database")
        with self.assertRaises(OSError) as ctx:
            store.migrate_execution_leases("tenant-a")
        self._assert_fixed_text(ctx)


class LeaseMigrationNoSurfaceChangeTests(_StoreCase):
    def test_storage_layer_entry_is_not_an_http_route(self):
        # The HTTP surface keeps exactly the acceptance endpoints; the
        # migration is storage-layer only and never changes routing.
        store = self._store()
        handler_cls = httpapi.make_handler(store)

        class _Dummy:
            pass

        dummy = _Dummy()
        dummy.path = "/requests"
        self.assertEqual(handler_cls._route(dummy), ("collection", None))
        dummy.path = "/requests/abc"
        self.assertEqual(handler_cls._route(dummy), ("item", "abc"))
        for unknown in (
            "/execution-lease-migrations",
            "/execution-leases/migrate",
            "/leases",
        ):
            dummy.path = unknown
            self.assertEqual(handler_cls._route(dummy), (None, None))

    def test_accepted_request_without_lease_stays_with_reconcile(self):
        # An accepted request with no legacy lease is untouched: it is
        # not swept, and no lease bookkeeping is fabricated for it.
        store = self._store()
        receipt = self._submit(store)
        self._legacy_table()
        doc = self._parse(store.migrate_execution_leases("tenant-a"))
        self.assertEqual(doc["items"], [])
        self.assertTrue(doc["finished"])
        with sqlite3.connect(self.db_path) as raw:
            self.assertEqual(
                raw.execute(
                    "SELECT count(*) FROM claim_attempts WHERE request_id = ?",
                    (receipt["request_id"],),
                ).fetchone()[0],
                0,
            )
        # The ordinary claim path still starts attempt 1.
        claim = store.claim_next("tenant-a", "worker-1", 3600)
        self.assertEqual(claim["request_id"], receipt["request_id"])
        self.assertEqual(
            store.get_execution_log(
                "tenant-a", receipt["request_id"]
            )[0]["attempt_number"],
            1,
        )

    def test_anchored_database_migrates_without_secret_or_new_events(self):
        store = self._store(anchor_secret="anchor-secret")
        receipt = self._submit(store)
        claim = store.claim_next("tenant-a", "worker-1", 3600)
        self._move_live_claim_to_legacy(store, receipt["request_id"], claim)
        with sqlite3.connect(self.db_path) as raw:
            anchors_before = raw.execute(
                "SELECT count(*) FROM audit_anchors"
            ).fetchone()[0]
        # A rebuilt instance without the anchor secret still performs the
        # bookkeeping-only migration; no anchor event is involved.
        no_secret = self._store()
        doc = self._parse(no_secret.migrate_execution_leases("tenant-a"))
        self.assertEqual(doc["items"][0]["outcome"], "upgraded")
        with sqlite3.connect(self.db_path) as raw:
            self.assertEqual(
                raw.execute("SELECT count(*) FROM audit_anchors").fetchone()[0],
                anchors_before,
            )
        # The settled chain still verifies under the secret holder.
        rebuilt_secret = self._store(anchor_secret="anchor-secret")
        self.assertTrue(
            rebuilt_secret.verify_chain("tenant-a", receipt["request_id"])
        )
        self.assertEqual(
            rebuilt_secret.get_status(
                "tenant-a", receipt["request_id"]
            )["status"],
            "processing",
        )

    def test_deferred_wrapper_is_storage_faithful_and_http_unchanged(self):
        # The deferred wrapper keeps serving the storage entry like the
        # rest of the orchestration, while the HTTP module exposes no new
        # endpoint.
        deferred = httpapi.DeferredRequestStore(self.db_path)
        self.assertTrue(hasattr(deferred, "migrate_execution_leases"))
        text = deferred.migrate_execution_leases("tenant-a")
        self._parse(text)


if __name__ == "__main__":
    unittest.main()
