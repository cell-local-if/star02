"""Tests for read-only, resumable batch audit inspection.

Covers RequestStore.audit_inspection on the storage layer only: the
fixed result shape, stable acceptance-order scanning, per-item verified
flag and stable reason codes, tamper detection (event delete/alter/
insert/reorder, cross-request and cross-tenant substitution, chain
head, anchor and global head corruption), legacy un-anchored and
secret-missing databases, historical-secret rotation handling, cursor
pagination and resume across rebuilds, atomic same-cursor concurrent
continuation (one winning page, empty-item losers observing the
winner's committed progress), the read-only audit_inspection_summary
and audit_inspection_metrics entry points, validation without writes,
corruption semantics and the strict read-only guarantee for every
audit, anchor and key record.
These entry points are deliberately not exposed over HTTP.
"""

import json
import os
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor

from forgetting_evidence.requests import (
    AuditInspectionNotFound,
    RequestStore,
    _INSPECTION_CURSOR_PREFIX,
    _encode_cursor,
)


class _StoreCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "evidence.db")

    def tearDown(self):
        self._tmp.cleanup()

    def _store(self, secret="anchor-secret", history=None):
        return RequestStore(
            self.db_path, anchor_secret=secret, anchor_history_secrets=history
        )

    def _submit_many(self, store, count, tenant="tenant-a"):
        return [
            store.submit(tenant, f"subject-{i}", ["email"], f"key-{i}")["request_id"]
            for i in range(count)
        ]

    def _raw(self):
        return sqlite3.connect(self.db_path)

    def _table_dump(self, table):
        with self._raw() as raw:
            return raw.execute(f"SELECT * FROM {table}").fetchall()


class InspectionShapeTests(_StoreCase):
    def test_empty_tenant_finishes_with_no_items(self):
        store = self._store()
        result = store.audit_inspection("tenant-a")
        self.assertEqual(
            list(result), ["batch_id", "next_cursor", "finished", "items"]
        )
        self.assertIsInstance(result["batch_id"], str)
        self.assertTrue(result["batch_id"])
        self.assertIsNone(result["next_cursor"])
        self.assertIs(result["finished"], True)
        self.assertEqual(result["items"], [])

    def test_healthy_requests_verify_with_empty_reason(self):
        store = self._store()
        request_ids = self._submit_many(store, 3)
        result = store.audit_inspection("tenant-a")
        self.assertIs(result["finished"], True)
        self.assertEqual([item["request_id"] for item in result["items"]], request_ids)
        for item in result["items"]:
            self.assertEqual(set(item), {"request_id", "verified", "reason"})
            self.assertIs(item["verified"], True)
            self.assertEqual(item["reason"], "")

    def test_item_value_types_are_only_str_and_bool(self):
        store = self._store()
        self._submit_many(store, 2)
        result = store.audit_inspection("tenant-a")
        for item in result["items"]:
            self.assertIsInstance(item["request_id"], str)
            self.assertIsInstance(item["verified"], bool)
            self.assertIsInstance(item["reason"], str)

    def test_scan_order_is_acceptance_time_then_request_id(self):
        store = self._store()
        self._submit_many(store, 5)
        result = store.audit_inspection("tenant-a")
        with self._raw() as raw:
            expected = [
                row[0]
                for row in raw.execute(
                    "SELECT request_id FROM requests WHERE tenant_id = ? "
                    "ORDER BY created_at ASC, request_id ASC",
                    ("tenant-a",),
                )
            ]
        self.assertEqual([item["request_id"] for item in result["items"]], expected)

    def test_other_tenants_are_not_scanned(self):
        store = self._store()
        own = self._submit_many(store, 2, tenant="tenant-a")
        self._submit_many(store, 3, tenant="tenant-b")
        result = store.audit_inspection("tenant-a")
        self.assertEqual([item["request_id"] for item in result["items"]], own)
        self.assertIs(result["finished"], True)


class InspectionTrustTests(_StoreCase):
    def test_unanchored_legacy_database_is_not_trusted(self):
        store = RequestStore(self.db_path)  # historical no-secret store
        self._submit_many(store, 2)
        result = store.audit_inspection("tenant-a")
        self.assertEqual(len(result["items"]), 2)
        for item in result["items"]:
            self.assertIs(item["verified"], False)
            self.assertEqual(item["reason"], "unanchored_database")

    def test_anchored_file_without_secret_is_not_trusted(self):
        store = self._store()
        self._submit_many(store, 2)
        no_secret = RequestStore(self.db_path)
        result = no_secret.audit_inspection("tenant-a")
        for item in result["items"]:
            self.assertIs(item["verified"], False)
            self.assertEqual(item["reason"], "anchor_secret_missing")

    def test_wrong_secret_is_not_trusted(self):
        store = self._store()
        self._submit_many(store, 2)
        wrong = RequestStore(self.db_path, anchor_secret="other-secret")
        result = wrong.audit_inspection("tenant-a")
        for item in result["items"]:
            self.assertIs(item["verified"], False)
            self.assertEqual(item["reason"], "anchor_auth_failed")

    def test_altered_event_fails_only_the_tampered_request(self):
        store = self._store()
        request_ids = self._submit_many(store, 2)
        with self._raw() as raw:
            raw.execute(
                "UPDATE status_events SET status = 'failed' "
                "WHERE request_id = ? AND seq = 0",
                (request_ids[0],),
            )
        result = store.audit_inspection("tenant-a")
        by_id = {item["request_id"]: item for item in result["items"]}
        self.assertIs(by_id[request_ids[0]]["verified"], False)
        self.assertTrue(by_id[request_ids[0]]["reason"])
        # The untouched request still verifies: per-item results differ.
        self.assertIs(by_id[request_ids[1]]["verified"], True)
        self.assertEqual(by_id[request_ids[1]]["reason"], "")

    def test_deleted_event_is_detected(self):
        store = self._store()
        request_ids = self._submit_many(store, 2)
        store.transition("tenant-a", request_ids[0], "processing")
        with self._raw() as raw:
            raw.execute(
                "DELETE FROM status_events WHERE request_id = ? AND seq = 1",
                (request_ids[0],),
            )
        result = store.audit_inspection("tenant-a")
        by_id = {item["request_id"]: item for item in result["items"]}
        self.assertIs(by_id[request_ids[0]]["verified"], False)
        self.assertTrue(by_id[request_ids[0]]["reason"])

    def test_inserted_event_is_detected(self):
        store = self._store()
        request_ids = self._submit_many(store, 1)
        with self._raw() as raw:
            row = raw.execute(
                "SELECT tenant_id, request_id, chain_hash FROM status_events "
                "WHERE request_id = ? AND seq = 0",
                (request_ids[0],),
            ).fetchone()
            raw.execute(
                "INSERT INTO status_events ("
                "tenant_id, request_id, seq, status, occurred_at, chain_hash"
                ") VALUES (?, ?, 1, 'processing', '2026-01-01T00:00:00.000000Z', ?)",
                (row[0], row[1], row[2]),
            )
        result = store.audit_inspection("tenant-a")
        self.assertIs(result["items"][0]["verified"], False)
        self.assertTrue(result["items"][0]["reason"])

    def test_reordered_events_are_detected(self):
        store = self._store()
        request_ids = self._submit_many(store, 1)
        store.transition("tenant-a", request_ids[0], "processing")
        store.transition("tenant-a", request_ids[0], "completed")
        with self._raw() as raw:
            # Swap seq 1 and 2 via a scratch value (the primary key
            # forbids a direct one-statement swap).
            raw.execute(
                "UPDATE status_events SET seq = 99 "
                "WHERE request_id = ? AND seq = 1",
                (request_ids[0],),
            )
            raw.execute(
                "UPDATE status_events SET seq = 1 "
                "WHERE request_id = ? AND seq = 2",
                (request_ids[0],),
            )
            raw.execute(
                "UPDATE status_events SET seq = 2 "
                "WHERE request_id = ? AND seq = 99",
                (request_ids[0],),
            )
        result = store.audit_inspection("tenant-a")
        self.assertIs(result["items"][0]["verified"], False)
        self.assertTrue(result["items"][0]["reason"])

    def test_cross_request_event_substitution_is_detected(self):
        store = self._store()
        request_ids = self._submit_many(store, 2)
        with self._raw() as raw:
            # Swap the two requests' genesis events via a scratch id.
            raw.execute(
                "UPDATE status_events SET request_id = 'scratch' "
                "WHERE request_id = ? AND seq = 0",
                (request_ids[0],),
            )
            raw.execute(
                "UPDATE status_events SET request_id = ? "
                "WHERE request_id = ? AND seq = 0",
                (request_ids[0], request_ids[1]),
            )
            raw.execute(
                "UPDATE status_events SET request_id = ? "
                "WHERE request_id = 'scratch' AND seq = 0",
                (request_ids[1],),
            )
        result = store.audit_inspection("tenant-a")
        self.assertEqual(len(result["items"]), 2)
        self.assertTrue(all(not item["verified"] for item in result["items"]))

    def test_cross_tenant_event_substitution_is_detected(self):
        store = self._store()
        own = self._submit_many(store, 1, tenant="tenant-a")
        self._submit_many(store, 1, tenant="tenant-b")
        with self._raw() as raw:
            raw.execute(
                "UPDATE status_events SET tenant_id = 'tenant-b' "
                "WHERE request_id = ? AND seq = 0",
                (own[0],),
            )
        result = store.audit_inspection("tenant-a")
        self.assertIs(result["items"][0]["verified"], False)
        self.assertTrue(result["items"][0]["reason"])

    def test_tampered_request_chain_head_is_detected(self):
        store = self._store()
        request_ids = self._submit_many(store, 2)
        with self._raw() as raw:
            raw.execute(
                "UPDATE requests SET chain_hash = ? WHERE request_id = ?",
                ("0" * 64, request_ids[0]),
            )
        result = store.audit_inspection("tenant-a")
        by_id = {item["request_id"]: item for item in result["items"]}
        self.assertIs(by_id[request_ids[0]]["verified"], False)
        self.assertEqual(by_id[request_ids[0]]["reason"], "chain_head_mismatch")
        self.assertIs(by_id[request_ids[1]]["verified"], True)

    def test_tampered_anchor_is_detected(self):
        store = self._store()
        request_ids = self._submit_many(store, 1)
        with self._raw() as raw:
            raw.execute(
                "UPDATE audit_anchors SET anchor_hmac = ? WHERE request_id = ?",
                ("1" * 64, request_ids[0]),
            )
        result = store.audit_inspection("tenant-a")
        self.assertIs(result["items"][0]["verified"], False)
        self.assertTrue(result["items"][0]["reason"])

    def test_deleted_anchor_breaks_the_global_commit_order(self):
        store = self._store()
        request_ids = self._submit_many(store, 2)
        with self._raw() as raw:
            raw.execute(
                "DELETE FROM audit_anchors WHERE request_id = ?", (request_ids[0],)
            )
        result = store.audit_inspection("tenant-a")
        # The file-wide commit sequence no longer replays gap-free, so no
        # request can be judged trusted.
        self.assertEqual(len(result["items"]), 2)
        for item in result["items"]:
            self.assertIs(item["verified"], False)
            self.assertTrue(item["reason"])

    def test_tampered_global_head_fails_every_request(self):
        store = self._store()
        self._submit_many(store, 2)
        with self._raw() as raw:
            raw.execute("UPDATE audit_anchor_meta SET head_hmac = ?", ("2" * 64,))
        result = store.audit_inspection("tenant-a")
        for item in result["items"]:
            self.assertIs(item["verified"], False)
            self.assertEqual(item["reason"], "anchor_head_mismatch")

    def test_corrupt_event_row_is_detected(self):
        store = self._store()
        request_ids = self._submit_many(store, 1)
        with self._raw() as raw:
            raw.execute(
                "UPDATE status_events SET chain_hash = 'zz' WHERE request_id = ?",
                (request_ids[0],),
            )
        result = store.audit_inspection("tenant-a")
        self.assertIs(result["items"][0]["verified"], False)
        self.assertEqual(result["items"][0]["reason"], "anchor_row_corrupt")

    def test_missing_historical_secret_is_not_trusted(self):
        store = self._store(secret="secret-1")
        self._submit_many(store, 1)
        store.rotate_anchor_key("secret-1", "secret-2")
        # Sealed under generation 2 (a distinct idempotency key).
        store.submit("tenant-a", "subject-9", ["email"], "key-9")
        # Rebuilt without the generation-1 historical secret.
        rebuilt = self._store(secret="secret-2")
        result = rebuilt.audit_inspection("tenant-a")
        self.assertEqual(len(result["items"]), 2)
        for item in result["items"]:
            self.assertIs(item["verified"], False)
            self.assertEqual(item["reason"], "anchor_key_missing")
        # Rebuilt with the historical secret: everything verifies again.
        complete = self._store(secret="secret-2", history={1: "secret-1"})
        result = complete.audit_inspection("tenant-a")
        for item in result["items"]:
            self.assertIs(item["verified"], True)
            self.assertEqual(item["reason"], "")

    def test_broken_generation_association_is_detected(self):
        store = self._store()
        request_ids = self._submit_many(store, 1)
        with self._raw() as raw:
            raw.execute(
                "UPDATE audit_anchors SET key_generation = 9 WHERE request_id = ?",
                (request_ids[0],),
            )
        result = store.audit_inspection("tenant-a")
        self.assertIs(result["items"][0]["verified"], False)
        self.assertTrue(result["items"][0]["reason"])


class InspectionPaginationTests(_StoreCase):
    def test_limit_paginates_and_cursor_resumes_same_batch(self):
        store = self._store()
        request_ids = self._submit_many(store, 3)
        first = store.audit_inspection("tenant-a", limit=2)
        self.assertIs(first["finished"], False)
        self.assertEqual(len(first["items"]), 2)
        self.assertIsInstance(first["next_cursor"], str)
        self.assertTrue(first["next_cursor"].startswith(_INSPECTION_CURSOR_PREFIX))
        second = store.audit_inspection("tenant-a", cursor=first["next_cursor"])
        self.assertEqual(second["batch_id"], first["batch_id"])
        self.assertIs(second["finished"], True)
        self.assertIsNone(second["next_cursor"])
        self.assertEqual(len(second["items"]), 1)
        seen = [item["request_id"] for item in first["items"] + second["items"]]
        self.assertEqual(seen, request_ids)

    def test_default_limit_is_one_hundred(self):
        store = self._store()
        self._submit_many(store, 101)
        result = store.audit_inspection("tenant-a")
        self.assertIs(result["finished"], False)
        self.assertEqual(len(result["items"]), 100)

    def test_resume_survives_store_rebuild(self):
        store = self._store()
        request_ids = self._submit_many(store, 3)
        first = store.audit_inspection("tenant-a", limit=1)
        rebuilt = self._store()
        second = rebuilt.audit_inspection(
            "tenant-a", cursor=first["next_cursor"], limit=1
        )
        self.assertEqual(second["batch_id"], first["batch_id"])
        third = rebuilt.audit_inspection(
            "tenant-a", cursor=second["next_cursor"], limit=1
        )
        seen = [
            item["request_id"]
            for item in first["items"] + second["items"] + third["items"]
        ]
        self.assertEqual(seen, request_ids)
        self.assertIs(third["finished"], True)

    def test_finished_batch_cursor_replay_reports_nothing(self):
        store = self._store()
        self._submit_many(store, 2)
        first = store.audit_inspection("tenant-a", limit=1)
        second = store.audit_inspection("tenant-a", cursor=first["next_cursor"])
        self.assertIs(second["finished"], True)
        # A stale cursor resumes from the durable position, not its own
        # encoded count: the finished batch reports no further items.
        third = store.audit_inspection("tenant-a", cursor=first["next_cursor"])
        self.assertEqual(third["batch_id"], first["batch_id"])
        self.assertIs(third["finished"], True)
        self.assertEqual(third["items"], [])

    def test_settled_items_are_persisted_once(self):
        store = self._store()
        self._submit_many(store, 3)
        first = store.audit_inspection("tenant-a", limit=2)
        store.audit_inspection("tenant-a", cursor=first["next_cursor"])
        with self._raw() as raw:
            rows = raw.execute(
                "SELECT seq, request_id, verified, reason "
                "FROM inspection_batch_items WHERE batch_id = ? ORDER BY seq",
                (first["batch_id"],),
            ).fetchall()
        self.assertEqual([row[0] for row in rows], [1, 2, 3])
        self.assertTrue(all(row[2] == 1 and row[3] == "" for row in rows))


class InspectionValidationTests(_StoreCase):
    def _batch_count(self):
        if not os.path.exists(self.db_path):
            return None
        with self._raw() as raw:
            return raw.execute("SELECT count(*) FROM inspection_batches").fetchone()[0]

    def test_invalid_tenant_id_raises_without_writing(self):
        store = self._store()
        for bad in ("", None, 5, True, ["tenant-a"]):
            with self.assertRaises(ValueError):
                store.audit_inspection(bad)
        self.assertEqual(self._batch_count(), 0)

    def test_invalid_limit_raises_without_writing(self):
        store = self._store()
        self._submit_many(store, 1)
        before = self._batch_count()
        for bad in (0, 1001, -1, True, False, "100", 1.5, object()):
            with self.assertRaises(ValueError):
                store.audit_inspection("tenant-a", limit=bad)
        self.assertEqual(self._batch_count(), before)

    def test_invalid_cursor_raises_without_writing(self):
        store = self._store()
        self._submit_many(store, 1)
        before = self._batch_count()
        for bad in ("", 5, True, "nonsense", "rc1." + "A" * 8, "ai1.!!!"):
            with self.assertRaises(ValueError):
                store.audit_inspection("tenant-a", cursor=bad)
        self.assertEqual(self._batch_count(), before)

    def test_reconcile_cursor_is_an_unknown_format_here(self):
        store = self._store()
        self._submit_many(store, 1)
        reconcile_cursor = _encode_cursor("some-batch", 0)  # rc1. prefix
        with self.assertRaises(ValueError):
            store.audit_inspection("tenant-a", cursor=reconcile_cursor)
        # And the inspection cursor is foreign to the reconcile entry.
        inspection_cursor = _encode_cursor(
            "some-batch", 0, _INSPECTION_CURSOR_PREFIX
        )
        with self.assertRaises(ValueError):
            store.reconcile_batch("tenant-a", cursor=inspection_cursor)

    def test_unknown_batch_cursor_raises(self):
        store = self._store()
        self._submit_many(store, 1)
        cursor = _encode_cursor("no-such-batch", 0, _INSPECTION_CURSOR_PREFIX)
        with self.assertRaises(ValueError):
            store.audit_inspection("tenant-a", cursor=cursor)

    def test_cross_tenant_cursor_raises(self):
        store = self._store()
        self._submit_many(store, 2, tenant="tenant-a")
        self._submit_many(store, 1, tenant="tenant-b")
        first = store.audit_inspection("tenant-a", limit=1)
        with self.assertRaises(ValueError):
            store.audit_inspection("tenant-b", cursor=first["next_cursor"])


class InspectionCorruptionTests(_StoreCase):
    def test_corrupt_batch_state_raises_storage_error(self):
        store = self._store()
        self._submit_many(store, 2)
        first = store.audit_inspection("tenant-a", limit=1)
        with self._raw() as raw:
            raw.execute(
                "UPDATE inspection_batches SET finished = 7 WHERE batch_id = ?",
                (first["batch_id"],),
            )
        with self.assertRaises(OSError) as caught:
            store.audit_inspection("tenant-a", cursor=first["next_cursor"])
        self.assertEqual(str(caught.exception), "request store is unavailable")

    def test_split_batch_position_raises_storage_error(self):
        store = self._store()
        self._submit_many(store, 2)
        first = store.audit_inspection("tenant-a", limit=1)
        with self._raw() as raw:
            raw.execute(
                "UPDATE inspection_batches SET position_request_id = NULL "
                "WHERE batch_id = ?",
                (first["batch_id"],),
            )
        with self.assertRaises(OSError) as caught:
            store.audit_inspection("tenant-a", cursor=first["next_cursor"])
        self.assertEqual(str(caught.exception), "request store is unavailable")


class InspectionReadOnlyTests(_StoreCase):
    def test_inspection_never_modifies_audit_anchor_or_key_records(self):
        store = self._store(secret="secret-1")
        request_ids = self._submit_many(store, 3)
        store.transition("tenant-a", request_ids[0], "processing")
        store.rotate_anchor_key("secret-1", "secret-2")
        tables = (
            "requests",
            "status_events",
            "audit_anchors",
            "audit_anchor_meta",
            "anchor_key_generations",
            "claim_attempts",
            "claim_tokens",
            "deletion_receipts",
            "receipt_keys",
        )
        before = {table: self._table_dump(table) for table in tables}
        result = store.audit_inspection("tenant-a")
        self.assertIs(result["finished"], True)
        self.assertEqual(len(result["items"]), 3)
        after = {table: self._table_dump(table) for table in tables}
        self.assertEqual(before, after)

    def test_inspection_of_tampered_file_still_writes_only_bookkeeping(self):
        store = self._store()
        request_ids = self._submit_many(store, 1)
        with self._raw() as raw:
            raw.execute(
                "UPDATE status_events SET status = 'failed' WHERE request_id = ?",
                (request_ids[0],),
            )
        before = {
            table: self._table_dump(table)
            for table in ("requests", "status_events", "audit_anchors")
        }
        result = store.audit_inspection("tenant-a")
        self.assertIs(result["items"][0]["verified"], False)
        after = {
            table: self._table_dump(table)
            for table in ("requests", "status_events", "audit_anchors")
        }
        # The tampered evidence is reported, never repaired or recomputed.
        self.assertEqual(before, after)


class InspectionConcurrentContinuationTests(_StoreCase):
    def _continue(self, store, tenant_id, cursor, limit, barrier=None):
        if barrier is not None:
            barrier.wait()
        return store.audit_inspection(tenant_id, cursor=cursor, limit=limit)

    def test_sequential_same_cursor_replay_reports_nothing_twice(self):
        store = self._store()
        request_ids = self._submit_many(store, 6)
        first = store.audit_inspection("tenant-a", limit=2)
        self.assertEqual(
            [item["request_id"] for item in first["items"]], request_ids[:2]
        )
        # The first presentation of the cursor is the normal resume and
        # advances the next page.
        second = store.audit_inspection(
            "tenant-a", cursor=first["next_cursor"], limit=2
        )
        self.assertEqual(
            [item["request_id"] for item in second["items"]], request_ids[2:4]
        )
        # Re-presenting the now-stale first cursor is a pure replay:
        # empty items at the post-commit progress, nothing re-reported.
        replay = store.audit_inspection(
            "tenant-a", cursor=first["next_cursor"], limit=2
        )
        self.assertEqual(replay["batch_id"], first["batch_id"])
        self.assertEqual(replay["items"], [])
        self.assertEqual(replay["next_cursor"], second["next_cursor"])
        self.assertIs(replay["finished"], False)
        with self._raw() as raw:
            count = raw.execute(
                "SELECT count(*) FROM inspection_batch_items WHERE batch_id = ?",
                (first["batch_id"],),
            ).fetchone()[0]
        self.assertEqual(count, 4)

    def test_concurrent_same_cursor_has_one_winning_page(self):
        # Distinct store instances share the file so the database write
        # lock (not the in-process lock) decides the race.
        stores = [self._store() for _ in range(8)]
        request_ids = self._submit_many(stores[0], 5)
        first = stores[0].audit_inspection("tenant-a", limit=2)
        self.assertEqual(len(first["items"]), 2)
        stale_cursor = first["next_cursor"]

        barrier = threading.Barrier(len(stores))
        with ThreadPoolExecutor(max_workers=len(stores)) as pool:
            results = list(
                pool.map(
                    lambda store: self._continue(
                        store, "tenant-a", stale_cursor, 2, barrier
                    ),
                    stores,
                )
            )

        # Exactly one call won the page; every competitor replayed the
        # winner's committed progress with an empty item list.
        winning = [result for result in results if result["items"]]
        losing = [result for result in results if not result["items"]]
        self.assertEqual(len(winning), 1)
        self.assertEqual(len(losing), len(stores) - 1)
        winner = winning[0]
        self.assertEqual(
            [item["request_id"] for item in winner["items"]], request_ids[2:4]
        )
        for result in results:
            self.assertEqual(result["batch_id"], first["batch_id"])
            self.assertEqual(result["next_cursor"], winner["next_cursor"])
            self.assertIs(result["finished"], False)
        # The page committed atomically exactly once.
        with self._raw() as raw:
            rows = raw.execute(
                "SELECT seq, request_id FROM inspection_batch_items "
                "WHERE batch_id = ? ORDER BY seq",
                (first["batch_id"],),
            ).fetchall()
        self.assertEqual([row[0] for row in rows], [1, 2, 3, 4])
        self.assertEqual([row[1] for row in rows], request_ids[:4])

    def test_concurrent_first_call_creates_independent_batches(self):
        # No cursor means a fresh batch per call: concurrency must never
        # merge two sweeps into one batch or duplicate rows within one.
        stores = [self._store() for _ in range(6)]
        self._submit_many(stores[0], 3)
        barrier = threading.Barrier(len(stores))

        def run(store):
            barrier.wait()
            return store.audit_inspection("tenant-a", limit=2)

        with ThreadPoolExecutor(max_workers=len(stores)) as pool:
            results = list(pool.map(run, stores))
        batch_ids = {result["batch_id"] for result in results}
        self.assertEqual(len(batch_ids), len(stores))
        for result in results:
            self.assertEqual(len(result["items"]), 2)
        # Every batch owns its own disjoint seq space.
        with self._raw() as raw:
            per_batch = raw.execute(
                "SELECT batch_id, count(*) FROM inspection_batch_items GROUP BY batch_id"
            ).fetchall()
        self.assertEqual(sorted(count for _b, count in per_batch), [2] * len(stores))

    def test_concurrent_finished_cursor_replays_empty_with_null_cursor(self):
        stores = [self._store() for _ in range(6)]
        self._submit_many(stores[0], 2)
        first = stores[0].audit_inspection("tenant-a", limit=1)
        # Drive the batch to its finished state.
        stores[0].audit_inspection("tenant-a", cursor=first["next_cursor"])
        barrier = threading.Barrier(len(stores))
        with ThreadPoolExecutor(max_workers=len(stores)) as pool:
            results = list(
                pool.map(
                    lambda store: self._continue(
                        store, "tenant-a", first["next_cursor"], 1, barrier
                    ),
                    stores,
                )
            )
        for result in results:
            self.assertEqual(result["items"], [])
            self.assertIsNone(result["next_cursor"])
            self.assertIs(result["finished"], True)

    def test_resume_after_concurrent_win_does_not_re_report(self):
        stores = [self._store() for _ in range(4)]
        request_ids = self._submit_many(stores[0], 4)
        first = stores[0].audit_inspection("tenant-a", limit=1)
        barrier = threading.Barrier(len(stores))
        with ThreadPoolExecutor(max_workers=len(stores)) as pool:
            results = list(
                pool.map(
                    lambda store: self._continue(
                        store, "tenant-a", first["next_cursor"], 1, barrier
                    ),
                    stores,
                )
            )
        winner = next(result for result in results if result["items"])
        losers = [result for result in results if not result["items"]]
        self.assertTrue(losers)
        # A sequential resume from the winner's cursor continues after
        # the winner's page and never repeats a settled request.
        tail = stores[0].audit_inspection("tenant-a", cursor=winner["next_cursor"])
        reported = [
            item["request_id"]
            for item in first["items"] + winner["items"] + tail["items"]
        ]
        self.assertEqual(reported, request_ids)
        self.assertIs(tail["finished"], True)
        self.assertIsNone(tail["next_cursor"])

    def test_concurrent_continuation_never_touches_business_records(self):
        stores = [self._store() for _ in range(6)]
        request_ids = self._submit_many(stores[0], 3)
        stores[0].transition("tenant-a", request_ids[0], "processing")
        tables = (
            "requests",
            "status_events",
            "audit_anchors",
            "audit_anchor_meta",
            "anchor_key_generations",
            "claim_attempts",
            "claim_tokens",
            "deletion_receipts",
            "receipt_keys",
        )
        before = {table: self._table_dump(table) for table in tables}
        first = stores[0].audit_inspection("tenant-a", limit=1)
        barrier = threading.Barrier(len(stores))
        with ThreadPoolExecutor(max_workers=len(stores)) as pool:
            list(
                pool.map(
                    lambda store: self._continue(
                        store, "tenant-a", first["next_cursor"], 1, barrier
                    ),
                    stores,
                )
            )
        after = {table: self._table_dump(table) for table in tables}
        self.assertEqual(before, after)


class InspectionSummaryTests(_StoreCase):
    def _summary(self, store, tenant_id, batch_id):
        return store.audit_inspection_summary(tenant_id, batch_id)

    def _parse(self, text):
        self.assertTrue(text.endswith("\n"))
        self.assertFalse(text.endswith("\n\n"))
        # Compact JSON: no whitespace outside strings, fields in order.
        self.assertNotIn(" ", text)
        parsed = json.loads(text)
        self.assertEqual(
            list(parsed),
            ["batch_id", "scanned", "verified", "unverified", "next_cursor", "finished"],
        )
        return parsed

    def test_summary_of_finished_batch(self):
        store = self._store()
        request_ids = self._submit_many(store, 3)
        result = store.audit_inspection("tenant-a")
        text = self._summary(store, "tenant-a", result["batch_id"])
        parsed = self._parse(text)
        self.assertEqual(parsed["batch_id"], result["batch_id"])
        self.assertEqual(parsed["scanned"], 3)
        self.assertEqual(parsed["verified"], 3)
        self.assertEqual(parsed["unverified"], 0)
        self.assertIsNone(parsed["next_cursor"])
        self.assertIs(parsed["finished"], True)
        self.assertEqual(len(request_ids), parsed["scanned"])
        for name in ("scanned", "verified", "unverified"):
            self.assertIsInstance(parsed[name], int)
            self.assertGreaterEqual(parsed[name], 0)
        self.assertEqual(parsed["scanned"], parsed["verified"] + parsed["unverified"])

    def test_summary_of_partial_batch_carries_resumable_cursor(self):
        store = self._store()
        self._submit_many(store, 4)
        result = store.audit_inspection("tenant-a", limit=3)
        text = self._summary(store, "tenant-a", result["batch_id"])
        parsed = self._parse(text)
        self.assertEqual(parsed["scanned"], 3)
        self.assertIs(parsed["finished"], False)
        self.assertEqual(parsed["next_cursor"], result["next_cursor"])
        # The summary's cursor resumes the batch.
        tail = store.audit_inspection("tenant-a", cursor=parsed["next_cursor"])
        self.assertEqual(len(tail["items"]), 1)
        self.assertIs(tail["finished"], True)

    def test_summary_counts_unverified_items(self):
        store = self._store()
        request_ids = self._submit_many(store, 3)
        with self._raw() as raw:
            raw.execute(
                "UPDATE status_events SET status = 'failed' "
                "WHERE request_id = ? AND seq = 0",
                (request_ids[0],),
            )
        result = store.audit_inspection("tenant-a")
        parsed = self._parse(
            self._summary(store, "tenant-a", result["batch_id"])
        )
        self.assertEqual(parsed["scanned"], 3)
        self.assertEqual(parsed["verified"], 2)
        self.assertEqual(parsed["unverified"], 1)

    def test_summary_of_brand_new_empty_batch(self):
        store = self._store()
        result = store.audit_inspection("tenant-a")
        parsed = self._parse(
            self._summary(store, "tenant-a", result["batch_id"])
        )
        self.assertEqual(parsed["scanned"], 0)
        self.assertEqual(parsed["verified"], 0)
        self.assertEqual(parsed["unverified"], 0)
        self.assertIsNone(parsed["next_cursor"])
        self.assertIs(parsed["finished"], True)

    def test_summary_is_strictly_read_only(self):
        store = self._store(secret="secret-1")
        request_ids = self._submit_many(store, 3)
        store.transition("tenant-a", request_ids[0], "processing")
        store.rotate_anchor_key("secret-1", "secret-2")
        result = store.audit_inspection("tenant-a", limit=2)
        tables = (
            "requests",
            "status_events",
            "audit_anchors",
            "audit_anchor_meta",
            "anchor_key_generations",
            "claim_attempts",
            "claim_tokens",
            "deletion_receipts",
            "receipt_keys",
            "inspection_batches",
            "inspection_batch_items",
        )
        before = {table: self._table_dump(table) for table in tables}
        self._summary(store, "tenant-a", result["batch_id"])
        # Repeated reads do not advance anything either.
        self._summary(store, "tenant-a", result["batch_id"])
        after = {table: self._table_dump(table) for table in tables}
        self.assertEqual(before, after)
        # The batch is still mid-sweep, exactly as the summary reported.
        unchanged = store.audit_inspection(
            "tenant-a", cursor=result["next_cursor"]
        )
        self.assertEqual(len(unchanged["items"]), 1)

    def test_summary_invalid_arguments_raise_value_error_without_writing(self):
        store = self._store()
        result = store.audit_inspection("tenant-a")

        def batch_count():
            with self._raw() as raw:
                return raw.execute("SELECT count(*) FROM inspection_batches").fetchone()[0]

        before = batch_count()
        for bad_tenant in ("", None, 5, True, ["tenant-a"]):
            with self.assertRaises(ValueError):
                store.audit_inspection_summary(bad_tenant, result["batch_id"])
        for bad_batch in ("", None, 7, False, {"id": "x"}):
            with self.assertRaises(ValueError):
                store.audit_inspection_summary("tenant-a", bad_batch)
        self.assertEqual(batch_count(), before)

    def test_summary_missing_batch_raises_not_found(self):
        store = self._store()
        self._submit_many(store, 1)
        with self.assertRaises(AuditInspectionNotFound):
            self._summary(store, "tenant-a", "no-such-batch")

    def test_summary_cross_tenant_batch_raises_not_found(self):
        store = self._store()
        self._submit_many(store, 1, tenant="tenant-a")
        result = store.audit_inspection("tenant-a")
        with self.assertRaises(AuditInspectionNotFound):
            self._summary(store, "tenant-b", result["batch_id"])

    def test_summary_corrupt_bookkeeping_raises_storage_error(self):
        store = self._store()
        self._submit_many(store, 2)
        result = store.audit_inspection("tenant-a", limit=1)
        with self._raw() as raw:
            raw.execute(
                "UPDATE inspection_batch_items SET verified = 9 WHERE batch_id = ?",
                (result["batch_id"],),
            )
        with self.assertRaises(OSError) as caught:
            self._summary(store, "tenant-a", result["batch_id"])
        self.assertEqual(str(caught.exception), "request store is unavailable")

    def test_summary_missing_table_raises_storage_error(self):
        store = self._store()
        result = store.audit_inspection("tenant-a")
        with self._raw() as raw:
            raw.execute("DROP TABLE inspection_batches")
        with self.assertRaises(OSError) as caught:
            self._summary(store, "tenant-a", result["batch_id"])
        self.assertEqual(str(caught.exception), "request store is unavailable")

    def test_summary_accepts_batch_id_not_cursor(self):
        # The raw batch id works; an encoded cursor is not a batch id and
        # is simply a missing batch, never decoded.
        store = self._store()
        self._submit_many(store, 2)
        result = store.audit_inspection("tenant-a", limit=1)
        parsed = self._parse(
            self._summary(store, "tenant-a", result["batch_id"])
        )
        self.assertTrue(parsed["next_cursor"])
        with self.assertRaises(AuditInspectionNotFound):
            self._summary(store, "tenant-a", result["next_cursor"])


class InspectionMetricsTests(_StoreCase):
    def _metrics(self, store, tenant_id, batch_id):
        return store.audit_inspection_metrics(tenant_id, batch_id)

    def _parse(self, text):
        self.assertTrue(text.endswith("\n"))
        self.assertFalse(text.endswith("\n\n"))
        # Compact JSON: no whitespace outside strings, fields in order.
        self.assertNotIn(" ", text)
        parsed = json.loads(text)
        self.assertEqual(
            list(parsed),
            ["batch_id", "scanned", "reasons", "next_cursor", "finished"],
        )
        return parsed

    def test_metrics_of_finished_batch_all_verified(self):
        store = self._store()
        request_ids = self._submit_many(store, 3)
        result = store.audit_inspection("tenant-a")
        parsed = self._parse(self._metrics(store, "tenant-a", result["batch_id"]))
        self.assertEqual(parsed["batch_id"], result["batch_id"])
        self.assertEqual(parsed["scanned"], len(request_ids))
        self.assertIsInstance(parsed["scanned"], int)
        self.assertNotIsInstance(parsed["scanned"], bool)
        self.assertGreaterEqual(parsed["scanned"], 0)
        # Verified items carry the empty reason and never enter the list.
        self.assertEqual(parsed["reasons"], [])
        self.assertIsNone(parsed["next_cursor"])
        self.assertIs(parsed["finished"], True)

    def test_metrics_reason_counts_merged_sorted_and_counted_once(self):
        store = self._store()
        request_ids = self._submit_many(store, 4)
        with self._raw() as raw:
            # Two requests fail with the same reason, one with another.
            raw.execute(
                "UPDATE status_events SET status = 'failed' "
                "WHERE request_id = ? AND seq = 0",
                (request_ids[0],),
            )
            raw.execute(
                "UPDATE status_events SET status = 'failed' "
                "WHERE request_id = ? AND seq = 0",
                (request_ids[2],),
            )
            raw.execute(
                "UPDATE requests SET chain_hash = ? WHERE request_id = ?",
                ("0" * 64, request_ids[1]),
            )
        result = store.audit_inspection("tenant-a")
        parsed = self._parse(self._metrics(store, "tenant-a", result["batch_id"]))
        self.assertEqual(parsed["scanned"], 4)
        # Expected breakdown derived from the settled per-item results:
        # duplicate reasons merge, each unverified item contributes once.
        expected = {}
        for item in result["items"]:
            if item["verified"]:
                self.assertEqual(item["reason"], "")
                continue
            expected[item["reason"]] = expected.get(item["reason"], 0) + 1
        self.assertEqual(len(expected), 2)
        self.assertEqual(
            parsed["reasons"],
            [
                {"reason": reason, "count": expected[reason]}
                for reason in sorted(expected)
            ],
        )
        counts = {entry["reason"]: entry["count"] for entry in parsed["reasons"]}
        self.assertEqual(counts.get("chain_head_mismatch"), 1)
        self.assertEqual(sum(counts.values()), 3)
        # Unicode code point order, no duplicate codes, positive counts.
        codes = [entry["reason"] for entry in parsed["reasons"]]
        self.assertEqual(codes, sorted(codes))
        self.assertEqual(len(codes), len(set(codes)))
        for entry in parsed["reasons"]:
            self.assertEqual(list(entry), ["reason", "count"])
            self.assertIsInstance(entry["reason"], str)
            self.assertTrue(entry["reason"])
            self.assertIsInstance(entry["count"], int)
            self.assertNotIsInstance(entry["count"], bool)
            self.assertGreaterEqual(entry["count"], 1)

    def test_metrics_of_partial_batch_carries_resumable_cursor(self):
        store = self._store()
        self._submit_many(store, 4)
        result = store.audit_inspection("tenant-a", limit=3)
        parsed = self._parse(self._metrics(store, "tenant-a", result["batch_id"]))
        self.assertEqual(parsed["scanned"], 3)
        self.assertEqual(parsed["reasons"], [])
        self.assertIs(parsed["finished"], False)
        self.assertEqual(parsed["next_cursor"], result["next_cursor"])
        # The metrics' cursor resumes the batch; the read advanced nothing.
        tail = store.audit_inspection("tenant-a", cursor=parsed["next_cursor"])
        self.assertEqual(len(tail["items"]), 1)
        self.assertIs(tail["finished"], True)

    def test_metrics_of_brand_new_empty_batch(self):
        store = self._store()
        result = store.audit_inspection("tenant-a")
        parsed = self._parse(self._metrics(store, "tenant-a", result["batch_id"]))
        self.assertEqual(parsed["scanned"], 0)
        self.assertEqual(parsed["reasons"], [])
        self.assertIsNone(parsed["next_cursor"])
        self.assertIs(parsed["finished"], True)

    def test_metrics_is_strictly_read_only(self):
        store = self._store(secret="secret-1")
        request_ids = self._submit_many(store, 3)
        store.transition("tenant-a", request_ids[0], "processing")
        store.rotate_anchor_key("secret-1", "secret-2")
        result = store.audit_inspection("tenant-a", limit=2)
        tables = (
            "requests",
            "status_events",
            "audit_anchors",
            "audit_anchor_meta",
            "anchor_key_generations",
            "claim_attempts",
            "claim_tokens",
            "deletion_receipts",
            "receipt_keys",
            "inspection_batches",
            "inspection_batch_items",
        )
        before = {table: self._table_dump(table) for table in tables}
        first = self._metrics(store, "tenant-a", result["batch_id"])
        # Repeated reads return the same text and advance nothing.
        second = self._metrics(store, "tenant-a", result["batch_id"])
        self.assertEqual(first, second)
        after = {table: self._table_dump(table) for table in tables}
        self.assertEqual(before, after)
        # The batch is still mid-sweep, exactly as the metrics reported.
        unchanged = store.audit_inspection(
            "tenant-a", cursor=result["next_cursor"]
        )
        self.assertEqual(len(unchanged["items"]), 1)

    def test_metrics_invalid_arguments_raise_value_error_without_writing(self):
        store = self._store()
        result = store.audit_inspection("tenant-a")

        def batch_count():
            with self._raw() as raw:
                return raw.execute("SELECT count(*) FROM inspection_batches").fetchone()[0]

        before = batch_count()
        for bad_tenant in ("", None, 5, True, ["tenant-a"]):
            with self.assertRaises(ValueError):
                store.audit_inspection_metrics(bad_tenant, result["batch_id"])
        for bad_batch in ("", None, 7, False, {"id": "x"}):
            with self.assertRaises(ValueError):
                store.audit_inspection_metrics("tenant-a", bad_batch)
        self.assertEqual(batch_count(), before)

    def test_metrics_missing_batch_raises_not_found(self):
        store = self._store()
        self._submit_many(store, 1)
        with self.assertRaises(AuditInspectionNotFound):
            self._metrics(store, "tenant-a", "no-such-batch")

    def test_metrics_cross_tenant_batch_raises_not_found(self):
        store = self._store()
        self._submit_many(store, 1, tenant="tenant-a")
        result = store.audit_inspection("tenant-a")
        # Missing and cross-tenant batches share one indistinguishable outcome.
        with self.assertRaises(AuditInspectionNotFound):
            self._metrics(store, "tenant-b", result["batch_id"])

    def test_metrics_corrupt_bookkeeping_raises_storage_error(self):
        statements = (
            "UPDATE inspection_batch_items SET verified = 9 WHERE batch_id = ?",
            "UPDATE inspection_batch_items SET reason = 'chain_hash_mismatch' "
            "WHERE batch_id = ? AND verified = 1",
            "UPDATE inspection_batch_items SET reason = '' "
            "WHERE batch_id = ? AND verified = 0",
        )
        for index, statement in enumerate(statements):
            with self.subTest(statement=statement):
                # Each corruption gets its own fresh database file.
                db_path = os.path.join(
                    self._tmp.name, f"corrupt-{index}", "evidence.db"
                )
                store = RequestStore(db_path, anchor_secret="anchor-secret")
                request_ids = self._submit_many(store, 2)
                with sqlite3.connect(db_path) as raw:
                    raw.execute(
                        "UPDATE status_events SET status = 'failed' "
                        "WHERE request_id = ? AND seq = 0",
                        (request_ids[0],),
                    )
                result = store.audit_inspection("tenant-a")
                with sqlite3.connect(db_path) as raw:
                    raw.execute(statement, (result["batch_id"],))
                with self.assertRaises(OSError) as caught:
                    self._metrics(store, "tenant-a", result["batch_id"])
                self.assertEqual(str(caught.exception), "request store is unavailable")

    def test_metrics_missing_table_raises_storage_error(self):
        store = self._store()
        result = store.audit_inspection("tenant-a")
        with self._raw() as raw:
            raw.execute("DROP TABLE inspection_batches")
        with self.assertRaises(OSError) as caught:
            self._metrics(store, "tenant-a", result["batch_id"])
        self.assertEqual(str(caught.exception), "request store is unavailable")

    def test_metrics_accepts_batch_id_not_cursor(self):
        # The raw batch id works; an encoded cursor is not a batch id and
        # is simply a missing batch, never decoded.
        store = self._store()
        self._submit_many(store, 2)
        result = store.audit_inspection("tenant-a", limit=1)
        parsed = self._parse(self._metrics(store, "tenant-a", result["batch_id"]))
        self.assertTrue(parsed["next_cursor"])
        with self.assertRaises(AuditInspectionNotFound):
            self._metrics(store, "tenant-a", result["next_cursor"])


if __name__ == "__main__":
    unittest.main()
