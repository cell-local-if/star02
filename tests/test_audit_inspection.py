"""Tests for read-only, resumable batch audit inspection.

Covers RequestStore.audit_inspection on the storage layer only: the
fixed result shape, stable acceptance-order scanning, per-item verified
flag and stable reason codes, tamper detection (event delete/alter/
insert/reorder, cross-request and cross-tenant substitution, chain
head, anchor and global head corruption), legacy un-anchored and
secret-missing databases, historical-secret rotation handling, cursor
pagination and resume across rebuilds, validation without writes,
corruption semantics and the strict read-only guarantee for every
audit, anchor and key record. This entry point is deliberately not
exposed over HTTP.
"""

import os
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor

from forgetting_evidence.requests import (
    RequestStore,
    _INSPECTION_CURSOR_PREFIX,
    _decode_cursor,
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


class InspectionConcurrencyTests(_StoreCase):
    def test_concurrent_same_cursor_has_one_whole_page_winner(self):
        store = self._store()
        ids = self._submit_many(store, 8)
        first = store.audit_inspection("tenant-a", limit=2)

        def retry(_index):
            return store.audit_inspection(
                "tenant-a", cursor=first["next_cursor"], limit=6
            )

        with ThreadPoolExecutor(max_workers=8) as pool:
            pages = list(pool.map(retry, range(8)))
        winners = [page for page in pages if page["items"]]
        losers = [page for page in pages if not page["items"]]
        # Exactly one call atomically advanced and reported the page.
        self.assertEqual(len(winners), 1)
        winner = winners[0]
        self.assertEqual(
            [item["request_id"] for item in winner["items"]], ids[2:]
        )
        self.assertIs(winner["finished"], True)
        self.assertIsNone(winner["next_cursor"])
        # Every competitor keeps the same shape with an empty item list
        # and reflects the winner's post-commit position.
        for page in losers:
            self.assertEqual(page["batch_id"], first["batch_id"])
            self.assertEqual(page["items"], [])
            self.assertIs(page["finished"], True)
            self.assertIsNone(page["next_cursor"])
        with self._raw() as raw:
            self.assertEqual(
                raw.execute(
                    "SELECT count(*) FROM inspection_batch_items"
                ).fetchone()[0],
                8,
            )
            self.assertEqual(
                raw.execute("SELECT count(*) FROM inspection_batches").fetchone()[0],
                1,
            )

    def test_concurrent_resume_across_separate_instances(self):
        # Independent store instances (separate in-process locks, the
        # cross-process deployment shape) share the file; SQLite is the
        # only arbiter and still serialises the whole page.
        first_store = self._store()
        self._submit_many(first_store, 9)
        first = first_store.audit_inspection("tenant-a", limit=2)
        others = [self._store() for _ in range(5)]

        def retry(index):
            return others[index].audit_inspection(
                "tenant-a", cursor=first["next_cursor"], limit=7
            )

        with ThreadPoolExecutor(max_workers=5) as pool:
            pages = list(pool.map(retry, range(5)))
        winners = [page for page in pages if page["items"]]
        self.assertEqual(len(winners), 1)
        self.assertEqual(len(winners[0]["items"]), 7)
        self.assertTrue(all(page["finished"] for page in pages))
        self.assertTrue(all(page["next_cursor"] is None for page in pages))
        with self._raw() as raw:
            self.assertEqual(
                raw.execute(
                    "SELECT count(*) FROM inspection_batch_items"
                ).fetchone()[0],
                9,
            )

    def test_concurrent_losers_report_winner_unfinished_cursor(self):
        # The winning page does not finish the sweep: losers must return
        # the winner's new cursor, which remains usable to continue.
        first_store = self._store()
        self._submit_many(first_store, 10)
        first = first_store.audit_inspection("tenant-a", limit=3)
        others = [self._store() for _ in range(4)]

        def retry(index):
            return others[index].audit_inspection(
                "tenant-a", cursor=first["next_cursor"], limit=3
            )

        with ThreadPoolExecutor(max_workers=4) as pool:
            pages = list(pool.map(retry, range(4)))
        winners = [page for page in pages if page["items"]]
        losers = [page for page in pages if not page["items"]]
        self.assertEqual(len(winners), 1)
        winner = winners[0]
        self.assertEqual(len(winner["items"]), 3)
        self.assertIs(winner["finished"], False)
        self.assertEqual(
            _decode_cursor(winner["next_cursor"], _INSPECTION_CURSOR_PREFIX),
            (first["batch_id"], 6),
        )
        self.assertTrue(losers)
        for page in losers:
            self.assertEqual(page["items"], [])
            self.assertIs(page["finished"], False)
            self.assertEqual(page["next_cursor"], winner["next_cursor"])
        continued = first_store.audit_inspection(
            "tenant-a", cursor=losers[0]["next_cursor"], limit=10
        )
        self.assertEqual(len(continued["items"]), 4)
        self.assertIs(continued["finished"], True)
        self.assertIsNone(continued["next_cursor"])

    def test_concurrent_first_calls_create_distinct_batches(self):
        # Calls with no cursor are independent fresh batches; each is its
        # own whole-page advance, never a loser against another batch.
        store = self._store()
        self._submit_many(store, 3)

        def first_page(_index):
            return store.audit_inspection("tenant-a", limit=3)

        with ThreadPoolExecutor(max_workers=4) as pool:
            pages = list(pool.map(first_page, range(4)))
        # Four independent batches, each reporting all three items once.
        self.assertEqual(len({page["batch_id"] for page in pages}), 4)
        self.assertTrue(all(len(page["items"]) == 3 for page in pages))
        with self._raw() as raw:
            self.assertEqual(
                raw.execute("SELECT count(*) FROM inspection_batches").fetchone()[0],
                4,
            )
            self.assertEqual(
                raw.execute("SELECT count(*) FROM inspection_batch_items").fetchone()[0],
                12,
            )

    def test_sequential_retry_after_concurrent_win_does_not_re_report(self):
        store = self._store()
        self._submit_many(store, 4)
        first = store.audit_inspection("tenant-a", limit=2)

        def retry(_index):
            return store.audit_inspection(
                "tenant-a", cursor=first["next_cursor"], limit=2
            )

        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(retry, range(4)))
        # A later, sequential replay of the same now-finished cursor
        # reports nothing and keeps the empty finished cursor.
        again = store.audit_inspection("tenant-a", cursor=first["next_cursor"])
        self.assertEqual(again["batch_id"], first["batch_id"])
        self.assertEqual(again["items"], [])
        self.assertIs(again["finished"], True)
        self.assertIsNone(again["next_cursor"])

    def test_whole_page_commits_results_and_position_together(self):
        store = self._store()
        ids = self._submit_many(store, 5)
        # Tamper with the middle request so the page holds mixed verdicts;
        # the whole page still commits atomically with its position.
        with self._raw() as raw:
            raw.execute(
                "UPDATE requests SET chain_hash = ? WHERE request_id = ?",
                ("0" * 64, ids[2]),
            )
        page = store.audit_inspection("tenant-a")
        self.assertEqual(len(page["items"]), 5)
        self.assertIs(page["finished"], True)
        by_id = {item["request_id"]: item for item in page["items"]}
        self.assertIs(by_id[ids[2]]["verified"], False)
        with self._raw() as raw:
            verdicts = raw.execute(
                "SELECT seq, verified, reason FROM inspection_batch_items "
                "WHERE batch_id = ? ORDER BY seq",
                (page["batch_id"],),
            ).fetchall()
        self.assertEqual([row[0] for row in verdicts], [1, 2, 3, 4, 5])
        self.assertEqual(verdicts[2][1], 0)
        self.assertTrue(verdicts[2][2])
        self.assertTrue(all(row[1] == 1 for i, row in enumerate(verdicts) if i != 2))


class InspectionSummaryTests(_StoreCase):
    def _json_loads(self, text):
        import json

        self.assertTrue(text.endswith("\n"))
        self.assertFalse(text.endswith("\n\n"))
        parsed = json.loads(text)
        # Compact JSON, fixed field order.
        self.assertEqual(
            text,
            json.dumps(parsed, ensure_ascii=False, separators=(",", ":")) + "\n",
        )
        return parsed

    def test_summary_shape_after_finished_batch(self):
        store = self._store()
        ids = self._submit_many(store, 3)
        page = store.audit_inspection("tenant-a")
        text = store.audit_inspection_summary("tenant-a", page["batch_id"])
        summary = self._json_loads(text)
        self.assertEqual(
            list(summary),
            ["batch_id", "scanned", "verified", "unverified",
             "next_cursor", "finished"],
        )
        self.assertEqual(summary["batch_id"], page["batch_id"])
        self.assertEqual(summary["scanned"], 3)
        self.assertEqual(summary["verified"], 3)
        self.assertEqual(summary["unverified"], 0)
        self.assertIsNone(summary["next_cursor"])
        self.assertIs(summary["finished"], True)

    def test_summary_mid_batch_tracks_progress_and_cursor(self):
        store = self._store()
        self._submit_many(store, 5)
        page = store.audit_inspection("tenant-a", limit=2)
        summary = self._json_loads(
            store.audit_inspection_summary("tenant-a", page["batch_id"])
        )
        self.assertEqual(summary["scanned"], 2)
        self.assertEqual(summary["verified"], 2)
        self.assertEqual(summary["unverified"], 0)
        self.assertIs(summary["finished"], False)
        self.assertEqual(summary["next_cursor"], page["next_cursor"])
        # Finish the sweep; the summary advances without a cursor.
        store.audit_inspection("tenant-a", cursor=page["next_cursor"])
        finished_summary = self._json_loads(
            store.audit_inspection_summary("tenant-a", page["batch_id"])
        )
        self.assertEqual(finished_summary["scanned"], 5)
        self.assertIsNone(finished_summary["next_cursor"])
        self.assertIs(finished_summary["finished"], True)

    def test_summary_counts_unverified(self):
        store = self._store()
        ids = self._submit_many(store, 4)
        # Tamper with one request's chain head: only that item fails.
        with self._raw() as raw:
            raw.execute(
                "UPDATE requests SET chain_hash = ? WHERE request_id = ?",
                ("0" * 64, ids[1]),
            )
        page = store.audit_inspection("tenant-a")
        summary = self._json_loads(
            store.audit_inspection_summary("tenant-a", page["batch_id"])
        )
        self.assertEqual(summary["scanned"], 4)
        self.assertEqual(summary["verified"], 3)
        self.assertEqual(summary["unverified"], 1)
        self.assertEqual(
            summary["scanned"], summary["verified"] + summary["unverified"]
        )
        for name in ("scanned", "verified", "unverified"):
            self.assertIsInstance(summary[name], int)
            self.assertGreaterEqual(summary[name], 0)

    def test_summary_does_not_write_anything(self):
        store = self._store()
        self._submit_many(store, 2)
        page = store.audit_inspection("tenant-a")
        tables = (
            "requests",
            "status_events",
            "audit_anchors",
            "audit_anchor_meta",
            "anchor_key_generations",
            "inspection_batches",
            "inspection_batch_items",
            "deletion_receipts",
            "receipt_keys",
            "claim_attempts",
            "claim_tokens",
        )
        before = {table: self._table_dump(table) for table in tables}
        for _ in range(3):
            store.audit_inspection_summary("tenant-a", page["batch_id"])
        after = {table: self._table_dump(table) for table in tables}
        self.assertEqual(before, after)

    def test_summary_does_not_advance_or_create_a_batch(self):
        store = self._store()
        self._submit_many(store, 3)
        page = store.audit_inspection("tenant-a", limit=1)
        store.audit_inspection_summary("tenant-a", page["batch_id"])
        with self._raw() as raw:
            count = raw.execute(
                "SELECT count(*) FROM inspection_batch_items"
            ).fetchone()[0]
            batches = raw.execute(
                "SELECT count(*) FROM inspection_batches"
            ).fetchone()[0]
        self.assertEqual(count, 1)
        self.assertEqual(batches, 1)

    def test_invalid_arguments_raise_value_error_without_writing(self):
        from forgetting_evidence.requests import AuditInspectionNotFound  # noqa: F401

        store = self._store()
        page = store.audit_inspection("tenant-a")
        for bad in ("", None, 5, True, ["tenant-a"]):
            with self.assertRaises(ValueError):
                store.audit_inspection_summary(bad, page["batch_id"])
            with self.assertRaises(ValueError):
                store.audit_inspection_summary("tenant-a", bad)
        with self._raw() as raw:
            self.assertEqual(
                raw.execute("SELECT count(*) FROM inspection_batches").fetchone()[0],
                1,
            )

    def test_missing_batch_raises_not_found(self):
        from forgetting_evidence.requests import AuditInspectionNotFound

        store = self._store()
        with self.assertRaises(AuditInspectionNotFound):
            store.audit_inspection_summary("tenant-a", "no-such-batch")

    def test_cross_tenant_batch_raises_not_found(self):
        from forgetting_evidence.requests import AuditInspectionNotFound

        store = self._store()
        self._submit_many(store, 1, tenant="tenant-a")
        page = store.audit_inspection("tenant-a")
        # The batch exists for tenant-a; tenant-b must not see it.
        with self.assertRaises(AuditInspectionNotFound):
            store.audit_inspection_summary("tenant-b", page["batch_id"])

    def test_corrupt_bookkeeping_raises_storage_error(self):
        store = self._store()
        self._submit_many(store, 2)
        page = store.audit_inspection("tenant-a", limit=1)
        with self._raw() as raw:
            raw.execute(
                "UPDATE inspection_batches SET finished = 7 WHERE batch_id = ?",
                (page["batch_id"],),
            )
        with self.assertRaises(OSError) as caught:
            store.audit_inspection_summary("tenant-a", page["batch_id"])
        self.assertEqual(str(caught.exception), "request store is unavailable")

    def test_corrupt_item_verdict_raises_storage_error(self):
        store = self._store()
        self._submit_many(store, 1)
        page = store.audit_inspection("tenant-a")
        with self._raw() as raw:
            raw.execute(
                "UPDATE inspection_batch_items SET verified = 5 "
                "WHERE batch_id = ?",
                (page["batch_id"],),
            )
        with self.assertRaises(OSError):
            store.audit_inspection_summary("tenant-a", page["batch_id"])


if __name__ == "__main__":
    unittest.main()
