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

from forgetting_evidence.requests import (
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


if __name__ == "__main__":
    unittest.main()
