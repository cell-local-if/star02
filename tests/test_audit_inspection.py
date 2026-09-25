"""Tests for the read-only, resumable batch audit inspection.

Covers RequestStore.audit_inspection on the storage layer only: the
fixed result shape, stable acceptance-order scanning, limit pagination,
opaque cursor resume and idempotency across retries and rebuilds,
per-item verification outcomes with stable reason codes under
tampering, the strictly read-only guarantee for audit/anchor/key
records, validation of tenant/cursor/limit without writes, corruption
semantics, and the no-leak guarantees. This entry point is deliberately
not exposed over HTTP.
"""

import base64
import hashlib
import json
import os
import sqlite3
import struct
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor

from forgetting_evidence import httpapi
from forgetting_evidence.requests import (
    RequestStore,
    _INSPECTION_CURSOR_PREFIX,
    _decode_cursor,
    _encode_cursor,
)

SECRET = "anchor-secret-one"
GENESIS = hashlib.sha256(b"").hexdigest()

# The stable, detail-free reason codes an item may ever report.
KNOWN_REASONS = {
    "anchor_secret_missing",
    "unanchored_database",
    "anchor_state_split",
    "anchor_meta_corrupt",
    "event_unanchored",
    "anchor_orphan",
    "event_order_invalid",
    "chain_hash_mismatch",
    "chain_head_mismatch",
    "request_status_mismatch",
    "request_association_mismatch",
    "anchor_auth_failed",
    "anchor_sequence_gap",
    "anchor_head_mismatch",
    "anchor_row_corrupt",
    "anchor_key_missing",
}

# Tables holding the audit, anchor, receipt and key evidence: an
# inspection may never change any of them.
EVIDENCE_TABLES = (
    "requests",
    "status_events",
    "claim_attempts",
    "claim_tokens",
    "reconcile_batches",
    "reconcile_batch_items",
    "deletion_receipts",
    "receipt_keys",
    "audit_anchors",
    "audit_anchor_meta",
    "anchor_key_generations",
)


def _cursor(batch_id, position):
    return _encode_cursor(batch_id, position, _INSPECTION_CURSOR_PREFIX)


def _chain_hash(tenant_id, request_id, seq, status, occurred_at, predecessor):
    """Independent reimplementation of the database link hash."""
    digest = hashlib.sha256()
    for field in (tenant_id, request_id, str(seq), status, occurred_at, predecessor):
        raw = field.encode("utf-8")
        digest.update(struct.pack(">Q", len(raw)))
        digest.update(raw)
    return digest.hexdigest()


class _StoreCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "evidence.db")

    def tearDown(self):
        self._tmp.cleanup()

    def _store(self, secret=SECRET, history=None):
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

    def _evidence_dump(self):
        with self._raw() as raw:
            return {
                table: raw.execute(f"SELECT * FROM {table}").fetchall()
                for table in EVIDENCE_TABLES
            }


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

    def test_item_shape_and_value_types(self):
        store = self._store()
        self._submit_many(store, 2)
        result = store.audit_inspection("tenant-a", limit=10)
        self.assertIsInstance(result["finished"], bool)
        self.assertIs(result["finished"], True)
        self.assertEqual(len(result["items"]), 2)
        for item in result["items"]:
            self.assertEqual(set(item), {"request_id", "verified", "reasons"})
            self.assertIsInstance(item["request_id"], str)
            self.assertIs(item["verified"], True)
            self.assertEqual(item["reasons"], [])

    def test_in_memory_store_inspects(self):
        store = RequestStore(":memory:", anchor_secret=SECRET)
        rid = store.submit("tenant-a", "subject-1", ["email"], "key-1")["request_id"]
        result = store.audit_inspection("tenant-a")
        self.assertEqual(
            result["items"],
            [{"request_id": rid, "verified": True, "reasons": []}],
        )
        self.assertIs(result["finished"], True)


class InspectionVerificationTests(_StoreCase):
    def test_normal_requests_verify_true_in_acceptance_order(self):
        store = self._store()
        ids = self._submit_many(store, 4)
        # Mix every lifecycle state: processing, completed, failed, accepted.
        claim = store.claim_next("tenant-a", "worker-1", 3600)
        self.assertEqual(claim["request_id"], ids[0])
        done = store.claim_next("tenant-a", "worker-1", 3600)
        self.assertEqual(done["request_id"], ids[1])
        store.finish_claim("tenant-a", ids[1], done["claim_token"], "completed")
        failed = store.claim_next("tenant-a", "worker-1", 3600)
        self.assertEqual(failed["request_id"], ids[2])
        store.finish_claim("tenant-a", ids[2], failed["claim_token"], "failed")
        result = store.audit_inspection("tenant-a")
        self.assertEqual(
            result["items"],
            [
                {"request_id": rid, "verified": True, "reasons": []}
                for rid in ids
            ],
        )
        self.assertIs(result["finished"], True)

    def _assert_untrusted(self, store, tenant="tenant-a"):
        result = store.audit_inspection(tenant)
        self.assertTrue(result["items"])
        for item in result["items"]:
            self.assertIs(item["verified"], False)
            self.assertTrue(item["reasons"])
            self.assertEqual(item["reasons"], sorted(item["reasons"]))
            self.assertLessEqual(set(item["reasons"]), KNOWN_REASONS)
            # Each item reports exactly what the whole-file diagnosis does.
            self.assertEqual(
                item["reasons"],
                store.diagnose_chain(tenant, item["request_id"]),
            )
        return result

    def test_modified_event_is_untrusted(self):
        store = self._store()
        rid = self._submit_many(store, 1)[0]
        with self._raw() as raw:
            raw.execute(
                "UPDATE status_events SET occurred_at = occurred_at || 'x' "
                "WHERE request_id = ?",
                (rid,),
            )
        result = self._assert_untrusted(store)
        self.assertIn("chain_hash_mismatch", result["items"][0]["reasons"])

    def test_deleted_event_is_untrusted(self):
        store = self._store()
        ids = self._submit_many(store, 2)
        store.transition("tenant-a", ids[0], "processing")
        with self._raw() as raw:
            raw.execute(
                "DELETE FROM status_events WHERE request_id = ? AND seq = 1",
                (ids[0],),
            )
        self._assert_untrusted(store)

    def test_inserted_event_is_untrusted(self):
        store = self._store()
        rid = self._submit_many(store, 1)[0]
        with self._raw() as raw:
            raw.execute(
                "INSERT INTO status_events ("
                "tenant_id, request_id, seq, status, occurred_at, chain_hash"
                ") VALUES ('tenant-a', ?, 1, 'failed', "
                "'2020-01-01T00:00:00.000000Z', ?)",
                (rid, "0" * 64),
            )
        self._assert_untrusted(store)

    def test_reordered_events_are_untrusted(self):
        store = self._store()
        rid = self._submit_many(store, 1)[0]
        store.transition("tenant-a", rid, "processing")
        store.transition("tenant-a", rid, "completed")
        with self._raw() as raw:
            raw.execute(
                "UPDATE status_events SET seq = seq + 10 WHERE request_id = ?",
                (rid,),
            )
        self._assert_untrusted(store)

    def test_cross_request_substitution_is_untrusted(self):
        store = self._store()
        ids = self._submit_many(store, 2)
        with self._raw() as raw:
            # Swap the two requests' event timelines (via a scratch id to
            # avoid the events primary key colliding mid-update).
            raw.execute(
                "UPDATE status_events SET request_id = 'swap-scratch' "
                "WHERE request_id = ?",
                (ids[0],),
            )
            raw.execute(
                "UPDATE status_events SET request_id = ? WHERE request_id = ?",
                (ids[0], ids[1]),
            )
            raw.execute(
                "UPDATE status_events SET request_id = ? "
                "WHERE request_id = 'swap-scratch'",
                (ids[1],),
            )
        self._assert_untrusted(store)

    def test_cross_tenant_substitution_is_untrusted(self):
        store = self._store()
        a = store.submit("tenant-a", "s", ["email"], "ka")["request_id"]
        b = store.submit("tenant-b", "s", ["email"], "kb")["request_id"]
        with self._raw() as raw:
            raw.execute(
                "UPDATE status_events SET request_id = "
                "CASE request_id WHEN ? THEN ? ELSE ? END "
                "WHERE request_id IN (?, ?)",
                (a, b, a, a, b),
            )
        self._assert_untrusted(store, "tenant-a")
        self._assert_untrusted(store, "tenant-b")

    def test_request_head_tamper_is_untrusted(self):
        store = self._store()
        rid = self._submit_many(store, 1)[0]
        with self._raw() as raw:
            raw.execute(
                "UPDATE requests SET chain_hash = ? WHERE request_id = ?",
                ("0" * 64, rid),
            )
        result = self._assert_untrusted(store)
        self.assertIn("chain_head_mismatch", result["items"][0]["reasons"])

    def test_anchor_tamper_is_untrusted(self):
        store = self._store()
        rid = self._submit_many(store, 1)[0]
        with self._raw() as raw:
            raw.execute(
                "UPDATE audit_anchors SET anchor_hmac = ? WHERE request_id = ?",
                ("0" * 64, rid),
            )
        result = self._assert_untrusted(store)
        self.assertIn("anchor_auth_failed", result["items"][0]["reasons"])

    def test_global_head_tamper_is_untrusted(self):
        store = self._store()
        self._submit_many(store, 2)
        with self._raw() as raw:
            raw.execute("UPDATE audit_anchor_meta SET head_hmac = ?", ("0" * 64,))
        result = self._assert_untrusted(store)
        self.assertIn("anchor_head_mismatch", result["items"][0]["reasons"])

    def test_interrupted_commit_is_untrusted(self):
        store = self._store()
        self._submit_many(store, 1)
        with self._raw() as raw:
            raw.execute("DELETE FROM audit_anchor_meta")
        self._assert_untrusted(store)

    def test_forged_chain_without_secret_is_untrusted(self):
        # An attacker rewrites an event and recomputes every database
        # link hash plus the request head so the internal chain verifies
        # again; without the anchor secret the forgery still fails.
        store = self._store()
        rid = self._submit_many(store, 1)[0]
        store.transition("tenant-a", rid, "processing")
        with self._raw() as raw:
            rows = raw.execute(
                "SELECT seq, status, occurred_at FROM status_events "
                "WHERE request_id = ? ORDER BY seq",
                (rid,),
            ).fetchall()
            predecessor = GENESIS
            for seq, status, occurred_at in rows:
                if seq == 0:
                    occurred_at = "2020-01-01T00:00:00.000000Z"
                link = _chain_hash(
                    "tenant-a", rid, seq, status, occurred_at, predecessor
                )
                raw.execute(
                    "UPDATE status_events SET occurred_at = ?, chain_hash = ? "
                    "WHERE request_id = ? AND seq = ?",
                    (occurred_at, link, rid, seq),
                )
                predecessor = link
            raw.execute(
                "UPDATE requests SET chain_hash = ? WHERE request_id = ?",
                (predecessor, rid),
            )
        result = self._assert_untrusted(store)
        self.assertIn("anchor_auth_failed", result["items"][0]["reasons"])

    def test_legacy_unanchored_database_is_untrusted(self):
        # A database written before anchors existed (events, no anchors)
        # must never be judged trusted.
        legacy = RequestStore(self.db_path)
        rid = legacy.submit("tenant-a", "subject-1", ["email"], "key-1")[
            "request_id"
        ]
        result = legacy.audit_inspection("tenant-a")
        self.assertEqual(
            result["items"],
            [
                {
                    "request_id": rid,
                    "verified": False,
                    "reasons": ["unanchored_database"],
                }
            ],
        )

    def test_anchored_database_without_secret_is_untrusted(self):
        store = self._store()
        self._submit_many(store, 1)
        blind = RequestStore(self.db_path)
        result = blind.audit_inspection("tenant-a")
        self.assertEqual(
            [item["reasons"] for item in result["items"]],
            [["anchor_secret_missing"]],
        )
        self.assertIs(result["items"][0]["verified"], False)

    def test_missing_historical_secret_is_untrusted(self):
        store = self._store()
        rid = self._submit_many(store, 1)[0]
        rotation = store.rotate_anchor_key(SECRET, "anchor-secret-two")
        self.assertEqual(rotation["generation"], 2)
        # A rebuilt store holding only the current secret cannot
        # authenticate the generation-1 anchors.
        rebuilt = self._store(secret="anchor-secret-two")
        result = rebuilt.audit_inspection("tenant-a")
        self.assertEqual(
            result["items"],
            [
                {
                    "request_id": rid,
                    "verified": False,
                    "reasons": ["anchor_key_missing"],
                }
            ],
        )
        # Handing the historical secret back restores trust.
        with_history = self._store(
            secret="anchor-secret-two", history={1: SECRET}
        )
        trusted = with_history.audit_inspection("tenant-a")
        self.assertEqual(
            trusted["items"],
            [{"request_id": rid, "verified": True, "reasons": []}],
        )

    def test_corruption_in_another_tenant_is_visible(self):
        # The global head seals every tenant: tampering with tenant-b's
        # chain makes tenant-a's items untrusted as well.
        store = self._store()
        self._submit_many(store, 1, tenant="tenant-a")
        victim = store.submit("tenant-b", "s", ["email"], "kb")["request_id"]
        with self._raw() as raw:
            raw.execute(
                "UPDATE status_events SET occurred_at = occurred_at || 'x' "
                "WHERE request_id = ?",
                (victim,),
            )
        self._assert_untrusted(store, "tenant-a")


class InspectionPaginationTests(_StoreCase):
    def test_limit_pages_and_cursor_resumes_same_batch(self):
        store = self._store()
        ids = self._submit_many(store, 5)
        first = store.audit_inspection("tenant-a", limit=2)
        self.assertEqual([i["request_id"] for i in first["items"]], ids[:2])
        self.assertIs(first["finished"], False)
        self.assertIsInstance(first["next_cursor"], str)
        self.assertTrue(first["next_cursor"].startswith("ai1."))
        # The cursor names this exact batch and the durable item count.
        batch_id, position = _decode_cursor(
            first["next_cursor"], _INSPECTION_CURSOR_PREFIX
        )
        self.assertEqual(batch_id, first["batch_id"])
        self.assertEqual(position, 2)
        second = store.audit_inspection("tenant-a", first["next_cursor"], limit=2)
        self.assertEqual(second["batch_id"], first["batch_id"])
        self.assertEqual([i["request_id"] for i in second["items"]], ids[2:4])
        self.assertIs(second["finished"], False)
        third = store.audit_inspection("tenant-a", second["next_cursor"], limit=2)
        self.assertEqual(third["batch_id"], first["batch_id"])
        self.assertEqual([i["request_id"] for i in third["items"]], ids[4:])
        self.assertIs(third["finished"], True)
        self.assertIsNone(third["next_cursor"])
        # The full item order across the batch is stable and settled once.
        with self._raw() as raw:
            rows = raw.execute(
                "SELECT seq, request_id, verified, reasons_json "
                "FROM inspection_batch_items WHERE batch_id = ? ORDER BY seq",
                (first["batch_id"],),
            ).fetchall()
        self.assertEqual([row[0] for row in rows], list(range(1, 6)))
        self.assertEqual([row[1] for row in rows], ids)
        self.assertEqual([row[2] for row in rows], [1] * 5)
        self.assertEqual([json.loads(row[3]) for row in rows], [[]] * 5)

    def test_finished_when_limit_exactly_exhausts_requests(self):
        store = self._store()
        self._submit_many(store, 2)
        result = store.audit_inspection("tenant-a", limit=2)
        self.assertEqual(len(result["items"]), 2)
        self.assertIs(result["finished"], True)
        self.assertIsNone(result["next_cursor"])

    def test_omitting_limit_uses_bounded_default(self):
        store = self._store()
        self._submit_many(store, 3)
        result = store.audit_inspection("tenant-a")
        self.assertEqual(len(result["items"]), 3)
        self.assertIs(result["finished"], True)

    def test_limit_boundaries_are_accepted(self):
        store = self._store()
        for value in (1, 1000):
            self.assertIn("items", store.audit_inspection("tenant-a", limit=value))


class InspectionResumeTests(_StoreCase):
    def test_retry_of_same_cursor_continues_from_committed_position(self):
        store = self._store()
        ids = self._submit_many(store, 4)
        first = store.audit_inspection("tenant-a", limit=2)
        # Calling again with the same cursor does not re-report the
        # settled items; it resumes after the committed position.
        again = store.audit_inspection("tenant-a", first["next_cursor"], limit=2)
        self.assertEqual(again["batch_id"], first["batch_id"])
        self.assertEqual([i["request_id"] for i in again["items"]], ids[2:4])
        self.assertIs(again["finished"], True)
        with self._raw() as raw:
            count = raw.execute(
                "SELECT count(*) FROM inspection_batch_items WHERE batch_id = ?",
                (first["batch_id"],),
            ).fetchone()[0]
        self.assertEqual(count, 4)

    def test_cursor_position_in_payload_is_not_trusted_for_resume(self):
        store = self._store()
        ids = self._submit_many(store, 4)
        first = store.audit_inspection("tenant-a", limit=2)
        # A forged cursor for the same batch id with a bogus position
        # still resumes from the persisted position (after ids[1]).
        forged = _cursor(first["batch_id"], 999)
        page = store.audit_inspection("tenant-a", forged, limit=2)
        self.assertEqual(page["batch_id"], first["batch_id"])
        self.assertEqual([i["request_id"] for i in page["items"]], ids[2:4])

    def test_replay_of_old_cursor_after_finish_reports_nothing(self):
        store = self._store()
        self._submit_many(store, 3)
        first = store.audit_inspection("tenant-a", limit=2)
        store.audit_inspection("tenant-a", first["next_cursor"], limit=2)
        replay = store.audit_inspection("tenant-a", first["next_cursor"], limit=2)
        self.assertEqual(replay["batch_id"], first["batch_id"])
        self.assertEqual(replay["items"], [])
        self.assertIs(replay["finished"], True)
        self.assertIsNone(replay["next_cursor"])
        with self._raw() as raw:
            self.assertEqual(
                raw.execute(
                    "SELECT count(*) FROM inspection_batch_items"
                ).fetchone()[0],
                3,
            )

    def test_resume_survives_restart_with_same_batch_id(self):
        first_store = self._store()
        ids = self._submit_many(first_store, 4)
        page = first_store.audit_inspection("tenant-a", limit=2)
        rebuilt = self._store()
        resumed = rebuilt.audit_inspection("tenant-a", page["next_cursor"], limit=10)
        self.assertEqual(resumed["batch_id"], page["batch_id"])
        self.assertEqual([i["request_id"] for i in resumed["items"]], ids[2:4])
        self.assertIs(resumed["finished"], True)

    def test_fresh_call_starts_a_new_batch(self):
        store = self._store()
        ids = self._submit_many(store, 2)
        first = store.audit_inspection("tenant-a")
        self.assertEqual(len(first["items"]), 2)
        # A fresh call (no cursor) is its own sweep: a distinct batch id
        # that re-verifies every request.
        second = store.audit_inspection("tenant-a")
        self.assertNotEqual(second["batch_id"], first["batch_id"])
        self.assertEqual(
            [i["request_id"] for i in second["items"]], ids
        )

    def test_batches_are_partitioned_per_tenant(self):
        store = self._store()
        a = store.submit("tenant-a", "s", ["email"], "ka")["request_id"]
        b = store.submit("tenant-b", "s", ["email"], "kb")["request_id"]
        ra = store.audit_inspection("tenant-a")
        rb = store.audit_inspection("tenant-b")
        self.assertEqual([i["request_id"] for i in ra["items"]], [a])
        self.assertEqual([i["request_id"] for i in rb["items"]], [b])
        self.assertNotEqual(ra["batch_id"], rb["batch_id"])

    def test_concurrent_retry_of_same_cursor_does_not_double_write(self):
        store = self._store()
        ids = self._submit_many(store, 6)
        first = store.audit_inspection("tenant-a", limit=2)

        def retry(_index):
            return store.audit_inspection("tenant-a", first["next_cursor"], limit=10)

        with ThreadPoolExecutor(max_workers=8) as pool:
            pages = list(pool.map(retry, range(8)))
        # Every concurrent resume used the same batch and the remaining
        # items were recorded exactly once across all retries.
        self.assertTrue(all(p["batch_id"] == first["batch_id"] for p in pages))
        self.assertEqual(sum(len(p["items"]) for p in pages), 4)
        with self._raw() as raw:
            self.assertEqual(
                raw.execute(
                    "SELECT count(*) FROM inspection_batch_items"
                ).fetchone()[0],
                6,
            )
            # The persisted order is still the stable acceptance order.
            ordered = raw.execute(
                "SELECT request_id FROM inspection_batch_items ORDER BY seq"
            ).fetchall()
        self.assertEqual([row[0] for row in ordered], ids)


class InspectionReadOnlyTests(_StoreCase):
    def test_inspection_never_changes_evidence_records(self):
        store = self._store()
        ids = self._submit_many(store, 3)
        claim = store.claim_next("tenant-a", "worker-1", 3600)
        store.finish_claim("tenant-a", ids[0], claim["claim_token"], "completed")
        receipt = store.generate_receipt("tenant-a", ids[0], "receipt-key")
        store.rotate_anchor_key(SECRET, "anchor-secret-two")
        before = self._evidence_dump()
        result = store.audit_inspection("tenant-a")
        self.assertEqual(len(result["items"]), 3)
        self.assertTrue(all(item["verified"] for item in result["items"]))
        self.assertEqual(before, self._evidence_dump())
        # The receipt and the rotated anchor state still work as before.
        self.assertTrue(store.verify_receipt(receipt, "receipt-key"))
        self.assertTrue(store.verify_chain())
        # Only the inspection bookkeeping was persisted.
        with self._raw() as raw:
            self.assertEqual(
                raw.execute("SELECT count(*) FROM inspection_batches").fetchone()[0],
                1,
            )
            self.assertEqual(
                raw.execute(
                    "SELECT count(*) FROM inspection_batch_items"
                ).fetchone()[0],
                3,
            )

    def test_inspection_does_not_repair_tampered_evidence(self):
        store = self._store()
        rid = self._submit_many(store, 1)[0]
        with self._raw() as raw:
            raw.execute(
                "UPDATE status_events SET occurred_at = occurred_at || 'x' "
                "WHERE request_id = ?",
                (rid,),
            )
        before = self._evidence_dump()
        result = store.audit_inspection("tenant-a")
        self.assertIs(result["items"][0]["verified"], False)
        # The tampered row is reported, never repaired, backfilled,
        # recomputed or overwritten.
        self.assertEqual(before, self._evidence_dump())
        self.assertEqual(store.diagnose_chain(), result["items"][0]["reasons"])
        with self._raw() as raw:
            tampered = raw.execute(
                "SELECT occurred_at FROM status_events WHERE request_id = ?",
                (rid,),
            ).fetchone()[0]
        self.assertTrue(tampered.endswith("x"))


class InspectionValidationTests(_StoreCase):
    def _assert_no_batches(self):
        with self._raw() as raw:
            self.assertEqual(
                raw.execute("SELECT count(*) FROM inspection_batches").fetchone()[0],
                0,
            )

    def test_bad_tenant_is_value_error_without_writes(self):
        store = self._store()
        self._submit_many(store, 1)
        for bad in ("", None, 7, b"t", ["t"], True):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    store.audit_inspection(bad)
        self._assert_no_batches()

    def test_bad_limit_is_value_error_without_writes(self):
        store = self._store()
        self._submit_many(store, 1)
        for bad in (0, -1, 1001, 10_000, 1.0, 0.5, True, False, "5", "x", [5]):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    store.audit_inspection("tenant-a", limit=bad)
        self._assert_no_batches()

    def test_bad_cursor_shapes_are_value_error(self):
        store = self._store()
        encoded = {
            "v": 1,
            "b": "00000000-0000-4000-8000-000000000000",
            "n": 0,
        }
        unknown = "ai1." + base64.urlsafe_b64encode(
            json.dumps(encoded).encode("utf-8")
        ).decode("ascii")
        bad_cursors = [
            "",
            "x",
            "ai1",
            "ai1.",
            "ai1.@@@",
            "ai1.aaaa",
            "other." + base64.urlsafe_b64encode(b"{}").decode("ascii"),
            7,
            b"ai1.aaaa",
            ["ai1.aaaa"],
            True,
            # Well-formed envelope, wrong payload shapes.
            "ai1." + base64.urlsafe_b64encode(b"not-json").decode("ascii"),
            "ai1." + base64.urlsafe_b64encode(b"[]").decode("ascii"),
            "ai1." + base64.urlsafe_b64encode(b'{"v":2,"b":"x","n":0}').decode("ascii"),
            "ai1." + base64.urlsafe_b64encode(b'{"v":1.0,"b":"x","n":0}').decode("ascii"),
            "ai1." + base64.urlsafe_b64encode(b'{"v":true,"b":"x","n":0}').decode("ascii"),
            "ai1." + base64.urlsafe_b64encode(b'{"v":1,"b":"","n":0}').decode("ascii"),
            "ai1." + base64.urlsafe_b64encode(b'{"v":1,"b":7,"n":0}').decode("ascii"),
            "ai1." + base64.urlsafe_b64encode(b'{"v":1,"b":"x","n":-1}').decode("ascii"),
            "ai1." + base64.urlsafe_b64encode(b'{"v":1,"b":"x","n":true}').decode("ascii"),
            "ai1." + base64.urlsafe_b64encode(b'{"v":1,"b":"x"}').decode("ascii"),
            # Known shape but no such batch.
            unknown,
        ]
        for bad in bad_cursors:
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    store.audit_inspection("tenant-a", cursor=bad)
        # None is the explicit "start a new batch" value and is accepted.
        self.assertIn("items", store.audit_inspection("tenant-a", cursor=None))

    def test_reconcile_cursor_is_not_an_inspection_cursor(self):
        store = self._store()
        self._submit_many(store, 2)
        reconcile_page = store.reconcile_batch("tenant-a", limit=1)
        if reconcile_page["next_cursor"] is not None:
            with self.assertRaises(ValueError):
                store.audit_inspection(
                    "tenant-a", cursor=reconcile_page["next_cursor"]
                )
        # The other direction holds as well.
        inspection_page = store.audit_inspection("tenant-a", limit=1)
        self.assertIsNotNone(inspection_page["next_cursor"])
        with self.assertRaises(ValueError):
            store.reconcile_batch(
                "tenant-a", cursor=inspection_page["next_cursor"]
            )

    def test_cross_tenant_cursor_is_value_error_without_writes(self):
        store = self._store()
        self._submit_many(store, 1, tenant="tenant-a")
        self._submit_many(store, 2, tenant="tenant-b")
        page_b = store.audit_inspection("tenant-b", limit=1)
        with self.assertRaises(ValueError):
            store.audit_inspection("tenant-a", page_b["next_cursor"])
        # No batch row was created for tenant-a by the rejected call.
        with self._raw() as raw:
            self.assertEqual(
                raw.execute(
                    "SELECT count(*) FROM inspection_batches "
                    "WHERE tenant_id = 'tenant-a'"
                ).fetchone()[0],
                0,
            )


class InspectionCorruptionTests(_StoreCase):
    def _fixed(self, ctx):
        self.assertEqual(str(ctx.exception), "request store is unavailable")
        self.assertNotIn("sqlite", str(ctx.exception).lower())
        self.assertNotIn(self.db_path, str(ctx.exception))

    def test_missing_batch_table_is_os_error(self):
        store = self._store()
        self._submit_many(store, 1)
        with self._raw() as raw:
            raw.execute("DROP TABLE inspection_batches")
        with self.assertRaises(OSError) as ctx:
            store.audit_inspection("tenant-a")
        self._fixed(ctx)

    def test_missing_item_table_is_os_error_without_half_result(self):
        store = self._store()
        self._submit_many(store, 2)
        with self._raw() as raw:
            raw.execute("DROP TABLE inspection_batch_items")
        with self.assertRaises(OSError) as ctx:
            store.audit_inspection("tenant-a")
        self._fixed(ctx)

    def test_corrupt_file_is_os_error(self):
        store = self._store()
        self._submit_many(store, 1)
        with open(self.db_path, "wb") as handle:
            handle.write(b"not a sqlite database")
        with self.assertRaises(OSError) as ctx:
            store.audit_inspection("tenant-a")
        self._fixed(ctx)

    def test_split_persisted_position_is_os_error(self):
        store = self._store()
        self._submit_many(store, 2)
        page = store.audit_inspection("tenant-a", limit=1)
        # Split the keyset position out of band.
        with self._raw() as raw:
            raw.execute(
                "UPDATE inspection_batches SET position_request_id = NULL "
                "WHERE batch_id = ?",
                (page["batch_id"],),
            )
        with self.assertRaises(OSError) as ctx:
            store.audit_inspection("tenant-a", page["next_cursor"])
        self._fixed(ctx)


class InspectionNoLeakTests(_StoreCase):
    def test_items_expose_only_the_fixed_fields(self):
        store = self._store()
        rid = store.submit("tenant-a", "subject-SECRET", ["email"], "key-1")[
            "request_id"
        ]
        result = store.audit_inspection("tenant-a")
        rendered = repr(result)
        self.assertNotIn("subject-SECRET", rendered)
        self.assertNotIn("email", rendered)
        self.assertNotIn(SECRET, rendered)
        self.assertEqual(
            result["items"],
            [{"request_id": rid, "verified": True, "reasons": []}],
        )

    def test_cursor_is_opaque_and_does_not_embed_sensitive_data(self):
        store = self._store()
        ids = self._submit_many(store, 3)
        page = store.audit_inspection("tenant-a", limit=1)
        cursor = page["next_cursor"]
        self.assertTrue(cursor.startswith("ai1."))
        decoded = base64.urlsafe_b64decode(cursor[4:]).decode("utf-8")
        self.assertNotIn("tenant-a", decoded)
        for rid in ids:
            self.assertNotIn(rid, decoded)

    def test_batch_ids_are_distinct_uuids(self):
        import uuid

        store = self._store()
        one = store.audit_inspection("tenant-a")
        two = store.audit_inspection("tenant-a")
        self.assertNotEqual(one["batch_id"], two["batch_id"])
        for value in (one["batch_id"], two["batch_id"]):
            uuid.UUID(value)


class DeferredInspectionTests(_StoreCase):
    def test_inspection_is_proxied(self):
        store = httpapi.DeferredRequestStore(self.db_path)
        # The deferred wrapper builds an un-anchored store; the legacy
        # un-anchored outcome is reported, never trusted.
        rid = store.submit("tenant-a", "subject-1", ["email"], "key-1")[
            "request_id"
        ]
        result = store.audit_inspection("tenant-a")
        self.assertEqual(
            result["items"],
            [
                {
                    "request_id": rid,
                    "verified": False,
                    "reasons": ["unanchored_database"],
                }
            ],
        )

    def test_unavailable_storage_is_reported_consistently(self):
        blocker = os.path.join(self._tmp.name, "a-file")
        with open(blocker, "wb") as handle:
            handle.write(b"x")
        impossible = os.path.join(blocker, "nested", "evidence.db")
        store = httpapi.DeferredRequestStore(impossible)
        with self.assertRaises(httpapi._StorageUnavailable):
            store.audit_inspection("tenant-a")


if __name__ == "__main__":
    unittest.main()
