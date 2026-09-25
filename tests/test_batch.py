"""Tests for tenant-scoped, resumable batch reconciliation.

Covers RequestStore.reconcile_batch on the storage layer only: the fixed
result shape, first-scan skipping of accepted requests, processing
(live-lease / expired / unexplainable) and terminal handling, stable
scan ordering, limit pagination, opaque cursor resume and idempotency
across retries and rebuilds, per-item transaction atomicity, validation
of tenant/cursor/limit without writes, corruption semantics, concurrent
convergence with single reconcile/claim, and the no-leak guarantees.
This entry point is deliberately not exposed over HTTP.
"""

import base64
import json
import os
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor

from forgetting_evidence import httpapi
from forgetting_evidence.requests import (
    ClaimConflict,
    RequestNotFound,
    RequestStore,
    _decode_cursor,
    _encode_cursor,
)


def _wait_for_expiry(seconds=1.15):
    import time

    time.sleep(seconds)


def _cursor(batch_id, position):
    return _encode_cursor(batch_id, position)


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

    def _expire(self, store, count=1):
        """Claim the oldest *count* accepted requests on 1s leases, wait out."""
        claims = []
        for _ in range(count):
            claims.append(store.claim_next("tenant-a", "worker-x", 1))
        _wait_for_expiry()
        return claims


class BatchShapeTests(_StoreCase):
    def test_empty_tenant_finishes_with_no_items(self):
        store = self._store()
        result = store.reconcile_batch("tenant-a")
        self.assertEqual(
            list(result), ["batch_id", "next_cursor", "finished", "items"]
        )
        self.assertIsInstance(result["batch_id"], str)
        self.assertTrue(result["batch_id"])
        self.assertIsNone(result["next_cursor"])
        self.assertIs(result["finished"], True)
        self.assertEqual(result["items"], [])

    def test_value_types_are_only_str_int_bool_none(self):
        store = self._store()
        self._submit(store)
        result = store.reconcile_batch("tenant-a", limit=10)
        self.assertIsInstance(result["finished"], bool)
        # An accepted-only sweep finishes immediately and skips accepted.
        self.assertIs(result["finished"], True)
        for value in result["items"]:
            self.assertEqual(set(value), {"request_id", "status"})
            self.assertIsInstance(value["request_id"], str)
            self.assertIsInstance(value["status"], str)
            for leaf in value.values():
                self.assertNotIsInstance(leaf, float)
                self.assertNotIsInstance(leaf, bool)


class BatchAcceptedSkipTests(_StoreCase):
    def test_accepted_are_skipped_without_attempt_event_or_receipt_change(self):
        store = self._store()
        receipts = [self._submit(store, key=f"k{i}") for i in range(3)]
        result = store.reconcile_batch("tenant-a")
        # Nothing reconcilable: no items, but the sweep is finished after
        # advancing past every accepted row.
        self.assertEqual(result["items"], [])
        self.assertIs(result["finished"], True)
        with sqlite3.connect(self.db_path) as raw:
            self.assertEqual(
                raw.execute("SELECT count(*) FROM claim_attempts").fetchone()[0], 0
            )
            self.assertEqual(
                raw.execute("SELECT count(*) FROM claim_tokens").fetchone()[0], 0
            )
            self.assertEqual(
                raw.execute("SELECT count(*) FROM reconcile_batch_items").fetchone()[0],
                0,
            )
        for receipt in receipts:
            rid = receipt["request_id"]
            self.assertEqual(store.get_status("tenant-a", rid)["status"], "accepted")
            self.assertEqual(store.get("tenant-a", rid), receipt)
            self.assertEqual(
                [e["status"] for e in store.audit("tenant-a", rid)], ["accepted"]
            )

    def test_skipping_accepted_does_not_consume_the_limit(self):
        store = self._store()
        accepted_ids = self._submit_many(store, 3)
        claim = store.claim_next("tenant-a", "w", 1)  # oldest -> processing
        _wait_for_expiry()
        # The single reconcilable item converges even with limit=1 while
        # the other two accepted rows are scanned and skipped.
        result = store.reconcile_batch("tenant-a", limit=1)
        self.assertEqual(
            result["items"],
            [{"request_id": claim["request_id"], "status": "failed"}],
        )
        # Two accepted rows remain beyond the committed position, so the
        # sweep is not finished yet and a cursor is returned.
        self.assertIs(result["finished"], False)
        self.assertIsInstance(result["next_cursor"], str)
        for rid in accepted_ids[1:]:
            self.assertEqual(store.get_status("tenant-a", rid)["status"], "accepted")
        # Resuming skips the accepted rows and then finishes.
        resumed = store.reconcile_batch("tenant-a", result["next_cursor"], limit=1)
        self.assertEqual(resumed["items"], [])
        self.assertIs(resumed["finished"], True)
        self.assertIsNone(resumed["next_cursor"])


class BatchConvergenceTests(_StoreCase):
    def test_live_lease_stays_processing_and_is_recorded_once(self):
        store = self._store()
        rid = self._submit(store)["request_id"]
        claim = store.claim_next("tenant-a", "w", 3600)
        result = store.reconcile_batch("tenant-a")
        self.assertEqual(result["items"], [{"request_id": rid, "status": "processing"}])
        self.assertIs(result["finished"], True)
        # No new attempt, no early terminal; the live credential still works.
        self.assertEqual(len(store.get_execution_log("tenant-a", rid)), 1)
        self.assertEqual(
            store.finish_claim(
                "tenant-a", rid, claim["claim_token"], "completed"
            )["status"],
            "completed",
        )

    def test_expired_processing_is_compensated_to_failed(self):
        store = self._store()
        rid = self._submit(store)["request_id"]
        claim = store.claim_next("tenant-a", "w", 1)
        _wait_for_expiry()
        result = store.reconcile_batch("tenant-a")
        self.assertEqual(result["items"], [{"request_id": rid, "status": "failed"}])
        entry = store.get_execution_log("tenant-a", rid)[0]
        self.assertEqual(entry["result"], "failed")
        self.assertIsInstance(entry["completed_at"], str)
        self.assertEqual(
            [e["status"] for e in store.audit("tenant-a", rid)],
            ["accepted", "processing", "failed"],
        )
        self.assertTrue(store.verify_evidence("tenant-a", rid))
        # The dead credential was released with the compensation.
        with self.assertRaises(ClaimConflict):
            store.finish_claim("tenant-a", rid, claim["claim_token"], "completed")

    def test_unexplainable_processing_converges_to_failed(self):
        store = self._store()
        rid = self._submit(store)["request_id"]
        store.transition("tenant-a", rid, "processing")  # no attempt/lease
        result = store.reconcile_batch("tenant-a")
        self.assertEqual(result["items"], [{"request_id": rid, "status": "failed"}])
        self.assertEqual(
            [e["status"] for e in store.audit("tenant-a", rid)],
            ["accepted", "processing", "failed"],
        )

    def test_terminal_requests_are_excluded_from_the_sweep(self):
        store = self._store()
        completed = self._submit(store, key="k1")["request_id"]
        failed = self._submit(store, key="k2")["request_id"]
        for rid, result in ((completed, "completed"), (failed, "failed")):
            claim = store.claim_next("tenant-a", "w", 3600)
            self.assertEqual(claim["request_id"], rid)
            store.finish_claim("tenant-a", rid, claim["claim_token"], result)
        batch = store.reconcile_batch("tenant-a")
        self.assertEqual(batch["items"], [])
        self.assertIs(batch["finished"], True)
        with sqlite3.connect(self.db_path) as raw:
            self.assertEqual(
                raw.execute("SELECT count(*) FROM reconcile_batch_items").fetchone()[0],
                0,
            )

    def test_mixed_batches_follow_reconcile_rules_in_stable_order(self):
        store = self._store()
        ids = self._submit_many(store, 6)
        # ids[0] live, ids[1] expired, ids[2] completed (terminal),
        # ids[3], ids[4] accepted, ids[5] unexplainable processing.
        live = store.claim_next("tenant-a", "w", 3600)
        self.assertEqual(live["request_id"], ids[0])
        expiring = store.claim_next("tenant-a", "w", 1)
        self.assertEqual(expiring["request_id"], ids[1])
        finishing = store.claim_next("tenant-a", "w", 3600)
        self.assertEqual(finishing["request_id"], ids[2])
        store.finish_claim("tenant-a", ids[2], finishing["claim_token"], "completed")
        store.transition("tenant-a", ids[5], "processing")
        _wait_for_expiry()
        result = store.reconcile_batch("tenant-a")
        # Terminal ids[2] excluded; accepted ids[3]/ids[4] skipped. The
        # reconcilable items come back in the stable scan order.
        self.assertEqual(
            result["items"],
            [
                {"request_id": ids[0], "status": "processing"},
                {"request_id": ids[1], "status": "failed"},
                {"request_id": ids[5], "status": "failed"},
            ],
        )
        self.assertIs(result["finished"], True)

    def test_items_follow_stable_acceptance_order(self):
        store = self._store()
        ids = self._submit_many(store, 4)
        # Claim the first three (oldest accepted) so they are processing;
        # leave ids[3] accepted. All processing leases expire.
        self._expire(store, 3)
        result = store.reconcile_batch("tenant-a")
        self.assertEqual(
            [item["request_id"] for item in result["items"]],
            [ids[0], ids[1], ids[2]],
        )
        self.assertTrue(
            all(item["status"] == "failed" for item in result["items"])
        )


class BatchPaginationTests(_StoreCase):
    def test_limit_pages_and_cursor_resumes_same_batch(self):
        store = self._store()
        ids = self._submit_many(store, 5)
        self._expire(store, 5)
        first = store.reconcile_batch("tenant-a", limit=2)
        self.assertEqual([i["request_id"] for i in first["items"]], ids[:2])
        self.assertIs(first["finished"], False)
        self.assertIsInstance(first["next_cursor"], str)
        # The cursor names this exact batch.
        batch_id, position = _decode_cursor(first["next_cursor"])
        self.assertEqual(batch_id, first["batch_id"])
        self.assertEqual(position, 2)
        second = store.reconcile_batch("tenant-a", first["next_cursor"], limit=2)
        self.assertEqual(second["batch_id"], first["batch_id"])
        self.assertEqual([i["request_id"] for i in second["items"]], ids[2:4])
        self.assertIs(second["finished"], False)
        third = store.reconcile_batch("tenant-a", second["next_cursor"], limit=2)
        self.assertEqual(third["batch_id"], first["batch_id"])
        self.assertEqual([i["request_id"] for i in third["items"]], ids[4:])
        self.assertIs(third["finished"], True)
        self.assertIsNone(third["next_cursor"])
        # Full item order across the single batch is stable.
        with sqlite3.connect(self.db_path) as raw:
            rows = raw.execute(
                "SELECT seq, request_id FROM reconcile_batch_items "
                "WHERE batch_id=? ORDER BY seq", (first["batch_id"],)
            ).fetchall()
        self.assertEqual([r[0] for r in rows], list(range(1, 6)))
        self.assertEqual([r[1] for r in rows], ids)

    def test_finished_when_limit_exactly_exhausts_reconcilable(self):
        store = self._store()
        ids = self._submit_many(store, 2)
        self._expire(store, 2)
        result = store.reconcile_batch("tenant-a", limit=2)
        self.assertEqual(len(result["items"]), 2)
        self.assertIs(result["finished"], True)
        self.assertIsNone(result["next_cursor"])

    def test_omitting_limit_uses_bounded_default(self):
        store = self._store()
        # The default is accepted without supplying a limit.
        result = store.reconcile_batch("tenant-a")
        self.assertIn("items", result)


class BatchResumeIdempotencyTests(_StoreCase):
    def test_retry_of_same_cursor_continues_from_committed_position(self):
        store = self._store()
        ids = self._submit_many(store, 4)
        self._expire(store, 4)
        first = store.reconcile_batch("tenant-a", limit=2)
        # Calling again with the same cursor does not rewrite the first
        # page; it resumes after the two already-committed items.
        again = store.reconcile_batch("tenant-a", first["next_cursor"], limit=2)
        self.assertEqual(again["batch_id"], first["batch_id"])
        self.assertEqual([i["request_id"] for i in again["items"]], ids[2:4])
        with sqlite3.connect(self.db_path) as raw:
            count = raw.execute(
                "SELECT count(*) FROM reconcile_batch_items WHERE batch_id=?",
                (first["batch_id"],),
            ).fetchone()[0]
        self.assertEqual(count, 4)

    def test_cursor_position_in_payload_is_not_trusted_for_resume(self):
        store = self._store()
        ids = self._submit_many(store, 4)
        self._expire(store, 4)
        first = store.reconcile_batch("tenant-a", limit=2)
        # A forged cursor for the same batch id with a bogus position must
        # still resume from the persisted position (after ids[1]).
        forged = _cursor(first["batch_id"], 999)
        page = store.reconcile_batch("tenant-a", forged, limit=2)
        self.assertEqual(page["batch_id"], first["batch_id"])
        self.assertEqual([i["request_id"] for i in page["items"]], ids[2:4])
        self.assertIs(page["finished"], True)

    def test_settled_items_are_not_rewritten_on_retry(self):
        store = self._store()
        ids = self._submit_many(store, 3)
        self._expire(store, 3)
        first = store.reconcile_batch("tenant-a", limit=2)
        stamps_first = {
            rid: store.get_execution_log("tenant-a", rid)[0]["completed_at"]
            for rid in ids[:2]
        }
        events_first = {
            rid: store.audit("tenant-a", rid) for rid in ids[:2]
        }
        store.reconcile_batch("tenant-a", first["next_cursor"], limit=2)
        # Replaying the first cursor after completion changes nothing.
        replay = store.reconcile_batch("tenant-a", first["next_cursor"], limit=2)
        self.assertEqual(replay["items"], [])
        self.assertIs(replay["finished"], True)
        for rid in ids[:2]:
            self.assertEqual(store.audit("tenant-a", rid), events_first[rid])
            self.assertEqual(
                store.get_execution_log("tenant-a", rid)[0]["completed_at"],
                stamps_first[rid],
            )
        with sqlite3.connect(self.db_path) as raw:
            self.assertEqual(
                raw.execute(
                    "SELECT count(*) FROM reconcile_batch_items"
                ).fetchone()[0],
                3,
            )

    def test_resume_survives_restart_with_same_batch_id(self):
        first = self._store()
        ids = self._submit_many(first, 4)
        self._expire(first, 4)
        page = first.reconcile_batch("tenant-a", limit=2)
        rebuilt = self._store()
        resumed = rebuilt.reconcile_batch(
            "tenant-a", page["next_cursor"], limit=10
        )
        self.assertEqual(resumed["batch_id"], page["batch_id"])
        self.assertEqual([i["request_id"] for i in resumed["items"]], ids[2:4])
        self.assertIs(resumed["finished"], True)
        for rid in ids:
            self.assertTrue(rebuilt.verify_evidence("tenant-a", rid))

    def test_repeated_full_sweeps_are_each_their_own_batch(self):
        store = self._store()
        ids = self._submit_many(store, 2)
        self._expire(store, 2)
        first = store.reconcile_batch("tenant-a")
        self.assertEqual(len(first["items"]), 2)
        # A fresh call (no cursor) starts a new batch; nothing is left to
        # converge, so it returns no items but a distinct batch id.
        second = store.reconcile_batch("tenant-a")
        self.assertNotEqual(second["batch_id"], first["batch_id"])
        self.assertEqual(second["items"], [])
        self.assertIs(second["finished"], True)

    def test_batches_are_partitioned_per_tenant(self):
        store = self._store()
        a = store.submit("tenant-a", "s", ["email"], "ka")["request_id"]
        b = store.submit("tenant-b", "s", ["email"], "kb")["request_id"]
        store.claim_next("tenant-a", "w", 1)
        store.claim_next("tenant-b", "w", 1)
        _wait_for_expiry()
        ra = store.reconcile_batch("tenant-a")
        rb = store.reconcile_batch("tenant-b")
        self.assertEqual(ra["items"], [{"request_id": a, "status": "failed"}])
        self.assertEqual(rb["items"], [{"request_id": b, "status": "failed"}])
        self.assertNotEqual(ra["batch_id"], rb["batch_id"])


class BatchPerItemAtomicityTests(_StoreCase):
    def test_corrupt_later_item_keeps_earlier_committed_items(self):
        store = self._store()
        ids = self._submit_many(store, 2)
        self._expire(store, 2)
        # Corrupt only the second request's attempt row out of band.
        with sqlite3.connect(self.db_path) as raw:
            raw.execute(
                "UPDATE claim_attempts SET result = 'bogus' "
                "WHERE request_id = ?",
                (ids[1],),
            )
        with self.assertRaises(OSError) as ctx:
            store.reconcile_batch("tenant-a")
        self.assertEqual(str(ctx.exception), "request store is unavailable")
        # Earlier item committed in its own transaction.
        self.assertEqual(store.get_status("tenant-a", ids[0])["status"], "failed")
        # Later item is untouched: no half result, no fabricated terminal.
        # (Its row is still corrupt, so read it raw rather than through
        # the strictly-validating execution log.)
        self.assertEqual(store.get_status("tenant-a", ids[1])["status"], "processing")
        with sqlite3.connect(self.db_path) as raw:
            self.assertEqual(
                raw.execute(
                    "SELECT result, completed_at FROM claim_attempts "
                    "WHERE request_id = ?",
                    (ids[1],),
                ).fetchone(),
                ("bogus", None),
            )

    def test_batch_commit_failure_returns_no_half_result(self):
        store = self._store()
        rid = self._submit(store)["request_id"]
        store.claim_next("tenant-a", "w", 1)
        _wait_for_expiry()
        with sqlite3.connect(self.db_path) as raw:
            raw.execute("DROP TABLE reconcile_batch_items")
        with self.assertRaises(OSError) as ctx:
            store.reconcile_batch("tenant-a")
        self.assertEqual(str(ctx.exception), "request store is unavailable")
        self.assertNotIn("sqlite", str(ctx.exception).lower())
        self.assertNotIn(self.db_path, str(ctx.exception))
        # The request was not converged by the aborted batch call.
        self.assertEqual(store.get_status("tenant-a", rid)["status"], "processing")


class BatchValidationTests(_StoreCase):
    def test_bad_tenant_is_value_error_without_writes(self):
        store = self._store()
        self._submit(store)
        for bad in ("", None, 7, b"t", ["t"], True):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    store.reconcile_batch(bad)
        with sqlite3.connect(self.db_path) as raw:
            self.assertEqual(
                raw.execute("SELECT count(*) FROM reconcile_batches").fetchone()[0], 0
            )

    def test_bad_limit_is_value_error_without_writes(self):
        store = self._store()
        self._submit(store)
        for bad in (0, -1, 1001, 10_000, 1.0, 0.5, True, False, "5", "x", [5]):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    store.reconcile_batch("tenant-a", limit=bad)
        with sqlite3.connect(self.db_path) as raw:
            self.assertEqual(
                raw.execute("SELECT count(*) FROM reconcile_batches").fetchone()[0], 0
            )

    def test_limit_boundaries_are_accepted(self):
        store = self._store()
        for value in (1, 1000):
            self.assertIn(
                "items", store.reconcile_batch("tenant-a", limit=value)
            )

    def test_bad_cursor_shapes_are_value_error(self):
        store = self._store()
        encoded = {
            "v": 1,
            "b": "00000000-0000-4000-8000-000000000000",
            "n": 0,
        }
        unknown = "rc1." + base64.urlsafe_b64encode(
            json.dumps(encoded).encode("utf-8")
        ).decode("ascii")
        bad_cursors = [
            "",
            "x",
            "rc1",
            "rc1.",
            "rc1.@@@",
            "rc1.aaaa",
            "other." + base64.urlsafe_b64encode(b"{}").decode("ascii"),
            7,
            b"rc1.aaaa",
            ["rc1.aaaa"],
            True,
            # Well-formed envelope, wrong payload shapes.
            "rc1." + base64.urlsafe_b64encode(b"not-json").decode("ascii"),
            "rc1." + base64.urlsafe_b64encode(b"[]").decode("ascii"),
            "rc1." + base64.urlsafe_b64encode(b'{"v":2,"b":"x","n":0}').decode("ascii"),
            "rc1." + base64.urlsafe_b64encode(b'{"v":1.0,"b":"x","n":0}').decode("ascii"),
            "rc1." + base64.urlsafe_b64encode(b'{"v":true,"b":"x","n":0}').decode("ascii"),
            "rc1." + base64.urlsafe_b64encode(b'{"v":1,"b":"","n":0}').decode("ascii"),
            "rc1." + base64.urlsafe_b64encode(b'{"v":1,"b":7,"n":0}').decode("ascii"),
            "rc1." + base64.urlsafe_b64encode(b'{"v":1,"b":"x","n":-1}').decode("ascii"),
            "rc1." + base64.urlsafe_b64encode(b'{"v":1,"b":"x","n":true}').decode("ascii"),
            "rc1." + base64.urlsafe_b64encode(b'{"v":1,"b":"x"}').decode("ascii"),
            # Known shape but no such batch.
            unknown,
        ]
        for bad in bad_cursors:
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    store.reconcile_batch("tenant-a", cursor=bad)
        # None is the explicit "start a new batch" value and is accepted.
        self.assertIn("items", store.reconcile_batch("tenant-a", cursor=None))
        # A finished batch returned no cursor; its batch_id alone cannot be
        # guessed, and presenting a foreign batch still raises ValueError.

    def test_cross_tenant_cursor_is_value_error_without_writes(self):
        store = self._store()
        self._submit(store, tenant="tenant-a", key="ka")
        self._submit(store, tenant="tenant-b", key="kb")
        store.reconcile_batch("tenant-b", limit=1)
        with sqlite3.connect(self.db_path) as raw:
            bid_b = raw.execute(
                "SELECT batch_id FROM reconcile_batches WHERE tenant_id='tenant-b'"
            ).fetchone()[0]
        forged = _cursor(bid_b, 0)
        with self.assertRaises(ValueError):
            store.reconcile_batch("tenant-a", forged)
        # No batch row was created for tenant-a by the rejected call.
        with sqlite3.connect(self.db_path) as raw:
            self.assertEqual(
                raw.execute(
                    "SELECT count(*) FROM reconcile_batches WHERE tenant_id='tenant-a'"
                ).fetchone()[0],
                0,
            )


class BatchCorruptionTests(_StoreCase):
    def _fixed(self, ctx):
        self.assertEqual(str(ctx.exception), "request store is unavailable")
        self.assertNotIn("sqlite", str(ctx.exception).lower())
        self.assertNotIn(self.db_path, str(ctx.exception))

    def test_missing_batch_table_is_os_error(self):
        store = self._store()
        self._submit(store)
        with sqlite3.connect(self.db_path) as raw:
            raw.execute("DROP TABLE reconcile_batches")
        with self.assertRaises(OSError) as ctx:
            store.reconcile_batch("tenant-a")
        self._fixed(ctx)

    def test_corrupt_file_is_os_error(self):
        store = self._store()
        self._submit(store)
        with open(self.db_path, "wb") as handle:
            handle.write(b"not a sqlite database")
        with self.assertRaises(OSError) as ctx:
            store.reconcile_batch("tenant-a")
        self._fixed(ctx)

    def test_split_persisted_position_is_os_error(self):
        store = self._store()
        ids = self._submit_many(store, 2)
        self._expire(store, 2)
        page = store.reconcile_batch("tenant-a", limit=1)
        # Split the keyset position out of band.
        with sqlite3.connect(self.db_path) as raw:
            raw.execute(
                "UPDATE reconcile_batches SET position_request_id = NULL "
                "WHERE batch_id = ?",
                (page["batch_id"],),
            )
        with self.assertRaises(OSError):
            store.reconcile_batch("tenant-a", page["next_cursor"])


class BatchConcurrencyTests(_StoreCase):
    def test_concurrent_batch_and_single_reconcile_converge_once(self):
        store = self._store()
        ids = self._submit_many(store, 12)
        self._expire(store, 12)

        def worker(index):
            if index % 2 == 0:
                return store.reconcile_batch("tenant-a", limit=12)
            store.reconcile_execution("tenant-a", ids[index])
            return None

        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(worker, range(12)))
        for rid in ids:
            self.assertEqual(store.get_status("tenant-a", rid)["status"], "failed")
            self.assertEqual(
                [e["status"] for e in store.audit("tenant-a", rid)],
                ["accepted", "processing", "failed"],
            )
            self.assertEqual(
                [a["result"] for a in store.get_execution_log("tenant-a", rid)],
                ["failed"],
            )
            self.assertTrue(store.verify_evidence("tenant-a", rid))

    def test_concurrent_batch_and_claim_leave_one_legal_state(self):
        store = self._store()
        rid = self._submit(store)["request_id"]
        store.claim_next("tenant-a", "w", 1)
        _wait_for_expiry()
        errors = []

        def batch():
            try:
                store.reconcile_batch("tenant-a")
            except Exception as exc:  # pragma: no cover - defensive
                errors.append(exc)

        def reclaim():
            try:
                store.claim_next("tenant-a", "w", 3600)
            except Exception as exc:  # pragma: no cover - defensive
                errors.append(exc)

        with ThreadPoolExecutor(max_workers=2) as pool:
            list(pool.map(lambda fn: fn(), (batch, reclaim)))
        self.assertEqual(errors, [])
        status = store.get_status("tenant-a", rid)["status"]
        self.assertIn(status, ("processing", "failed"))
        self.assertTrue(store.verify_evidence("tenant-a", rid))
        # Never two terminal events; at most one live lease row.
        timeline = [e["status"] for e in store.audit("tenant-a", rid)]
        self.assertEqual(
            timeline.count("failed"), 1 if status == "failed" else 0
        )
        with sqlite3.connect(self.db_path) as raw:
            self.assertLessEqual(
                raw.execute(
                    "SELECT count(*) FROM claim_tokens WHERE request_id = ?", (rid,)
                ).fetchone()[0],
                1,
            )

    def test_concurrent_retry_of_same_cursor_does_not_double_write(self):
        store = self._store()
        ids = self._submit_many(store, 6)
        self._expire(store, 6)
        first = store.reconcile_batch("tenant-a", limit=2)

        def retry(_index):
            return store.reconcile_batch("tenant-a", first["next_cursor"], limit=10)

        with ThreadPoolExecutor(max_workers=8) as pool:
            pages = list(pool.map(retry, range(8)))
        # Every concurrent resume used the same batch and the remaining
        # items were recorded exactly once across all retries.
        self.assertTrue(all(p["batch_id"] == first["batch_id"] for p in pages))
        # Exactly one resume can win the remaining four items.
        self.assertEqual(
            sum(len(p["items"]) for p in pages), 4
        )
        with sqlite3.connect(self.db_path) as raw:
            self.assertEqual(
                raw.execute("SELECT count(*) FROM reconcile_batch_items").fetchone()[0],
                6,
            )
        for rid in ids:
            self.assertTrue(store.verify_evidence("tenant-a", rid))

    def test_concurrent_resume_cursor_reports_durable_settled_count(self):
        # Two independent store instances share the file but hold separate
        # in-process write locks (the cross-process deployment shape); only
        # SQLite serializes their per-item transactions. When both resume
        # the same cursor and each settle two disjoint items, every returned
        # cursor must name the database-authoritative settled count, never a
        # per-call snapshot that lags behind committed items.
        first_store = self._store()
        self._submit_many(first_store, 8)
        self._expire(first_store, 8)
        first = first_store.reconcile_batch("tenant-a", limit=2)
        _bid, start_n = _decode_cursor(first["next_cursor"])
        self.assertEqual(start_n, 2)

        store_a = self._store()
        store_b = self._store()
        after_first = threading.Barrier(2)
        after_second = threading.Barrier(2)
        settled = {"a": 0, "b": 0}
        original = RequestStore._batch_transaction

        def patched(self, conn, action):
            result = original(self, conn, action)
            tag = "a" if self is store_a else "b" if self is store_b else None
            if tag is not None and isinstance(result, tuple) and result[0] == "item":
                settled[tag] += 1
                if settled[tag] == 1:
                    after_first.wait(timeout=10)
                elif settled[tag] == 2:
                    after_second.wait(timeout=10)
            return result

        pages = {}

        def run(store, tag):
            pages[tag] = store.reconcile_batch(
                "tenant-a", first["next_cursor"], limit=2
            )

        RequestStore._batch_transaction = patched
        try:
            threads = [
                threading.Thread(target=run, args=(store_a, "a")),
                threading.Thread(target=run, args=(store_b, "b")),
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
        finally:
            RequestStore._batch_transaction = original

        with sqlite3.connect(self.db_path) as raw:
            durable = raw.execute(
                "SELECT count(*) FROM reconcile_batch_items"
            ).fetchone()[0]
            finished_flag = raw.execute(
                "SELECT finished FROM reconcile_batches"
            ).fetchone()[0]
        # Each call settled two disjoint items; six are durably committed
        # and two candidates remain, so the batch is still resumable.
        self.assertEqual(durable, 6)
        self.assertEqual(finished_flag, 0)
        for tag in ("a", "b"):
            page = pages[tag]
            self.assertEqual(page["batch_id"], first["batch_id"])
            self.assertEqual(len(page["items"]), 2)
            self.assertIs(page["finished"], False)
            self.assertIsNotNone(page["next_cursor"])
            # The cursor must report the durable count (6), not a stale
            # start+this-call value (4).
            self.assertEqual(_decode_cursor(page["next_cursor"]), (first["batch_id"], 6))
        # Resuming from either authoritative cursor settles the final two
        # exactly once and finishes the batch.
        resumed = first_store.reconcile_batch(
            "tenant-a", pages["a"]["next_cursor"], limit=10
        )
        self.assertEqual(len(resumed["items"]), 2)
        self.assertIs(resumed["finished"], True)
        self.assertIsNone(resumed["next_cursor"])
        with sqlite3.connect(self.db_path) as raw:
            self.assertEqual(
                raw.execute("SELECT count(*) FROM reconcile_batch_items").fetchone()[0],
                8,
            )


class BatchNoLeakTests(_StoreCase):
    def test_items_expose_only_request_id_and_status(self):
        store = self._store()
        rid = self._submit(store, subject="subject-SECRET")["request_id"]
        store.claim_next("tenant-a", "worker-SECRET", 1)
        _wait_for_expiry()
        result = store.reconcile_batch("tenant-a")
        rendered = repr(result)
        self.assertNotIn("subject-SECRET", rendered)
        self.assertNotIn("worker-SECRET", rendered)
        self.assertNotIn("email", rendered)
        for item in result["items"]:
            self.assertEqual(set(item), {"request_id", "status"})

    def test_cursor_is_opaque_and_does_not_embed_sensitive_data(self):
        store = self._store()
        ids = self._submit_many(store, 3)
        self._expire(store, 3)
        page = store.reconcile_batch("tenant-a", limit=1)
        cursor = page["next_cursor"]
        self.assertTrue(cursor.startswith("rc1."))
        decoded = base64.urlsafe_b64decode(cursor[4:]).decode("utf-8")
        self.assertNotIn("tenant-a", decoded)
        for rid in ids:
            self.assertNotIn(rid, decoded)

    def test_batch_ids_are_distinct_uuids(self):
        import uuid

        store = self._store()
        one = store.reconcile_batch("tenant-a")
        two = store.reconcile_batch("tenant-a")
        self.assertNotEqual(one["batch_id"], two["batch_id"])
        for value in (one["batch_id"], two["batch_id"]):
            uuid.UUID(value)


class FinishNotFoundPrecedenceTests(_StoreCase):
    def test_unknown_id_with_invalid_token_raises_not_found_first(self):
        store = self._store()
        for token in ("never-issued", "", None, 7, b"t"):
            with self.subTest(token=token):
                if not isinstance(token, str) or not token:
                    expected = ValueError
                else:
                    expected = RequestNotFound
                with self.assertRaises(expected):
                    store.finish_claim(
                        "tenant-a",
                        "00000000-0000-4000-8000-000000000000",
                        token,
                        "completed",
                    )

    def test_existing_request_with_invalid_token_still_conflicts(self):
        store = self._store()
        rid = self._submit(store)["request_id"]
        store.claim_next("tenant-a", "w", 3600)
        with self.assertRaises(ClaimConflict):
            store.finish_claim("tenant-a", rid, "no-such-token", "completed")
        self.assertEqual(store.get_status("tenant-a", rid)["status"], "processing")

    def test_unknown_id_with_foreign_live_token_still_conflicts(self):
        store = self._store()
        a = self._submit(store, key="ka")["request_id"]
        claim = store.claim_next("tenant-a", "w", 3600)
        self.assertEqual(claim["request_id"], a)
        # A valid live token presented against an unknown request id:
        # the credential exists, so this remains a claim conflict.
        with self.assertRaises(ClaimConflict):
            store.finish_claim(
                "tenant-a",
                "00000000-0000-4000-8000-000000000000",
                claim["claim_token"],
                "completed",
            )

    def test_cross_tenant_unknown_id_with_invalid_token_is_not_found(self):
        store = self._store()
        rid = self._submit(store, tenant="tenant-a")["request_id"]
        with self.assertRaises(RequestNotFound):
            store.finish_claim("tenant-b", rid, "no-such-token", "completed")
        # State, attempts and evidence of the real owner are untouched.
        self.assertEqual(store.get_status("tenant-a", rid)["status"], "accepted")


class DeferredBatchTests(_StoreCase):
    def test_batch_is_proxied(self):
        store = httpapi.DeferredRequestStore(self.db_path)
        rid = store.submit("tenant-a", "subject-1", ["email"], "key-1")["request_id"]
        store.claim_next("tenant-a", "worker-1", 1)
        _wait_for_expiry()
        result = store.reconcile_batch("tenant-a")
        self.assertEqual(result["items"], [{"request_id": rid, "status": "failed"}])

    def test_unavailable_storage_is_reported_consistently(self):
        blocker = os.path.join(self._tmp.name, "a-file")
        with open(blocker, "wb") as handle:
            handle.write(b"x")
        impossible = os.path.join(blocker, "nested", "evidence.db")
        store = httpapi.DeferredRequestStore(impossible)
        with self.assertRaises(httpapi._StorageUnavailable):
            store.reconcile_batch("tenant-a")


if __name__ == "__main__":
    unittest.main()
