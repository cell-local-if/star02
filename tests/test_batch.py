"""Tests for batched, resumable execution reconciliation.

Covers reconcile_batch on the storage layer only: the return shape and
type contract, keyset-stable ordering, accepted skipping without side
effects, live-lease preservation, expiry/unexplainable-lease
compensation and terminal idempotency per item, bounded pagination with
opaque continuation cursors, idempotent cursor retry (same batch id and
window) and resumption from the persisted position after an
interruption, tenant isolation, validation/not-found/finish-precedence
semantics, fixed-text storage corruption handling, persistence across
rebuilds, concurrent convergence to a single terminal state, and the
guarantee that no HTTP route is added.
"""

import http.client
import os
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor

from forgetting_evidence import httpapi
from forgetting_evidence.httpapi import build_server
from forgetting_evidence.requests import (
    ClaimConflict,
    RequestNotFound,
    RequestStore,
)

_PAST = "2020-01-01T00:00:00.000000Z"
_UNKNOWN_ID = "00000000-0000-4000-8000-000000000000"


class _StoreCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "evidence.db")

    def tearDown(self):
        self._tmp.cleanup()

    def _store(self):
        return RequestStore(self.db_path)

    def _backdate_lease(self, request_id, tenant="tenant-a"):
        # Force the open attempt's lease into the past without sleeping.
        with sqlite3.connect(self.db_path) as raw:
            raw.execute(
                "UPDATE claim_attempts SET lease_expires_at = ? "
                "WHERE tenant_id = ? AND request_id = ?",
                (_PAST, tenant, request_id),
            )

    def _seed(self, store, kind, key, tenant="tenant-a"):
        """Create a single request in the given state; return (id, expected).

        Only safe when no other claimable request exists in the tenant;
        multi-request fixtures must use :meth:`_seed_many`.
        """
        receipt = store.submit(tenant, f"subject-{key}", ["email"], key)
        rid = receipt["request_id"]
        token = None
        if kind == "accepted":
            expected = "accepted"
        elif kind == "live":
            claim = store.claim_next(tenant, "worker", 3600)
            assert claim["request_id"] == rid
            token = claim["claim_token"]
            expected = "processing"
        elif kind == "expired":
            claim = store.claim_next(tenant, "worker", 3600)
            assert claim["request_id"] == rid
            self._backdate_lease(rid, tenant)
            expected = "failed"
        elif kind == "stuck":
            # processing without any explainable attempt or lease
            store.transition(tenant, rid, "processing")
            expected = "failed"
        elif kind in ("completed", "failed"):
            claim = store.claim_next(tenant, "worker", 3600)
            assert claim["request_id"] == rid
            store.finish_claim(tenant, rid, claim["claim_token"], kind)
            expected = kind
        else:  # pragma: no cover - test authoring error
            raise AssertionError(kind)
        return rid, expected, token

    def _seed_many(self, store, kinds, tenant="tenant-a"):
        """Build several requests in stable keyset order.

        Returns a list of ``(rid, expected, token)``; accepted rows
        carry expected ``accepted`` and never appear in a batch window.
        Leases are all acquired while live (so an expired lease cannot be
        reclaimed ahead of a later submission); terminal finishes and
        lease expiries are applied afterwards, and the designated
        accepted rows are submitted last so they are never claimed.
        """
        # Submit and park unexplainable-processing rows first: once
        # transitioned (with no attempt) they are not claim candidates.
        stuck = [i for i, kind in enumerate(kinds) if kind == "stuck"]
        stuck_ids: dict[int, str] = {}
        for i in stuck:
            receipt = store.submit(tenant, f"subject-{i}", ["email"], f"k{i}")
            store.transition(tenant, receipt["request_id"], "processing")
            stuck_ids[i] = receipt["request_id"]
        # Submit the lease-taking rows in their intended relative order.
        lease_indices = [
            i
            for i, kind in enumerate(kinds)
            if kind in ("live", "expired", "completed", "failed")
        ]
        lease_receipts: dict[int, tuple] = {}
        for i in lease_indices:
            lease_receipts[i] = store.submit(
                tenant, f"subject-{i}", ["email"], f"k{i}"
            )
        tokens: dict[int, str] = {}
        for i in lease_indices:
            rid = lease_receipts[i]["request_id"]
            claim = store.claim_next(tenant, "worker", 3600)
            assert claim["request_id"] == rid
            tokens[i] = claim["claim_token"]
        # Finish terminals and expire dead leases only after every lease
        # was acquired.
        for i in lease_indices:
            rid = lease_receipts[i]["request_id"]
            if kinds[i] in ("completed", "failed"):
                store.finish_claim(tenant, rid, tokens[i], kinds[i])
            elif kinds[i] == "expired":
                self._backdate_lease(rid, tenant)
        # Finally submit the rows that must remain accepted.
        accepted_ids: dict[int, str] = {}
        for i, kind in enumerate(kinds):
            if kind == "accepted":
                accepted_ids[i] = store.submit(
                    tenant, f"subject-{i}", ["email"], f"k{i}"
                )["request_id"]
        out = []
        for i, kind in enumerate(kinds):
            if kind == "accepted":
                out.append((accepted_ids[i], "accepted", None))
            elif kind == "stuck":
                out.append((stuck_ids[i], "failed", None))
            elif kind == "live":
                out.append((lease_receipts[i]["request_id"], "processing", tokens[i]))
            elif kind == "expired":
                out.append((lease_receipts[i]["request_id"], "failed", tokens[i]))
            else:
                out.append((lease_receipts[i]["request_id"], kind, None))
        return out

    def _keyset_ids(self, tenant="tenant-a"):
        with sqlite3.connect(self.db_path) as raw:
            return [
                row[0]
                for row in raw.execute(
                    "SELECT request_id FROM requests "
                    "WHERE tenant_id = ? AND status != 'accepted' "
                    "ORDER BY created_at ASC, request_id ASC",
                    (tenant,),
                )
            ]


class BatchShapeTests(_StoreCase):
    def test_result_shape_and_types(self):
        store = self._store()
        rid, _exp, token = self._seed(store, "live", "k1")
        result = store.reconcile_batch("tenant-a")
        self.assertEqual(
            list(result), ["batch_id", "next_cursor", "finished", "items"]
        )
        self.assertIsInstance(result["batch_id"], str)
        self.assertTrue(result["batch_id"])
        self.assertTrue(result["finished"])
        self.assertIsNone(result["next_cursor"])
        self.assertIsInstance(result["finished"], bool)
        self.assertEqual(len(result["items"]), 1)
        item = result["items"][0]
        self.assertEqual(list(item), ["request_id", "status"])
        self.assertEqual(item, {"request_id": rid, "status": "processing"})
        # Only str/int/bool/None ever appear; no float leaks through.
        for value in (result["batch_id"], result["next_cursor"], item["request_id"],
                      item["status"]):
            self.assertTrue(value is None or isinstance(value, str))

    def test_empty_and_accepted_only_tenant_finishes_with_empty_window(self):
        store = self._store()
        for key in ("a", "b"):
            self._seed(store, "accepted", key)
        first = store.reconcile_batch("tenant-a", None, 50)
        self.assertTrue(first["finished"])
        self.assertIsNone(first["next_cursor"])
        self.assertEqual(first["items"], [])
        # A brand-new start over the same accepted-only tenant is also an
        # independent, immediately-finished empty batch.
        second = store.reconcile_batch("tenant-a")
        self.assertTrue(second["finished"])
        self.assertEqual(second["items"], [])
        self.assertNotEqual(first["batch_id"], second["batch_id"])

    def test_no_data_in_tenant_is_finished_empty(self):
        store = self._store()
        result = store.reconcile_batch("tenant-a")
        self.assertTrue(result["finished"])
        self.assertIsNone(result["next_cursor"])
        self.assertEqual(result["items"], [])


class BatchSkipAndConvergeTests(_StoreCase):
    def test_accepted_requests_are_skipped_without_any_write(self):
        store = self._store()
        accepted_ids = [self._seed(store, "accepted", f"a{i}")[0] for i in range(3)]
        result = store.reconcile_batch("tenant-a")
        self.assertTrue(result["finished"])
        self.assertEqual(result["items"], [])
        with sqlite3.connect(self.db_path) as raw:
            self.assertEqual(
                raw.execute("SELECT count(*) FROM claim_attempts").fetchone()[0], 0
            )
            self.assertEqual(
                raw.execute("SELECT count(*) FROM claim_tokens").fetchone()[0], 0
            )
        for rid in accepted_ids:
            self.assertEqual(store.get_status("tenant-a", rid)["status"], "accepted")
            self.assertEqual(store.get_execution_log("tenant-a", rid), [])
            self.assertEqual(
                [e["status"] for e in store.audit("tenant-a", rid)], ["accepted"]
            )

    def test_live_lease_stays_processing_and_remains_finishable(self):
        store = self._store()
        rid, _exp, token = self._seed(store, "live", "k1")
        result = store.reconcile_batch("tenant-a")
        self.assertEqual(result["items"], [{"request_id": rid, "status": "processing"}])
        self.assertEqual(
            store.get_status("tenant-a", rid)["status"], "processing"
        )
        # No new attempt was generated and the live credential still works.
        self.assertEqual(len(store.get_execution_log("tenant-a", rid)), 1)
        done = store.finish_claim("tenant-a", rid, token, "completed")
        self.assertEqual(done["status"], "completed")

    def test_expired_and_unexplainable_processing_converge_to_failed(self):
        store = self._store()
        expired, _, _ = self._seed(store, "expired", "ke")
        stuck, _, _ = self._seed(store, "stuck", "ks")
        result = store.reconcile_batch("tenant-a")
        statuses = {i["request_id"]: i["status"] for i in result["items"]}
        self.assertEqual(statuses[expired], "failed")
        self.assertEqual(statuses[stuck], "failed")
        for rid in (expired, stuck):
            self.assertEqual(store.get_status("tenant-a", rid)["status"], "failed")
            entry = store.get_execution_log("tenant-a", expired)[0]
            self.assertEqual(entry["result"], "failed")
            self.assertIsNotNone(entry["completed_at"])
            self.assertTrue(store.verify_evidence("tenant-a", rid))
        # Dead credentials were released.
        with sqlite3.connect(self.db_path) as raw:
            self.assertEqual(
                raw.execute("SELECT count(*) FROM claim_tokens").fetchone()[0], 0
            )

    def test_terminals_are_idempotent_no_ops(self):
        store = self._store()
        completed, _, _ = self._seed(store, "completed", "kc")
        failed, _, _ = self._seed(store, "failed", "kf")
        timeline = {
            rid: [e["status"] for e in store.audit("tenant-a", rid)]
            for rid in (completed, failed)
        }
        for _ in range(3):
            result = store.reconcile_batch("tenant-a")
            statuses = {i["request_id"]: i["status"] for i in result["items"]}
            self.assertEqual(statuses[completed], "completed")
            self.assertEqual(statuses[failed], "failed")
        for rid in (completed, failed):
            self.assertEqual(
                [e["status"] for e in store.audit("tenant-a", rid)], timeline[rid]
            )

    def test_batch_then_single_reconcile_is_stable(self):
        store = self._store()
        rid, _, _ = self._seed(store, "expired", "ke")
        batch = store.reconcile_batch("tenant-a")
        self.assertEqual(batch["items"][0]["status"], "failed")
        again = store.reconcile_execution("tenant-a", rid)
        self.assertEqual(again["status"], "failed")
        # The compensation completion time is written exactly once.
        log = store.get_execution_log("tenant-a", rid)
        self.assertEqual(len(log), 1)
        self.assertEqual(log[0]["result"], "failed")


class BatchOrderingTests(_StoreCase):
    def test_items_follow_stable_keyset_order(self):
        store = self._store()
        kinds = ["expired", "live", "completed", "accepted", "stuck", "failed"]
        seeded = self._seed_many(store, kinds)
        expected = {rid: after for rid, after, _ in seeded if after != "accepted"}
        result = store.reconcile_batch("tenant-a", None, 100)
        ordered_ids = self._keyset_ids()
        self.assertEqual([i["request_id"] for i in result["items"]], ordered_ids)
        self.assertEqual(
            result["items"],
            [{"request_id": rid, "status": expected[rid]} for rid in ordered_ids],
        )

    def test_equal_acceptance_time_tie_breaks_by_request_id(self):
        # Two terminal rows at the identical acceptance instant (terminal
        # reconciliation is read-only, so no attempt rows are required)
        # must be reported in ascending request id order.
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
                raw.execute(
                    "INSERT INTO requests VALUES (?, 'tenant-a', ?, 's', '[]', "
                    "'failed', ?, 'x')",
                    (rid, f"key-{rid}", created_at),
                )
        result = self._store().reconcile_batch("tenant-a")
        self.assertEqual([i["request_id"] for i in result["items"]], [low, high])
        self.assertTrue(all(i["status"] == "failed" for i in result["items"]))


class BatchPaginationTests(_StoreCase):
    def test_window_is_bounded_and_chains_to_completion(self):
        store = self._store()
        kinds = ["expired", "live", "completed", "accepted", "stuck", "failed"]
        seeded = self._seed_many(store, kinds)
        expected = {rid: after for rid, after, _ in seeded if after != "accepted"}
        ordered_ids = self._keyset_ids()

        collected = []
        batch_ids = []
        cursor = None
        batches = 0
        while True:
            result = store.reconcile_batch("tenant-a", cursor, 2)
            batches += 1
            batch_ids.append(result["batch_id"])
            self.assertLessEqual(len(result["items"]), 2)
            collected.extend(result["items"])
            if result["finished"]:
                self.assertIsNone(result["next_cursor"])
                break
            self.assertIsInstance(result["next_cursor"], str)
            cursor = result["next_cursor"]
        # Five non-accepted requests at two per batch => three batches,
        # the last holding a single item.
        self.assertEqual(batches, 3)
        self.assertEqual(len(set(batch_ids)), 3)
        self.assertEqual([i["request_id"] for i in collected], ordered_ids)
        self.assertEqual(
            collected,
            [{"request_id": rid, "status": expected[rid]} for rid in ordered_ids],
        )

    def test_default_limit_applies(self):
        store = self._store()
        for index in range(3):
            self._seed(store, "stuck", f"k{index}")
        result = store.reconcile_batch("tenant-a")  # default cap
        self.assertTrue(result["finished"])
        self.assertEqual(len(result["items"]), 3)


class BatchIdempotencyTests(_StoreCase):
    def _start_cursor(self, tenant="tenant-a"):
        with sqlite3.connect(self.db_path) as raw:
            return raw.execute(
                "SELECT cursor_token FROM reconcile_batches "
                "WHERE tenant_id = ? ORDER BY rowid ASC LIMIT 1",
                (tenant,),
            ).fetchone()[0]

    def test_retrying_start_cursor_replays_same_batch_and_window(self):
        store = self._store()
        for index in range(3):
            self._seed(store, "stuck", f"k{index}")
        first = store.reconcile_batch("tenant-a", None, 2)
        start_cursor = self._start_cursor()
        self.assertFalse(first["finished"])
        # Retrying the original start cursor is the same batch, the same
        # window and the same statuses -- nothing is re-converged.
        retry = store.reconcile_batch("tenant-a", start_cursor, 2)
        self.assertEqual(retry["batch_id"], first["batch_id"])
        self.assertEqual(retry["items"], first["items"])
        self.assertFalse(retry["finished"])
        self.assertEqual(retry["next_cursor"], first["next_cursor"])

    def test_retrying_continuation_cursor_replays_same_batch(self):
        store = self._store()
        for index in range(3):
            self._seed(store, "stuck", f"k{index}")
        first = store.reconcile_batch("tenant-a", None, 2)
        second = store.reconcile_batch("tenant-a", first["next_cursor"], 2)
        self.assertTrue(second["finished"])
        second_retry = store.reconcile_batch("tenant-a", first["next_cursor"], 2)
        self.assertEqual(second_retry["batch_id"], second["batch_id"])
        self.assertEqual(second_retry["items"], second["items"])
        self.assertTrue(second_retry["finished"])
        self.assertIsNone(second_retry["next_cursor"])

    def test_window_replays_after_rebuild(self):
        first_store = self._store()
        for index in range(3):
            self._seed(first_store, "stuck", f"k{index}")
        first = first_store.reconcile_batch("tenant-a", None, 2)
        rebuilt = self._store()
        retry = rebuilt.reconcile_batch("tenant-a", first["next_cursor"], 2)
        self.assertTrue(retry["finished"])
        self.assertEqual(len(retry["items"]), 1)
        # The first window is replayable on the rebuilt store as well.
        start_cursor = self._start_cursor()
        again = rebuilt.reconcile_batch("tenant-a", start_cursor, 2)
        self.assertEqual(again["batch_id"], first["batch_id"])
        self.assertEqual(again["items"], first["items"])


class _InterruptedStore(RequestStore):
    """Fails the Nth per-item reconciliation to simulate an interruption."""

    fail_on = None
    calls = 0

    def _reconcile_locked(self, conn, tenant_id, request_id):
        self.calls += 1
        if self.fail_on is not None and self.calls == self.fail_on:
            raise OSError("request store is unavailable")
        return super()._reconcile_locked(conn, tenant_id, request_id)


class BatchResumeTests(_StoreCase):
    def test_interrupted_batch_resumes_from_persisted_position(self):
        store = _InterruptedStore(self.db_path)
        kinds = ["stuck", "expired", "stuck", "expired"]
        self._seed_many(store, kinds)
        # Fail while processing the third item; the first two committed
        # per-item transactions survive.
        store.fail_on = 3
        with self.assertRaises(OSError) as ctx:
            store.reconcile_batch("tenant-a", None, 4)
        self.assertEqual(str(ctx.exception), "request store is unavailable")
        with sqlite3.connect(self.db_path) as raw:
            self.assertEqual(
                raw.execute(
                    "SELECT inspected, sealed FROM reconcile_batches"
                ).fetchone(),
                (2, 0),
            )
            start_cursor = raw.execute(
                "SELECT cursor_token FROM reconcile_batches"
            ).fetchone()[0]
        # Resume with the same cursor: it continues after the persisted
        # position and returns the whole, fully-converged window.
        store.fail_on = None
        result = store.reconcile_batch("tenant-a", start_cursor, 4)
        self.assertTrue(result["finished"])
        self.assertEqual(len(result["items"]), 4)
        ordered = self._keyset_ids()
        self.assertEqual([i["request_id"] for i in result["items"]], ordered)
        self.assertTrue(all(i["status"] == "failed" for i in result["items"]))
        # Each request converged exactly once.
        for rid in ordered:
            self.assertEqual(store.get_status("tenant-a", rid)["status"], "failed")
            self.assertEqual(
                [e["status"] for e in store.audit("tenant-a", rid)],
                ["accepted", "processing", "failed"],
            )
            self.assertTrue(store.verify_evidence("tenant-a", rid))


class BatchValidationTests(_StoreCase):
    def test_bad_tenant_is_value_error_without_writes(self):
        store = self._store()
        self._seed(store, "stuck", "k1")
        for bad in ("", None, 7, b"t", ["t"], True):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    store.reconcile_batch(bad)
        with sqlite3.connect(self.db_path) as raw:
            self.assertEqual(
                raw.execute("SELECT count(*) FROM reconcile_batches").fetchone()[0], 0
            )
        self.assertEqual(
            store.get_status(
                "tenant-a", self._keyset_ids()[0]
            )["status"],
            "processing",
        )

    def test_bad_cursor_shape_is_value_error(self):
        store = self._store()
        self._seed(store, "stuck", "k1")
        for bad in (
            "",
            7,
            b"v1.s.aaaaaaaaaaaaaaaaaaaaaa",
            ["cursor"],
            True,
            "nonsense",
            "v1.s.short",
            "v2.s.aaaaaaaaaaaaaaaaaaaaaa",  # unknown version
            "v1.x.aaaaaaaaaaaaaaaaaaaaaa",  # unknown kind
            "v1.s." + "A" * 43,  # well-formed but fabricated token
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    store.reconcile_batch("tenant-a", bad)
        with sqlite3.connect(self.db_path) as raw:
            self.assertEqual(
                raw.execute("SELECT count(*) FROM reconcile_batches").fetchone()[0], 0
            )

    def test_cursor_from_other_tenant_is_unknown(self):
        store = self._store()
        self._seed_many(store, ["stuck", "stuck"])
        first = store.reconcile_batch("tenant-a", None, 1)
        self.assertIsInstance(first["next_cursor"], str)
        # A continuation cursor only resolves within its own tenant.
        with self.assertRaises(ValueError):
            store.reconcile_batch("tenant-b", first["next_cursor"], 1)

    def test_bad_limit_is_value_error_without_writes(self):
        store = self._store()
        self._seed(store, "stuck", "k1")
        for bad in (0, -1, 1001, 10_000, 1.0, 0.5, True, False, "5", [5]):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    store.reconcile_batch("tenant-a", None, bad)
        with sqlite3.connect(self.db_path) as raw:
            self.assertEqual(
                raw.execute("SELECT count(*) FROM reconcile_batches").fetchone()[0], 0
            )


class BatchCorruptionTests(_StoreCase):
    def _fixed_message(self, ctx):
        self.assertEqual(str(ctx.exception), "request store is unavailable")
        self.assertNotIn("sqlite", str(ctx.exception).lower())
        self.assertNotIn(self.db_path, str(ctx.exception))

    def test_missing_batch_table_is_os_error(self):
        store = self._store()
        self._seed(store, "stuck", "k1")
        with sqlite3.connect(self.db_path) as raw:
            raw.execute("DROP TABLE reconcile_batches")
        with self.assertRaises(OSError) as ctx:
            store.reconcile_batch("tenant-a")
        self._fixed_message(ctx)

    def test_missing_item_table_is_os_error(self):
        store = self._store()
        self._seed(store, "stuck", "k1")
        first = store.reconcile_batch("tenant-a", None, 1)
        with sqlite3.connect(self.db_path) as raw:
            raw.execute("DROP TABLE reconcile_batch_items")
        # Retrying the sealed batch cannot reload its persisted window.
        with self.assertRaises(OSError) as ctx:
            store.reconcile_batch("tenant-a", first["next_cursor"], 1)
        self._fixed_message(ctx)

    def test_unknown_request_status_is_os_error(self):
        store = self._store()
        rid, _, _ = self._seed(store, "stuck", "k1")
        with sqlite3.connect(self.db_path) as raw:
            raw.execute(
                "UPDATE requests SET status = 'bogus' WHERE request_id = ?",
                (rid,),
            )
        with self.assertRaises(OSError) as ctx:
            store.reconcile_batch("tenant-a")
        self._fixed_message(ctx)

    def test_corrupt_file_is_os_error(self):
        store = self._store()
        self._seed(store, "stuck", "k1")
        with open(self.db_path, "wb") as handle:
            handle.write(b"not a sqlite database")
        with self.assertRaises(OSError) as ctx:
            store.reconcile_batch("tenant-a")
        self._fixed_message(ctx)


class BatchConcurrencyTests(_StoreCase):
    def test_concurrent_continuation_resolves_to_one_batch(self):
        store = self._store()
        for index in range(4):
            self._seed(store, "stuck", f"k{index}")
        first = store.reconcile_batch("tenant-a", None, 2)
        cursor = first["next_cursor"]

        def continue_batch(_index):
            return store.reconcile_batch("tenant-a", cursor, 2)

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(continue_batch, range(16)))
        batch_ids = {r["batch_id"] for r in results}
        self.assertEqual(len(batch_ids), 1)
        self.assertTrue(all(r["finished"] for r in results))
        windows = {tuple((i["request_id"], i["status"]) for i in r["items"])
                   for r in results}
        self.assertEqual(len(windows), 1)
        self.assertEqual(len(next(iter(windows))), 2)

    def test_concurrent_batch_and_reconcile_converge_once(self):
        store = self._store()
        seeded = self._seed_many(store, ["expired"] * 8)
        ids = [rid for rid, _expected, _token in seeded]
        barrier = threading.Barrier(2)

        def batch():
            barrier.wait()
            out = []
            cursor = None
            while True:
                result = store.reconcile_batch("tenant-a", cursor, 3)
                out.extend(i["request_id"] for i in result["items"])
                if result["finished"]:
                    return out
                cursor = result["next_cursor"]

        def reconcile():
            barrier.wait()
            for rid in ids:
                try:
                    store.reconcile_execution("tenant-a", rid)
                except RequestNotFound:  # pragma: no cover - never expected
                    pass

        with ThreadPoolExecutor(max_workers=2) as pool:
            list(pool.map(lambda fn: fn(), (batch, reconcile)))
        for rid in ids:
            self.assertEqual(store.get_status("tenant-a", rid)["status"], "failed")
            self.assertEqual(
                [e["status"] for e in store.audit("tenant-a", rid)],
                ["accepted", "processing", "failed"],
            )
            log = store.get_execution_log("tenant-a", rid)
            # Exactly one attempt, compensated exactly once.
            self.assertEqual(len(log), 1)
            self.assertEqual(log[0]["result"], "failed")
            self.assertIsNotNone(log[0]["completed_at"])
            self.assertTrue(store.verify_evidence("tenant-a", rid))


class FinishPrecedenceTests(_StoreCase):
    def test_unknown_id_with_invalid_credential_is_not_found_first(self):
        store = self._store()
        self._seed(store, "live", "ka", tenant="tenant-a")
        other = self._seed(store, "live", "kb", tenant="tenant-b")
        foreign_token = other[2]
        # Invalid credential against an unknown id.
        with self.assertRaises(RequestNotFound):
            store.finish_claim("tenant-a", _UNKNOWN_ID, "garbage", "completed")
        # A real but foreign live credential against an unknown id is
        # still not-found, never ClaimConflict.
        with self.assertRaises(RequestNotFound):
            store.finish_claim("tenant-a", _UNKNOWN_ID, foreign_token, "completed")
        # A cross-tenant id with the caller's own live credential is
        # likewise not-found.
        own = self._seed(store, "live", "kc", tenant="tenant-a")
        with self.assertRaises(RequestNotFound):
            store.finish_claim("tenant-a", other[0], own[2], "completed")
        # A visible target with a wrong credential stays a conflict.
        with self.assertRaises(ClaimConflict):
            store.finish_claim("tenant-a", own[0], "garbage", "completed")
        # Nothing converged or completed.
        self.assertEqual(store.get_status("tenant-a", own[0])["status"], "processing")
        self.assertEqual(
            store.get_status("tenant-b", other[0])["status"], "processing"
        )


class DeferredBatchTests(_StoreCase):
    def test_batch_is_proxied(self):
        store = httpapi.DeferredRequestStore(self.db_path)
        rid = store.submit("tenant-a", "subject-1", ["email"], "key-1")["request_id"]
        claim = store.claim_next("tenant-a", "worker", 3600)
        assert claim["request_id"] == rid
        result = store.reconcile_batch("tenant-a")
        self.assertEqual(
            result["items"], [{"request_id": rid, "status": "processing"}]
        )

    def test_unavailable_storage_is_reported_consistently(self):
        blocker = os.path.join(self._tmp.name, "a-file")
        with open(blocker, "wb") as handle:
            handle.write(b"x")
        impossible = os.path.join(blocker, "nested", "evidence.db")
        store = httpapi.DeferredRequestStore(impossible)
        with self.assertRaises(httpapi._StorageUnavailable):
            store.reconcile_batch("tenant-a")


class BatchHttpSurfaceTests(_StoreCase):
    def test_no_batch_route_is_exposed(self):
        store = self._store()
        server = build_server(store, "127.0.0.1", 0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_address[1]
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            for method, path in (
                ("POST", "/reconcile-batches"),
                ("GET", "/reconcile-batches"),
            ):
                conn.request(method, path, body="{}")
                resp = conn.getresponse()
                resp.read()
                self.assertEqual(resp.status, 404, (method, path, resp.status))
            conn.close()
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
