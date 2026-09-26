"""Tests for the instantaneous, read-only tenant health snapshot.

Covers RequestStore.audit_health on the storage layer only: the fixed
plain-dictionary shape (``total``, ``statuses``, ``verified``,
``unverified``, ``reasons``), the four lifecycle status counts with
explicit zeros, the complementary verified/unverified tally, the merged
reason-count list ordered by Unicode code point, the same full-chain
trust criteria as the inspection sweep (tampering, legacy un-anchored
and secret-missing databases, wrong secret, missing historical
secret), the single read-only consistent snapshot under concurrent
writes, strict read-only behaviour (no batches, cursors, evidence or
business writes), validation without writes, the fixed-text
``audit_health_failed`` OSError contract, repeatability across rebuilds
and the absence of any HTTP route or health-command change.
"""

import http.client
import json
import os
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from logging import getLogger

from forgetting_evidence import httpapi
from forgetting_evidence.httpapi import build_server
from forgetting_evidence.requests import RequestStore

_STATUS_NAMES = ("accepted", "processing", "completed", "failed")
_LOGGER_NAME = "forgetting_evidence.requests"


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

    def _assert_well_formed(self, snapshot, expected_total):
        # Plain dictionary with exactly the five documented keys in
        # order; nothing else rides along.
        self.assertIsInstance(snapshot, dict)
        self.assertEqual(
            list(snapshot),
            ["total", "statuses", "verified", "unverified", "reasons"],
        )
        total = snapshot["total"]
        self.assertIsInstance(total, int)
        self.assertNotIsInstance(total, bool)
        self.assertEqual(total, expected_total)
        self.assertGreaterEqual(total, 0)
        statuses = snapshot["statuses"]
        self.assertIsInstance(statuses, dict)
        self.assertEqual(list(statuses), list(_STATUS_NAMES))
        for name in _STATUS_NAMES:
            count = statuses[name]
            self.assertIsInstance(count, int)
            self.assertNotIsInstance(count, bool)
            self.assertGreaterEqual(count, 0)
        # The four status buckets partition the request population.
        self.assertEqual(total, sum(statuses.values()))
        verified = snapshot["verified"]
        unverified = snapshot["unverified"]
        for value in (verified, unverified):
            self.assertIsInstance(value, int)
            self.assertNotIsInstance(value, bool)
            self.assertGreaterEqual(value, 0)
        # The trust counts are complementary and cover every request.
        self.assertEqual(total, verified + unverified)
        reasons = snapshot["reasons"]
        self.assertIsInstance(reasons, list)
        merged = 0
        previous = None
        for entry in reasons:
            self.assertEqual(list(entry), ["reason", "count"])
            reason = entry["reason"]
            count = entry["count"]
            self.assertIsInstance(reason, str)
            self.assertTrue(reason)
            self.assertIsInstance(count, int)
            self.assertNotIsInstance(count, bool)
            self.assertGreater(count, 0)
            if previous is not None:
                # Ordered by Unicode code point.
                self.assertLess(previous, reason)
            previous = reason
            merged += count
        # The reason buckets partition the unverified population.
        self.assertEqual(merged, unverified)
        # Never a float, negative zero or non-finite value anywhere.
        json.dumps(snapshot, allow_nan=False)


class HealthShapeTests(_StoreCase):
    def test_empty_tenant_is_all_zeros(self):
        store = self._store()
        snapshot = store.audit_health("tenant-a")
        self._assert_well_formed(snapshot, 0)
        self.assertEqual(snapshot["statuses"], {name: 0 for name in _STATUS_NAMES})
        self.assertEqual(snapshot["verified"], 0)
        self.assertEqual(snapshot["unverified"], 0)
        self.assertEqual(snapshot["reasons"], [])

    def test_healthy_requests_are_all_verified_accepted(self):
        store = self._store()
        self._submit_many(store, 3)
        snapshot = store.audit_health("tenant-a")
        self._assert_well_formed(snapshot, 3)
        self.assertEqual(snapshot["statuses"]["accepted"], 3)
        self.assertEqual(snapshot["verified"], 3)
        self.assertEqual(snapshot["unverified"], 0)
        self.assertEqual(snapshot["reasons"], [])

    def test_status_counts_cover_all_four_lifecycle_states(self):
        store = self._store()
        ids = self._submit_many(store, 4)
        # accepted -> processing -> completed for one.
        claim = store.claim_next("tenant-a", "worker-1", 300)
        self.assertEqual(claim["request_id"], ids[0])
        store.finish_claim("tenant-a", ids[0], claim["claim_token"], "completed")
        # accepted -> processing for another.
        store.transition("tenant-a", ids[1], "processing")
        # accepted -> failed directly for a third.
        store.transition("tenant-a", ids[2], "failed")
        # ids[3] stays accepted.
        snapshot = store.audit_health("tenant-a")
        self._assert_well_formed(snapshot, 4)
        self.assertEqual(
            snapshot["statuses"],
            {"accepted": 1, "processing": 1, "completed": 1, "failed": 1},
        )
        self.assertEqual(snapshot["verified"], 4)
        self.assertEqual(snapshot["unverified"], 0)

    def test_other_tenants_are_excluded_but_their_absence_is_zero(self):
        store = self._store()
        own = self._submit_many(store, 2, tenant="tenant-a")
        self._submit_many(store, 3, tenant="tenant-b")
        snapshot_a = store.audit_health("tenant-a")
        self._assert_well_formed(snapshot_a, 2)
        self.assertEqual(snapshot_a["statuses"]["accepted"], 2)
        snapshot_b = store.audit_health("tenant-b")
        self._assert_well_formed(snapshot_b, 3)
        # A tenant with no requests at all still carries explicit zeros.
        snapshot_c = store.audit_health("tenant-c")
        self._assert_well_formed(snapshot_c, 0)
        self.assertEqual(len(own), 2)

    def test_in_memory_store_uses_the_same_snapshot_path(self):
        store = RequestStore(":memory:", anchor_secret="anchor-secret")
        store.submit("tenant-a", "subject-1", ["email"], "key-1")
        snapshot = store.audit_health("tenant-a")
        self._assert_well_formed(snapshot, 1)
        self.assertEqual(snapshot["verified"], 1)


class HealthTrustTests(_StoreCase):
    def test_unanchored_legacy_database_is_unverified(self):
        store = RequestStore(self.db_path)  # historical no-secret store
        self._submit_many(store, 2)
        snapshot = store.audit_health("tenant-a")
        self._assert_well_formed(snapshot, 2)
        self.assertEqual(snapshot["verified"], 0)
        self.assertEqual(snapshot["unverified"], 2)
        self.assertEqual(
            snapshot["reasons"],
            [{"reason": "unanchored_database", "count": 2}],
        )

    def test_anchored_database_without_secret_is_unverified(self):
        store = self._store()
        self._submit_many(store, 2)
        no_secret = RequestStore(self.db_path)
        snapshot = no_secret.audit_health("tenant-a")
        self._assert_well_formed(snapshot, 2)
        self.assertEqual(
            snapshot["reasons"],
            [{"reason": "anchor_secret_missing", "count": 2}],
        )

    def test_wrong_secret_is_unverified(self):
        store = self._store()
        self._submit_many(store, 2)
        wrong = RequestStore(self.db_path, anchor_secret="other-secret")
        snapshot = wrong.audit_health("tenant-a")
        self._assert_well_formed(snapshot, 2)
        self.assertEqual(
            snapshot["reasons"],
            [{"reason": "anchor_auth_failed", "count": 2}],
        )

    def test_tampered_global_head_fails_every_request(self):
        store = self._store()
        self._submit_many(store, 2)
        with self._raw() as raw:
            raw.execute(
                "UPDATE audit_anchor_meta SET head_hmac = ?", ("2" * 64,)
            )
        snapshot = store.audit_health("tenant-a")
        self._assert_well_formed(snapshot, 2)
        self.assertEqual(snapshot["verified"], 0)
        self.assertEqual(
            snapshot["reasons"],
            [{"reason": "anchor_head_mismatch", "count": 2}],
        )

    def test_tampered_chain_head_fails_only_that_request(self):
        store = self._store()
        ids = self._submit_many(store, 2)
        with self._raw() as raw:
            raw.execute(
                "UPDATE requests SET chain_hash = ? WHERE request_id = ?",
                ("0" * 64, ids[0]),
            )
        snapshot = store.audit_health("tenant-a")
        self._assert_well_formed(snapshot, 2)
        self.assertEqual(snapshot["verified"], 1)
        self.assertEqual(snapshot["unverified"], 1)
        self.assertEqual(
            snapshot["reasons"],
            [{"reason": "chain_head_mismatch", "count": 1}],
        )

    def test_reasons_are_merged_and_unicode_sorted(self):
        store = self._store()
        ids = self._submit_many(store, 4)
        # All legitimate writes happen while the evidence is intact: the
        # write gate rejects a store whose anchors no longer verify.
        store.transition("tenant-a", ids[1], "processing")
        with self._raw() as raw:
            # Request 0: tampered request head only -> chain_head_mismatch.
            raw.execute(
                "UPDATE requests SET chain_hash = ? WHERE request_id = ?",
                ("0" * 64, ids[0]),
            )
            # Request 1: delete its processing event so the anchor is
            # orphaned and the head no longer matches -> anchor_orphan,
            # which sorts before chain_head_mismatch.
            raw.execute(
                "DELETE FROM status_events WHERE request_id = ? AND seq = 1",
                (ids[1],),
            )
            # Request 2: a substituted head only.
            raw.execute(
                "UPDATE requests SET chain_hash = ? WHERE request_id = ?",
                ("3" * 64, ids[2]),
            )
        snapshot = store.audit_health("tenant-a")
        self._assert_well_formed(snapshot, 4)
        self.assertEqual(snapshot["statuses"]["accepted"], 3)
        self.assertEqual(snapshot["statuses"]["processing"], 1)
        self.assertEqual(snapshot["verified"], 1)
        self.assertEqual(snapshot["unverified"], 3)
        self.assertEqual(
            snapshot["reasons"],
            [
                {"reason": "anchor_orphan", "count": 1},
                {"reason": "chain_head_mismatch", "count": 2},
            ],
        )

    def test_missing_historical_secret_marks_every_request(self):
        store = self._store(secret="secret-1")
        store.submit("tenant-a", "subject-0", ["email"], "key-0")
        store.rotate_anchor_key("secret-1", "secret-2")
        store.submit("tenant-a", "subject-1", ["email"], "key-1")
        rebuilt = self._store(secret="secret-2")
        snapshot = rebuilt.audit_health("tenant-a")
        self._assert_well_formed(snapshot, 2)
        self.assertEqual(
            snapshot["reasons"],
            [{"reason": "anchor_key_missing", "count": 2}],
        )
        complete = self._store(secret="secret-2", history={1: "secret-1"})
        healed = complete.audit_health("tenant-a")
        self._assert_well_formed(healed, 2)
        self.assertEqual(healed["verified"], 2)
        self.assertEqual(healed["reasons"], [])


class HealthStabilityTests(_StoreCase):
    def test_repeated_reads_and_rebuilds_return_the_same_snapshot(self):
        store = self._store()
        ids = self._submit_many(store, 3)
        with self._raw() as raw:
            raw.execute(
                "UPDATE requests SET chain_hash = ? WHERE request_id = ?",
                ("0" * 64, ids[0]),
            )
        first = store.audit_health("tenant-a")
        self.assertEqual(store.audit_health("tenant-a"), first)
        rebuilt = self._store()
        self.assertEqual(rebuilt.audit_health("tenant-a"), first)

    def test_snapshot_reflects_the_instant_then_stays_read_only(self):
        store = self._store()
        ids = self._submit_many(store, 2)
        before = store.audit_health("tenant-a")
        self.assertEqual(before["total"], 2)
        store.transition("tenant-a", ids[0], "processing")
        after = store.audit_health("tenant-a")
        self.assertEqual(after["statuses"]["processing"], 1)
        self.assertEqual(after["statuses"]["accepted"], 1)
        self.assertEqual(after["verified"], 2)


class HealthReadOnlyTests(_StoreCase):
    def test_health_read_modifies_no_table(self):
        store = self._store(secret="secret-1")
        ids = self._submit_many(store, 3)
        store.transition("tenant-a", ids[0], "processing")
        store.rotate_anchor_key("secret-1", "secret-2")
        # Leave an open inspection batch and its bookkeeping in place.
        store.audit_inspection("tenant-a", limit=2)
        tables = (
            "requests",
            "status_events",
            "claim_attempts",
            "claim_tokens",
            "reconcile_batches",
            "reconcile_batch_items",
            "inspection_batches",
            "inspection_batch_items",
            "deletion_receipts",
            "receipt_keys",
            "audit_anchors",
            "audit_anchor_meta",
            "anchor_key_generations",
        )
        before = {table: self._table_dump(table) for table in tables}
        store.audit_health("tenant-a")
        store.audit_health("tenant-a")
        after = {table: self._table_dump(table) for table in tables}
        self.assertEqual(before, after)

    def test_health_read_creates_no_inspection_batch(self):
        store = self._store()
        self._submit_many(store, 2)
        store.audit_health("tenant-a")
        store.audit_health("tenant-empty")
        with self._raw() as raw:
            self.assertEqual(
                raw.execute("SELECT count(*) FROM inspection_batches").fetchone()[0],
                0,
            )
            self.assertEqual(
                raw.execute(
                    "SELECT count(*) FROM inspection_batch_items"
                ).fetchone()[0],
                0,
            )

    def test_health_read_does_not_advance_an_open_cursor(self):
        store = self._store()
        self._submit_many(store, 3)
        first = store.audit_inspection("tenant-a", limit=2)
        store.audit_health("tenant-a")
        # The open batch still resumes with the remaining single item.
        tail = store.audit_inspection("tenant-a", cursor=first["next_cursor"])
        self.assertEqual(len(tail["items"]), 1)
        self.assertIs(tail["finished"], True)


class HealthValidationTests(_StoreCase):
    def test_invalid_tenant_raises_value_error_without_writing(self):
        store = self._store()
        self._submit_many(store, 1)
        tables = (
            "requests",
            "status_events",
            "inspection_batches",
            "inspection_batch_items",
            "audit_anchors",
        )
        before = {table: self._table_dump(table) for table in tables}
        for bad in ("", None, 5, True, False, ["tenant-a"], b"tenant-a", 1.5):
            with self.assertRaises(ValueError):
                store.audit_health(bad)
        after = {table: self._table_dump(table) for table in tables}
        self.assertEqual(before, after)


class HealthStorageFailureTests(_StoreCase):
    def test_missing_table_raises_audit_health_failed(self):
        store = self._store()
        self._submit_many(store, 1)
        with self._raw() as raw:
            raw.execute("DROP TABLE audit_anchors")
        with self.assertRaises(OSError) as caught:
            store.audit_health("tenant-a")
        self.assertEqual(str(caught.exception), "audit_health_failed")

    def test_unknown_status_value_raises_audit_health_failed(self):
        store = self._store()
        self._submit_many(store, 1)
        with self._raw() as raw:
            raw.execute(
                "INSERT INTO requests ("
                "request_id, tenant_id, idempotency_key, subject_id, "
                "scopes_json, status, created_at, chain_hash"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "ffffffff-ffff-ffff-ffff-ffffffffffff",
                    "tenant-a",
                    "key-bad",
                    "subject-bad",
                    "[]",
                    "bogus",
                    "2026-01-01T00:00:00.000000Z",
                    "0" * 64,
                ),
            )
        with self.assertRaises(OSError) as caught:
            store.audit_health("tenant-a")
        self.assertEqual(str(caught.exception), "audit_health_failed")

    def test_unreadable_storage_raises_audit_health_failed(self):
        store = self._store()
        self._submit_many(store, 1)
        # A database file with a destroyed header opens lazily but fails
        # on the snapshot's first read, inside the transaction the entry
        # owns.
        with open(self.db_path, "r+b") as handle:
            handle.write(b"not a sqlite database" + b"\0" * 64)
        with self.assertRaises(OSError) as caught:
            store.audit_health("tenant-a")
        self.assertEqual(str(caught.exception), "audit_health_failed")

    def test_empty_unverified_reason_raises_audit_health_failed(self):
        store = self._store()
        self._submit_many(store, 1)
        original = RequestStore._evaluate_inspection_rows

        def patched(meta, events, anchors, requests, gens, secret, history, scope):
            return [""]

        try:
            RequestStore._evaluate_inspection_rows = staticmethod(patched)
            with self.assertRaises(OSError) as caught:
                store.audit_health("tenant-a")
            self.assertEqual(str(caught.exception), "audit_health_failed")
        finally:
            RequestStore._evaluate_inspection_rows = staticmethod(original)
        # The failed read never returned a partial snapshot or wrote.
        snapshot = store.audit_health("tenant-a")
        self.assertEqual(snapshot["verified"], 1)

    def test_non_string_unverified_reason_raises_audit_health_failed(self):
        store = self._store()
        self._submit_many(store, 1)
        original = RequestStore._evaluate_inspection_rows

        def patched(meta, events, anchors, requests, gens, secret, history, scope):
            return [None]

        try:
            RequestStore._evaluate_inspection_rows = staticmethod(patched)
            with self.assertRaises(OSError) as caught:
                store.audit_health("tenant-a")
            self.assertEqual(str(caught.exception), "audit_health_failed")
        finally:
            RequestStore._evaluate_inspection_rows = staticmethod(original)


class HealthConcurrencyTests(_StoreCase):
    def test_concurrent_writes_always_yield_a_consistent_snapshot(self):
        writer = self._store()
        readers = [self._store() for _ in range(4)]
        stop = threading.Event()

        def write_workload():
            local = self._store()
            index = 0
            while not stop.is_set():
                for _ in range(10):
                    rid = local.submit(
                        "tenant-a",
                        f"subject-{threading.get_ident()}-{index}",
                        ["email"],
                        f"key-{threading.get_ident()}-{index}",
                    )["request_id"]
                    if index % 2 == 0:
                        local.transition("tenant-a", rid, "processing")
                    index += 1

        def read_workload():
            seen = []
            local = readers.pop()
            while not stop.is_set():
                snapshot = local.audit_health("tenant-a")
                total = snapshot["total"]
                self.assertEqual(total, sum(snapshot["statuses"].values()))
                self.assertEqual(
                    total, snapshot["verified"] + snapshot["unverified"]
                )
                self.assertEqual(
                    sum(entry["count"] for entry in snapshot["reasons"]),
                    snapshot["unverified"],
                )
                # Anchored writes from secret-holding stores verify.
                self.assertEqual(snapshot["verified"], total)
                self.assertEqual(snapshot["reasons"], [])
                seen.append(total)
            return seen

        with ThreadPoolExecutor(max_workers=5) as pool:
            write_futures = [pool.submit(write_workload) for _ in range(2)]
            read_futures = [pool.submit(read_workload) for _ in range(2)]
            stop.wait(1.0)
            stop.set()
            for future in write_futures:
                future.result()
            totals = []
            for future in read_futures:
                totals.extend(future.result())
        self.assertTrue(totals)
        final = writer.audit_health("tenant-a")
        self._assert_well_formed(final, final["total"])
        self.assertEqual(final["verified"], final["total"])
        self.assertGreaterEqual(final["total"], 10)


class HealthLeakageTests(_StoreCase):
    def test_logs_and_errors_carry_only_counts(self):
        store = self._store(secret="very-secret-material")
        store.submit("tenant-a", "subject-secret", ["scope-secret"], "key-secret")
        with self.assertLogs(_LOGGER_NAME, level="INFO") as logs:
            snapshot = store.audit_health("tenant-a")
        self.assertEqual(snapshot["verified"], 1)
        text = "\n".join(logs.output)
        for secret_fragment in (
            "very-secret-material",
            "subject-secret",
            "scope-secret",
            "key-secret",
            self.db_path,
        ):
            self.assertNotIn(secret_fragment, text)
        # And the fixed error text never embeds the path either.
        with self._raw() as raw:
            raw.execute("DROP TABLE audit_anchor_meta")
        try:
            store.audit_health("tenant-a")
        except OSError as exc:
            self.assertEqual(str(exc), "audit_health_failed")
            self.assertNotIn(self.db_path, str(exc))
        else:
            self.fail("audit_health should have raised")


class HealthHttpSurfaceTests(_StoreCase):
    def _serve(self, store):
        server = build_server(store, "127.0.0.1", 0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server, thread

    def test_no_http_route_or_delegate_is_added(self):
        store = self._store()
        # The deferred HTTP store does not gain the storage-layer entry.
        self.assertFalse(hasattr(httpapi.DeferredRequestStore, "audit_health"))
        server, thread = self._serve(store)
        try:
            conn = http.client.HTTPConnection(
                "127.0.0.1", server.server_address[1], timeout=10
            )
            try:
                for path in ("/audit-health", "/audit-health?tenant_id=tenant-a"):
                    conn.request("GET", path, headers={"X-Tenant-Id": "tenant-a"})
                    response = conn.getresponse()
                    self.assertEqual(response.status, 404)
                    response.read()
            finally:
                conn.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_health_command_is_unchanged(self):
        from forgetting_evidence.__main__ import main

        self.assertEqual(main(["audit-health"]), 2)


if __name__ == "__main__":
    unittest.main()
