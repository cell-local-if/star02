"""Tests for the GET /audit-inspection HTTP endpoint.

The endpoint puts the storage layer's batched audit inspection behind
one tenant-scoped read: without ``cursor``/``batch_id`` a persistent
batch is created, with ``cursor`` the named batch is continued, and
with ``batch_id`` the call is the strictly read-only metrics query.
Covers the fixed single-line JSON shapes and field order (scan:
``batch_id``, ``next_cursor``, ``finished``, ``items`` with
``request_id``, ``verified``, ``reason``; metrics: ``batch_id``,
``scanned``, ``verified``, ``unverified``, ``reasons``,
``next_cursor``, ``finished``), the cursor/batch_id mutual exclusion,
the limit domain, the 400/401/403/404/405/503 error contract and its
ordering, the read-only guarantee of the metrics query, the
single-winner semantics of concurrent same-cursor continuations and
the absence of any subject, scope, idempotency key, worker, token,
secret, SQL or path leakage.
"""

import http.client
import json
import os
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor

from forgetting_evidence.httpapi import (
    AuthConfig,
    DeferredRequestStore,
    build_server,
)
from forgetting_evidence.requests import (
    RequestStore,
    _INSPECTION_CURSOR_PREFIX,
    _encode_cursor,
)

INVALID_REQUEST = b'{"error":"invalid_request"}\n'
UNAUTHORIZED = b'{"error":"unauthorized"}\n'
FORBIDDEN = b'{"error":"forbidden"}\n'
NOT_FOUND = b'{"error":"not_found"}\n'
METHOD_NOT_ALLOWED = b'{"error":"method_not_allowed"}\n'
STORAGE_UNAVAILABLE = b'{"error":"storage_unavailable"}\n'

PATH = "/audit-inspection"
SECRET = "anchor-secret"

READ_A = {"token": "tok-read-a", "tenant_id": "tenant-a",
          "roles": ["request:read"]}
SUBMIT_A = {"token": "tok-submit-a", "tenant_id": "tenant-a",
            "roles": ["request:submit"]}
RECONCILE_A = {"token": "tok-reconcile-a", "tenant_id": "tenant-a",
               "roles": ["request:reconcile"]}
RECONCILE_B = {"token": "tok-reconcile-b", "tenant_id": "tenant-b",
               "roles": ["request:reconcile"]}
POLICY_A = {"token": "tok-policy-a", "tenant_id": "tenant-a",
            "roles": ["policy:read"]}


class _Server:
    def __init__(self, store, auth=None):
        self.server = build_server(store, "127.0.0.1", 0, auth)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def port(self):
        return self.server.server_address[1]

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


class _Base(unittest.TestCase):
    auth = None

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "evidence.db")
        self.store = RequestStore(self.db_path, anchor_secret=SECRET)
        self._fixture = _Server(self.store, self.auth)
        self._fixture.__enter__()
        self.port = self._fixture.port

    def tearDown(self):
        self._fixture.__exit__(None, None, None)
        self._tmp.cleanup()

    def _request(self, method, path, headers=None, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        try:
            conn.request(method, path, headers=headers or {}, body=body)
            resp = conn.getresponse()
            return resp.status, dict(resp.getheaders()), resp.read()
        finally:
            conn.close()

    def _get(self, path=PATH, tenant="tenant-a", headers=None):
        merged = {"X-Tenant-Id": tenant} if tenant is not None else {}
        merged.update(headers or {})
        return self._request("GET", path, headers=merged)

    def _submit_many(self, count, tenant="tenant-a"):
        return [
            self.store.submit(
                tenant, f"subject-{tenant}-{i}", ["email"], f"key-{tenant}-{i}"
            )["request_id"]
            for i in range(count)
        ]

    def _raw(self):
        return sqlite3.connect(self.db_path)

    def _table_dump(self, table):
        with self._raw() as raw:
            return raw.execute(f"SELECT * FROM {table}").fetchall()

    def _assert_scan_shape(self, payload):
        self.assertEqual(
            list(payload), ["batch_id", "next_cursor", "finished", "items"]
        )
        self.assertIsInstance(payload["batch_id"], str)
        self.assertTrue(payload["batch_id"])
        self.assertIsInstance(payload["finished"], bool)
        self.assertIs(payload["finished"], payload["next_cursor"] is None)
        self.assertIsInstance(payload["items"], list)
        for item in payload["items"]:
            self.assertEqual(list(item), ["request_id", "verified", "reason"])
            self.assertIsInstance(item["request_id"], str)
            self.assertIsInstance(item["verified"], bool)
            self.assertIsInstance(item["reason"], str)
            self.assertIs(item["verified"], item["reason"] == "")

    def _assert_metrics_shape(self, payload):
        self.assertEqual(
            list(payload),
            [
                "batch_id",
                "scanned",
                "verified",
                "unverified",
                "reasons",
                "next_cursor",
                "finished",
            ],
        )
        for name in ("scanned", "verified", "unverified"):
            self.assertIsInstance(payload[name], int)
            self.assertNotIsInstance(payload[name], bool)
            self.assertGreaterEqual(payload[name], 0)
        self.assertEqual(
            payload["scanned"], payload["verified"] + payload["unverified"]
        )
        self.assertIsInstance(payload["finished"], bool)
        self.assertIs(payload["finished"], payload["next_cursor"] is None)
        merged = 0
        previous = None
        for entry in payload["reasons"]:
            self.assertEqual(list(entry), ["reason", "count"])
            self.assertIsInstance(entry["reason"], str)
            self.assertTrue(entry["reason"])
            self.assertIsInstance(entry["count"], int)
            self.assertGreater(entry["count"], 0)
            if previous is not None:
                self.assertLess(previous, entry["reason"])
            previous = entry["reason"]
            merged += entry["count"]
        self.assertEqual(merged, payload["unverified"])


class InspectionScanTests(_Base):
    def test_empty_tenant_finishes_with_no_items(self):
        status, headers, body = self._get()
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertTrue(body.endswith(b"\n"))
        self.assertEqual(body.count(b"\n"), 1)
        self.assertNotIn(b" ", body)
        payload = json.loads(body)
        self._assert_scan_shape(payload)
        self.assertIsNone(payload["next_cursor"])
        self.assertIs(payload["finished"], True)
        self.assertEqual(payload["items"], [])

    def test_healthy_requests_verify_with_empty_reason(self):
        request_ids = self._submit_many(3)
        status, _, body = self._get()
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self._assert_scan_shape(payload)
        self.assertIs(payload["finished"], True)
        self.assertEqual(
            [item["request_id"] for item in payload["items"]], request_ids
        )
        for item in payload["items"]:
            self.assertIs(item["verified"], True)
            self.assertEqual(item["reason"], "")

    def test_tampered_request_reports_stable_reason(self):
        request_ids = self._submit_many(2)
        with self._raw() as raw:
            raw.execute(
                "UPDATE requests SET chain_hash = ? WHERE request_id = ?",
                ("0" * 64, request_ids[0]),
            )
        status, _, body = self._get()
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self._assert_scan_shape(payload)
        by_id = {item["request_id"]: item for item in payload["items"]}
        self.assertIs(by_id[request_ids[0]]["verified"], False)
        self.assertEqual(
            by_id[request_ids[0]]["reason"], "chain_head_mismatch"
        )
        self.assertIs(by_id[request_ids[1]]["verified"], True)

    def test_other_tenants_are_not_scanned(self):
        own = self._submit_many(2, tenant="tenant-a")
        self._submit_many(3, tenant="tenant-b")
        status, _, body = self._get()
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertEqual(
            [item["request_id"] for item in payload["items"]], own
        )

    def test_limit_paginates_and_cursor_resumes_same_batch(self):
        request_ids = self._submit_many(3)
        status, _, body = self._get(PATH + "?limit=2")
        self.assertEqual(status, 200)
        first = json.loads(body)
        self._assert_scan_shape(first)
        self.assertIs(first["finished"], False)
        self.assertEqual(len(first["items"]), 2)
        self.assertTrue(
            first["next_cursor"].startswith(_INSPECTION_CURSOR_PREFIX)
        )
        status, _, body = self._get(
            PATH + "?cursor=" + first["next_cursor"]
        )
        self.assertEqual(status, 200)
        second = json.loads(body)
        self._assert_scan_shape(second)
        self.assertEqual(second["batch_id"], first["batch_id"])
        self.assertIs(second["finished"], True)
        self.assertIsNone(second["next_cursor"])
        self.assertEqual(len(second["items"]), 1)
        seen = [
            item["request_id"]
            for item in first["items"] + second["items"]
        ]
        self.assertEqual(seen, request_ids)

    def test_default_limit_is_one_hundred(self):
        self._submit_many(101)
        status, _, body = self._get()
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertIs(payload["finished"], False)
        self.assertEqual(len(payload["items"]), 100)

    def test_limit_and_cursor_combine(self):
        self._submit_many(4)
        first = json.loads(self._get(PATH + "?limit=1")[2])
        second = json.loads(
            self._get(PATH + "?cursor=" + first["next_cursor"] + "&limit=2")[2]
        )
        self.assertEqual(second["batch_id"], first["batch_id"])
        self.assertEqual(len(second["items"]), 2)
        self.assertIs(second["finished"], False)

    def test_replayed_cursor_reports_nothing_twice(self):
        self._submit_many(3)
        first = json.loads(self._get(PATH + "?limit=2")[2])
        cursor = first["next_cursor"]
        second = json.loads(self._get(PATH + "?cursor=" + cursor)[2])
        self.assertEqual(len(second["items"]), 1)
        self.assertIs(second["finished"], True)
        replay = json.loads(self._get(PATH + "?cursor=" + cursor)[2])
        self.assertEqual(replay["batch_id"], first["batch_id"])
        self.assertEqual(replay["items"], [])
        self.assertIsNone(replay["next_cursor"])
        self.assertIs(replay["finished"], True)

    def test_scan_creates_one_batch_per_call_without_cursor(self):
        self._submit_many(2)
        first = json.loads(self._get()[2])
        second = json.loads(self._get()[2])
        self.assertNotEqual(first["batch_id"], second["batch_id"])

    def test_concurrent_same_cursor_has_one_winning_page(self):
        self._submit_many(5)
        first = json.loads(self._get(PATH + "?limit=2")[2])
        stale = first["next_cursor"]
        barrier = threading.Barrier(6)

        def continue_once():
            barrier.wait()
            return json.loads(
                self._get(PATH + "?cursor=" + stale + "&limit=2")[2]
            )

        with ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(lambda _: continue_once(), range(6)))
        winning = [result for result in results if result["items"]]
        self.assertEqual(len(winning), 1)
        winner = winning[0]
        for result in results:
            self.assertEqual(result["batch_id"], first["batch_id"])
            self.assertEqual(result["next_cursor"], winner["next_cursor"])
            self.assertIs(result["finished"], False)
        with self._raw() as raw:
            count = raw.execute(
                "SELECT count(*) FROM inspection_batch_items WHERE batch_id = ?",
                (first["batch_id"],),
            ).fetchone()[0]
        self.assertEqual(count, 4)

    def test_scan_never_modifies_business_or_audit_records(self):
        request_ids = self._submit_many(3)
        self.store.transition("tenant-a", request_ids[0], "processing")
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
        status, _, _ = self._get()
        self.assertEqual(status, 200)
        after = {table: self._table_dump(table) for table in tables}
        self.assertEqual(before, after)

    def test_body_never_leaks_subject_scope_key_or_secret(self):
        self.store.submit(
            "tenant-a", "subject-SECRETXYZ", ["scope-SECRETXYZ"], "key-SECRETXYZ"
        )
        _, _, body = self._get()
        for leaked in (b"SECRETXYZ", SECRET.encode(), self.db_path.encode()):
            self.assertNotIn(leaked, body)


class InspectionMetricsTests(_Base):
    def _scan(self, query=""):
        status, _, body = self._get(PATH + query)
        self.assertEqual(status, 200)
        return json.loads(body)

    def _metrics(self, batch_id, tenant="tenant-a"):
        return self._get(PATH + "?batch_id=" + batch_id, tenant=tenant)

    def test_metrics_of_finished_batch(self):
        self._submit_many(3)
        scan = self._scan()
        status, _, body = self._metrics(scan["batch_id"])
        self.assertEqual(status, 200)
        self.assertTrue(body.endswith(b"\n"))
        self.assertEqual(body.count(b"\n"), 1)
        self.assertNotIn(b" ", body)
        payload = json.loads(body)
        self._assert_metrics_shape(payload)
        self.assertEqual(payload["batch_id"], scan["batch_id"])
        self.assertEqual(payload["scanned"], 3)
        self.assertEqual(payload["verified"], 3)
        self.assertEqual(payload["unverified"], 0)
        self.assertEqual(payload["reasons"], [])
        self.assertIsNone(payload["next_cursor"])
        self.assertIs(payload["finished"], True)

    def test_metrics_aggregates_reasons_merged_and_sorted(self):
        request_ids = self._submit_many(4)
        with self._raw() as raw:
            raw.execute(
                "UPDATE requests SET chain_hash = ? WHERE request_id = ?",
                ("0" * 64, request_ids[0]),
            )
            raw.execute(
                "UPDATE requests SET chain_hash = ? WHERE request_id = ?",
                ("0" * 64, request_ids[1]),
            )
            raw.execute(
                "UPDATE status_events SET status = 'failed' "
                "WHERE request_id = ? AND seq = 0",
                (request_ids[2],),
            )
        scan = self._scan()
        status, _, body = self._metrics(scan["batch_id"])
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self._assert_metrics_shape(payload)
        self.assertEqual(payload["scanned"], 4)
        self.assertEqual(payload["verified"], 1)
        self.assertEqual(payload["unverified"], 3)
        reasons = payload["reasons"]
        self.assertEqual(
            [entry["reason"] for entry in reasons],
            sorted(entry["reason"] for entry in reasons),
        )
        by_reason = {entry["reason"]: entry["count"] for entry in reasons}
        self.assertEqual(by_reason["chain_head_mismatch"], 2)
        self.assertEqual(sum(by_reason.values()), 3)

    def test_metrics_of_partial_batch_carries_resumable_cursor(self):
        self._submit_many(4)
        scan = self._scan("?limit=3")
        status, _, body = self._metrics(scan["batch_id"])
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self._assert_metrics_shape(payload)
        self.assertEqual(payload["scanned"], 3)
        self.assertIs(payload["finished"], False)
        self.assertEqual(payload["next_cursor"], scan["next_cursor"])
        # The metrics' cursor resumes the very same batch.
        tail = json.loads(
            self._get(PATH + "?cursor=" + payload["next_cursor"])[2]
        )
        self.assertEqual(tail["batch_id"], scan["batch_id"])
        self.assertEqual(len(tail["items"]), 1)
        self.assertIs(tail["finished"], True)

    def test_metrics_is_strictly_read_only(self):
        self._submit_many(3)
        scan = self._scan("?limit=2")
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
        self._metrics(scan["batch_id"])
        self._metrics(scan["batch_id"])
        after = {table: self._table_dump(table) for table in tables}
        self.assertEqual(before, after)
        # The batch is still mid-sweep, exactly as the metrics reported.
        tail = json.loads(self._get(PATH + "?cursor=" + scan["next_cursor"])[2])
        self.assertEqual(len(tail["items"]), 1)
        self.assertIs(tail["finished"], True)

    def test_metrics_accepts_limit_and_ignores_it(self):
        self._submit_many(2)
        scan = self._scan()
        status, _, body = self._get(
            PATH + "?batch_id=" + scan["batch_id"] + "&limit=5"
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["scanned"], 2)

    def test_metrics_of_unknown_batch_is_404(self):
        self._submit_many(1)
        status, _, body = self._metrics("no-such-batch")
        self.assertEqual(status, 404)
        self.assertEqual(body, NOT_FOUND)

    def test_metrics_of_cross_tenant_batch_is_404(self):
        self._submit_many(1, tenant="tenant-a")
        scan = self._scan()
        status, _, body = self._metrics(scan["batch_id"], tenant="tenant-b")
        self.assertEqual(status, 404)
        self.assertEqual(body, NOT_FOUND)

    def test_metrics_treats_cursor_text_as_plain_batch_id(self):
        self._submit_many(2)
        scan = self._scan("?limit=1")
        status, _, body = self._metrics(scan["next_cursor"])
        self.assertEqual(status, 404)
        self.assertEqual(body, NOT_FOUND)

    def test_metrics_body_never_leaks_subject_scope_key_or_secret(self):
        self.store.submit(
            "tenant-a", "subject-SECRETXYZ", ["scope-SECRETXYZ"], "key-SECRETXYZ"
        )
        scan = self._scan()
        _, _, body = self._metrics(scan["batch_id"])
        for leaked in (b"SECRETXYZ", SECRET.encode(), self.db_path.encode()):
            self.assertNotIn(leaked, body)


class InspectionValidationTests(_Base):
    def test_cursor_and_batch_id_are_mutually_exclusive(self):
        self._submit_many(2)
        scan = json.loads(self._get(PATH + "?limit=1")[2])
        query = (
            PATH + "?cursor=" + scan["next_cursor"]
            + "&batch_id=" + scan["batch_id"]
        )
        status, _, body = self._get(query)
        self.assertEqual(status, 400)
        self.assertEqual(body, INVALID_REQUEST)

    def test_unknown_query_parameter_is_400(self):
        for query in ("?unknown=1", "?status=accepted", "?batch=no"):
            status, _, body = self._get(PATH + query)
            self.assertEqual(status, 400, query)
            self.assertEqual(body, INVALID_REQUEST)

    def test_duplicate_query_key_is_400(self):
        for query in (
            "?limit=1&limit=2",
            "?cursor=a&cursor=b",
            "?batch_id=a&batch_id=b",
            "?tenant_id=tenant-a&tenant_id=tenant-a",
        ):
            status, _, body = self._get(PATH + query)
            self.assertEqual(status, 400, query)
            self.assertEqual(body, INVALID_REQUEST)

    def test_invalid_limit_is_400(self):
        for value in ("0", "1001", "-1", "1.5", "abc", "true", "", "1" * 11):
            status, _, body = self._get(PATH + "?limit=" + value)
            self.assertEqual(status, 400, value)
            self.assertEqual(body, INVALID_REQUEST)

    def test_empty_cursor_or_batch_id_is_400(self):
        for query in ("?cursor=", "?batch_id="):
            status, _, body = self._get(PATH + query)
            self.assertEqual(status, 400, query)
            self.assertEqual(body, INVALID_REQUEST)

    def test_malformed_cursor_is_400(self):
        for value in ("nonsense", "ai1.!!!", "rc1." + "A" * 8):
            status, _, body = self._get(PATH + "?cursor=" + value)
            self.assertEqual(status, 400, value)
            self.assertEqual(body, INVALID_REQUEST)

    def test_unknown_batch_cursor_is_400(self):
        self._submit_many(1)
        cursor = _encode_cursor("no-such-batch", 0, _INSPECTION_CURSOR_PREFIX)
        status, _, body = self._get(PATH + "?cursor=" + cursor)
        self.assertEqual(status, 400)
        self.assertEqual(body, INVALID_REQUEST)

    def test_cross_tenant_cursor_is_400(self):
        self._submit_many(2, tenant="tenant-a")
        scan = json.loads(self._get(PATH + "?limit=1")[2])
        status, _, body = self._get(
            PATH + "?cursor=" + scan["next_cursor"], tenant="tenant-b"
        )
        self.assertEqual(status, 400)
        self.assertEqual(body, INVALID_REQUEST)

    def test_missing_tenant_is_400(self):
        status, _, body = self._get(tenant=None)
        self.assertEqual(status, 400)
        self.assertEqual(body, INVALID_REQUEST)

    def test_tenant_via_query_parameter(self):
        self._submit_many(1)
        status, _, body = self._get(PATH + "?tenant_id=tenant-a", tenant=None)
        self.assertEqual(status, 200)
        self.assertEqual(len(json.loads(body)["items"]), 1)

    def test_rejected_calls_write_nothing(self):
        self._submit_many(1)
        before = {
            table: self._table_dump(table)
            for table in ("inspection_batches", "inspection_batch_items")
        }
        for query in (
            "?limit=0",
            "?cursor=nonsense",
            "?batch_id=",
            "?cursor=a&batch_id=b",
            "?unknown=1",
        ):
            self._get(PATH + query)
        after = {
            table: self._table_dump(table)
            for table in ("inspection_batches", "inspection_batch_items")
        }
        self.assertEqual(before, after)


class InspectionRoutingTests(_Base):
    def test_non_get_methods_are_405_with_allow_get(self):
        for method in ("POST", "PUT", "DELETE", "PATCH", "OPTIONS"):
            status, headers, body = self._request(method, PATH)
            self.assertEqual(status, 405, method)
            self.assertEqual(headers.get("Allow"), "GET")
            self.assertEqual(body, METHOD_NOT_ALLOWED)

    def test_head_is_405_headless_with_allow_get(self):
        status, headers, body = self._request("HEAD", PATH)
        self.assertEqual(status, 405)
        self.assertEqual(headers.get("Allow"), "GET")
        self.assertEqual(body, b"")

    def test_unknown_neighbour_paths_are_404(self):
        for path in (
            "/audit-inspection/",
            "/audit-inspections",
            "/audit-inspection/extra",
        ):
            status, _, body = self._get(path)
            self.assertEqual(status, 404, path)
            self.assertEqual(body, NOT_FOUND)


class InspectionStorageFailureTests(_Base):
    def test_corrupt_batch_state_is_503(self):
        self._submit_many(2)
        scan = json.loads(self._get(PATH + "?limit=1")[2])
        with self._raw() as raw:
            raw.execute(
                "UPDATE inspection_batches SET finished = 7 WHERE batch_id = ?",
                (scan["batch_id"],),
            )
        status, _, body = self._get(PATH + "?cursor=" + scan["next_cursor"])
        self.assertEqual(status, 503)
        self.assertEqual(body, STORAGE_UNAVAILABLE)

    def test_corrupt_metrics_bookkeeping_is_503(self):
        self._submit_many(2)
        scan = json.loads(self._get(PATH + "?limit=1")[2])
        with self._raw() as raw:
            raw.execute(
                "UPDATE inspection_batch_items SET verified = 9 "
                "WHERE batch_id = ?",
                (scan["batch_id"],),
            )
        status, _, body = self._get(PATH + "?batch_id=" + scan["batch_id"])
        self.assertEqual(status, 503)
        self.assertEqual(body, STORAGE_UNAVAILABLE)

    def test_dropped_bookkeeping_table_is_503(self):
        self._submit_many(1)
        scan = json.loads(self._get()[2])
        with self._raw() as raw:
            raw.execute("DROP TABLE inspection_batches")
        status, _, body = self._get(PATH + "?batch_id=" + scan["batch_id"])
        self.assertEqual(status, 503)
        self.assertEqual(body, STORAGE_UNAVAILABLE)

    def test_error_body_never_leaks_path_or_sql(self):
        self._submit_many(1)
        scan = json.loads(self._get()[2])
        with self._raw() as raw:
            raw.execute("DROP TABLE inspection_batches")
        _, _, body = self._get(PATH + "?batch_id=" + scan["batch_id"])
        self.assertNotIn(self.db_path.encode(), body)
        self.assertNotIn(b"inspection_batches", body)
        self.assertNotIn(b"SELECT", body)


class InspectionAuthTests(_Base):
    auth = AuthConfig([READ_A, SUBMIT_A, RECONCILE_A, RECONCILE_B, POLICY_A])

    def _auth_get(self, token, path=PATH, tenant="tenant-a"):
        headers = {}
        if tenant is not None:
            headers["X-Tenant-Id"] = tenant
        if token is not None:
            headers["Authorization"] = token
        return self._request("GET", path, headers=headers)

    def test_missing_malformed_or_unknown_token_is_401(self):
        for header in (
            None,
            "tok-reconcile-a",
            "Bearer",
            "Bearer ",
            "Basic tok-reconcile-a",
            "bearer tok-reconcile-a",
            "Bearer unknown-token",
        ):
            status, _, body = self._auth_get(header)
            self.assertEqual(status, 401, header)
            self.assertEqual(body, UNAUTHORIZED)

    def test_wrong_role_is_403(self):
        for token in ("tok-read-a", "tok-submit-a", "tok-policy-a"):
            status, _, body = self._auth_get(f"Bearer {token}")
            self.assertEqual(status, 403, token)
            self.assertEqual(body, FORBIDDEN)

    def test_reconcile_role_scans_own_tenant(self):
        self._submit_many(2)
        status, _, body = self._auth_get("Bearer tok-reconcile-a")
        self.assertEqual(status, 200)
        self.assertEqual(len(json.loads(body)["items"]), 2)

    def test_reconcile_role_reads_metrics_of_own_tenant(self):
        self._submit_many(1)
        scan = json.loads(self._auth_get("Bearer tok-reconcile-a")[2])
        status, _, body = self._auth_get(
            "Bearer tok-reconcile-a",
            PATH + "?batch_id=" + scan["batch_id"],
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["scanned"], 1)

    def test_cross_tenant_is_403(self):
        self._submit_many(1, tenant="tenant-b")
        status, _, body = self._auth_get(
            "Bearer tok-reconcile-a", tenant="tenant-b"
        )
        self.assertEqual(status, 403)
        self.assertEqual(body, FORBIDDEN)

    def test_other_tenant_principal_scans_own_tenant(self):
        self._submit_many(2, tenant="tenant-b")
        status, _, body = self._auth_get(
            "Bearer tok-reconcile-b", tenant="tenant-b"
        )
        self.assertEqual(status, 200)
        self.assertEqual(len(json.loads(body)["items"]), 2)

    def test_method_check_precedes_authentication(self):
        status, _, body = self._request("POST", PATH)
        self.assertEqual(status, 405)
        self.assertEqual(body, METHOD_NOT_ALLOWED)

    def test_unknown_path_stays_404_without_token(self):
        status, _, body = self._request("GET", "/no-such-path")
        self.assertEqual(status, 404)
        self.assertEqual(body, NOT_FOUND)

    def test_error_bodies_never_echo_token(self):
        for token in ("tok-reconcile-a", "tok-read-a"):
            _, _, body = self._auth_get(f"Bearer {token}", tenant="tenant-b")
            self.assertNotIn(token.encode(), body)


class InspectionUnauthenticatedTests(_Base):
    def test_authorization_header_is_ignored_without_auth_config(self):
        self._submit_many(1)
        status, _, body = self._get(
            headers={"Authorization": "Bearer anything"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(len(json.loads(body)["items"]), 1)


class InspectionDeferredStoreTests(_Base):
    def test_endpoint_works_through_the_deferred_store(self):
        # The production wiring wraps the store in DeferredRequestStore;
        # the endpoint must serve both the scan and the metrics query
        # through it.
        self._fixture.__exit__(None, None, None)
        deferred = DeferredRequestStore(self.db_path)
        self._fixture = _Server(deferred, self.auth)
        self._fixture.__enter__()
        self.port = self._fixture.port
        self._submit_many(2)
        scan = json.loads(self._get()[2])
        self.assertEqual(len(scan["items"]), 2)
        status, _, body = self._get(PATH + "?batch_id=" + scan["batch_id"])
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["scanned"], 2)


if __name__ == "__main__":
    unittest.main()
