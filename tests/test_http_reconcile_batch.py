"""HTTP tests for the batched reconciliation endpoint.

Covers ``POST /reconcile`` only: the empty-body rule, the
tenant/cursor/limit query contract, the four-field batch response,
resumable sweep semantics observed through HTTP (accepted rows only
advance the position, live leases stay processing, expired leases are
compensated to failed, terminal rows are untouched), routing/method
rules (Allow: POST, deeper paths 404), tenant and parameter error
ordering, storage error mapping, bearer/RBAC behaviour for the
``request:reconcile`` role and the no-leak guarantees.
"""

import http.client
import json
import os
import sqlite3
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor

from forgetting_evidence.httpapi import (
    AuthConfig,
    DeferredRequestStore,
    build_server,
)
from forgetting_evidence.requests import RequestStore

NOT_FOUND = b'{"error":"not_found"}\n'
INVALID_REQUEST = b'{"error":"invalid_request"}\n'
METHOD_NOT_ALLOWED = b'{"error":"method_not_allowed"}\n'
STORAGE_UNAVAILABLE = b'{"error":"storage_unavailable"}\n'
UNAUTHORIZED = b'{"error":"unauthorized"}\n'
FORBIDDEN = b'{"error":"forbidden"}\n'

RECONCILE_A = {
    "token": "tok-reconcile-a",
    "tenant_id": "tenant-a",
    "roles": ["request:reconcile"],
}
READ_A = {
    "token": "tok-read-a",
    "tenant_id": "tenant-a",
    "roles": ["request:read"],
}
SUBMIT_A = {
    "token": "tok-submit-a",
    "tenant_id": "tenant-a",
    "roles": ["request:submit"],
}
RECONCILE_B = {
    "token": "tok-reconcile-b",
    "tenant_id": "tenant-b",
    "roles": ["request:reconcile"],
}


class _Server:
    def __init__(self, store, auth=None, host="127.0.0.1", port=0):
        self.server = build_server(store, host, port, auth)
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


class _StoreCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "evidence.db")
        self.store = RequestStore(self.db_path)
        self._fixture = _Server(self.store)
        self._fixture.__enter__()
        self.port = self._fixture.port

    def tearDown(self):
        self._fixture.__exit__(None, None, None)
        self._tmp.cleanup()

    def _request(self, method, path, raw_body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            kwargs = {}
            if raw_body is not None:
                kwargs["body"] = raw_body
            conn.request(method, path, headers=headers or {}, **kwargs)
            resp = conn.getresponse()
            return resp.status, dict(resp.getheaders()), resp.read()
        finally:
            conn.close()

    def _submit(self, tenant="tenant-a", key="key-1"):
        return self.store.submit(tenant, "subject-1", ["email"], key)

    def _reconcile(self, query="", tenant="tenant-a", raw_body=None, headers=None):
        extra = dict(headers or {})
        if tenant is not None:
            extra["X-Tenant-Id"] = tenant
        return self._request("POST", f"/reconcile{query}", raw_body=raw_body, headers=extra)

    def _batch(self, query="", tenant="tenant-a"):
        status, _, data = self._reconcile(query, tenant=tenant)
        self.assertEqual(status, 200, data)
        return json.loads(data)


class BatchReconcileSuccessTests(_StoreCase):
    def test_empty_pipeline_finishes_immediately_with_empty_items(self):
        status, headers, data = self._reconcile()
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("Content-Type"), "application/json")
        self.assertTrue(data.endswith(b"\n"))
        self.assertEqual(data.count(b"\n"), 1)
        payload = json.loads(data)
        self.assertEqual(
            list(payload), ["batch_id", "next_cursor", "finished", "items"]
        )
        self.assertIsInstance(payload["batch_id"], str)
        self.assertTrue(payload["batch_id"])
        self.assertIsNone(payload["next_cursor"])
        self.assertIs(payload["finished"], True)
        self.assertEqual(payload["items"], [])

    def test_accepted_requests_only_advance_the_position(self):
        first = self._submit(key="key-1")
        second = self._submit(key="key-2")
        payload = self._batch()
        self.assertIs(payload["finished"], True)
        self.assertIsNone(payload["next_cursor"])
        self.assertEqual(payload["items"], [])
        # No attempt, receipt or status event was produced for either.
        for receipt in (first, second):
            rid = receipt["request_id"]
            self.assertEqual(self.store.get_execution_log("tenant-a", rid), [])
            self.assertEqual(
                self.store.get_status("tenant-a", rid)["status"], "accepted"
            )
            self.assertEqual(
                [e["status"] for e in self.store.audit("tenant-a", rid)],
                ["accepted"],
            )
        with sqlite3.connect(self.db_path) as raw:
            self.assertEqual(
                raw.execute("SELECT count(*) FROM claim_attempts").fetchone()[0],
                0,
            )

    def test_live_lease_stays_processing_and_is_listed(self):
        receipt = self._submit()
        rid = receipt["request_id"]
        claim = self.store.claim_next("tenant-a", "worker-1", 3600)
        payload = self._batch()
        self.assertIs(payload["finished"], True)
        self.assertEqual(payload["items"], [{"request_id": rid, "status": "processing"}])
        self.assertEqual(
            self.store.get_status("tenant-a", rid)["status"], "processing"
        )
        # The live lease is untouched: the credential still finishes it.
        done = self.store.finish_claim(
            "tenant-a", rid, claim["claim_token"], "completed"
        )
        self.assertEqual(done["status"], "completed")

    def test_expired_lease_is_compensated_to_failed(self):
        receipt = self._submit()
        rid = receipt["request_id"]
        self.store.claim_next("tenant-a", "worker-1", 1)
        time.sleep(1.15)
        payload = self._batch()
        self.assertEqual(payload["items"], [{"request_id": rid, "status": "failed"}])
        self.assertEqual(
            self.store.get_status("tenant-a", rid)["status"], "failed"
        )
        log = self.store.get_execution_log("tenant-a", rid)
        self.assertEqual(len(log), 1)
        self.assertEqual(log[0]["result"], "failed")
        # The lease was released: the request is no longer claimable and
        # the compensation is anchored in the audit chain.
        self.assertIsNone(self.store.claim_next("tenant-a", "worker-2", 60))
        self.assertEqual(
            [e["status"] for e in self.store.audit("tenant-a", rid)],
            ["accepted", "processing", "failed"],
        )

    def test_terminal_requests_are_not_candidates(self):
        done_receipt = self._submit(key="key-1")
        claim = self.store.claim_next("tenant-a", "worker-1", 60)
        self.store.finish_claim(
            "tenant-a", done_receipt["request_id"], claim["claim_token"], "completed"
        )
        failed_receipt = self._submit(key="key-2")
        claim = self.store.claim_next("tenant-a", "worker-1", 1)
        time.sleep(1.15)
        # Single-request reconcile settles the failed one beforehand.
        self.store.reconcile_execution("tenant-a", failed_receipt["request_id"])
        payload = self._batch()
        self.assertIs(payload["finished"], True)
        self.assertEqual(payload["items"], [])
        self.assertEqual(
            self.store.get_status("tenant-a", done_receipt["request_id"])["status"],
            "completed",
        )
        self.assertEqual(
            self.store.get_status("tenant-a", failed_receipt["request_id"])["status"],
            "failed",
        )

    def test_items_follow_acceptance_order_and_carry_no_extra_fields(self):
        receipts = [self._submit(key=f"key-{i}") for i in range(3)]
        for _ in receipts:
            self.store.claim_next("tenant-a", "worker-1", 1)
        time.sleep(1.15)
        status, _, data = self._reconcile()
        self.assertEqual(status, 200)
        payload = json.loads(data)
        self.assertEqual(
            payload["items"],
            [
                {"request_id": receipt["request_id"], "status": "failed"}
                for receipt in receipts
            ],
        )
        for item in payload["items"]:
            self.assertEqual(list(item), ["request_id", "status"])
        # No subject, scope, idempotency key or worker identity leaks.
        self.assertNotIn(b"subject-1", data)
        self.assertNotIn(b"email", data)
        self.assertNotIn(b"key-", data)
        self.assertNotIn(b"worker", data)

    def test_limit_truncates_and_cursor_resumes_the_same_batch(self):
        receipts = [self._submit(key=f"key-{i}") for i in range(3)]
        for _ in receipts:
            self.store.claim_next("tenant-a", "worker-1", 1)
        time.sleep(1.15)
        first = self._batch("?limit=2")
        self.assertIs(first["finished"], False)
        self.assertIsInstance(first["next_cursor"], str)
        self.assertEqual(len(first["items"]), 2)
        second = self._batch(f"?cursor={first['next_cursor']}")
        self.assertEqual(second["batch_id"], first["batch_id"])
        self.assertIs(second["finished"], True)
        self.assertIsNone(second["next_cursor"])
        self.assertEqual(len(second["items"]), 1)
        # The two pages cover every request exactly once, in order.
        seen = first["items"] + second["items"]
        self.assertEqual(
            [item["request_id"] for item in seen],
            [receipt["request_id"] for receipt in receipts],
        )

    def test_accepted_rows_do_not_consume_the_limit(self):
        receipts = [self._submit(key=f"key-{i}") for i in range(3)]
        # Only the oldest is claimed into processing; the other two stay
        # accepted and merely advance the scan position.
        self.store.claim_next("tenant-a", "worker-1", 1)
        time.sleep(1.15)
        first = self._batch("?limit=1")
        self.assertEqual(
            first["items"],
            [{"request_id": receipts[0]["request_id"], "status": "failed"}],
        )
        # The two accepted rows remain candidates, so the sweep is not
        # finished even though the single-item limit was reached.
        self.assertIs(first["finished"], False)
        second = self._batch(f"?cursor={first['next_cursor']}")
        self.assertEqual(second["batch_id"], first["batch_id"])
        self.assertIs(second["finished"], True)
        self.assertEqual(second["items"], [])
        # The accepted rows were never touched: no attempt, no event.
        for receipt in receipts[1:]:
            rid = receipt["request_id"]
            self.assertEqual(
                self.store.get_status("tenant-a", rid)["status"], "accepted"
            )
            self.assertEqual(self.store.get_execution_log("tenant-a", rid), [])

    def test_retrying_a_cursor_never_rewrites_committed_items(self):
        receipts = [self._submit(key=f"key-{i}") for i in range(2)]
        for _ in receipts:
            self.store.claim_next("tenant-a", "worker-1", 1)
        time.sleep(1.15)
        first = self._batch("?limit=1")
        self.assertEqual(len(first["items"]), 1)
        with sqlite3.connect(self.db_path) as raw:
            committed = raw.execute(
                "SELECT count(*) FROM reconcile_batch_items WHERE batch_id = ?",
                (first["batch_id"],),
            ).fetchone()[0]
        # Re-driving the same cursor resumes from the durable position
        # instead of rewriting the already committed item.
        replay = self._batch(f"?cursor={first['next_cursor']}")
        self.assertEqual(replay["batch_id"], first["batch_id"])
        with sqlite3.connect(self.db_path) as raw:
            rows = raw.execute(
                "SELECT request_id, status FROM reconcile_batch_items "
                "WHERE batch_id = ? ORDER BY seq",
                (first["batch_id"],),
            ).fetchall()
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0][0], first["items"][0]["request_id"])
        self.assertEqual(
            [row[0] for row in rows],
            [receipt["request_id"] for receipt in receipts],
        )
        self.assertGreaterEqual(committed, 1)

    def test_default_limit_is_one_hundred(self):
        for i in range(5):
            self._submit(key=f"key-{i}")
        # No limit parameter: the whole small pipeline converges at once.
        payload = self._batch()
        self.assertIs(payload["finished"], True)
        self.assertEqual(payload["items"], [])

    def test_tenant_query_parameter_and_header_precedence(self):
        self._submit(tenant="tenant-b", key="key-b")
        # Query-only tenant resolution works.
        status, _, data = self._request("POST", "/reconcile?tenant_id=tenant-b")
        self.assertEqual(status, 200)
        self.assertIs(json.loads(data)["finished"], True)
        # The header wins over a conflicting query tenant.
        status, _, data = self._reconcile("?tenant_id=tenant-b", tenant="tenant-a")
        self.assertEqual(status, 200)
        # tenant-b's accepted request was not swept by tenant-a's batch.
        self.assertEqual(
            self.store.get_status(
                "tenant-b", self.store.submit("tenant-b", "s", ["email"], "key-c")["request_id"]
            )["status"],
            "accepted",
        )

    def test_tenants_are_swept_independently(self):
        self._submit(tenant="tenant-a", key="key-a")
        self.store.claim_next("tenant-a", "worker-1", 1)
        self._submit(tenant="tenant-b", key="key-b")
        self.store.claim_next("tenant-b", "worker-1", 1)
        time.sleep(1.15)
        payload_a = self._batch(tenant="tenant-a")
        self.assertEqual(len(payload_a["items"]), 1)
        # tenant-b's processing request is untouched by tenant-a's batch.
        payload_b = self._batch(tenant="tenant-b")
        self.assertEqual(len(payload_b["items"]), 1)
        self.assertNotEqual(payload_a["batch_id"], payload_b["batch_id"])


class BatchReconcileValidationTests(_StoreCase):
    def test_unknown_or_duplicate_query_parameter_is_400(self):
        for query in (
            "?foo=1",
            "?status=accepted",
            "?batch_id=x",
            "?limit=1&limit=2",
            "?cursor=a&cursor=b",
            "?tenant_id=tenant-a&tenant_id=tenant-a",
            "?limit=1&foo=1",
        ):
            with self.subTest(query=query):
                status, _, data = self._reconcile(query)
                self.assertEqual(status, 400)
                self.assertEqual(data, INVALID_REQUEST)

    def test_invalid_limit_is_400(self):
        for value in ("0", "1001", "-1", "abc", "", "1.5", "%201", "1%20", "99999999999"):
            with self.subTest(limit=value):
                status, _, data = self._reconcile(f"?limit={value}")
                self.assertEqual(status, 400)
                self.assertEqual(data, INVALID_REQUEST)

    def test_valid_limit_bounds_are_accepted(self):
        for value in ("1", "100", "1000"):
            with self.subTest(limit=value):
                status, _, data = self._reconcile(f"?limit={value}")
                self.assertEqual(status, 200)
                self.assertIs(json.loads(data)["finished"], True)

    def test_missing_or_empty_tenant_is_400(self):
        for headers in ({}, {"X-Tenant-Id": ""}, {"X-Tenant-Id": "   "}):
            with self.subTest(headers=headers):
                status, _, data = self._request("POST", "/reconcile", headers=headers)
                self.assertEqual(status, 400)
                self.assertEqual(data, INVALID_REQUEST)
        status, _, data = self._request("POST", "/reconcile?tenant_id=")
        self.assertEqual(status, 400)
        self.assertEqual(data, INVALID_REQUEST)

    def test_non_empty_body_is_400(self):
        for body in (b"{}", b"x", b"[]", b"\x00" * 16):
            with self.subTest(body=body):
                status, _, data = self._reconcile(raw_body=body)
                self.assertEqual(status, 400)
                self.assertEqual(data, INVALID_REQUEST)

    def test_malformed_unknown_and_cross_tenant_cursor_is_400(self):
        # Drive a batch into a resumable (unfinished) state first.
        self._submit(key="key-1")
        self._submit(key="key-2")
        self.store.claim_next("tenant-a", "worker-1", 1)
        self.store.claim_next("tenant-a", "worker-1", 1)
        time.sleep(1.15)
        pending = self._batch("?limit=1", tenant="tenant-a")
        self.assertIs(pending["finished"], False)
        cursors = [
            "",
            "bogus",
            "rc1.",
            "rc1.!!!",
            "ai1." + pending["next_cursor"][4:],
            "em1." + pending["next_cursor"][4:],
            pending["next_cursor"] + "x",
        ]
        for cursor in cursors:
            with self.subTest(cursor=cursor):
                status, _, data = self._reconcile(f"?cursor={cursor}")
                self.assertEqual(status, 400)
                self.assertEqual(data, INVALID_REQUEST)
        # A genuine cursor presented under another tenant is equally
        # invalid and indistinguishable.
        status, _, data = self._reconcile(
            f"?cursor={pending['next_cursor']}", tenant="tenant-b"
        )
        self.assertEqual(status, 400)
        self.assertEqual(data, INVALID_REQUEST)

    def test_rejected_calls_advance_nothing(self):
        receipt = self._submit()
        self.store.claim_next("tenant-a", "worker-1", 1)
        time.sleep(1.15)
        rid = receipt["request_id"]
        for query in ("?limit=0", "?foo=1", "?cursor=bogus"):
            self._reconcile(query)
        # The processing request was never compensated by the rejects.
        self.assertEqual(
            self.store.get_status("tenant-a", rid)["status"], "processing"
        )
        # A valid call still sweeps from the very beginning.
        payload = self._batch()
        self.assertEqual(payload["items"], [{"request_id": rid, "status": "failed"}])
        # A rejected resume does not move a live batch's position.
        self._submit(key="key-2")
        self._submit(key="key-3")
        self.store.claim_next("tenant-a", "worker-1", 1)
        self.store.claim_next("tenant-a", "worker-1", 1)
        time.sleep(1.15)
        first = self._batch("?limit=1")
        self.assertIs(first["finished"], False)
        status, _, _ = self._reconcile(f"?cursor={first['next_cursor']}&limit=0")
        self.assertEqual(status, 400)
        resumed = self._batch(f"?cursor={first['next_cursor']}")
        self.assertEqual(resumed["batch_id"], first["batch_id"])
        self.assertEqual(len(resumed["items"]), 1)


class BatchReconcileRoutingTests(_StoreCase):
    def test_get_head_put_delete_are_405_with_allow_post(self):
        for method in ("GET", "HEAD", "PUT", "DELETE", "PATCH", "OPTIONS"):
            with self.subTest(method=method):
                status, headers, data = self._request(
                    method, "/reconcile", headers={"X-Tenant-Id": "tenant-a"}
                )
                self.assertEqual(status, 405)
                self.assertEqual(headers.get("Allow"), "POST")
                if method != "HEAD":
                    self.assertEqual(data, METHOD_NOT_ALLOWED)

    def test_deeper_or_sibling_paths_are_404(self):
        for path in ("/reconcile/", "/reconcile/extra", "/reconciles", "/Reconcile"):
            with self.subTest(path=path):
                for method in ("GET", "POST"):
                    status, _, data = self._request(
                        method, path, headers={"X-Tenant-Id": "tenant-a"}
                    )
                    self.assertEqual(status, 404)
                    self.assertEqual(data, NOT_FOUND)

    def test_existing_endpoints_are_unaffected(self):
        receipt = self._submit()
        rid = receipt["request_id"]
        status, _, data = self._request(
            "POST", f"/requests/{rid}/reconcile", headers={"X-Tenant-Id": "tenant-a"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)["status"], "accepted")
        status, _, data = self._request(
            "GET", "/requests", headers={"X-Tenant-Id": "tenant-a"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(len(json.loads(data)["items"]), 1)


class BatchReconcileStorageErrorTests(_StoreCase):
    def test_corrupt_database_is_503(self):
        with open(self.db_path, "wb") as handle:
            handle.write(b"not a sqlite database")
        status, _, data = self._reconcile()
        self.assertEqual(status, 503)
        self.assertEqual(data, STORAGE_UNAVAILABLE)
        self.assertNotIn(self.db_path.encode(), data)

    def test_deferred_store_without_database_is_503(self):
        blocker = os.path.join(self._tmp.name, "blocker")
        with open(blocker, "w", encoding="utf-8") as handle:
            handle.write("not a directory")
        deferred = DeferredRequestStore(os.path.join(blocker, "evidence.db"))
        with _Server(deferred) as fixture:
            conn = http.client.HTTPConnection("127.0.0.1", fixture.port, timeout=10)
            try:
                conn.request(
                    "POST", "/reconcile", headers={"X-Tenant-Id": "tenant-a"}
                )
                resp = conn.getresponse()
                self.assertEqual(resp.status, 503)
                self.assertEqual(resp.read(), STORAGE_UNAVAILABLE)
            finally:
                conn.close()

    def test_broken_store_maps_to_503_without_leaking(self):
        secret = "SECRET-batch-detail"

        class BrokenStore:
            def reconcile_batch(self, *args, **kwargs):
                raise sqlite3.OperationalError(secret)

        with _Server(BrokenStore()) as fixture:
            conn = http.client.HTTPConnection("127.0.0.1", fixture.port, timeout=10)
            try:
                conn.request(
                    "POST", "/reconcile", headers={"X-Tenant-Id": "tenant-a"}
                )
                resp = conn.getresponse()
                data = resp.read()
                self.assertEqual(resp.status, 503)
                self.assertEqual(data, STORAGE_UNAVAILABLE)
                self.assertNotIn(secret.encode(), data)
            finally:
                conn.close()

    def test_corrupt_batch_state_is_503(self):
        self._submit(key="key-1")
        self._submit(key="key-2")
        self.store.claim_next("tenant-a", "worker-1", 1)
        self.store.claim_next("tenant-a", "worker-1", 1)
        time.sleep(1.15)
        first = self._batch("?limit=1")
        self.assertIs(first["finished"], False)
        # Corrupt the persisted batch position out of band.
        with sqlite3.connect(self.db_path) as raw:
            raw.execute(
                "UPDATE reconcile_batches SET position_request_id = NULL "
                "WHERE batch_id = ?",
                (first["batch_id"],),
            )
        status, _, data = self._reconcile(f"?cursor={first['next_cursor']}")
        self.assertEqual(status, 503)
        self.assertEqual(data, STORAGE_UNAVAILABLE)


class BatchReconcileConcurrencyTests(_StoreCase):
    def test_concurrent_resumes_settle_each_item_exactly_once(self):
        receipts = [self._submit(key=f"key-{i}") for i in range(4)]
        for _ in receipts:
            self.store.claim_next("tenant-a", "worker-1", 1)
        time.sleep(1.15)
        first = self._batch("?limit=1")
        cursor = first["next_cursor"]

        def call(_index):
            conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
            try:
                conn.request(
                    "POST",
                    f"/reconcile?cursor={cursor}&limit=1",
                    headers={"X-Tenant-Id": "tenant-a"},
                )
                resp = conn.getresponse()
                return resp.status, resp.read()
            finally:
                conn.close()

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(call, range(8)))
        self.assertTrue(all(status == 200 for status, _ in results))
        # Every response names the same batch and no item was settled
        # twice across all committed rows.
        for _, data in results:
            self.assertEqual(json.loads(data)["batch_id"], first["batch_id"])
        with sqlite3.connect(self.db_path) as raw:
            rows = raw.execute(
                "SELECT request_id FROM reconcile_batch_items WHERE batch_id = ?",
                (first["batch_id"],),
            ).fetchall()
        settled = [row[0] for row in rows]
        self.assertEqual(len(settled), len(set(settled)))
        self.assertEqual(
            self.store.get_status("tenant-a", receipts[0]["request_id"])["status"],
            "failed",
        )


class BatchReconcileHttpAuthTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "evidence.db")
        self.store = RequestStore(self.db_path)
        self.auth = AuthConfig([RECONCILE_A, READ_A, SUBMIT_A, RECONCILE_B])
        self._fixture = _Server(self.store, self.auth)
        self._fixture.__enter__()
        self.port = self._fixture.port

    def tearDown(self):
        self._fixture.__exit__(None, None, None)
        self._tmp.cleanup()

    def _request(self, method, path, raw_body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            kwargs = {}
            if raw_body is not None:
                kwargs["body"] = raw_body
            conn.request(method, path, headers=headers or {}, **kwargs)
            resp = conn.getresponse()
            return resp.status, dict(resp.getheaders()), resp.read()
        finally:
            conn.close()

    def _reconcile(self, query="", token=None, tenant="tenant-a"):
        headers = {}
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        if tenant is not None:
            headers["X-Tenant-Id"] = tenant
        return self._request("POST", f"/reconcile{query}", headers=headers)

    def test_missing_or_unknown_credential_is_401(self):
        for headers in (
            {},
            {"Authorization": ""},
            {"Authorization": "Basic tok-reconcile-a"},
            {"Authorization": "Bearer"},
            {"Authorization": "Bearer "},
            {"Authorization": "bearer tok-reconcile-a"},
            {"Authorization": "Bearer unknown-token"},
            {"Authorization": "tok-reconcile-a"},
        ):
            with self.subTest(headers=headers):
                headers = dict(headers)
                headers["X-Tenant-Id"] = "tenant-a"
                status, _, data = self._request("POST", "/reconcile", headers=headers)
                self.assertEqual(status, 401)
                self.assertEqual(data, UNAUTHORIZED)

    def test_submit_and_read_principals_are_forbidden(self):
        for token in ("tok-submit-a", "tok-read-a"):
            with self.subTest(token=token):
                status, _, data = self._reconcile(token=token)
                self.assertEqual(status, 403)
                self.assertEqual(data, FORBIDDEN)

    def test_cross_tenant_principal_is_forbidden(self):
        status, _, data = self._reconcile(token="tok-reconcile-b", tenant="tenant-a")
        self.assertEqual(status, 403)
        self.assertEqual(data, FORBIDDEN)
        # Its own tenant is fine.
        status, _, data = self._reconcile(token="tok-reconcile-b", tenant="tenant-b")
        self.assertEqual(status, 200)

    def test_authentication_precedes_parameter_validation(self):
        # An invalid limit with no credential is 401, not 400.
        status, _, data = self._reconcile("?limit=0")
        self.assertEqual(status, 401)
        self.assertEqual(data, UNAUTHORIZED)
        # An invalid limit with an under-roled credential is 403.
        status, _, data = self._reconcile("?limit=0", token="tok-read-a")
        self.assertEqual(status, 403)
        self.assertEqual(data, FORBIDDEN)
        # A cross-tenant principal with an invalid limit is 403.
        status, _, data = self._reconcile(
            "?limit=0", token="tok-reconcile-b", tenant="tenant-a"
        )
        self.assertEqual(status, 403)
        self.assertEqual(data, FORBIDDEN)

    def test_authorized_call_succeeds_and_leaks_no_token(self):
        status, _, data = self._reconcile(token="tok-reconcile-a")
        self.assertEqual(status, 200)
        payload = json.loads(data)
        self.assertEqual(
            list(payload), ["batch_id", "next_cursor", "finished", "items"]
        )
        self.assertNotIn(b"tok-reconcile-a", data)


if __name__ == "__main__":
    unittest.main()
