"""HTTP tests for the batched reconciliation endpoint.

Covers ``POST /reconcile`` only: the empty-body rule, the fixed
batch-shaped response, pagination and resumable cursors, the
storage-layer convergence rules observed through HTTP (accepted rows
skipped, live leases kept, expired leases compensated, terminal rows
untouched), routing/method rules (Allow: POST, headless HEAD, sibling
paths 404), tenant and parameter error ordering, storage error mapping,
bearer/RBAC behaviour for the ``request:reconcile`` role and the
no-leak guarantees.
"""

import base64
import http.client
import json
import os
import socket
import sqlite3
import tempfile
import threading
import time
import unittest
import uuid

from forgetting_evidence.httpapi import (
    AuthConfig,
    build_server,
    make_handler,
)
from forgetting_evidence.requests import RequestStore

NOT_FOUND = b'{"error":"not_found"}\n'
INVALID_REQUEST = b'{"error":"invalid_request"}\n'
METHOD_NOT_ALLOWED = b'{"error":"method_not_allowed"}\n'
STORAGE_UNAVAILABLE = b'{"error":"storage_unavailable"}\n'
UNAUTHORIZED = b'{"error":"unauthorized"}\n'
FORBIDDEN = b'{"error":"forbidden"}\n'


def _cursor_for(batch_id, position=0):
    payload = json.dumps(
        {"v": 1, "b": batch_id, "n": position}, separators=(",", ":")
    ).encode("utf-8")
    return "rc1." + base64.urlsafe_b64encode(payload).decode("ascii")


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

    def _reconcile(self, query="", tenant="tenant-a", raw_body=None,
                   extra_headers=None):
        headers = dict(extra_headers or {})
        if tenant is not None:
            headers["X-Tenant-Id"] = tenant
        return self._request("POST", f"/reconcile{query}",
                             raw_body=raw_body, headers=headers)

    def _batch_rows(self):
        with sqlite3.connect(self.db_path) as raw:
            return raw.execute(
                "SELECT batch_id, tenant_id, finished FROM reconcile_batches"
            ).fetchall()

    def _item_rows(self):
        with sqlite3.connect(self.db_path) as raw:
            return raw.execute(
                "SELECT batch_id, seq, request_id, status "
                "FROM reconcile_batch_items ORDER BY batch_id, seq"
            ).fetchall()

    def _expired_processing(self, tenant="tenant-a", key="key-1"):
        receipt = self._submit(tenant=tenant, key=key)
        self.store.claim_next(tenant, "worker-1", 1)
        return receipt["request_id"]


class ReconcileBatchSuccessTests(_StoreCase):
    def test_empty_tenant_finishes_with_empty_items(self):
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

    def test_accepted_only_sweeps_without_items_or_side_effects(self):
        first = self._submit(key="key-1")
        second = self._submit(key="key-2")
        status, _, data = self._reconcile()
        self.assertEqual(status, 200)
        payload = json.loads(data)
        self.assertEqual(payload["items"], [])
        self.assertIs(payload["finished"], True)
        self.assertIsNone(payload["next_cursor"])
        # Accepted rows were only advanced past: no attempt, no receipt,
        # no extra status event, no status change.
        for rid in (first["request_id"], second["request_id"]):
            self.assertEqual(
                self.store.get_status("tenant-a", rid)["status"], "accepted"
            )
            self.assertEqual(self.store.get_execution_log("tenant-a", rid), [])
            self.assertEqual(
                [e["status"] for e in self.store.audit("tenant-a", rid)],
                ["accepted"],
            )
        with sqlite3.connect(self.db_path) as raw:
            self.assertEqual(
                raw.execute("SELECT count(*) FROM claim_attempts").fetchone()[0],
                0,
            )
            self.assertEqual(
                raw.execute(
                    "SELECT count(*) FROM reconcile_batch_items"
                ).fetchone()[0],
                0,
            )

    def test_live_lease_stays_processing_and_is_listed(self):
        receipt = self._submit()
        rid = receipt["request_id"]
        claim = self.store.claim_next("tenant-a", "worker-1", 3600)
        status, _, data = self._reconcile()
        self.assertEqual(status, 200)
        payload = json.loads(data)
        self.assertEqual(
            payload["items"], [{"request_id": rid, "status": "processing"}]
        )
        self.assertIs(payload["finished"], True)
        # No attempt detail beyond the live claim; the credential works.
        self.assertEqual(len(self.store.get_execution_log("tenant-a", rid)), 1)
        done = self.store.finish_claim(
            "tenant-a", rid, claim["claim_token"], "completed"
        )
        self.assertEqual(done["status"], "completed")

    def test_expired_lease_is_compensated_and_listed_as_failed(self):
        rid = self._expired_processing()
        time.sleep(1.15)
        status, _, data = self._reconcile()
        self.assertEqual(status, 200)
        payload = json.loads(data)
        self.assertEqual(
            payload["items"], [{"request_id": rid, "status": "failed"}]
        )
        log = self.store.get_execution_log("tenant-a", rid)
        self.assertEqual(len(log), 1)
        self.assertEqual(log[0]["result"], "failed")
        self.assertIsNotNone(log[0]["completed_at"])
        self.assertEqual(
            [e["status"] for e in self.store.audit("tenant-a", rid)],
            ["accepted", "processing", "failed"],
        )

    def test_mixed_sweep_follows_the_reconcile_rules_in_scan_order(self):
        # Acceptance order: expired-processing, live-processing,
        # completed, accepted. (claim_next always takes the oldest
        # accepted request, so the never-claimed one is submitted last.)
        expired = self._expired_processing(key="key-1")
        live = self._submit(key="key-2")["request_id"]
        live_claim = self.store.claim_next("tenant-a", "worker-2", 3600)
        self.assertEqual(live_claim["request_id"], live)
        done_rid = self._submit(key="key-3")["request_id"]
        claim = self.store.claim_next("tenant-a", "worker-1", 3600)
        self.assertEqual(claim["request_id"], done_rid)
        self.store.finish_claim(
            "tenant-a", done_rid, claim["claim_token"], "completed"
        )
        accepted = self._submit(key="key-4")["request_id"]
        time.sleep(1.15)
        status, _, data = self._reconcile()
        self.assertEqual(status, 200)
        payload = json.loads(data)
        # Only the two processing requests are listed, in acceptance
        # order; the accepted row is skipped and the completed row is
        # never swept.
        self.assertEqual(
            payload["items"],
            [
                {"request_id": expired, "status": "failed"},
                {"request_id": live, "status": "processing"},
            ],
        )
        for item in payload["items"]:
            self.assertEqual(list(item), ["request_id", "status"])
        self.assertEqual(
            self.store.get_status("tenant-a", accepted)["status"], "accepted"
        )
        self.assertEqual(
            self.store.get_status("tenant-a", done_rid)["status"], "completed"
        )
        # No subject, scope, idempotency key or worker detail leaks.
        for marker in (b"subject-1", b"email", b"key-", b"worker"):
            self.assertNotIn(marker, data)

    def test_repeated_full_sweeps_create_distinct_batches(self):
        self._submit()
        _, _, first = self._reconcile()
        _, _, second = self._reconcile()
        first_id = json.loads(first)["batch_id"]
        second_id = json.loads(second)["batch_id"]
        self.assertNotEqual(first_id, second_id)
        self.assertEqual(len(self._batch_rows()), 2)


class ReconcileBatchPaginationTests(_StoreCase):
    def _two_expired(self):
        first = self._expired_processing(key="key-1")
        second = self._expired_processing(key="key-2")
        time.sleep(1.15)
        return first, second

    def test_limit_truncates_and_cursor_resumes_the_same_batch(self):
        first, second = self._two_expired()
        status, _, data = self._reconcile("?limit=1")
        self.assertEqual(status, 200)
        page1 = json.loads(data)
        self.assertIs(page1["finished"], False)
        self.assertIsInstance(page1["next_cursor"], str)
        self.assertTrue(page1["next_cursor"])
        self.assertEqual(
            page1["items"], [{"request_id": first, "status": "failed"}]
        )
        status, _, data = self._reconcile(
            f"?limit=1&cursor={page1['next_cursor']}"
        )
        self.assertEqual(status, 200)
        page2 = json.loads(data)
        self.assertEqual(page2["batch_id"], page1["batch_id"])
        self.assertIs(page2["finished"], True)
        self.assertIsNone(page2["next_cursor"])
        self.assertEqual(
            page2["items"], [{"request_id": second, "status": "failed"}]
        )

    def test_retry_of_consumed_cursor_never_rewrites_committed_items(self):
        self._two_expired()
        _, _, data = self._reconcile("?limit=1")
        cursor = json.loads(data)["next_cursor"]
        _, _, data = self._reconcile(f"?limit=1&cursor={cursor}")
        self.assertIs(json.loads(data)["finished"], True)
        items_before = self._item_rows()
        # Replaying the same cursor resumes from the committed position:
        # the batch is already finished, nothing is settled again.
        status, _, data = self._reconcile(f"?limit=1&cursor={cursor}")
        self.assertEqual(status, 200)
        payload = json.loads(data)
        self.assertIs(payload["finished"], True)
        self.assertIsNone(payload["next_cursor"])
        self.assertEqual(payload["items"], [])
        self.assertEqual(self._item_rows(), items_before)
        self.assertEqual(len(items_before), 2)

    def test_cursor_is_accepted_from_the_query_string_only(self):
        self._two_expired()
        _, _, data = self._reconcile("?limit=1")
        cursor = json.loads(data)["next_cursor"]
        # A cursor in the body is not a cursor: the body must be empty.
        status, _, data = self._reconcile(
            raw_body=json.dumps({"cursor": cursor}).encode()
        )
        self.assertEqual(status, 400)
        self.assertEqual(data, INVALID_REQUEST)

    def test_default_limit_is_bounded_and_completes_small_sweeps(self):
        first = self._submit(key="key-1")
        second = self._submit(key="key-2")
        status, _, data = self._reconcile()
        self.assertEqual(status, 200)
        payload = json.loads(data)
        self.assertIs(payload["finished"], True)
        self.assertEqual(payload["items"], [])

    def test_limit_boundaries_are_accepted(self):
        for limit in ("1", "1000", "010"):
            with self.subTest(limit=limit):
                status, _, data = self._reconcile(f"?limit={limit}")
                self.assertEqual(status, 200)
                self.assertIs(json.loads(data)["finished"], True)


class ReconcileBatchValidationTests(_StoreCase):
    def test_unknown_and_duplicate_parameters_are_400(self):
        for query in (
            "?unknown=1",
            "?status=failed",
            "?limit=1&limit=2",
            "?cursor=a&cursor=b",
            "?tenant_id=tenant-a&tenant_id=tenant-a",
            "?limit=",
            "?cursor=",
        ):
            with self.subTest(query=query):
                status, _, data = self._reconcile(query)
                self.assertEqual(status, 400)
                self.assertEqual(data, INVALID_REQUEST)
                self.assertEqual(set(json.loads(data)), {"error"})
        self.assertEqual(self._batch_rows(), [])

    def test_invalid_limits_are_400(self):
        for limit in ("0", "1001", "-1", "1.5", "abc", "1e2", "%201", "1%20",
                      "9" * 11):
            with self.subTest(limit=limit):
                status, _, data = self._reconcile(f"?limit={limit}")
                self.assertEqual(status, 400)
                self.assertEqual(data, INVALID_REQUEST)
        self.assertEqual(self._batch_rows(), [])

    def test_missing_or_empty_tenant_is_400(self):
        for headers in ({}, {"X-Tenant-Id": ""}, {"X-Tenant-Id": "   "}):
            with self.subTest(headers=headers):
                status, _, data = self._request(
                    "POST", "/reconcile", headers=headers
                )
                self.assertEqual(status, 400)
                self.assertEqual(data, INVALID_REQUEST)
        status, _, data = self._request("POST", "/reconcile?tenant_id=")
        self.assertEqual(status, 400)
        self.assertEqual(data, INVALID_REQUEST)
        self.assertEqual(self._batch_rows(), [])

    def test_header_tenant_takes_precedence_over_query(self):
        self._submit(tenant="tenant-b", key="key-b")
        status, _, data = self._request(
            "POST",
            "/reconcile?tenant_id=tenant-a",
            headers={"X-Tenant-Id": "tenant-b"},
        )
        self.assertEqual(status, 200)
        # The header tenant's sweep ran; tenant-a has no batch.
        self.assertEqual(
            [row[1] for row in self._batch_rows()], ["tenant-b"]
        )

    def test_any_non_empty_body_is_400_and_creates_no_batch(self):
        for raw in (b"{}", b"[]", b"null", b"x", b'{"cursor":"abc"}'):
            with self.subTest(raw=raw):
                status, _, data = self._reconcile(raw_body=raw)
                self.assertEqual(status, 400)
                self.assertEqual(data, INVALID_REQUEST)
        self.assertEqual(self._batch_rows(), [])

    def test_malformed_and_unknown_cursors_are_400(self):
        for cursor in (
            "junk",
            "rc1.",
            "rc1.!!!",
            "rc1." + "A" * 4,  # valid base64, not JSON
            _cursor_for(str(uuid.uuid4())),  # well-formed, unknown batch
            _cursor_for("not-a-batch", 3),
        ):
            with self.subTest(cursor=cursor):
                status, _, data = self._reconcile(f"?cursor={cursor}")
                self.assertEqual(status, 400)
                self.assertEqual(data, INVALID_REQUEST)
        self.assertEqual(self._batch_rows(), [])

    def test_cross_tenant_cursor_is_400_and_does_not_advance_the_batch(self):
        first = self._expired_processing(key="key-1")
        second = self._expired_processing(key="key-2")
        time.sleep(1.15)
        page = self.store.reconcile_batch("tenant-a", limit=1)
        cursor = page["next_cursor"]
        self.assertIsNotNone(cursor)
        # The same cursor under another tenant is rejected and the
        # tenant-a batch keeps its committed position.
        status, _, data = self._reconcile(
            f"?cursor={cursor}", tenant="tenant-b"
        )
        self.assertEqual(status, 400)
        self.assertEqual(data, INVALID_REQUEST)
        resumed = self.store.reconcile_batch("tenant-a", cursor=cursor, limit=10)
        self.assertEqual(
            resumed["items"], [{"request_id": second, "status": "failed"}]
        )
        self.assertTrue(resumed["finished"])

    def test_rejected_calls_never_change_requests(self):
        rid = self._expired_processing()
        time.sleep(1.15)
        self._reconcile("?limit=0")
        self._reconcile("?cursor=junk")
        self._reconcile(raw_body=b"{}")
        self._reconcile("?unknown=1")
        self.assertEqual(
            self.store.get_status("tenant-a", rid)["status"], "processing"
        )
        self.assertEqual(
            [e["status"] for e in self.store.audit("tenant-a", rid)],
            ["accepted", "processing"],
        )
        self.assertEqual(self._batch_rows(), [])


class ReconcileBatchRoutingTests(_StoreCase):
    def test_non_post_methods_are_405_with_allow_post(self):
        for method in ("GET", "PUT", "DELETE", "PATCH", "OPTIONS"):
            with self.subTest(method=method):
                status, headers, data = self._request(
                    method, "/reconcile",
                    headers={"X-Tenant-Id": "tenant-a"},
                )
                self.assertEqual(status, 405)
                self.assertEqual(data, METHOD_NOT_ALLOWED)
                self.assertEqual(headers.get("Allow"), "POST")

    def test_head_is_405_headless_with_allow_post(self):
        status, headers, data = self._request(
            "HEAD", "/reconcile", headers={"X-Tenant-Id": "tenant-a"}
        )
        self.assertEqual(status, 405)
        self.assertEqual(data, b"")
        self.assertEqual(headers.get("Allow"), "POST")
        self.assertEqual(
            headers.get("Content-Length"), str(len(METHOD_NOT_ALLOWED))
        )

    def test_sibling_and_deeper_paths_stay_404(self):
        for method, path in (
            ("POST", "/reconcile/extra"),
            ("GET", "/reconcile/extra"),
            ("POST", "/reconcile/"),
            ("POST", "/reconcilex"),
            ("GET", "/Reconcile"),
        ):
            with self.subTest(method=method, path=path):
                status, _, data = self._request(
                    method, path, headers={"X-Tenant-Id": "tenant-a"}
                )
                self.assertEqual(status, 404)
                self.assertEqual(data, NOT_FOUND)

    def test_existing_routes_are_unchanged(self):
        rid = self._submit()["request_id"]
        # The single-request reconcile is still POST-only.
        status, headers, _ = self._request(
            "GET", f"/requests/{rid}/reconcile",
            headers={"X-Tenant-Id": "tenant-a"},
        )
        self.assertEqual(status, 405)
        self.assertEqual(headers.get("Allow"), "POST")
        # The collection still accepts GET and POST.
        status, headers, _ = self._request("PUT", "/requests")
        self.assertEqual(status, 405)
        self.assertEqual(headers.get("Allow"), "GET, POST")


class ReconcileBatchStorageErrorTests(_StoreCase):
    def _broken_server(self, broken_store):
        handler = make_handler(broken_store)
        server = __import__(
            "http.server", fromlist=["ThreadingHTTPServer"]
        ).ThreadingHTTPServer(("127.0.0.1", 0), handler)
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server

    @staticmethod
    def _raw_reconcile(server, query=""):
        port = server.server_address[1]
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        try:
            conn.request(
                "POST", f"/reconcile{query}",
                headers={"X-Tenant-Id": "tenant-a"},
            )
            resp = conn.getresponse()
            return resp.status, dict(resp.getheaders()), resp.read()
        finally:
            conn.close()

    def test_value_error_maps_to_400(self):
        secret = "database SECRET-SQL PATH"

        class BrokenStore:
            def reconcile_batch(self, *a, **k):
                raise ValueError(secret)

        server = self._broken_server(BrokenStore())
        try:
            status, _, data = self._raw_reconcile(server)
            self.assertEqual(status, 400)
            self.assertEqual(data, INVALID_REQUEST)
            self.assertNotIn(b"SECRET", data)
        finally:
            server.shutdown()
            server.server_close()

    def test_runtime_os_sqlite_errors_map_to_503_without_leak(self):
        secret = "database is locked SECRET-SQL-DETAIL /secret/path"

        class BrokenStore:
            def reconcile_batch(self, *a, **k):
                raise RuntimeError(secret)

        server = self._broken_server(BrokenStore())
        try:
            status, _, data = self._raw_reconcile(server)
            self.assertEqual(status, 503)
            self.assertEqual(data, STORAGE_UNAVAILABLE)
            self.assertNotIn(b"SECRET", data)
        finally:
            server.shutdown()
            server.server_close()

        class BrokenStore2:
            def reconcile_batch(self, *a, **k):
                raise sqlite3.OperationalError(secret)

        server = self._broken_server(BrokenStore2())
        try:
            status, _, data = self._raw_reconcile(server)
            self.assertEqual(status, 503)
            self.assertNotIn(b"SECRET", data)
        finally:
            server.shutdown()
            server.server_close()

    def test_malformed_store_result_maps_to_503(self):
        class OddStore:
            def __init__(self, result):
                self._result = result

            def reconcile_batch(self, *a, **k):
                return self._result

        for result in (
            {"batch_id": "b", "next_cursor": None, "finished": True},
            {"batch_id": "b", "next_cursor": "c", "finished": True,
             "items": []},
            {"batch_id": "b", "next_cursor": None, "finished": False,
             "items": []},
            {"batch_id": "b", "next_cursor": None, "finished": True,
             "items": [{"request_id": "r", "status": "accepted"}]},
            {"batch_id": "b", "next_cursor": None, "finished": True,
             "items": [{"request_id": "r", "status": "failed", "x": 1}]},
            {"batch_id": "b", "next_cursor": None, "finished": True,
             "items": [], "extra": 1},
        ):
            with self.subTest(result=result):
                server = self._broken_server(OddStore(result))
                try:
                    status, _, data = self._raw_reconcile(server)
                    self.assertEqual(status, 503)
                    self.assertEqual(data, STORAGE_UNAVAILABLE)
                finally:
                    server.shutdown()
                    server.server_close()

    def test_store_receives_only_the_given_arguments(self):
        seen = []

        class SpyStore:
            def reconcile_batch(self, tenant_id, cursor=None, limit=None):
                seen.append((tenant_id, cursor, limit))
                return {
                    "batch_id": "b",
                    "next_cursor": None,
                    "finished": True,
                    "items": [],
                }

        server = self._broken_server(SpyStore())
        try:
            status, _, _ = self._raw_reconcile(server)
            self.assertEqual(status, 200)
            self.assertEqual(seen, [("tenant-a", None, None)])
            status, _, _ = self._raw_reconcile(server, "?limit=5")
            self.assertEqual(status, 200)
            self.assertEqual(seen[-1], ("tenant-a", None, 5))
        finally:
            server.shutdown()
            server.server_close()

    def test_corrupt_database_is_503(self):
        self._submit()
        with open(self.db_path, "wb") as handle:
            handle.write(b"not a sqlite database")
        status, _, data = self._reconcile()
        self.assertEqual(status, 503)
        self.assertEqual(data, STORAGE_UNAVAILABLE)
        self.assertNotIn(self.db_path.encode(), data)


SUBMIT_A = {"token": "tok-submit-a", "tenant_id": "tenant-a",
            "roles": ["request:submit"]}
READ_A = {"token": "tok-read-a", "tenant_id": "tenant-a",
          "roles": ["request:read"]}
RECONCILE_A = {"token": "tok-reconcile-a", "tenant_id": "tenant-a",
               "roles": ["request:reconcile"]}
ALL_A = {"token": "tok-all-a", "tenant_id": "tenant-a",
         "roles": ["request:submit", "request:read", "request:reconcile"]}
RECONCILE_B = {"token": "tok-reconcile-b", "tenant_id": "tenant-b",
               "roles": ["request:reconcile"]}


class ReconcileBatchHttpAuthTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "evidence.db")
        self.store = RequestStore(self.db_path)
        self.auth = AuthConfig(
            [SUBMIT_A, READ_A, RECONCILE_A, ALL_A, RECONCILE_B]
        )
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

    def _bearer(self, token):
        return {"Authorization": f"Bearer {token}"}

    def _reconcile(self, token=None, tenant="tenant-a", query="",
                   raw_body=None):
        headers = {}
        if token is not None:
            headers.update(self._bearer(token))
        if tenant is not None:
            headers["X-Tenant-Id"] = tenant
        return self._request("POST", f"/reconcile{query}",
                             raw_body=raw_body, headers=headers)

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
                status, _, data = self._request(
                    "POST", "/reconcile", headers=headers
                )
                self.assertEqual(status, 401)
                self.assertEqual(data, UNAUTHORIZED)

    def test_submit_and_read_principals_are_forbidden(self):
        for token in ("tok-submit-a", "tok-read-a"):
            with self.subTest(token=token):
                status, _, data = self._reconcile(token=token)
                self.assertEqual(status, 403)
                self.assertEqual(data, FORBIDDEN)

    def test_cross_tenant_principal_is_forbidden(self):
        status, _, data = self._reconcile(
            token="tok-reconcile-a", tenant="tenant-b"
        )
        self.assertEqual(status, 403)
        self.assertEqual(data, FORBIDDEN)

    def test_auth_precedes_parameter_and_body_validation(self):
        # No credential at all: 401 even with an invalid limit.
        status, _, data = self._request(
            "POST", "/reconcile?limit=0",
            headers={"X-Tenant-Id": "tenant-a"},
        )
        self.assertEqual(status, 401)
        self.assertEqual(data, UNAUTHORIZED)
        # A role-less principal: 403 even with a non-empty body.
        status, _, data = self._reconcile(
            token="tok-read-a", raw_body=b'{"x":1}'
        )
        self.assertEqual(status, 403)
        self.assertEqual(data, FORBIDDEN)
        # A cross-tenant target: 403 even with an invalid limit.
        status, _, data = self._reconcile(
            token="tok-reconcile-a", tenant="tenant-b", query="?limit=0"
        )
        self.assertEqual(status, 403)
        self.assertEqual(data, FORBIDDEN)

    def test_routing_precedes_authentication(self):
        # GET on the POST-only resource is 405 even without a token.
        status, headers, data = self._request(
            "GET", "/reconcile", headers={"X-Tenant-Id": "tenant-a"}
        )
        self.assertEqual(status, 405)
        self.assertEqual(data, METHOD_NOT_ALLOWED)
        self.assertEqual(headers.get("Allow"), "POST")

    def test_authorized_reconcile_succeeds(self):
        rid = self.store.submit(
            "tenant-a", "subject-1", ["email"], "key-1"
        )["request_id"]
        self.store.claim_next("tenant-a", "worker-1", 1)
        time.sleep(1.15)
        status, headers, data = self._reconcile(token="tok-reconcile-a")
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("Content-Type"), "application/json")
        payload = json.loads(data)
        self.assertEqual(
            payload["items"], [{"request_id": rid, "status": "failed"}]
        )
        # The all-roles principal may run a batch as well.
        status, _, _ = self._reconcile(token="tok-all-a")
        self.assertEqual(status, 200)

    def test_authorized_token_with_body_is_400(self):
        status, _, data = self._reconcile(
            token="tok-reconcile-a", raw_body=b"{}"
        )
        self.assertEqual(status, 400)
        self.assertEqual(data, INVALID_REQUEST)

    def test_missing_tenant_with_valid_token_is_400(self):
        status, _, data = self._reconcile(token="tok-reconcile-a", tenant=None)
        self.assertEqual(status, 400)
        self.assertEqual(data, INVALID_REQUEST)

    def test_batches_are_partitioned_per_tenant_under_auth(self):
        self.store.submit("tenant-a", "subject-1", ["email"], "key-a")
        self.store.submit("tenant-b", "subject-2", ["email"], "key-b")
        status, _, data = self._reconcile(token="tok-reconcile-a")
        self.assertEqual(status, 200)
        batch_a = json.loads(data)["batch_id"]
        status, _, data = self._reconcile(
            token="tok-reconcile-b", tenant="tenant-b"
        )
        self.assertEqual(status, 200)
        batch_b = json.loads(data)["batch_id"]
        self.assertNotEqual(batch_a, batch_b)
        with sqlite3.connect(self.db_path) as raw:
            tenants = {
                row[0]
                for row in raw.execute(
                    "SELECT tenant_id FROM reconcile_batches"
                )
            }
        self.assertEqual(tenants, {"tenant-a", "tenant-b"})

    def test_token_and_role_are_not_persisted(self):
        token = "tok-reconcile-a"
        status, _, _ = self._reconcile(token=token)
        self.assertEqual(status, 200)
        with open(self.db_path, "rb") as handle:
            db_bytes = handle.read()
        self.assertNotIn(token.encode(), db_bytes)
        self.assertNotIn(b"request:reconcile", db_bytes)


if __name__ == "__main__":
    unittest.main()
