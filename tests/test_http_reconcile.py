"""HTTP tests for the single-request reconciliation endpoint.

Covers ``POST /requests/{request_id}/reconcile`` only: the empty-body
rule, the status-shaped single-row response, idempotency and the
storage-layer convergence observed through HTTP, routing/method rules
(Allow: POST, headless HEAD, deeper paths 404), tenant and id error
ordering, storage error mapping, bearer/RBAC behaviour for the new
``request:reconcile`` role, concurrency and the no-leak guarantees.
"""

import http.client
import json
import os
import socket
import sqlite3
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor

from forgetting_evidence.httpapi import (
    AuthConfig,
    AuthConfigError,
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

UNKNOWN_RID = "00000000-0000-4000-8000-000000000000"


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

    def _reconcile(self, rid, tenant="tenant-a", raw_body=None, extra_headers=None):
        headers = dict(extra_headers or {})
        if tenant is not None:
            headers["X-Tenant-Id"] = tenant
        return self._request(
            "POST", f"/requests/{rid}/reconcile", raw_body=raw_body, headers=headers
        )

    def _status(self, rid, tenant="tenant-a"):
        return self._request(
            "GET",
            f"/requests/{rid}/status",
            headers={"X-Tenant-Id": tenant} if tenant else {},
        )

    def _raw_http(self, raw, read_to_close=False):
        with socket.create_connection(("127.0.0.1", self.port), timeout=10) as sock:
            sock.sendall(raw)
            chunks = []
            if read_to_close:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    chunks.append(chunk)
                return b"".join(chunks)
            conn_file = sock.makefile("rb")
            status_line = conn_file.readline().decode()
            headers = {}
            while True:
                line = conn_file.readline()
                if line in (b"\r\n", b""):
                    break
                name, _, value = line.decode().partition(":")
                headers[name.strip()] = value.strip()
            length = int(headers.get("Content-Length", "0"))
            body = conn_file.read(length)
            return status_line, headers, body


class ReconcileSuccessTests(_StoreCase):
    def test_accepted_reconcile_returns_status_shaped_record(self):
        receipt = self._submit()
        rid = receipt["request_id"]
        status, headers, data = self._reconcile(rid)
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("Content-Type"), "application/json")
        self.assertTrue(data.endswith(b"\n"))
        self.assertEqual(data.count(b"\n"), 1)
        payload = json.loads(data)
        self.assertEqual(list(payload), ["request_id", "status", "created_at"])
        self.assertEqual(set(payload), {"request_id", "status", "created_at"})
        self.assertEqual(payload, receipt)
        # Byte-identical to the read-only status observation.
        _, _, status_data = self._status(rid)
        self.assertEqual(data, status_data)
        # No subject, scope, idempotency key or other field leaks.
        self.assertNotIn(b"subject-1", data)
        self.assertNotIn(b"email", data)
        self.assertNotIn(b"key-1", data)

    def test_missing_content_length_means_no_body(self):
        rid = self._submit()["request_id"]
        raw = (
            f"POST /requests/{rid}/reconcile HTTP/1.1\r\n"
            "Host: x\r\nX-Tenant-Id: tenant-a\r\nConnection: close\r\n\r\n"
        ).encode()
        response = self._raw_http(raw, read_to_close=True)
        self.assertIn(b" 200 ", response.split(b"\r\n", 1)[0])
        self.assertIn(b'"status":"accepted"', response)

    def test_explicit_zero_content_length_means_no_body(self):
        rid = self._submit()["request_id"]
        raw = (
            f"POST /requests/{rid}/reconcile HTTP/1.1\r\n"
            "Host: x\r\nX-Tenant-Id: tenant-a\r\n"
            "Content-Length: 0\r\nConnection: close\r\n\r\n"
        ).encode()
        response = self._raw_http(raw, read_to_close=True)
        self.assertIn(b" 200 ", response.split(b"\r\n", 1)[0])

    def test_query_parameter_tenant_is_accepted(self):
        rid = self._submit()["request_id"]
        status, _, data = self._request(
            "POST", f"/requests/{rid}/reconcile?tenant_id=tenant-a"
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)["status"], "accepted")

    def test_live_lease_stays_processing_and_credential_survives(self):
        receipt = self._submit()
        rid = receipt["request_id"]
        claim = self.store.claim_next("tenant-a", "worker-1", 3600)
        status, _, data = self._reconcile(rid)
        self.assertEqual(status, 200)
        payload = json.loads(data)
        self.assertEqual(payload["status"], "processing")
        self.assertEqual(payload["created_at"], receipt["created_at"])
        # The HTTP call created no attempt detail beyond the live claim.
        self.assertEqual(
            len(self.store.get_execution_log("tenant-a", rid)), 1
        )
        # The credential still works after reconciliation.
        done = self.store.finish_claim(
            "tenant-a", rid, claim["claim_token"], "completed"
        )
        self.assertEqual(done["status"], "completed")

    def test_expired_lease_is_compensated_through_http(self):
        receipt = self._submit()
        rid = receipt["request_id"]
        self.store.claim_next("tenant-a", "worker-1", 1)
        time.sleep(1.15)
        status, headers, data = self._reconcile(rid)
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("Content-Type"), "application/json")
        payload = json.loads(data)
        self.assertEqual(payload["request_id"], rid)
        self.assertEqual(payload["status"], "failed")
        self.assertEqual(payload["created_at"], receipt["created_at"])
        log = self.store.get_execution_log("tenant-a", rid)
        self.assertEqual(len(log), 1)
        self.assertEqual(log[0]["result"], "failed")
        self.assertIsNotNone(log[0]["completed_at"])
        self.assertTrue(
            self.store.verify_evidence("tenant-a", rid)
        )

    def test_repeated_reconcile_is_idempotent_and_byte_identical(self):
        receipt = self._submit()
        rid = receipt["request_id"]
        self.store.claim_next("tenant-a", "worker-1", 1)
        time.sleep(1.15)
        status, _, first = self._reconcile(rid)
        self.assertEqual(status, 200)
        log_before = self.store.get_execution_log("tenant-a", rid)
        stamp = log_before[0]["completed_at"]
        for _ in range(3):
            again_status, _, again = self._reconcile(rid)
            self.assertEqual(again_status, 200)
            self.assertEqual(again, first)
        log_after = self.store.get_execution_log("tenant-a", rid)
        self.assertEqual(log_after, log_before)
        self.assertEqual(log_after[0]["completed_at"], stamp)
        self.assertEqual(
            [e["status"] for e in self.store.audit("tenant-a", rid)],
            ["accepted", "processing", "failed"],
        )
        _, _, status_data = self._status(rid)
        self.assertEqual(first, status_data)

    def test_terminal_completed_is_unchanged_by_reconcile(self):
        receipt = self._submit()
        rid = receipt["request_id"]
        claim = self.store.claim_next("tenant-a", "worker-1", 60)
        done = self.store.finish_claim(
            "tenant-a", rid, claim["claim_token"], "completed"
        )
        log_before = self.store.get_execution_log("tenant-a", rid)
        status, _, data = self._reconcile(rid)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data), done)
        self.assertEqual(
            self.store.get_execution_log("tenant-a", rid), log_before
        )

    def test_successful_reconcile_creates_no_receipt_or_request_rows(self):
        receipt = self._submit()
        rid = receipt["request_id"]
        self._reconcile(rid)
        with sqlite3.connect(self.db_path) as raw:
            self.assertEqual(
                raw.execute("SELECT count(*) FROM requests").fetchone()[0], 1
            )
            self.assertEqual(
                raw.execute("SELECT count(*) FROM claim_attempts").fetchone()[0], 0
            )
            self.assertEqual(
                raw.execute("SELECT count(*) FROM claim_tokens").fetchone()[0], 0
            )
        # The acceptance receipt stays the frozen accepted record.
        status, _, receipt_data = self._request(
            "GET", f"/requests/{rid}", headers={"X-Tenant-Id": "tenant-a"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(receipt_data)["status"], "accepted")

    def test_reconciled_compensation_survives_server_restart(self):
        receipt = self._submit()
        rid = receipt["request_id"]
        self.store.claim_next("tenant-a", "worker-1", 1)
        time.sleep(1.15)
        _, _, first = self._reconcile(rid)
        self._fixture.__exit__(None, None, None)
        rebuilt = RequestStore(self.db_path)
        with _Server(rebuilt) as fixture:
            conn = http.client.HTTPConnection("127.0.0.1", fixture.port, timeout=10)
            try:
                conn.request(
                    "POST",
                    f"/requests/{rid}/reconcile",
                    headers={"X-Tenant-Id": "tenant-a"},
                )
                resp = conn.getresponse()
                self.assertEqual(resp.status, 200)
                self.assertEqual(resp.read(), first)
            finally:
                conn.close()


class ReconcileBodyValidationTests(_StoreCase):
    def test_any_non_empty_body_is_400_and_converges_nothing(self):
        receipt = self._submit()
        rid = receipt["request_id"]
        for raw in (
            b"{}",
            b"[]",
            b'""',
            b"null",
            b"12",
            b" ",
            b'{"x":1}',
            b"\x00",
        ):
            with self.subTest(raw=raw):
                status, _, data = self._reconcile(rid, raw_body=raw)
                self.assertEqual(status, 400)
                self.assertEqual(data, INVALID_REQUEST)
                self.assertEqual(set(json.loads(data)), {"error"})
        # Rejected bodies neither converged nor wrote any bookkeeping.
        self.assertEqual(
            self.store.get_status("tenant-a", rid)["status"], "accepted"
        )
        self.assertEqual(self.store.get_execution_log("tenant-a", rid), [])
        self.assertEqual(
            [e["status"] for e in self.store.audit("tenant-a", rid)],
            ["accepted"],
        )

    def test_malformed_content_length_is_400(self):
        rid = self._submit()["request_id"]
        raw = (
            f"POST /requests/{rid}/reconcile HTTP/1.1\r\n"
            "Host: x\r\nX-Tenant-Id: tenant-a\r\n"
            "Content-Length: abc\r\nConnection: close\r\n\r\n"
        ).encode()
        response = self._raw_http(raw, read_to_close=True)
        self.assertIn(b" 400 ", response.split(b"\r\n", 1)[0])
        self.assertTrue(response.rstrip(b"\r\n").endswith(INVALID_REQUEST.rstrip(b"\r\n")))

    def test_oversized_body_is_400(self):
        rid = self._submit()["request_id"]
        raw_body = b"x" * ((1 << 20) + 1)
        status, _, data = self._reconcile(rid, raw_body=raw_body)
        self.assertEqual(status, 400)
        self.assertEqual(data, INVALID_REQUEST)

    def test_bounded_rejected_body_keeps_connection_alive(self):
        rid = self._submit()["request_id"]
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            # A bounded non-empty body is drained: the 400 is followed by
            # a clean successful request over the same connection.
            conn.request(
                "POST",
                f"/requests/{rid}/reconcile",
                body=b'{"unwanted":true}',
                headers={"X-Tenant-Id": "tenant-a"},
            )
            resp = conn.getresponse()
            self.assertEqual(resp.status, 400)
            self.assertEqual(resp.read(), INVALID_REQUEST)
            conn.request(
                "POST",
                f"/requests/{rid}/reconcile",
                headers={"X-Tenant-Id": "tenant-a", "Content-Length": "0"},
            )
            resp = conn.getresponse()
            self.assertEqual(resp.status, 200)
            self.assertEqual(json.loads(resp.read())["status"], "accepted")
        finally:
            conn.close()


class ReconcileRoutingTests(_StoreCase):
    def test_non_post_methods_are_405_with_allow_post(self):
        rid = self._submit()["request_id"]
        for method in ("GET", "PUT", "DELETE", "PATCH", "OPTIONS"):
            with self.subTest(method=method):
                status, headers, data = self._request(
                    method,
                    f"/requests/{rid}/reconcile",
                    headers={"X-Tenant-Id": "tenant-a"},
                )
                self.assertEqual(status, 405)
                self.assertEqual(data, METHOD_NOT_ALLOWED)
                self.assertEqual(headers.get("Allow"), "POST")

    def test_head_is_405_headless_with_allow_post(self):
        rid = self._submit()["request_id"]
        status, headers, data = self._request(
            "HEAD",
            f"/requests/{rid}/reconcile",
            headers={"X-Tenant-Id": "tenant-a"},
        )
        self.assertEqual(status, 405)
        self.assertEqual(data, b"")
        self.assertEqual(headers.get("Allow"), "POST")
        self.assertEqual(
            headers.get("Content-Length"), str(len(METHOD_NOT_ALLOWED))
        )

    def test_deeper_and_sibling_paths_stay_404(self):
        rid = self._submit()["request_id"]
        for method, path in (
            ("POST", f"/requests/{rid}/reconcile/extra"),
            ("GET", f"/requests/{rid}/reconcile/extra"),
            ("POST", f"/requests/{rid}/reconcile/"),
            ("POST", "/requests//reconcile"),
            ("POST", f"/requests/{rid}/other"),
        ):
            with self.subTest(method=method, path=path):
                status, _, data = self._request(
                    method, path, headers={"X-Tenant-Id": "tenant-a"}
                )
                self.assertEqual(status, 404)
                self.assertEqual(data, NOT_FOUND)

    def test_unknown_path_with_any_verb_is_404(self):
        for method in ("POST", "GET", "PUT", "DELETE"):
            status, _, data = self._request(method, "/nothing/here")
            self.assertEqual(status, 404)
            self.assertEqual(data, NOT_FOUND)

    def test_existing_routes_keep_their_allow_headers(self):
        rid = self._submit()["request_id"]
        # The item resource is still GET-only.
        status, headers, _ = self._request(
            "POST", f"/requests/{rid}", headers={"X-Tenant-Id": "tenant-a"}
        )
        self.assertEqual(status, 405)
        self.assertEqual(headers.get("Allow"), "GET")
        # The status resource is still GET-only.
        status, headers, _ = self._request(
            "POST", f"/requests/{rid}/status",
            headers={"X-Tenant-Id": "tenant-a"},
        )
        self.assertEqual(status, 405)
        self.assertEqual(headers.get("Allow"), "GET")
        # The collection still accepts GET and POST.
        status, headers, _ = self._request("PUT", "/requests")
        self.assertEqual(status, 405)
        self.assertEqual(headers.get("Allow"), "GET, POST")


class ReconcileResolutionTests(_StoreCase):
    def test_missing_or_empty_tenant_is_400(self):
        rid = self._submit()["request_id"]
        for headers in (
            {},
            {"X-Tenant-Id": ""},
            {"X-Tenant-Id": "   "},
        ):
            with self.subTest(headers=headers):
                status, _, data = self._request(
                    "POST", f"/requests/{rid}/reconcile", headers=headers
                )
                self.assertEqual(status, 400)
                self.assertEqual(data, INVALID_REQUEST)
        # Blank query tenant is 400 as well.
        status, _, data = self._request(
            "POST", f"/requests/{rid}/reconcile?tenant_id="
        )
        self.assertEqual(status, 400)
        self.assertEqual(data, INVALID_REQUEST)

    def test_malformed_unknown_unaccepted_and_cross_tenant_are_404(self):
        rid = self._submit()["request_id"]
        cases = [
            (f"/requests/not-a-uuid/reconcile", "tenant-a"),
            (f"/requests/123/reconcile", "tenant-a"),
            (f"/requests/{UNKNOWN_RID}/reconcile", "tenant-a"),
            (f"/requests/{rid}/reconcile", "tenant-b"),
            (f"/requests/{rid}/reconcile?tenant_id=tenant-b", None),
        ]
        for path, tenant in cases:
            with self.subTest(path=path):
                status, _, data = self._request(
                    "POST",
                    path,
                    headers={"X-Tenant-Id": tenant} if tenant else {},
                )
                self.assertEqual(status, 404)
                self.assertEqual(data, NOT_FOUND)
                self.assertEqual(set(json.loads(data)), {"error"})

    def test_unauthenticated_ordering_id_shape_precedes_tenant(self):
        # Without auth the historical id-before-tenant order is kept.
        status, _, data = self._request(
            "POST", "/requests/not-a-uuid/reconcile"
        )
        self.assertEqual(status, 404)
        self.assertEqual(data, NOT_FOUND)

    def test_failed_resolution_writes_nothing(self):
        rid = self._submit()["request_id"]
        self._reconcile(rid, tenant="tenant-b")
        self._reconcile("not-a-uuid", tenant="tenant-a")
        self._request("POST", f"/requests/{rid}/reconcile")
        self.assertEqual(
            [e["status"] for e in self.store.audit("tenant-a", rid)],
            ["accepted"],
        )
        self.assertEqual(self.store.get_execution_log("tenant-a", rid), [])


class ReconcileStorageErrorTests(_StoreCase):
    def _broken_server(self, broken_store):
        handler = make_handler(broken_store)
        server = __import__(
            "http.server", fromlist=["ThreadingHTTPServer"]
        ).ThreadingHTTPServer(("127.0.0.1", 0), handler)
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server, thread

    def test_value_error_maps_to_400(self):
        secret = "database SECRET-SQL PATH"

        class BrokenStore:
            def reconcile_execution(self, *a, **k):
                raise ValueError(secret)

        server, _ = self._broken_server(BrokenStore())
        try:
            status, _, data = self._raw_reconcile(server)
            self.assertEqual(status, 400)
            self.assertEqual(data, INVALID_REQUEST)
        finally:
            server.shutdown()
            server.server_close()

    def test_runtime_os_sqlite_errors_map_to_503_without_leak(self):
        secret = "database is locked SECRET-SQL-DETAIL /secret/path"

        class BrokenStore:
            def reconcile_execution(self, *a, **k):
                raise RuntimeError(secret)

        server, _ = self._broken_server(BrokenStore())
        try:
            status, _, data = self._raw_reconcile(server)
            self.assertEqual(status, 503)
            self.assertEqual(data, STORAGE_UNAVAILABLE)
            self.assertNotIn(b"SECRET", data)
        finally:
            server.shutdown()
            server.server_close()

        class BrokenStore2:
            def reconcile_execution(self, *a, **k):
                raise sqlite3.OperationalError(secret)

        server, _ = self._broken_server(BrokenStore2())
        try:
            status, _, data = self._raw_reconcile(server)
            self.assertEqual(status, 503)
            self.assertNotIn(b"SECRET", data)
        finally:
            server.shutdown()
            server.server_close()

    @staticmethod
    def _raw_reconcile(server):
        port = server.server_address[1]
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        try:
            conn.request(
                "POST",
                f"/requests/{UNKNOWN_RID}/reconcile",
                headers={"X-Tenant-Id": "tenant-a"},
            )
            resp = conn.getresponse()
            return resp.status, dict(resp.getheaders()), resp.read()
        finally:
            conn.close()

    def test_corrupt_database_is_503(self):
        rid = self._submit()["request_id"]
        with open(self.db_path, "wb") as handle:
            handle.write(b"not a sqlite database")
        status, _, data = self._reconcile(rid)
        self.assertEqual(status, 503)
        self.assertEqual(data, STORAGE_UNAVAILABLE)
        self.assertNotIn(self.db_path.encode(), data)


class ReconcileConcurrencyTests(_StoreCase):
    def test_concurrent_calls_converge_exactly_once(self):
        rid = self._submit()["request_id"]
        self.store.claim_next("tenant-a", "worker-1", 1)
        time.sleep(1.15)

        def call(_index):
            conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
            try:
                conn.request(
                    "POST",
                    f"/requests/{rid}/reconcile",
                    headers={"X-Tenant-Id": "tenant-a"},
                )
                resp = conn.getresponse()
                return resp.status, resp.read()
            finally:
                conn.close()

        with ThreadPoolExecutor(max_workers=16) as pool:
            results = list(pool.map(call, range(32)))
        self.assertTrue(all(status == 200 for status, _ in results))
        bodies = {data for _, data in results}
        self.assertEqual(len(bodies), 1)
        self.assertEqual(json.loads(bodies.pop())["status"], "failed")
        log = self.store.get_execution_log("tenant-a", rid)
        self.assertEqual(len(log), 1)
        self.assertEqual(log[0]["result"], "failed")
        self.assertEqual(
            [e["status"] for e in self.store.audit("tenant-a", rid)],
            ["accepted", "processing", "failed"],
        )
        self.assertTrue(self.store.verify_evidence("tenant-a", rid))

    def test_concurrent_calls_on_terminal_all_return_the_stable_record(self):
        rid = self._submit()["request_id"]
        claim = self.store.claim_next("tenant-a", "worker-1", 60)
        terminal = self.store.finish_claim(
            "tenant-a", rid, claim["claim_token"], "completed"
        )
        log_before = self.store.get_execution_log("tenant-a", rid)

        def call(_index):
            status, _, data = self._reconcile(rid)
            return status, data

        with ThreadPoolExecutor(max_workers=16) as pool:
            results = list(pool.map(call, range(16)))
        self.assertTrue(all(status == 200 for status, _ in results))
        expected = (
            json.dumps(
                {
                    "request_id": terminal["request_id"],
                    "status": terminal["status"],
                    "created_at": terminal["created_at"],
                },
                separators=(",", ":"),
            )
            + "\n"
        ).encode()
        self.assertTrue(all(data == expected for _, data in results))
        self.assertEqual(
            self.store.get_execution_log("tenant-a", rid), log_before
        )


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


class ReconcileAuthConfigTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self._tmp.cleanup()

    def _config(self, principals):
        path = os.path.join(self._tmp.name, "auth.json")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(json.dumps({"principals": principals}))
        from forgetting_evidence.httpapi import load_auth_config

        return load_auth_config(path)

    def test_reconcile_role_loads(self):
        for roles in (
            ["request:reconcile"],
            ["request:reconcile", "request:read"],
            ["request:submit", "request:read", "request:reconcile"],
        ):
            with self.subTest(roles=roles):
                config = self._config(
                    [{"token": "t", "tenant_id": "tn", "roles": roles}]
                )
                self.assertEqual(
                    config.authenticate("t"),
                    ("tn", frozenset(roles)),
                )

    def test_legacy_roles_still_load_and_unknown_role_still_rejected(self):
        config = self._config([SUBMIT_A, READ_A, RECONCILE_B])
        self.assertIsNotNone(config.authenticate("tok-submit-a"))
        self.assertIsNotNone(config.authenticate("tok-read-a"))
        with self.assertRaises(AuthConfigError):
            self._config(
                [{"token": "t", "tenant_id": "tn",
                  "roles": ["request:reconcile", "request:delete"]}]
            )
        with self.assertRaises(AuthConfigError):
            self._config(
                [{"token": "t", "tenant_id": "tn",
                  "roles": ["request:reconcile", "request:reconcile"]}]
            )


class ReconcileHttpAuthTests(unittest.TestCase):
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

    def _reconcile(self, rid, token=None, tenant="tenant-a", raw_body=None):
        headers = {}
        if token is not None:
            headers.update(self._bearer(token))
        if tenant is not None:
            headers["X-Tenant-Id"] = tenant
        return self._request(
            "POST",
            f"/requests/{rid}/reconcile",
            raw_body=raw_body,
            headers=headers,
        )

    def test_missing_or_unknown_credential_is_401(self):
        rid = self.store.submit(
            "tenant-a", "subject-1", ["email"], "key-1"
        )["request_id"]
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
                    "POST", f"/requests/{rid}/reconcile", headers=headers
                )
                self.assertEqual(status, 401)
                self.assertEqual(data, UNAUTHORIZED)

    def test_submit_and_read_principals_are_forbidden(self):
        rid = self.store.submit(
            "tenant-a", "subject-1", ["email"], "key-1"
        )["request_id"]
        for token in ("tok-submit-a", "tok-read-a"):
            with self.subTest(token=token):
                status, _, data = self._reconcile(rid, token=token)
                self.assertEqual(status, 403)
                self.assertEqual(data, FORBIDDEN)

    def test_cross_tenant_principal_is_forbidden_before_id_probe(self):
        rid_b = self.store.submit(
            "tenant-b", "subject-1", ["email"], "key-b"
        )["request_id"]
        # Token belongs to tenant-a; target header names tenant-b, so the
        # tenant mismatch is a 403 before storage is ever touched.
        status, _, data = self._reconcile(rid_b, token="tok-reconcile-a",
                                          tenant="tenant-b")
        self.assertEqual(status, 403)
        self.assertEqual(data, FORBIDDEN)
        # A malformed foreign id is still 403: tenant authorization
        # precedes request-id validation.
        status, _, data = self._reconcile(
            "not-a-uuid", token="tok-reconcile-a", tenant="tenant-b"
        )
        self.assertEqual(status, 403)
        self.assertEqual(data, FORBIDDEN)

    def test_role_check_precedes_body_validation(self):
        rid = self.store.submit(
            "tenant-a", "subject-1", ["email"], "key-1"
        )["request_id"]
        status, _, data = self._reconcile(
            rid, token="tok-read-a", raw_body=b'{"x":1}'
        )
        self.assertEqual(status, 403)
        self.assertEqual(data, FORBIDDEN)

    def test_missing_tenant_with_valid_token_is_400(self):
        rid = self.store.submit(
            "tenant-a", "subject-1", ["email"], "key-1"
        )["request_id"]
        status, _, data = self._reconcile(rid, token="tok-reconcile-a", tenant=None)
        self.assertEqual(status, 400)
        self.assertEqual(data, INVALID_REQUEST)

    def test_authorized_reconcile_succeeds_and_compensates(self):
        rid = self.store.submit(
            "tenant-a", "subject-1", ["email"], "key-1"
        )["request_id"]
        self.store.claim_next("tenant-a", "worker-1", 1)
        time.sleep(1.15)
        status, headers, data = self._reconcile(rid, token="tok-reconcile-a")
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("Content-Type"), "application/json")
        self.assertEqual(json.loads(data)["status"], "failed")
        # The all-roles principal may reconcile as well.
        status, _, _ = self._reconcile(rid, token="tok-all-a")
        self.assertEqual(status, 200)

    def test_authorized_token_with_body_is_400(self):
        rid = self.store.submit(
            "tenant-a", "subject-1", ["email"], "key-1"
        )["request_id"]
        status, _, data = self._reconcile(
            rid, token="tok-reconcile-a", raw_body=b"{}"
        )
        self.assertEqual(status, 400)
        self.assertEqual(data, INVALID_REQUEST)

    def test_unknown_id_under_auth_is_404(self):
        status, _, data = self._reconcile(UNKNOWN_RID, token="tok-reconcile-a")
        self.assertEqual(status, 404)
        self.assertEqual(data, NOT_FOUND)

    def test_header_tenant_takes_precedence(self):
        rid_b = self.store.submit(
            "tenant-b", "subject-1", ["email"], "key-b"
        )["request_id"]
        status, _, _ = self._request(
            "POST",
            f"/requests/{rid_b}/reconcile?tenant_id=tenant-a",
            headers={**self._bearer("tok-reconcile-b"),
                     "X-Tenant-Id": "tenant-b"},
        )
        self.assertEqual(status, 200)
        status, _, data = self._request(
            "POST",
            f"/requests/{rid_b}/reconcile?tenant_id=tenant-b",
            headers={**self._bearer("tok-reconcile-b"),
                     "X-Tenant-Id": "tenant-a"},
        )
        self.assertEqual(status, 403)
        self.assertEqual(data, FORBIDDEN)

    def test_routing_precedes_authentication(self):
        # GET on the POST-only resource is 405 even without a token.
        status, headers, data = self._request(
            "GET",
            f"/requests/{UNKNOWN_RID}/reconcile",
            headers={"X-Tenant-Id": "tenant-a"},
        )
        self.assertEqual(status, 405)
        self.assertEqual(data, METHOD_NOT_ALLOWED)
        self.assertEqual(headers.get("Allow"), "POST")
        # Unknown paths stay 404 without a token.
        status, _, data = self._request("POST", "/nothing/here")
        self.assertEqual(status, 404)
        self.assertEqual(data, NOT_FOUND)

    def test_token_and_role_are_not_persisted(self):
        token = "tok-reconcile-a"
        rid = self.store.submit(
            "tenant-a", "subject-1", ["email"], "key-1"
        )["request_id"]
        status, _, _ = self._reconcile(rid, token=token)
        self.assertEqual(status, 200)
        with open(self.db_path, "rb") as handle:
            db_bytes = handle.read()
        self.assertNotIn(token.encode(), db_bytes)
        self.assertNotIn(b"request:reconcile", db_bytes)


if __name__ == "__main__":
    unittest.main()
