"""Tests for the POST /requests/{request_id}/reconcile HTTP endpoint.

Covers the single-request execution reconcile route only: the no-body
rule, the receipt-shaped success body, tenant resolution, the
404/400/405/503 error mapping, the ``request:reconcile`` role gate and
the idempotent/concurrent semantics delegated to the store's
``reconcile_execution``. Every other endpoint's contract is unchanged
and covered by the existing suites.
"""

import http.client
import json
import os
import sqlite3
import socket
import tempfile
import threading
import time
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from forgetting_evidence.httpapi import AuthConfig, build_server
from forgetting_evidence.requests import RequestStore


def _parse_utc(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


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


INVALID_REQUEST = b'{"error":"invalid_request"}\n'
UNAUTHORIZED = b'{"error":"unauthorized"}\n'
FORBIDDEN = b'{"error":"forbidden"}\n'
NOT_FOUND = b'{"error":"not_found"}\n'
METHOD_NOT_ALLOWED = b'{"error":"method_not_allowed"}\n'
STORAGE_UNAVAILABLE = b'{"error":"storage_unavailable"}\n'


class HttpReconcileTests(unittest.TestCase):
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

    # -- helpers -------------------------------------------------------

    def _request(self, method, path, body=None, headers=None, raw_body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            kwargs = {}
            if raw_body is not None:
                kwargs["body"] = raw_body
            elif body is not None:
                kwargs["body"] = json.dumps(body)
            conn.request(method, path, headers=headers or {}, **kwargs)
            resp = conn.getresponse()
            data = resp.read()
            return resp.status, dict(resp.getheaders()), data
        finally:
            conn.close()

    def _submit(self, tenant="tenant-a", key="key-1", subject="subject-1"):
        status, _, data = self._request(
            "POST",
            "/requests",
            body={
                "tenant_id": tenant,
                "subject_id": subject,
                "idempotency_key": key,
                "scopes": ["email", "profile"],
            },
        )
        self.assertEqual(status, 200)
        return json.loads(data)

    def _reconcile(self, request_id, tenant="tenant-a", **kwargs):
        headers = kwargs.pop("headers", {})
        if tenant is not None:
            headers = {**headers, "X-Tenant-Id": tenant}
        return self._request(
            "POST", f"/requests/{request_id}/reconcile", headers=headers, **kwargs
        )

    # -- success shape ---------------------------------------------------

    def test_reconcile_accepted_returns_current_record(self):
        receipt = self._submit()
        status, headers, data = self._reconcile(receipt["request_id"])
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("Content-Type"), "application/json")
        # Single line, fixed field order, exactly the three fields.
        self.assertTrue(data.endswith(b"\n"))
        self.assertEqual(data.count(b"\n"), 1)
        self.assertTrue(data.startswith(b'{"request_id":"'), data)
        record = json.loads(data)
        self.assertEqual(list(record), ["request_id", "status", "created_at"])
        self.assertEqual(record["request_id"], receipt["request_id"])
        self.assertEqual(record["status"], "accepted")
        self.assertEqual(record["created_at"], receipt["created_at"])
        uuid.UUID(record["request_id"])
        self.assertEqual(
            _parse_utc(record["created_at"]).utcoffset().total_seconds(), 0
        )
        # The accepted reconcile writes nothing: no attempt, same receipt.
        self.assertEqual(
            self.store.get_execution_log("tenant-a", receipt["request_id"]), []
        )
        self.assertEqual(
            self.store.get("tenant-a", receipt["request_id"]), receipt
        )

    def test_reconcile_body_matches_status_read_after_reconcile(self):
        receipt = self._submit()
        status, _, data = self._reconcile(receipt["request_id"])
        self.assertEqual(status, 200)
        status, _, status_data = self._request(
            "GET",
            f"/requests/{receipt['request_id']}/status",
            headers={"X-Tenant-Id": "tenant-a"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(data, status_data)

    def test_reconcile_without_content_length_succeeds(self):
        # http.client sends no Content-Length for a bodyless request.
        receipt = self._submit()
        status, _, data = self._reconcile(receipt["request_id"])
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)["status"], "accepted")

    def test_reconcile_with_zero_content_length_succeeds(self):
        receipt = self._submit()
        status, _, data = self._request(
            "POST",
            f"/requests/{receipt['request_id']}/reconcile",
            raw_body=b"",
            headers={"X-Tenant-Id": "tenant-a"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)["request_id"], receipt["request_id"])

    def test_reconcile_tenant_via_query_parameter(self):
        receipt = self._submit()
        status, _, data = self._reconcile(
            receipt["request_id"], tenant=None
        )
        # No tenant anywhere is a 400...
        self.assertEqual(status, 400)
        self.assertEqual(data, INVALID_REQUEST)
        # ...while the query parameter resolves the tenant like the GETs.
        status, _, data = self._request(
            "POST",
            f"/requests/{receipt['request_id']}/reconcile?tenant_id=tenant-a",
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)["status"], "accepted")

    # -- no-body rule ----------------------------------------------------

    def test_reconcile_with_any_body_is_400(self):
        receipt = self._submit()
        for raw_body in (b"{}", b"x", b'{"tenant_id":"tenant-a"}', b"\x00" * 16):
            with self.subTest(raw_body=raw_body):
                status, _, data = self._reconcile(
                    receipt["request_id"], raw_body=raw_body
                )
                self.assertEqual(status, 400)
                self.assertEqual(data, INVALID_REQUEST)
                self.assertEqual(set(json.loads(data)), {"error"})
        # The rejected calls wrote nothing and the request still reconciles.
        self.assertEqual(
            self.store.get_execution_log("tenant-a", receipt["request_id"]), []
        )
        status, _, data = self._reconcile(receipt["request_id"])
        self.assertEqual(status, 200)

    def test_reconcile_with_unparseable_content_length_is_400(self):
        receipt = self._submit()
        with socket.create_connection(("127.0.0.1", self.port), timeout=10) as sock:
            sock.sendall(
                (
                    f"POST /requests/{receipt['request_id']}/reconcile HTTP/1.1\r\n"
                    "Host: x\r\nX-Tenant-Id: tenant-a\r\n"
                    "Content-Length: abc\r\nConnection: close\r\n\r\n"
                ).encode()
            )
            raw = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                raw += chunk
        self.assertIn(b" 400 ", raw.split(b"\r\n", 1)[0])
        self.assertIn(INVALID_REQUEST.strip(), raw)

    # -- 400 / 404 mapping -------------------------------------------------

    def test_reconcile_missing_or_blank_tenant_is_400(self):
        receipt = self._submit()
        status, _, data = self._reconcile(receipt["request_id"], tenant=None)
        self.assertEqual(status, 400)
        self.assertEqual(data, INVALID_REQUEST)
        status, _, data = self._request(
            "POST",
            f"/requests/{receipt['request_id']}/reconcile",
            headers={"X-Tenant-Id": "   "},
        )
        self.assertEqual(status, 400)
        self.assertEqual(data, INVALID_REQUEST)

    def test_reconcile_malformed_unknown_and_cross_tenant_ids_are_404(self):
        receipt = self._submit()
        other = self._submit(tenant="tenant-b", key="key-b")
        unknown = "00000000-0000-4000-8000-000000000000"
        for request_id in ("not-a-uuid", unknown, other["request_id"]):
            with self.subTest(request_id=request_id):
                status, _, data = self._reconcile(request_id)
                self.assertEqual(status, 404)
                self.assertEqual(data, NOT_FOUND)
        # Upper-case spellings of a real id canonicalise and reconcile.
        status, _, data = self._reconcile(receipt["request_id"].upper())
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)["request_id"], receipt["request_id"])

    # -- reconciliation semantics through HTTP ----------------------------

    def test_reconcile_converges_expired_lease_to_failed(self):
        receipt = self._submit()
        claim = self.store.claim_next("tenant-a", "worker-1", 1)
        self.assertEqual(claim["request_id"], receipt["request_id"])
        time.sleep(1.15)
        status, _, data = self._reconcile(receipt["request_id"])
        self.assertEqual(status, 200)
        record = json.loads(data)
        self.assertEqual(record["status"], "failed")
        self.assertEqual(record["created_at"], receipt["created_at"])
        # The abandoned attempt was compensated exactly once.
        log = self.store.get_execution_log("tenant-a", receipt["request_id"])
        self.assertEqual(len(log), 1)
        self.assertEqual(log[0]["result"], "failed")
        first_completed_at = log[0]["completed_at"]
        self.assertIsNotNone(first_completed_at)
        # A repeated reconcile is byte-identical and writes nothing more.
        status, _, again = self._reconcile(receipt["request_id"])
        self.assertEqual(status, 200)
        self.assertEqual(again, data)
        log = self.store.get_execution_log("tenant-a", receipt["request_id"])
        self.assertEqual(len(log), 1)
        self.assertEqual(log[0]["completed_at"], first_completed_at)

    def test_reconcile_live_lease_keeps_processing(self):
        receipt = self._submit()
        claim = self.store.claim_next("tenant-a", "worker-1", 3600)
        status, _, data = self._reconcile(receipt["request_id"])
        self.assertEqual(status, 200)
        record = json.loads(data)
        self.assertEqual(record["status"], "processing")
        self.assertEqual(record["created_at"], receipt["created_at"])
        # No terminal result written early, no new attempt generated.
        log = self.store.get_execution_log("tenant-a", receipt["request_id"])
        self.assertEqual(len(log), 1)
        self.assertIsNone(log[0]["result"])
        # The live credential still finishes the claim afterwards.
        done = self.store.finish_claim(
            "tenant-a", receipt["request_id"], claim["claim_token"], "completed"
        )
        self.assertEqual(done["status"], "completed")

    def test_reconcile_terminal_is_idempotent_noop(self):
        receipt = self._submit()
        claim = self.store.claim_next("tenant-a", "worker-1", 3600)
        self.store.finish_claim(
            "tenant-a", receipt["request_id"], claim["claim_token"], "completed"
        )
        status, _, data = self._reconcile(receipt["request_id"])
        self.assertEqual(status, 200)
        record = json.loads(data)
        self.assertEqual(record["status"], "completed")
        self.assertEqual(record["created_at"], receipt["created_at"])
        status, _, again = self._reconcile(receipt["request_id"])
        self.assertEqual(status, 200)
        self.assertEqual(again, data)
        log = self.store.get_execution_log("tenant-a", receipt["request_id"])
        self.assertEqual(len(log), 1)
        self.assertEqual(log[0]["result"], "completed")

    def test_concurrent_reconcile_converges_once(self):
        receipt = self._submit()
        self.store.claim_next("tenant-a", "worker-1", 1)
        time.sleep(1.15)
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(
                pool.map(
                    lambda _: self._reconcile(receipt["request_id"]),
                    range(8),
                )
            )
        bodies = {data for _, _, data in results}
        for status, _, _ in results:
            self.assertEqual(status, 200)
        # One unique outcome: every caller saw the same converged record.
        self.assertEqual(len(bodies), 1)
        self.assertEqual(json.loads(bodies.pop())["status"], "failed")
        log = self.store.get_execution_log("tenant-a", receipt["request_id"])
        self.assertEqual(len(log), 1)
        self.assertEqual(log[0]["result"], "failed")

    # -- 405 / routing -----------------------------------------------------

    def test_non_post_methods_on_reconcile_are_405_with_allow_post(self):
        receipt = self._submit()
        path = f"/requests/{receipt['request_id']}/reconcile"
        for method in ("GET", "PUT", "DELETE", "PATCH", "OPTIONS"):
            with self.subTest(method=method):
                status, headers, data = self._request(
                    method, path, headers={"X-Tenant-Id": "tenant-a"}
                )
                self.assertEqual(status, 405)
                self.assertEqual(data, METHOD_NOT_ALLOWED)
                self.assertEqual(headers.get("Allow"), "POST")
        # The 405s did not reconcile anything.
        self.assertEqual(
            self.store.get_status("tenant-a", receipt["request_id"])["status"],
            "accepted",
        )

    def test_head_on_reconcile_has_no_body(self):
        receipt = self._submit()
        status, headers, data = self._request(
            "HEAD",
            f"/requests/{receipt['request_id']}/reconcile",
            headers={"X-Tenant-Id": "tenant-a"},
        )
        self.assertEqual(status, 405)
        self.assertEqual(data, b"")
        self.assertEqual(headers.get("Allow"), "POST")
        self.assertEqual(
            headers.get("Content-Length"), str(len(METHOD_NOT_ALLOWED))
        )

    def test_deeper_paths_below_reconcile_are_404(self):
        receipt = self._submit()
        for method in ("GET", "POST"):
            with self.subTest(method=method):
                status, _, data = self._request(
                    method,
                    f"/requests/{receipt['request_id']}/reconcile/extra",
                    headers={"X-Tenant-Id": "tenant-a"},
                )
                self.assertEqual(status, 404)
                self.assertEqual(data, NOT_FOUND)

    def test_existing_routes_keep_their_method_contract(self):
        # The new sub-resource did not change sibling routes: POST on the
        # item and the read-only sub-resources stays 405 with Allow: GET.
        receipt = self._submit()
        request_id = receipt["request_id"]
        for path in (
            f"/requests/{request_id}",
            f"/requests/{request_id}/status",
            f"/requests/{request_id}/execution-log",
        ):
            with self.subTest(path=path):
                status, headers, data = self._request("POST", path)
                self.assertEqual(status, 405)
                self.assertEqual(data, METHOD_NOT_ALLOWED)
                self.assertEqual(headers.get("Allow"), "GET")

    # -- 503 storage unavailable ------------------------------------------

    def test_corrupt_database_returns_503(self):
        receipt = self._submit()
        with open(self.db_path, "wb") as handle:
            handle.write(b"this is definitely not a sqlite database")
        status, _, data = self._reconcile(receipt["request_id"])
        self.assertEqual(status, 503)
        self.assertEqual(data, STORAGE_UNAVAILABLE)

    def test_store_exception_becomes_503_without_leak(self):
        secret = "database is locked SECRET-SQL-DETAIL"

        class BrokenStore:
            def reconcile_execution(self, *a, **k):
                raise sqlite3.OperationalError(secret)

        fixture = _Server(BrokenStore())
        fixture.__enter__()
        try:
            conn = http.client.HTTPConnection(
                "127.0.0.1", fixture.port, timeout=10
            )
            try:
                conn.request(
                    "POST",
                    "/requests/00000000-0000-4000-8000-000000000000/reconcile",
                    headers={"X-Tenant-Id": "tenant-a"},
                )
                resp = conn.getresponse()
                data = resp.read()
                self.assertEqual(resp.status, 503)
                self.assertEqual(data, STORAGE_UNAVAILABLE)
                self.assertNotIn(b"SECRET", data)
            finally:
                conn.close()
        finally:
            fixture.__exit__(None, None, None)

    # -- no leakage ---------------------------------------------------------

    def test_reconcile_response_does_not_leak_request_fields(self):
        secret_subject = "subject-SECRETXYZ"
        secret_key = "key-SECRETXYZ"
        status, _, data = self._request(
            "POST",
            "/requests",
            body={
                "tenant_id": "tenant-a",
                "subject_id": secret_subject,
                "idempotency_key": secret_key,
                "scopes": ["scope-SECRETXYZ"],
            },
        )
        self.assertEqual(status, 200)
        request_id = json.loads(data)["request_id"]
        status, _, data = self._reconcile(request_id)
        self.assertEqual(status, 200)
        self.assertNotIn(secret_subject.encode(), data)
        self.assertNotIn(secret_key.encode(), data)
        self.assertNotIn(b"scope-SECRETXYZ", data)
        self.assertEqual(set(json.loads(data)), {"request_id", "status", "created_at"})


class HttpReconcileAuthTests(unittest.TestCase):
    PRINCIPALS = [
        {"token": "tok-submit-a", "tenant_id": "tenant-a",
         "roles": ["request:submit"]},
        {"token": "tok-read-a", "tenant_id": "tenant-a",
         "roles": ["request:read"]},
        {"token": "tok-reconcile-a", "tenant_id": "tenant-a",
         "roles": ["request:reconcile"]},
        {"token": "tok-all-a", "tenant_id": "tenant-a",
         "roles": ["request:submit", "request:read", "request:reconcile"]},
        {"token": "tok-reconcile-b", "tenant_id": "tenant-b",
         "roles": ["request:reconcile"]},
    ]

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "evidence.db")
        self.store = RequestStore(self.db_path)
        self.auth = AuthConfig(self.PRINCIPALS)
        self._fixture = _Server(self.store, self.auth)
        self._fixture.__enter__()
        self.port = self._fixture.port

    def tearDown(self):
        self._fixture.__exit__(None, None, None)
        self._tmp.cleanup()

    def _request(self, method, path, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request(method, path, headers=headers or {})
            resp = conn.getresponse()
            return resp.status, dict(resp.getheaders()), resp.read()
        finally:
            conn.close()

    def _bearer(self, token):
        return {"Authorization": f"Bearer {token}"}

    def _seed(self, tenant="tenant-a", key="key-1"):
        return self.store.submit(tenant, "subject-1", ["email"], key)

    def _reconcile_path(self, request_id):
        return f"/requests/{request_id}/reconcile"

    # -- 401 ------------------------------------------------------------

    def test_reconcile_requires_bearer_token(self):
        receipt = self._seed()
        for headers in (
            {},
            {"Authorization": ""},
            {"Authorization": "Basic tok-reconcile-a"},
            {"Authorization": "Bearer"},
            {"Authorization": "Bearer "},
            {"Authorization": "Bearer unknown-token"},
        ):
            with self.subTest(headers=headers):
                merged = {**headers, "X-Tenant-Id": "tenant-a"}
                status, _, data = self._request(
                    "POST", self._reconcile_path(receipt["request_id"]),
                    headers=merged,
                )
                self.assertEqual(status, 401)
                self.assertEqual(data, UNAUTHORIZED)

    # -- 403 ------------------------------------------------------------

    def test_reconcile_requires_reconcile_role(self):
        receipt = self._seed()
        for token in ("tok-submit-a", "tok-read-a"):
            with self.subTest(token=token):
                status, _, data = self._request(
                    "POST", self._reconcile_path(receipt["request_id"]),
                    headers={**self._bearer(token), "X-Tenant-Id": "tenant-a"},
                )
                self.assertEqual(status, 403)
                self.assertEqual(data, FORBIDDEN)
        # Nothing was reconciled or written by the rejected calls.
        self.assertEqual(
            self.store.get_status("tenant-a", receipt["request_id"])["status"],
            "accepted",
        )

    def test_reconcile_for_other_tenant_is_forbidden(self):
        receipt_b = self._seed(tenant="tenant-b", key="key-b")
        # A tenant-a principal naming tenant-b is forbidden before any
        # request-id validation or storage access.
        status, _, data = self._request(
            "POST", self._reconcile_path(receipt_b["request_id"]),
            headers={**self._bearer("tok-reconcile-a"),
                     "X-Tenant-Id": "tenant-b"},
        )
        self.assertEqual(status, 403)
        self.assertEqual(data, FORBIDDEN)
        # A malformed foreign id is still 403, never 404.
        status, _, data = self._request(
            "POST", "/requests/not-a-uuid/reconcile",
            headers={**self._bearer("tok-reconcile-a"),
                     "X-Tenant-Id": "tenant-b"},
        )
        self.assertEqual(status, 403)
        self.assertEqual(data, FORBIDDEN)

    # -- authorized success --------------------------------------------

    def test_reconcile_role_succeeds_and_matches_status_read(self):
        receipt = self._seed()
        status, _, data = self._request(
            "POST", self._reconcile_path(receipt["request_id"]),
            headers={**self._bearer("tok-reconcile-a"),
                     "X-Tenant-Id": "tenant-a"},
        )
        self.assertEqual(status, 200)
        record = json.loads(data)
        self.assertEqual(list(record), ["request_id", "status", "created_at"])
        self.assertEqual(record["status"], "accepted")
        # The triple-role principal gets the same record via the query
        # parameter tenant rule.
        status, _, again = self._request(
            "POST",
            self._reconcile_path(receipt["request_id"]) + "?tenant_id=tenant-a",
            headers=self._bearer("tok-all-a"),
        )
        self.assertEqual(status, 200)
        self.assertEqual(again, data)

    def test_reconcile_unknown_or_cross_tenant_id_is_404_when_authorized(self):
        receipt_b = self._seed(tenant="tenant-b", key="key-b")
        unknown = "00000000-0000-4000-8000-000000000000"
        for request_id in (unknown, receipt_b["request_id"]):
            with self.subTest(request_id=request_id):
                status, _, data = self._request(
                    "POST", self._reconcile_path(request_id),
                    headers={**self._bearer("tok-reconcile-a"),
                             "X-Tenant-Id": "tenant-a"},
                )
                self.assertEqual(status, 404)
                self.assertEqual(data, NOT_FOUND)

    def test_reconcile_missing_tenant_with_valid_token_is_400(self):
        receipt = self._seed()
        status, _, data = self._request(
            "POST", self._reconcile_path(receipt["request_id"]),
            headers=self._bearer("tok-reconcile-a"),
        )
        self.assertEqual(status, 400)
        self.assertEqual(data, INVALID_REQUEST)

    # -- ordering: routing before auth ------------------------------------

    def test_unsupported_method_stays_405_even_without_token(self):
        receipt = self._seed()
        status, headers, data = self._request(
            "GET", self._reconcile_path(receipt["request_id"])
        )
        self.assertEqual(status, 405)
        self.assertEqual(data, METHOD_NOT_ALLOWED)
        self.assertEqual(headers.get("Allow"), "POST")

    def test_unknown_path_stays_404_without_token(self):
        status, _, data = self._request("POST", "/nothing/here")
        self.assertEqual(status, 404)
        self.assertEqual(data, NOT_FOUND)

    def test_role_check_precedes_body_validation(self):
        # A submit-only principal sending a body still gets 403, not 400.
        receipt = self._seed()
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request(
                "POST", self._reconcile_path(receipt["request_id"]),
                body=b"{}",
                headers={**self._bearer("tok-submit-a"),
                         "X-Tenant-Id": "tenant-a"},
            )
            resp = conn.getresponse()
            self.assertEqual(resp.status, 403)
            self.assertEqual(resp.read(), FORBIDDEN)
        finally:
            conn.close()

    def test_reconcile_role_token_is_not_persisted(self):
        receipt = self._seed()
        status, _, _ = self._request(
            "POST", self._reconcile_path(receipt["request_id"]),
            headers={**self._bearer("tok-reconcile-a"),
                     "X-Tenant-Id": "tenant-a"},
        )
        self.assertEqual(status, 200)
        with open(self.db_path, "rb") as handle:
            db_bytes = handle.read()
        self.assertNotIn(b"tok-reconcile-a", db_bytes)
        self.assertNotIn(b"request:reconcile", db_bytes)


class ReconcileAuthConfigTests(unittest.TestCase):
    def test_reconcile_role_loads_and_old_roles_still_load(self):
        config = AuthConfig([
            {"token": "t1", "tenant_id": "tn",
             "roles": ["request:submit", "request:read"]},
            {"token": "t2", "tenant_id": "tn", "roles": ["request:reconcile"]},
        ])
        self.assertEqual(
            config.authenticate("t1"),
            ("tn", frozenset({"request:submit", "request:read"})),
        )
        self.assertEqual(
            config.authenticate("t2"), ("tn", frozenset({"request:reconcile"}))
        )


if __name__ == "__main__":
    unittest.main()
