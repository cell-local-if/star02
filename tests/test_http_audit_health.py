"""Tests for the read-only GET /audit-health endpoint.

Covers the single-line compact JSON shape (exactly ``total``,
``statuses``, ``verified``, ``unverified`` and ``reasons`` in that
order, one trailing newline), the four lifecycle status counts with
explicit zeros, the merged Unicode-ordered reason list, the tenant
resolution rules (header overrides query, a single ``tenant_id`` query
key only), the error mapping (400/401/403/404/405/503), the all-zero
snapshot for an unknown tenant, byte-identical repeated reads, strictly
read-only behaviour (no inspection batch, cursor or evidence writes)
and the absence of any tenant, request id, SQL or path leakage.
"""

import http.client
import json
import os
import sqlite3
import tempfile
import threading
import unittest

from forgetting_evidence.httpapi import AuthConfig, build_server
from forgetting_evidence.requests import RequestStore

NOT_FOUND = b'{"error":"not_found"}\n'
INVALID_REQUEST = b'{"error":"invalid_request"}\n'
METHOD_NOT_ALLOWED = b'{"error":"method_not_allowed"}\n'
STORAGE_UNAVAILABLE = b'{"error":"storage_unavailable"}\n'
UNAUTHORIZED = b'{"error":"unauthorized"}\n'
FORBIDDEN = b'{"error":"forbidden"}\n'

FIELDS = ["total", "statuses", "verified", "unverified", "reasons"]
STATUS_NAMES = ["accepted", "processing", "completed", "failed"]
SECRET = "anchor-secret-alpha-0001"


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


class AuditHealthEndpointTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "health.db")
        self.store = RequestStore(self.db_path, anchor_secret=SECRET)
        self._fixture = _Server(self.store)
        self._fixture.__enter__()
        self.port = self._fixture.port

    def tearDown(self):
        self._fixture.__exit__(None, None, None)
        self._tmp.cleanup()

    def _request(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            kwargs = {}
            if body is not None:
                kwargs["body"] = json.dumps(body)
            conn.request(method, path, headers=headers or {}, **kwargs)
            resp = conn.getresponse()
            return resp.status, dict(resp.getheaders()), resp.read()
        finally:
            conn.close()

    def _get(self, path, tenant="tenant-a"):
        return self._request(
            "GET", path, headers={"X-Tenant-Id": tenant} if tenant else {}
        )

    def _health(self, tenant="tenant-a"):
        return self._get("/audit-health", tenant)

    def _submit_many(self, count, tenant="tenant-a"):
        return [
            self.store.submit(tenant, f"subject-{i}", ["email"], f"key-{i}")[
                "request_id"
            ]
            for i in range(count)
        ]

    def _raw(self):
        return sqlite3.connect(self.db_path)

    def _table_dump(self, table):
        with self._raw() as raw:
            return raw.execute(f"SELECT * FROM {table}").fetchall()

    # -- success shape --------------------------------------------------

    def test_empty_tenant_is_all_zeros(self):
        status, headers, data = self._health()
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("Content-Type"), "application/json")
        self.assertEqual(
            data,
            b'{"total":0,"statuses":{"accepted":0,"processing":0,'
            b'"completed":0,"failed":0},"verified":0,"unverified":0,'
            b'"reasons":[]}\n',
        )

    def test_counts_and_field_order(self):
        ids = self._submit_many(4)
        claim = self.store.claim_next("tenant-a", "worker-1", 300)
        self.store.finish_claim(
            "tenant-a", ids[0], claim["claim_token"], "completed"
        )
        self.store.transition("tenant-a", ids[1], "processing")
        self.store.transition("tenant-a", ids[2], "failed")
        status, headers, data = self._health()
        self.assertEqual(status, 200)
        self.assertTrue(data.endswith(b"\n"))
        self.assertEqual(data.count(b"\n"), 1)
        record = json.loads(data)
        self.assertEqual(list(record), FIELDS)
        self.assertEqual(list(record["statuses"]), STATUS_NAMES)
        self.assertEqual(record["total"], 4)
        self.assertEqual(
            record["statuses"],
            {"accepted": 1, "processing": 1, "completed": 1, "failed": 1},
        )
        self.assertEqual(record["verified"], 4)
        self.assertEqual(record["unverified"], 0)
        self.assertEqual(record["reasons"], [])
        # The invariants hold and the rendering is compact.
        self.assertEqual(
            record["total"],
            sum(record["statuses"].values()),
        )
        self.assertEqual(
            record["total"], record["verified"] + record["unverified"]
        )
        self.assertEqual(
            data,
            b'{"total":4,"statuses":{"accepted":1,"processing":1,'
            b'"completed":1,"failed":1},"verified":4,"unverified":0,'
            b'"reasons":[]}\n',
        )

    def test_tenants_are_isolated_and_unknown_tenant_is_zero(self):
        self._submit_many(2, tenant="tenant-a")
        self._submit_many(3, tenant="tenant-b")
        status, _, data = self._health("tenant-a")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)["total"], 2)
        status, _, data = self._health("tenant-b")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)["total"], 3)
        # A tenant that does not exist is an all-zero snapshot, not an
        # error.
        status, _, data = self._health("tenant-never-seen")
        self.assertEqual(status, 200)
        record = json.loads(data)
        self.assertEqual(record["total"], 0)
        self.assertEqual(record["statuses"], {name: 0 for name in STATUS_NAMES})
        self.assertEqual(record["reasons"], [])

    def test_unverified_requests_render_merged_sorted_reasons(self):
        # A historical no-secret store leaves a legacy un-anchored
        # database; every request is unverified with the stable reason.
        legacy = RequestStore(self.db_path)
        for i in range(2):
            legacy.submit("tenant-a", f"subject-{i}", ["email"], f"key-{i}")
        status, _, data = self._health()
        self.assertEqual(status, 200)
        record = json.loads(data)
        self.assertEqual(record["total"], 2)
        self.assertEqual(record["verified"], 0)
        self.assertEqual(record["unverified"], 2)
        self.assertEqual(
            record["reasons"],
            [{"reason": "unanchored_database", "count": 2}],
        )
        self.assertEqual(list(record["reasons"][0]), ["reason", "count"])

    def test_repeated_reads_are_byte_identical(self):
        self._submit_many(2)
        first = self._health()
        second = self._health()
        self.assertEqual(first[0], 200)
        self.assertEqual(first[2], second[2])

    def test_tenant_query_parameter_and_header_precedence(self):
        self._submit_many(1, tenant="tenant-a")
        status, _, data = self._request("GET", "/audit-health?tenant_id=tenant-a")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)["total"], 1)
        # The header wins over the query parameter.
        status, _, data = self._get(
            "/audit-health?tenant_id=tenant-b", tenant="tenant-a"
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)["total"], 1)

    # -- read-only behaviour ---------------------------------------------

    def test_read_never_writes_anything(self):
        self._submit_many(2)
        with self._raw() as raw:
            tables = [
                row[0]
                for row in raw.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            ]
            before = {table: self._table_dump(table) for table in tables}
        status, _, _ = self._health()
        self.assertEqual(status, 200)
        after = {table: self._table_dump(table) for table in tables}
        self.assertEqual(before, after)
        # In particular no inspection batch or cursor was created.
        self.assertEqual(after["inspection_batches"], [])
        self.assertEqual(after["inspection_batch_items"], [])

    # -- client errors ----------------------------------------------------

    def test_missing_or_empty_tenant_is_400(self):
        for path, tenant in (
            ("/audit-health", None),
            ("/audit-health", ""),
            ("/audit-health?tenant_id=", None),
            ("/audit-health?tenant_id=%20", None),
        ):
            status, _, data = self._get(path, tenant)
            self.assertEqual(status, 400, (path, tenant))
            self.assertEqual(data, INVALID_REQUEST)

    def test_duplicate_or_unknown_query_parameter_is_400(self):
        for path in (
            "/audit-health?tenant_id=tenant-a&tenant_id=tenant-a",
            "/audit-health?tenant_id=tenant-a&tenant_id=tenant-b",
            "/audit-health?cursor=abc",
            "/audit-health?limit=10",
            "/audit-health?tenant_id=tenant-a&unknown=1",
        ):
            status, _, data = self._get(path)
            self.assertEqual(status, 400, path)
            self.assertEqual(data, INVALID_REQUEST)

    def test_unknown_paths_are_404(self):
        for path in (
            "/audit-health/",
            "/audit-health/extra",
            "/audit",
            "/audit-healthx",
        ):
            status, _, data = self._get(path)
            self.assertEqual(status, 404, path)
            self.assertEqual(data, NOT_FOUND)

    def test_unsupported_methods_are_405_with_allow_get(self):
        for method in ("POST", "PUT", "DELETE", "PATCH", "OPTIONS"):
            status, headers, data = self._request(method, "/audit-health")
            self.assertEqual(status, 405, method)
            self.assertEqual(headers.get("Allow"), "GET")
            self.assertEqual(data, METHOD_NOT_ALLOWED)
        # HEAD is header-only but routes the same way.
        status, headers, data = self._request("HEAD", "/audit-health")
        self.assertEqual(status, 405)
        self.assertEqual(headers.get("Allow"), "GET")
        self.assertEqual(data, b"")

    # -- storage failures ---------------------------------------------------

    def test_corrupt_bookkeeping_is_503_without_leakage(self):
        self._submit_many(1)
        with self._raw() as raw:
            raw.execute("DROP TABLE status_events")
        status, _, data = self._health()
        self.assertEqual(status, 503)
        self.assertEqual(data, STORAGE_UNAVAILABLE)

    def test_unknown_status_value_is_503(self):
        self._submit_many(1)
        with self._raw() as raw:
            raw.execute("UPDATE requests SET status = 'bogus'")
        status, _, data = self._health()
        self.assertEqual(status, 503)
        self.assertEqual(data, STORAGE_UNAVAILABLE)


class AuditHealthAuthTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "health.db")
        self.store = RequestStore(self.db_path, anchor_secret=SECRET)
        self.store.submit("tenant-a", "subject-1", ["email"], "key-1")
        self.auth = AuthConfig(
            [
                {
                    "token": "token-reader-a",
                    "tenant_id": "tenant-a",
                    "roles": ["request:read"],
                },
                {
                    "token": "token-submitter-a",
                    "tenant_id": "tenant-a",
                    "roles": ["request:submit"],
                },
                {
                    "token": "token-reader-b",
                    "tenant_id": "tenant-b",
                    "roles": ["request:read"],
                },
            ]
        )
        self._fixture = _Server(self.store, auth=self.auth)
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

    def _get(self, path, token=None, tenant="tenant-a"):
        headers = {}
        if token is not None:
            headers["Authorization"] = token
        if tenant is not None:
            headers["X-Tenant-Id"] = tenant
        return self._request("GET", path, headers=headers)

    def test_reader_gets_own_tenant_snapshot(self):
        status, _, data = self._get(
            "/audit-health", token="Bearer token-reader-a"
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)["total"], 1)

    def test_missing_malformed_or_unknown_token_is_401(self):
        for header in (None, "Bearer", "Bearer ", "Token token-reader-a",
                       "Bearer no-such-token"):
            status, _, data = self._get("/audit-health", token=header)
            self.assertEqual(status, 401, header)
            self.assertEqual(data, UNAUTHORIZED)

    def test_missing_role_is_403(self):
        status, _, data = self._get(
            "/audit-health", token="Bearer token-submitter-a"
        )
        self.assertEqual(status, 403)
        self.assertEqual(data, FORBIDDEN)

    def test_cross_tenant_is_403(self):
        # tenant-b's reader cannot read tenant-a's summary, whether the
        # tenant arrives by header or by query.
        status, _, data = self._get(
            "/audit-health", token="Bearer token-reader-b", tenant="tenant-a"
        )
        self.assertEqual(status, 403)
        self.assertEqual(data, FORBIDDEN)
        status, _, data = self._get(
            "/audit-health?tenant_id=tenant-a",
            token="Bearer token-reader-b",
            tenant=None,
        )
        self.assertEqual(status, 403)
        self.assertEqual(data, FORBIDDEN)
        # Its own tenant works and reports its own (zero) counts.
        status, _, data = self._get(
            "/audit-health", token="Bearer token-reader-b", tenant="tenant-b"
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)["total"], 0)

    def test_routing_precedes_authentication(self):
        # Unknown paths stay 404 and unsupported methods stay 405 even
        # without a token.
        status, _, data = self._get("/no-such-path")
        self.assertEqual(status, 404)
        self.assertEqual(data, NOT_FOUND)
        status, headers, data = self._request("POST", "/audit-health")
        self.assertEqual(status, 405)
        self.assertEqual(headers.get("Allow"), "GET")
        self.assertEqual(data, METHOD_NOT_ALLOWED)


if __name__ == "__main__":
    unittest.main()
