"""Tests for the read-only GET /policy-catalog/versions HTTP endpoint.

The endpoint publishes the tenant's policy-catalog version history
without any subject detail: the body is the verbatim single-line
compact JSON text of ``RequestStore.audit_policy_catalog``. The read
never creates or advances catalog versions, requests, attempts,
tombstones, receipts or audit records. With auth enabled it requires
the ``policy:read`` role and a matching principal tenant.
"""

import http.client
import json
import os
import sqlite3
import tempfile
import threading
import unittest

from forgetting_evidence.httpapi import (
    AuthConfig,
    DeferredRequestStore,
    build_server,
    load_auth_config,
)
from forgetting_evidence.requests import RequestStore

POLICY_A = {"token": "tok-policy-a", "tenant_id": "tenant-a",
            "roles": ["policy:read"]}
READ_A = {"token": "tok-read-a", "tenant_id": "tenant-a",
          "roles": ["request:read"]}
POLICY_B = {"token": "tok-policy-b", "tenant_id": "tenant-b",
            "roles": ["policy:read"]}

INVALID_REQUEST = b'{"error":"invalid_request"}\n'
UNAUTHORIZED = b'{"error":"unauthorized"}\n'
FORBIDDEN = b'{"error":"forbidden"}\n'
NOT_FOUND = b'{"error":"not_found"}\n'
METHOD_NOT_ALLOWED = b'{"error":"method_not_allowed"}\n'
STORAGE_UNAVAILABLE = b'{"error":"storage_unavailable"}\n'

PATH = "/policy-catalog/versions"


def _rule(selector, days, reason="ordinary reason"):
    return {"selector": selector, "days": days, "reason": reason}


def _exception(subject, selector, days, reason="exception reason"):
    return {
        "subject": subject,
        "selector": selector,
        "days": days,
        "reason": reason,
    }


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
        self.store = self._make_store()
        self._fixture = _Server(self.store, self.auth)
        self._fixture.__enter__()
        self.port = self._fixture.port

    def _make_store(self):
        return RequestStore(self.db_path)

    def tearDown(self):
        self._fixture.__exit__(None, None, None)
        self._tmp.cleanup()

    def _request(self, method, path, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request(method, path, headers=headers or {})
            resp = conn.getresponse()
            data = resp.read()
            return resp.status, dict(resp.getheaders()), data
        finally:
            conn.close()

    def _get(self, path=PATH, tenant="tenant-a", headers=None):
        merged = {"X-Tenant-Id": tenant} if tenant is not None else {}
        merged.update(headers or {})
        return self._request("GET", path, headers=merged)

    def _publish(self, tenant="tenant-a", rules=None, exceptions=None):
        return self.store.publish_policy_catalog(
            tenant,
            {"p-default": _rule("*", 30, "default retention")}
            if rules is None else rules,
            {"x-1": _exception("subject-1", "users*", 90, "legal hold")}
            if exceptions is None else exceptions,
        )


class PolicyCatalogVersionsReadTests(_Base):
    def test_empty_tenant_returns_empty_versions(self):
        status, headers, body = self._get()
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertEqual(body, b'{"versions":[]}\n')

    def test_history_matches_store_audit_verbatim(self):
        self._publish()
        self._publish(rules={
            "p-default": _rule("*", 30, "default retention"),
            "p-users": _rule("users*", 14, "shorter retention"),
        })
        expected = self.store.audit_policy_catalog("tenant-a")
        status, headers, body = self._get()
        self.assertEqual(status, 200)
        self.assertEqual(body, expected.encode("utf-8"))
        payload = json.loads(body)
        self.assertEqual(list(payload), ["versions"])
        self.assertEqual([v["version"] for v in payload["versions"]], [1, 2])
        for entry in payload["versions"]:
            self.assertEqual(
                set(entry),
                {"version", "effective_at", "rule_count",
                 "exception_count", "status"},
            )
        self.assertEqual(payload["versions"][0]["status"], False)
        self.assertEqual(payload["versions"][1]["status"], True)
        self.assertEqual(payload["versions"][1]["rule_count"], 2)
        self.assertEqual(payload["versions"][1]["exception_count"], 1)

    def test_body_never_carries_subject_or_catalog_detail(self):
        self._publish()
        _, _, body = self._get()
        for leaked in (b"subject-1", b"p-default", b"x-1", b"users*",
                       b"legal hold", b"retention", b"selector",
                       b"policy_id", b"reason", b"subject"):
            self.assertNotIn(leaked, body)

    def test_tenant_via_query_parameter(self):
        self._publish()
        status, _, body = self._get(PATH + "?tenant_id=tenant-a", tenant=None)
        self.assertEqual(status, 200)
        self.assertEqual(
            body, self.store.audit_policy_catalog("tenant-a").encode("utf-8")
        )

    def test_tenants_are_isolated(self):
        self._publish("tenant-a")
        status, _, body = self._get(tenant="tenant-b")
        self.assertEqual(status, 200)
        self.assertEqual(body, b'{"versions":[]}\n')

    def test_repeated_reads_are_byte_identical_and_read_only(self):
        self._publish()
        before = self.store.audit_policy_catalog("tenant-a")
        bodies = [self._get()[2] for _ in range(3)]
        self.assertEqual(len(set(bodies)), 1)
        self.assertEqual(bodies[0], before.encode("utf-8"))
        # The read created no version, request, attempt or tombstone.
        self.assertEqual(self.store.audit_policy_catalog("tenant-a"), before)
        self.assertEqual(
            self.store.list_requests("tenant-a"),
            {"items": [], "next_cursor": None},
        )

    def test_read_after_restart_returns_same_snapshot(self):
        self._publish()
        before = self._get()[2]
        self._fixture.__exit__(None, None, None)
        self.store = RequestStore(self.db_path)
        self._fixture = _Server(self.store, self.auth)
        self._fixture.__enter__()
        self.port = self._fixture.port
        self.assertEqual(self._get()[2], before)

    def test_missing_tenant_is_400(self):
        status, _, body = self._get(tenant=None)
        self.assertEqual(status, 400)
        self.assertEqual(body, INVALID_REQUEST)

    def test_blank_tenant_is_400(self):
        for headers in ({"X-Tenant-Id": "   "}, {"X-Tenant-Id": ""}):
            status, _, body = self._request("GET", PATH, headers=headers)
            self.assertEqual(status, 400)
            self.assertEqual(body, INVALID_REQUEST)
        status, _, body = self._get(PATH + "?tenant_id=%20%20", tenant=None)
        self.assertEqual(status, 400)
        self.assertEqual(body, INVALID_REQUEST)

    def test_unknown_query_parameter_is_400(self):
        for path in (PATH + "?tenant_id=tenant-a&cursor=abc",
                     PATH + "?tenant_id=tenant-a&limit=10",
                     PATH + "?tenant_id=tenant-a&status=current",
                     PATH + "?tenant_id=tenant-a&bogus="):
            status, _, body = self._get(path, tenant=None)
            self.assertEqual(status, 400, path)
            self.assertEqual(body, INVALID_REQUEST)

    def test_duplicate_query_key_is_400(self):
        for path in (PATH + "?tenant_id=tenant-a&tenant_id=tenant-a",
                     PATH + "?tenant_id=tenant-a&tenant_id=tenant-b"):
            status, _, body = self._get(path, tenant=None)
            self.assertEqual(status, 400, path)
            self.assertEqual(body, INVALID_REQUEST)

    def test_unsupported_methods_are_405(self):
        for method in ("PUT", "DELETE", "PATCH", "OPTIONS"):
            status, headers, body = self._request(method, PATH)
            self.assertEqual(status, 405, method)
            self.assertEqual(headers["Allow"], "GET, POST")
            self.assertEqual(body, METHOD_NOT_ALLOWED)

    def test_unknown_neighbour_paths_are_404(self):
        for path in ("/policy-catalog", "/policy-catalog/",
                     PATH + "/", PATH + "/extra", "/policy-catalogs/versions"):
            status, _, body = self._get(path)
            self.assertEqual(status, 404, path)
            self.assertEqual(body, NOT_FOUND)

    def test_corrupt_catalog_is_503_without_partial_history(self):
        self._publish()
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute(
                "UPDATE policy_catalog_rules SET days = days + 1 "
                "WHERE tenant_id = 'tenant-a'"
            )
            conn.commit()
        finally:
            conn.close()
        status, _, body = self._get()
        self.assertEqual(status, 503)
        self.assertEqual(body, STORAGE_UNAVAILABLE)

    def test_unwritable_database_is_503(self):
        blocker = os.path.join(self._tmp.name, "blocker")
        with open(blocker, "w", encoding="utf-8") as handle:
            handle.write("not a directory")
        deferred = DeferredRequestStore(os.path.join(blocker, "evidence.db"))
        with _Server(deferred) as fixture:
            conn = http.client.HTTPConnection(
                "127.0.0.1", fixture.port, timeout=10
            )
            try:
                conn.request("GET", PATH, headers={"X-Tenant-Id": "tenant-a"})
                resp = conn.getresponse()
                body = resp.read()
                self.assertEqual(resp.status, 503)
                self.assertEqual(body, STORAGE_UNAVAILABLE)
            finally:
                conn.close()


class PolicyCatalogVersionsAuthTests(_Base):
    auth = AuthConfig([POLICY_A, READ_A, POLICY_B])

    def _auth_get(self, token, path=PATH, tenant="tenant-a"):
        headers = {}
        if tenant is not None:
            headers["X-Tenant-Id"] = tenant
        if token is not None:
            headers["Authorization"] = token
        return self._request("GET", path, headers=headers)

    def test_missing_malformed_or_unknown_token_is_401(self):
        for header in (None, "tok-policy-a", "Bearer", "Bearer ",
                       "Basic tok-policy-a", "Bearer unknown-token"):
            status, _, body = self._auth_get(header)
            self.assertEqual(status, 401, header)
            self.assertEqual(body, UNAUTHORIZED)

    def test_missing_policy_read_role_is_403(self):
        status, _, body = self._auth_get("Bearer tok-read-a")
        self.assertEqual(status, 403)
        self.assertEqual(body, FORBIDDEN)

    def test_policy_read_role_reads_own_tenant(self):
        self._publish()
        status, _, body = self._auth_get("Bearer tok-policy-a")
        self.assertEqual(status, 200)
        self.assertEqual(
            body, self.store.audit_policy_catalog("tenant-a").encode("utf-8")
        )

    def test_cross_tenant_is_403(self):
        self._publish()
        status, _, body = self._auth_get("Bearer tok-policy-b")
        self.assertEqual(status, 403)
        self.assertEqual(body, FORBIDDEN)
        # Also via the query-parameter tenant.
        status, _, body = self._auth_get(
            "Bearer tok-policy-b", PATH + "?tenant_id=tenant-a", tenant=None
        )
        self.assertEqual(status, 403)
        self.assertEqual(body, FORBIDDEN)

    def test_other_tenant_principal_reads_own_empty_history(self):
        self._publish("tenant-a")
        status, _, body = self._auth_get("Bearer tok-policy-b", tenant="tenant-b")
        self.assertEqual(status, 200)
        self.assertEqual(body, b'{"versions":[]}\n')

    def test_error_bodies_never_echo_token(self):
        for header in ("Bearer tok-policy-a", "Bearer unknown-token"):
            _, _, body = self._auth_get(header, tenant="tenant-b")
            self.assertNotIn(b"tok-", body)


class PolicyCatalogAuthConfigTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self._tmp.cleanup()

    def _load(self, principals):
        path = os.path.join(self._tmp.name, "auth.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump({"principals": principals}, handle)
        return load_auth_config(path)

    def test_policy_read_role_is_accepted(self):
        config = self._load([POLICY_A])
        self.assertEqual(
            config.authenticate("tok-policy-a"),
            ("tenant-a", frozenset({"policy:read"})),
        )

    def test_existing_roles_still_load_without_policy_read(self):
        config = self._load([
            {"token": "t1", "tenant_id": "tn",
             "roles": ["request:submit", "request:read",
                       "request:reconcile"]},
        ])
        self.assertEqual(
            config.authenticate("t1"),
            ("tn",
             frozenset({"request:submit", "request:read",
                        "request:reconcile"})),
        )
        self.assertIsNone(config.authenticate("missing"))


if __name__ == "__main__":
    unittest.main()
