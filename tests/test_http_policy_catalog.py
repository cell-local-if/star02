"""Tests for the /policy-catalog/versions HTTP endpoints.

GET publishes the tenant's policy-catalog version history without any
subject detail: the body is the verbatim single-line compact JSON text
of ``RequestStore.audit_policy_catalog``. The read never creates or
advances catalog versions, requests, attempts, tombstones, receipts or
audit records. With auth enabled it requires the ``policy:read`` role
and a matching principal tenant.

POST is the only catalog publication entry point: it freezes the body's
``rules``/``exceptions`` catalog for the body's ``tenant_id`` as one
immutable version and answers exactly ``version`` and ``effective_at``.
With auth enabled it requires the ``policy:write`` role and the body
tenant must be the principal's tenant.
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
WRITE_A = {"token": "tok-write-a", "tenant_id": "tenant-a",
           "roles": ["policy:write"]}
WRITE_B = {"token": "tok-write-b", "tenant_id": "tenant-b",
            "roles": ["policy:write"]}
LEGACY_A = {"token": "tok-legacy-a", "tenant_id": "tenant-a",
            "roles": ["request:submit", "request:read",
                      "request:reconcile"]}

INVALID_REQUEST = b'{"error":"invalid_request"}\n'
UNAUTHORIZED = b'{"error":"unauthorized"}\n'
FORBIDDEN = b'{"error":"forbidden"}\n'
NOT_FOUND = b'{"error":"not_found"}\n'
METHOD_NOT_ALLOWED = b'{"error":"method_not_allowed"}\n'
STORAGE_UNAVAILABLE = b'{"error":"storage_unavailable"}\n'
POLICY_CATALOG_CONFLICT = b'{"error":"policy_catalog_conflict"}\n'

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

    def _post(self, body, headers=None, path=PATH):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        merged = {"Content-Length": str(len(data))}
        merged.update(headers or {})
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request("POST", path, body=data, headers=merged)
            resp = conn.getresponse()
            payload = resp.read()
            return resp.status, dict(resp.getheaders()), payload
        finally:
            conn.close()

    def _catalog(self, tenant="tenant-a", rules=None, exceptions=None):
        return {
            "tenant_id": tenant,
            "rules": {"p-default": _rule("*", 30, "default retention")}
            if rules is None else rules,
            "exceptions": {"x-1": _exception("subject-1", "users*", 90,
                                             "legal hold")}
            if exceptions is None else exceptions,
        }

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


class PolicyCatalogVersionsPublishTests(_Base):
    def test_first_publish_is_version_one(self):
        status, headers, body = self._post(self._catalog())
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "application/json")
        payload = json.loads(body)
        self.assertEqual(list(payload), ["version", "effective_at"])
        self.assertEqual(payload["version"], 1)
        self.assertIsInstance(payload["effective_at"], str)
        self.assertTrue(payload["effective_at"])
        self.assertEqual(body, json.dumps(payload, separators=(",", ":"))
                         .encode() + b"\n")
        # The version is readable through the existing history summary.
        history = json.loads(self._get()[2])
        self.assertEqual([v["version"] for v in history["versions"]], [1])

    def test_identical_republish_reuses_first_version_and_writes_nothing(self):
        _, _, first = self._post(self._catalog())
        # A different key order in the body is the same normalized catalog.
        shuffled = {
            "exceptions": self._catalog()["exceptions"],
            "tenant_id": "tenant-a",
            "rules": self._catalog()["rules"],
        }
        for body in (self._catalog(), shuffled):
            status, _, repeated = self._post(body)
            self.assertEqual(status, 200)
            self.assertEqual(repeated, first)
        history = json.loads(self.store.audit_policy_catalog("tenant-a"))
        self.assertEqual(len(history["versions"]), 1)

    def test_different_catalog_takes_next_consecutive_version(self):
        _, _, first = self._post(self._catalog())
        other = self._catalog(rules={
            "p-default": _rule("*", 30, "default retention"),
            "p-users": _rule("users*", 14, "shorter retention"),
        })
        status, _, body = self._post(other)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["version"], 2)
        # The first catalog still replays its first version afterwards.
        status, _, replay = self._post(self._catalog())
        self.assertEqual(status, 200)
        self.assertEqual(replay, first)
        history = json.loads(self.store.audit_policy_catalog("tenant-a"))
        self.assertEqual([v["version"] for v in history["versions"]], [1, 2])

    def test_tenants_publish_independently(self):
        self._post(self._catalog(tenant="tenant-a"))
        status, _, body = self._post(self._catalog(tenant="tenant-b"))
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["version"], 1)

    def test_concurrent_identical_publications_land_once(self):
        results = []

        def publish():
            results.append(self._post(self._catalog()))

        threads = [threading.Thread(target=publish) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertTrue(all(status == 200 for status, _, _ in results))
        self.assertEqual(len({body for _, _, body in results}), 1)
        history = json.loads(self.store.audit_policy_catalog("tenant-a"))
        self.assertEqual(len(history["versions"]), 1)

    def test_concurrent_different_publications_have_a_single_winner(self):
        catalog_a = self._catalog(rules={
            "p-default": _rule("*", 30, "default retention"),
            "p-a": _rule("a*", 1, "catalog a"),
        })
        catalog_b = self._catalog(rules={
            "p-default": _rule("*", 30, "default retention"),
            "p-b": _rule("b*", 2, "catalog b"),
        })
        results = []

        def publish(catalog):
            results.append(self._post(catalog))

        threads = [threading.Thread(target=publish, args=(catalog,))
                   for catalog in (catalog_a, catalog_b) * 5]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        for status, _, body in results:
            self.assertIn(status, (200, 409))
            if status == 409:
                self.assertEqual(body, POLICY_CATALOG_CONFLICT)
        self.assertTrue(any(status == 200 for status, _, _ in results))
        self.assertTrue(any(status == 409 for status, _, _ in results))
        # The loser's catalog never landed: every stored version
        # deserializes and the sequence stays gap-free.
        history = json.loads(self.store.audit_policy_catalog("tenant-a"))
        versions = [v["version"] for v in history["versions"]]
        self.assertEqual(versions, list(range(1, len(versions) + 1)))

    def test_invalid_bodies_are_400_and_write_nothing(self):
        valid_rules = {"p-default": _rule("*", 30, "default retention")}
        bad_bodies = [
            b"not json",
            b"[1, 2]",
            b"null",
            b'"text"',
            {"tenant_id": "tenant-a", "rules": valid_rules},
            {"tenant_id": "tenant-a", "exceptions": {}},
            {"rules": valid_rules, "exceptions": {}},
            dict(self._catalog(), extra=1),
            self._catalog(tenant=""),
            self._catalog(tenant="   "),
            self._catalog(tenant=123),
            self._catalog(rules=[]),
            self._catalog(exceptions=[]),
            # Illegal selector.
            self._catalog(rules={"p": _rule("Users*", 1, "r")}),
            self._catalog(rules={"p": _rule("users", 1, "r")}),
            # Negative, boolean and non-integer day counts.
            self._catalog(rules={"p": _rule("*", -1, "r")}),
            self._catalog(rules={"p": _rule("*", True, "r")}),
            self._catalog(rules={"p": _rule("*", 1.5, "r")}),
            # Empty reason.
            self._catalog(rules={"p": _rule("*", 1, "")}),
            # Missing whole-data default rule.
            self._catalog(rules={"p": _rule("users*", 1, "r")}),
            # A rule entry with missing or extra keys.
            self._catalog(rules={"p": {"selector": "*", "days": 1}}),
            self._catalog(rules={"p": dict(_rule("*", 1, "r"), extra=1)}),
            # policy_id duplicated across rules and exceptions.
            self._catalog(
                rules={"p": _rule("*", 1, "r")},
                exceptions={"p": _exception("s", "*", 1, "r")},
            ),
            # Exception with a blank subject.
            self._catalog(exceptions={"x": _exception("  ", "*", 1, "r")}),
        ]
        for body in bad_bodies:
            status, _, payload = self._post(body)
            self.assertEqual(status, 400, body)
            self.assertEqual(payload, INVALID_REQUEST)
        self.assertEqual(
            self.store.audit_policy_catalog("tenant-a"),
            '{"versions":[]}\n'
        )

    def test_oversized_body_is_400(self):
        catalog = self._catalog(
            rules={"p-default": _rule("*", 30, "x" * (1 << 20))}
        )
        status, _, body = self._post(catalog)
        self.assertEqual(status, 400)
        self.assertEqual(body, INVALID_REQUEST)

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
                data = json.dumps(self._catalog()).encode()
                conn.request("POST", PATH, body=data,
                             headers={"Content-Length": str(len(data))})
                resp = conn.getresponse()
                body = resp.read()
                self.assertEqual(resp.status, 503)
                self.assertEqual(body, STORAGE_UNAVAILABLE)
            finally:
                conn.close()

    def test_publish_does_not_touch_requests_or_receipts(self):
        self._post(self._catalog())
        self.assertEqual(
            self.store.list_requests("tenant-a"),
            {"items": [], "next_cursor": None},
        )


class PolicyCatalogVersionsPublishAuthTests(_Base):
    auth = AuthConfig([POLICY_A, WRITE_A, WRITE_B, LEGACY_A])

    def _auth_post(self, token, body=None):
        headers = {}
        if token is not None:
            headers["Authorization"] = token
        return self._post(self._catalog() if body is None else body,
                          headers=headers)

    def test_missing_malformed_or_unknown_token_is_401(self):
        for header in (None, "tok-write-a", "Bearer", "Bearer ",
                       "Basic tok-write-a", "Bearer unknown-token"):
            status, _, body = self._auth_post(header)
            self.assertEqual(status, 401, header)
            self.assertEqual(body, UNAUTHORIZED)

    def test_missing_policy_write_role_is_403(self):
        for token in ("Bearer tok-policy-a", "Bearer tok-legacy-a"):
            status, _, body = self._auth_post(token)
            self.assertEqual(status, 403, token)
            self.assertEqual(body, FORBIDDEN)

    def test_body_tenant_other_than_principal_is_403(self):
        status, _, body = self._auth_post("Bearer tok-write-b")
        self.assertEqual(status, 403)
        self.assertEqual(body, FORBIDDEN)
        # The rejected cross-tenant call published nothing.
        self.assertEqual(
            self.store.audit_policy_catalog("tenant-a"),
            '{"versions":[]}\n'
        )

    def test_principal_publishes_own_tenant(self):
        status, _, body = self._auth_post("Bearer tok-write-a")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["version"], 1)
        status, _, body = self._auth_post(
            "Bearer tok-write-b", self._catalog(tenant="tenant-b")
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["version"], 1)

    def test_auth_precedes_json_validation(self):
        # An unknown token with a malformed body is 401, never 400.
        status, _, body = self._post(b"garbage",
                                     headers={"Authorization": "Bearer nope"})
        self.assertEqual(status, 401)
        self.assertEqual(body, UNAUTHORIZED)
        # A missing role with a malformed body is 403, never 400.
        status, _, body = self._post(
            b"garbage", headers={"Authorization": "Bearer tok-policy-a"}
        )
        self.assertEqual(status, 403)
        self.assertEqual(body, FORBIDDEN)

    def test_error_bodies_never_echo_token_or_catalog_detail(self):
        bodies = [
            self._auth_post("Bearer tok-write-b")[2],
            self._auth_post("Bearer unknown-token")[2],
            self._auth_post("Bearer tok-policy-a")[2],
        ]
        for body in bodies:
            for leaked in (b"tok-", b"subject-1", b"users*",
                           b"legal hold", b"policy"):
                self.assertNotIn(leaked, body)


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

    def test_policy_write_role_is_accepted(self):
        config = self._load([WRITE_A])
        self.assertEqual(
            config.authenticate("tok-write-a"),
            ("tenant-a", frozenset({"policy:write"})),
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
