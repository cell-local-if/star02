"""Tests for the read-only GET /policy-catalog/retention-trace endpoint.

The endpoint publishes the per-scope retention evidence of
``RequestStore.resolve_retention_trace`` for one subject under one
published catalog version: the body is the verbatim single-line
compact JSON text the store renders for the same tenant, subject,
ordered scope sequence and version. Published versions are the only
catalog source; no request body or inline catalog is accepted. With
auth enabled it requires the ``policy:read`` role and a matching
principal tenant.
"""

import http.client
import json
import os
import sqlite3
import tempfile
import threading
import unittest
from urllib.parse import urlencode

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

PATH = "/policy-catalog/retention-trace"

_HEADER_KEYS = [
    "catalog_source",
    "subject_id",
    "scopes",
    "retention_days",
    "policy_id",
    "reason",
    "exception",
    "scope_evidence",
]
_EVIDENCE_KEYS = ["scope", "level", "policy_id", "exception",
                  "retention_days"]


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

    def _request(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            resp = conn.getresponse()
            data = resp.read()
            return resp.status, dict(resp.getheaders()), data
        finally:
            conn.close()

    def _trace_path(self, scopes=("users:alice",), subject="subject-1",
                    version=1, tenant="tenant-a", **extra):
        def _pairs(name, value):
            if isinstance(value, (list, tuple)):
                return [(name, str(item)) for item in value]
            return [(name, str(value))]

        params = _pairs("subject_id", subject) + _pairs("version", version)
        params.extend(("scope", scope) for scope in scopes)
        for key, value in extra.items():
            params.extend(_pairs(key, value))
        path = PATH + "?" + urlencode(params)
        headers = {"X-Tenant-Id": tenant} if tenant is not None else {}
        return path, headers

    def _get(self, scopes=("users:alice",), subject="subject-1", version=1,
             tenant="tenant-a", **extra):
        path, headers = self._trace_path(
            scopes, subject, version, tenant, **extra
        )
        return self._request("GET", path, headers=headers)

    def _publish(self, tenant="tenant-a", rules=None, exceptions=None):
        return self.store.publish_policy_catalog(
            tenant,
            {
                "p-default": _rule("*", 30, "default retention"),
                "p-users": _rule("users*", 60, "users group"),
            }
            if rules is None
            else rules,
            {
                "x-alice": _exception(
                    "subject-1", "users:alice", 365, "legal hold"
                )
            }
            if exceptions is None
            else exceptions,
        )


class RetentionTraceReadTests(_Base):
    def test_trace_matches_store_verbatim_for_same_input(self):
        self._publish()
        scopes = ["orders:o1", "users:alice"]
        status, headers, body = self._get(scopes=scopes)
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "application/json")
        expected = self.store.resolve_retention_trace(
            "tenant-a", "subject-1", scopes, version=1
        )
        self.assertEqual(body, expected.encode("utf-8"))
        payload = json.loads(body)
        self.assertEqual(list(payload), _HEADER_KEYS)
        self.assertEqual(payload["catalog_source"], "published_version")
        self.assertEqual(payload["subject_id"], "subject-1")
        self.assertEqual(payload["scopes"], ["orders:o1", "users:alice"])
        self.assertEqual(payload["retention_days"], 365)
        self.assertEqual(payload["policy_id"], "x-alice")
        self.assertEqual(payload["reason"], "legal hold")
        self.assertIs(payload["exception"], True)
        self.assertEqual(len(payload["scope_evidence"]), 2)
        for item in payload["scope_evidence"]:
            self.assertEqual(list(item), _EVIDENCE_KEYS)
        levels = {item["scope"]: item for item in payload["scope_evidence"]}
        self.assertEqual(levels["users:alice"]["level"], "entry")
        self.assertEqual(levels["users:alice"]["policy_id"], "x-alice")
        self.assertIs(levels["users:alice"]["exception"], True)
        self.assertEqual(levels["users:alice"]["retention_days"], 365)
        self.assertEqual(levels["orders:o1"]["level"], "all")
        self.assertEqual(levels["orders:o1"]["policy_id"], "p-default")
        self.assertIs(levels["orders:o1"]["exception"], False)
        self.assertEqual(levels["orders:o1"]["retention_days"], 30)

    def test_body_is_single_compact_line_with_one_newline(self):
        self._publish()
        _, _, body = self._get()
        self.assertTrue(body.endswith(b"\n"))
        self.assertFalse(body.endswith(b"\n\n"))
        self.assertNotIn(b"\n", body[:-1])
        self.assertNotIn(b"\r", body)
        payload = json.loads(body)
        canonical = (
            json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
            + "\n"
        ).encode("utf-8")
        self.assertEqual(body, canonical)

    def test_named_version_is_used_for_its_immutable_catalog(self):
        self._publish()
        self._publish(
            rules={
                "p-default": _rule("*", 7, "new default"),
            },
            exceptions={},
        )
        # Version 1 keeps its frozen 365-day exception; version 2 has
        # only the 7-day default.
        _, _, body_v1 = self._get(version=1)
        self.assertEqual(json.loads(body_v1)["retention_days"], 365)
        _, _, body_v2 = self._get(version=2)
        payload = json.loads(body_v2)
        self.assertEqual(payload["retention_days"], 7)
        self.assertEqual(payload["policy_id"], "p-default")
        self.assertIs(payload["exception"], False)

    def test_repeated_scope_keys_give_the_ordered_selector_sequence(self):
        self._publish()
        # Passing order is the input order; normalization sorts and
        # collapses, matching the store exactly.
        status, _, body = self._get(
            scopes=["users:bob", "users:alice"]
        )
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertEqual(payload["scopes"], ["users:alice", "users:bob"])
        self.assertEqual(
            [item["scope"] for item in payload["scope_evidence"]],
            ["users:alice", "users:bob"],
        )
        expected = self.store.resolve_retention_trace(
            "tenant-a",
            "subject-1",
            ["users:bob", "users:alice"],
            version=1,
        )
        self.assertEqual(body, expected.encode("utf-8"))

    def test_normalization_collapses_group_and_whole_data(self):
        self._publish()
        # A group selector dominates its concrete entries.
        _, _, body = self._get(
            scopes=["users:bob", "users:alice", "users*"]
        )
        payload = json.loads(body)
        self.assertEqual(payload["scopes"], ["users*"])
        self.assertEqual(len(payload["scope_evidence"]), 1)
        # A whole-data selector dominates everything else.
        _, _, body = self._get(scopes=["users*", "*"])
        payload = json.loads(body)
        self.assertEqual(payload["scopes"], ["*"])
        self.assertEqual(len(payload["scope_evidence"]), 1)
        self.assertEqual(payload["scope_evidence"][0]["level"], "all")

    def test_normalized_scopes_order_by_unicode_code_point(self):
        self._publish()
        _, _, body = self._get(scopes=["zeta:x", "alpha:x", "mid*"])
        payload = json.loads(body)
        self.assertEqual(payload["scopes"], ["alpha:x", "mid*", "zeta:x"])

    def test_tenant_via_query_parameter_with_last_non_empty_value(self):
        self._publish()
        path, _ = self._trace_path(tenant=None)
        status, _, body = self._request(
            "GET",
            PATH
            + "?tenant_id=tenant-a&subject_id=subject-1&version=1"
            + "&scope=users:alice",
        )
        self.assertEqual(status, 200)
        expected = self.store.resolve_retention_trace(
            "tenant-a", "subject-1", ["users:alice"], version=1
        )
        self.assertEqual(body, expected.encode("utf-8"))
        # The header wins when both name a tenant.
        status, _, body = self._request(
            "GET",
            PATH
            + "?tenant_id=tenant-b&subject_id=subject-1&version=1"
            + "&scope=users:alice",
            headers={"X-Tenant-Id": "tenant-a"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(body, expected.encode("utf-8"))

    def test_tenants_are_isolated(self):
        self._publish("tenant-a")
        # tenant-b has no version 1: the foreign version is invisible.
        status, _, body = self._get(tenant="tenant-b")
        self.assertEqual(status, 404)
        self.assertEqual(body, NOT_FOUND)

    def test_repeated_reads_are_byte_identical_and_read_only(self):
        self._publish()
        before = self.store.resolve_retention_trace(
            "tenant-a", "subject-1", ["users:alice"], version=1
        )
        history_before = self.store.audit_policy_catalog("tenant-a")
        bodies = [self._get()[2] for _ in range(3)]
        self.assertEqual(len(set(bodies)), 1)
        self.assertEqual(bodies[0], before.encode("utf-8"))
        self.assertEqual(
            self.store.resolve_retention_trace(
                "tenant-a", "subject-1", ["users:alice"], version=1
            ),
            before,
        )
        self.assertEqual(
            self.store.audit_policy_catalog("tenant-a"), history_before
        )
        self.assertEqual(
            self.store.list_requests("tenant-a"),
            {"items": [], "next_cursor": None},
        )

    def test_read_after_restart_returns_same_text(self):
        self._publish()
        before = self._get()[2]
        self._fixture.__exit__(None, None, None)
        self.store = RequestStore(self.db_path)
        self._fixture = _Server(self.store, self.auth)
        self._fixture.__enter__()
        self.port = self._fixture.port
        self.assertEqual(self._get()[2], before)

    def test_trace_never_carries_call_time_source_or_raw_catalog(self):
        self._publish()
        _, _, body = self._get()
        self.assertNotIn(b"call_time", body)
        # The endpoint takes no inline catalog keys.
        self.assertNotIn(b"rules", body)
        self.assertNotIn(b"exceptions", body)

    # -- query validation ----------------------------------------------

    def test_missing_tenant_is_400(self):
        self._publish()
        # tenant=None: no X-Tenant-Id header and no tenant_id query
        # parameter.
        path, headers = self._trace_path(tenant=None)
        self.assertNotIn("tenant_id", path)
        status, _, body = self._request("GET", path, headers=headers)
        self.assertEqual(status, 400)
        self.assertEqual(body, INVALID_REQUEST)

    def test_blank_tenant_is_400(self):
        self._publish()
        for headers in ({"X-Tenant-Id": "   "}, {"X-Tenant-Id": ""}):
            status, _, body = self._request(
                "GET",
                PATH
                + "?subject_id=subject-1&version=1&scope=users:alice",
                headers=headers,
            )
            self.assertEqual(status, 400, headers)
            self.assertEqual(body, INVALID_REQUEST)
        status, _, body = self._request(
            "GET",
            PATH
            + "?tenant_id=%20%20&subject_id=subject-1&version=1"
            "&scope=users:alice",
        )
        self.assertEqual(status, 400)
        self.assertEqual(body, INVALID_REQUEST)

    def test_missing_subject_is_400(self):
        self._publish()
        status, _, body = self._request(
            "GET",
            PATH + "?tenant_id=tenant-a&version=1&scope=users:alice",
            headers={"X-Tenant-Id": "tenant-a"},
        )
        self.assertEqual(status, 400)
        self.assertEqual(body, INVALID_REQUEST)

    def test_duplicate_subject_is_400(self):
        self._publish()
        status, _, body = self._get(
            subject=["subject-1", "subject-2"]
        )
        self.assertEqual(status, 400)
        self.assertEqual(body, INVALID_REQUEST)

    def test_blank_subject_is_400(self):
        self._publish()
        for subject in ("", "   "):
            with self.subTest(subject=subject):
                status, _, body = self._get(subject=subject)
                self.assertEqual(status, 400)
                self.assertEqual(body, INVALID_REQUEST)

    def test_missing_version_is_400(self):
        self._publish()
        status, _, body = self._request(
            "GET",
            PATH
            + "?tenant_id=tenant-a&subject_id=subject-1&scope=users:alice",
            headers={"X-Tenant-Id": "tenant-a"},
        )
        self.assertEqual(status, 400)
        self.assertEqual(body, INVALID_REQUEST)

    def test_duplicate_version_is_400(self):
        self._publish()
        status, _, body = self._get(version=[1, 2])
        self.assertEqual(status, 400)
        self.assertEqual(body, INVALID_REQUEST)

    def test_invalid_version_is_400(self):
        self._publish()
        for version in ("0", "-1", "abc", "1.5", "1.0", "+1", "true", "",
                        "1" * 19):
            with self.subTest(version=version):
                status, _, body = self._get(version=version)
                self.assertEqual(status, 400)
                self.assertEqual(body, INVALID_REQUEST)

    def test_large_but_bindable_version_is_404_not_503(self):
        self._publish()
        # An 18-digit version parses and binds inside SQLite's 64-bit
        # range but simply does not exist.
        status, _, body = self._get(version="999999999999999999")
        self.assertEqual(status, 404)
        self.assertEqual(body, NOT_FOUND)

    def test_missing_scope_is_400(self):
        self._publish()
        status, _, body = self._request(
            "GET",
            PATH + "?tenant_id=tenant-a&subject_id=subject-1&version=1",
            headers={"X-Tenant-Id": "tenant-a"},
        )
        self.assertEqual(status, 400)
        self.assertEqual(body, INVALID_REQUEST)

    def test_blank_or_illegal_scope_is_400(self):
        self._publish()
        for scope in ("", "   ", "Users", "users", "users**",
                      "users:alice*", "*users", "USERS:x", "usérs:x"):
            with self.subTest(scope=scope):
                status, _, body = self._get(scopes=[scope])
                self.assertEqual(status, 400)
                self.assertEqual(body, INVALID_REQUEST)

    def test_one_illegal_scope_among_repeated_is_400(self):
        self._publish()
        status, _, body = self._get(scopes=["users:alice", "bad scope"])
        self.assertEqual(status, 400)
        self.assertEqual(body, INVALID_REQUEST)

    def test_exact_duplicate_scope_is_400(self):
        self._publish()
        status, _, body = self._get(scopes=["users:alice", "users:alice"])
        self.assertEqual(status, 400)
        self.assertEqual(body, INVALID_REQUEST)

    def test_overlapping_scopes_remain_valid(self):
        self._publish()
        # Non-identical overlapping selectors normalize and collapse
        # rather than reject.
        status, _, body = self._get(scopes=["users:alice", "users*"])
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["scopes"], ["users*"])

    def test_unknown_query_parameter_is_400(self):
        self._publish()
        for key in ("cursor", "limit", "status", "rules", "bogus"):
            with self.subTest(key=key):
                status, _, body = self._get(**{key: "1"})
                self.assertEqual(status, 400)
                self.assertEqual(body, INVALID_REQUEST)

    def test_duplicate_tenant_query_is_400(self):
        self._publish()
        status, _, body = self._request(
            "GET",
            PATH
            + "?tenant_id=tenant-a&tenant_id=tenant-a"
            "&subject_id=subject-1&version=1&scope=users:alice",
            headers={"X-Tenant-Id": "tenant-a"},
        )
        self.assertEqual(status, 400)
        self.assertEqual(body, INVALID_REQUEST)

    def test_non_empty_body_is_400(self):
        self._publish()
        path, headers = self._trace_path()
        status, _, body = self._request("GET", path, body=b"{}",
                                        headers=headers)
        self.assertEqual(status, 400)
        self.assertEqual(body, INVALID_REQUEST)

    def test_empty_body_is_accepted(self):
        self._publish()
        path, headers = self._trace_path()
        status, _, _ = self._request(
            "GET", path, body=b"",
            headers={**headers, "Content-Length": "0"},
        )
        self.assertEqual(status, 200)

    # -- not found, methods, paths, storage ----------------------------

    def test_missing_unpublished_version_is_404(self):
        self._publish()
        for version in (2, 99):
            with self.subTest(version=version):
                status, _, body = self._get(version=version)
                self.assertEqual(status, 404)
                self.assertEqual(body, NOT_FOUND)

    def test_version_not_found_for_tenant_with_no_publications(self):
        status, _, body = self._get(tenant="tenant-empty")
        self.assertEqual(status, 404)
        self.assertEqual(body, NOT_FOUND)

    def test_unsupported_methods_are_405_with_allow_get(self):
        self._publish()
        for method in ("POST", "PUT", "DELETE", "PATCH", "OPTIONS"):
            status, headers, body = self._request(
                method, PATH, headers={"X-Tenant-Id": "tenant-a"}
            )
            self.assertEqual(status, 405, method)
            self.assertEqual(headers["Allow"], "GET")
            self.assertEqual(body, METHOD_NOT_ALLOWED)

    def test_head_is_405_headless_with_allow_get(self):
        self._publish()
        status, headers, body = self._request(
            "HEAD", PATH, headers={"X-Tenant-Id": "tenant-a"}
        )
        self.assertEqual(status, 405)
        self.assertEqual(headers["Allow"], "GET")
        self.assertEqual(body, b"")
        self.assertEqual(
            headers["Content-Length"], str(len(METHOD_NOT_ALLOWED))
        )

    def test_unknown_neighbour_paths_are_404(self):
        for path in (
            "/policy-catalog",
            "/policy-catalog/",
            PATH + "/",
            PATH + "/extra",
            "/policy-catalog/retention-traces",
            "/policy-catalogs/retention-trace",
        ):
            with self.subTest(path=path):
                status, _, body = self._request(
                    "GET", path, headers={"X-Tenant-Id": "tenant-a"}
                )
                self.assertEqual(status, 404)
                self.assertEqual(body, NOT_FOUND)

    def test_corrupt_catalog_is_503_without_partial_body(self):
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
                conn.request(
                    "GET",
                    PATH
                    + "?tenant_id=tenant-a&subject_id=subject-1"
                    "&version=1&scope=users:alice",
                    headers={"X-Tenant-Id": "tenant-a"},
                )
                resp = conn.getresponse()
                body = resp.read()
                self.assertEqual(resp.status, 503)
                self.assertEqual(body, STORAGE_UNAVAILABLE)
            finally:
                conn.close()


class RetentionTraceAuthTests(_Base):
    auth = AuthConfig([POLICY_A, READ_A, POLICY_B])

    def _auth_get(self, token, scopes=("users:alice",), subject="subject-1",
                  version=1, tenant="tenant-a", method="GET", body=None):
        path, headers = self._trace_path(scopes, subject, version, tenant)
        if token is not None:
            headers["Authorization"] = token
        return self._request(method, path, body=body, headers=headers)

    def setUp(self):
        super().setUp()
        self._publish()

    def test_missing_malformed_or_unknown_token_is_401(self):
        for header in (None, "tok-policy-a", "Bearer", "Bearer ",
                       "Basic tok-policy-a", "Bearer unknown-token"):
            status, _, body = self._auth_get(header)
            self.assertEqual(status, 401, header)
            self.assertEqual(body, UNAUTHORIZED)

    def test_request_read_role_is_403(self):
        status, _, body = self._auth_get("Bearer tok-read-a")
        self.assertEqual(status, 403)
        self.assertEqual(body, FORBIDDEN)

    def test_policy_read_role_reads_own_tenant_trace(self):
        status, _, body = self._auth_get("Bearer tok-policy-a")
        self.assertEqual(status, 200)
        expected = self.store.resolve_retention_trace(
            "tenant-a", "subject-1", ["users:alice"], version=1
        )
        self.assertEqual(body, expected.encode("utf-8"))

    def test_cross_tenant_is_403(self):
        status, _, body = self._auth_get("Bearer tok-policy-b")
        self.assertEqual(status, 403)
        self.assertEqual(body, FORBIDDEN)
        # Also via the query-parameter tenant.
        status, _, body = self._request(
            "GET",
            PATH
            + "?tenant_id=tenant-a&subject_id=subject-1&version=1"
            "&scope=users:alice",
            headers={"Authorization": "Bearer tok-policy-b"},
        )
        self.assertEqual(status, 403)
        self.assertEqual(body, FORBIDDEN)

    def test_other_tenant_missing_version_is_404_for_own_tenant(self):
        status, _, body = self._auth_get(
            "Bearer tok-policy-b", tenant="tenant-b"
        )
        self.assertEqual(status, 404)
        self.assertEqual(body, NOT_FOUND)

    def test_authentication_precedes_payload_validation(self):
        # A missing/unknown token answers 401 even though the query
        # string and body are both invalid.
        status, _, body = self._auth_get(
            None, scopes=("BAD SCOPE",), version="bogus", body=b"{}"
        )
        self.assertEqual(status, 401)
        self.assertEqual(body, UNAUTHORIZED)
        status, _, body = self._auth_get(
            "Bearer unknown-token", scopes=("BAD SCOPE",)
        )
        self.assertEqual(status, 401)
        self.assertEqual(body, UNAUTHORIZED)
        # An authenticated principal without the role is rejected 403
        # before payload validation or storage can run.
        status, _, body = self._auth_get(
            "Bearer tok-read-a", scopes=("BAD SCOPE",), version="bogus"
        )
        self.assertEqual(status, 403)
        self.assertEqual(body, FORBIDDEN)

    def test_cross_tenant_forbidden_before_not_found(self):
        # A foreign principal naming a version its own tenant does not
        # hold is stopped at the tenant boundary, never probing storage.
        status, _, body = self._auth_get(
            "Bearer tok-policy-b", tenant="tenant-a", version=999
        )
        self.assertEqual(status, 403)
        self.assertEqual(body, FORBIDDEN)

    def test_method_routing_precedes_authentication(self):
        status, headers, body = self._auth_get(
            "Bearer tok-policy-a", method="POST"
        )
        self.assertEqual(status, 405)
        self.assertEqual(headers["Allow"], "GET")
        self.assertEqual(body, METHOD_NOT_ALLOWED)

    def test_error_bodies_never_echo_token(self):
        for header in ("Bearer tok-policy-a", "Bearer unknown-token"):
            _, _, body = self._auth_get(header, tenant="tenant-b")
            self.assertNotIn(b"tok-", body)


class RetentionTraceAuthConfigTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self._tmp.cleanup()

    def _load(self, principals):
        path = os.path.join(self._tmp.name, "auth.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump({"principals": principals}, handle)
        return load_auth_config(path)

    def test_legacy_roles_load_but_gain_no_policy_access(self):
        config = self._load([
            {"token": "t1", "tenant_id": "tn",
             "roles": ["request:submit", "request:read",
                       "request:reconcile"]},
        ])
        _, roles = config.authenticate("t1")
        self.assertNotIn("policy:read", roles)
        self.assertIsNone(config.authenticate("missing"))


if __name__ == "__main__":
    unittest.main()
