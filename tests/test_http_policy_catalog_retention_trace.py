"""Tests for the read-only GET /policy-catalog/retention-trace endpoint.

The endpoint publishes the storage layer's
``RequestStore.resolve_retention_trace`` per-scope retention evidence
byte for byte: the tenant follows the existing
``X-Tenant-Id``/``tenant_id`` query rule, the query string carries one
``subject_id``, one ``version`` and one-or-more repeatable ``scope``
selectors in order, and only a published catalog version is ever used.
The read never publishes a version and never writes anything. With
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

from forgetting_evidence.httpapi import (
    AuthConfig,
    DeferredRequestStore,
    build_server,
)
from forgetting_evidence.requests import RequestStore

POLICY_A = {"token": "tok-policy-a", "tenant_id": "tenant-a",
            "roles": ["policy:read"]}
POLICY_B = {"token": "tok-policy-b", "tenant_id": "tenant-b",
            "roles": ["policy:read"]}
READ_A = {"token": "tok-read-a", "tenant_id": "tenant-a",
          "roles": ["request:read"]}
WRITE_A = {"token": "tok-write-a", "tenant_id": "tenant-a",
           "roles": ["policy:write"]}

INVALID_REQUEST = b'{"error":"invalid_request"}\n'
UNAUTHORIZED = b'{"error":"unauthorized"}\n'
FORBIDDEN = b'{"error":"forbidden"}\n'
NOT_FOUND = b'{"error":"not_found"}\n'
METHOD_NOT_ALLOWED = b'{"error":"method_not_allowed"}\n'
STORAGE_UNAVAILABLE = b'{"error":"storage_unavailable"}\n'

PATH = "/policy-catalog/retention-trace"

HEADER_KEYS = [
    "catalog_source",
    "subject_id",
    "scopes",
    "retention_days",
    "policy_id",
    "reason",
    "exception",
    "scope_evidence",
]
EVIDENCE_KEYS = ["scope", "level", "policy_id", "exception", "retention_days"]


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
        self.rules = {
            "p-default": _rule("*", 30, "default retention"),
            "p-users": _rule("users*", 60, "users group"),
        }
        self.exceptions = {
            "x-alice": _exception("subject-1", "users:alice", 365, "legal hold"),
        }
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

    def _publish(self, tenant="tenant-a", rules=None, exceptions=None):
        return self.store.publish_policy_catalog(
            tenant,
            self.rules if rules is None else rules,
            self.exceptions if exceptions is None else exceptions,
        )

    def _get(self, query="subject_id=subject-1&version=1&scope=*",
             tenant="tenant-a", headers=None):
        merged = {"X-Tenant-Id": tenant} if tenant is not None else {}
        merged.update(headers or {})
        return self._request("GET", PATH + "?" + query, headers=merged)

    def _store_trace(self, scopes, version=1, tenant="tenant-a",
                     subject="subject-1"):
        return self.store.resolve_retention_trace(
            tenant, subject, scopes, version=version
        )


class RetentionTraceReadTests(_Base):
    def test_success_matches_store_text_byte_for_byte(self):
        self._publish()
        scopes = ["users:alice", "orders:o1"]
        query = "subject_id=subject-1&version=1&scope=users:alice&scope=orders:o1"
        status, headers, body = self._get(query)
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertEqual(body, self._store_trace(scopes).encode("utf-8"))
        doc = json.loads(body)
        self.assertEqual(list(doc), HEADER_KEYS)
        self.assertEqual(doc["catalog_source"], "published_version")
        self.assertEqual(doc["subject_id"], "subject-1")
        self.assertEqual(doc["scopes"], ["orders:o1", "users:alice"])
        self.assertEqual(doc["retention_days"], 365)
        self.assertEqual(doc["policy_id"], "x-alice")
        self.assertEqual(doc["reason"], "legal hold")
        self.assertIs(doc["exception"], True)
        self.assertEqual(
            [item["scope"] for item in doc["scope_evidence"]],
            ["orders:o1", "users:alice"],
        )
        for item in doc["scope_evidence"]:
            self.assertEqual(list(item), EVIDENCE_KEYS)
            self.assertIsInstance(item["retention_days"], int)
            self.assertIsInstance(item["exception"], bool)
            self.assertIn(item["level"], {"entry", "group", "all"})

    def test_body_is_single_compact_line_with_one_newline(self):
        self._publish()
        _, _, body = self._get()
        self.assertTrue(body.endswith(b"\n"))
        self.assertFalse(body.endswith(b"\n\n"))
        self.assertNotIn(b"\n", body[:-1])
        doc = json.loads(body)
        canonical = (
            json.dumps(doc, ensure_ascii=False, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        self.assertEqual(body, canonical)

    def test_scope_normalization_matches_storage_semantics(self):
        self._publish()
        # A whole-collection selector dominates its entries.
        status, _, body = self._get(
            "subject_id=subject-1&version=1&scope=users:bob"
            "&scope=users:alice&scope=users*"
        )
        self.assertEqual(status, 200)
        doc = json.loads(body)
        self.assertEqual(doc["scopes"], ["users*"])
        self.assertEqual(
            [item["scope"] for item in doc["scope_evidence"]], ["users*"]
        )
        self.assertEqual(doc["scope_evidence"][0]["level"], "group")
        # Whole-data dominates every other choice.
        status, _, body = self._get(
            "subject_id=subject-1&version=1&scope=users:a&scope=*"
        )
        self.assertEqual(status, 200)
        doc = json.loads(body)
        self.assertEqual(doc["scopes"], ["*"])
        self.assertEqual(doc["scope_evidence"][0]["level"], "all")

    def test_repeated_reads_byte_identical_and_read_only(self):
        self._publish()
        before = self.store.audit_policy_catalog("tenant-a")
        bodies = [self._get()[2] for _ in range(3)]
        self.assertEqual(len(set(bodies)), 1)
        self.assertEqual(bodies[0], self._store_trace(["*"]).encode("utf-8"))
        # The read created no version, request or any other row.
        self.assertEqual(self.store.audit_policy_catalog("tenant-a"), before)
        self.assertEqual(
            self.store.list_requests("tenant-a"),
            {"items": [], "next_cursor": None},
        )

    def test_read_after_restart_returns_same_bytes(self):
        self._publish()
        first = self._get()[2]
        self._fixture.__exit__(None, None, None)
        self.store = RequestStore(self.db_path)
        self._fixture = _Server(self.store, self.auth)
        self._fixture.__enter__()
        self.port = self._fixture.port
        self.assertEqual(self._get()[2], first)

    def test_tenant_via_query_parameter(self):
        self._publish()
        status, _, body = self._get(
            "tenant_id=tenant-a&subject_id=subject-1&version=1&scope=*",
            tenant=None,
        )
        self.assertEqual(status, 200)
        self.assertEqual(body, self._store_trace(["*"]).encode("utf-8"))

    def test_header_tenant_takes_priority_over_query(self):
        self._publish("tenant-a")
        self._publish(
            "tenant-b",
            rules={"p-default": _rule("*", 7, "short")},
            exceptions={},
        )
        # Header wins even when a query tenant is also present.
        status, _, body = self._get(
            "tenant_id=tenant-b&subject_id=subject-1&version=1&scope=*",
            tenant="tenant-a",
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["retention_days"], 30)

    def test_blank_header_falls_back_to_query_tenant(self):
        self._publish()
        status, _, body = self._request(
            "GET",
            PATH + "?tenant_id=tenant-a&subject_id=subject-1"
            "&version=1&scope=*",
            headers={"X-Tenant-Id": "   "},
        )
        self.assertEqual(status, 200)
        self.assertEqual(body, self._store_trace(["*"]).encode("utf-8"))

    # -- parameter validation ------------------------------------------

    def test_missing_tenant_is_400(self):
        self._publish()
        status, _, body = self._get(
            "subject_id=subject-1&version=1&scope=*", tenant=None
        )
        self.assertEqual(status, 400)
        self.assertEqual(body, INVALID_REQUEST)

    def test_missing_subject_version_or_scope_is400(self):
        self._publish()
        for query in (
            "version=1&scope=*",
            "subject_id=subject-1&scope=*",
            "subject_id=subject-1&version=1",
            "subject_id=&version=1&scope=*",
            "subject_id=subject-1&version=&scope=*",
            "subject_id=subject-1&version=1&scope=",
        ):
            status, _, body = self._get(query)
            self.assertEqual(status, 400, query)
            self.assertEqual(body, INVALID_REQUEST)

    def test_duplicated_single_value_parameters_are_400(self):
        self._publish()
        for query in (
            "subject_id=subject-1&subject_id=subject-2&version=1&scope=*",
            "subject_id=subject-1&version=1&version=2&scope=*",
            "tenant_id=tenant-a&tenant_id=tenant-b"
            "&subject_id=subject-1&version=1&scope=*",
        ):
            status, _, body = self._get(query, tenant=None)
            self.assertEqual(status, 400, query)
            self.assertEqual(body, INVALID_REQUEST)

    def test_unknown_parameter_is_400(self):
        self._publish()
        for query in (
            "subject_id=subject-1&version=1&scope=*&cursor=abc",
            "subject_id=subject-1&version=1&scope=*&limit=10",
            "subject_id=subject-1&version=1&scope=*&bogus=x",
            "subject_id=subject-1&version=1&scope=*"
            "&rules=%7B%7D&exceptions=%7B%7D",
        ):
            status, _, body = self._get(query)
            self.assertEqual(status, 400, query)
            self.assertEqual(body, INVALID_REQUEST)

    def test_invalid_version_is_400(self):
        self._publish()
        for bad in ("0", "-1", "1.5", "abc", "1x", "true", "01234567890123456789"):
            query = f"subject_id=subject-1&version={bad}&scope=*"
            status, _, body = self._get(query)
            self.assertEqual(status, 400, bad)
            self.assertEqual(body, INVALID_REQUEST)

    def test_blank_subject_is_400(self):
        self._publish()
        # A subject has no selector-style grammar, but a blank or
        # whitespace-only subject is rejected by the shared decision
        # semantics with the same 400 outcome.
        for bad in ("%20%20", "%09", "%09%20"):
            query = f"subject_id={bad}&version=1&scope=*"
            status, _, body = self._get(query)
            self.assertEqual(status, 400, bad)
            self.assertEqual(body, INVALID_REQUEST)
        # A subject carrying punctuation is otherwise accepted.
        status, _, body = self._get(
            "subject_id=user%2F42&version=1&scope=*"
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["subject_id"], "user/42")

    def test_invalid_scopes_are_400(self):
        self._publish()
        for bad_scope in (
            "users",
            "Users:a",
            "users:a:b",
            "users%20a",
            "%2Ausers",
            "users%3Aa%3Ab",
        ):
            query = f"subject_id=subject-1&version=1&scope={bad_scope}"
            status, _, body = self._get(query)
            self.assertEqual(status, 400, bad_scope)
            self.assertEqual(body, INVALID_REQUEST)
        # An exact duplicate scope reaches the store, which rejects an
        # exact duplicate with the same 400 outcome.
        status, _, body = self._get(
            "subject_id=subject-1&version=1&scope=users:a&scope=users:a"
        )
        self.assertEqual(status, 400)
        self.assertEqual(body, INVALID_REQUEST)

    def test_non_empty_body_is_400(self):
        self._publish()
        status, _, body = self._request(
            "GET",
            PATH + "?subject_id=subject-1&version=1&scope=*",
            body=b"not-empty",
            headers={"X-Tenant-Id": "tenant-a",
                     "Content-Type": "application/json"},
        )
        self.assertEqual(status, 400)
        self.assertEqual(body, INVALID_REQUEST)

    # -- not found / storage --------------------------------------------

    def test_unknown_unpublished_or_cross_tenant_version_is_404(self):
        self._publish("tenant-a")
        self._publish(
            "tenant-b",
            rules={"p-default": _rule("*", 7, "short")},
            exceptions={},
        )
        for query, tenant in (
            ("subject_id=subject-1&version=99&scope=*", "tenant-a"),
            ("subject_id=subject-1&version=1&scope=*", "tenant-c"),
        ):
            status, _, body = self._get(query, tenant=tenant)
            self.assertEqual(status, 404, query)
            self.assertEqual(body, NOT_FOUND)

    def test_tenant_without_publications_is_404(self):
        status, _, body = self._get(tenant="tenant-empty")
        self.assertEqual(status, 404)
        self.assertEqual(body, NOT_FOUND)

    def test_corrupt_catalog_is_503_without_partial_body(self):
        self._publish()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE policy_catalog_rules SET days = days + 1 "
                "WHERE tenant_id = 'tenant-a'"
            )
            conn.commit()
        status, _, body = self._get()
        self.assertEqual(status, 503)
        self.assertEqual(body, STORAGE_UNAVAILABLE)

    def test_corrupt_accepted_record_is_503(self):
        self._publish()
        receipt = self.store.submit(
            "tenant-a", "subject-1", ["users:a"], "key-1"
        )
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE requests SET scopes_json = 'not-json' WHERE request_id = ?",
                (receipt["request_id"],),
            )
            conn.commit()
        status, _, body = self._get()
        self.assertEqual(status, 503)
        self.assertEqual(body, STORAGE_UNAVAILABLE)

    def test_missing_table_is_503(self):
        self._publish()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DROP TABLE policy_catalog_versions")
            conn.commit()
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
                    PATH + "?subject_id=subject-1&version=1&scope=*",
                    headers={"X-Tenant-Id": "tenant-a"},
                )
                resp = conn.getresponse()
                body = resp.read()
                self.assertEqual(resp.status, 503)
                self.assertEqual(body, STORAGE_UNAVAILABLE)
            finally:
                conn.close()

    # -- methods and paths ----------------------------------------------

    def test_unsupported_methods_are_405_with_allow_get(self):
        self._publish()
        query = PATH + "?subject_id=subject-1&version=1&scope=*"
        for method in ("POST", "PUT", "DELETE", "PATCH", "OPTIONS"):
            status, headers, body = self._request(
                method, query, headers={"X-Tenant-Id": "tenant-a"}
            )
            self.assertEqual(status, 405, method)
            self.assertEqual(headers["Allow"], "GET")
            self.assertEqual(body, METHOD_NOT_ALLOWED)

    def test_head_is_405_without_body(self):
        self._publish()
        status, headers, body = self._request(
            "HEAD",
            PATH + "?subject_id=subject-1&version=1&scope=*",
            headers={"X-Tenant-Id": "tenant-a"},
        )
        self.assertEqual(status, 405)
        self.assertEqual(headers["Allow"], "GET")
        self.assertEqual(headers["Content-Length"], str(len(METHOD_NOT_ALLOWED)))
        self.assertEqual(body, b"")

    def test_deeper_and_neighbour_paths_are_404(self):
        for path in (
            PATH + "/",
            PATH + "/extra",
            "/policy-catalog",
            "/policy-catalog/",
            "/policy-catalog/retention-trac",
            "/policy-catalog/retention-trace2",
        ):
            status, _, body = self._request(
                "GET", path, headers={"X-Tenant-Id": "tenant-a"}
            )
            self.assertEqual(status, 404, path)
            self.assertEqual(body, NOT_FOUND)

    def test_error_bodies_carry_only_error_code(self):
        # A 404 body never names the tenant, subject, version, SQL or a
        # filesystem path.
        self._publish()
        _, _, not_found_body = self._get(
            "subject_id=subject-1&version=99&scope=*"
        )
        self.assertEqual(not_found_body, NOT_FOUND)
        self.assertNotIn(b"tenant-a", not_found_body)
        self.assertNotIn(b"subject-1", not_found_body)


class RetentionTraceAuthTests(_Base):
    auth = AuthConfig([POLICY_A, POLICY_B, READ_A, WRITE_A])

    def _auth_get(self, token, query="subject_id=subject-1&version=1&scope=*",
                  tenant="tenant-a", method="GET", body=None):
        headers = {}
        if tenant is not None:
            headers["X-Tenant-Id"] = tenant
        if token is not None:
            headers["Authorization"] = token
        return self._request(method, PATH + "?" + query, body=body,
                             headers=headers)

    def test_missing_malformed_or_unknown_token_is_401(self):
        self._publish()
        for header in (None, "tok-policy-a", "Bearer", "Bearer ",
                       "Basic tok-policy-a", "Bearer unknown-token"):
            status, _, body = self._auth_get(header)
            self.assertEqual(status, 401, header)
            self.assertEqual(body, UNAUTHORIZED)

    def test_request_read_role_is_403(self):
        self._publish()
        status, _, body = self._auth_get("Bearer tok-read-a")
        self.assertEqual(status, 403)
        self.assertEqual(body, FORBIDDEN)

    def test_policy_write_role_without_read_is_403(self):
        self._publish()
        status, _, body = self._auth_get("Bearer tok-write-a")
        self.assertEqual(status, 403)
        self.assertEqual(body, FORBIDDEN)

    def test_policy_read_role_reads_own_tenant(self):
        self._publish()
        status, _, body = self._auth_get("Bearer tok-policy-a")
        self.assertEqual(status, 200)
        self.assertEqual(body, self._store_trace(["*"]).encode("utf-8"))

    def test_cross_tenant_is_403(self):
        self._publish()
        status, _, body = self._auth_get("Bearer tok-policy-b")
        self.assertEqual(status, 403)
        self.assertEqual(body, FORBIDDEN)
        status, _, body = self._auth_get(
            "Bearer tok-policy-b",
            query="tenant_id=tenant-a&subject_id=subject-1&version=1&scope=*",
            tenant=None,
        )
        self.assertEqual(status, 403)
        self.assertEqual(body, FORBIDDEN)

    def test_other_tenant_principal_reads_own_version(self):
        self._publish(
            "tenant-b",
            rules={"p-default": _rule("*", 7, "short")},
            exceptions={},
        )
        status, _, body = self._auth_get("Bearer tok-policy-b", tenant="tenant-b")
        self.assertEqual(status, 200)
        self.assertEqual(
            json.loads(body)["retention_days"], 7
        )

    def test_authentication_precedes_payload_validation(self):
        self._publish()
        # Unknown token with an invalid query string: still 401.
        status, _, body = self._auth_get(
            "Bearer unknown-token", query="version=1&scope=*"
        )
        self.assertEqual(status, 401)
        self.assertEqual(body, UNAUTHORIZED)
        # A read-only principal with an invalid query string: still 403.
        status, _, body = self._auth_get(
            "Bearer tok-read-a", query="version=1&scope=*"
        )
        self.assertEqual(status, 403)
        self.assertEqual(body, FORBIDDEN)
        # A foreign principal reaching for a missing version: still 403.
        status, _, body = self._auth_get(
            "Bearer tok-policy-b",
            query="subject_id=subject-1&version=99&scope=*",
        )
        self.assertEqual(status, 403)
        # The authorized principal now sees the parameter 400 and the
        # storage 404/503 that the rejected callers never reached.
        status, _, body = self._auth_get(
            "Bearer tok-policy-a", query="version=1&scope=*"
        )
        self.assertEqual(status, 400)
        self.assertEqual(body, INVALID_REQUEST)
        status, _, body = self._auth_get(
            "Bearer tok-policy-a",
            query="subject_id=subject-1&version=99&scope=*",
        )
        self.assertEqual(status, 404)
        self.assertEqual(body, NOT_FOUND)

    def test_authentication_precedes_non_empty_body_rejection(self):
        self._publish()
        status, _, body = self._auth_get(
            "Bearer unknown-token", body=b"not-empty"
        )
        self.assertEqual(status, 401)
        self.assertEqual(body, UNAUTHORIZED)

    def test_error_bodies_never_echo_token(self):
        self._publish()
        for header in ("Bearer tok-policy-a", "Bearer unknown-token"):
            _, _, body = self._auth_get(header, tenant="tenant-b")
            self.assertNotIn(b"tok-", body)


if __name__ == "__main__":
    unittest.main()
