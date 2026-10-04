"""Tests for the POST /policy-catalog/versions publication endpoint.

The endpoint is the single policy-catalog publication entry point: the
JSON body carries exactly ``tenant_id``, ``rules`` and ``exceptions``
and the whole catalog is frozen as one immutable version. Success
answers 200 with exactly ``version`` and ``effective_at``; the first
publication is version 1, an identical normalized catalog reuses the
first version and effective time without writing, and a different
catalog takes the next consecutive version. Concurrent identical
publications land once; concurrent different publications have a single
winner and the losers answer 409 ``policy_catalog_conflict``. With auth
enabled the endpoint requires the ``policy:write`` role and the body's
``tenant_id`` must be the principal's tenant.
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
    load_auth_config,
)
from forgetting_evidence.requests import RequestStore

WRITE_A = {"token": "tok-write-a", "tenant_id": "tenant-a",
           "roles": ["policy:write"]}
READ_A = {"token": "tok-read-a", "tenant_id": "tenant-a",
          "roles": ["policy:read"]}
WRITE_B = {"token": "tok-write-b", "tenant_id": "tenant-b",
           "roles": ["policy:write"]}

INVALID_REQUEST = b'{"error":"invalid_request"}\n'
UNAUTHORIZED = b'{"error":"unauthorized"}\n'
FORBIDDEN = b'{"error":"forbidden"}\n'
NOT_FOUND = b'{"error":"not_found"}\n'
METHOD_NOT_ALLOWED = b'{"error":"method_not_allowed"}\n'
POLICY_CATALOG_CONFLICT = b'{"error":"policy_catalog_conflict"}\n'
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


def _catalog(days=30, with_exception=True):
    rules = {"p-default": _rule("*", days, "default retention")}
    exceptions = (
        {"x-1": _exception("subject-1", "users*", 90, "legal hold")}
        if with_exception
        else {}
    )
    return {"tenant_id": "tenant-a", "rules": rules,
            "exceptions": exceptions}


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
            data = None
            merged = dict(headers or {})
            if body is not None:
                data = body if isinstance(body, bytes) else json.dumps(
                    body
                ).encode("utf-8")
                merged.setdefault("Content-Type", "application/json")
                merged["Content-Length"] = str(len(data))
            conn.request(method, path, body=data, headers=merged)
            resp = conn.getresponse()
            payload = resp.read()
            return resp.status, dict(resp.getheaders()), payload
        finally:
            conn.close()

    def _post(self, body=None, path=PATH, headers=None, raw=None):
        return self._request(
            "POST", path, body=body if raw is None else raw, headers=headers
        )

    def _versions(self, tenant="tenant-a"):
        return json.loads(self.store.audit_policy_catalog(tenant))["versions"]


class PolicyCatalogPublishTests(_Base):
    def test_first_publication_is_version_one(self):
        status, headers, body = self._post(_catalog())
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "application/json")
        payload = json.loads(body)
        self.assertEqual(list(payload), ["version", "effective_at"])
        self.assertEqual(payload["version"], 1)
        self.assertIsInstance(payload["effective_at"], str)
        self.assertTrue(payload["effective_at"])
        versions = self._versions()
        self.assertEqual(len(versions), 1)
        self.assertEqual(versions[0]["effective_at"], payload["effective_at"])

    def test_response_is_one_compact_line(self):
        _, _, body = self._post(_catalog())
        self.assertTrue(body.endswith(b"\n"))
        self.assertNotIn(b"\n", body[:-1])
        self.assertNotIn(b"\r", body)
        self.assertEqual(body, json.dumps(
            json.loads(body), separators=(",", ":")
        ).encode("utf-8") + b"\n")

    def test_response_never_carries_catalog_content(self):
        _, _, body = self._post(_catalog())
        for leaked in (b"subject-1", b"p-default", b"x-1", b"users*",
                       b"legal hold", b"retention", b"selector",
                       b"policy_id", b"reason", b"subject", b"tenant"):
            self.assertNotIn(leaked, body)

    def test_identical_republish_reuses_first_version_and_writes_nothing(self):
        _, _, first = self._post(_catalog())
        for _ in range(3):
            status, _, body = self._post(_catalog())
            self.assertEqual(status, 200)
            self.assertEqual(body, first)
        self.assertEqual(len(self._versions()), 1)

    def test_same_normalized_catalog_reuses_version_regardless_of_order(self):
        _, _, first = self._post(_catalog())
        reordered = {
            "exceptions": _catalog()["exceptions"],
            "tenant_id": "tenant-a",
            "rules": _catalog()["rules"],
        }
        status, _, body = self._post(reordered)
        self.assertEqual(status, 200)
        self.assertEqual(body, first)
        self.assertEqual(len(self._versions()), 1)

    def test_different_catalog_issues_next_consecutive_version(self):
        self._post(_catalog())
        status, _, body = self._post(_catalog(days=14))
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertEqual(payload["version"], 2)
        versions = self._versions()
        self.assertEqual([v["version"] for v in versions], [1, 2])

    def test_republishing_old_catalog_after_newer_reuses_old_version(self):
        _, _, first = self._post(_catalog())
        self._post(_catalog(days=14))
        status, _, body = self._post(_catalog())
        self.assertEqual(status, 200)
        self.assertEqual(body, first)
        self.assertEqual(len(self._versions()), 2)

    def test_exception_change_alone_is_a_new_version(self):
        self._post(_catalog())
        changed = _catalog()
        changed["exceptions"]["x-1"] = _exception(
            "subject-1", "users*", 45, "shorter hold"
        )
        status, _, body = self._post(changed)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["version"], 2)

    def test_empty_exception_catalog_publishes(self):
        status, _, body = self._post(_catalog(with_exception=False))
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["version"], 1)
        versions = self._versions()
        self.assertEqual(versions[0]["exception_count"], 0)

    def test_zero_days_and_reason_text_survive(self):
        catalog = _catalog()
        catalog["rules"]["p-default"] = _rule("*", 0, "immediate")
        status, _, _ = self._post(catalog)
        self.assertEqual(status, 200)
        read = json.loads(self.store.read_policy_catalog("tenant-a", 1))
        self.assertEqual(read["rules"][0]["days"], 0)
        self.assertEqual(read["rules"][0]["reason"], "immediate")

    def test_tenants_have_independent_version_sequences(self):
        self._post(_catalog())
        other = _catalog()
        other["tenant_id"] = "tenant-b"
        status, _, body = self._post(other)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["version"], 1)
        self.assertEqual(len(self._versions("tenant-a")), 1)
        self.assertEqual(len(self._versions("tenant-b")), 1)

    def test_tenant_comes_from_body_alone(self):
        # A conflicting X-Tenant-Id header is ignored: the body's
        # tenant_id is the only tenant source.
        status, _, body = self._post(
            _catalog(), headers={"X-Tenant-Id": "tenant-b"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["version"], 1)
        self.assertEqual(len(self._versions("tenant-a")), 1)
        self.assertEqual(self._versions("tenant-b"), [])

    def test_history_read_reflects_publications(self):
        self._post(_catalog())
        self._post(_catalog(days=14))
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request("GET", PATH, headers={"X-Tenant-Id": "tenant-a"})
            resp = conn.getresponse()
            body = resp.read()
        finally:
            conn.close()
        self.assertEqual(resp.status, 200)
        self.assertEqual(
            body, self.store.audit_policy_catalog("tenant-a").encode("utf-8")
        )
        payload = json.loads(body)
        self.assertEqual([v["version"] for v in payload["versions"]], [1, 2])

    def test_published_version_is_usable_for_retention_resolution(self):
        self._post(_catalog())
        verdict = self.store.resolve_retention(
            "tenant-a", "subject-1", ["users:u-1"], version=1
        )
        self.assertEqual(verdict["retention_days"], 90)
        self.assertEqual(verdict["policy_id"], "x-1")

    # -- body and catalog validation ------------------------------------

    def test_non_object_bodies_are_400_and_write_nothing(self):
        for raw in (b"not json", b"[1,2]", b'"text"', b"42", b"null", b""):
            status, _, body = self._post(raw=raw)
            self.assertEqual(status, 400, raw)
            self.assertEqual(body, INVALID_REQUEST)
        self.assertEqual(self._versions(), [])

    def test_missing_fields_are_400_and_write_nothing(self):
        full = _catalog()
        for key in ("tenant_id", "rules", "exceptions"):
            broken = {k: v for k, v in full.items() if k != key}
            status, _, body = self._post(broken)
            self.assertEqual(status, 400, key)
            self.assertEqual(body, INVALID_REQUEST)
        self.assertEqual(self._versions(), [])

    def test_extra_fields_are_400_and_write_nothing(self):
        for extra in ("subject", "version", "effective_at", "tenant"):
            broken = _catalog()
            broken[extra] = "x"
            status, _, body = self._post(broken)
            self.assertEqual(status, 400, extra)
            self.assertEqual(body, INVALID_REQUEST)
        self.assertEqual(self._versions(), [])

    def test_invalid_tenant_values_are_400(self):
        for bad in ("", "   ", None, 7, True, ["tenant-a"]):
            broken = _catalog()
            broken["tenant_id"] = bad
            status, _, body = self._post(broken)
            self.assertEqual(status, 400, repr(bad))
            self.assertEqual(body, INVALID_REQUEST)
        self.assertEqual(self._versions(), [])

    def test_invalid_catalog_shapes_are_400_and_write_nothing(self):
        base = _catalog()
        bad_catalogs = []
        # Rules must be a non-empty mapping.
        for bad_rules in (None, [], "x", {}):
            broken = _catalog()
            broken["rules"] = bad_rules
            bad_catalogs.append(broken)
        # The whole-data default rule is mandatory.
        broken = _catalog()
        broken["rules"] = {"p-users": _rule("users*", 30)}
        bad_catalogs.append(broken)
        # Selectors follow the existing grammar.
        for bad_selector in ("", "**", "Users*", "users:", "users:u:1", 7):
            broken = _catalog()
            broken["rules"] = dict(base["rules"])
            broken["rules"]["p-extra"] = _rule(bad_selector, 30)
            bad_catalogs.append(broken)
        # Day counts are non-boolean non-negative integers.
        for bad_days in (-1, True, 1.5, "30", None):
            broken = _catalog()
            broken["rules"] = {"p-default": _rule("*", bad_days)}
            bad_catalogs.append(broken)
        # Reasons are non-empty strings (whitespace-only text is a legal
        # non-empty reason under the existing retention semantics).
        for bad_reason in ("", None, 9):
            broken = _catalog()
            broken["rules"] = {"p-default": _rule("*", 30, bad_reason)}
            bad_catalogs.append(broken)
        # A rule declares exactly selector, days and reason.
        broken = _catalog()
        broken["rules"] = {"p-default": {"selector": "*", "days": 30}}
        bad_catalogs.append(broken)
        broken = _catalog()
        broken["rules"] = {
            "p-default": _rule("*", 30) | {"subject": "subject-1"}
        }
        bad_catalogs.append(broken)
        # Policy ids are unique across both catalogs.
        broken = _catalog()
        broken["exceptions"] = {
            "p-default": _exception("subject-1", "users*", 90)
        }
        bad_catalogs.append(broken)
        # Exceptions bind a non-empty subject and exactly four fields.
        broken = _catalog()
        broken["exceptions"] = {"x-1": _exception("  ", "users*", 90)}
        bad_catalogs.append(broken)
        broken = _catalog()
        broken["exceptions"] = {"x-1": {"selector": "users*", "days": 90,
                                        "reason": "hold"}}
        bad_catalogs.append(broken)
        broken = _catalog()
        broken["exceptions"] = {"x-1": _exception("subject-1", "users*", -3)}
        bad_catalogs.append(broken)
        # Exceptions must be a mapping (possibly empty, never null).
        broken = _catalog()
        broken["exceptions"] = None
        bad_catalogs.append(broken)
        for index, broken in enumerate(bad_catalogs):
            status, _, body = self._post(broken)
            self.assertEqual(status, 400, index)
            self.assertEqual(body, INVALID_REQUEST, index)
        self.assertEqual(self._versions(), [])

    def test_error_bodies_never_echo_catalog_content(self):
        broken = _catalog()
        broken["exceptions"] = {
            "x-secret": _exception("subject-secret", "users-secret*", 90,
                                   "secret reason")
        }
        broken["rules"]["p-default"] = _rule("*", -1, "secret rule reason")
        _, _, body = self._post(broken)
        for leaked in (b"subject-secret", b"users-secret", b"secret",
                       b"x-secret", b"p-default"):
            self.assertNotIn(leaked, body)

    # -- concurrency ------------------------------------------------------

    def test_concurrent_identical_publish_lands_once(self):
        bodies = []

        def publish(_):
            status, _, body = self._post(_catalog())
            bodies.append((status, body))

        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(publish, range(16)))
        self.assertTrue(all(status == 200 for status, _ in bodies))
        self.assertEqual(len({body for _, body in bodies}), 1)
        self.assertEqual(len(self._versions()), 1)

    def test_concurrent_different_publish_has_single_winner(self):
        def publish(index):
            catalog = _catalog(days=100 + index)
            return self._post(catalog)

        with ThreadPoolExecutor(max_workers=8) as pool:
            outcomes = list(pool.map(publish, range(12)))
        winners = [o for o in outcomes if o[0] == 200]
        losers = [o for o in outcomes if o[0] == 409]
        self.assertEqual(len(winners), 1, outcomes)
        self.assertEqual(len(losers), 11, outcomes)
        for _, _, body in losers:
            self.assertEqual(body, POLICY_CATALOG_CONFLICT)
        self.assertEqual(json.loads(winners[0][2])["version"], 1)
        self.assertEqual(len(self._versions()), 1)

    # -- storage failures --------------------------------------------------

    def test_corrupt_catalog_is_503_without_half_version(self):
        self._post(_catalog())
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute(
                "UPDATE policy_catalog_versions SET effective_at = 'corrupt' "
                "WHERE tenant_id = 'tenant-a'"
            )
            conn.commit()
        finally:
            conn.close()
        status, _, body = self._post(_catalog())
        self.assertEqual(status, 503)
        self.assertEqual(body, STORAGE_UNAVAILABLE)
        # The failed publication left no half-written version behind.
        conn = sqlite3.connect(self.db_path)
        try:
            count = conn.execute(
                "SELECT count(*) FROM policy_catalog_versions "
                "WHERE tenant_id = 'tenant-a'"
            ).fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(count, 1)

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
                data = json.dumps(_catalog()).encode("utf-8")
                conn.request(
                    "POST", PATH, body=data,
                    headers={"Content-Length": str(len(data))},
                )
                resp = conn.getresponse()
                body = resp.read()
                self.assertEqual(resp.status, 503)
                self.assertEqual(body, STORAGE_UNAVAILABLE)
            finally:
                conn.close()

    # -- routing invariants -------------------------------------------------

    def test_unsupported_methods_are_405(self):
        for method in ("PUT", "DELETE", "PATCH", "OPTIONS"):
            status, headers, body = self._request(method, PATH)
            self.assertEqual(status, 405, method)
            self.assertEqual(headers["Allow"], "GET, POST")
            self.assertEqual(body, METHOD_NOT_ALLOWED)

    def test_unknown_neighbour_paths_are_404(self):
        for path in ("/policy-catalog", "/policy-catalog/",
                     PATH + "/", PATH + "/extra", "/policy-catalogs/versions"):
            status, _, body = self._post(_catalog(), path=path)
            self.assertEqual(status, 404, path)
            self.assertEqual(body, NOT_FOUND)
        self.assertEqual(self._versions(), [])


class PolicyCatalogPublishAuthTests(_Base):
    auth = AuthConfig([WRITE_A, READ_A, WRITE_B])

    def _auth_post(self, token, body=None, raw=None):
        headers = {}
        if token is not None:
            headers["Authorization"] = token
        return self._post(body, headers=headers, raw=raw)

    def test_missing_malformed_or_unknown_token_is_401(self):
        for header in (None, "tok-write-a", "Bearer", "Bearer ",
                       "Basic tok-write-a", "Bearer unknown-token"):
            status, _, body = self._auth_post(header, _catalog())
            self.assertEqual(status, 401, header)
            self.assertEqual(body, UNAUTHORIZED)
        self.assertEqual(self._versions(), [])

    def test_missing_policy_write_role_is_403(self):
        status, _, body = self._auth_post("Bearer tok-read-a", _catalog())
        self.assertEqual(status, 403)
        self.assertEqual(body, FORBIDDEN)
        self.assertEqual(self._versions(), [])

    def test_cross_tenant_body_is_403(self):
        status, _, body = self._auth_post("Bearer tok-write-b", _catalog())
        self.assertEqual(status, 403)
        self.assertEqual(body, FORBIDDEN)
        self.assertEqual(self._versions(), [])
        self.assertEqual(self._versions("tenant-b"), [])

    def test_policy_write_publishes_own_tenant(self):
        status, _, body = self._auth_post("Bearer tok-write-a", _catalog())
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["version"], 1)
        # The other tenant's principal publishes its own version 1.
        other = _catalog()
        other["tenant_id"] = "tenant-b"
        status, _, body = self._auth_post("Bearer tok-write-b", other)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["version"], 1)

    def test_auth_precedes_body_validation(self):
        # An unauthenticated or under-roled caller never reaches JSON
        # validation, even with a malformed body.
        status, _, body = self._auth_post(None, raw=b"not json")
        self.assertEqual(status, 401)
        self.assertEqual(body, UNAUTHORIZED)
        status, _, body = self._auth_post("Bearer tok-read-a", raw=b"not json")
        self.assertEqual(status, 403)
        self.assertEqual(body, FORBIDDEN)

    def test_error_bodies_never_echo_token_or_roles(self):
        for header in ("Bearer tok-write-a", "Bearer unknown-token"):
            _, _, body = self._auth_post(header, _catalog())
            self.assertNotIn(b"tok-", body)
            self.assertNotIn(b"policy:", body)


class PolicyCatalogPublishAuthConfigTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self._tmp.cleanup()

    def _load(self, principals):
        path = os.path.join(self._tmp.name, "auth.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump({"principals": principals}, handle)
        return load_auth_config(path)

    def test_policy_write_role_is_accepted(self):
        config = self._load([WRITE_A])
        self.assertEqual(
            config.authenticate("tok-write-a"),
            ("tenant-a", frozenset({"policy:write"})),
        )

    def test_existing_roles_still_load_without_policy_write(self):
        config = self._load([
            {"token": "t1", "tenant_id": "tn",
             "roles": ["request:submit", "request:read",
                       "request:reconcile", "policy:read"]},
        ])
        self.assertEqual(
            config.authenticate("t1"),
            ("tn", frozenset({"request:submit", "request:read",
                              "request:reconcile", "policy:read"})),
        )


if __name__ == "__main__":
    unittest.main()
