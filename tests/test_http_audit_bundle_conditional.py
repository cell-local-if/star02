"""Tests for HTTP conditional reads on GET /requests/{request_id}/audit-bundle.

Covers the strong ETag contract (``"sha256:<64 lowercase hex>"`` over
the exact body bytes, stable across repeat reads, concurrent readers
and process restarts, changing with the body), the If-None-Match
evaluation (exact double-quoted match and ``*`` yield 304 with no body,
a zero Content-Length and the same ETag; non-matching, multi-value
non-matching and weak ``W/`` tags yield the full 200 body), the 400
``invalid_request`` shapes (multiple headers, empty value, control
characters, illegal tags) rejected after auth/tenant/query validation
but before any storage access, and the precedence of the existing
404/409/503 outcomes over the conditional evaluation.
"""

import hashlib
import http.client
import json
import os
import re
import sqlite3
import tempfile
import threading
import unittest

from forgetting_evidence.httpapi import AuthConfig, build_server
from forgetting_evidence.requests import RequestStore

SECRET_A = "anchor-secret-alpha-0001"

NOT_FOUND = b'{"error":"not_found"}\n'
INVALID_REQUEST = b'{"error":"invalid_request"}\n'
METHOD_NOT_ALLOWED = b'{"error":"method_not_allowed"}\n'
STORAGE_UNAVAILABLE = b'{"error":"storage_unavailable"}\n'
AUDIT_BUNDLE_UNAVAILABLE = b'{"error":"audit_bundle_unavailable"}\n'
UNAUTHORIZED = b'{"error":"unauthorized"}\n'

ETAG_RE = re.compile(r'^"sha256:[0-9a-f]{64}"$')

READ_A = {"token": "tok-read-a", "tenant_id": "tenant-a",
          "roles": ["request:read"]}


def _etag_of(body):
    return '"sha256:' + hashlib.sha256(body).hexdigest() + '"'


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


class AuditBundleConditionalTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "evidence.db")
        self.store = RequestStore(self.db_path, anchor_secret=SECRET_A)
        self._fixture = _Server(self.store)
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

    def _raw_request(self, path, header_pairs):
        """Send a request with explicitly repeated/raw header lines."""
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.putrequest("GET", path)
            for name, value in header_pairs:
                conn.putheader(name, value)
            conn.endheaders()
            resp = conn.getresponse()
            return resp.status, dict(resp.getheaders()), resp.read()
        finally:
            conn.close()

    def _get(self, path, tenant="tenant-a", if_none_match=None):
        headers = {}
        if tenant:
            headers["X-Tenant-Id"] = tenant
        if if_none_match is not None:
            headers["If-None-Match"] = if_none_match
        return self._request("GET", path, headers=headers)

    def _bundle(self, rid, tenant="tenant-a", if_none_match=None):
        return self._get(f"/requests/{rid}/audit-bundle", tenant, if_none_match)

    def _lifecycle(self, statuses=("processing", "completed"), key="key-1",
                   tenant="tenant-a"):
        receipt = self.store.submit(tenant, "subject-1", ["email"], key)
        for target in statuses:
            self.store.transition(tenant, receipt["request_id"], target)
        return receipt

    def _all_tables(self):
        with sqlite3.connect(self.db_path) as raw:
            names = [
                row[0]
                for row in raw.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            ]
            return {
                name: raw.execute(f"SELECT * FROM {name}").fetchall()
                for name in names
            }

    # -- ETag on the 200 response ---------------------------------------

    def test_200_carries_strong_sha256_etag_of_body(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        status, headers, data = self._bundle(rid)
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("Content-Type"), "application/json")
        etag = headers.get("ETag")
        self.assertIsNotNone(etag)
        self.assertTrue(ETAG_RE.match(etag))
        self.assertEqual(etag, _etag_of(data))

    def test_same_body_same_etag(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        first = self._bundle(rid)
        second = self._bundle(rid)
        self.assertEqual(first[0], 200)
        self.assertEqual(second[0], 200)
        self.assertEqual(first[2], second[2])
        self.assertEqual(first[1]["ETag"], second[1]["ETag"])

    def test_body_change_changes_etag(self):
        receipt = self._lifecycle(("processing",))
        rid = receipt["request_id"]
        status, headers, before = self._bundle(rid)
        self.assertEqual(status, 200)
        self.store.transition("tenant-a", rid, "completed")
        status, headers2, after = self._bundle(rid)
        self.assertEqual(status, 200)
        self.assertNotEqual(before, after)
        self.assertNotEqual(headers["ETag"], headers2["ETag"])
        self.assertEqual(headers2["ETag"], _etag_of(after))

    def test_etag_stable_across_restart(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        status, headers, body = self._bundle(rid)
        self.assertEqual(status, 200)
        etag_before = headers["ETag"]
        # Simulate a process restart: close the server and the store,
        # reopen both against the same database file.
        self._fixture.__exit__(None, None, None)
        self.store = RequestStore(self.db_path, anchor_secret=SECRET_A)
        self._fixture = _Server(self.store)
        self._fixture.__enter__()
        self.port = self._fixture.port
        status, headers2, body2 = self._bundle(rid)
        self.assertEqual(status, 200)
        self.assertEqual(body, body2)
        self.assertEqual(headers2["ETag"], etag_before)

    # -- 304 Not Modified ------------------------------------------------

    def test_exact_match_returns_304(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        _, headers, body = self._bundle(rid)
        etag = headers["ETag"]
        status, headers2, data = self._bundle(rid, if_none_match=etag)
        self.assertEqual(status, 304)
        self.assertEqual(data, b"")
        self.assertEqual(headers2.get("Content-Length"), "0")
        self.assertEqual(headers2.get("ETag"), etag)

    def test_whitespace_padded_match_returns_304(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        etag = self._bundle(rid)[1]["ETag"]
        status, headers, data = self._bundle(
            rid, if_none_match=f" \t {etag} \t "
        )
        self.assertEqual(status, 304)
        self.assertEqual(data, b"")
        self.assertEqual(headers.get("ETag"), etag)

    def test_star_matches_exportable_bundle(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        etag = self._bundle(rid)[1]["ETag"]
        status, headers, data = self._bundle(rid, if_none_match="*")
        self.assertEqual(status, 304)
        self.assertEqual(data, b"")
        self.assertEqual(headers.get("Content-Length"), "0")
        self.assertEqual(headers.get("ETag"), etag)

    def test_list_with_one_match_returns_304(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        etag = self._bundle(rid)[1]["ETag"]
        other = '"sha256:' + "0" * 64 + '"'
        for value in (f"{other}, {etag}", f"{etag},{other}",
                      f'{other},W/"sha256:{"1" * 64}", {etag}'):
            with self.subTest(value=value):
                status, headers, data = self._bundle(rid, if_none_match=value)
                self.assertEqual(status, 304)
                self.assertEqual(data, b"")
                self.assertEqual(headers.get("ETag"), etag)

    def test_304_after_body_change_uses_new_etag(self):
        receipt = self._lifecycle(("processing",))
        rid = receipt["request_id"]
        old_etag = self._bundle(rid)[1]["ETag"]
        self.store.transition("tenant-a", rid, "completed")
        new_etag = self._bundle(rid)[1]["ETag"]
        # The stale tag no longer matches: full body with the new tag.
        status, headers, data = self._bundle(rid, if_none_match=old_etag)
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("ETag"), new_etag)
        self.assertEqual(data, self._bundle(rid)[2])
        # The new tag matches again.
        status, headers, data = self._bundle(rid, if_none_match=new_etag)
        self.assertEqual(status, 304)
        self.assertEqual(data, b"")
        self.assertEqual(headers.get("ETag"), new_etag)

    def test_conditional_read_writes_nothing(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        etag = self._bundle(rid)[1]["ETag"]
        before = self._all_tables()
        status, _, _ = self._bundle(rid, if_none_match=etag)
        self.assertEqual(status, 304)
        status, _, _ = self._bundle(rid, if_none_match="*")
        self.assertEqual(status, 304)
        self.assertEqual(before, self._all_tables())

    # -- non-matching conditions return the full 200 body ----------------

    def test_non_matching_tag_returns_200(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        _, headers, body = self._bundle(rid)
        stale = '"sha256:' + "0" * 64 + '"'
        status, headers2, data = self._bundle(rid, if_none_match=stale)
        self.assertEqual(status, 200)
        self.assertEqual(data, body)
        self.assertEqual(headers2.get("ETag"), headers["ETag"])

    def test_multi_value_list_without_match_returns_200(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        _, headers, body = self._bundle(rid)
        value = '"sha256:' + "0" * 64 + '", "sha256:' + "1" * 64 + '"'
        status, headers2, data = self._bundle(rid, if_none_match=value)
        self.assertEqual(status, 200)
        self.assertEqual(data, body)
        self.assertEqual(headers2.get("ETag"), headers["ETag"])

    def test_weak_tag_never_matches(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        _, headers, body = self._bundle(rid)
        weak = "W/" + headers["ETag"]
        status, headers2, data = self._bundle(rid, if_none_match=weak)
        self.assertEqual(status, 200)
        self.assertEqual(data, body)
        self.assertEqual(headers2.get("ETag"), headers["ETag"])

    def test_quoted_comma_inside_tag_is_one_tag(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        _, headers, body = self._bundle(rid)
        # A comma inside a quoted tag does not split the list; the tag
        # simply never matches the digest-shaped ETag.
        status, headers2, data = self._bundle(rid, if_none_match='"a,b"')
        self.assertEqual(status, 200)
        self.assertEqual(data, body)
        self.assertEqual(headers2.get("ETag"), headers["ETag"])

    # -- 400 invalid_request for malformed conditions --------------------

    def test_multiple_if_none_match_headers_are_400(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        etag = self._bundle(rid)[1]["ETag"]
        status, _, data = self._raw_request(
            f"/requests/{rid}/audit-bundle",
            [
                ("X-Tenant-Id", "tenant-a"),
                ("If-None-Match", etag),
                ("If-None-Match", "*"),
            ],
        )
        self.assertEqual((status, data), (400, INVALID_REQUEST))

    def test_empty_if_none_match_is_400(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        for value in ("", "   ", "\t"):
            with self.subTest(value=value):
                status, _, data = self._raw_request(
                    f"/requests/{rid}/audit-bundle",
                    [("X-Tenant-Id", "tenant-a"), ("If-None-Match", value)],
                )
                self.assertEqual((status, data), (400, INVALID_REQUEST))

    def test_control_character_is_400(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        etag = self._bundle(rid)[1]["ETag"]
        for value in (etag + "\x01", "\x0b" + etag, etag + "\x7f"):
            with self.subTest(value=value):
                status, _, data = self._raw_request(
                    f"/requests/{rid}/audit-bundle",
                    [("X-Tenant-Id", "tenant-a"), ("If-None-Match", value)],
                )
                self.assertEqual((status, data), (400, INVALID_REQUEST))

    def test_illegal_entity_tags_are_400(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        etag = self._bundle(rid)[1]["ETag"]
        for value in (
            "abc",                # unquoted
            '"unterminated',      # missing closing quote
            'etag',               # bare token
            "W/",                 # weak prefix without a tag
            "W/*",                # weak star is not legal
            "*x",                 # star must stand alone
            f"{etag}x",           # trailing garbage after a tag
            f'"{etag}"',          # quotes around the whole quoted tag
            f"{etag},",           # trailing comma: empty field
            f",{etag}",           # leading comma: empty field
            f"{etag},,{etag}",    # empty field between commas
            '"has space"',        # SP is not legal inside an opaque tag
        ):
            with self.subTest(value=value):
                status, _, data = self._bundle(rid, if_none_match=value)
                self.assertEqual((status, data), (400, INVALID_REQUEST))

    def test_invalid_condition_never_touches_storage(self):
        calls = []

        class SpyStore:
            def export_audit_bundle(self, *args, **kwargs):
                calls.append(1)
                raise AssertionError("storage must not be read")

        fixture = _Server(SpyStore())
        fixture.__enter__()
        self.addCleanup(fixture.__exit__, None, None, None)
        rid = "00000000-0000-4000-8000-000000000000"
        conn = http.client.HTTPConnection("127.0.0.1", fixture.port, timeout=10)
        try:
            conn.request(
                "GET",
                f"/requests/{rid}/audit-bundle",
                headers={"X-Tenant-Id": "tenant-a", "If-None-Match": "abc"},
            )
            resp = conn.getresponse()
            status, data = resp.status, resp.read()
        finally:
            conn.close()
        self.assertEqual((status, data), (400, INVALID_REQUEST))
        self.assertEqual(calls, [])

    # -- precedence of the existing outcomes ------------------------------

    def test_unknown_id_with_valid_condition_is_404(self):
        self._lifecycle()
        rid = "00000000-0000-4000-8000-000000000000"
        for condition in ("*", '"sha256:' + "0" * 64 + '"'):
            with self.subTest(condition=condition):
                status, _, data = self._bundle(rid, if_none_match=condition)
                self.assertEqual((status, data), (404, NOT_FOUND))

    def test_malformed_id_with_valid_condition_is_404(self):
        status, _, data = self._bundle("not-a-request", if_none_match="*")
        self.assertEqual((status, data), (404, NOT_FOUND))

    def test_malformed_id_beats_invalid_condition(self):
        # Request-id shape is validated before the condition header.
        status, _, data = self._bundle("not-a-request", if_none_match="abc")
        self.assertEqual((status, data), (404, NOT_FOUND))

    def test_invalid_condition_beats_unknown_id(self):
        # A well-formed but unknown id needs storage; the invalid
        # condition is rejected first, without any storage access.
        self._lifecycle()
        rid = "00000000-0000-4000-8000-000000000000"
        status, _, data = self._bundle(rid, if_none_match="abc")
        self.assertEqual((status, data), (400, INVALID_REQUEST))

    def test_unsettled_chain_with_condition_is_409(self):
        plain = RequestStore(self.db_path)
        receipt = plain.submit("tenant-a", "subject-1", ["email"], "key-x")
        rid = receipt["request_id"]
        for condition in ("*", '"sha256:' + "0" * 64 + '"'):
            with self.subTest(condition=condition):
                status, _, data = self._bundle(rid, if_none_match=condition)
                self.assertEqual((status, data), (409, AUDIT_BUNDLE_UNAVAILABLE))

    def test_storage_fault_with_condition_is_503(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        etag = self._bundle(rid)[1]["ETag"]
        with open(self.db_path, "wb") as handle:
            handle.write(b"not a sqlite database")
        status, _, data = self._bundle(rid, if_none_match=etag)
        self.assertEqual((status, data), (503, STORAGE_UNAVAILABLE))

    def test_missing_tenant_with_condition_is_400(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        status, _, data = self._get(
            f"/requests/{rid}/audit-bundle", tenant=None, if_none_match="*"
        )
        self.assertEqual((status, data), (400, INVALID_REQUEST))

    def test_unknown_query_parameter_beats_condition(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        status, _, data = self._get(
            f"/requests/{rid}/audit-bundle?foo=bar", if_none_match="*"
        )
        self.assertEqual((status, data), (400, INVALID_REQUEST))

    # -- methods and routing stay unchanged -------------------------------

    def test_non_get_methods_ignore_condition(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        etag = self._bundle(rid)[1]["ETag"]
        for method in ("POST", "PUT", "DELETE", "PATCH", "OPTIONS"):
            with self.subTest(method=method):
                status, headers, data = self._request(
                    method,
                    f"/requests/{rid}/audit-bundle",
                    headers={"If-None-Match": etag},
                )
                self.assertEqual(status, 405)
                self.assertEqual(headers.get("Allow"), "GET")
                self.assertEqual(data, METHOD_NOT_ALLOWED)

    def test_head_ignores_condition(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        etag = self._bundle(rid)[1]["ETag"]
        status, headers, data = self._request(
            "HEAD",
            f"/requests/{rid}/audit-bundle",
            headers={"If-None-Match": etag},
        )
        self.assertEqual(status, 405)
        self.assertEqual(headers.get("Allow"), "GET")
        self.assertEqual(data, b"")

    # -- concurrency -------------------------------------------------------

    def test_concurrent_reads_keep_etag_body_correspondence(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        path = f"/requests/{rid}/audit-bundle"
        errors = []

        def worker():
            conn = http.client.HTTPConnection(
                "127.0.0.1", self.port, timeout=10
            )
            try:
                for _ in range(20):
                    conn.request(
                        "GET", path, headers={"X-Tenant-Id": "tenant-a"}
                    )
                    resp = conn.getresponse()
                    body = resp.read()
                    etag = resp.getheader("ETag")
                    if resp.status != 200 or etag != _etag_of(body):
                        errors.append(("get", resp.status, etag))
                        return
                    conn.request(
                        "GET",
                        path,
                        headers={
                            "X-Tenant-Id": "tenant-a",
                            "If-None-Match": etag,
                        },
                    )
                    resp = conn.getresponse()
                    replay = resp.read()
                    if (
                        resp.status != 304
                        or replay != b""
                        or resp.getheader("ETag") != etag
                        or resp.getheader("Content-Length") != "0"
                    ):
                        errors.append(("conditional", resp.status, etag))
                        return
            finally:
                conn.close()

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=60)
        self.assertEqual(errors, [])


class AuditBundleConditionalAuthTests(unittest.TestCase):
    """Authentication and authorization still precede the condition."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "auth", "evidence.db")
        self.store = RequestStore(self.db_path, anchor_secret=SECRET_A)
        self._fixture = _Server(self.store, AuthConfig([READ_A]))
        self._fixture.__enter__()
        self.port = self._fixture.port

    def tearDown(self):
        self._fixture.__exit__(None, None, None)
        self._tmp.cleanup()

    def _lifecycle(self):
        receipt = self.store.submit("tenant-a", "subject-1", ["email"], "key-1")
        self.store.transition("tenant-a", receipt["request_id"], "processing")
        return receipt

    def _get(self, path, token="tok-read-a", tenant="tenant-a",
             if_none_match=None):
        headers = {}
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        if tenant is not None:
            headers["X-Tenant-Id"] = tenant
        if if_none_match is not None:
            headers["If-None-Match"] = if_none_match
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request("GET", path, headers=headers)
            resp = conn.getresponse()
            return resp.status, dict(resp.getheaders()), resp.read()
        finally:
            conn.close()

    def test_authorized_conditional_read_round_trips(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        path = f"/requests/{rid}/audit-bundle"
        status, headers, body = self._get(path)
        self.assertEqual(status, 200)
        etag = headers.get("ETag")
        self.assertEqual(etag, _etag_of(body))
        status, headers, data = self._get(path, if_none_match=etag)
        self.assertEqual(status, 304)
        self.assertEqual(data, b"")
        self.assertEqual(headers.get("ETag"), etag)

    def test_missing_token_beats_condition(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        path = f"/requests/{rid}/audit-bundle"
        status, _, data = self._get(path, token=None, if_none_match="*")
        self.assertEqual((status, data), (401, UNAUTHORIZED))
        # Even a malformed condition is never evaluated before auth.
        status, _, data = self._get(path, token=None, if_none_match="abc")
        self.assertEqual((status, data), (401, UNAUTHORIZED))


if __name__ == "__main__":
    unittest.main()
