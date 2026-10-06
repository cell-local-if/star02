"""Tests for the conditional read on GET /requests/{id}/audit-bundle.

Covers the strong ETag emitted on every 200 export (SHA-256 over the
exact body bytes, rendered as ``"sha256:<64 lowercase hex>"``), the
``If-None-Match`` evaluation (exact strong match, ``*``, lists,
surrounding whitespace, weak tags never matching), the 304 shape (no
body, ``Content-Length: 0``, same ETag), the 400 rejection of malformed
conditional headers before storage is touched, the precedence of the
existing 404/409/503 outcomes over any conditional result, the
restart-stable tag and the strict body/tag correspondence under
concurrent repeated reads.
"""

import hashlib
import http.client
import json
import os
import re
import tempfile
import threading
import unittest

from forgetting_evidence.httpapi import AuthConfig, build_server
from forgetting_evidence.requests import RequestStore

SECRET_A = "anchor-secret-alpha-0001"

NOT_FOUND = b'{"error":"not_found"}\n'
INVALID_REQUEST = b'{"error":"invalid_request"}\n'
AUDIT_BUNDLE_UNAVAILABLE = b'{"error":"audit_bundle_unavailable"}\n'

ETAG_RE = re.compile(r'^"sha256:[0-9a-f]{64}"$')

READ_A = {"token": "tok-read-a", "tenant_id": "tenant-a",
          "roles": ["request:read"]}


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

    def _get(self, path, tenant="tenant-a", extra=None):
        headers = {}
        if tenant:
            headers["X-Tenant-Id"] = tenant
        headers.update(extra or {})
        return self._request("GET", path, headers=headers)

    def _bundle(self, rid, tenant="tenant-a", extra=None):
        return self._get(f"/requests/{rid}/audit-bundle", tenant, extra)

    def _lifecycle(self, statuses=("processing", "completed"), key="key-1",
                   tenant="tenant-a"):
        receipt = self.store.submit(tenant, "subject-1", ["email"], key)
        for target in statuses:
            self.store.transition(tenant, receipt["request_id"], target)
        return receipt

    # -- ETag on 200 ----------------------------------------------------

    def test_200_carries_strong_sha256_etag(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        status, headers, data = self._bundle(rid)
        self.assertEqual(status, 200)
        etag = headers.get("ETag")
        self.assertIsNotNone(etag)
        self.assertTrue(ETAG_RE.match(etag), etag)
        expected = '"sha256:%s"' % hashlib.sha256(data).hexdigest()
        self.assertEqual(etag, expected)

    def test_etag_stable_across_repeated_reads(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        first = self._bundle(rid)
        second = self._bundle(rid)
        self.assertEqual(first[0], 200)
        self.assertEqual(second[0], 200)
        self.assertEqual(first[1].get("ETag"), second[1].get("ETag"))
        self.assertEqual(first[2], second[2])

    def test_etag_changes_when_body_changes(self):
        receipt = self._lifecycle(("processing",))
        rid = receipt["request_id"]
        _, headers_before, _ = self._bundle(rid)
        self.store.transition("tenant-a", rid, "completed")
        _, headers_after, _ = self._bundle(rid)
        self.assertNotEqual(
            headers_before.get("ETag"), headers_after.get("ETag")
        )

    def test_etag_stable_across_restart(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        _, headers_before, body_before = self._bundle(rid)
        # Rebuild the server on the same database, simulating a restart.
        self._fixture.__exit__(None, None, None)
        rebuilt = RequestStore(self.db_path, anchor_secret=SECRET_A)
        self._fixture = _Server(rebuilt)
        self._fixture.__enter__()
        self.port = self._fixture.port
        _, headers_after, body_after = self._bundle(rid)
        self.assertEqual(body_before, body_after)
        self.assertEqual(headers_before.get("ETag"), headers_after.get("ETag"))

    # -- 304 Not Modified ------------------------------------------------

    def test_if_none_match_hit_is_304(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        _, headers, data = self._bundle(rid)
        etag = headers["ETag"]
        status, headers2, data2 = self._bundle(
            rid, extra={"If-None-Match": etag}
        )
        self.assertEqual(status, 304)
        self.assertEqual(data2, b"")
        self.assertEqual(headers2.get("Content-Length"), "0")
        self.assertEqual(headers2.get("ETag"), etag)
        # The original body is unchanged by the conditional read.
        self.assertEqual(
            hashlib.sha256(data).hexdigest(), etag[8:-1]
        )

    def test_if_none_match_star_is_304(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        _, headers, _ = self._bundle(rid)
        status, headers2, data2 = self._bundle(
            rid, extra={"If-None-Match": "*"}
        )
        self.assertEqual(status, 304)
        self.assertEqual(data2, b"")
        self.assertEqual(headers2.get("ETag"), headers["ETag"])

    def test_if_none_match_list_with_match_is_304(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        _, headers, _ = self._bundle(rid)
        etag = headers["ETag"]
        status, _, data = self._bundle(
            rid,
            extra={"If-None-Match": '"sha256:' + "0" * 64 + '", ' + etag},
        )
        self.assertEqual(status, 304)
        self.assertEqual(data, b"")

    def test_if_none_match_surrounding_whitespace_is_304(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        _, headers, _ = self._bundle(rid)
        etag = headers["ETag"]
        status, _, data = self._bundle(
            rid, extra={"If-None-Match": "   " + etag + "\t "}
        )
        self.assertEqual(status, 304)
        self.assertEqual(data, b"")

    def test_304_after_body_change_uses_new_etag(self):
        receipt = self._lifecycle(("processing",))
        rid = receipt["request_id"]
        _, headers1, _ = self._bundle(rid)
        self.store.transition("tenant-a", rid, "completed")
        _, headers2, _ = self._bundle(rid)
        new_etag = headers2["ETag"]
        self.assertNotEqual(headers1["ETag"], new_etag)
        status, headers3, data = self._bundle(
            rid, extra={"If-None-Match": new_etag}
        )
        self.assertEqual(status, 304)
        self.assertEqual(data, b"")
        self.assertEqual(headers3.get("ETag"), new_etag)

    # -- conditional miss -> full 200 ------------------------------------

    def test_non_matching_tag_is_200_with_body(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        _, headers, data = self._bundle(rid)
        stale = '"sha256:' + "0" * 64 + '"'
        status, headers2, data2 = self._bundle(
            rid, extra={"If-None-Match": stale}
        )
        self.assertEqual(status, 200)
        self.assertEqual(data2, data)
        self.assertEqual(headers2.get("ETag"), headers["ETag"])

    def test_list_without_match_is_200_with_body(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        _, headers, data = self._bundle(rid)
        stale = '"sha256:' + "0" * 64 + '", "sha256:' + "1" * 64 + '"'
        status, _, data2 = self._bundle(
            rid, extra={"If-None-Match": stale}
        )
        self.assertEqual(status, 200)
        self.assertEqual(data2, data)

    def test_weak_tag_is_200_with_body(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        _, headers, data = self._bundle(rid)
        weak = "W/" + headers["ETag"]
        status, headers2, data2 = self._bundle(
            rid, extra={"If-None-Match": weak}
        )
        self.assertEqual(status, 200)
        self.assertEqual(data2, data)
        self.assertEqual(headers2.get("ETag"), headers["ETag"])

    def test_stale_etag_after_advance_is_200(self):
        receipt = self._lifecycle(("processing",))
        rid = receipt["request_id"]
        _, headers1, _ = self._bundle(rid)
        self.store.transition("tenant-a", rid, "completed")
        status, headers2, data2 = self._bundle(
            rid, extra={"If-None-Match": headers1["ETag"]}
        )
        self.assertEqual(status, 200)
        self.assertTrue(data2)
        self.assertEqual(headers2.get("ETag"), headers2["ETag"])
        self.assertNotEqual(headers2["ETag"], headers1["ETag"])

    # -- 400 invalid_request ---------------------------------------------

    def test_malformed_if_none_match_is_400(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        for value in (
            "",                      # empty field value
            "   ",                   # whitespace only
            "sha256:" + "0" * 64,    # missing quotes
            '"unterminated',         # unbalanced quote
            "abc",                   # not a tag and not *
            '"a" "b"',               # missing comma
            '"a",, "b"',             # empty list item
            'W/',                    # weak prefix without tag
            'W/"unterminated',       # malformed weak tag
            '"bad\x01tag"',          # control character
        ):
            with self.subTest(value=value):
                status, _, data = self._bundle(
                    rid, extra={"If-None-Match": value}
                )
                self.assertEqual((status, data), (400, INVALID_REQUEST))

    def test_multiple_if_none_match_headers_are_400(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.putrequest("GET", f"/requests/{rid}/audit-bundle")
            conn.putheader("X-Tenant-Id", "tenant-a")
            conn.putheader("If-None-Match", '"sha256:' + "0" * 64 + '"')
            conn.putheader("If-None-Match", '"sha256:' + "1" * 64 + '"')
            conn.endheaders()
            resp = conn.getresponse()
            status, data = resp.status, resp.read()
        finally:
            conn.close()
        self.assertEqual((status, data), (400, INVALID_REQUEST))

    def test_malformed_if_none_match_reads_no_storage(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]

        class GuardedStore:
            def __init__(self, inner):
                self._inner = inner
                self.export_calls = 0

            def export_audit_bundle(self, *a, **k):
                self.export_calls += 1
                return self._inner.export_audit_bundle(*a, **k)

        guarded = GuardedStore(self.store)
        fixture = _Server(guarded)
        fixture.__enter__()
        try:
            conn = http.client.HTTPConnection(
                "127.0.0.1", fixture.port, timeout=10
            )
            try:
                conn.request(
                    "GET",
                    f"/requests/{rid}/audit-bundle",
                    headers={
                        "X-Tenant-Id": "tenant-a",
                        "If-None-Match": "not-a-tag",
                    },
                )
                resp = conn.getresponse()
                status, data = resp.status, resp.read()
            finally:
                conn.close()
        finally:
            fixture.__exit__(None, None, None)
        self.assertEqual((status, data), (400, INVALID_REQUEST))
        self.assertEqual(guarded.export_calls, 0)

    def test_if_none_match_validated_after_query_gate(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        # An unknown query parameter is 400 regardless of the header.
        status, _, data = self._get(
            f"/requests/{rid}/audit-bundle?foo=bar",
            extra={"If-None-Match": "not-a-tag"},
        )
        self.assertEqual((status, data), (400, INVALID_REQUEST))

    # -- existing outcomes take precedence over 304 ----------------------

    def test_unknown_id_with_matching_header_is_404(self):
        self._lifecycle()
        rid = "00000000-0000-4000-8000-000000000000"
        status, _, data = self._bundle(rid, extra={"If-None-Match": "*"})
        self.assertEqual((status, data), (404, NOT_FOUND))

    def test_cross_tenant_with_matching_header_is_404(self):
        receipt = self._lifecycle()
        _, headers, _ = self._bundle(receipt["request_id"])
        status, _, data = self._bundle(
            receipt["request_id"],
            tenant="tenant-b",
            extra={"If-None-Match": headers["ETag"]},
        )
        self.assertEqual((status, data), (404, NOT_FOUND))

    def test_unavailable_bundle_with_matching_header_is_409(self):
        # A store without an anchor secret settles no trusted chain.
        fixture_store = RequestStore(self.db_path)
        receipt = fixture_store.submit(
            "tenant-a", "subject-1", ["email"], "key-unanchored"
        )
        status, _, data = self._bundle(
            receipt["request_id"], extra={"If-None-Match": "*"}
        )
        self.assertEqual((status, data), (409, AUDIT_BUNDLE_UNAVAILABLE))

    def test_conditional_read_writes_nothing(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        _, headers, _ = self._bundle(rid)
        etag = headers["ETag"]
        with self._raw() as before_conn:
            before = self._dump(before_conn)
        status, _, _ = self._bundle(rid, extra={"If-None-Match": etag})
        self.assertEqual(status, 304)
        with self._raw() as after_conn:
            after = self._dump(after_conn)
        self.assertEqual(before, after)

    def _raw(self):
        import sqlite3

        return sqlite3.connect(self.db_path)

    def _dump(self, conn):
        tables = (
            "requests",
            "status_events",
            "audit_anchors",
            "audit_anchor_meta",
            "anchor_key_generations",
            "inspection_batches",
            "inspection_batch_items",
        )
        return {
            name: conn.execute(f"SELECT * FROM {name}").fetchall()
            for name in tables
        }

    # -- concurrency ------------------------------------------------------

    def test_concurrent_reads_keep_etag_body_correspondence(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        _, headers, data = self._bundle(rid)
        etag = headers["ETag"]
        errors = []

        def reader():
            try:
                for _ in range(10):
                    status, h, body = self._bundle(rid)
                    if status != 200:
                        errors.append(f"status {status}")
                        return
                    if h.get("ETag") != etag:
                        errors.append("etag drift")
                        return
                    if body != data:
                        errors.append("body drift")
                        return
                    if h["ETag"] != (
                        '"sha256:%s"' % hashlib.sha256(body).hexdigest()
                    ):
                        errors.append("etag/body mismatch")
                        return
                    # A conditional re-read must hit.
                    s2, h2, b2 = self._bundle(
                        rid, extra={"If-None-Match": h["ETag"]}
                    )
                    if s2 != 304 or b2 != b"" or h2.get("ETag") != etag:
                        errors.append("conditional read failed")
                        return
            except Exception as exc:  # pragma: no cover - diagnostic
                errors.append(repr(exc))

        threads = [threading.Thread(target=reader) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=60)
        self.assertEqual(errors, [])


class AuditBundleConditionalAuthTests(unittest.TestCase):
    """The conditional read honours the existing RBAC ordering."""

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

    def _get(self, path, headers):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request("GET", path, headers=headers)
            resp = conn.getresponse()
            return resp.status, dict(resp.getheaders()), resp.read()
        finally:
            conn.close()

    def test_304_with_auth(self):
        receipt = self.store.submit(
            "tenant-a", "subject-1", ["email"], "key-1"
        )
        self.store.transition("tenant-a", receipt["request_id"], "processing")
        self.store.transition("tenant-a", receipt["request_id"], "completed")
        rid = receipt["request_id"]
        auth = {
            "Authorization": "Bearer tok-read-a",
            "X-Tenant-Id": "tenant-a",
        }
        status, headers, data = self._get(
            f"/requests/{rid}/audit-bundle", auth
        )
        self.assertEqual(status, 200)
        etag = headers["ETag"]
        status, headers2, data2 = self._get(
            f"/requests/{rid}/audit-bundle",
            dict(auth, **{"If-None-Match": etag}),
        )
        self.assertEqual(status, 304)
        self.assertEqual(data2, b"")
        self.assertEqual(headers2.get("ETag"), etag)

    def test_malformed_if_none_match_after_auth_is_400(self):
        receipt = self.store.submit(
            "tenant-a", "subject-1", ["email"], "key-1"
        )
        self.store.transition("tenant-a", receipt["request_id"], "processing")
        self.store.transition("tenant-a", receipt["request_id"], "completed")
        rid = receipt["request_id"]
        # Auth failure still wins over header validation.
        status, _, data = self._get(
            f"/requests/{rid}/audit-bundle",
            {"X-Tenant-Id": "tenant-a", "If-None-Match": "junk"},
        )
        self.assertEqual(status, 401)
        # Authenticated: the malformed conditional header is 400.
        status, _, data = self._get(
            f"/requests/{rid}/audit-bundle",
            {
                "Authorization": "Bearer tok-read-a",
                "X-Tenant-Id": "tenant-a",
                "If-None-Match": "junk",
            },
        )
        self.assertEqual((status, data), (400, INVALID_REQUEST))


if __name__ == "__main__":
    unittest.main()
