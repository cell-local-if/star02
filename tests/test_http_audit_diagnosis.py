"""Tests for the read-only GET /requests/{request_id}/audit-diagnosis
endpoint.

Covers the parallel diagnosis entry point to
``GET /requests/{request_id}/evidence``: the single-line compact JSON
body (exactly ``request_id``, ``trusted`` and ``reasons`` in that order,
one trailing newline), the normalised lower-case request id, the
de-duplicated, Unicode code-point-sorted stable reason codes and the
``trusted`` iff no reasons invariant; the tenant-resolution and
single-``tenant_id`` query-string rules; the
400/401/403/404/405/503 error contract and its ordering; the optional
bearer-token RBAC (``request:read``, tenant boundary); diagnosable chain
defects answering 200 with non-empty reasons (un-anchored chain, anchor
authentication failure, anchor head mismatch, deleted/altered/inserted/
reordered events, cross-request/cross-tenant substitution);
byte-identical repeat reads; restart stability; and strictly read-only
behaviour with no secret/material leakage.
"""

import http.client
import json
import os
import sqlite3
import tempfile
import threading
import unittest

from forgetting_evidence.httpapi import AuthConfig, build_server
from forgetting_evidence.requests import RequestNotFound, RequestStore

SECRET_A = "anchor-secret-alpha-0001"
SECRET_B = "anchor-secret-bravo-0002"

NOT_FOUND = b'{"error":"not_found"}\n'
INVALID_REQUEST = b'{"error":"invalid_request"}\n'
METHOD_NOT_ALLOWED = b'{"error":"method_not_allowed"}\n'
STORAGE_UNAVAILABLE = b'{"error":"storage_unavailable"}\n'
UNAUTHORIZED = b'{"error":"unauthorized"}\n'
FORBIDDEN = b'{"error":"forbidden"}\n'

FIELDS = ["request_id", "trusted", "reasons"]

SUBMIT_A = {"token": "tok-submit-a", "tenant_id": "tenant-a",
            "roles": ["request:submit"]}
READ_A = {"token": "tok-read-a", "tenant_id": "tenant-a",
          "roles": ["request:read"]}
READ_B = {"token": "tok-read-b", "tenant_id": "tenant-b",
          "roles": ["request:read"]}
RECONCILE_A = {"token": "tok-reconcile-a", "tenant_id": "tenant-a",
               "roles": ["request:reconcile"]}


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


class AuditDiagnosisEndpointTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "evidence.db")
        # An externally anchored store makes a healthy chain trusted;
        # tampering then produces the specific anchor/event reason codes.
        self.store = RequestStore(self.db_path, anchor_secret=SECRET_A)
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

    def _diagnosis(self, rid, tenant="tenant-a"):
        return self._get(f"/requests/{rid}/audit-diagnosis", tenant)

    def _lifecycle(self, statuses=("processing", "completed"), key="key-1",
                   tenant="tenant-a"):
        receipt = self.store.submit(tenant, "subject-1", ["email"], key)
        for target in statuses:
            self.store.transition(tenant, receipt["request_id"], target)
        return receipt

    def _raw(self):
        return sqlite3.connect(self.db_path)

    def _tamper(self, sql, params=()):
        with self._raw() as conn:
            conn.execute(sql, params)

    # -- success shape --------------------------------------------------

    def test_trusted_chain_shape(self):
        receipt = self._lifecycle(())
        rid = receipt["request_id"]
        status, headers, data = self._diagnosis(rid)
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("Content-Type"), "application/json")
        self.assertTrue(data.endswith(b"\n"))
        self.assertEqual(data.count(b"\n"), 1)
        self.assertTrue(data.startswith(b'{"request_id":"'), data)
        record = json.loads(data)
        self.assertEqual(list(record), FIELDS)
        self.assertEqual(set(record), set(FIELDS))
        self.assertEqual(record["request_id"], rid)
        self.assertIs(record["trusted"], True)
        self.assertEqual(record["reasons"], [])
        self.assertIsInstance(record["reasons"], list)
        self.assertEqual(
            data,
            (json.dumps(record, separators=(",", ":")) + "\n").encode("utf-8"),
        )
        # No subject, scope, idempotency key, timestamp or secret leaks.
        self.assertNotIn(b"subject-1", data)
        self.assertNotIn(b"email", data)
        self.assertNotIn(b"key-1", data)
        self.assertNotIn(b"occurred_at", data)
        self.assertNotIn(SECRET_A.encode(), data)

    def test_advanced_lifecycle_is_trusted(self):
        receipt = self._lifecycle()
        status, _, data = self._diagnosis(receipt["request_id"])
        self.assertEqual(status, 200)
        record = json.loads(data)
        self.assertIs(record["trusted"], True)
        self.assertEqual(record["reasons"], [])

    def test_reasons_sorted_deduped_and_trust_consistent(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        self._tamper(
            "UPDATE status_events SET status = 'failed' "
            "WHERE request_id = ? AND seq = 0",
            (rid,),
        )
        status, _, data = self._diagnosis(rid)
        self.assertEqual(status, 200)
        record = json.loads(data)
        self.assertIs(record["trusted"], False)
        reasons = record["reasons"]
        self.assertEqual(reasons, sorted(set(reasons)))
        self.assertTrue(all(isinstance(r, str) and r for r in reasons))
        self.assertTrue(len(reasons) >= 1)

    def test_repeated_reads_are_byte_identical(self):
        receipt = self._lifecycle()
        _, _, first = self._diagnosis(receipt["request_id"])
        for _ in range(3):
            _, _, again = self._diagnosis(receipt["request_id"])
            self.assertEqual(again, first)

    def test_diagnosis_stable_across_restart(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        _, _, first = self._diagnosis(rid)
        self._fixture.__exit__(None, None, None)
        rebuilt = RequestStore(self.db_path, anchor_secret=SECRET_A)
        with _Server(rebuilt) as fixture:
            conn = http.client.HTTPConnection(
                "127.0.0.1", fixture.port, timeout=10
            )
            try:
                conn.request(
                    "GET", f"/requests/{rid}/audit-diagnosis",
                    headers={"X-Tenant-Id": "tenant-a"},
                )
                resp = conn.getresponse()
                status, second = resp.status, resp.read()
            finally:
                conn.close()
        self.assertEqual(status, 200)
        self.assertEqual(second, first)

    # -- tenant location ------------------------------------------------

    def test_tenant_query_parameter_and_header_precedence(self):
        receipt = self._lifecycle(())
        rid = receipt["request_id"]
        status, _, data = self._request(
            "GET", f"/requests/{rid}/audit-diagnosis?tenant_id=tenant-a"
        )
        self.assertEqual(status, 200)
        self.assertIs(json.loads(data)["trusted"], True)
        # A non-empty header overrides the query string and scopes the read.
        status, _, data = self._request(
            "GET", f"/requests/{rid}/audit-diagnosis?tenant_id=tenant-a",
            headers={"X-Tenant-Id": "tenant-b"},
        )
        self.assertEqual((status, data), (404, NOT_FOUND))

    def test_uppercase_uuid_canonicalises(self):
        receipt = self._lifecycle(())
        _, _, lower = self._diagnosis(receipt["request_id"])
        status, _, upper = self._get(
            f"/requests/{receipt['request_id'].upper()}/audit-diagnosis"
        )
        self.assertEqual(status, 200)
        self.assertEqual(upper, lower)
        self.assertEqual(
            json.loads(upper)["request_id"], receipt["request_id"]
        )

    # -- query gate ------------------------------------------------------

    def test_unknown_query_parameter_is_400(self):
        receipt = self._lifecycle(())
        rid = receipt["request_id"]
        for path in (
            f"/requests/{rid}/audit-diagnosis?foo=bar",
            f"/requests/{rid}/audit-diagnosis?tenant_id=tenant-a&foo=bar",
            f"/requests/{rid}/audit-diagnosis?limit=10",
        ):
            with self.subTest(path=path):
                status, _, data = self._get(path)
                self.assertEqual((status, data), (400, INVALID_REQUEST))

    def test_duplicate_query_parameter_is_400(self):
        receipt = self._lifecycle(())
        rid = receipt["request_id"]
        for path in (
            f"/requests/{rid}/audit-diagnosis"
            "?tenant_id=tenant-a&tenant_id=tenant-a",
            # Even when the header supplies the tenant, a duplicated query
            # key (including a non-tenant key) is rejected.
            f"/requests/{rid}/audit-diagnosis?foo=1&foo=2",
        ):
            with self.subTest(path=path):
                status, _, data = self._get(path)
                self.assertEqual((status, data), (400, INVALID_REQUEST))

    def test_missing_or_empty_tenant_is_400(self):
        receipt = self._lifecycle(())
        rid = receipt["request_id"]
        for path in (
            f"/requests/{rid}/audit-diagnosis",
            f"/requests/{rid}/audit-diagnosis?tenant_id=",
            f"/requests/{rid}/audit-diagnosis?foo=bar",
        ):
            with self.subTest(path=path):
                status, _, data = self._request("GET", path)
                self.assertEqual((status, data), (400, INVALID_REQUEST))

    # -- 404 / 405 -------------------------------------------------------

    def test_malformed_unknown_cross_tenant_ids_are_404(self):
        receipt = self._lifecycle(())
        rid = receipt["request_id"]
        unknown = "00000000-0000-4000-8000-000000000000"
        for path, tenant in (
            ("/requests/not-a-uuid/audit-diagnosis", "tenant-a"),
            (f"/requests/{unknown}/audit-diagnosis", "tenant-a"),
            (f"/requests/{rid}/audit-diagnosis", "tenant-b"),
            (f"/requests/{rid}/audit-diagnosis?tenant_id=tenant-b", None),
        ):
            with self.subTest(path=path):
                status, _, data = self._request(
                    "GET", path,
                    headers={"X-Tenant-Id": tenant} if tenant else {},
                )
                self.assertEqual((status, data), (404, NOT_FOUND))

    def test_extra_path_levels_are_404(self):
        receipt = self._lifecycle(())
        rid = receipt["request_id"]
        for path in (
            f"/requests/{rid}/audit-diagnosis/",
            f"/requests/{rid}/audit-diagnosis/extra",
            "/requests//audit-diagnosis",
            f"/requests/{rid}/other",
        ):
            with self.subTest(path=path):
                status, _, data = self._get(path)
                self.assertEqual((status, data), (404, NOT_FOUND))

    def test_non_get_methods_are_405_with_get_allow(self):
        receipt = self._lifecycle(())
        rid = receipt["request_id"]
        for method in ("POST", "PUT", "DELETE", "PATCH", "OPTIONS"):
            with self.subTest(method=method):
                status, headers, data = self._request(
                    method, f"/requests/{rid}/audit-diagnosis",
                    body={} if method == "POST" else None,
                )
                self.assertEqual(status, 405)
                self.assertEqual(data, METHOD_NOT_ALLOWED)
                self.assertEqual(headers.get("Allow"), "GET")
        status, headers, data = self._request(
            "HEAD", f"/requests/{rid}/audit-diagnosis"
        )
        self.assertEqual(status, 405)
        self.assertEqual(headers.get("Allow"), "GET")
        self.assertEqual(data, b"")

    def test_corrupt_database_is_503(self):
        receipt = self._lifecycle(())
        with open(self.db_path, "wb") as handle:
            handle.write(b"not a sqlite database")
        status, _, data = self._diagnosis(receipt["request_id"])
        self.assertEqual((status, data), (503, STORAGE_UNAVAILABLE))
        self.assertEqual(set(json.loads(data)), {"error"})

    # -- diagnosable chain defects: 200 with stable reasons -------------

    def test_unanchored_database_reports_unanchored_reason(self):
        # A database written by a store with no anchor secret is the
        # historical un-anchored shape: a diagnosable 200, not a fault.
        self._fixture.__exit__(None, None, None)
        legacy = RequestStore(self.db_path)
        rid = legacy.submit(
            "tenant-a", "subject-1", ["email"], "legacy-key"
        )["request_id"]
        with _Server(legacy) as fixture:
            conn = http.client.HTTPConnection(
                "127.0.0.1", fixture.port, timeout=10
            )
            try:
                conn.request(
                    "GET", f"/requests/{rid}/audit-diagnosis",
                    headers={"X-Tenant-Id": "tenant-a"},
                )
                resp = conn.getresponse()
                status, data = resp.status, resp.read()
            finally:
                conn.close()
        self.assertEqual(status, 200)
        record = json.loads(data)
        self.assertIs(record["trusted"], False)
        self.assertIn("unanchored_database", record["reasons"])

    def test_wrong_secret_reports_anchor_auth_failed(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        self._fixture.__exit__(None, None, None)
        wrong = RequestStore(self.db_path, anchor_secret="wrong-secret")
        with _Server(wrong) as fixture:
            conn = http.client.HTTPConnection(
                "127.0.0.1", fixture.port, timeout=10
            )
            try:
                conn.request(
                    "GET", f"/requests/{rid}/audit-diagnosis",
                    headers={"X-Tenant-Id": "tenant-a"},
                )
                resp = conn.getresponse()
                status, data = resp.status, resp.read()
            finally:
                conn.close()
        self.assertEqual(status, 200)
        record = json.loads(data)
        self.assertIs(record["trusted"], False)
        self.assertIn("anchor_auth_failed", record["reasons"])
        self.assertNotIn(b"wrong-secret", data)

    def test_deleted_event_is_200_with_order_and_head_reasons(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        self._tamper(
            "DELETE FROM status_events WHERE request_id = ? AND seq = 1",
            (rid,),
        )
        status, _, data = self._diagnosis(rid)
        self.assertEqual(status, 200)
        record = json.loads(data)
        self.assertIs(record["trusted"], False)
        reasons = set(record["reasons"])
        self.assertIn("event_order_invalid", reasons)
        # The gap breaks the request head binding as well.
        self.assertTrue(reasons & {"chain_head_mismatch", "anchor_orphan"})

    def test_altered_event_is_200_with_hash_and_anchor_reasons(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        self._tamper(
            "UPDATE status_events SET status = 'failed' "
            "WHERE request_id = ? AND seq = 0",
            (rid,),
        )
        status, _, data = self._diagnosis(rid)
        self.assertEqual(status, 200)
        reasons = set(json.loads(data)["reasons"])
        self.assertIn("chain_hash_mismatch", reasons)
        # The event the anchor seals changed, so the HMAC cannot
        # authenticate: the unforgeable external anchor catches the
        # recomputable keyless chain tampering.
        self.assertIn("anchor_auth_failed", reasons)

    def test_inserted_unanchored_event_is_200(self):
        receipt = self._lifecycle(("processing",))
        rid = receipt["request_id"]
        events = self.store.audit("tenant-a", rid)
        self._tamper(
            "INSERT INTO status_events "
            "(tenant_id, request_id, seq, status, occurred_at, chain_hash) "
            "VALUES ('tenant-a', ?, 2, 'completed', ?, ?)",
            (rid, events[-1]["occurred_at"], "0" * 64),
        )
        status, _, data = self._diagnosis(rid)
        self.assertEqual(status, 200)
        record = json.loads(data)
        self.assertIs(record["trusted"], False)
        self.assertIn("event_unanchored", record["reasons"])
        self.assertIn("chain_hash_mismatch", record["reasons"])

    def test_reordered_event_is_200(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        self._tamper(
            "UPDATE status_events SET seq = 5 WHERE request_id = ? AND seq = 1",
            (rid,),
        )
        status, _, data = self._diagnosis(rid)
        self.assertEqual(status, 200)
        record = json.loads(data)
        self.assertIs(record["trusted"], False)
        self.assertIn("event_order_invalid", record["reasons"])

    def test_cross_request_rebound_event_is_200(self):
        one = self._lifecycle(("processing",), key="key-1")
        two = self.store.submit(
            "tenant-a", "subject-2", ["email"], "key-2"
        )
        self.store.transition("tenant-a", two["request_id"], "processing")
        with self._raw() as conn:
            forgery = conn.execute(
                "SELECT status, occurred_at, chain_hash FROM status_events "
                "WHERE request_id = ? AND seq = 0",
                (two["request_id"],),
            ).fetchone()
            conn.execute(
                "UPDATE status_events SET status = ?, occurred_at = ?, "
                "chain_hash = ? WHERE request_id = ? AND seq = 0",
                (*forgery, one["request_id"]),
            )
        status, _, data = self._diagnosis(one["request_id"])
        self.assertEqual(status, 200)
        reasons = set(json.loads(data)["reasons"])
        self.assertIs(json.loads(data)["trusted"], False)
        self.assertTrue(
            {"chain_hash_mismatch", "request_association_mismatch",
             "anchor_auth_failed"}
            & reasons
        )

    def test_replaced_request_head_is_200_with_head_mismatch(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        self._tamper(
            "UPDATE requests SET chain_hash = ? WHERE request_id = ?",
            ("a" * 64, rid),
        )
        status, _, data = self._diagnosis(rid)
        self.assertEqual(status, 200)
        reasons = set(json.loads(data)["reasons"])
        self.assertIn("chain_head_mismatch", reasons)

    def test_tampered_global_anchor_head_is_200_with_anchor_head_mismatch(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        self._tamper(
            "UPDATE audit_anchor_meta SET head_hmac = ? WHERE id = 1",
            ("b" * 64,),
        )
        status, _, data = self._diagnosis(rid)
        self.assertEqual(status, 200)
        record = json.loads(data)
        self.assertIs(record["trusted"], False)
        self.assertIn("anchor_head_mismatch", record["reasons"])

    def test_tampered_reads_are_repeatable(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        self._tamper(
            "UPDATE status_events SET occurred_at = occurred_at || 'X' "
            "WHERE request_id = ? AND seq = 0",
            (rid,),
        )
        _, _, first = self._diagnosis(rid)
        _, _, second = self._diagnosis(rid)
        self.assertEqual(first, second)
        self.assertIs(json.loads(first)["trusted"], False)

    # -- read-only ------------------------------------------------------

    def test_diagnosis_read_never_writes(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        # Healthy and tampered reads must leave the file byte-identical.
        self._tamper(
            "UPDATE status_events SET status = 'failed' "
            "WHERE request_id = ? AND seq = 0",
            (rid,),
        )
        with open(self.db_path, "rb") as handle:
            before = handle.read()
        for _ in range(5):
            status, _, _ = self._diagnosis(rid)
            self.assertEqual(status, 200)
        with open(self.db_path, "rb") as handle:
            after = handle.read()
        self.assertEqual(before, after)
        # No attempts, tombstones or receipts and no new anchors/events.
        with self._raw() as conn:
            self.assertEqual(
                conn.execute(
                    "SELECT count(*) FROM claim_attempts WHERE request_id = ?",
                    (rid,),
                ).fetchone()[0],
                0,
            )
            self.assertEqual(
                conn.execute(
                    "SELECT count(*) FROM deletion_tombstones "
                    "WHERE request_id = ?",
                    (rid,),
                ).fetchone()[0],
                0,
            )
            event_count = conn.execute(
                "SELECT count(*) FROM status_events WHERE request_id = ?",
                (rid,),
            ).fetchone()[0]
            anchor_count = conn.execute(
                "SELECT count(*) FROM audit_anchors WHERE request_id = ?",
                (rid,),
            ).fetchone()[0]
        self.assertEqual(event_count, anchor_count)
        self.assertEqual(event_count, 3)


class AuditDiagnosisAuthTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "evidence.db")
        self.store = RequestStore(self.db_path, anchor_secret=SECRET_A)
        self.auth = AuthConfig(
            [SUBMIT_A, READ_A, READ_B, RECONCILE_A]
        )
        self._fixture = _Server(self.store, self.auth)
        self._fixture.__enter__()
        self.port = self._fixture.port
        self.rid = self.store.submit(
            "tenant-a", "subject-1", ["email"], "key-1"
        )["request_id"]

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

    def test_missing_malformed_or_unknown_token_is_401(self):
        for headers in (
            {},
            {"Authorization": "Bearer unknown-token"},
            {"Authorization": "Basic tok-read-a"},
            {"Authorization": "Bearer "},
        ):
            with self.subTest(headers=headers):
                status, _, data = self._request(
                    "GET", f"/requests/{self.rid}/audit-diagnosis",
                    headers={**headers, "X-Tenant-Id": "tenant-a"},
                )
                self.assertEqual((status, data), (401, UNAUTHORIZED))

    def test_wrong_role_is_403(self):
        for token in ("tok-submit-a", "tok-reconcile-a"):
            with self.subTest(token=token):
                status, _, data = self._request(
                    "GET", f"/requests/{self.rid}/audit-diagnosis",
                    headers={**self._bearer(token),
                             "X-Tenant-Id": "tenant-a"},
                )
                self.assertEqual((status, data), (403, FORBIDDEN))

    def test_tenant_mismatch_is_403_before_id_validation(self):
        for path in (
            f"/requests/{self.rid}/audit-diagnosis",
            "/requests/not-a-uuid/audit-diagnosis",
        ):
            with self.subTest(path=path):
                status, _, data = self._request(
                    "GET", path,
                    headers={**self._bearer("tok-read-a"),
                             "X-Tenant-Id": "tenant-b"},
                )
                self.assertEqual((status, data), (403, FORBIDDEN))
        status, _, data = self._request(
            "GET",
            f"/requests/{self.rid}/audit-diagnosis?tenant_id=tenant-b",
            headers=self._bearer("tok-read-a"),
        )
        self.assertEqual((status, data), (403, FORBIDDEN))

    def test_missing_tenant_with_valid_token_is_400(self):
        status, _, data = self._request(
            "GET", f"/requests/{self.rid}/audit-diagnosis",
            headers=self._bearer("tok-read-a"),
        )
        self.assertEqual((status, data), (400, INVALID_REQUEST))

    def test_duplicate_tenant_query_with_valid_token_is_400(self):
        status, _, data = self._request(
            "GET",
            f"/requests/{self.rid}/audit-diagnosis"
            "?tenant_id=tenant-a&tenant_id=tenant-a",
            headers=self._bearer("tok-read-a"),
        )
        self.assertEqual((status, data), (400, INVALID_REQUEST))

    def test_authorized_read_succeeds(self):
        status, _, data = self._request(
            "GET", f"/requests/{self.rid}/audit-diagnosis",
            headers={**self._bearer("tok-read-a"),
                     "X-Tenant-Id": "tenant-a"},
        )
        self.assertEqual(status, 200)
        record = json.loads(data)
        self.assertEqual(record["request_id"], self.rid)
        self.assertIs(record["trusted"], True)
        self.assertEqual(record["reasons"], [])

    def test_cross_tenant_record_is_404_with_matching_token(self):
        status, _, data = self._request(
            "GET", f"/requests/{self.rid}/audit-diagnosis",
            headers={**self._bearer("tok-read-b"),
                     "X-Tenant-Id": "tenant-b"},
        )
        self.assertEqual((status, data), (404, NOT_FOUND))

    def test_method_check_precedes_authentication(self):
        status, _, data = self._request(
            "PUT", f"/requests/{self.rid}/audit-diagnosis"
        )
        self.assertEqual((status, data), (405, METHOD_NOT_ALLOWED))


class BrokenAuditDiagnosisStoreTests(unittest.TestCase):
    """A substitute store must never leak faults or extra fields."""

    def _serve(self, store):
        fixture = _Server(store)
        fixture.__enter__()
        return fixture

    def _get(self, port, path):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        try:
            conn.request("GET", path, headers={"X-Tenant-Id": "tenant-a"})
            resp = conn.getresponse()
            return resp.status, resp.read()
        finally:
            conn.close()

    def test_storage_exception_becomes_503_without_leak(self):
        secret = "SECRET-SQL-DETAIL-PATH"

        class BrokenStore:
            def get_request_audit_diagnosis(self, *a, **k):
                raise RuntimeError(secret)

        fixture = self._serve(BrokenStore())
        try:
            rid = "00000000-0000-4000-8000-000000000000"
            status, data = self._get(
                fixture.port, f"/requests/{rid}/audit-diagnosis"
            )
            self.assertEqual(status, 503)
            self.assertEqual(data, STORAGE_UNAVAILABLE)
            self.assertNotIn(b"SECRET", data)
        finally:
            fixture.__exit__(None, None, None)

    def test_extra_or_malformed_fields_become_503(self):
        rid = "00000000-0000-4000-8000-000000000000"
        leak = "subject-SECRET"
        cases = (
            {"request_id": rid, "trusted": True, "reasons": [],
             "subject_id": leak},
            {"request_id": rid, "trusted": True},
            {"request_id": rid, "trusted": "yes", "reasons": []},
            {"request_id": rid, "trusted": True, "reasons": None},
            {"request_id": rid, "trusted": True, "reasons": ["Bad Code"]},
            {"request_id": rid, "trusted": True, "reasons": [leak.upper()]},
            {"request_id": "", "trusted": True, "reasons": []},
        )

        class Store:
            def __init__(self, record):
                self._record = record

            def get_request_audit_diagnosis(self, *a, **k):
                return self._record

        for record in cases:
            with self.subTest(record=record):
                fixture = self._serve(Store(record))
                try:
                    status, data = self._get(
                        fixture.port, f"/requests/{rid}/audit-diagnosis"
                    )
                    self.assertEqual(status, 503)
                    self.assertEqual(data, STORAGE_UNAVAILABLE)
                    self.assertNotIn(b"SECRET", data)
                finally:
                    fixture.__exit__(None, None, None)

    def test_untrusted_store_record_is_rederived_and_normalised(self):
        # Even a substitute store that claims trust with reasons, hands
        # back duplicates/unsorted codes, is rendered through the strict
        # canonicaliser: trust is re-derived from the de-duplicated,
        # code-point-sorted reason list.
        rid = "00000000-0000-4000-8000-000000000000"

        class Store:
            def get_request_audit_diagnosis(self, *a, **k):
                return {
                    "request_id": rid,
                    "trusted": True,  # must be re-derived to False
                    "reasons": ["chain_head_mismatch", "anchor_auth_failed",
                                "anchor_auth_failed"],
                }

        fixture = self._serve(Store())
        try:
            status, data = self._get(
                fixture.port, f"/requests/{rid}/audit-diagnosis"
            )
            self.assertEqual(status, 200)
            record = json.loads(data)
            self.assertEqual(
                record,
                {
                    "request_id": rid,
                    "trusted": False,
                    "reasons": ["anchor_auth_failed",
                                "chain_head_mismatch"],
                },
            )
            self.assertEqual(
                data,
                (
                    json.dumps(record, separators=(",", ":")) + "\n"
                ).encode("utf-8"),
            )
        finally:
            fixture.__exit__(None, None, None)


class StorageDiagnosisMethodTests(unittest.TestCase):
    """Direct storage-layer contract for get_request_audit_diagnosis."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "evidence.db")

    def tearDown(self):
        self._tmp.cleanup()

    def test_trusted_and_untrusted_results(self):
        store = RequestStore(self.db_path, anchor_secret=SECRET_A)
        rid = store.submit("tenant-a", "s", ["email"], "k")["request_id"]
        record = store.get_request_audit_diagnosis("tenant-a", rid)
        self.assertEqual(
            record,
            {"request_id": rid, "trusted": True, "reasons": []},
        )
        # A store holding the wrong secret diagnoses anchor failure.
        blind = RequestStore(self.db_path, anchor_secret="wrong")
        record = blind.get_request_audit_diagnosis("tenant-a", rid)
        self.assertEqual(record["request_id"], rid)
        self.assertIs(record["trusted"], False)
        self.assertIn("anchor_auth_failed", record["reasons"])

    def test_unknown_and_cross_tenant_raise_not_found(self):
        store = RequestStore(self.db_path, anchor_secret=SECRET_A)
        rid = store.submit("tenant-a", "s", ["email"], "k")["request_id"]
        with self.assertRaises(RequestNotFound):
            store.get_request_audit_diagnosis(
                "tenant-b", "00000000-0000-4000-8000-000000000000"
            )
        with self.assertRaises(RequestNotFound):
            store.get_request_audit_diagnosis("tenant-b", rid)

    def test_empty_tenant_raises_value_error(self):
        store = RequestStore(self.db_path, anchor_secret=SECRET_A)
        rid = store.submit("tenant-a", "s", ["email"], "k")["request_id"]
        for bad in ("", None, 7):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    store.get_request_audit_diagnosis(bad, rid)

    def test_read_only(self):
        store = RequestStore(self.db_path, anchor_secret=SECRET_A)
        rid = store.submit("tenant-a", "s", ["email"], "k")["request_id"]
        store.transition("tenant-a", rid, "processing")
        with open(self.db_path, "rb") as handle:
            before = handle.read()
        for _ in range(3):
            store.get_request_audit_diagnosis("tenant-a", rid)
        with open(self.db_path, "rb") as handle:
            after = handle.read()
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
