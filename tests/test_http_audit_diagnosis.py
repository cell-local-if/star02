"""Tests for the read-only GET /requests/{request_id}/audit-diagnosis
endpoint.

Covers the single-line compact JSON shape (exactly ``request_id``,
``trusted`` and ``reasons`` in that order, one trailing newline), the
tenant resolution rules (header overrides query, a single ``tenant_id``
query key only), the error mapping (400/401/403/404/405/503), the
200-with-reasons diagnosis of an unanchored, tampered or substituted
chain, byte-identical repeated reads, strictly read-only behaviour and
the absence of any subject, scope, idempotency key, credential, secret,
SQL or path leakage.
"""

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

NOT_FOUND = b'{"error":"not_found"}\n'
INVALID_REQUEST = b'{"error":"invalid_request"}\n'
METHOD_NOT_ALLOWED = b'{"error":"method_not_allowed"}\n'
STORAGE_UNAVAILABLE = b'{"error":"storage_unavailable"}\n'
UNAUTHORIZED = b'{"error":"unauthorized"}\n'
FORBIDDEN = b'{"error":"forbidden"}\n'

FIELDS = ["request_id", "trusted", "reasons"]
SECRET = "anchor-secret-alpha-0001"
REASON_CODES = re.compile(r"^[a-z0-9_]+$")


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
        self.db_path = os.path.join(self._tmp.name, "nested", "diagnosis.db")
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

    def _diagnosis(self, rid, tenant="tenant-a"):
        return self._get(f"/requests/{rid}/audit-diagnosis", tenant)

    def _lifecycle(self, statuses=("processing", "completed"), key="key-1"):
        receipt = self.store.submit("tenant-a", "subject-1", ["email"], key)
        for target in statuses:
            self.store.transition("tenant-a", receipt["request_id"], target)
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
        record = json.loads(data)
        self.assertEqual(list(record), FIELDS)
        self.assertEqual(record["request_id"], rid)
        self.assertIs(record["trusted"], True)
        self.assertEqual(record["reasons"], [])
        # Compact single-line rendering, exactly the three fields.
        self.assertEqual(
            data,
            (
                json.dumps(record, separators=(",", ":")) + "\n"
            ).encode("utf-8"),
        )
        self.assertEqual(
            data,
            b'{"request_id":"%s","trusted":true,"reasons":[]}\n'
            % rid.encode("ascii"),
        )
        # No subject, scope, idempotency key or secret leaks.
        self.assertNotIn(b"subject-1", data)
        self.assertNotIn(b"email", data)
        self.assertNotIn(b"key-1", data)
        self.assertNotIn(SECRET.encode("ascii"), data)

    def test_trusted_after_lifecycle_advance(self):
        receipt = self._lifecycle()
        status, _, data = self._diagnosis(receipt["request_id"])
        self.assertEqual(status, 200)
        record = json.loads(data)
        self.assertIs(record["trusted"], True)
        self.assertEqual(record["reasons"], [])

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
        rebuilt = RequestStore(self.db_path, anchor_secret=SECRET)
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

    # -- query-string gate ----------------------------------------------

    def test_unknown_query_parameter_is_400(self):
        receipt = self._lifecycle(())
        rid = receipt["request_id"]
        for path in (
            f"/requests/{rid}/audit-diagnosis?tenant_id=tenant-a&cursor=abc",
            f"/requests/{rid}/audit-diagnosis?limit=10",
            f"/requests/{rid}/audit-diagnosis?status=accepted",
        ):
            with self.subTest(path=path):
                status, _, data = self._request(
                    "GET", path, headers={"X-Tenant-Id": "tenant-a"}
                )
                self.assertEqual((status, data), (400, INVALID_REQUEST))

    def test_duplicate_query_key_is_400(self):
        receipt = self._lifecycle(())
        rid = receipt["request_id"]
        status, _, data = self._request(
            "GET",
            f"/requests/{rid}/audit-diagnosis"
            "?tenant_id=tenant-a&tenant_id=tenant-a",
        )
        self.assertEqual((status, data), (400, INVALID_REQUEST))

    # -- error mapping --------------------------------------------------

    def test_missing_or_empty_tenant_is_400(self):
        receipt = self._lifecycle(())
        rid = receipt["request_id"]
        status, _, data = self._request(
            "GET", f"/requests/{rid}/audit-diagnosis"
        )
        self.assertEqual((status, data), (400, INVALID_REQUEST))
        status, _, data = self._request(
            "GET", f"/requests/{rid}/audit-diagnosis?tenant_id="
        )
        self.assertEqual((status, data), (400, INVALID_REQUEST))
        status, _, data = self._request(
            "GET", f"/requests/{rid}/audit-diagnosis",
            headers={"X-Tenant-Id": "   "},
        )
        self.assertEqual((status, data), (400, INVALID_REQUEST))

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

    def test_illegal_subresource_shapes_are_unknown_paths(self):
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
        # HEAD answers 405 with headers but no body.
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

    # -- diagnosis: 200 with non-empty reasons --------------------------

    def _assert_untrusted(self, rid, expected_reasons=None):
        status, _, data = self._diagnosis(rid)
        self.assertEqual(status, 200)
        record = json.loads(data)
        self.assertEqual(list(record), FIELDS)
        self.assertEqual(record["request_id"], rid)
        self.assertIs(record["trusted"], False)
        reasons = record["reasons"]
        self.assertIsInstance(reasons, list)
        self.assertTrue(reasons)
        # Stable, detail-free codes: deduplicated, sorted by Unicode
        # code point, lower-case tokens without any detail.
        self.assertEqual(reasons, sorted(set(reasons)))
        for reason in reasons:
            self.assertTrue(REASON_CODES.match(reason), reason)
        if expected_reasons is not None:
            self.assertEqual(reasons, expected_reasons)
        # A tampered read is repeatable byte-for-byte.
        _, _, again = self._diagnosis(rid)
        self.assertEqual(again, data)
        return record

    def test_unanchored_chain_is_200_with_reason(self):
        # A database that has never carried an anchor diagnoses as
        # unanchored, never as a read failure.
        plain_path = os.path.join(self._tmp.name, "plain.db")
        plain = RequestStore(plain_path)
        rid = plain.submit("tenant-a", "subject-1", ["email"], "key-9")[
            "request_id"
        ]
        with _Server(plain) as fixture:
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
        self.assertEqual(list(record), FIELDS)
        self.assertIs(record["trusted"], False)
        self.assertEqual(record["reasons"], ["unanchored_database"])

    def test_deleted_event_is_200_with_reasons(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        self._tamper(
            "DELETE FROM status_events WHERE request_id = ? AND seq = 1",
            (rid,),
        )
        record = self._assert_untrusted(rid)
        self.assertIn("anchor_state_split", record["reasons"])

    def test_altered_event_is_200_with_reasons(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        self._tamper(
            "UPDATE status_events SET status = 'failed' "
            "WHERE request_id = ? AND seq = 0",
            (rid,),
        )
        record = self._assert_untrusted(rid)
        self.assertIn("chain_hash_mismatch", record["reasons"])

    def test_inserted_event_is_200_with_reasons(self):
        receipt = self._lifecycle(("failed",))
        rid = receipt["request_id"]
        events = self.store.audit("tenant-a", rid)
        self._tamper(
            "INSERT INTO status_events "
            "(tenant_id, request_id, seq, status, occurred_at, chain_hash) "
            "VALUES ('tenant-a', ?, 2, 'processing', ?, ?)",
            (rid, events[-1]["occurred_at"], "0" * 64),
        )
        self._assert_untrusted(rid)

    def test_reordered_event_is_200_with_reasons(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        self._tamper(
            "UPDATE status_events SET seq = 5 "
            "WHERE request_id = ? AND seq = 1",
            (rid,),
        )
        record = self._assert_untrusted(rid)
        self.assertIn("event_order_invalid", record["reasons"])

    def test_cross_request_substitution_is_200_with_reasons(self):
        one = self._lifecycle(("processing",), key="key-1")
        two = self.store.submit("tenant-a", "subject-2", ["email"], "key-2")
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
        self._assert_untrusted(one["request_id"])

    def test_anchor_authentication_failure_is_200_with_reasons(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        self._tamper(
            "UPDATE audit_anchors SET anchor_hmac = ? "
            "WHERE request_id = ? AND seq = 0",
            ("b" * 64, rid),
        )
        record = self._assert_untrusted(rid)
        self.assertIn("anchor_auth_failed", record["reasons"])

    def test_anchor_head_mismatch_is_200_with_reasons(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        self._tamper(
            "UPDATE audit_anchor_meta SET head_hmac = ?", ("c" * 64,)
        )
        record = self._assert_untrusted(rid)
        self.assertIn("anchor_head_mismatch", record["reasons"])

    def test_reasons_match_storage_layer_diagnosis(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        self._tamper(
            "DELETE FROM status_events WHERE request_id = ? AND seq = 1",
            (rid,),
        )
        _, _, data = self._diagnosis(rid)
        record = json.loads(data)
        self.assertEqual(
            record["reasons"], self.store.diagnose_chain("tenant-a", rid)
        )
        self.assertIs(record["trusted"], False)

    # -- read-only ------------------------------------------------------

    def test_diagnosis_read_never_writes(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        with open(self.db_path, "rb") as handle:
            before = handle.read()
        for _ in range(5):
            status, _, _ = self._diagnosis(rid)
            self.assertEqual(status, 200)
        with open(self.db_path, "rb") as handle:
            after = handle.read()
        self.assertEqual(before, after)
        # No attempts, tombstones, receipts or extra events appeared.
        with self._raw() as conn:
            for table in (
                "claim_attempts",
                "deletion_tombstones",
                "deletion_receipts",
            ):
                self.assertEqual(
                    conn.execute(
                        f"SELECT count(*) FROM {table} WHERE request_id = ?",
                        (rid,),
                    ).fetchone()[0],
                    0,
                )
            self.assertEqual(
                conn.execute(
                    "SELECT count(*) FROM status_events WHERE request_id = ?",
                    (rid,),
                ).fetchone()[0],
                3,
            )


SUBMIT_A = {"token": "tok-submit-a", "tenant_id": "tenant-a",
            "roles": ["request:submit"]}
READ_A = {"token": "tok-read-a", "tenant_id": "tenant-a",
          "roles": ["request:read"]}
READ_B = {"token": "tok-read-b", "tenant_id": "tenant-b",
          "roles": ["request:read"]}
RECONCILE_A = {"token": "tok-reconcile-a", "tenant_id": "tenant-a",
               "roles": ["request:reconcile"]}


class AuditDiagnosisAuthTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "diagnosis.db")
        self.store = RequestStore(self.db_path, anchor_secret=SECRET)
        self.auth = AuthConfig([SUBMIT_A, READ_A, READ_B, RECONCILE_A])
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
            "GET", f"/requests/{self.rid}/audit-diagnosis?tenant_id=tenant-b",
            headers=self._bearer("tok-read-a"),
        )
        self.assertEqual((status, data), (403, FORBIDDEN))

    def test_missing_tenant_with_valid_token_is_400(self):
        status, _, data = self._request(
            "GET", f"/requests/{self.rid}/audit-diagnosis",
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


class BrokenDiagnosisStoreTests(unittest.TestCase):
    """A substitute store must never leak faults or malformed reasons."""

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
            def diagnose_chain(self, *a, **k):
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

    def test_malformed_reasons_become_503(self):
        rid = "00000000-0000-4000-8000-000000000000"
        cases = (
            "unanchored_database",  # not a list
            [""],  # empty reason code
            [None],  # non-string reason
            [42],  # non-string reason
            [{"reason": "anchor_orphan"}],  # structured detail
        )

        class Store:
            def __init__(self, reasons):
                self._reasons = reasons

            def diagnose_chain(self, *a, **k):
                return self._reasons

        for reasons in cases:
            with self.subTest(reasons=reasons):
                fixture = self._serve(Store(reasons))
                try:
                    status, data = self._get(
                        fixture.port, f"/requests/{rid}/audit-diagnosis"
                    )
                    self.assertEqual(status, 503)
                    self.assertEqual(data, STORAGE_UNAVAILABLE)
                finally:
                    fixture.__exit__(None, None, None)

    def test_duplicate_or_unsorted_reasons_are_normalised(self):
        rid = "00000000-0000-4000-8000-000000000000"

        class Store:
            def diagnose_chain(self, *a, **k):
                return ["chain_hash_mismatch", "anchor_orphan",
                        "anchor_orphan"]

        fixture = self._serve(Store())
        try:
            status, data = self._get(
                fixture.port, f"/requests/{rid}/audit-diagnosis"
            )
            self.assertEqual(status, 200)
            record = json.loads(data)
            self.assertEqual(list(record), FIELDS)
            self.assertEqual(record["request_id"], rid)
            self.assertIs(record["trusted"], False)
            self.assertEqual(
                record["reasons"], ["anchor_orphan", "chain_hash_mismatch"]
            )
            self.assertEqual(
                data,
                b'{"request_id":"%s","trusted":false,'
                b'"reasons":["anchor_orphan","chain_hash_mismatch"]}\n'
                % rid.encode("ascii"),
            )
        finally:
            fixture.__exit__(None, None, None)


if __name__ == "__main__":
    unittest.main()
