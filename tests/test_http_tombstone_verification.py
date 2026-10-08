"""Tests for the read-only GET /requests/{request_id}/tombstone-verification
endpoint.

Covers the verbatim single-line compact JSON report (exactly
``request_id``, ``verified``, ``coverage``, ``tombstone_count``,
``evidence_digest`` and ``reasons`` in that order, one trailing
newline), the coverage ladder (``not_applicable`` / ``incomplete`` /
``complete``), every stable reason code and their coexistence, the
tenant resolution rules (header overrides query, a single
``tenant_id`` query key only), the error mapping
(400/401/403/404/405/503), byte-identical repeated reads, strictly
read-only behaviour and the absence of any object, proof body,
subject, raw scope, idempotency key, credential, SQL or path leakage.
The existing tombstone paging, storage-layer verification, error codes
and authentication are unchanged.
"""

import hashlib
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

FIELDS = [
    "request_id",
    "verified",
    "coverage",
    "tombstone_count",
    "evidence_digest",
    "reasons",
]

ALL_REASONS = {
    "request_not_completed",
    "scope_coverage_invalid",
    "tombstone_record_invalid",
    "operation_id_invalid",
    "evidence_digest_mismatch",
}


def _digest(seed):
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


def _item(scope, operation, adapter="adapter-1", outcome="deleted", proof=None):
    return {
        "adapter_id": adapter,
        "scope": scope,
        "operation_id": operation,
        "outcome": outcome,
        "proof_digest": proof if proof is not None else _digest(operation),
    }


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


class TombstoneVerificationEndpointTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "verify.db")
        self.store = RequestStore(self.db_path)
        self._fixture = _Server(self.store)
        self._fixture.__enter__()
        self.port = self._fixture.port

    def tearDown(self):
        self._fixture.__exit__(None, None, None)
        self._tmp.cleanup()

    # -- fixtures -------------------------------------------------------

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

    def _verify(self, rid, tenant="tenant-a"):
        return self._get(f"/requests/{rid}/tombstone-verification", tenant)

    def _submit(self, store=None, tenant="tenant-a", key="key-1",
                scopes=("email", "profile")):
        return (store or self.store).submit(
            tenant, "subject-1", list(scopes), key
        )

    def _claimed(self, store=None, scopes=("email", "profile"),
                 tenant="tenant-a", key="key-1"):
        store = store or self.store
        receipt = self._submit(store, tenant=tenant, key=key, scopes=scopes)
        claim = store.claim_next(tenant, "worker-1", 3600)
        return store, receipt, claim

    def _completed(self, scopes=("email", "profile")):
        store, receipt, claim = self._claimed(scopes=scopes)
        rid = receipt["request_id"]
        items = [_item(scope, f"op-{scope}") for scope in scopes]
        store.record_deletion_tombstones(
            "tenant-a", rid, claim["claim_token"], items
        )
        store.finish_scoped_claim(
            "tenant-a", rid, claim["claim_token"], "completed"
        )
        return store, rid, items

    def _raw(self):
        conn = sqlite3.connect(self.db_path)
        conn.isolation_level = None
        return conn

    def _tamper(self, sql, params=()):
        with self._raw() as conn:
            conn.execute(sql, params)

    # -- success shape --------------------------------------------------

    def test_verified_complete_shape(self):
        store, rid, items = self._completed()
        status, headers, data = self._verify(rid)
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("Content-Type"), "application/json")
        self.assertTrue(data.endswith(b"\n"))
        self.assertEqual(data.count(b"\n"), 1)
        record = json.loads(data)
        self.assertEqual(list(record), FIELDS)
        self.assertEqual(record["request_id"], rid)
        self.assertIs(record["verified"], True)
        self.assertEqual(record["coverage"], "complete")
        self.assertEqual(record["tombstone_count"], 2)
        self.assertRegex(record["evidence_digest"], r"^[0-9a-f]{64}$")
        self.assertEqual(record["reasons"], [])
        # The HTTP body is byte-identical to the storage-layer report.
        self.assertEqual(
            data,
            store.verify_deletion_tombstones("tenant-a", rid).encode("utf-8"),
        )
        # Compact single-line rendering, exactly the six fields.
        self.assertEqual(
            data,
            (
                json.dumps(record, separators=(",", ":")) + "\n"
            ).encode("utf-8"),
        )
        # No object, proof body, subject, raw scope, idempotency key,
        # worker, adapter, operation id, SQL or path leaks.
        for secret in (
            b"subject-1",
            b"email",
            b"profile",
            b"key-1",
            b"worker-1",
            b"adapter-1",
            b"op-email",
            self.db_path.encode("utf-8"),
        ):
            self.assertNotIn(secret, data)

    def test_repeated_reads_are_byte_identical(self):
        _, rid, _ = self._completed()
        _, _, first = self._verify(rid)
        for _ in range(3):
            _, _, again = self._verify(rid)
            self.assertEqual(again, first)

    def test_verify_stable_across_restart(self):
        _, rid, _ = self._completed()
        _, _, first = self._verify(rid)
        self._fixture.__exit__(None, None, None)
        rebuilt = RequestStore(self.db_path)
        with _Server(rebuilt) as fixture:
            conn = http.client.HTTPConnection(
                "127.0.0.1", fixture.port, timeout=10
            )
            try:
                conn.request(
                    "GET", f"/requests/{rid}/tombstone-verification",
                    headers={"X-Tenant-Id": "tenant-a"},
                )
                resp = conn.getresponse()
                status, second = resp.status, resp.read()
            finally:
                conn.close()
        self.assertEqual(status, 200)
        self.assertEqual(second, first)

    # -- coverage ladder ------------------------------------------------

    def test_not_completed_is_not_applicable(self):
        receipt = self._submit()
        status, _, data = self._verify(receipt["request_id"])
        self.assertEqual(status, 200)
        record = json.loads(data)
        self.assertEqual(list(record), FIELDS)
        self.assertEqual(record["coverage"], "not_applicable")
        self.assertIs(record["verified"], False)
        self.assertEqual(record["tombstone_count"], 0)
        self.assertIsNone(record["evidence_digest"])
        self.assertEqual(record["reasons"], ["request_not_completed"])

    def test_failed_is_not_applicable(self):
        store, receipt, claim = self._claimed(key="key-2")
        rid = receipt["request_id"]
        store.finish_scoped_claim(
            "tenant-a", rid, claim["claim_token"], "failed"
        )
        _, _, data = self._verify(rid)
        record = json.loads(data)
        self.assertEqual(record["coverage"], "not_applicable")
        self.assertIsNone(record["evidence_digest"])
        self.assertEqual(record["reasons"], ["request_not_completed"])

    def test_completed_with_missing_scope_is_incomplete(self):
        store, receipt, claim = self._claimed()
        rid = receipt["request_id"]
        store.record_deletion_tombstones(
            "tenant-a", rid, claim["claim_token"], [_item("email", "op-email")]
        )
        # Plain finish checks no coverage, so the completed row may
        # carry an under-covered ledger.
        store.finish_claim("tenant-a", rid, claim["claim_token"], "completed")
        _, _, data = self._verify(rid)
        record = json.loads(data)
        self.assertEqual(record["coverage"], "incomplete")
        self.assertIs(record["verified"], False)
        self.assertEqual(record["tombstone_count"], 1)
        self.assertIsNone(record["evidence_digest"])
        self.assertEqual(record["reasons"], ["scope_coverage_invalid"])

    def test_completed_with_duplicated_scope_is_incomplete(self):
        store, receipt, claim = self._claimed()
        rid = receipt["request_id"]
        token = claim["claim_token"]
        store.record_deletion_tombstones(
            "tenant-a",
            rid,
            token,
            [
                _item("email", "op-1"),
                _item("email", "op-2", adapter="adapter-2"),
            ],
        )
        store.finish_claim("tenant-a", rid, token, "completed")
        record = json.loads(self._verify(rid)[2])
        self.assertEqual(record["coverage"], "incomplete")
        self.assertEqual(record["reasons"], ["scope_coverage_invalid"])

    # -- reason codes ---------------------------------------------------

    def test_tombstone_record_invalid_and_mismatch_coexist(self):
        _, rid, _ = self._completed()
        self._tamper(
            "UPDATE deletion_tombstones SET outcome = 'purged' "
            "WHERE operation_id = 'op-email'"
        )
        record = json.loads(self._verify(rid)[2])
        self.assertEqual(record["coverage"], "complete")
        self.assertIs(record["verified"], False)
        self.assertRegex(record["evidence_digest"], r"^[0-9a-f]{64}$")
        self.assertEqual(
            record["reasons"],
            ["evidence_digest_mismatch", "tombstone_record_invalid"],
        )

    def test_evidence_digest_mismatch_alone(self):
        _, rid, _ = self._completed()
        self._tamper(
            "UPDATE deletion_tombstone_finishes SET evidence_digest = ? "
            "WHERE request_id = ?",
            (_digest("altered"), rid),
        )
        record = json.loads(self._verify(rid)[2])
        self.assertEqual(record["coverage"], "complete")
        self.assertIs(record["verified"], False)
        self.assertEqual(record["reasons"], ["evidence_digest_mismatch"])
        # The reported digest is the recomputed one, not the ledger's.
        self.assertNotEqual(record["evidence_digest"], _digest("altered"))

    def test_operation_id_invalid(self):
        store, rid, _ = self._completed()
        other = self._submit(store, key="key-2")
        conn = self._raw()
        try:
            # Lose the global operation-number uniqueness guard and
            # bind the same operation number to another request.
            conn.execute("DROP INDEX idx_deletion_tombstones_operation")
            conn.execute(
                "INSERT INTO deletion_tombstones ("
                "tenant_id, request_id, scope, adapter_id, operation_id, "
                "outcome, proof_digest, recorded_at"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "tenant-a",
                    other["request_id"],
                    "email",
                    "adapter-9",
                    "op-email",
                    "deleted",
                    _digest("op-email"),
                    "2026-01-01T00:00:00Z",
                ),
            )
        finally:
            conn.close()
        record = json.loads(self._verify(rid)[2])
        self.assertEqual(record["coverage"], "complete")
        self.assertIs(record["verified"], False)
        self.assertEqual(record["reasons"], ["operation_id_invalid"])

    def test_reasons_are_sorted_and_deduplicated(self):
        _, rid, _ = self._completed()
        self._tamper(
            "UPDATE deletion_tombstones SET outcome = 'purged' "
            "WHERE operation_id = 'op-email'"
        )
        self._tamper(
            "UPDATE deletion_tombstone_finishes SET evidence_digest = ? "
            "WHERE request_id = ?",
            (_digest("altered"), rid),
        )
        reasons = json.loads(self._verify(rid)[2])["reasons"]
        self.assertEqual(reasons, sorted(set(reasons)))
        for reason in reasons:
            self.assertIn(reason, ALL_REASONS)

    # -- tenant location ------------------------------------------------

    def test_tenant_query_parameter_and_header_precedence(self):
        _, rid, _ = self._completed()
        status, _, data = self._request(
            "GET", f"/requests/{rid}/tombstone-verification?tenant_id=tenant-a"
        )
        self.assertEqual(status, 200)
        self.assertIs(json.loads(data)["verified"], True)
        # A non-empty header overrides the query string and scopes the read.
        status, _, data = self._request(
            "GET",
            f"/requests/{rid}/tombstone-verification?tenant_id=tenant-a",
            headers={"X-Tenant-Id": "tenant-b"},
        )
        self.assertEqual((status, data), (404, NOT_FOUND))

    def test_uppercase_uuid_canonicalises(self):
        _, rid, _ = self._completed()
        _, _, lower = self._verify(rid)
        status, _, upper = self._get(
            f"/requests/{rid.upper()}/tombstone-verification"
        )
        self.assertEqual(status, 200)
        self.assertEqual(upper, lower)
        self.assertEqual(json.loads(upper)["request_id"], rid)

    # -- query-string gate ----------------------------------------------

    def test_unknown_query_parameter_is_400(self):
        _, rid, _ = self._completed()
        for path in (
            f"/requests/{rid}/tombstone-verification?tenant_id=tenant-a&cursor=abc",
            f"/requests/{rid}/tombstone-verification?limit=10",
            f"/requests/{rid}/tombstone-verification?status=completed",
        ):
            with self.subTest(path=path):
                status, _, data = self._request("GET", path)
                self.assertEqual((status, data), (400, INVALID_REQUEST))

    def test_duplicate_tenant_id_is_400(self):
        _, rid, _ = self._completed()
        status, _, data = self._request(
            "GET",
            f"/requests/{rid}/tombstone-verification"
            "?tenant_id=tenant-a&tenant_id=tenant-a",
        )
        self.assertEqual((status, data), (400, INVALID_REQUEST))

    def test_missing_or_empty_tenant_is_400(self):
        _, rid, _ = self._completed()
        status, _, data = self._request(
            "GET", f"/requests/{rid}/tombstone-verification"
        )
        self.assertEqual((status, data), (400, INVALID_REQUEST))
        status, _, data = self._request(
            "GET", f"/requests/{rid}/tombstone-verification?tenant_id="
        )
        self.assertEqual((status, data), (400, INVALID_REQUEST))
        status, _, data = self._request(
            "GET", f"/requests/{rid}/tombstone-verification",
            headers={"X-Tenant-Id": "   "},
        )
        self.assertEqual((status, data), (400, INVALID_REQUEST))

    # -- routing / error mapping ----------------------------------------

    def test_malformed_unknown_cross_tenant_ids_are_404(self):
        _, rid, _ = self._completed()
        unknown = "00000000-0000-4000-8000-000000000000"
        for path, tenant in (
            ("/requests/not-a-uuid/tombstone-verification", "tenant-a"),
            (f"/requests/{unknown}/tombstone-verification", "tenant-a"),
            (f"/requests/{rid}/tombstone-verification", "tenant-b"),
            (f"/requests/{rid}/tombstone-verification?tenant_id=tenant-b", None),
        ):
            with self.subTest(path=path):
                status, _, data = self._request(
                    "GET", path,
                    headers={"X-Tenant-Id": tenant} if tenant else {},
                )
                self.assertEqual((status, data), (404, NOT_FOUND))

    def test_extra_path_segments_are_404(self):
        _, rid, _ = self._completed()
        for path in (
            f"/requests/{rid}/tombstone-verification/",
            f"/requests/{rid}/tombstone-verification/extra",
            "/requests//tombstone-verification",
            f"/requests/{rid}/other",
        ):
            with self.subTest(path=path):
                status, _, data = self._get(path)
                self.assertEqual((status, data), (404, NOT_FOUND))

    def test_non_get_methods_are_405_with_get_allow(self):
        _, rid, _ = self._completed()
        for method in ("POST", "PUT", "DELETE", "PATCH", "OPTIONS"):
            with self.subTest(method=method):
                status, headers, data = self._request(
                    method, f"/requests/{rid}/tombstone-verification",
                    body={} if method == "POST" else None,
                )
                self.assertEqual(status, 405)
                self.assertEqual(data, METHOD_NOT_ALLOWED)
                self.assertEqual(headers.get("Allow"), "GET")
        status, headers, data = self._request(
            "HEAD", f"/requests/{rid}/tombstone-verification"
        )
        self.assertEqual(status, 405)
        self.assertEqual(headers.get("Allow"), "GET")
        self.assertEqual(data, b"")

    def test_corrupt_database_is_503(self):
        _, rid, _ = self._completed()
        with open(self.db_path, "wb") as handle:
            handle.write(b"not a sqlite database")
        status, _, data = self._verify(rid)
        self.assertEqual((status, data), (503, STORAGE_UNAVAILABLE))
        self.assertEqual(set(json.loads(data)), {"error"})

    # -- read-only ------------------------------------------------------

    def test_verification_read_never_writes(self):
        _, rid, _ = self._completed()
        for _ in range(5):
            status, _, _ = self._verify(rid)
            self.assertEqual(status, 200)
        with sqlite3.connect(self.db_path) as conn:
            # The read created no attempt, receipt or extra finish row.
            self.assertEqual(
                conn.execute(
                    "SELECT count(*) FROM claim_attempts WHERE request_id = ?",
                    (rid,),
                ).fetchone()[0],
                1,
            )
            self.assertEqual(
                conn.execute(
                    "SELECT count(*) FROM deletion_receipts WHERE request_id = ?",
                    (rid,),
                ).fetchone()[0],
                0,
            )
            self.assertEqual(
                conn.execute(
                    "SELECT count(*) FROM deletion_tombstones WHERE request_id = ?",
                    (rid,),
                ).fetchone()[0],
                2,
            )
            self.assertEqual(
                conn.execute(
                    "SELECT count(*) FROM deletion_tombstone_finishes "
                    "WHERE request_id = ?",
                    (rid,),
                ).fetchone()[0],
                1,
            )
        self.assertEqual(
            self.store.get_status("tenant-a", rid)["status"], "completed"
        )


SUBMIT_A = {"token": "tok-submit-a", "tenant_id": "tenant-a",
            "roles": ["request:submit"]}
READ_A = {"token": "tok-read-a", "tenant_id": "tenant-a",
          "roles": ["request:read"]}
READ_B = {"token": "tok-read-b", "tenant_id": "tenant-b",
          "roles": ["request:read"]}
RECONCILE_A = {"token": "tok-reconcile-a", "tenant_id": "tenant-a",
               "roles": ["request:reconcile"]}


class TombstoneVerificationAuthTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "verify-auth.db")
        self.store = RequestStore(self.db_path)
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

    def _path(self):
        return f"/requests/{self.rid}/tombstone-verification"

    def test_missing_malformed_or_unknown_token_is_401(self):
        for headers in (
            {},
            {"Authorization": "Bearer unknown-token"},
            {"Authorization": "Basic tok-read-a"},
            {"Authorization": "Bearer "},
        ):
            with self.subTest(headers=headers):
                status, _, data = self._request(
                    "GET", self._path(),
                    headers={**headers, "X-Tenant-Id": "tenant-a"},
                )
                self.assertEqual((status, data), (401, UNAUTHORIZED))

    def test_wrong_role_is_403(self):
        for token in ("tok-submit-a", "tok-reconcile-a"):
            with self.subTest(token=token):
                status, _, data = self._request(
                    "GET", self._path(),
                    headers={**self._bearer(token),
                             "X-Tenant-Id": "tenant-a"},
                )
                self.assertEqual((status, data), (403, FORBIDDEN))

    def test_tenant_mismatch_is_403_before_id_validation(self):
        for path in (
            self._path(),
            "/requests/not-a-uuid/tombstone-verification",
        ):
            with self.subTest(path=path):
                status, _, data = self._request(
                    "GET", path,
                    headers={**self._bearer("tok-read-a"),
                             "X-Tenant-Id": "tenant-b"},
                )
                self.assertEqual((status, data), (403, FORBIDDEN))
        status, _, data = self._request(
            "GET", f"{self._path()}?tenant_id=tenant-b",
            headers=self._bearer("tok-read-a"),
        )
        self.assertEqual((status, data), (403, FORBIDDEN))

    def test_missing_tenant_with_valid_token_is_400(self):
        status, _, data = self._request(
            "GET", self._path(), headers=self._bearer("tok-read-a")
        )
        self.assertEqual((status, data), (400, INVALID_REQUEST))

    def test_authorized_read_succeeds(self):
        status, _, data = self._request(
            "GET", self._path(),
            headers={**self._bearer("tok-read-a"),
                     "X-Tenant-Id": "tenant-a"},
        )
        self.assertEqual(status, 200)
        record = json.loads(data)
        self.assertEqual(list(record), FIELDS)
        self.assertEqual(record["request_id"], self.rid)
        self.assertEqual(record["coverage"], "not_applicable")
        self.assertIs(record["verified"], False)
        self.assertEqual(record["reasons"], ["request_not_completed"])

    def test_cross_tenant_record_is_404_with_matching_token(self):
        status, _, data = self._request(
            "GET", self._path(),
            headers={**self._bearer("tok-read-b"),
                     "X-Tenant-Id": "tenant-b"},
        )
        self.assertEqual((status, data), (404, NOT_FOUND))

    def test_method_check_precedes_authentication(self):
        status, _, data = self._request("PUT", self._path())
        self.assertEqual((status, data), (405, METHOD_NOT_ALLOWED))


class BrokenVerificationStoreTests(unittest.TestCase):
    """A substitute store must never leak faults or a malformed report."""

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
            def verify_deletion_tombstones(self, *a, **k):
                raise RuntimeError(secret)

        fixture = self._serve(BrokenStore())
        try:
            rid = "00000000-0000-4000-8000-000000000000"
            status, data = self._get(
                fixture.port, f"/requests/{rid}/tombstone-verification"
            )
            self.assertEqual(status, 503)
            self.assertEqual(data, STORAGE_UNAVAILABLE)
            self.assertNotIn(b"SECRET", data)
        finally:
            fixture.__exit__(None, None, None)

    def test_malformed_report_becomes_503(self):
        rid = "00000000-0000-4000-8000-000000000000"
        good_digest = "a" * 64
        cases = (
            "not json\n",
            json.dumps(["unexpected"]) + "\n",  # not an object
            json.dumps(
                {
                    "request_id": rid,
                    "verified": True,
                    "coverage": "complete",
                    "tombstone_count": 0,
                    "evidence_digest": good_digest,
                    "reasons": [],
                    "extra": 1,
                },
                separators=(",", ":"),
            )
            + "\n",  # extra key
            json.dumps(
                {
                    "request_id": "not-a-uuid",
                    "verified": True,
                    "coverage": "complete",
                    "tombstone_count": 0,
                    "evidence_digest": good_digest,
                    "reasons": [],
                },
                separators=(",", ":"),
            )
            + "\n",  # bad request id
            json.dumps(
                {
                    "request_id": rid,
                    "verified": False,
                    "coverage": "bogus",
                    "tombstone_count": 0,
                    "evidence_digest": None,
                    "reasons": [],
                },
                separators=(",", ":"),
            )
            + "\n",  # bad coverage
            json.dumps(
                {
                    "request_id": rid,
                    "verified": False,
                    "coverage": "not_applicable",
                    "tombstone_count": 0,
                    "evidence_digest": good_digest,
                    "reasons": ["request_not_completed"],
                },
                separators=(",", ":"),
            )
            + "\n",  # digest present outside complete
            json.dumps(
                {
                    "request_id": rid,
                    "verified": True,
                    "coverage": "complete",
                    "tombstone_count": 0,
                    "evidence_digest": good_digest,
                    "reasons": ["evidence_digest_mismatch"],
                },
                separators=(",", ":"),
            )
            + "\n",  # verified true despite reasons
            json.dumps(
                {
                    "request_id": rid,
                    "verified": False,
                    "coverage": "complete",
                    "tombstone_count": 0,
                    "evidence_digest": "ZZ" * 32,
                    "reasons": ["evidence_digest_mismatch"],
                },
                separators=(",", ":"),
            )
            + "\n",  # non-lowercase-hex digest
            json.dumps(
                {
                    "request_id": rid,
                    "verified": False,
                    "coverage": "complete",
                    "tombstone_count": 0,
                    "evidence_digest": good_digest,
                    "reasons": ["some_unknown_reason"],
                },
                separators=(",", ":"),
            )
            + "\n",  # unknown reason code
        )

        class Store:
            def __init__(self, report):
                self._report = report

            def verify_deletion_tombstones(self, *a, **k):
                return self._report

        for report in cases:
            with self.subTest(report=report):
                fixture = self._serve(Store(report))
                try:
                    status, data = self._get(
                        fixture.port, f"/requests/{rid}/tombstone-verification"
                    )
                    self.assertEqual(status, 503)
                    self.assertEqual(data, STORAGE_UNAVAILABLE)
                finally:
                    fixture.__exit__(None, None, None)

    def test_unsorted_or_duplicate_reasons_are_normalised(self):
        rid = "00000000-0000-4000-8000-000000000000"

        class Store:
            def verify_deletion_tombstones(self, *a, **k):
                return json.dumps(
                    {
                        "request_id": rid,
                        "verified": False,
                        "coverage": "complete",
                        "tombstone_count": 1,
                        "evidence_digest": "a" * 64,
                        "reasons": [
                            "tombstone_record_invalid",
                            "evidence_digest_mismatch",
                            "evidence_digest_mismatch",
                        ],
                    },
                    separators=(",", ":"),
                ) + "\n"

        fixture = self._serve(Store())
        try:
            status, data = self._get(
                fixture.port, f"/requests/{rid}/tombstone-verification"
            )
            # A well-formed but un-normalised (duplicated, unsorted)
            # report is re-rendered into the canonical single line.
            self.assertEqual(status, 200)
            record = json.loads(data)
            self.assertEqual(
                record["reasons"],
                ["evidence_digest_mismatch", "tombstone_record_invalid"],
            )
            self.assertEqual(
                data,
                b'{"request_id":"%s","verified":false,"coverage":"complete",'
                b'"tombstone_count":1,"evidence_digest":"%s",'
                b'"reasons":["evidence_digest_mismatch",'
                b'"tombstone_record_invalid"]}\n'
                % (rid.encode("ascii"), b"a" * 64),
            )
        finally:
            fixture.__exit__(None, None, None)


if __name__ == "__main__":
    unittest.main()
