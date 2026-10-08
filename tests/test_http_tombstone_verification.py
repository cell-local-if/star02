"""Tests for the read-only GET /requests/{request_id}/tombstone-verification
endpoint.

Covers the HTTP exposure of the store's strictly read-only tombstone
ledger verification: the verbatim single-line compact JSON body
(byte-identical to ``RequestStore.verify_deletion_tombstones`` for the
same tenant and request, exactly one trailing newline, no wrapper
object), the coverage ladder and every reason code over HTTP, the
tenant-resolution and query-string rules, the 400/401/403/404/405/503
error contract and its ordering, the optional bearer-token RBAC and the
strictly read-only behaviour (the read never advances state, never
creates an attempt, a tombstone or a receipt and never changes the
audit chain).
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

NOT_FOUND = b'{"error":"not_found"}\n'
INVALID_REQUEST = b'{"error":"invalid_request"}\n'
METHOD_NOT_ALLOWED = b'{"error":"method_not_allowed"}\n'
STORAGE_UNAVAILABLE = b'{"error":"storage_unavailable"}\n'
UNAUTHORIZED = b'{"error":"unauthorized"}\n'
FORBIDDEN = b'{"error":"forbidden"}\n'

HEX64 = re.compile(r"^[0-9a-f]{64}$")
FIELDS = [
    "request_id",
    "verified",
    "coverage",
    "tombstone_count",
    "evidence_digest",
    "reasons",
]
COVERAGES = {"complete", "incomplete", "not_applicable"}
REASONS = {
    "request_not_completed",
    "scope_coverage_invalid",
    "tombstone_record_invalid",
    "operation_id_invalid",
    "evidence_digest_mismatch",
}

READ_A = {"token": "tok-read-a", "tenant_id": "tenant-a",
          "roles": ["request:read"]}
SUBMIT_A = {"token": "tok-submit-a", "tenant_id": "tenant-a",
            "roles": ["request:submit"]}
READ_B = {"token": "tok-read-b", "tenant_id": "tenant-b",
          "roles": ["request:read"]}

TABLES = (
    "requests",
    "status_events",
    "claim_attempts",
    "claim_tokens",
    "deletion_tombstones",
    "deletion_tombstone_finishes",
    "deletion_receipts",
    "receipt_keys",
    "audit_anchors",
    "audit_anchor_meta",
    "anchor_key_generations",
)


def _digest(seed):
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


def _item(scope, operation, adapter="adapter-1", outcome="deleted"):
    return {
        "adapter_id": adapter,
        "scope": scope,
        "operation_id": operation,
        "outcome": outcome,
        "proof_digest": _digest(operation),
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
        self.db_path = os.path.join(self._tmp.name, "nested", "evidence.db")
        self.store = RequestStore(self.db_path)
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

    def _get(self, path, tenant="tenant-a"):
        return self._request(
            "GET", path, headers={"X-Tenant-Id": tenant} if tenant else {}
        )

    def _verification(self, rid, tenant="tenant-a"):
        return self._get(f"/requests/{rid}/tombstone-verification", tenant)

    def _submit(self, tenant="tenant-a", key="idem-1",
                scopes=("email", "profile")):
        return self.store.submit(tenant, "subject-1", list(scopes), key)

    def _claimed(self, tenant="tenant-a", key="idem-1",
                 scopes=("email", "profile")):
        accepted = self._submit(tenant, key, scopes)
        claim = self.store.claim_next(tenant, "worker-1", 60)
        return accepted, claim

    def _completed(self, tenant="tenant-a", key="idem-1",
                   scopes=("email", "profile")):
        """A request completed through the scoped finish, full coverage."""
        accepted, claim = self._claimed(tenant, key, scopes)
        rid = accepted["request_id"]
        token = claim["claim_token"]
        items = [_item(scope, f"op-{scope}") for scope in scopes]
        self.store.record_deletion_tombstones(tenant, rid, token, items)
        self.store.finish_scoped_claim(tenant, rid, token, "completed")
        return accepted, items

    def _raw(self):
        return sqlite3.connect(self.db_path)

    def _tamper(self, sql, params=()):
        with self._raw() as conn:
            conn.execute(sql, params)

    def _table_dump(self, table):
        with self._raw() as raw:
            return raw.execute(f"SELECT * FROM {table}").fetchall()

    def _all_tables(self):
        return {name: self._table_dump(name) for name in TABLES}

    # -- success shape --------------------------------------------------

    def test_body_is_verbatim_store_text(self):
        accepted, _ = self._completed()
        rid = accepted["request_id"]
        status, headers, data = self._verification(rid)
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("Content-Type"), "application/json")
        # Byte-identical to the store's own read-only verification.
        self.assertEqual(
            data,
            self.store.verify_deletion_tombstones(
                "tenant-a", rid
            ).encode("utf-8"),
        )
        # Exactly one line, exactly one trailing newline.
        self.assertTrue(data.endswith(b"\n"))
        self.assertFalse(data.endswith(b"\n\n"))
        self.assertEqual(data.count(b"\n"), 1)
        self.assertNotIn(b"\r", data)
        payload = json.loads(data)
        self.assertEqual(list(payload), FIELDS)
        self.assertEqual(payload["request_id"], rid)
        # Compact rendering: no insignificant whitespace anywhere.
        self.assertEqual(
            data,
            (json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
             + "\n").encode("utf-8"),
        )

    def test_complete_coverage_verifies(self):
        accepted, items = self._completed()
        status, _, data = self._verification(accepted["request_id"])
        self.assertEqual(status, 200)
        payload = json.loads(data)
        self.assertIs(payload["verified"], True)
        self.assertEqual(payload["coverage"], "complete")
        self.assertEqual(payload["tombstone_count"], len(items))
        self.assertTrue(HEX64.match(payload["evidence_digest"]))
        self.assertEqual(payload["reasons"], [])

    def test_not_completed_is_not_applicable(self):
        accepted = self._submit()
        status, _, data = self._verification(accepted["request_id"])
        self.assertEqual(status, 200)
        payload = json.loads(data)
        self.assertIs(payload["verified"], False)
        self.assertEqual(payload["coverage"], "not_applicable")
        self.assertEqual(payload["tombstone_count"], 0)
        self.assertIsNone(payload["evidence_digest"])
        self.assertEqual(payload["reasons"], ["request_not_completed"])

    def test_incomplete_coverage_reports_scope_coverage_invalid(self):
        # Completed through the plain finish, which checks no coverage.
        accepted, claim = self._claimed()
        rid = accepted["request_id"]
        self.store.record_deletion_tombstones(
            "tenant-a", rid, claim["claim_token"], [_item("email", "op-1")]
        )
        self.store.finish_claim(
            "tenant-a", rid, claim["claim_token"], "completed"
        )
        status, _, data = self._verification(rid)
        self.assertEqual(status, 200)
        payload = json.loads(data)
        self.assertIs(payload["verified"], False)
        self.assertEqual(payload["coverage"], "incomplete")
        self.assertEqual(payload["tombstone_count"], 1)
        self.assertIsNone(payload["evidence_digest"])
        self.assertEqual(payload["reasons"], ["scope_coverage_invalid"])

    def test_tombstone_record_invalid_reason(self):
        accepted, _ = self._completed()
        rid = accepted["request_id"]
        self._tamper(
            "UPDATE deletion_tombstones SET outcome = 'purged' "
            "WHERE operation_id = 'op-email'"
        )
        status, _, data = self._verification(rid)
        self.assertEqual(status, 200)
        payload = json.loads(data)
        self.assertEqual(payload["coverage"], "complete")
        self.assertIs(payload["verified"], False)
        self.assertIn("tombstone_record_invalid", payload["reasons"])

    def test_operation_id_invalid_reason(self):
        accepted, _ = self._completed()
        rid = accepted["request_id"]
        other = self._submit(key="idem-2")
        with self._raw() as conn:
            # Simulate an out-of-band ledger that lost the global
            # operation-number uniqueness guard.
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
        status, _, data = self._verification(rid)
        self.assertEqual(status, 200)
        payload = json.loads(data)
        self.assertEqual(payload["coverage"], "complete")
        self.assertIs(payload["verified"], False)
        self.assertEqual(payload["reasons"], ["operation_id_invalid"])

    def test_evidence_digest_mismatch_reason(self):
        accepted, _ = self._completed()
        rid = accepted["request_id"]
        self._tamper(
            "UPDATE deletion_tombstone_finishes SET evidence_digest = ? "
            "WHERE request_id = ?",
            (_digest("altered"), rid),
        )
        status, _, data = self._verification(rid)
        self.assertEqual(status, 200)
        payload = json.loads(data)
        self.assertEqual(payload["coverage"], "complete")
        self.assertIs(payload["verified"], False)
        self.assertEqual(payload["reasons"], ["evidence_digest_mismatch"])
        # The reported digest is the recomputed one, not the ledger's.
        self.assertNotEqual(payload["evidence_digest"], _digest("altered"))

    def test_reasons_coexist_sorted_and_deduplicated(self):
        accepted, _ = self._completed()
        rid = accepted["request_id"]
        # A foreign-scope tombstone breaks coverage and is itself an
        # invalid record; the finish commitment is altered too.
        with self._raw() as conn:
            conn.execute(
                "INSERT INTO deletion_tombstones ("
                "tenant_id, request_id, scope, adapter_id, operation_id, "
                "outcome, proof_digest, recorded_at"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "tenant-a",
                    rid,
                    "unknown-scope",
                    "adapter-9",
                    "op-9",
                    "deleted",
                    _digest("op-9"),
                    "2026-01-01T00:00:00Z",
                ),
            )
        status, _, data = self._verification(rid)
        self.assertEqual(status, 200)
        payload = json.loads(data)
        self.assertEqual(payload["coverage"], "incomplete")
        self.assertIs(payload["verified"], False)
        self.assertIsNone(payload["evidence_digest"])
        self.assertEqual(
            payload["reasons"],
            ["scope_coverage_invalid", "tombstone_record_invalid"],
        )
        # Deduplicated and ordered by Unicode code point.
        self.assertEqual(
            payload["reasons"], sorted(set(payload["reasons"]))
        )
        for reason in payload["reasons"]:
            self.assertIn(reason, REASONS)

    def test_coverage_and_reason_vocabularies(self):
        accepted, _ = self._completed()
        status, _, data = self._verification(accepted["request_id"])
        self.assertEqual(status, 200)
        payload = json.loads(data)
        self.assertIn(payload["coverage"], COVERAGES)
        self.assertLessEqual(set(payload["reasons"]), REASONS)

    def test_body_never_carries_request_details(self):
        accepted, _ = self._completed()
        status, _, data = self._verification(accepted["request_id"])
        self.assertEqual(status, 200)
        # No subject, raw scope, idempotency key, worker, adapter,
        # operation number or proof body is ever exposed.
        for leaked in (
            b"subject-1",
            b"email",
            b"profile",
            b"idem-1",
            b"worker-1",
            b"adapter-1",
            b"op-email",
            b"op-profile",
        ):
            self.assertNotIn(leaked, data)

    def test_repeated_reads_are_byte_identical(self):
        accepted, _ = self._completed()
        rid = accepted["request_id"]
        first = None
        for _ in range(5):
            status, _, data = self._verification(rid)
            self.assertEqual(status, 200)
            if first is None:
                first = data
            else:
                self.assertEqual(data, first)

    def test_survives_process_rebuild(self):
        accepted, _ = self._completed()
        rid = accepted["request_id"]
        status, _, before = self._verification(rid)
        self.assertEqual(status, 200)
        rebuilt = RequestStore(self.db_path)
        self.assertEqual(
            before,
            rebuilt.verify_deletion_tombstones("tenant-a", rid).encode("utf-8"),
        )

    # -- tenant resolution and query string ------------------------------

    def test_header_tenant_wins_over_query(self):
        accepted, _ = self._completed()
        rid = accepted["request_id"]
        status, _, data = self._request(
            "GET",
            f"/requests/{rid}/tombstone-verification?tenant_id=tenant-b",
            headers={"X-Tenant-Id": "tenant-a"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)["request_id"], rid)

    def test_query_only_tenant_is_accepted(self):
        accepted, _ = self._completed()
        rid = accepted["request_id"]
        status, _, data = self._get(
            f"/requests/{rid}/tombstone-verification?tenant_id=tenant-a",
            tenant=None,
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)["request_id"], rid)

    def test_missing_tenant_is_400(self):
        accepted, _ = self._completed()
        status, _, data = self._get(
            f"/requests/{accepted['request_id']}/tombstone-verification",
            tenant=None,
        )
        self.assertEqual(status, 400)
        self.assertEqual(data, INVALID_REQUEST)

    def test_empty_tenant_is_400(self):
        accepted, _ = self._completed()
        status, _, data = self._get(
            f"/requests/{accepted['request_id']}/tombstone-verification",
            tenant="   ",
        )
        self.assertEqual(status, 400)
        self.assertEqual(data, INVALID_REQUEST)

    def test_duplicate_tenant_id_is_400(self):
        accepted, _ = self._completed()
        rid = accepted["request_id"]
        status, _, data = self._get(
            f"/requests/{rid}/tombstone-verification"
            "?tenant_id=tenant-a&tenant_id=tenant-a",
            tenant=None,
        )
        self.assertEqual(status, 400)
        self.assertEqual(data, INVALID_REQUEST)

    def test_unknown_query_parameter_is_400(self):
        accepted, _ = self._completed()
        rid = accepted["request_id"]
        status, _, data = self._get(
            f"/requests/{rid}/tombstone-verification?cursor=abc"
        )
        self.assertEqual(status, 400)
        self.assertEqual(data, INVALID_REQUEST)

    # -- 404 / 405 / deeper paths ----------------------------------------

    def test_unknown_request_is_404(self):
        self._completed()
        status, _, data = self._verification(
            "123e4567-e89b-42d3-a456-426614174000"
        )
        self.assertEqual(status, 404)
        self.assertEqual(data, NOT_FOUND)

    def test_malformed_request_id_is_404(self):
        self._completed()
        status, _, data = self._verification("not-a-uuid")
        self.assertEqual(status, 404)
        self.assertEqual(data, NOT_FOUND)

    def test_cross_tenant_request_is_404(self):
        accepted, _ = self._completed()
        status, _, data = self._verification(
            accepted["request_id"], tenant="tenant-b"
        )
        self.assertEqual(status, 404)
        self.assertEqual(data, NOT_FOUND)

    def test_non_get_methods_are_405(self):
        accepted, _ = self._completed()
        rid = accepted["request_id"]
        path = f"/requests/{rid}/tombstone-verification"
        for method in ("POST", "PUT", "DELETE", "PATCH", "OPTIONS"):
            with self.subTest(method=method):
                status, headers, data = self._request(
                    method, path, headers={"X-Tenant-Id": "tenant-a"}
                )
                self.assertEqual(status, 405)
                self.assertEqual(data, METHOD_NOT_ALLOWED)
                self.assertEqual(headers.get("Allow"), "GET")

    def test_head_is_405_without_body(self):
        accepted, _ = self._completed()
        status, headers, data = self._request(
            "HEAD",
            f"/requests/{accepted['request_id']}/tombstone-verification",
            headers={"X-Tenant-Id": "tenant-a"},
        )
        self.assertEqual(status, 405)
        self.assertEqual(data, b"")
        self.assertEqual(headers.get("Allow"), "GET")

    def test_deeper_path_is_404(self):
        accepted, _ = self._completed()
        rid = accepted["request_id"]
        status, _, data = self._get(
            f"/requests/{rid}/tombstone-verification/extra"
        )
        self.assertEqual(status, 404)
        self.assertEqual(data, NOT_FOUND)

    # -- storage faults ---------------------------------------------------

    def test_corrupt_request_row_is_503(self):
        accepted, _ = self._completed()
        rid = accepted["request_id"]
        self._tamper(
            "UPDATE requests SET scopes_json = 'not-json' "
            "WHERE request_id = ?",
            (rid,),
        )
        status, _, data = self._verification(rid)
        self.assertEqual(status, 503)
        self.assertEqual(data, STORAGE_UNAVAILABLE)

    def test_corrupt_finish_row_is_503(self):
        accepted, _ = self._completed()
        rid = accepted["request_id"]
        self._tamper(
            "UPDATE deletion_tombstone_finishes SET result = 'purged' "
            "WHERE request_id = ?",
            (rid,),
        )
        status, _, data = self._verification(rid)
        self.assertEqual(status, 503)
        self.assertEqual(data, STORAGE_UNAVAILABLE)

    def test_dropped_ledger_is_503(self):
        accepted, _ = self._completed()
        rid = accepted["request_id"]
        self._tamper("DROP TABLE deletion_tombstones")
        status, _, data = self._verification(rid)
        self.assertEqual(status, 503)
        self.assertEqual(data, STORAGE_UNAVAILABLE)

    # -- read-only guarantees ---------------------------------------------

    def test_read_has_no_side_effects(self):
        accepted, _ = self._completed()
        rid = accepted["request_id"]
        before = self._all_tables()
        for _ in range(3):
            status, _, _ = self._verification(rid)
            self.assertEqual(status, 200)
        self.assertEqual(self._all_tables(), before)

    def test_error_reads_have_no_side_effects(self):
        accepted, _ = self._completed()
        rid = accepted["request_id"]
        before = self._all_tables()
        self._verification(rid, tenant="tenant-b")
        self._verification("123e4567-e89b-42d3-a456-426614174000")
        self._get(
            f"/requests/{rid}/tombstone-verification?cursor=abc"
        )
        self._request(
            "POST",
            f"/requests/{rid}/tombstone-verification",
            headers={"X-Tenant-Id": "tenant-a"},
        )
        self.assertEqual(self._all_tables(), before)


class TombstoneVerificationAuthTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "evidence.db")
        self.store = RequestStore(self.db_path)
        self.auth = AuthConfig([READ_A, SUBMIT_A, READ_B])
        self._fixture = _Server(self.store, auth=self.auth)
        self._fixture.__enter__()
        self.port = self._fixture.port

    def tearDown(self):
        self._fixture.__exit__(None, None, None)
        self._tmp.cleanup()

    def _completed(self, tenant="tenant-a"):
        accepted = self.store.submit(tenant, "subject-1", ["email"], "idem-1")
        rid = accepted["request_id"]
        claim = self.store.claim_next(tenant, "worker-1", 60)
        token = claim["claim_token"]
        self.store.record_deletion_tombstones(
            tenant, rid, token, [_item("email", "op-email")]
        )
        self.store.finish_scoped_claim(tenant, rid, token, "completed")
        return accepted

    def _request(self, method, path, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request(method, path, headers=headers or {})
            resp = conn.getresponse()
            return resp.status, dict(resp.getheaders()), resp.read()
        finally:
            conn.close()

    def _get(self, path, token=None, tenant="tenant-a"):
        headers = {}
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        if tenant is not None:
            headers["X-Tenant-Id"] = tenant
        return self._request("GET", path, headers=headers)

    def test_read_role_verifies_the_ledger(self):
        accepted = self._completed()
        rid = accepted["request_id"]
        status, _, data = self._get(
            f"/requests/{rid}/tombstone-verification", token="tok-read-a"
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            data,
            self.store.verify_deletion_tombstones(
                "tenant-a", rid
            ).encode("utf-8"),
        )

    def test_missing_token_is_401(self):
        accepted = self._completed()
        status, _, data = self._get(
            f"/requests/{accepted['request_id']}/tombstone-verification"
        )
        self.assertEqual(status, 401)
        self.assertEqual(data, UNAUTHORIZED)

    def test_malformed_token_is_401(self):
        accepted = self._completed()
        status, _, data = self._get(
            f"/requests/{accepted['request_id']}/tombstone-verification",
            token="",
        )
        self.assertEqual(status, 401)
        self.assertEqual(data, UNAUTHORIZED)

    def test_unknown_token_is_401(self):
        accepted = self._completed()
        status, _, data = self._get(
            f"/requests/{accepted['request_id']}/tombstone-verification",
            token="tok-nobody",
        )
        self.assertEqual(status, 401)
        self.assertEqual(data, UNAUTHORIZED)

    def test_wrong_role_is_403(self):
        accepted = self._completed()
        status, _, data = self._get(
            f"/requests/{accepted['request_id']}/tombstone-verification",
            token="tok-submit-a",
        )
        self.assertEqual(status, 403)
        self.assertEqual(data, FORBIDDEN)

    def test_cross_tenant_principal_is_403(self):
        accepted = self._completed()
        # tenant-b's reader may not name tenant-a as the target tenant.
        status, _, data = self._get(
            f"/requests/{accepted['request_id']}/tombstone-verification",
            token="tok-read-b",
        )
        self.assertEqual(status, 403)
        self.assertEqual(data, FORBIDDEN)

    def test_other_tenants_request_is_404_for_foreign_principal(self):
        accepted = self._completed()
        # tenant-b's reader resolving its own tenant never sees
        # tenant-a's request.
        status, _, data = self._get(
            f"/requests/{accepted['request_id']}/tombstone-verification",
            token="tok-read-b",
            tenant="tenant-b",
        )
        self.assertEqual(status, 404)
        self.assertEqual(data, NOT_FOUND)


if __name__ == "__main__":
    unittest.main()
