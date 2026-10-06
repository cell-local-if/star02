"""Tests for the read-only GET /requests/{request_id}/deletion-receipt
endpoint.

Covers the HTTP recovery of the request's already-settled deletion
execution receipt without any signature key: the verbatim single-line
compact JSON body (byte-identical to ``RequestStore.get_receipt`` for
the same tenant and request, exactly one trailing newline, no wrapper
object), the tenant-resolution and query-string rules, the
400/401/403/404/405/409/503 error contract and its ordering, the
optional bearer-token RBAC, the freeze semantics (repeat reads, process
rebuilds, concurrent reads and receipt key rotations never changing the
bytes) and the strictly read-only behaviour (the read never mints a
receipt, never registers a key generation and never advances state).
"""

import http.client
import json
import os
import re
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor

from forgetting_evidence.httpapi import AuthConfig, build_server
from forgetting_evidence.requests import RequestStore

KEY = "receipt-key-0001"
NEW_KEY = "receipt-key-0002"

NOT_FOUND = b'{"error":"not_found"}\n'
INVALID_REQUEST = b'{"error":"invalid_request"}\n'
METHOD_NOT_ALLOWED = b'{"error":"method_not_allowed"}\n'
STORAGE_UNAVAILABLE = b'{"error":"storage_unavailable"}\n'
RECEIPT_UNAVAILABLE = b'{"error":"receipt_unavailable"}\n'
UNAUTHORIZED = b'{"error":"unauthorized"}\n'
FORBIDDEN = b'{"error":"forbidden"}\n'

HEX64 = re.compile(r"^[0-9a-f]{64}$")
RFC3339 = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$"
)
FIELDS = [
    "tenant_id",
    "request_id",
    "created_at",
    "completed_at",
    "scope_digest",
    "attempt_digest",
    "tag",
]

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


class DeletionReceiptEndpointTests(unittest.TestCase):
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

    def _receipt(self, rid, tenant="tenant-a"):
        return self._get(f"/requests/{rid}/deletion-receipt", tenant)

    def _submit(self, tenant="tenant-a", key="idem-1"):
        return self.store.submit(tenant, "subject-1", ["email", "profile"], key)

    def _completed(self, tenant="tenant-a", key="idem-1"):
        accepted = self._submit(tenant, key)
        request_id = accepted["request_id"]
        claim = self.store.claim_next(tenant, "worker-1", 60)
        self.store.finish_claim(
            tenant, request_id, claim["claim_token"], "completed"
        )
        return accepted

    def _settled(self, tenant="tenant-a", key="idem-1", receipt_key=KEY):
        accepted = self._completed(tenant, key)
        request_id = accepted["request_id"]
        text = self.store.generate_receipt(tenant, request_id, receipt_key)
        return accepted, text

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
        accepted, text = self._settled()
        rid = accepted["request_id"]
        status, headers, data = self._receipt(rid)
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("Content-Type"), "application/json")
        # Byte-identical to the store's own read-only recovery.
        self.assertEqual(data, text.encode("utf-8"))
        self.assertEqual(
            data, self.store.get_receipt("tenant-a", rid).encode("utf-8")
        )
        # Exactly one line, exactly one trailing newline.
        self.assertTrue(data.endswith(b"\n"))
        self.assertFalse(data.endswith(b"\n\n"))
        self.assertEqual(data.count(b"\n"), 1)
        self.assertNotIn(b"\r", data)
        payload = json.loads(data)
        self.assertEqual(list(payload), FIELDS)
        self.assertEqual(payload["tenant_id"], "tenant-a")
        self.assertEqual(payload["request_id"], rid)
        # Compact rendering: no insignificant whitespace anywhere.
        self.assertEqual(
            data,
            (json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
             + "\n").encode("utf-8"),
        )

    def test_field_shapes(self):
        accepted, _ = self._settled()
        status, _, data = self._receipt(accepted["request_id"])
        self.assertEqual(status, 200)
        payload = json.loads(data)
        self.assertTrue(RFC3339.match(payload["created_at"]))
        self.assertTrue(RFC3339.match(payload["completed_at"]))
        for name in ("scope_digest", "attempt_digest", "tag"):
            self.assertTrue(HEX64.match(payload[name]))

    def test_body_never_carries_request_details(self):
        accepted, _ = self._settled()
        status, _, data = self._receipt(accepted["request_id"])
        self.assertEqual(status, 200)
        # No subject, raw scope, idempotency key, worker, credential,
        # signature key or key fingerprint is ever exposed.
        for leaked in (
            b"subject-1",
            b"email",
            b"profile",
            b"idem-1",
            b"worker-1",
            KEY.encode("utf-8"),
            b"fingerprint",
        ):
            self.assertNotIn(leaked, data)

    # -- freeze semantics -------------------------------------------------

    def test_repeated_reads_are_byte_identical(self):
        accepted, text = self._settled()
        rid = accepted["request_id"]
        for _ in range(5):
            status, _, data = self._receipt(rid)
            self.assertEqual(status, 200)
            self.assertEqual(data, text.encode("utf-8"))

    def test_survives_process_rebuild(self):
        accepted, text = self._settled()
        rid = accepted["request_id"]
        self._fixture.__exit__(None, None, None)
        rebuilt = RequestStore(self.db_path)
        self._fixture = _Server(rebuilt)
        self._fixture.__enter__()
        self.port = self._fixture.port
        status, _, data = self._receipt(rid)
        self.assertEqual(status, 200)
        self.assertEqual(data, text.encode("utf-8"))

    def test_same_bytes_before_and_after_key_rotation(self):
        accepted, text = self._settled()
        rid = accepted["request_id"]
        self.store.rotate_receipt_key("tenant-a", KEY, NEW_KEY)
        status, _, data = self._receipt(rid)
        self.assertEqual(status, 200)
        self.assertEqual(data, text.encode("utf-8"))

    def test_concurrent_reads_are_byte_identical(self):
        accepted, text = self._settled()
        rid = accepted["request_id"]
        expected = text.encode("utf-8")

        def read():
            status, _, data = self._receipt(rid)
            return status, data

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: read(), range(16)))
        for status, data in results:
            self.assertEqual(status, 200)
            self.assertEqual(data, expected)

    # -- tenant resolution and query string -------------------------------

    def test_header_tenant_wins_over_query(self):
        accepted, text = self._settled()
        rid = accepted["request_id"]
        status, _, data = self._get(
            f"/requests/{rid}/deletion-receipt?tenant_id=tenant-b"
        )
        self.assertEqual(status, 200)
        self.assertEqual(data, text.encode("utf-8"))

    def test_query_only_tenant_is_accepted(self):
        accepted, text = self._settled()
        rid = accepted["request_id"]
        status, _, data = self._get(
            f"/requests/{rid}/deletion-receipt?tenant_id=tenant-a",
            tenant=None,
        )
        self.assertEqual(status, 200)
        self.assertEqual(data, text.encode("utf-8"))

    def test_missing_tenant_is_400(self):
        accepted, _ = self._settled()
        status, _, data = self._get(
            f"/requests/{accepted['request_id']}/deletion-receipt",
            tenant=None,
        )
        self.assertEqual(status, 400)
        self.assertEqual(data, INVALID_REQUEST)

    def test_empty_tenant_is_400(self):
        accepted, _ = self._settled()
        rid = accepted["request_id"]
        for path in (
            f"/requests/{rid}/deletion-receipt?tenant_id=",
            f"/requests/{rid}/deletion-receipt?tenant_id=%20",
        ):
            status, _, data = self._get(path, tenant=None)
            self.assertEqual(status, 400)
            self.assertEqual(data, INVALID_REQUEST)
        status, _, data = self._get(
            f"/requests/{rid}/deletion-receipt",
            tenant="   ",
        )
        self.assertEqual(status, 400)
        self.assertEqual(data, INVALID_REQUEST)

    def test_duplicate_tenant_id_is_400(self):
        accepted, _ = self._settled()
        rid = accepted["request_id"]
        status, _, data = self._get(
            f"/requests/{rid}/deletion-receipt"
            "?tenant_id=tenant-a&tenant_id=tenant-a",
            tenant=None,
        )
        self.assertEqual(status, 400)
        self.assertEqual(data, INVALID_REQUEST)

    def test_unknown_query_parameter_is_400(self):
        accepted, _ = self._settled()
        rid = accepted["request_id"]
        for query in ("?cursor=abc", "?limit=10", "?tenant_id=tenant-a&x=1"):
            status, _, data = self._get(
                f"/requests/{rid}/deletion-receipt{query}"
            )
            self.assertEqual(status, 400)
            self.assertEqual(data, INVALID_REQUEST)

    # -- error contract ----------------------------------------------------

    def test_unknown_request_is_404(self):
        self._settled()
        rid = "00000000-0000-4000-8000-000000000000"
        status, _, data = self._receipt(rid)
        self.assertEqual(status, 404)
        self.assertEqual(data, NOT_FOUND)

    def test_malformed_request_id_is_404(self):
        self._settled()
        for rid in ("not-a-uuid", "", "00000000-0000-0000-0000-00000000000g"):
            status, _, data = self._receipt(rid)
            self.assertEqual(status, 404)
            self.assertEqual(data, NOT_FOUND)

    def test_cross_tenant_request_is_404(self):
        accepted, _ = self._settled()
        status, _, data = self._receipt(accepted["request_id"], tenant="tenant-b")
        self.assertEqual(status, 404)
        self.assertEqual(data, NOT_FOUND)

    def test_unsettled_request_is_409(self):
        # Accepted but never executed: no receipt may exist.
        accepted = self._submit()
        status, _, data = self._receipt(accepted["request_id"])
        self.assertEqual(status, 409)
        self.assertEqual(data, RECEIPT_UNAVAILABLE)

    def test_processing_request_is_409(self):
        accepted = self._submit()
        self.store.transition("tenant-a", accepted["request_id"], "processing")
        status, _, data = self._receipt(accepted["request_id"])
        self.assertEqual(status, 409)
        self.assertEqual(data, RECEIPT_UNAVAILABLE)

    def test_failed_request_is_409(self):
        accepted = self._submit()
        rid = accepted["request_id"]
        claim = self.store.claim_next("tenant-a", "worker-1", 60)
        self.store.finish_claim("tenant-a", rid, claim["claim_token"], "failed")
        status, _, data = self._receipt(rid)
        self.assertEqual(status, 409)
        self.assertEqual(data, RECEIPT_UNAVAILABLE)

    def test_completed_without_receipt_is_409(self):
        # The execution completed but no receipt was ever minted; the
        # read must not create one.
        accepted = self._completed()
        status, _, data = self._receipt(accepted["request_id"])
        self.assertEqual(status, 409)
        self.assertEqual(data, RECEIPT_UNAVAILABLE)
        # Still no receipt afterwards: the read minted nothing.
        self.assertEqual(self._table_dump("deletion_receipts"), [])
        self.assertEqual(self._table_dump("receipt_keys"), [])

    def test_non_get_methods_are_405(self):
        accepted, _ = self._settled()
        rid = accepted["request_id"]
        for method in ("POST", "PUT", "DELETE", "PATCH", "OPTIONS"):
            status, headers, data = self._request(
                method, f"/requests/{rid}/deletion-receipt"
            )
            self.assertEqual(status, 405, method)
            self.assertEqual(headers.get("Allow"), "GET")
            self.assertEqual(data, METHOD_NOT_ALLOWED)

    def test_deeper_path_is_404(self):
        accepted, _ = self._settled()
        rid = accepted["request_id"]
        status, _, data = self._get(
            f"/requests/{rid}/deletion-receipt/extra"
        )
        self.assertEqual(status, 404)
        self.assertEqual(data, NOT_FOUND)

    def test_corrupt_receipt_row_is_503(self):
        accepted, _ = self._settled()
        rid = accepted["request_id"]
        self._tamper(
            "UPDATE deletion_receipts SET receipt_json = ? "
            "WHERE tenant_id = ? AND request_id = ?",
            ('{"tenant_id":"tenant-a"}', "tenant-a", rid),
        )
        status, _, data = self._receipt(rid)
        self.assertEqual(status, 503)
        self.assertEqual(data, STORAGE_UNAVAILABLE)

    # -- read-only behaviour ------------------------------------------------

    def test_read_has_no_side_effects(self):
        accepted, _ = self._settled()
        rid = accepted["request_id"]
        before = self._all_tables()
        for _ in range(3):
            status, _, _ = self._receipt(rid)
            self.assertEqual(status, 200)
        self.assertEqual(self._all_tables(), before)

    def test_error_reads_have_no_side_effects(self):
        accepted = self._completed()
        rid = accepted["request_id"]
        before = self._all_tables()
        self._receipt(rid)  # 409: no receipt yet
        self._receipt("00000000-0000-4000-8000-000000000000")  # 404
        self._get(f"/requests/{rid}/deletion-receipt?bogus=1")  # 400
        self.assertEqual(self._all_tables(), before)


class DeletionReceiptAuthTests(unittest.TestCase):
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

    def _settled(self, tenant="tenant-a"):
        accepted = self.store.submit(tenant, "subject-1", ["email"], "idem-1")
        rid = accepted["request_id"]
        claim = self.store.claim_next(tenant, "worker-1", 60)
        self.store.finish_claim(tenant, rid, claim["claim_token"], "completed")
        text = self.store.generate_receipt(tenant, rid, KEY)
        return accepted, text

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

    def test_read_role_recovers_the_receipt(self):
        accepted, text = self._settled()
        rid = accepted["request_id"]
        status, _, data = self._get(
            f"/requests/{rid}/deletion-receipt", token="tok-read-a"
        )
        self.assertEqual(status, 200)
        self.assertEqual(data, text.encode("utf-8"))

    def test_missing_token_is_401(self):
        accepted, _ = self._settled()
        status, _, data = self._get(
            f"/requests/{accepted['request_id']}/deletion-receipt"
        )
        self.assertEqual(status, 401)
        self.assertEqual(data, UNAUTHORIZED)

    def test_unknown_token_is_401(self):
        accepted, _ = self._settled()
        status, _, data = self._get(
            f"/requests/{accepted['request_id']}/deletion-receipt",
            token="tok-nobody",
        )
        self.assertEqual(status, 401)
        self.assertEqual(data, UNAUTHORIZED)

    def test_wrong_role_is_403(self):
        accepted, _ = self._settled()
        status, _, data = self._get(
            f"/requests/{accepted['request_id']}/deletion-receipt",
            token="tok-submit-a",
        )
        self.assertEqual(status, 403)
        self.assertEqual(data, FORBIDDEN)

    def test_cross_tenant_principal_is_403(self):
        accepted, _ = self._settled()
        # tenant-b's reader may not name tenant-a as the target tenant.
        status, _, data = self._get(
            f"/requests/{accepted['request_id']}/deletion-receipt",
            token="tok-read-b",
        )
        self.assertEqual(status, 403)
        self.assertEqual(data, FORBIDDEN)

    def test_other_tenants_receipt_is_404_for_foreign_principal(self):
        accepted, _ = self._settled()
        # tenant-b's reader resolving its own tenant never sees
        # tenant-a's request.
        status, _, data = self._get(
            f"/requests/{accepted['request_id']}/deletion-receipt",
            token="tok-read-b",
            tenant="tenant-b",
        )
        self.assertEqual(status, 404)
        self.assertEqual(data, NOT_FOUND)


if __name__ == "__main__":
    unittest.main()
