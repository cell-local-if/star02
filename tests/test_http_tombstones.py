"""HTTP tests for GET /requests/{request_id}/tombstones.

Covers the tenant-scoped, paginated deletion-tombstone read: the fixed
single-line body shape and field order, whole-ledger recorded_at and
evidence_digest on every page, limit/cursor validation, cursor binding
and replay, tenant resolution and header precedence, the shared
400/401/403/404/405/503 error contract, read-only guarantees and the
sensitive-information boundary.
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


def _digest(seed):
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


def _item(scope, operation, adapter=None, outcome="deleted", proof=None):
    return {
        "adapter_id": adapter if adapter is not None else f"adapter-{operation}",
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


class _StoreCase(unittest.TestCase):
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

    def _ledger(self, items, tenant="tenant-a", key="key-1",
                scopes=("email", "profile")):
        receipt = self.store.submit(tenant, "subject-1", list(scopes), key)
        rid = receipt["request_id"]
        claim = self.store.claim_next(tenant, "worker-1", 3600)
        self.store.record_deletion_tombstones(
            tenant, rid, claim["claim_token"], items
        )
        return rid


class TombstonePageShapeTests(_StoreCase):
    def test_shape_field_order_and_trailing_newline(self):
        rid = self._ledger([
            _item("profile", "op-2", adapter="adapter-b", outcome="absent"),
            _item("email", "op-1", adapter="adapter-a"),
        ])
        status, headers, data = self._get(f"/requests/{rid}/tombstones")
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("Content-Type"), "application/json")
        self.assertTrue(data.endswith(b"\n"))
        self.assertEqual(data.count(b"\n"), 1)
        payload = json.loads(data)
        self.assertEqual(
            list(payload),
            ["request_id", "tombstones", "recorded_at",
             "evidence_digest", "next_cursor"],
        )
        self.assertEqual(payload["request_id"], rid)
        self.assertEqual(len(payload["tombstones"]), 2)
        for entry in payload["tombstones"]:
            self.assertEqual(
                list(entry),
                ["adapter_id", "scope", "operation_id", "outcome",
                 "proof_digest", "recorded_at"],
            )
        # Normalized scope code point order, then adapter_id.
        self.assertEqual(
            [(t["scope"], t["adapter_id"]) for t in payload["tombstones"]],
            [("email", "adapter-a"), ("profile", "adapter-b")],
        )
        first, second = payload["tombstones"]
        self.assertEqual(first["outcome"], "deleted")
        self.assertEqual(second["outcome"], "absent")
        for entry in payload["tombstones"]:
            self.assertRegex(entry["proof_digest"], r"^[0-9a-f]{64}$")
            self.assertIsInstance(entry["recorded_at"], str)
        # Whole-ledger fields match the storage layer verbatim.
        full = self.store.get_deletion_tombstones("tenant-a", rid)
        self.assertEqual(payload["recorded_at"], full["recorded_at"])
        self.assertEqual(payload["evidence_digest"], full["evidence_digest"])
        self.assertRegex(payload["evidence_digest"], r"^[0-9a-f]{64}$")
        self.assertIsNone(payload["next_cursor"])
        # The body never carries a subject, an idempotency key, a worker
        # identity or a claim credential.
        for leaked in (b"subject-1", b"key-1", b"worker-1", b"claim_token"):
            self.assertNotIn(leaked, data)

    def test_empty_ledger_renders_nulls(self):
        receipt = self.store.submit(
            "tenant-a", "subject-1", ["email"], "key-1"
        )
        rid = receipt["request_id"]
        status, _, data = self._get(f"/requests/{rid}/tombstones")
        self.assertEqual(status, 200)
        self.assertEqual(
            data,
            b'{"request_id":"' + rid.encode()
            + b'","tombstones":[],"recorded_at":null,'
            b'"evidence_digest":null,"next_cursor":null}\n',
        )

    def test_matches_storage_layer_page_for_page(self):
        items = [_item("email", f"op-{i:04d}", adapter=f"adapter-{i:04d}")
                 for i in range(7)]
        rid = self._ledger(items, scopes=("email",))
        cursor = None
        pages = 0
        while True:
            query = "" if cursor is None else f"?cursor={cursor}"
            status, _, data = self._get(
                f"/requests/{rid}/tombstones{query}&limit=3"
                if cursor else f"/requests/{rid}/tombstones?limit=3"
            )
            self.assertEqual(status, 200)
            http_page = json.loads(data)
            store_page = self.store.page_deletion_tombstones(
                "tenant-a", rid, cursor=cursor, limit=3
            )
            self.assertEqual(http_page, store_page)
            # Every page carries the whole-ledger commitment.
            self.assertIsNotNone(http_page["evidence_digest"])
            self.assertIsNotNone(http_page["recorded_at"])
            pages += 1
            cursor = http_page["next_cursor"]
            if cursor is None:
                break
            self.assertLessEqual(pages, 10)
        self.assertEqual(pages, 3)

    def test_default_limit_is_100_and_cursor_replay_is_byte_identical(self):
        items = [_item("email", f"op-{i:04d}", adapter=f"adapter-{i:04d}")
                 for i in range(150)]
        rid = self._ledger(items, scopes=("email",))
        status, _, first = self._get(f"/requests/{rid}/tombstones")
        self.assertEqual(status, 200)
        first_page = json.loads(first)
        self.assertEqual(len(first_page["tombstones"]), 100)
        cursor = first_page["next_cursor"]
        self.assertIsNotNone(cursor)
        # Replaying the same first-page read is byte-identical.
        _, _, again = self._get(f"/requests/{rid}/tombstones")
        self.assertEqual(again, first)
        # The cursor resumes strictly after the first page's last item
        # and a replayed cursor returns byte-identical bytes as well.
        status, _, second = self._get(
            f"/requests/{rid}/tombstones?cursor={cursor}"
        )
        self.assertEqual(status, 200)
        second_page = json.loads(second)
        self.assertEqual(len(second_page["tombstones"]), 50)
        self.assertIsNone(second_page["next_cursor"])
        self.assertEqual(
            second_page["tombstones"][0]["operation_id"], "op-0100"
        )
        _, _, second_again = self._get(
            f"/requests/{rid}/tombstones?cursor={cursor}"
        )
        self.assertEqual(second_again, second)


class TombstoneQueryValidationTests(_StoreCase):
    def setUp(self):
        super().setUp()
        self.rid = self._ledger([_item("email", "op-1"),
                                 _item("profile", "op-2")])

    def test_unknown_and_duplicate_parameters_are_400(self):
        for query in (
            "status=accepted",
            "limit=1&bogus=1",
            "cursor=x&cursor=y",
            "limit=1&limit=2",
            "tenant_id=tenant-a&status=accepted",
        ):
            with self.subTest(query=query):
                status, _, data = self._get(
                    f"/requests/{self.rid}/tombstones?{query}"
                )
                self.assertEqual((status, data), (400, INVALID_REQUEST))

    def test_invalid_limits_are_400(self):
        for value in ("0", "1001", "-1", "1.5", "abc", "", "1" * 40,
                      "true", "%201", "1%20"):
            with self.subTest(limit=value):
                status, _, data = self._get(
                    f"/requests/{self.rid}/tombstones?limit={value}"
                )
                self.assertEqual((status, data), (400, INVALID_REQUEST))

    def test_valid_limit_bounds_are_200(self):
        for value in ("1", "1000"):
            with self.subTest(limit=value):
                status, _, _ = self._get(
                    f"/requests/{self.rid}/tombstones?limit={value}"
                )
                self.assertEqual(status, 200)

    def test_empty_malformed_and_foreign_cursors_are_400(self):
        first = json.loads(
            self._get(f"/requests/{self.rid}/tombstones?limit=1")[2]
        )
        cursor = first["next_cursor"]
        self.assertIsNotNone(cursor)
        for value in ("", "garbage", "dt1.", "dt1.!!!", "rc1.QUJDRA==",
                      "rl1.QUJDRA=="):
            with self.subTest(cursor=value):
                status, _, data = self._get(
                    f"/requests/{self.rid}/tombstones?cursor={value}"
                )
                self.assertEqual((status, data), (400, INVALID_REQUEST))
        # A cursor issued for another request of the same tenant.
        other_rid = self._ledger(
            [_item("email", "other-op-9"), _item("email", "other-op-8")],
            key="key-2", scopes=("email",),
        )
        status, _, data = self._get(
            f"/requests/{other_rid}/tombstones?cursor={cursor}"
        )
        self.assertEqual((status, data), (400, INVALID_REQUEST))
        # A cursor issued under another tenant's coordinates.
        other_tenant_rid = self._ledger(
            [_item("email", "tb-op-1"), _item("email", "tb-op-2")],
            tenant="tenant-b", key="key-3", scopes=("email",),
        )
        status, _, data = self._get(
            f"/requests/{other_tenant_rid}/tombstones?cursor={cursor}",
            tenant="tenant-b",
        )
        self.assertEqual((status, data), (400, INVALID_REQUEST))

    def test_stale_cursor_after_ledger_grows_is_400(self):
        items = [_item("email", "stale-op-1"), _item("email", "stale-op-2")]
        receipt = self.store.submit("tenant-a", "subject-1", ["email"], "k")
        rid = receipt["request_id"]
        claim = self.store.claim_next("tenant-a", "worker-1", 3600)
        self.store.record_deletion_tombstones(
            "tenant-a", rid, claim["claim_token"], items
        )
        first = json.loads(
            self._get(f"/requests/{rid}/tombstones?limit=1")[2]
        )
        cursor = first["next_cursor"]
        self.assertIsNotNone(cursor)
        # The cursor still resumes while the ledger is unchanged.
        status, _, _ = self._get(f"/requests/{rid}/tombstones?cursor={cursor}")
        self.assertEqual(status, 200)
        # Once the ledger grows, the old cursor is caller error.
        self.store.record_deletion_tombstones(
            "tenant-a", rid, claim["claim_token"], [_item("email", "stale-op-3")]
        )
        status, _, data = self._get(
            f"/requests/{rid}/tombstones?cursor={cursor}"
        )
        self.assertEqual((status, data), (400, INVALID_REQUEST))
        # A fresh first-page read over the new snapshot still works.
        status, _, data = self._get(f"/requests/{rid}/tombstones")
        self.assertEqual(status, 200)
        self.assertEqual(len(json.loads(data)["tombstones"]), 3)


class TombstoneRoutingAndErrorTests(_StoreCase):
    def test_tenant_resolution_and_header_precedence(self):
        rid = self._ledger([_item("email", "op-1")])
        # Query-only tenant.
        status, _, data = self._request(
            "GET", f"/requests/{rid}/tombstones?tenant_id=tenant-a"
        )
        self.assertEqual(status, 200)
        # Last non-empty query value wins without a header.
        status, _, _ = self._request(
            "GET",
            f"/requests/{rid}/tombstones?tenant_id=tenant-b"
            "&tenant_id=tenant-a",
        )
        self.assertEqual(status, 200)
        # A non-empty header overrides the query string.
        status, _, data = self._request(
            "GET",
            f"/requests/{rid}/tombstones?tenant_id=tenant-a",
            headers={"X-Tenant-Id": "tenant-b"},
        )
        self.assertEqual((status, data), (404, NOT_FOUND))

    def test_missing_tenant_malformed_unknown_cross_tenant(self):
        rid = self._ledger([_item("email", "op-1")])
        unknown = "00000000-0000-4000-8000-000000000000"
        status, _, data = self._request(
            "GET", f"/requests/{rid}/tombstones"
        )
        self.assertEqual((status, data), (400, INVALID_REQUEST))
        for path, tenant in (
            ("/requests/not-a-uuid/tombstones", "tenant-a"),
            (f"/requests/{unknown}/tombstones", "tenant-a"),
            (f"/requests/{rid}/tombstones", "tenant-b"),
            (f"/requests/{rid}/tombstones?tenant_id=tenant-b", None),
        ):
            with self.subTest(path=path):
                status, _, data = self._request(
                    "GET", path,
                    headers={"X-Tenant-Id": tenant} if tenant else {},
                )
                self.assertEqual((status, data), (404, NOT_FOUND))
        for path in (
            f"/requests/{rid}/tombstones/",
            f"/requests/{rid}/tombstones/extra",
            "/requests//tombstones",
        ):
            with self.subTest(path=path):
                status, _, data = self._get(path)
                self.assertEqual((status, data), (404, NOT_FOUND))

    def test_unsupported_methods_are_405_and_head_has_no_body(self):
        rid = self._ledger([_item("email", "op-1")])
        for method in ("POST", "PUT", "DELETE", "PATCH", "OPTIONS"):
            with self.subTest(method=method):
                status, headers, data = self._request(
                    method, f"/requests/{rid}/tombstones",
                    body={} if method == "POST" else None,
                )
                self.assertEqual(status, 405)
                self.assertEqual(data, METHOD_NOT_ALLOWED)
                self.assertEqual(headers.get("Allow"), "GET")
        status, headers, data = self._request(
            "HEAD", f"/requests/{rid}/tombstones"
        )
        self.assertEqual(status, 405)
        self.assertEqual(headers.get("Allow"), "GET")
        self.assertEqual(data, b"")

    def test_corrupt_database_is_503(self):
        rid = self._ledger([_item("email", "op-1")])
        with open(self.db_path, "wb") as handle:
            handle.write(b"not a sqlite database")
        status, _, data = self._get(f"/requests/{rid}/tombstones")
        self.assertEqual((status, data), (503, STORAGE_UNAVAILABLE))

    def test_corrupt_tombstone_row_is_503(self):
        rid = self._ledger([_item("email", "op-1")])
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE deletion_tombstones SET outcome = 'purged' "
                "WHERE operation_id = 'op-1'"
            )
        status, _, data = self._get(f"/requests/{rid}/tombstones")
        self.assertEqual((status, data), (503, STORAGE_UNAVAILABLE))

    def test_read_is_read_only(self):
        rid = self._ledger([_item("email", "op-1"), _item("profile", "op-2")])
        before = self.store.get_deletion_tombstones("tenant-a", rid)
        _, _, one = self._get(f"/requests/{rid}/tombstones?limit=1")
        page = json.loads(one)
        _, _, two = self._get(
            f"/requests/{rid}/tombstones?cursor={page['next_cursor']}"
        )
        self.assertEqual(json.loads(two)["tombstones"][0]["scope"], "profile")
        # The ledger, its digest, the status and the attempts are
        # untouched by the reads.
        self.assertEqual(
            self.store.get_deletion_tombstones("tenant-a", rid), before
        )
        self.assertEqual(
            self.store.get_status("tenant-a", rid)["status"], "processing"
        )
        self.assertEqual(
            len(self.store.get_execution_log("tenant-a", rid)), 1
        )
        with sqlite3.connect(self.db_path) as raw:
            finish_count = raw.execute(
                "SELECT COUNT(*) FROM deletion_tombstone_finishes "
                "WHERE request_id = ?",
                (rid,),
            ).fetchone()[0]
        self.assertEqual(finish_count, 0)


SUBMIT_A = {"token": "tok-submit-a", "tenant_id": "tenant-a",
            "roles": ["request:submit"]}
READ_A = {"token": "tok-read-a", "tenant_id": "tenant-a",
          "roles": ["request:read"]}
READ_B = {"token": "tok-read-b", "tenant_id": "tenant-b",
          "roles": ["request:read"]}


class TombstoneAuthTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "evidence.db")
        self.store = RequestStore(self.db_path)
        self.auth = AuthConfig([SUBMIT_A, READ_A, READ_B])
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

    def test_missing_or_unknown_token_is_401(self):
        for headers in (
            {},
            {"Authorization": "Bearer unknown-token"},
            {"Authorization": "Basic tok-read-a"},
            {"Authorization": "Bearer "},
        ):
            with self.subTest(headers=headers):
                status, _, data = self._request(
                    "GET",
                    f"/requests/{self.rid}/tombstones",
                    headers={**headers, "X-Tenant-Id": "tenant-a"},
                )
                self.assertEqual((status, data), (401, UNAUTHORIZED))

    def test_submit_role_is_forbidden(self):
        status, _, data = self._request(
            "GET", f"/requests/{self.rid}/tombstones",
            headers={**self._bearer("tok-submit-a"),
                     "X-Tenant-Id": "tenant-a"},
        )
        self.assertEqual((status, data), (403, FORBIDDEN))

    def test_tenant_mismatch_is_forbidden_before_id_validation(self):
        for path in (
            f"/requests/{self.rid}/tombstones",
            "/requests/not-a-uuid/tombstones",
        ):
            with self.subTest(path=path):
                status, _, data = self._request(
                    "GET", path,
                    headers={**self._bearer("tok-read-a"),
                             "X-Tenant-Id": "tenant-b"},
                )
                self.assertEqual((status, data), (403, FORBIDDEN))
        status, _, data = self._request(
            "GET", f"/requests/{self.rid}/tombstones?tenant_id=tenant-b",
            headers=self._bearer("tok-read-a"),
        )
        self.assertEqual((status, data), (403, FORBIDDEN))

    def test_missing_tenant_with_valid_token_is_400(self):
        status, _, data = self._request(
            "GET", f"/requests/{self.rid}/tombstones",
            headers=self._bearer("tok-read-a"),
        )
        self.assertEqual((status, data), (400, INVALID_REQUEST))

    def test_authorized_read_and_cross_tenant_404(self):
        status, _, data = self._request(
            "GET", f"/requests/{self.rid}/tombstones",
            headers={**self._bearer("tok-read-a"),
                     "X-Tenant-Id": "tenant-a"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)["tombstones"], [])
        # The other tenant's principal gets an indistinguishable 404.
        status, _, data = self._request(
            "GET", f"/requests/{self.rid}/tombstones",
            headers={**self._bearer("tok-read-b"),
                     "X-Tenant-Id": "tenant-b"},
        )
        self.assertEqual((status, data), (404, NOT_FOUND))

    def test_method_check_precedes_authentication(self):
        status, _, data = self._request(
            "PUT", f"/requests/{self.rid}/tombstones"
        )
        self.assertEqual((status, data), (405, METHOD_NOT_ALLOWED))


class BrokenStoreTombstoneTests(unittest.TestCase):
    """A substitute store must never leak storage faults or extra fields."""

    def _get(self, port, path):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        try:
            conn.request("GET", path, headers={"X-Tenant-Id": "tenant-a"})
            resp = conn.getresponse()
            return resp.status, resp.read()
        finally:
            conn.close()

    def test_storage_exceptions_become_503(self):
        secret = "SECRET-SQL-DETAIL-PATH"

        class BrokenStore:
            def page_deletion_tombstones(self, *a, **k):
                raise RuntimeError(secret)

        fixture = _Server(BrokenStore())
        fixture.__enter__()
        try:
            rid = "00000000-0000-4000-8000-000000000000"
            status, data = self._get(
                fixture.port, f"/requests/{rid}/tombstones"
            )
            self.assertEqual(status, 503)
            self.assertEqual(data, STORAGE_UNAVAILABLE)
            self.assertNotIn(b"SECRET", data)
        finally:
            fixture.__exit__(None, None, None)

    def test_extra_or_malformed_fields_become_503(self):
        rid = "00000000-0000-4000-8000-000000000000"

        class LeakyStore:
            def page_deletion_tombstones(self, *a, **k):
                return {
                    "request_id": rid,
                    "tombstones": [{
                        "adapter_id": "adapter-a",
                        "scope": "email",
                        "operation_id": "op-1",
                        "outcome": "deleted",
                        "proof_digest": _digest("op-1"),
                        "recorded_at": "2026-01-01T00:00:00Z",
                        "subject_id": "subject-SECRET",
                    }],
                    "recorded_at": "2026-01-01T00:00:00Z",
                    "evidence_digest": _digest("ledger"),
                    "next_cursor": None,
                }

        class BadOutcomeStore:
            def page_deletion_tombstones(self, *a, **k):
                return {
                    "request_id": rid,
                    "tombstones": [{
                        "adapter_id": "adapter-a",
                        "scope": "email",
                        "operation_id": "op-1",
                        "outcome": "purged",
                        "proof_digest": _digest("op-1"),
                        "recorded_at": "2026-01-01T00:00:00Z",
                    }],
                    "recorded_at": "2026-01-01T00:00:00Z",
                    "evidence_digest": _digest("ledger"),
                    "next_cursor": None,
                }

        class BadDigestStore:
            def page_deletion_tombstones(self, *a, **k):
                return {
                    "request_id": rid,
                    "tombstones": [],
                    "recorded_at": None,
                    "evidence_digest": "not-a-digest",
                    "next_cursor": None,
                }

        for store in (LeakyStore(), BadOutcomeStore(), BadDigestStore()):
            with self.subTest(store=type(store).__name__):
                fixture = _Server(store)
                fixture.__enter__()
                try:
                    status, data = self._get(
                        fixture.port, f"/requests/{rid}/tombstones"
                    )
                    self.assertEqual(status, 503)
                    self.assertEqual(data, STORAGE_UNAVAILABLE)
                    self.assertNotIn(b"SECRET", data)
                finally:
                    fixture.__exit__(None, None, None)


if __name__ == "__main__":
    unittest.main()
