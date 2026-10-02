"""HTTP tests for the read-only deletion-tombstones observation endpoint.

Covers GET /requests/{request_id}/deletion-tombstones only: response
shape, field order and trailing newline, ordering and commitment rules,
byte stability across restarts, the strictly read-only guarantee, tenant
resolution, error codes, optional bearer auth and the no-leak rendering
contract. Tombstone registration and scoped completion stay on the
storage layer; these tests drive them directly to settle a ledger.
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

    def _submit(self, tenant="tenant-a", key="key-1", subject="subject-1",
                scopes=("email", "profile")):
        return self.store.submit(tenant, subject, list(scopes), key)

    def _get(self, path, tenant="tenant-a"):
        return self._request(
            "GET", path, headers={"X-Tenant-Id": tenant} if tenant else {}
        )

    def _recorded(self, tenant="tenant-a", scopes=("email", "profile")):
        """Submit, claim and register one tombstone per scope."""
        receipt = self._submit(tenant=tenant, scopes=scopes)
        rid = receipt["request_id"]
        claim = self.store.claim_next(tenant, "worker-1", 60)
        items = [
            _item("profile", "op-2", adapter="adapter-b", outcome="absent"),
            _item("email", "op-1", adapter="adapter-a"),
        ]
        self.store.record_deletion_tombstones(
            tenant, rid, claim["claim_token"], items
        )
        return rid, claim


class TombstonesEndpointTests(_StoreCase):
    def test_empty_ledger_shape_and_trailing_newline(self):
        receipt = self._submit()
        rid = receipt["request_id"]
        status, headers, data = self._get(
            f"/requests/{rid}/deletion-tombstones"
        )
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("Content-Type"), "application/json")
        self.assertEqual(data.count(b"\n"), 1)
        self.assertTrue(data.endswith(b"\n"))
        self.assertEqual(
            data,
            (
                f'{{"request_id":"{rid}","tombstones":[],'
                f'"recorded_at":null,"evidence_digest":null}}\n'
            ).encode(),
        )

    def test_recorded_ledger_shape_order_and_commitment(self):
        rid, _ = self._recorded()
        status, _, data = self._get(f"/requests/{rid}/deletion-tombstones")
        self.assertEqual(status, 200)
        payload = json.loads(data)
        self.assertEqual(
            list(payload),
            ["request_id", "tombstones", "recorded_at", "evidence_digest"],
        )
        self.assertEqual(payload["request_id"], rid)
        tombstones = payload["tombstones"]
        self.assertEqual(len(tombstones), 2)
        for entry in tombstones:
            self.assertEqual(
                list(entry),
                [
                    "adapter_id",
                    "scope",
                    "operation_id",
                    "outcome",
                    "proof_digest",
                    "recorded_at",
                ],
            )
        # Ordered by normalized scope, then adapter_id.
        self.assertEqual(
            [(t["scope"], t["adapter_id"]) for t in tombstones],
            [("email", "adapter-a"), ("profile", "adapter-b")],
        )
        self.assertEqual(tombstones[0]["outcome"], "deleted")
        self.assertEqual(tombstones[1]["outcome"], "absent")
        # The read matches the storage layer verbatim.
        stored = self.store.get_deletion_tombstones("tenant-a", rid)
        self.assertEqual(payload, stored)
        self.assertIsInstance(payload["recorded_at"], str)
        self.assertEqual(payload["recorded_at"], stored["recorded_at"])
        self.assertEqual(payload["evidence_digest"], stored["evidence_digest"])

    def test_top_level_recorded_at_is_earliest_registration(self):
        receipt = self._submit()
        rid = receipt["request_id"]
        claim = self.store.claim_next("tenant-a", "worker-1", 60)
        token = claim["claim_token"]
        first = self.store.record_deletion_tombstones(
            "tenant-a", rid, token, [_item("email", "op-1")]
        )
        self.store.record_deletion_tombstones(
            "tenant-a", rid, token, [_item("profile", "op-2")]
        )
        _, _, data = self._get(f"/requests/{rid}/deletion-tombstones")
        payload = json.loads(data)
        self.assertEqual(payload["recorded_at"], first["recorded_at"])
        self.assertEqual(len(payload["tombstones"]), 2)
        self.assertEqual(
            payload["evidence_digest"],
            self.store.get_deletion_tombstones("tenant-a", rid)[
                "evidence_digest"
            ],
        )

    def test_byte_stable_across_restart(self):
        rid, _ = self._recorded()
        _, _, first = self._get(f"/requests/{rid}/deletion-tombstones")
        self._fixture.__exit__(None, None, None)
        rebuilt = RequestStore(self.db_path)
        with _Server(rebuilt) as fixture:
            conn = http.client.HTTPConnection(
                "127.0.0.1", fixture.port, timeout=10
            )
            try:
                conn.request(
                    "GET", f"/requests/{rid}/deletion-tombstones",
                    headers={"X-Tenant-Id": "tenant-a"},
                )
                resp = conn.getresponse()
                status, second = resp.status, resp.read()
            finally:
                conn.close()
        self.assertEqual(status, 200)
        self.assertEqual(second, first)

    def test_read_only_creates_no_bookkeeping(self):
        receipt = self._submit()
        rid = receipt["request_id"]
        _, _, one = self._get(f"/requests/{rid}/deletion-tombstones")
        _, _, two = self._get(f"/requests/{rid}/deletion-tombstones")
        self.assertEqual(one, two)
        with sqlite3.connect(self.db_path) as conn:
            for table in ("deletion_tombstones", "deletion_tombstone_finishes"):
                count = conn.execute(
                    f"SELECT count(*) FROM {table} "
                    "WHERE tenant_id = ? AND request_id = ?",
                    ("tenant-a", rid),
                ).fetchone()[0]
                self.assertEqual(count, 0)
        # Observation did not advance the request: still claimable once.
        claim = self.store.claim_next("tenant-a", "worker-1", 60)
        self.assertIsNotNone(claim)
        self.assertEqual(claim["request_id"], rid)
        self.assertEqual(
            self.store.get_status("tenant-a", rid)["status"], "processing"
        )

    def test_response_never_carries_credentials_or_request_fields(self):
        rid, claim = self._recorded()
        _, _, data = self._get(f"/requests/{rid}/deletion-tombstones")
        for secret in (
            claim["claim_token"].encode(),
            b"claim_token",
            b"worker",
            b"subject",
            b"idempotency",
            b"key-1",
        ):
            self.assertNotIn(secret, data)

    def test_query_parameter_tenant_and_header_precedence(self):
        rid, _ = self._recorded()
        status, _, data = self._request(
            "GET", f"/requests/{rid}/deletion-tombstones?tenant_id=tenant-a"
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)["request_id"], rid)
        # Last non-empty query value wins without a header.
        status, _, _ = self._request(
            "GET",
            f"/requests/{rid}/deletion-tombstones"
            "?tenant_id=tenant-b&tenant_id=tenant-a",
        )
        self.assertEqual(status, 200)
        # A non-empty header overrides the query string.
        status, _, data = self._request(
            "GET",
            f"/requests/{rid}/deletion-tombstones?tenant_id=tenant-a",
            headers={"X-Tenant-Id": "tenant-b"},
        )
        self.assertEqual((status, data), (404, NOT_FOUND))

    def test_errors_missing_tenant_malformed_unknown_cross_tenant(self):
        rid, _ = self._recorded()
        unknown = "00000000-0000-4000-8000-000000000000"
        # Missing tenant.
        status, _, data = self._request(
            "GET", f"/requests/{rid}/deletion-tombstones"
        )
        self.assertEqual((status, data), (400, INVALID_REQUEST))
        # Malformed / unknown / cross-tenant ids are all 404.
        for path, tenant in (
            ("/requests/not-a-uuid/deletion-tombstones", "tenant-a"),
            (f"/requests/{unknown}/deletion-tombstones", "tenant-a"),
            (f"/requests/{rid}/deletion-tombstones", "tenant-b"),
            (f"/requests/{rid}/deletion-tombstones?tenant_id=tenant-b", None),
        ):
            with self.subTest(path=path):
                status, _, data = self._request(
                    "GET", path,
                    headers={"X-Tenant-Id": tenant} if tenant else {},
                )
                self.assertEqual((status, data), (404, NOT_FOUND))
        # Illegal sub-resource shapes stay unknown paths.
        for path in (
            f"/requests/{rid}/deletion-tombstones/",
            f"/requests/{rid}/deletion-tombstones/extra",
            "/requests//deletion-tombstones",
            f"/requests/{rid}/other",
        ):
            with self.subTest(path=path):
                status, _, data = self._get(path)
                self.assertEqual((status, data), (404, NOT_FOUND))

    def test_unsupported_methods_are_405(self):
        rid, _ = self._recorded()
        for method in ("POST", "PUT", "DELETE", "PATCH", "OPTIONS"):
            with self.subTest(method=method):
                status, headers, data = self._request(
                    method, f"/requests/{rid}/deletion-tombstones",
                    body={} if method == "POST" else None,
                )
                self.assertEqual(status, 405)
                self.assertEqual(data, METHOD_NOT_ALLOWED)
                self.assertEqual(headers.get("Allow"), "GET")

    def test_corrupt_database_is_503(self):
        receipt = self._submit()
        with open(self.db_path, "wb") as handle:
            handle.write(b"not a sqlite database")
        status, _, data = self._get(
            f"/requests/{receipt['request_id']}/deletion-tombstones"
        )
        self.assertEqual((status, data), (503, STORAGE_UNAVAILABLE))

    def test_corrupt_tombstone_row_is_503(self):
        rid, _ = self._recorded()
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute(
                "UPDATE deletion_tombstones SET outcome = 'purged' "
                "WHERE operation_id = 'op-1'"
            )
            conn.commit()
        finally:
            conn.close()
        status, _, data = self._get(f"/requests/{rid}/deletion-tombstones")
        self.assertEqual((status, data), (503, STORAGE_UNAVAILABLE))


SUBMIT_A = {"token": "tok-submit-a", "tenant_id": "tenant-a",
            "roles": ["request:submit"]}
READ_A = {"token": "tok-read-a", "tenant_id": "tenant-a",
          "roles": ["request:read"]}
READ_B = {"token": "tok-read-b", "tenant_id": "tenant-b",
          "roles": ["request:read"]}


class TombstonesAuthTests(unittest.TestCase):
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
        claim = self.store.claim_next("tenant-a", "worker-1", 60)
        self.store.record_deletion_tombstones(
            "tenant-a", self.rid, claim["claim_token"],
            [_item("email", "op-1")],
        )

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
                    f"/requests/{self.rid}/deletion-tombstones",
                    headers={**headers, "X-Tenant-Id": "tenant-a"},
                )
                self.assertEqual((status, data), (401, UNAUTHORIZED))

    def test_submit_role_is_forbidden(self):
        status, _, data = self._request(
            "GET", f"/requests/{self.rid}/deletion-tombstones",
            headers={**self._bearer("tok-submit-a"),
                     "X-Tenant-Id": "tenant-a"},
        )
        self.assertEqual((status, data), (403, FORBIDDEN))

    def test_tenant_mismatch_is_forbidden_before_id_validation(self):
        # Foreign tenant header forbids even a malformed id, before storage.
        for path in (
            f"/requests/{self.rid}/deletion-tombstones",
            "/requests/not-a-uuid/deletion-tombstones",
        ):
            with self.subTest(path=path):
                status, _, data = self._request(
                    "GET", path,
                    headers={**self._bearer("tok-read-a"),
                             "X-Tenant-Id": "tenant-b"},
                )
                self.assertEqual((status, data), (403, FORBIDDEN))
        # Query parameter target tenant is checked too.
        status, _, data = self._request(
            "GET",
            f"/requests/{self.rid}/deletion-tombstones?tenant_id=tenant-b",
            headers=self._bearer("tok-read-a"),
        )
        self.assertEqual((status, data), (403, FORBIDDEN))

    def test_missing_tenant_with_valid_token_is_400(self):
        status, _, data = self._request(
            "GET", f"/requests/{self.rid}/deletion-tombstones",
            headers=self._bearer("tok-read-a"),
        )
        self.assertEqual((status, data), (400, INVALID_REQUEST))

    def test_authorized_read_and_header_precedence(self):
        status, _, data = self._request(
            "GET", f"/requests/{self.rid}/deletion-tombstones",
            headers={**self._bearer("tok-read-a"),
                     "X-Tenant-Id": "tenant-a"},
        )
        self.assertEqual(status, 200)
        payload = json.loads(data)
        self.assertEqual(payload["request_id"], self.rid)
        self.assertEqual(len(payload["tombstones"]), 1)
        # Header tenant-b matches read-b despite the query naming tenant-a.
        status, _, data = self._request(
            "GET",
            f"/requests/{self.rid}/deletion-tombstones?tenant_id=tenant-a",
            headers={**self._bearer("tok-read-b"),
                     "X-Tenant-Id": "tenant-b"},
        )
        self.assertEqual((status, data), (404, NOT_FOUND))

    def test_method_check_precedes_authentication(self):
        status, _, data = self._request(
            "PUT", f"/requests/{self.rid}/deletion-tombstones"
        )
        self.assertEqual((status, data), (405, METHOD_NOT_ALLOWED))


class UnauthenticatedTombstonesTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "evidence.db")
        self.store = RequestStore(self.db_path)
        self._fixture = _Server(self.store, None)
        self._fixture.__enter__()
        self.port = self._fixture.port

    def tearDown(self):
        self._fixture.__exit__(None, None, None)
        self._tmp.cleanup()

    def test_authorization_header_is_ignored_without_auth_config(self):
        rid = self.store.submit(
            "tenant-a", "subject-1", ["email"], "key-1"
        )["request_id"]
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request(
                "GET", f"/requests/{rid}/deletion-tombstones",
                headers={"X-Tenant-Id": "tenant-a",
                         "Authorization": "Bearer anything"},
            )
            resp = conn.getresponse()
            status, data = resp.status, resp.read()
        finally:
            conn.close()
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)["tombstones"], [])


class BrokenStoreTombstonesTests(unittest.TestCase):
    """A substitute store must never leak storage faults or extra fields."""

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

    def test_storage_exceptions_become_503(self):
        secret = "SECRET-SQL-DETAIL-PATH"

        class BrokenStore:
            def get_deletion_tombstones(self, *a, **k):
                raise OSError(secret)

        fixture = self._serve(BrokenStore())
        try:
            rid = "00000000-0000-4000-8000-000000000000"
            status, data = self._get(
                fixture.port, f"/requests/{rid}/deletion-tombstones"
            )
            self.assertEqual(status, 503)
            self.assertEqual(data, STORAGE_UNAVAILABLE)
            self.assertNotIn(b"SECRET", data)
        finally:
            fixture.__exit__(None, None, None)

    def test_extra_or_malformed_fields_become_503(self):
        rid = "00000000-0000-4000-8000-000000000000"
        good_entry = {
            "adapter_id": "adapter-1",
            "scope": "email",
            "operation_id": "op-1",
            "outcome": "deleted",
            "proof_digest": _digest("op-1"),
            "recorded_at": "2026-01-01T00:00:00Z",
        }
        good_record = {
            "request_id": rid,
            "tombstones": [dict(good_entry)],
            "recorded_at": "2026-01-01T00:00:00Z",
            "evidence_digest": _digest("ledger"),
        }

        def record_with(**overrides):
            record = dict(good_record)
            record.update(overrides)
            return record

        leaky_entry = dict(good_entry)
        leaky_entry["claim_token"] = "token-SECRET"
        bad_records = [
            # Extra top-level or entry keys.
            record_with(subject_id="subject-SECRET"),
            record_with(tombstones=[leaky_entry]),
            # Wrong value domains.
            record_with(tombstones=[dict(good_entry, outcome="purged")]),
            record_with(tombstones=[dict(good_entry, proof_digest="zz" * 32)]),
            record_with(tombstones=[dict(good_entry, scope="")]),
            record_with(evidence_digest="not-a-digest"),
            # Ordering violated.
            record_with(tombstones=[
                dict(good_entry, scope="profile", adapter_id="a"),
                dict(good_entry, scope="email", adapter_id="b"),
            ]),
            # Empty ledger must commit to nothing.
            record_with(tombstones=[]),
            record_with(tombstones=[], recorded_at=None,
                        evidence_digest=None, extra="x"),
        ]
        for record in bad_records:
            with self.subTest(record=record):

                class BadStore:
                    def get_deletion_tombstones(self, *a, **k):
                        return record

                fixture = self._serve(BadStore())
                try:
                    status, data = self._get(
                        fixture.port,
                        f"/requests/{rid}/deletion-tombstones",
                    )
                    self.assertEqual(status, 503)
                    self.assertEqual(data, STORAGE_UNAVAILABLE)
                    self.assertNotIn(b"SECRET", data)
                finally:
                    fixture.__exit__(None, None, None)


if __name__ == "__main__":
    unittest.main()
