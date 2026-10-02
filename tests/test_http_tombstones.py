"""Tests for the read-only GET /requests/{request_id}/deletion-tombstones
endpoint.

Covers the response shape and field order, ordering by normalized scope
then adapter_id, the empty-ledger null commitments, byte stability
across a restart, the strictly read-only behaviour, the error/_method_
routing contract, the optional bearer-token RBAC and the no-leak
guarantees against a broken or substituted store. Tombstone
registration and scoped completion stay storage-layer only.
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

    def _submit(self, tenant="tenant-a", key="key-1", scopes=("email", "profile")):
        return self.store.submit(tenant, "subject-1", list(scopes), key)

    def _recorded(self, scopes=("email", "profile"), tenant="tenant-a"):
        """Submit, claim and register one tombstone per scope."""
        receipt = self._submit(tenant=tenant, scopes=scopes)
        rid = receipt["request_id"]
        claim = self.store.claim_next(tenant, "worker-1", 60)
        items = [
            _item("profile", "op-2", adapter="adapter-b", outcome="absent"),
            _item("email", "op-1", adapter="adapter-a"),
        ][: len(scopes)]
        record = self.store.record_deletion_tombstones(
            tenant, rid, claim["claim_token"], items
        )
        return rid, claim, items, record


class DeletionTombstonesEndpointTests(_StoreCase):
    def test_empty_ledger_shape_and_trailing_newline(self):
        receipt = self._submit()
        rid = receipt["request_id"]
        status, headers, data = self._get(f"/requests/{rid}/deletion-tombstones")
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
        record = json.loads(data)
        self.assertEqual(
            list(record),
            ["request_id", "tombstones", "recorded_at", "evidence_digest"],
        )

    def test_recorded_tombstones_shape_order_and_commitment(self):
        rid, claim, items, record = self._recorded()
        status, _, data = self._get(f"/requests/{rid}/deletion-tombstones")
        self.assertEqual(status, 200)
        payload = json.loads(data)
        self.assertEqual(
            list(payload),
            ["request_id", "tombstones", "recorded_at", "evidence_digest"],
        )
        self.assertEqual(payload["request_id"], rid)
        self.assertEqual(payload["recorded_at"], record["recorded_at"])
        self.assertEqual(payload["evidence_digest"], record["evidence_digest"])
        tombstones = payload["tombstones"]
        # Ordered by normalized scope, then adapter_id.
        self.assertEqual(
            [(t["scope"], t["adapter_id"]) for t in tombstones],
            [("email", "adapter-a"), ("profile", "adapter-b")],
        )
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
        self.assertEqual(tombstones[0]["outcome"], "deleted")
        self.assertEqual(tombstones[1]["outcome"], "absent")
        # No credential, identity, subject or proof body leaks.
        self.assertNotIn(claim["claim_token"].encode(), data)
        self.assertNotIn(b"worker-1", data)
        self.assertNotIn(b"subject-1", data)
        self.assertNotIn(b"key-1", data)

    def test_matches_storage_layer_and_stable_across_restart(self):
        rid, _, _, _ = self._recorded()
        _, _, first = self._get(f"/requests/{rid}/deletion-tombstones")
        self.assertEqual(
            json.loads(first),
            self.store.get_deletion_tombstones("tenant-a", rid),
        )
        self._fixture.__exit__(None, None, None)
        rebuilt = RequestStore(self.db_path)
        with _Server(rebuilt) as fixture:
            conn = http.client.HTTPConnection("127.0.0.1", fixture.port, timeout=10)
            try:
                conn.request(
                    "GET",
                    f"/requests/{rid}/deletion-tombstones",
                    headers={"X-Tenant-Id": "tenant-a"},
                )
                resp = conn.getresponse()
                status, second = resp.status, resp.read()
            finally:
                conn.close()
        self.assertEqual(status, 200)
        self.assertEqual(second, first)

    def test_settled_completion_keeps_same_commitment(self):
        rid, claim, _, record = self._recorded()
        self.store.finish_scoped_claim(
            "tenant-a", rid, claim["claim_token"], "completed"
        )
        status, _, data = self._get(f"/requests/{rid}/deletion-tombstones")
        self.assertEqual(status, 200)
        payload = json.loads(data)
        self.assertEqual(payload["evidence_digest"], record["evidence_digest"])
        self.assertEqual(payload["recorded_at"], record["recorded_at"])
        self.assertEqual(len(payload["tombstones"]), 2)

    def test_read_only_creates_no_bookkeeping(self):
        receipt = self._submit()
        rid = receipt["request_id"]
        _, _, one = self._get(f"/requests/{rid}/deletion-tombstones")
        _, _, two = self._get(f"/requests/{rid}/deletion-tombstones")
        self.assertEqual(one, two)
        with sqlite3.connect(self.db_path) as conn:
            for table in ("claim_attempts", "deletion_tombstones"):
                count = conn.execute(
                    f"SELECT count(*) FROM {table} "
                    "WHERE tenant_id = ? AND request_id = ?",
                    ("tenant-a", rid),
                ).fetchone()[0]
                self.assertEqual(count, 0)
        # Observation did not advance the request's state.
        self.assertEqual(
            self.store.get_status("tenant-a", rid)["status"], "accepted"
        )
        claim = self.store.claim_next("tenant-a", "worker-1", 60)
        self.assertIsNotNone(claim)
        self.assertEqual(claim["request_id"], rid)

    def test_query_parameter_tenant_and_header_precedence(self):
        rid, _, _, _ = self._recorded()
        status, _, data = self._request(
            "GET", f"/requests/{rid}/deletion-tombstones?tenant_id=tenant-a"
        )
        self.assertEqual(status, 200)
        self.assertEqual(len(json.loads(data)["tombstones"]), 2)
        # Last non-empty query value wins without a header.
        status, _, _ = self._request(
            "GET",
            f"/requests/{rid}/deletion-tombstones"
            "?tenant_id=tenant-b&tenant_id=tenant-a",
        )
        self.assertEqual(status, 200)
        # A non-empty header overrides the query string.
        status, _, _ = self._request(
            "GET",
            f"/requests/{rid}/deletion-tombstones?tenant_id=tenant-a",
            headers={"X-Tenant-Id": "tenant-b"},
        )
        self.assertEqual(status, 404)

    def test_errors_missing_tenant_malformed_unknown_cross_tenant(self):
        receipt = self._submit()
        rid = receipt["request_id"]
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
        ):
            with self.subTest(path=path):
                status, _, data = self._get(path)
                self.assertEqual((status, data), (404, NOT_FOUND))

    def test_unsupported_methods_are_405(self):
        receipt = self._submit()
        rid = receipt["request_id"]
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


SUBMIT_A = {"token": "tok-submit-a", "tenant_id": "tenant-a",
            "roles": ["request:submit"]}
READ_A = {"token": "tok-read-a", "tenant_id": "tenant-a",
          "roles": ["request:read"]}
READ_B = {"token": "tok-read-b", "tenant_id": "tenant-b",
          "roles": ["request:read"]}


class DeletionTombstonesAuthTests(unittest.TestCase):
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

    def _path(self, rid=None):
        return f"/requests/{rid or self.rid}/deletion-tombstones"

    def test_missing_or_unknown_token_is_401(self):
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

    def test_submit_role_is_forbidden(self):
        status, _, data = self._request(
            "GET", self._path(),
            headers={**self._bearer("tok-submit-a"),
                     "X-Tenant-Id": "tenant-a"},
        )
        self.assertEqual((status, data), (403, FORBIDDEN))

    def test_tenant_mismatch_is_forbidden_before_id_validation(self):
        for path in (self._path(), self._path("not-a-uuid")):
            with self.subTest(path=path):
                status, _, data = self._request(
                    "GET", path,
                    headers={**self._bearer("tok-read-a"),
                             "X-Tenant-Id": "tenant-b"},
                )
                self.assertEqual((status, data), (403, FORBIDDEN))
        status, _, data = self._request(
            "GET", self._path() + "?tenant_id=tenant-b",
            headers=self._bearer("tok-read-a"),
        )
        self.assertEqual((status, data), (403, FORBIDDEN))

    def test_missing_tenant_with_valid_token_is_400(self):
        status, _, data = self._request(
            "GET", self._path(), headers=self._bearer("tok-read-a")
        )
        self.assertEqual((status, data), (400, INVALID_REQUEST))

    def test_authorized_read_and_cross_tenant_404(self):
        status, _, data = self._request(
            "GET", self._path(),
            headers={**self._bearer("tok-read-a"),
                     "X-Tenant-Id": "tenant-a"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)["tombstones"], [])
        # tenant-b's principal sees the tenant-a record as missing.
        status, _, data = self._request(
            "GET", self._path(),
            headers={**self._bearer("tok-read-b"),
                     "X-Tenant-Id": "tenant-b"},
        )
        self.assertEqual((status, data), (404, NOT_FOUND))

    def test_method_check_precedes_authentication(self):
        status, _, data = self._request("PUT", self._path())
        self.assertEqual((status, data), (405, METHOD_NOT_ALLOWED))


class UnauthenticatedDeletionTombstonesTests(unittest.TestCase):
    def test_authorization_header_is_ignored_without_auth_config(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        store = RequestStore(os.path.join(tmp.name, "evidence.db"))
        rid = store.submit("tenant-a", "subject-1", ["email"], "key-1")[
            "request_id"
        ]
        with _Server(store, None) as fixture:
            conn = http.client.HTTPConnection(
                "127.0.0.1", fixture.port, timeout=10
            )
            try:
                conn.request(
                    "GET",
                    f"/requests/{rid}/deletion-tombstones",
                    headers={"X-Tenant-Id": "tenant-a",
                             "Authorization": "Bearer anything"},
                )
                resp = conn.getresponse()
                status, data = resp.status, resp.read()
            finally:
                conn.close()
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)["tombstones"], [])


class BrokenStoreDeletionTombstonesTests(unittest.TestCase):
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
            def get_deletion_tombstones(self, *a, **k):
                raise OSError(secret)

        with _Server(BrokenStore()) as fixture:
            rid = "00000000-0000-4000-8000-000000000000"
            status, data = self._get(
                fixture.port, f"/requests/{rid}/deletion-tombstones"
            )
        self.assertEqual(status, 503)
        self.assertEqual(data, STORAGE_UNAVAILABLE)
        self.assertNotIn(b"SECRET", data)

    def test_extra_or_malformed_fields_become_503(self):
        rid = "00000000-0000-4000-8000-000000000000"
        good_entry = {
            "adapter_id": "adapter-1",
            "scope": "email",
            "operation_id": "op-1",
            "outcome": "deleted",
            "proof_digest": "a" * 64,
            "recorded_at": "2026-01-01T00:00:00Z",
        }
        good_record = {
            "request_id": rid,
            "tombstones": [dict(good_entry)],
            "recorded_at": "2026-01-01T00:00:00Z",
            "evidence_digest": "b" * 64,
        }
        variants = [
            # Extra leaky keys on the record and on an entry.
            dict(good_record, subject_id="subject-SECRET"),
            dict(good_record,
                 tombstones=[dict(good_entry, proof_body="proof-SECRET")]),
            # Bad outcome, bad digest, unsorted entries, null mismatch.
            dict(good_record,
                 tombstones=[dict(good_entry, outcome="weird")]),
            dict(good_record,
                 tombstones=[dict(good_entry, proof_digest="zz")]),
            dict(good_record, tombstones=[
                dict(good_entry, scope="profile", adapter_id="b"),
                dict(good_entry, scope="email", adapter_id="a"),
            ]),
            dict(good_record, recorded_at=None),
            dict(good_record, evidence_digest=None),
            dict(good_record, tombstones=[]),
        ]
        for record in variants:
            with self.subTest(record=record):

                class LeakyStore:
                    def get_deletion_tombstones(self, *a, **k):
                        return record

                with _Server(LeakyStore()) as fixture:
                    status, data = self._get(
                        fixture.port,
                        f"/requests/{rid}/deletion-tombstones",
                    )
                self.assertEqual(status, 503)
                self.assertEqual(data, STORAGE_UNAVAILABLE)
                self.assertNotIn(b"SECRET", data)


if __name__ == "__main__":
    unittest.main()
