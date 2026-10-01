import http.client
import json
import os
import tempfile
import threading
import time
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


def _attempts_fixture(store, tenant="tenant-a", rid=None, lease=60):
    """Return (request_id, claim1, claim2) with attempt 1 expired/abandoned
    and attempt 2 still open."""
    if rid is None:
        rid = store.submit(tenant, "subject-1", ["email"], "key-1")["request_id"]
    claim1 = store.claim_next(tenant, "worker-1", 1)
    assert claim1 is not None and claim1["request_id"] == rid
    time.sleep(1.15)
    claim2 = store.claim_next(tenant, "worker-2", lease)
    assert claim2 is not None and claim2["request_id"] == rid
    return rid, claim1, claim2


class StatusEndpointTests(_StoreCase):
    def test_status_shape_field_order_and_trailing_newline(self):
        receipt = self._submit()
        status, headers, data = self._get(
            f"/requests/{receipt['request_id']}/status"
        )
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("Content-Type"), "application/json")
        self.assertTrue(data.endswith(b"\n"))
        self.assertEqual(data.count(b"\n"), 1)
        self.assertTrue(data.startswith(b'{"request_id":"'), data)
        record = json.loads(data)
        self.assertEqual(list(record), ["request_id", "status", "created_at"])
        self.assertEqual(set(record), {"request_id", "status", "created_at"})
        self.assertEqual(record["request_id"], receipt["request_id"])
        self.assertEqual(record["status"], "accepted")
        self.assertEqual(record["created_at"], receipt["created_at"])

    def test_status_tracks_current_state_but_keeps_created_at(self):
        receipt = self._submit()
        rid = receipt["request_id"]
        self.store.transition("tenant-a", rid, "processing")
        _, _, processing = self._get(f"/requests/{rid}/status")
        self.assertEqual(json.loads(processing)["status"], "processing")
        self.store.transition("tenant-a", rid, "completed")
        status, _, data = self._get(f"/requests/{rid}/status")
        self.assertEqual(status, 200)
        record = json.loads(data)
        self.assertEqual(record["status"], "completed")
        self.assertEqual(record["created_at"], receipt["created_at"])
        # The acceptance lookup stays frozen at accepted, byte identical.
        _, _, receipt_body = self._get(f"/requests/{rid}")
        self.assertEqual(json.loads(receipt_body)["status"], "accepted")

    def test_status_after_failed_finish(self):
        receipt = self._submit()
        rid = receipt["request_id"]
        claim = self.store.claim_next("tenant-a", "worker-1", 60)
        self.store.finish_claim("tenant-a", rid, claim["claim_token"], "failed")
        _, _, data = self._get(f"/requests/{rid}/status")
        record = json.loads(data)
        self.assertEqual(record["status"], "failed")
        self.assertEqual(record["created_at"], receipt["created_at"])

    def test_status_is_byte_stable_across_restart(self):
        receipt = self._submit()
        rid = receipt["request_id"]
        self.store.transition("tenant-a", rid, "processing")
        _, _, first = self._get(f"/requests/{rid}/status")
        self._fixture.__exit__(None, None, None)
        rebuilt = RequestStore(self.db_path)
        with _Server(rebuilt) as fixture:
            conn = http.client.HTTPConnection("127.0.0.1", fixture.port, timeout=10)
            try:
                conn.request(
                    "GET", f"/requests/{rid}/status",
                    headers={"X-Tenant-Id": "tenant-a"},
                )
                second = conn.getresponse().read()
            finally:
                conn.close()
        self.assertEqual(second, first)
        self.assertEqual(json.loads(second)["status"], "processing")

    def test_status_query_parameter_tenant_and_header_precedence(self):
        receipt = self._submit()
        rid = receipt["request_id"]
        status, _, data = self._request(
            "GET", f"/requests/{rid}/status?tenant_id=tenant-a"
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)["status"], "accepted")
        # Last non-empty query value wins without a header.
        status, _, data = self._request(
            "GET",
            f"/requests/{rid}/status?tenant_id=tenant-b&tenant_id=tenant-a",
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)["status"], "accepted")
        # A non-empty header overrides the query string.
        status, _, _ = self._request(
            "GET",
            f"/requests/{rid}/status?tenant_id=tenant-a",
            headers={"X-Tenant-Id": "tenant-b"},
        )
        self.assertEqual(status, 404)

    def test_status_errors_missing_tenant_malformed_unknown_cross_tenant(self):
        receipt = self._submit()
        rid = receipt["request_id"]
        unknown = "00000000-0000-4000-8000-000000000000"
        # Missing tenant.
        status, _, data = self._request("GET", f"/requests/{rid}/status")
        self.assertEqual((status, data), (400, INVALID_REQUEST))
        # Malformed / unknown / cross-tenant ids are all 404.
        for path, tenant in (
            (f"/requests/not-a-uuid/status", "tenant-a"),
            (f"/requests/{unknown}/status", "tenant-a"),
            (f"/requests/{rid}/status", "tenant-b"),
            (f"/requests/{rid}/status?tenant_id=tenant-b", None),
        ):
            with self.subTest(path=path):
                status, _, data = self._request(
                    "GET", path,
                    headers={"X-Tenant-Id": tenant} if tenant else {},
                )
                self.assertEqual((status, data), (404, NOT_FOUND))
        # Illegal sub-resource shapes stay unknown paths.
        for path in (
            f"/requests/{rid}/status/",
            f"/requests/{rid}/status/extra",
            "/requests//status",
            f"/requests/{rid}/other",
        ):
            with self.subTest(path=path):
                status, _, data = self._get(path)
                self.assertEqual((status, data), (404, NOT_FOUND))

    def test_status_unsupported_methods_are_405(self):
        receipt = self._submit()
        rid = receipt["request_id"]
        for method in ("POST", "PUT", "DELETE", "PATCH", "OPTIONS"):
            with self.subTest(method=method):
                status, headers, data = self._request(
                    method, f"/requests/{rid}/status",
                    body={} if method == "POST" else None,
                )
                self.assertEqual(status, 405)
                self.assertEqual(data, METHOD_NOT_ALLOWED)
                self.assertEqual(headers.get("Allow"), "GET")
        # 405 precedes authentication and tenant resolution.
        status, _, _ = self._request("POST", f"/requests/{rid}/status")
        self.assertEqual(status, 405)

    def test_status_corrupt_database_is_503(self):
        receipt = self._submit()
        with open(self.db_path, "wb") as handle:
            handle.write(b"not a sqlite database")
        status, _, data = self._get(f"/requests/{receipt['request_id']}/status")
        self.assertEqual((status, data), (503, STORAGE_UNAVAILABLE))


class ExecutionLogEndpointTests(_StoreCase):
    def test_empty_log_for_accepted_request(self):
        receipt = self._submit()
        status, headers, data = self._get(
            f"/requests/{receipt['request_id']}/execution-log"
        )
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("Content-Type"), "application/json")
        self.assertEqual(data.count(b"\n"), 1)
        self.assertTrue(data.endswith(b"\n"))
        self.assertEqual(
            data,
            f'{{"request_id":"{receipt["request_id"]}","attempts":[]}}\n'.encode(),
        )

    def test_open_attempt_has_null_result_and_completed_at(self):
        rid, _, claim = _attempts_fixture(self.store, rid=self._submit()["request_id"])
        status, _, data = self._get(f"/requests/{rid}/execution-log")
        self.assertEqual(status, 200)
        payload = json.loads(data)
        self.assertEqual(list(payload), ["request_id", "attempts"])
        self.assertEqual(payload["request_id"], rid)
        attempts = payload["attempts"]
        self.assertEqual(len(attempts), 2)
        open_attempt, live_attempt = attempts
        for attempt in attempts:
            self.assertEqual(
                list(attempt),
                [
                    "attempt_number",
                    "claimed_at",
                    "lease_expires_at",
                    "result",
                    "completed_at",
                ],
            )
            self.assertEqual(set(attempt), {
                "attempt_number",
                "claimed_at",
                "lease_expires_at",
                "result",
                "completed_at",
            })
        # Abandoned attempt 1 and the still-open attempt 2 are unfinished.
        self.assertEqual(open_attempt["attempt_number"], 1)
        self.assertIsNone(open_attempt["result"])
        self.assertIsNone(open_attempt["completed_at"])
        self.assertIsInstance(open_attempt["claimed_at"], str)
        self.assertIsInstance(open_attempt["lease_expires_at"], str)
        self.assertEqual(live_attempt["attempt_number"], 2)
        self.assertIsNone(live_attempt["result"])
        self.assertIsNone(live_attempt["completed_at"])
        # The claim tokens and worker identities never appear.
        self.assertNotIn(claim["claim_token"].encode(), data)
        self.assertNotIn(b"worker-1", data)
        self.assertNotIn(b"worker-2", data)
        self.assertNotIn(b"subject-1", data)
        self.assertNotIn(b"email", data)

    def test_finished_attempt_uses_stored_result_and_completion_time(self):
        receipt = self._submit()
        rid = receipt["request_id"]
        claim = self.store.claim_next("tenant-a", "worker-1", 60)
        self.store.finish_claim(
            "tenant-a", rid, claim["claim_token"], "completed"
        )
        stored_completed_at = self.store.get_execution_log("tenant-a", rid)[0][
            "completed_at"
        ]
        status, _, data = self._get(f"/requests/{rid}/execution-log")
        self.assertEqual(status, 200)
        (attempt,) = json.loads(data)["attempts"]
        self.assertEqual(attempt["attempt_number"], 1)
        self.assertEqual(attempt["result"], "completed")
        self.assertEqual(attempt["completed_at"], stored_completed_at)
        self.assertIsInstance(attempt["claimed_at"], str)
        self.assertIsInstance(attempt["lease_expires_at"], str)
        # No credential, identity or request-subject fields.
        self.assertNotIn(claim["claim_token"].encode(), data)
        self.assertNotIn(b"claim_token", data)
        self.assertNotIn(b"worker", data)

    def test_abandoned_then_completed_attempts(self):
        rid, _, claim2 = _attempts_fixture(
            self.store, rid=self._submit()["request_id"]
        )
        self.store.finish_claim("tenant-a", rid, claim2["claim_token"], "completed")
        _, _, data = self._get(f"/requests/{rid}/execution-log")
        attempts = json.loads(data)["attempts"]
        self.assertEqual([a["attempt_number"] for a in attempts], [1, 2])
        first, second = attempts
        self.assertIsNone(first["result"])
        self.assertIsNone(first["completed_at"])
        self.assertEqual(second["result"], "completed")
        self.assertIsInstance(second["completed_at"], str)

    def test_execution_log_matches_storage_layer_and_is_stable_across_restart(self):
        rid, _, claim2 = _attempts_fixture(
            self.store, rid=self._submit()["request_id"]
        )
        self.store.finish_claim("tenant-a", rid, claim2["claim_token"], "failed")
        _, _, first = self._get(f"/requests/{rid}/execution-log")
        # Matches the storage layer verbatim (request_id plus attempts).
        expected = {
            "request_id": rid,
            "attempts": self.store.get_execution_log("tenant-a", rid),
        }
        self.assertEqual(json.loads(first), expected)
        self._fixture.__exit__(None, None, None)
        rebuilt = RequestStore(self.db_path)
        with _Server(rebuilt) as fixture:
            conn = http.client.HTTPConnection("127.0.0.1", fixture.port, timeout=10)
            try:
                conn.request(
                    "GET", f"/requests/{rid}/execution-log",
                    headers={"X-Tenant-Id": "tenant-a"},
                )
                resp = conn.getresponse()
                status, second = resp.status, resp.read()
            finally:
                conn.close()
        self.assertEqual(status, 200)
        self.assertEqual(second, first)

    def test_execution_log_read_only_creates_no_bookkeeping(self):
        import sqlite3

        receipt = self._submit()
        rid = receipt["request_id"]
        # Two reads return identical bytes and leave no attempts behind.
        _, _, one = self._get(f"/requests/{rid}/execution-log")
        _, _, two = self._get(f"/requests/{rid}/execution-log")
        self.assertEqual(one, two)
        with sqlite3.connect(self.db_path) as conn:
            count = conn.execute(
                "SELECT count(*) FROM claim_attempts "
                "WHERE tenant_id = ? AND request_id = ?",
                ("tenant-a", rid),
            ).fetchone()[0]
        self.assertEqual(count, 0)
        # The request is still claimable exactly once: observation did not
        # advance its state.
        claim = self.store.claim_next("tenant-a", "worker-1", 60)
        self.assertIsNotNone(claim)
        self.assertEqual(claim["request_id"], rid)
        self.assertEqual(
            self.store.get_status("tenant-a", rid)["status"], "processing"
        )

    def test_execution_log_errors(self):
        receipt = self._submit()
        rid = receipt["request_id"]
        unknown = "00000000-0000-4000-8000-000000000000"
        status, _, data = self._request(
            "GET", f"/requests/{rid}/execution-log"
        )
        self.assertEqual((status, data), (400, INVALID_REQUEST))
        for path, tenant in (
            (f"/requests/not-a-uuid/execution-log", "tenant-a"),
            (f"/requests/{unknown}/execution-log", "tenant-a"),
            (f"/requests/{rid}/execution-log", "tenant-b"),
        ):
            with self.subTest(path=path):
                status, _, data = self._request(
                    "GET", path, headers={"X-Tenant-Id": tenant}
                )
                self.assertEqual((status, data), (404, NOT_FOUND))
        for path in (
            f"/requests/{rid}/execution-log/",
            f"/requests/{rid}/execution-log/1",
            "/requests//execution-log",
        ):
            with self.subTest(path=path):
                status, _, data = self._get(path)
                self.assertEqual((status, data), (404, NOT_FOUND))
        for method in ("POST", "PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                status, headers, data = self._request(
                    method, f"/requests/{rid}/execution-log",
                    body={} if method == "POST" else None,
                )
                self.assertEqual(status, 405)
                self.assertEqual(data, METHOD_NOT_ALLOWED)
                self.assertEqual(headers.get("Allow"), "GET")

    def test_execution_log_corrupt_database_is_503(self):
        receipt = self._submit()
        with open(self.db_path, "wb") as handle:
            handle.write(b"not a sqlite database")
        status, _, data = self._get(
            f"/requests/{receipt['request_id']}/execution-log"
        )
        self.assertEqual((status, data), (503, STORAGE_UNAVAILABLE))


SUBMIT_A = {"token": "tok-submit-a", "tenant_id": "tenant-a",
            "roles": ["request:submit"]}
READ_A = {"token": "tok-read-a", "tenant_id": "tenant-a",
          "roles": ["request:read"]}
READ_B = {"token": "tok-read-b", "tenant_id": "tenant-b",
          "roles": ["request:read"]}


class ObservabilityAuthTests(unittest.TestCase):
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
        for suffix in ("status", "execution-log"):
            for headers in (
                {},
                {"Authorization": "Bearer unknown-token"},
                {"Authorization": "Basic tok-read-a"},
                {"Authorization": "Bearer "},
            ):
                with self.subTest(suffix=suffix, headers=headers):
                    status, _, data = self._request(
                        "GET",
                        f"/requests/{self.rid}/{suffix}",
                        headers={**headers, "X-Tenant-Id": "tenant-a"},
                    )
                    self.assertEqual((status, data), (401, UNAUTHORIZED))

    def test_submit_role_is_forbidden(self):
        for suffix in ("status", "execution-log"):
            with self.subTest(suffix=suffix):
                status, _, data = self._request(
                    "GET", f"/requests/{self.rid}/{suffix}",
                    headers={**self._bearer("tok-submit-a"),
                             "X-Tenant-Id": "tenant-a"},
                )
                self.assertEqual((status, data), (403, FORBIDDEN))

    def test_tenant_mismatch_is_forbidden_before_id_validation(self):
        # Foreign tenant header forbids even a malformed id, before storage.
        for suffix in ("status", "execution-log"):
            for path in (
                f"/requests/{self.rid}/{suffix}",
                f"/requests/not-a-uuid/{suffix}",
            ):
                with self.subTest(suffix=suffix, path=path):
                    status, _, data = self._request(
                        "GET", path,
                        headers={**self._bearer("tok-read-a"),
                                 "X-Tenant-Id": "tenant-b"},
                    )
                    self.assertEqual((status, data), (403, FORBIDDEN))
            # Query parameter target tenant is checked too.
            status, _, data = self._request(
                "GET", f"/requests/{self.rid}/{suffix}?tenant_id=tenant-b",
                headers=self._bearer("tok-read-a"),
            )
            self.assertEqual((status, data), (403, FORBIDDEN))

    def test_missing_tenant_with_valid_token_is_400(self):
        for suffix in ("status", "execution-log"):
            with self.subTest(suffix=suffix):
                status, _, data = self._request(
                    "GET", f"/requests/{self.rid}/{suffix}",
                    headers=self._bearer("tok-read-a"),
                )
                self.assertEqual((status, data), (400, INVALID_REQUEST))

    def test_authorized_reads_and_header_precedence(self):
        for suffix, expected_status in (
            ("status", "accepted"),
            ("execution-log", None),
        ):
            status, _, data = self._request(
                "GET", f"/requests/{self.rid}/{suffix}",
                headers={**self._bearer("tok-read-a"),
                         "X-Tenant-Id": "tenant-a"},
            )
            self.assertEqual(status, 200)
            payload = json.loads(data)
            if suffix == "status":
                self.assertEqual(payload["status"], expected_status)
            else:
                self.assertEqual(payload["attempts"], [])
        # Header tenant-b matches read-b despite the query naming tenant-a.
        status, _, _ = self._request(
            "GET",
            f"/requests/{self.rid}/status?tenant_id=tenant-a",
            headers={**self._bearer("tok-read-b"),
                     "X-Tenant-Id": "tenant-b"},
        )
        self.assertEqual(status, 404)

    def test_cross_tenant_record_is_404_when_tenant_matches_token(self):
        for suffix in ("status", "execution-log"):
            with self.subTest(suffix=suffix):
                status, _, data = self._request(
                    "GET", f"/requests/{self.rid}/{suffix}",
                    headers={**self._bearer("tok-read-b"),
                             "X-Tenant-Id": "tenant-b"},
                )
                self.assertEqual((status, data), (404, NOT_FOUND))

    def test_method_check_precedes_authentication(self):
        for suffix in ("status", "execution-log"):
            status, _, data = self._request(
                "PUT", f"/requests/{self.rid}/{suffix}"
            )
            self.assertEqual((status, data), (405, METHOD_NOT_ALLOWED))


class UnauthenticatedObservabilityTests(unittest.TestCase):
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

    def _request(self, method, path, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request(method, path, headers=headers or {})
            resp = conn.getresponse()
            return resp.status, resp.read()
        finally:
            conn.close()

    def test_authorization_header_is_ignored_without_auth_config(self):
        rid = self.store.submit(
            "tenant-a", "subject-1", ["email"], "key-1"
        )["request_id"]
        headers = {"X-Tenant-Id": "tenant-a",
                   "Authorization": "Bearer anything"}
        status, data = self._request(
            "GET", f"/requests/{rid}/status", headers=headers
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)["status"], "accepted")
        status, data = self._request(
            "GET", f"/requests/{rid}/execution-log", headers=headers
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)["attempts"], [])


class BrokenStoreObservabilityTests(unittest.TestCase):
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
            def get(self, *a, **k):
                raise RuntimeError(secret)

            def get_status(self, *a, **k):
                raise RuntimeError(secret)

            def get_execution_log(self, *a, **k):
                raise OSError(secret)

        fixture = self._serve(BrokenStore())
        try:
            rid = "00000000-0000-4000-8000-000000000000"
            for path in (
                f"/requests/{rid}/status",
                f"/requests/{rid}/execution-log",
            ):
                with self.subTest(path=path):
                    status, data = self._get(fixture.port, path)
                    self.assertEqual(status, 503)
                    self.assertEqual(data, STORAGE_UNAVAILABLE)
                    self.assertNotIn(b"SECRET", data)
        finally:
            fixture.__exit__(None, None, None)

    def test_extra_or_malformed_fields_become_503(self):
        rid = "00000000-0000-4000-8000-000000000000"

        class LeakyStatusStore:
            def get_status(self, *a, **k):
                return {"request_id": rid, "status": "completed",
                        "created_at": "2026-01-01T00:00:00Z",
                        "subject_id": "subject-SECRET"}

        class LeakyLogStore:
            def get_execution_log(self, *a, **k):
                return [{
                    "attempt_number": 1,
                    "claimed_at": "2026-01-01T00:00:00Z",
                    "lease_expires_at": "2026-01-01T00:01:00Z",
                    "result": None,
                    "completed_at": None,
                    "claim_token": "token-SECRET",
                    "worker_id": "worker-SECRET",
                }]

        for store, path in (
            (LeakyStatusStore(), f"/requests/{rid}/status"),
            (LeakyLogStore(), f"/requests/{rid}/execution-log"),
        ):
            with self.subTest(path=path):
                fixture = self._serve(store)
                try:
                    status, data = self._get(fixture.port, path)
                    self.assertEqual(status, 503)
                    self.assertNotIn(b"SECRET", data)
                finally:
                    fixture.__exit__(None, None, None)

        class BadNumberingStore:
            def get_execution_log(self, *a, **k):
                return [{
                    "attempt_number": 2,
                    "claimed_at": "2026-01-01T00:00:00Z",
                    "lease_expires_at": "2026-01-01T00:01:00Z",
                    "result": "weird",
                    "completed_at": None,
                }]

        fixture = self._serve(BadNumberingStore())
        try:
            status, data = self._get(
                fixture.port, f"/requests/{rid}/execution-log"
            )
            self.assertEqual(status, 503)
            self.assertEqual(data, STORAGE_UNAVAILABLE)
        finally:
            fixture.__exit__(None, None, None)


if __name__ == "__main__":
    unittest.main()
