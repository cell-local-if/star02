"""HTTP tests for the read-only observability views.

Covers ``GET /requests/{request_id}/status`` and
``GET /requests/{request_id}/execution-log``: current-state vs frozen
receipt, execution-attempt projection (open and finished), read-only
guarantees, restart persistence, routing/method/tenant/error codes,
bearer RBAC and the no-leak contract. The acceptance and receipt
endpoints must remain byte-for-byte unchanged.
"""

import http.client
import json
import os
import tempfile
import threading
import time
import unittest

from forgetting_evidence.httpapi import AuthConfig, build_server
from forgetting_evidence.requests import RequestStore


def _wait_for_expiry(seconds=1.15):
    time.sleep(seconds)


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


NOT_FOUND = b'{"error":"not_found"}\n'
INVALID_REQUEST = b'{"error":"invalid_request"}\n'
METHOD_NOT_ALLOWED = b'{"error":"method_not_allowed"}\n'
STORAGE_UNAVAILABLE = b'{"error":"storage_unavailable"}\n'
UNAUTHORIZED = b'{"error":"unauthorized"}\n'
FORBIDDEN = b'{"error":"forbidden"}\n'


class _ObservabilityCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "evidence.db")
        self.store = RequestStore(self.db_path)
        self.auth = None
        self._fixture = _Server(self.store, self.auth)
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
                kwargs["body"] = body
            conn.request(method, path, headers=headers or {}, **kwargs)
            resp = conn.getresponse()
            return resp.status, dict(resp.getheaders()), resp.read()
        finally:
            conn.close()

    def _submit(self, store=None, tenant="tenant-a", key="key-1"):
        store = store if store is not None else self.store
        return store.submit(tenant, "subject-1", ["email", "profile"], key)

    def _get(self, path, tenant="tenant-a"):
        return self._request("GET", path, headers={"X-Tenant-Id": tenant})


class StatusViewTests(_ObservabilityCase):
    def test_status_reports_current_state_with_original_acceptance_time(self):
        receipt = self._submit()
        # Before any transition the status view mirrors accepted.
        status, headers, data = self._get(
            f"/requests/{receipt['request_id']}/status"
        )
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("Content-Type"), "application/json")
        self.assertTrue(data.endswith(b"\n"))
        self.assertEqual(data.count(b"\n"), 1)
        self.assertTrue(data.startswith(b'{"request_id":"'))
        record = json.loads(data)
        self.assertEqual(list(record), ["request_id", "status", "created_at"])
        self.assertEqual(
            record,
            {
                "request_id": receipt["request_id"],
                "status": "accepted",
                "created_at": receipt["created_at"],
            },
        )
        # Advance on the storage layer only.
        self.store.transition(
            "tenant-a", receipt["request_id"], "processing"
        )
        self.store.transition(
            "tenant-a", receipt["request_id"], "failed"
        )
        status, _, data = self._get(
            f"/requests/{receipt['request_id']}/status"
        )
        self.assertEqual(status, 200)
        record = json.loads(data)
        self.assertEqual(
            list(record), ["request_id", "status", "created_at"]
        )
        self.assertEqual(record["status"], "failed")
        # created_at is still the original acceptance time.
        self.assertEqual(record["created_at"], receipt["created_at"])
        self.assertEqual(record["request_id"], receipt["request_id"])

    def test_status_distinct_from_frozen_receipt(self):
        receipt = self._submit()
        self.store.transition(
            "tenant-a", receipt["request_id"], "processing"
        )
        self.store.transition(
            "tenant-a", receipt["request_id"], "completed"
        )
        _, _, receipt_data = self._get(f"/requests/{receipt['request_id']}")
        _, _, status_data = self._get(
            f"/requests/{receipt['request_id']}/status"
        )
        self.assertEqual(json.loads(receipt_data)["status"], "accepted")
        self.assertEqual(json.loads(status_data)["status"], "completed")
        self.assertNotEqual(receipt_data, status_data)

    def test_status_query_parameter_tenant(self):
        receipt = self._submit()
        status, _, data = self._request(
            "GET", f"/requests/{receipt['request_id']}?tenant_id=tenant-a"
        )
        self.assertEqual(status, 200)
        status, _, data = self._request(
            "GET",
            f"/requests/{receipt['request_id']}/status?tenant_id=tenant-a",
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)["status"], "accepted")
        # Header (non-empty) wins over a differing query value.
        status, _, _ = self._request(
            "GET",
            f"/requests/{receipt['request_id']}/status?tenant_id=tenant-b",
            headers={"X-Tenant-Id": "tenant-a"},
        )
        self.assertEqual(status, 200)

    def test_status_persists_across_restart(self):
        receipt = self._submit()
        self.store.transition(
            "tenant-a", receipt["request_id"], "processing"
        )
        self.store.transition(
            "tenant-a", receipt["request_id"], "completed"
        )
        self._fixture.__exit__(None, None, None)
        rebuilt = RequestStore(self.db_path)
        with _Server(rebuilt) as fixture:
            conn = http.client.HTTPConnection("127.0.0.1", fixture.port, timeout=10)
            try:
                conn.request(
                    "GET",
                    f"/requests/{receipt['request_id']}/status",
                    headers={"X-Tenant-Id": "tenant-a"},
                )
                resp = conn.getresponse()
                self.assertEqual(resp.status, 200)
                data = resp.read()
            finally:
                conn.close()
        self.assertEqual(
            json.loads(data),
            {
                "request_id": receipt["request_id"],
                "status": "completed",
                "created_at": receipt["created_at"],
            },
        )


class ExecutionLogViewTests(_ObservabilityCase):
    def test_empty_log_before_any_attempt(self):
        receipt = self._submit()
        status, headers, data = self._get(
            f"/requests/{receipt['request_id']}/execution-log"
        )
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("Content-Type"), "application/json")
        self.assertTrue(data.endswith(b"\n"))
        self.assertEqual(data.count(b"\n"), 1)
        self.assertTrue(data.startswith(b'{"request_id":"'))
        record = json.loads(data)
        self.assertEqual(list(record), ["request_id", "attempts"])
        self.assertEqual(
            record, {"request_id": receipt["request_id"], "attempts": []}
        )

    def test_open_attempt_has_null_result_and_completion(self):
        receipt = self._submit()
        claim = self.store.claim_next("tenant-a", "worker-1", 3600)
        self.assertEqual(claim["request_id"], receipt["request_id"])
        status, _, data = self._get(
            f"/requests/{receipt['request_id']}/execution-log"
        )
        self.assertEqual(status, 200)
        record = json.loads(data)
        self.assertEqual(list(record), ["request_id", "attempts"])
        self.assertEqual(len(record["attempts"]), 1)
        attempt = record["attempts"][0]
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
        self.assertEqual(attempt["attempt_number"], 1)
        self.assertIsNone(attempt["result"])
        self.assertIsNone(attempt["completed_at"])
        self.assertIsInstance(attempt["claimed_at"], str)
        self.assertTrue(attempt["claimed_at"])
        self.assertIsInstance(attempt["lease_expires_at"], str)
        self.assertTrue(attempt["lease_expires_at"])
        # No credential, worker identity or request payload is exposed.
        self.assertNotIn(b"claim_token", data)
        self.assertNotIn(b"worker", data)
        self.assertNotIn(b"subject", data)
        self.assertNotIn(b"scope", data)
        self.assertNotIn(b"idempotency", data)
        self.assertNotIn(claim["claim_token"].encode(), data)
        self.assertNotIn(b"worker-1", data)
        self.assertNotIn(b"subject-1", data)
        self.assertNotIn(b"profile", data)

    def test_finished_attempts_carry_completed_and_failed_results(self):
        for result, key in (("completed", "k-done"), ("failed", "k-fail")):
            with self.subTest(result=result):
                receipt = self._submit(key=key)
                claim = self.store.claim_next("tenant-a", "worker-1", 3600)
                finished = self.store.finish_claim(
                    "tenant-a",
                    receipt["request_id"],
                    claim["claim_token"],
                    result,
                )
                self.assertEqual(finished["status"], result)
                status, _, data = self._get(
                    f"/requests/{receipt['request_id']}/execution-log"
                )
                self.assertEqual(status, 200)
                attempt = json.loads(data)["attempts"][0]
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
                self.assertEqual(attempt["attempt_number"], 1)
                self.assertEqual(attempt["result"], result)
                self.assertIsInstance(attempt["completed_at"], str)
                self.assertTrue(attempt["completed_at"])

    def test_attempts_are_sequenced_after_expiry_reclaim(self):
        receipt = self._submit()
        first = self.store.claim_next("tenant-a", "worker-1", 1)
        # The live lease cannot be claimed again.
        self.assertIsNone(self.store.claim_next("tenant-a", "worker-2", 1))
        _wait_for_expiry()
        second = self.store.claim_next("tenant-a", "worker-2", 3600)
        self.assertIsNotNone(second)
        # Finish the second attempt as completed.
        self.store.finish_claim(
            "tenant-a", receipt["request_id"], second["claim_token"], "completed"
        )
        status, _, data = self._get(
            f"/requests/{receipt['request_id']}/execution-log"
        )
        self.assertEqual(status, 200)
        attempts = json.loads(data)["attempts"]
        self.assertEqual([a["attempt_number"] for a in attempts], [1, 2])
        # The abandoned first attempt is open; the successor finished.
        self.assertIsNone(attempts[0]["result"])
        self.assertIsNone(attempts[0]["completed_at"])
        self.assertEqual(attempts[1]["result"], "completed")
        self.assertIsNotNone(attempts[1]["completed_at"])
        # No credential material from either lease is present.
        self.assertNotIn(first["claim_token"].encode(), data)
        self.assertNotIn(second["claim_token"].encode(), data)

    def test_log_persists_across_restart(self):
        receipt = self._submit()
        claim = self.store.claim_next("tenant-a", "worker-1", 3600)
        self.store.finish_claim(
            "tenant-a", receipt["request_id"], claim["claim_token"], "failed"
        )
        before_status, _, before = self._get(
            f"/requests/{receipt['request_id']}/execution-log"
        )
        self.assertEqual(before_status, 200)
        self._fixture.__exit__(None, None, None)
        rebuilt = RequestStore(self.db_path)
        with _Server(rebuilt) as fixture:
            conn = http.client.HTTPConnection("127.0.0.1", fixture.port, timeout=10)
            try:
                conn.request(
                    "GET",
                    f"/requests/{receipt['request_id']}/execution-log",
                    headers={"X-Tenant-Id": "tenant-a"},
                )
                resp = conn.getresponse()
                self.assertEqual(resp.status, 200)
                after = resp.read()
            finally:
                conn.close()
        self.assertEqual(after, before)
        self.assertEqual(json.loads(after)["attempts"][0]["result"], "failed")


class ReadOnlyGuaranteeTests(_ObservabilityCase):
    def test_views_do_not_create_attempts_or_advance_status(self):
        receipt = self._submit()
        for _ in range(3):
            status, _, _ = self._get(
                f"/requests/{receipt['request_id']}/status"
            )
            self.assertEqual(status, 200)
            status, _, data = self._get(
                f"/requests/{receipt['request_id']}/execution-log"
            )
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(data)["attempts"], [])
        # Storage confirms no attempts and the request stays accepted.
        self.assertEqual(
            self.store.get_execution_log(
                "tenant-a", receipt["request_id"]
            ),
            [],
        )
        self.assertEqual(
            self.store.get_status("tenant-a", receipt["request_id"])["status"],
            "accepted",
        )

    def test_views_do_not_change_response_of_existing_endpoints(self):
        _, _, post_data = self._request(
            "POST",
            "/requests",
            body=json.dumps(
                {
                    "tenant_id": "tenant-a",
                    "subject_id": "subject-1",
                    "idempotency_key": "key-1",
                    "scopes": ["email", "profile"],
                }
            ),
        )
        receipt = json.loads(post_data)
        self.store.transition(
            "tenant-a", receipt["request_id"], "processing"
        )
        _, _, lookup = self._get(f"/requests/{receipt['request_id']}")
        self.assertEqual(lookup, post_data)
        # Idempotent replay remains byte-identical.
        _, _, replay = self._request(
            "POST",
            "/requests",
            body=json.dumps(
                {
                    "tenant_id": "tenant-a",
                    "subject_id": "subject-1",
                    "idempotency_key": "key-1",
                    "scopes": ["profile", "email"],
                }
            ),
        )
        self.assertEqual(replay, post_data)


class RoutingAndErrorTests(_ObservabilityCase):
    def _rid(self):
        return self._submit()["request_id"]

    def test_missing_malformed_and_cross_tenant_are_404(self):
        rid = self._rid()
        unknown = "00000000-0000-4000-8000-000000000000"
        for suffix in ("status", "execution-log"):
            cases = [
                (f"/requests/{unknown}/{suffix}", {"X-Tenant-Id": "tenant-a"}),
                (f"/requests/{rid}/{suffix}", {"X-Tenant-Id": "tenant-b"}),
                (
                    f"/requests/{rid}/{suffix}?tenant_id=tenant-b",
                    {},
                ),
                (f"/requests/not-a-uuid/{suffix}", {"X-Tenant-Id": "tenant-a"}),
                (f"/requests/123/{suffix}", {"X-Tenant-Id": "tenant-a"}),
            ]
            for path, headers in cases:
                with self.subTest(suffix=suffix, path=path):
                    status, _, data = self._request("GET", path, headers=headers)
                    self.assertEqual(status, 404)
                    self.assertEqual(data, NOT_FOUND)

    def test_unknown_or_deeply_nested_sub_resources_are_404(self):
        rid = self._rid()
        for method, path in (
            ("GET", f"/requests/{rid}/bogus"),
            ("GET", f"/requests/{rid}/status/"),
            ("GET", f"/requests/{rid}/status/x"),
            ("GET", f"/requests/{rid}/execution-log/2"),
            ("GET", f"/requests//status"),
            ("POST", f"/requests/{rid}/bogus"),
            ("PUT", f"/requests/{rid}/status/x"),
        ):
            with self.subTest(method=method, path=path):
                status, _, data = self._request(
                    method, path, headers={"X-Tenant-Id": "tenant-a"}
                )
                self.assertEqual(status, 404)
                self.assertEqual(data, NOT_FOUND)

    def test_missing_tenant_is_400(self):
        rid = self._rid()
        for suffix in ("status", "execution-log"):
            with self.subTest(suffix=suffix):
                status, _, data = self._request(
                    "GET", f"/requests/{rid}/{suffix}"
                )
                self.assertEqual(status, 400)
                self.assertEqual(data, INVALID_REQUEST)
                # A whitespace-only tenant header falls through to an
                # empty/missing query tenant and is also rejected.
                status, _, data = self._request(
                    "GET",
                    f"/requests/{rid}/{suffix}",
                    headers={"X-Tenant-Id": "   "},
                )
                self.assertEqual(status, 400)
                self.assertEqual(data, INVALID_REQUEST)

    def test_unsupported_methods_are_405_with_get_allow(self):
        rid = self._rid()
        for suffix in ("status", "execution-log"):
            path = f"/requests/{rid}/{suffix}"
            for method in ("POST", "PUT", "PATCH", "DELETE", "OPTIONS"):
                with self.subTest(method=method, suffix=suffix):
                    status, headers, data = self._request(
                        method, path, headers={"X-Tenant-Id": "tenant-a"}
                    )
                    self.assertEqual(status, 405)
                    self.assertEqual(data, METHOD_NOT_ALLOWED)
                    self.assertEqual(headers.get("Allow"), "GET")

    def test_head_honours_sub_resource_routing(self):
        rid = self._rid()
        for suffix in ("status", "execution-log"):
            status, headers, data = self._request(
                "HEAD",
                f"/requests/{rid}/{suffix}",
                headers={"X-Tenant-Id": "tenant-a"},
            )
            self.assertEqual(status, 405)
            self.assertEqual(data, b"")
            self.assertEqual(headers.get("Allow"), "GET")
        # HEAD against an unknown path stays 404.
        status, _, data = self._request("HEAD", "/nothing/here")
        self.assertEqual(status, 404)
        self.assertEqual(data, b"")

    def test_corrupt_database_is_503(self):
        rid = self._rid()
        with open(self.db_path, "wb") as handle:
            handle.write(b"this is definitely not a sqlite database")
        for suffix in ("status", "execution-log"):
            with self.subTest(suffix=suffix):
                status, _, data = self._get(f"/requests/{rid}/{suffix}")
                self.assertEqual(status, 503)
                self.assertEqual(data, STORAGE_UNAVAILABLE)


SUBMIT_A = {
    "token": "tok-submit-a",
    "tenant_id": "tenant-a",
    "roles": ["request:submit"],
}
READ_A = {
    "token": "tok-read-a",
    "tenant_id": "tenant-a",
    "roles": ["request:read"],
}
SUBMIT_B = {
    "token": "tok-submit-b",
    "tenant_id": "tenant-b",
    "roles": ["request:submit"],
}
READ_B = {
    "token": "tok-read-b",
    "tenant_id": "tenant-b",
    "roles": ["request:read"],
}


class ObservabilityAuthTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "evidence.db")
        self.store = RequestStore(self.db_path)
        self.auth = AuthConfig([SUBMIT_A, READ_A, SUBMIT_B, READ_B])
        self._fixture = _Server(self.store, self.auth)
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

    def _bearer(self, token):
        return {"Authorization": f"Bearer {token}"}

    def _seed(self, tenant="tenant-a", key="key-1"):
        return self.store.submit(tenant, "subject-1", ["email"], key)

    def test_views_require_authentication(self):
        receipt = self._seed()
        for suffix in ("status", "execution-log"):
            for headers in (
                {},
                {"Authorization": ""},
                {"Authorization": "Basic tok-read-a"},
                {"Authorization": "Bearer"},
                {"Authorization": "Bearer "},
                {"Authorization": "bearer tok-read-a"},
                {"Authorization": "Bearer unknown-token"},
            ):
                with self.subTest(suffix=suffix, headers=headers):
                    merged = {**headers, "X-Tenant-Id": "tenant-a"}
                    status, _, data = self._request(
                        "GET",
                        f"/requests/{receipt['request_id']}/{suffix}",
                        merged,
                    )
                    self.assertEqual(status, 401)
                    self.assertEqual(data, UNAUTHORIZED)

    def test_submit_role_cannot_read_views(self):
        receipt = self._seed()
        for suffix in ("status", "execution-log"):
            status, _, data = self._request(
                "GET",
                f"/requests/{receipt['request_id']}/{suffix}",
                {**self._bearer("tok-submit-a"), "X-Tenant-Id": "tenant-a"},
            )
            self.assertEqual(status, 403)
            self.assertEqual(data, FORBIDDEN)

    def test_cross_tenant_is_forbidden_before_id_validation(self):
        receipt_b = self._seed(tenant="tenant-b", key="key-b")
        for suffix in ("status", "execution-log"):
            # Matching foreign record, own-principal tenant header.
            status, _, data = self._request(
                "GET",
                f"/requests/{receipt_b['request_id']}/{suffix}",
                {**self._bearer("tok-read-a"), "X-Tenant-Id": "tenant-a"},
            )
            self.assertEqual(status, 404)
            self.assertEqual(data, NOT_FOUND)
            # Naming the other tenant explicitly is a role/tenant 403
            # before the request id is even inspected.
            status, _, data = self._request(
                "GET",
                f"/requests/{receipt_b['request_id']}/{suffix}",
                {**self._bearer("tok-read-a"), "X-Tenant-Id": "tenant-b"},
            )
            self.assertEqual(status, 403)
            self.assertEqual(data, FORBIDDEN)
            # A malformed id under a foreign tenant is still 403.
            status, _, data = self._request(
                "GET",
                f"/requests/not-a-uuid/{suffix}",
                {**self._bearer("tok-read-a"), "X-Tenant-Id": "tenant-b"},
            )
            self.assertEqual(status, 403)
            self.assertEqual(data, FORBIDDEN)

    def test_missing_tenant_with_valid_token_is_400(self):
        receipt = self._seed()
        for suffix in ("status", "execution-log"):
            status, _, data = self._request(
                "GET",
                f"/requests/{receipt['request_id']}/{suffix}",
                self._bearer("tok-read-a"),
            )
            self.assertEqual(status, 400)
            self.assertEqual(data, INVALID_REQUEST)

    def test_header_tenant_precedence(self):
        receipt_b = self._seed(tenant="tenant-b", key="key-b")
        for suffix in ("status", "execution-log"):
            # Header tenant-b matches read-b even though query says a.
            status, _, _ = self._request(
                "GET",
                f"/requests/{receipt_b['request_id']}/{suffix}"
                "?tenant_id=tenant-a",
                {**self._bearer("tok-read-b"), "X-Tenant-Id": "tenant-b"},
            )
            self.assertEqual(status, 200)
            # Header for a different tenant forbids regardless of query.
            status, _, data = self._request(
                "GET",
                f"/requests/{receipt_b['request_id']}/{suffix}"
                "?tenant_id=tenant-b",
                {**self._bearer("tok-read-b"), "X-Tenant-Id": "tenant-a"},
            )
            self.assertEqual(status, 403)
            self.assertEqual(data, FORBIDDEN)

    def test_authorized_views_succeed_via_header_and_query(self):
        receipt = self._seed()
        self.store.transition(
            "tenant-a", receipt["request_id"], "processing"
        )
        for suffix in ("status", "execution-log"):
            status, _, data = self._request(
                "GET",
                f"/requests/{receipt['request_id']}/{suffix}",
                {**self._bearer("tok-read-a"), "X-Tenant-Id": "tenant-a"},
            )
            self.assertEqual(status, 200)
            self.assertTrue(data.endswith(b"\n"))
            status, _, data = self._request(
                "GET",
                f"/requests/{receipt['request_id']}/{suffix}"
                "?tenant_id=tenant-a",
                self._bearer("tok-read-a"),
            )
            self.assertEqual(status, 200)

    def test_unsupported_method_stays_405_without_token(self):
        receipt = self._seed()
        for suffix in ("status", "execution-log"):
            status, _, data = self._request(
                "PUT",
                f"/requests/{receipt['request_id']}/{suffix}",
            )
            self.assertEqual(status, 405)
            self.assertEqual(data, METHOD_NOT_ALLOWED)
        # Unknown path stays 404 even with a valid token.
        status, _, data = self._request(
            "GET", "/nothing/here", self._bearer("tok-read-a")
        )
        self.assertEqual(status, 404)
        self.assertEqual(data, NOT_FOUND)


if __name__ == "__main__":
    unittest.main()
