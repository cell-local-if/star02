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

NOT_FOUND = b'{"error":"not_found"}\n'
INVALID_REQUEST = b'{"error":"invalid_request"}\n'
METHOD_NOT_ALLOWED = b'{"error":"method_not_allowed"}\n'
STORAGE_UNAVAILABLE = b'{"error":"storage_unavailable"}\n'
UNAUTHORIZED = b'{"error":"unauthorized"}\n'
FORBIDDEN = b'{"error":"forbidden"}\n'

HEX64 = re.compile(r"^[0-9a-f]{64}$")
FIELDS = ["request_id", "status", "event_count", "chain_hash", "verified"]


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


class EvidenceEndpointTests(unittest.TestCase):
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

    def _evidence(self, rid, tenant="tenant-a"):
        return self._get(f"/requests/{rid}/evidence", tenant)

    def _lifecycle(self, statuses=("processing", "completed"), key="key-1"):
        receipt = self.store.submit(
            "tenant-a", "subject-1", ["email"], key
        )
        for target in statuses:
            self.store.transition("tenant-a", receipt["request_id"], target)
        return receipt

    def _raw(self):
        return sqlite3.connect(self.db_path)

    def _tamper(self, sql, params=()):
        with self._raw() as conn:
            conn.execute(sql, params)

    # -- success shape --------------------------------------------------

    def test_accepted_request_evidence_shape(self):
        receipt = self._lifecycle(())
        rid = receipt["request_id"]
        status, headers, data = self._evidence(rid)
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("Content-Type"), "application/json")
        self.assertTrue(data.endswith(b"\n"))
        self.assertEqual(data.count(b"\n"), 1)
        self.assertTrue(data.startswith(b'{"request_id":"'), data)
        record = json.loads(data)
        self.assertEqual(list(record), FIELDS)
        self.assertEqual(set(record), set(FIELDS))
        self.assertEqual(record["request_id"], rid)
        self.assertEqual(record["status"], "accepted")
        self.assertEqual(record["event_count"], 1)
        self.assertIsInstance(record["event_count"], int)
        self.assertTrue(HEX64.match(record["chain_hash"]))
        self.assertEqual(record["chain_hash"], record["chain_hash"].lower())
        self.assertIs(record["verified"], True)
        # Compact single-line rendering, exactly the five fields.
        self.assertEqual(
            data,
            (
                json.dumps(record, separators=(",", ":")) + "\n"
            ).encode("utf-8"),
        )
        # No subject, scope, idempotency key or event timestamp leaks.
        self.assertNotIn(b"subject-1", data)
        self.assertNotIn(b"email", data)
        self.assertNotIn(b"key-1", data)
        self.assertNotIn(b"occurred_at", data)

    def test_evidence_tracks_committed_lifecycle(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        status, _, data = self._evidence(rid)
        self.assertEqual(status, 200)
        record = json.loads(data)
        self.assertEqual(record["status"], "completed")
        self.assertEqual(record["event_count"], 3)
        self.assertIs(record["verified"], True)
        self.assertEqual(
            record["chain_hash"],
            self.store.evidence("tenant-a", rid)["chain_hash"],
        )
        events = self.store.audit("tenant-a", rid)
        self.assertEqual(record["event_count"], len(events))
        self.assertEqual(record["status"], events[-1]["status"])

    def test_failed_lifecycle_verifies(self):
        receipt = self._lifecycle(("failed",))
        status, _, data = self._evidence(receipt["request_id"])
        self.assertEqual(status, 200)
        record = json.loads(data)
        self.assertEqual(record["status"], "failed")
        self.assertEqual(record["event_count"], 2)
        self.assertIs(record["verified"], True)

    def test_repeated_reads_are_byte_identical(self):
        receipt = self._lifecycle()
        _, _, first = self._evidence(receipt["request_id"])
        for _ in range(3):
            _, _, again = self._evidence(receipt["request_id"])
            self.assertEqual(again, first)

    def test_evidence_stable_across_restart(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        _, _, first = self._evidence(rid)
        self._fixture.__exit__(None, None, None)
        rebuilt = RequestStore(self.db_path)
        with _Server(rebuilt) as fixture:
            conn = http.client.HTTPConnection("127.0.0.1", fixture.port, timeout=10)
            try:
                conn.request(
                    "GET", f"/requests/{rid}/evidence",
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
            "GET", f"/requests/{rid}/evidence?tenant_id=tenant-a"
        )
        self.assertEqual(status, 200)
        self.assertIs(json.loads(data)["verified"], True)
        # Last non-empty query value wins without a header.
        status, _, data = self._request(
            "GET",
            f"/requests/{rid}/evidence"
            "?tenant_id=tenant-b&tenant_id=tenant-a",
        )
        self.assertEqual(status, 200)
        self.assertIs(json.loads(data)["verified"], True)
        # A non-empty header overrides the query string and scopes the read.
        status, _, data = self._request(
            "GET", f"/requests/{rid}/evidence?tenant_id=tenant-a",
            headers={"X-Tenant-Id": "tenant-b"},
        )
        self.assertEqual((status, data), (404, NOT_FOUND))

    def test_uppercase_uuid_canonicalises(self):
        receipt = self._lifecycle(())
        _, _, lower = self._evidence(receipt["request_id"])
        status, _, upper = self._get(
            f"/requests/{receipt['request_id'].upper()}/evidence"
        )
        self.assertEqual(status, 200)
        self.assertEqual(upper, lower)

    # -- error mapping --------------------------------------------------

    def test_missing_tenant_is_400(self):
        receipt = self._lifecycle(())
        status, _, data = self._request(
            "GET", f"/requests/{receipt['request_id']}/evidence"
        )
        self.assertEqual((status, data), (400, INVALID_REQUEST))
        status, _, data = self._request(
            "GET", f"/requests/{receipt['request_id']}/evidence?tenant_id="
        )
        self.assertEqual((status, data), (400, INVALID_REQUEST))

    def test_malformed_unknown_cross_tenant_ids_are_404(self):
        receipt = self._lifecycle(())
        rid = receipt["request_id"]
        unknown = "00000000-0000-4000-8000-000000000000"
        for path, tenant in (
            ("/requests/not-a-uuid/evidence", "tenant-a"),
            (f"/requests/{unknown}/evidence", "tenant-a"),
            (f"/requests/{rid}/evidence", "tenant-b"),
            (f"/requests/{rid}/evidence?tenant_id=tenant-b", None),
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
            f"/requests/{rid}/evidence/",
            f"/requests/{rid}/evidence/extra",
            "/requests//evidence",
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
                    method, f"/requests/{rid}/evidence",
                    body={} if method == "POST" else None,
                )
                self.assertEqual(status, 405)
                self.assertEqual(data, METHOD_NOT_ALLOWED)
                self.assertEqual(headers.get("Allow"), "GET")
        # HEAD answers 405 with headers but no body.
        status, headers, data = self._request(
            "HEAD", f"/requests/{rid}/evidence"
        )
        self.assertEqual(status, 405)
        self.assertEqual(headers.get("Allow"), "GET")
        self.assertEqual(data, b"")

    def test_corrupt_database_is_503(self):
        receipt = self._lifecycle(())
        with open(self.db_path, "wb") as handle:
            handle.write(b"not a sqlite database")
        status, _, data = self._evidence(receipt["request_id"])
        self.assertEqual((status, data), (503, STORAGE_UNAVAILABLE))
        self.assertEqual(set(json.loads(data)), {"error"})

    # -- tampering: 200 with verified false -----------------------------

    def test_deleted_event_is_200_verified_false(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        self._tamper(
            "DELETE FROM status_events WHERE request_id = ? AND seq = 1",
            (rid,),
        )
        status, _, data = self._evidence(rid)
        self.assertEqual(status, 200)
        record = json.loads(data)
        self.assertIs(record["verified"], False)
        # Persisted fields still describe the stored snapshot.
        self.assertEqual(record["status"], "completed")
        self.assertEqual(record["event_count"], 2)
        self.assertTrue(HEX64.match(record["chain_hash"]))

    def test_all_events_deleted_is_200_verified_false_count_zero(self):
        receipt = self._lifecycle(())
        rid = receipt["request_id"]
        self._tamper(
            "DELETE FROM status_events WHERE request_id = ?", (rid,)
        )
        status, _, data = self._evidence(rid)
        self.assertEqual(status, 200)
        record = json.loads(data)
        self.assertIs(record["verified"], False)
        self.assertEqual(record["event_count"], 0)
        # The request-row head is still a legal digest and reported as is.
        self.assertTrue(HEX64.match(record["chain_hash"]))

    def test_altered_event_is_200_verified_false(self):
        receipt = self._lifecycle()
        self._tamper(
            "UPDATE status_events SET status = 'failed' "
            "WHERE request_id = ? AND seq = 0",
            (receipt["request_id"],),
        )
        status, _, data = self._evidence(receipt["request_id"])
        self.assertEqual(status, 200)
        self.assertIs(json.loads(data)["verified"], False)

    def test_inserted_forged_event_is_200_verified_false(self):
        receipt = self._lifecycle(("failed",))
        rid = receipt["request_id"]
        events = self.store.audit("tenant-a", rid)
        self._tamper(
            "INSERT INTO status_events "
            "(tenant_id, request_id, seq, status, occurred_at, chain_hash) "
            "VALUES ('tenant-a', ?, 2, 'processing', ?, ?)",
            (rid, events[-1]["occurred_at"], "0" * 64),
        )
        status, _, data = self._evidence(rid)
        self.assertEqual(status, 200)
        record = json.loads(data)
        self.assertIs(record["verified"], False)
        self.assertEqual(record["event_count"], 3)

    def test_reordered_event_is_200_verified_false(self):
        receipt = self._lifecycle()
        self._tamper(
            "UPDATE status_events SET seq = 5 "
            "WHERE request_id = ? AND seq = 1",
            (receipt["request_id"],),
        )
        status, _, data = self._evidence(receipt["request_id"])
        self.assertEqual(status, 200)
        self.assertIs(json.loads(data)["verified"], False)

    def test_cross_request_rebound_event_is_200_verified_false(self):
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
        status, _, data = self._evidence(one["request_id"])
        self.assertEqual(status, 200)
        self.assertIs(json.loads(data)["verified"], False)

    def test_substituted_head_is_reported_verbatim_with_verified_false(self):
        receipt = self._lifecycle()
        forged = "a" * 64
        self._tamper(
            "UPDATE requests SET chain_hash = ? WHERE request_id = ?",
            (forged, receipt["request_id"]),
        )
        status, _, data = self._evidence(receipt["request_id"])
        self.assertEqual(status, 200)
        record = json.loads(data)
        self.assertEqual(record["chain_hash"], forged)
        self.assertIs(record["verified"], False)
        self.assertEqual(record["status"], "completed")
        self.assertEqual(record["event_count"], 3)

    def test_tampered_current_status_is_reported_with_verified_false(self):
        receipt = self._lifecycle()
        self._tamper(
            "UPDATE requests SET status = 'failed' WHERE request_id = ?",
            (receipt["request_id"],),
        )
        status, _, data = self._evidence(receipt["request_id"])
        self.assertEqual(status, 200)
        record = json.loads(data)
        self.assertEqual(record["status"], "failed")
        self.assertIs(record["verified"], False)

    def test_malformed_persisted_head_is_null_and_verified_false(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        self._tamper(
            "UPDATE requests SET chain_hash = 'not-a-digest' WHERE request_id = ?",
            (rid,),
        )
        status, headers, data = self._evidence(rid)
        self.assertEqual(status, 200)
        record = json.loads(data)
        self.assertIsNone(record["chain_hash"])
        self.assertIs(record["verified"], False)
        self.assertEqual(record["status"], "completed")
        self.assertEqual(record["event_count"], 3)
        self.assertEqual(headers.get("Content-Type"), "application/json")
        # Null serialises verbatim in the fixed field position.
        self.assertIn(b'"chain_hash":null,"verified":false', data)

    def test_tampered_reads_are_repeatable(self):
        receipt = self._lifecycle()
        self._tamper(
            "UPDATE status_events SET occurred_at = occurred_at || 'X' "
            "WHERE request_id = ? AND seq = 0",
            (receipt["request_id"],),
        )
        _, _, first = self._evidence(receipt["request_id"])
        _, _, second = self._evidence(receipt["request_id"])
        self.assertEqual(first, second)
        self.assertIs(json.loads(first)["verified"], False)

    # -- read-only ------------------------------------------------------

    def test_evidence_read_never_writes(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        with open(self.db_path, "rb") as handle:
            before = handle.read()
        for _ in range(5):
            status, _, _ = self._evidence(rid)
            self.assertEqual(status, 200)
        with open(self.db_path, "rb") as handle:
            after = handle.read()
        self.assertEqual(before, after)
        # No attempts, tombstones or receipts appeared and state is intact.
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
                    "SELECT count(*) FROM deletion_tombstones WHERE request_id = ?",
                    (rid,),
                ).fetchone()[0],
                0,
            )
            self.assertEqual(
                conn.execute(
                    "SELECT count(*) FROM deletion_receipts WHERE request_id = ?",
                    (rid,),
                ).fetchone()[0],
                0,
            )

    # -- snapshot consistency under concurrent writes -------------------

    def test_never_a_torn_verdict_under_concurrent_transitions(self):
        receipt = self.store.submit(
            "tenant-a", "subject-1", ["email"], "key-1"
        )
        rid = receipt["request_id"]

        def move():
            for target in ("processing", "completed", "accepted",
                           "processing", "failed", "processing"):
                try:
                    self.store.transition("tenant-a", rid, target)
                except Exception:
                    pass

        def read():
            status, _, data = self._evidence(rid)
            self.assertEqual(status, 200)
            record = json.loads(data)
            self.assertEqual(list(record), FIELDS)
            # Every committed snapshot is internally self-consistent: a
            # mixed-transaction response would render status/head from one
            # commit and events from another and verify false here.
            self.assertIs(record["verified"], True)

        with ThreadPoolExecutor(max_workers=8) as pool:
            movers = [pool.submit(move) for _ in range(4)]
            readers = [pool.submit(read) for _ in range(4) for _ in range(25)]
            for future in movers + readers:
                future.result()
        # Final state is intact and verifies.
        _, _, data = self._evidence(rid)
        self.assertIs(json.loads(data)["verified"], True)


SUBMIT_A = {"token": "tok-submit-a", "tenant_id": "tenant-a",
            "roles": ["request:submit"]}
READ_A = {"token": "tok-read-a", "tenant_id": "tenant-a",
          "roles": ["request:read"]}
READ_B = {"token": "tok-read-b", "tenant_id": "tenant-b",
          "roles": ["request:read"]}
RECONCILE_A = {"token": "tok-reconcile-a", "tenant_id": "tenant-a",
               "roles": ["request:reconcile"]}


class EvidenceAuthTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "evidence.db")
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

    def test_missing_malformed_or_unknown_token_is_401(self):
        for headers in (
            {},
            {"Authorization": "Bearer unknown-token"},
            {"Authorization": "Basic tok-read-a"},
            {"Authorization": "Bearer "},
        ):
            with self.subTest(headers=headers):
                status, _, data = self._request(
                    "GET", f"/requests/{self.rid}/evidence",
                    headers={**headers, "X-Tenant-Id": "tenant-a"},
                )
                self.assertEqual((status, data), (401, UNAUTHORIZED))

    def test_wrong_role_is_403(self):
        for token in ("tok-submit-a", "tok-reconcile-a"):
            with self.subTest(token=token):
                status, _, data = self._request(
                    "GET", f"/requests/{self.rid}/evidence",
                    headers={**self._bearer(token),
                             "X-Tenant-Id": "tenant-a"},
                )
                self.assertEqual((status, data), (403, FORBIDDEN))

    def test_tenant_mismatch_is_403_before_id_validation(self):
        for path in (
            f"/requests/{self.rid}/evidence",
            "/requests/not-a-uuid/evidence",
        ):
            with self.subTest(path=path):
                status, _, data = self._request(
                    "GET", path,
                    headers={**self._bearer("tok-read-a"),
                             "X-Tenant-Id": "tenant-b"},
                )
                self.assertEqual((status, data), (403, FORBIDDEN))
        status, _, data = self._request(
            "GET", f"/requests/{self.rid}/evidence?tenant_id=tenant-b",
            headers=self._bearer("tok-read-a"),
        )
        self.assertEqual((status, data), (403, FORBIDDEN))

    def test_missing_tenant_with_valid_token_is_400(self):
        status, _, data = self._request(
            "GET", f"/requests/{self.rid}/evidence",
            headers=self._bearer("tok-read-a"),
        )
        self.assertEqual((status, data), (400, INVALID_REQUEST))

    def test_authorized_read_succeeds(self):
        status, _, data = self._request(
            "GET", f"/requests/{self.rid}/evidence",
            headers={**self._bearer("tok-read-a"),
                     "X-Tenant-Id": "tenant-a"},
        )
        self.assertEqual(status, 200)
        record = json.loads(data)
        self.assertEqual(record["request_id"], self.rid)
        self.assertIs(record["verified"], True)

    def test_cross_tenant_record_is_404_with_matching_token(self):
        status, _, data = self._request(
            "GET", f"/requests/{self.rid}/evidence",
            headers={**self._bearer("tok-read-b"),
                     "X-Tenant-Id": "tenant-b"},
        )
        self.assertEqual((status, data), (404, NOT_FOUND))

    def test_method_check_precedes_authentication(self):
        status, _, data = self._request(
            "PUT", f"/requests/{self.rid}/evidence"
        )
        self.assertEqual((status, data), (405, METHOD_NOT_ALLOWED))

    def test_authorization_header_ignored_unauthenticated_separately(self):
        # With auth configured, a read-only principal still cannot submit.
        status, _, _ = self._request(
            "POST", "/requests",
            headers={**self._bearer("tok-read-a"),
                     "Content-Type": "application/json"},
        )
        self.assertEqual(status, 403)


class BrokenEvidenceStoreTests(unittest.TestCase):
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
            def get_request_evidence(self, *a, **k):
                raise RuntimeError(secret)

        fixture = self._serve(BrokenStore())
        try:
            rid = "00000000-0000-4000-8000-000000000000"
            status, data = self._get(
                fixture.port, f"/requests/{rid}/evidence"
            )
            self.assertEqual(status, 503)
            self.assertEqual(data, STORAGE_UNAVAILABLE)
            self.assertNotIn(b"SECRET", data)
        finally:
            fixture.__exit__(None, None, None)

    def test_extra_or_malformed_fields_become_503(self):
        rid = "00000000-0000-4000-8000-000000000000"
        good_hash = "a" * 64
        cases = (
            {
                "request_id": rid,
                "status": "completed",
                "event_count": 1,
                "chain_hash": good_hash,
                "verified": True,
                "subject_id": "subject-SECRET",
            },
            {
                "request_id": rid,
                "status": "",
                "event_count": 1,
                "chain_hash": good_hash,
                "verified": True,
            },
            {
                "request_id": rid,
                "status": "completed",
                "event_count": -1,
                "chain_hash": good_hash,
                "verified": True,
            },
            {
                "request_id": rid,
                "status": "completed",
                "event_count": 1,
                "chain_hash": "not-a-digest",
                "verified": True,
            },
            {
                "request_id": rid,
                "status": "completed",
                "event_count": 1,
                "chain_hash": good_hash,
                "verified": "yes",
            },
        )

        class Store:
            def __init__(self, record):
                self._record = record

            def get_request_evidence(self, *a, **k):
                return self._record

        for record in cases:
            with self.subTest(record=record):
                fixture = self._serve(Store(record))
                try:
                    status, data = self._get(
                        fixture.port, f"/requests/{rid}/evidence"
                    )
                    self.assertEqual(status, 503)
                    self.assertEqual(data, STORAGE_UNAVAILABLE)
                    self.assertNotIn(b"SECRET", data)
                finally:
                    fixture.__exit__(None, None, None)


if __name__ == "__main__":
    unittest.main()
