import http.client
import json
import os
import re
import sqlite3
import tempfile
import threading
import unittest

from forgetting_evidence.httpapi import AuthConfig, DeferredRequestStore, build_server
from forgetting_evidence.requests import RequestStore

HEX64 = re.compile(r"^[0-9a-f]{64}$")

READ_A = {
    "token": "tok-read-a",
    "tenant_id": "tenant-a",
    "roles": ["request:read"],
}
SUBMIT_A = {
    "token": "tok-submit-a",
    "tenant_id": "tenant-a",
    "roles": ["request:submit"],
}
READ_B = {
    "token": "tok-read-b",
    "tenant_id": "tenant-b",
    "roles": ["request:read"],
}


class _Server:
    def __init__(self, store, auth=None):
        self.server = build_server(store, "127.0.0.1", 0, auth)
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


class HttpEvidenceTests(unittest.TestCase):
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

    # -- helpers -------------------------------------------------------

    def _request(self, method, path, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request(method, path, headers=headers or {})
            resp = conn.getresponse()
            data = resp.read()
            return resp.status, dict(resp.getheaders()), data
        finally:
            conn.close()

    def _submit(self, tenant="tenant-a", key="key-1"):
        receipt = self.store.submit(tenant, "subject-1", ["email"], key)
        return receipt["request_id"]

    def _evidence(self, request_id, tenant="tenant-a"):
        return self._request(
            "GET",
            f"/requests/{request_id}/evidence",
            headers={"X-Tenant-Id": tenant},
        )

    def _tamper(self, sql, params=()):
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute(sql, params)
            conn.commit()
        finally:
            conn.close()

    # -- success shape -------------------------------------------------

    def test_evidence_after_submit_only(self):
        request_id = self._submit()
        status, headers, data = self._evidence(request_id)
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("Content-Type"), "application/json")
        # One compact line plus exactly one trailing newline.
        self.assertTrue(data.endswith(b"\n"))
        self.assertEqual(data.count(b"\n"), 1)
        self.assertNotIn(b" ", data)
        body = json.loads(data)
        self.assertEqual(
            list(body),
            ["request_id", "status", "event_count", "chain_hash", "verified"],
        )
        self.assertEqual(body["request_id"], request_id)
        self.assertEqual(body["status"], "accepted")
        self.assertEqual(body["event_count"], 1)
        self.assertIsInstance(body["event_count"], int)
        self.assertTrue(HEX64.match(body["chain_hash"]))
        self.assertIs(body["verified"], True)

    def test_evidence_tracks_status_transitions(self):
        request_id = self._submit()
        self.store.transition("tenant-a", request_id, "processing")
        self.store.transition("tenant-a", request_id, "completed")
        status, _, data = self._evidence(request_id)
        self.assertEqual(status, 200)
        body = json.loads(data)
        self.assertEqual(body["status"], "completed")
        self.assertEqual(body["event_count"], 3)
        self.assertIs(body["verified"], True)
        # The persisted head matches the storage layer's own evidence.
        self.assertEqual(
            body["chain_hash"],
            self.store.evidence("tenant-a", request_id)["chain_hash"],
        )

    def test_evidence_is_byte_identical_across_reads(self):
        request_id = self._submit()
        _, _, first = self._evidence(request_id)
        _, _, second = self._evidence(request_id)
        self.assertEqual(first, second)

    def test_evidence_read_is_read_only(self):
        request_id = self._submit()
        before = self.store.audit("tenant-a", request_id)
        self._evidence(request_id)
        self._evidence(request_id)
        self.assertEqual(self.store.audit("tenant-a", request_id), before)
        self.assertEqual(
            self.store.get_status("tenant-a", request_id)["status"], "accepted"
        )

    def test_tenant_via_query_parameter(self):
        request_id = self._submit()
        status, _, data = self._request(
            "GET", f"/requests/{request_id}/evidence?tenant_id=tenant-a"
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)["request_id"], request_id)

    # -- client errors ---------------------------------------------------

    def test_malformed_request_id_is_not_found(self):
        status, _, data = self._evidence("not-a-uuid")
        self.assertEqual(status, 404)
        self.assertEqual(data, b'{"error":"not_found"}\n')

    def test_unknown_request_id_is_not_found(self):
        status, _, data = self._evidence(
            "00000000-0000-0000-0000-000000000000"
        )
        self.assertEqual(status, 404)
        self.assertEqual(data, b'{"error":"not_found"}\n')

    def test_cross_tenant_lookup_is_not_found(self):
        request_id = self._submit(tenant="tenant-a")
        status, _, data = self._evidence(request_id, tenant="tenant-b")
        self.assertEqual(status, 404)
        self.assertEqual(data, b'{"error":"not_found"}\n')

    def test_missing_tenant_is_invalid_request(self):
        request_id = self._submit()
        status, _, data = self._request(
            "GET", f"/requests/{request_id}/evidence"
        )
        self.assertEqual(status, 400)
        self.assertEqual(data, b'{"error":"invalid_request"}\n')

    def test_post_to_evidence_is_method_not_allowed(self):
        request_id = self._submit()
        status, headers, data = self._request(
            "POST",
            f"/requests/{request_id}/evidence",
            headers={"X-Tenant-Id": "tenant-a"},
        )
        self.assertEqual(status, 405)
        self.assertEqual(headers.get("Allow"), "GET")
        self.assertEqual(data, b'{"error":"method_not_allowed"}\n')

    # -- tampered persistence still answers 200 with verified false ------

    def test_modified_event_still_answers_200_unverified(self):
        request_id = self._submit()
        self.store.transition("tenant-a", request_id, "processing")
        self._tamper(
            "UPDATE status_events SET status = 'failed' "
            "WHERE request_id = ? AND seq = 1",
            (request_id,),
        )
        status, _, data = self._evidence(request_id)
        self.assertEqual(status, 200)
        body = json.loads(data)
        self.assertIs(body["verified"], False)
        self.assertEqual(body["event_count"], 2)
        # The persisted head is still reported as stored.
        self.assertTrue(HEX64.match(body["chain_hash"]))

    def test_deleted_event_still_answers_200_unverified(self):
        request_id = self._submit()
        self.store.transition("tenant-a", request_id, "processing")
        self._tamper(
            "DELETE FROM status_events WHERE request_id = ? AND seq = 1",
            (request_id,),
        )
        status, _, data = self._evidence(request_id)
        self.assertEqual(status, 200)
        body = json.loads(data)
        self.assertIs(body["verified"], False)
        self.assertEqual(body["event_count"], 1)

    def test_rebound_events_still_answer_200_unverified(self):
        request_id = self._submit()
        other = self._submit(key="key-2")
        self._tamper(
            "DELETE FROM status_events WHERE request_id = ?",
            (other,),
        )
        self._tamper(
            "UPDATE status_events SET request_id = ? WHERE request_id = ?",
            (other, request_id),
        )
        status, _, data = self._evidence(other)
        self.assertEqual(status, 200)
        body = json.loads(data)
        self.assertIs(body["verified"], False)

    def test_malformed_persisted_head_renders_null_chain_hash(self):
        request_id = self._submit()
        self._tamper(
            "UPDATE requests SET chain_hash = 'not-a-digest' "
            "WHERE request_id = ?",
            (request_id,),
        )
        status, _, data = self._evidence(request_id)
        self.assertEqual(status, 200)
        body = json.loads(data)
        self.assertIsNone(body["chain_hash"])
        self.assertIs(body["verified"], False)
        self.assertEqual(body["status"], "accepted")
        self.assertEqual(body["event_count"], 1)

    def test_tampered_valid_head_is_reported_but_unverified(self):
        request_id = self._submit()
        forged = "0" * 64
        self._tamper(
            "UPDATE requests SET chain_hash = ? WHERE request_id = ?",
            (forged, request_id),
        )
        status, _, data = self._evidence(request_id)
        self.assertEqual(status, 200)
        body = json.loads(data)
        # The persisted head is reported as stored, never recomputed.
        self.assertEqual(body["chain_hash"], forged)
        self.assertIs(body["verified"], False)

    # -- storage failure ---------------------------------------------------

    def test_storage_unavailable(self):
        # A database path that can never be opened (a directory).
        bad_store = DeferredRequestStore(self._tmp.name)
        with _Server(bad_store) as fixture:
            conn = http.client.HTTPConnection(
                "127.0.0.1", fixture.port, timeout=10
            )
            try:
                conn.request(
                    "GET",
                    "/requests/00000000-0000-0000-0000-000000000000/evidence",
                    headers={"X-Tenant-Id": "tenant-a"},
                )
                resp = conn.getresponse()
                data = resp.read()
            finally:
                conn.close()
        self.assertEqual(resp.status, 503)
        self.assertEqual(data, b'{"error":"storage_unavailable"}\n')


class HttpEvidenceAuthTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "evidence.db")
        self.store = RequestStore(self.db_path)
        auth = AuthConfig([READ_A, SUBMIT_A, READ_B])
        self._fixture = _Server(self.store, auth=auth)
        self._fixture.__enter__()
        self.port = self._fixture.port
        receipt = self.store.submit("tenant-a", "subject-1", ["email"], "key-1")
        self.request_id = receipt["request_id"]

    def tearDown(self):
        self._fixture.__exit__(None, None, None)
        self._tmp.cleanup()

    def _get(self, token=None, tenant="tenant-a"):
        headers = {"X-Tenant-Id": tenant}
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request(
                "GET", f"/requests/{self.request_id}/evidence", headers=headers
            )
            resp = conn.getresponse()
            return resp.status, resp.read()
        finally:
            conn.close()

    def test_missing_token_is_unauthorized(self):
        status, data = self._get()
        self.assertEqual(status, 401)
        self.assertEqual(data, b'{"error":"unauthorized"}\n')

    def test_unknown_token_is_unauthorized(self):
        status, data = self._get(token="nope")
        self.assertEqual(status, 401)
        self.assertEqual(data, b'{"error":"unauthorized"}\n')

    def test_submit_only_role_is_forbidden(self):
        status, data = self._get(token="tok-submit-a")
        self.assertEqual(status, 403)
        self.assertEqual(data, b'{"error":"forbidden"}\n')

    def test_foreign_tenant_principal_is_forbidden(self):
        # tenant-b's reader may not address tenant-a's namespace.
        status, data = self._get(token="tok-read-b", tenant="tenant-a")
        self.assertEqual(status, 403)
        self.assertEqual(data, b'{"error":"forbidden"}\n')

    def test_read_role_succeeds(self):
        status, data = self._get(token="tok-read-a")
        self.assertEqual(status, 200)
        body = json.loads(data)
        self.assertEqual(body["request_id"], self.request_id)
        self.assertIs(body["verified"], True)

    def test_own_tenant_reader_sees_not_found_for_foreign_record(self):
        # tenant-b's reader addressing its own namespace cannot see
        # tenant-a's request: missing and cross-tenant are one outcome.
        status, data = self._get(token="tok-read-b", tenant="tenant-b")
        self.assertEqual(status, 404)
        self.assertEqual(data, b'{"error":"not_found"}\n')


if __name__ == "__main__":
    unittest.main()
