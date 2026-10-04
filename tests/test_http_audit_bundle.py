"""Tests for the read-only GET /requests/{request_id}/audit-bundle endpoint.

Covers the HTTP export of the request's settled audit chain as a
portable evidence bundle: the verbatim single-line compact JSON body
(byte-identical to ``RequestStore.export_audit_bundle`` from the same
snapshot, exactly one trailing newline, no wrapper object), the
tenant-resolution and query-string rules, the 400/401/403/404/405/409/
503 error contract and its ordering, the optional bearer-token RBAC,
the freeze semantics (repeat reads byte-identical, later events never
changing an already rendered text) and the strictly read-only behaviour.
"""

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

SECRET_A = "anchor-secret-alpha-0001"
SECRET_B = "anchor-secret-bravo-0002"

NOT_FOUND = b'{"error":"not_found"}\n'
INVALID_REQUEST = b'{"error":"invalid_request"}\n'
METHOD_NOT_ALLOWED = b'{"error":"method_not_allowed"}\n'
STORAGE_UNAVAILABLE = b'{"error":"storage_unavailable"}\n'
AUDIT_BUNDLE_UNAVAILABLE = b'{"error":"audit_bundle_unavailable"}\n'
UNAUTHORIZED = b'{"error":"unauthorized"}\n'
FORBIDDEN = b'{"error":"forbidden"}\n'

HEX64 = re.compile(r"^[0-9a-f]{64}$")
RFC3339 = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$"
)
FIELDS = ["request_id", "status", "events", "chain", "anchors", "generations"]

READ_A = {"token": "tok-read-a", "tenant_id": "tenant-a",
          "roles": ["request:read"]}
SUBMIT_A = {"token": "tok-submit-a", "tenant_id": "tenant-a",
            "roles": ["request:submit"]}
READ_B = {"token": "tok-read-b", "tenant_id": "tenant-b",
          "roles": ["request:read"]}


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


class AuditBundleEndpointTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "evidence.db")
        self.store = RequestStore(self.db_path, anchor_secret=SECRET_A)
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

    def _bundle(self, rid, tenant="tenant-a"):
        return self._get(f"/requests/{rid}/audit-bundle", tenant)

    def _lifecycle(self, statuses=("processing", "completed"), key="key-1",
                   tenant="tenant-a"):
        receipt = self.store.submit(tenant, "subject-1", ["email"], key)
        for target in statuses:
            self.store.transition(tenant, receipt["request_id"], target)
        return receipt

    def _raw(self):
        return sqlite3.connect(self.db_path)

    def _tamper(self, sql, params=()):
        with self._raw() as conn:
            conn.execute(sql, params)

    def _table_dump(self, table):
        with self._raw() as raw:
            return raw.execute(f"SELECT * FROM {table}").fetchall()

    def _all_tables(self):
        return {
            name: self._table_dump(name)
            for name in (
                "requests",
                "status_events",
                "audit_anchors",
                "audit_anchor_meta",
                "anchor_key_generations",
                "inspection_batches",
                "inspection_batch_items",
            )
        }

    # -- success shape --------------------------------------------------

    def test_export_is_verbatim_store_text(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        status, headers, data = self._bundle(rid)
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("Content-Type"), "application/json")
        # Byte-identical to the store's own export from the same state.
        expected = self.store.export_audit_bundle("tenant-a", rid)
        self.assertEqual(data, expected.encode("utf-8"))
        # Exactly one line, exactly one trailing newline.
        self.assertTrue(data.endswith(b"\n"))
        self.assertFalse(data.endswith(b"\n\n"))
        self.assertEqual(data.count(b"\n"), 1)
        self.assertNotIn(b"\r", data)
        payload = json.loads(data)
        self.assertEqual(list(payload), FIELDS)
        self.assertEqual(payload["request_id"], rid)
        self.assertEqual(payload["status"], "completed")
        # Compact rendering: no insignificant whitespace anywhere.
        self.assertEqual(
            data,
            (json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
             + "\n").encode("utf-8"),
        )

    def test_export_field_shapes(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        status, _, data = self._bundle(rid)
        self.assertEqual(status, 200)
        payload = json.loads(data)
        events = payload["events"]
        self.assertEqual(len(events), 3)
        for seq, event in enumerate(events):
            self.assertEqual(
                list(event), ["seq", "status", "occurred_at", "chain_hash"]
            )
            self.assertEqual(event["seq"], seq)
            self.assertIn(
                event["status"], ("accepted", "processing", "completed")
            )
            self.assertTrue(RFC3339.match(event["occurred_at"]))
            self.assertTrue(HEX64.match(event["chain_hash"]))
        self.assertEqual(
            list(payload["chain"]), ["tenant_id", "event_count", "head"]
        )
        self.assertEqual(payload["chain"]["tenant_id"], "tenant-a")
        self.assertEqual(payload["chain"]["event_count"], 3)
        self.assertTrue(HEX64.match(payload["chain"]["head"]))
        anchors = payload["anchors"]
        self.assertEqual(len(anchors), 3)
        for seq, anchor in enumerate(anchors):
            self.assertEqual(
                list(anchor), ["seq", "anchor_hmac", "key_generation"]
            )
            self.assertEqual(anchor["seq"], seq)
            self.assertTrue(HEX64.match(anchor["anchor_hmac"]))
            self.assertEqual(anchor["key_generation"], 1)
        generations = payload["generations"]
        self.assertEqual(len(generations), 1)
        record = generations[0]
        self.assertEqual(
            list(record), ["generation", "key_fingerprint", "effective_at"]
        )
        self.assertEqual(record["generation"], 1)
        self.assertTrue(HEX64.match(record["key_fingerprint"]))
        self.assertTrue(RFC3339.match(record["effective_at"]))

    def test_export_never_leaks_request_details(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        status, _, data = self._bundle(rid)
        self.assertEqual(status, 200)
        # No subject, raw scope, idempotency key, credential or secret.
        for leaked in (b"subject-1", b"email", b"key-1", SECRET_A.encode()):
            self.assertNotIn(leaked, data)

    def test_repeat_reads_are_byte_identical(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        first = self._bundle(rid)
        second = self._bundle(rid)
        self.assertEqual(first[0], 200)
        self.assertEqual(first, second)

    def test_later_events_never_change_rendered_text(self):
        receipt = self._lifecycle(("processing",))
        rid = receipt["request_id"]
        status, _, before = self._bundle(rid)
        self.assertEqual(status, 200)
        self.store.transition("tenant-a", rid, "completed")
        status, _, after = self._bundle(rid)
        self.assertEqual(status, 200)
        self.assertNotEqual(before, after)
        # The earlier text is a prefix of the growing chain and still
        # verifies offline; the new text verifies too.
        self.assertTrue(
            RequestStore.verify_audit_bundle(
                before.decode("utf-8"), {1: SECRET_A}
            )
        )
        self.assertTrue(
            RequestStore.verify_audit_bundle(
                after.decode("utf-8"), {1: SECRET_A}
            )
        )
        # Re-reading after the advance is stable again.
        self.assertEqual(self._bundle(rid)[2], after)

    def test_other_requests_never_alter_bundle(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        status, _, before = self._bundle(rid)
        self.assertEqual(status, 200)
        other = self.store.submit("tenant-a", "subject-2", ["files"], "key-2")
        self.store.transition("tenant-a", other["request_id"], "processing")
        status, _, after = self._bundle(rid)
        self.assertEqual(status, 200)
        self.assertEqual(before, after)
        # The other request's id never leaks into this bundle.
        self.assertNotIn(other["request_id"].encode(), after)

    def test_tenant_from_query_parameter(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        status, _, data = self._request(
            "GET", f"/requests/{rid}/audit-bundle?tenant_id=tenant-a"
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)["request_id"], rid)

    def test_header_takes_precedence_over_query(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        status, _, data = self._request(
            "GET",
            f"/requests/{rid}/audit-bundle?tenant_id=tenant-b",
            headers={"X-Tenant-Id": "tenant-a"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)["chain"]["tenant_id"], "tenant-a")

    def test_read_only_export_writes_nothing(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        before = self._all_tables()
        status, _, _ = self._bundle(rid)
        self.assertEqual(status, 200)
        self.assertEqual(before, self._all_tables())

    # -- 400 invalid_request --------------------------------------------

    def test_missing_tenant_is_400(self):
        receipt = self._lifecycle()
        status, _, data = self._get(
            f"/requests/{receipt['request_id']}/audit-bundle", tenant=None
        )
        self.assertEqual((status, data), (400, INVALID_REQUEST))

    def test_unknown_query_parameter_is_400(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        for path in (
            f"/requests/{rid}/audit-bundle?foo=bar",
            f"/requests/{rid}/audit-bundle?tenant_id=tenant-a&foo=bar",
            f"/requests/{rid}/audit-bundle?limit=10",
            f"/requests/{rid}/audit-bundle?cursor=abc",
        ):
            with self.subTest(path=path):
                status, _, data = self._get(path)
                self.assertEqual((status, data), (400, INVALID_REQUEST))

    def test_duplicate_query_parameter_is_400(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        for path in (
            f"/requests/{rid}/audit-bundle"
            "?tenant_id=tenant-a&tenant_id=tenant-a",
            f"/requests/{rid}/audit-bundle?foo=1&foo=2",
        ):
            with self.subTest(path=path):
                status, _, data = self._get(path)
                self.assertEqual((status, data), (400, INVALID_REQUEST))

    # -- 404 not_found --------------------------------------------------

    def test_malformed_request_id_is_404(self):
        for rid in ("not-a-request", "12345", ""):
            with self.subTest(rid=rid):
                status, _, data = self._get(f"/requests/{rid}/audit-bundle")
                self.assertEqual((status, data), (404, NOT_FOUND))

    def test_unknown_request_id_is_404(self):
        self._lifecycle()
        rid = "00000000-0000-4000-8000-000000000000"
        status, _, data = self._bundle(rid)
        self.assertEqual((status, data), (404, NOT_FOUND))

    def test_cross_tenant_lookup_is_404(self):
        receipt = self._lifecycle()
        status, _, data = self._bundle(receipt["request_id"], tenant="tenant-b")
        self.assertEqual((status, data), (404, NOT_FOUND))

    def test_deeper_path_is_404(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        for path in (
            f"/requests/{rid}/audit-bundle/extra",
            f"/requests/{rid}/audit-bundle/extra/deep",
        ):
            with self.subTest(path=path):
                status, _, data = self._get(path)
                self.assertEqual((status, data), (404, NOT_FOUND))

    # -- 405 method_not_allowed -----------------------------------------

    def test_non_get_methods_are_405(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        for method in ("POST", "PUT", "DELETE", "PATCH", "OPTIONS"):
            with self.subTest(method=method):
                status, headers, data = self._request(
                    method, f"/requests/{rid}/audit-bundle"
                )
                self.assertEqual(status, 405)
                self.assertEqual(headers.get("Allow"), "GET")
                self.assertEqual(data, METHOD_NOT_ALLOWED)

    def test_head_is_405_without_body(self):
        receipt = self._lifecycle()
        status, headers, data = self._request(
            "HEAD", f"/requests/{receipt['request_id']}/audit-bundle"
        )
        self.assertEqual(status, 405)
        self.assertEqual(headers.get("Allow"), "GET")
        self.assertEqual(data, b"")

    # -- 409 audit_bundle_unavailable -----------------------------------

    def test_unanchored_chain_is_409(self):
        # A store without an anchor secret settles no trusted chain.
        fixture_store = RequestStore(self.db_path)
        receipt = fixture_store.submit(
            "tenant-a", "subject-1", ["email"], "key-unanchored"
        )
        status, _, data = self._bundle(receipt["request_id"])
        self.assertEqual((status, data), (409, AUDIT_BUNDLE_UNAVAILABLE))
        self.assertEqual(set(json.loads(data)), {"error"})

    def test_damaged_evidence_is_409(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        self._tamper(
            "UPDATE status_events SET status = 'failed' "
            "WHERE request_id = ? AND seq = 1",
            (rid,),
        )
        status, _, data = self._bundle(rid)
        self.assertEqual((status, data), (409, AUDIT_BUNDLE_UNAVAILABLE))

    def test_deleted_anchor_is_409(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        self._tamper(
            "DELETE FROM audit_anchors WHERE request_id = ? AND seq = 1",
            (rid,),
        )
        status, _, data = self._bundle(rid)
        self.assertEqual((status, data), (409, AUDIT_BUNDLE_UNAVAILABLE))

    def test_missing_historical_secret_is_409(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        self.store.rotate_anchor_key(SECRET_A, SECRET_B)
        # Rebuilt without the historical generation-1 secret.
        rebuilt = RequestStore(self.db_path, anchor_secret=SECRET_B)
        fixture = _Server(rebuilt)
        fixture.__enter__()
        try:
            conn = http.client.HTTPConnection(
                "127.0.0.1", fixture.port, timeout=10
            )
            try:
                conn.request(
                    "GET",
                    f"/requests/{rid}/audit-bundle",
                    headers={"X-Tenant-Id": "tenant-a"},
                )
                resp = conn.getresponse()
                status, data = resp.status, resp.read()
            finally:
                conn.close()
        finally:
            fixture.__exit__(None, None, None)
        self.assertEqual((status, data), (409, AUDIT_BUNDLE_UNAVAILABLE))

    # -- 503 storage_unavailable ----------------------------------------

    def test_corrupt_database_is_503(self):
        receipt = self._lifecycle()
        with open(self.db_path, "wb") as handle:
            handle.write(b"not a sqlite database")
        status, _, data = self._bundle(receipt["request_id"])
        self.assertEqual((status, data), (503, STORAGE_UNAVAILABLE))
        self.assertEqual(set(json.loads(data)), {"error"})

    def test_dropped_evidence_table_is_503(self):
        receipt = self._lifecycle()
        self._tamper("DROP TABLE audit_anchors")
        status, _, data = self._bundle(receipt["request_id"])
        self.assertEqual((status, data), (503, STORAGE_UNAVAILABLE))


class AuditBundleStoreSubstitutionTests(unittest.TestCase):
    """A corrupt or substituted store must never leak or half-render."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)

    def _serve(self, store):
        fixture = _Server(store)
        fixture.__enter__()
        self.addCleanup(fixture.__exit__, None, None, None)
        return fixture

    def _get(self, port, path):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        try:
            conn.request(
                "GET", path, headers={"X-Tenant-Id": "tenant-a"}
            )
            resp = conn.getresponse()
            return resp.status, resp.read()
        finally:
            conn.close()

    def test_storage_exception_becomes_503_without_leak(self):
        secret = "SECRET-SQL-DETAIL-PATH"

        class BrokenStore:
            def export_audit_bundle(self, *a, **k):
                raise RuntimeError(secret)

        fixture = self._serve(BrokenStore())
        rid = "00000000-0000-4000-8000-000000000000"
        status, data = self._get(fixture.port, f"/requests/{rid}/audit-bundle")
        self.assertEqual(status, 503)
        self.assertEqual(data, STORAGE_UNAVAILABLE)
        self.assertNotIn(b"SECRET", data)

    def test_malformed_bundle_texts_become_503_without_leak(self):
        rid = "00000000-0000-4000-8000-000000000000"
        good = {
            "request_id": rid,
            "status": "completed",
            "events": [
                {
                    "seq": 0,
                    "status": "accepted",
                    "occurred_at": "2026-01-01T00:00:00Z",
                    "chain_hash": "a" * 64,
                }
            ],
            "chain": {
                "tenant_id": "tenant-a",
                "event_count": 1,
                "head": "a" * 64,
            },
            "anchors": [
                {"seq": 0, "anchor_hmac": "b" * 64, "key_generation": 1}
            ],
            "generations": [
                {
                    "generation": 1,
                    "key_fingerprint": "c" * 64,
                    "effective_at": "2026-01-01T00:00:00Z",
                }
            ],
        }

        def render(payload):
            return json.dumps(
                payload, ensure_ascii=False, separators=(",", ":")
            ) + "\n"

        def mutated(**changes):
            payload = json.loads(render(good))
            payload.update(changes)
            return render(payload)

        cases = [
            # Not a string at all.
            None,
            123,
            # Missing or duplicated trailing newline, interior break.
            render(good)[:-1],
            render(good) + "\n",
            render(good)[:-1] + "\n\n",
            # Not JSON.
            "not json\n",
            # Extra top-level key carrying a would-be secret.
            mutated(subject_id="subject-SECRET"),
            # Missing top-level key.
            render({"request_id": rid}),
            # Unknown status.
            mutated(status="vanished"),
            # Empty events.
            mutated(events=[]),
            # Event with an extra field.
            mutated(events=[dict(good["events"][0], worker="w-SECRET")]),
            # Event with a float seq.
            mutated(events=[dict(good["events"][0], seq=0.5)]),
            # Event with a malformed digest.
            mutated(events=[dict(good["events"][0], chain_hash="zz")]),
            # Chain with a malformed head.
            mutated(chain=dict(good["chain"], head="nope")),
            # Anchor with a negative generation.
            mutated(anchors=[dict(good["anchors"][0], key_generation=-1)]),
            # Generation record with a bad fingerprint.
            mutated(
                generations=[
                    dict(good["generations"][0], key_fingerprint="xx")
                ]
            ),
            # Pretty-printed (non-canonical) text.
            json.dumps(good, indent=2) + "\n",
            # Wrapped in a response envelope.
            render({"bundle": good}),
        ]
        for text in cases:
            with self.subTest(text=text):
                class Store:
                    def export_audit_bundle(self, *a, **k):
                        return text

                fixture = self._serve(Store())
                status, data = self._get(
                    fixture.port, f"/requests/{rid}/audit-bundle"
                )
                self.assertEqual(status, 503)
                self.assertEqual(data, STORAGE_UNAVAILABLE)
                self.assertNotIn(b"SECRET", data)

    def test_store_value_error_is_400(self):
        class Store:
            def export_audit_bundle(self, *a, **k):
                raise ValueError("bad tenant")

        fixture = self._serve(Store())
        rid = "00000000-0000-4000-8000-000000000000"
        status, data = self._get(fixture.port, f"/requests/{rid}/audit-bundle")
        self.assertEqual((status, data), (400, INVALID_REQUEST))


class AuditBundleAuthTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "auth", "evidence.db")
        self.store = RequestStore(self.db_path, anchor_secret=SECRET_A)
        auth = AuthConfig([READ_A, SUBMIT_A, READ_B])
        self._fixture = _Server(self.store, auth)
        self._fixture.__enter__()
        self.port = self._fixture.port

    def tearDown(self):
        self._fixture.__exit__(None, None, None)
        self._tmp.cleanup()

    def _request(self, method, path, token=None, tenant=None):
        headers = {}
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        if tenant is not None:
            headers["X-Tenant-Id"] = tenant
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request(method, path, headers=headers)
            resp = conn.getresponse()
            return resp.status, dict(resp.getheaders()), resp.read()
        finally:
            conn.close()

    def _bundle(self, rid, token="tok-read-a", tenant="tenant-a"):
        return self._request(
            "GET", f"/requests/{rid}/audit-bundle", token=token, tenant=tenant
        )

    def _lifecycle(self, tenant="tenant-a", key="key-1"):
        receipt = self.store.submit(tenant, "subject-1", ["email"], key)
        self.store.transition(tenant, receipt["request_id"], "processing")
        return receipt

    def test_authorized_read_returns_bundle(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        status, headers, data = self._bundle(rid)
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("Content-Type"), "application/json")
        self.assertEqual(json.loads(data)["request_id"], rid)
        # No token material ever leaks.
        self.assertNotIn(b"tok-", data)

    def test_missing_token_is_401(self):
        receipt = self._lifecycle()
        status, _, data = self._bundle(receipt["request_id"], token=None)
        self.assertEqual((status, data), (401, UNAUTHORIZED))

    def test_unknown_token_is_401(self):
        receipt = self._lifecycle()
        status, _, data = self._bundle(receipt["request_id"], token="nope")
        self.assertEqual((status, data), (401, UNAUTHORIZED))

    def test_missing_read_role_is_403(self):
        receipt = self._lifecycle()
        status, _, data = self._bundle(
            receipt["request_id"], token="tok-submit-a"
        )
        self.assertEqual((status, data), (403, FORBIDDEN))

    def test_other_tenant_token_is_403(self):
        receipt = self._lifecycle()
        # The principal's own tenant does not match the target tenant.
        status, _, data = self._bundle(receipt["request_id"], token="tok-read-b")
        self.assertEqual((status, data), (403, FORBIDDEN))

    def test_other_tenant_query_target_is_403(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        status, _, data = self._request(
            "GET",
            f"/requests/{rid}/audit-bundle?tenant_id=tenant-b",
            token="tok-read-a",
        )
        self.assertEqual((status, data), (403, FORBIDDEN))

    def test_authorized_cross_tenant_id_is_404(self):
        # A tenant-b request read by the tenant-b principal through its
        # own tenant still cannot name tenant-a's request.
        receipt = self._lifecycle(tenant="tenant-b", key="key-b")
        rid = receipt["request_id"]
        status, _, data = self._request(
            "GET",
            f"/requests/{rid}/audit-bundle",
            token="tok-read-b",
            tenant="tenant-b",
        )
        self.assertEqual(status, 200)
        # tenant-a's principal targeting its own tenant with tenant-b's
        # id gets the detail-free not-found.
        other = self._lifecycle(tenant="tenant-a", key="key-a")
        status, _, data = self._request(
            "GET",
            f"/requests/{other['request_id']}/audit-bundle",
            token="tok-read-b",
            tenant="tenant-b",
        )
        self.assertEqual((status, data), (404, NOT_FOUND))

    def test_auth_precedes_id_validation(self):
        # An unauthenticated caller cannot probe id shapes; a malformed
        # id under a valid token is the detail-free not-found.
        status, _, data = self._bundle("not-a-request", token=None)
        self.assertEqual((status, data), (401, UNAUTHORIZED))
        status, _, data = self._bundle("not-a-request")
        self.assertEqual((status, data), (404, NOT_FOUND))

    def test_missing_tenant_with_valid_token_is_400(self):
        receipt = self._lifecycle()
        status, _, data = self._bundle(receipt["request_id"], tenant=None)
        self.assertEqual((status, data), (400, INVALID_REQUEST))

    def test_unknown_path_stays_404_with_token(self):
        status, _, data = self._request(
            "GET", "/requests/unknown/audit-bundle/extra", token="tok-read-a"
        )
        self.assertEqual((status, data), (404, NOT_FOUND))

    def test_non_get_stays_405_without_token(self):
        receipt = self._lifecycle()
        status, headers, data = self._request(
            "POST", f"/requests/{receipt['request_id']}/audit-bundle"
        )
        self.assertEqual(status, 405)
        self.assertEqual(headers.get("Allow"), "GET")
        self.assertEqual(data, METHOD_NOT_ALLOWED)


if __name__ == "__main__":
    unittest.main()
