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
AUDIT_BUNDLE_UNAVAILABLE = b'{"error":"audit_bundle_unavailable"}\n'
UNAUTHORIZED = b'{"error":"unauthorized"}\n'
FORBIDDEN = b'{"error":"forbidden"}\n'

SECRET = "anchor-secret-alpha-0001"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
FIELDS = ["request_id", "status", "events", "chain", "anchors", "generations"]


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
        self.store = RequestStore(self.db_path, anchor_secret=SECRET)
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

    def _bundle(self, rid, tenant="tenant-a"):
        return self._get(f"/requests/{rid}/audit-bundle", tenant)

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

    def test_export_matches_store_text_verbatim(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        status, headers, data = self._bundle(rid)
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("Content-Type"), "application/json")
        # Exactly the store's single-line compact text, one trailing
        # newline, no wrapper object.
        self.assertEqual(
            data, self.store.export_audit_bundle("tenant-a", rid).encode()
        )
        self.assertTrue(data.endswith(b"\n"))
        self.assertEqual(data.count(b"\n"), 1)
        payload = json.loads(data)
        self.assertEqual(list(payload), FIELDS)
        self.assertEqual(payload["request_id"], rid)
        self.assertEqual(payload["status"], "completed")
        self.assertEqual(payload["chain"]["tenant_id"], "tenant-a")
        self.assertEqual(payload["chain"]["event_count"], 3)
        self.assertTrue(HEX64.match(payload["chain"]["head"]))
        self.assertEqual(len(payload["events"]), 3)
        self.assertEqual(len(payload["anchors"]), 3)
        # No subject, scope, idempotency key or secret material leaks.
        self.assertNotIn(b"subject-1", data)
        self.assertNotIn(b"email", data)
        self.assertNotIn(b"key-1", data)
        self.assertNotIn(SECRET.encode(), data)

    def test_repeated_reads_are_byte_identical(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        _, _, first = self._bundle(rid)
        for _ in range(3):
            status, _, again = self._bundle(rid)
            self.assertEqual(status, 200)
            self.assertEqual(again, first)

    def test_later_events_never_change_an_exported_bundle(self):
        receipt = self._lifecycle(("processing",))
        rid = receipt["request_id"]
        _, _, frozen = self._bundle(rid)
        self.store.transition("tenant-a", rid, "completed")
        status, _, advanced = self._bundle(rid)
        self.assertEqual(status, 200)
        self.assertNotEqual(advanced, frozen)
        # The earlier text is untouched and still authenticates offline.
        self.assertTrue(
            RequestStore.verify_audit_bundle(frozen.decode(), {1: SECRET})
        )
        self.assertTrue(
            RequestStore.verify_audit_bundle(advanced.decode(), {1: SECRET})
        )
        # And the frozen text is still what a chain at that head renders.
        self.assertEqual(json.loads(frozen)["chain"]["event_count"], 2)
        self.assertEqual(json.loads(advanced)["chain"]["event_count"], 3)

    def test_bundle_stable_across_restart(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        _, _, first = self._bundle(rid)
        self._fixture.__exit__(None, None, None)
        rebuilt = RequestStore(self.db_path, anchor_secret=SECRET)
        with _Server(rebuilt) as fixture:
            conn = http.client.HTTPConnection(
                "127.0.0.1", fixture.port, timeout=10
            )
            try:
                conn.request(
                    "GET", f"/requests/{rid}/audit-bundle",
                    headers={"X-Tenant-Id": "tenant-a"},
                )
                resp = conn.getresponse()
                status, second = resp.status, resp.read()
            finally:
                conn.close()
        self.assertEqual(status, 200)
        self.assertEqual(second, first)
        self._fixture = _Server(self.store)
        self._fixture.__enter__()
        self.port = self._fixture.port

    # -- tenant location ------------------------------------------------

    def test_tenant_query_parameter_and_header_precedence(self):
        receipt = self._lifecycle(())
        rid = receipt["request_id"]
        status, _, data = self._request(
            "GET", f"/requests/{rid}/audit-bundle?tenant_id=tenant-a"
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)["request_id"], rid)
        # A non-empty header overrides the query string and scopes the read.
        status, _, data = self._request(
            "GET", f"/requests/{rid}/audit-bundle?tenant_id=tenant-a",
            headers={"X-Tenant-Id": "tenant-b"},
        )
        self.assertEqual((status, data), (404, NOT_FOUND))

    def test_uppercase_uuid_canonicalises(self):
        receipt = self._lifecycle(())
        _, _, lower = self._bundle(receipt["request_id"])
        status, _, upper = self._get(
            f"/requests/{receipt['request_id'].upper()}/audit-bundle"
        )
        self.assertEqual(status, 200)
        self.assertEqual(upper, lower)

    # -- error mapping --------------------------------------------------

    def test_missing_tenant_is_400(self):
        receipt = self._lifecycle(())
        status, _, data = self._request(
            "GET", f"/requests/{receipt['request_id']}/audit-bundle"
        )
        self.assertEqual((status, data), (400, INVALID_REQUEST))
        status, _, data = self._request(
            "GET", f"/requests/{receipt['request_id']}/audit-bundle?tenant_id="
        )
        self.assertEqual((status, data), (400, INVALID_REQUEST))

    def test_unknown_or_duplicate_query_params_are_400(self):
        receipt = self._lifecycle(())
        rid = receipt["request_id"]
        for path in (
            f"/requests/{rid}/audit-bundle?cursor=abc",
            f"/requests/{rid}/audit-bundle?limit=10",
            f"/requests/{rid}/audit-bundle?tenant_id=tenant-a&status=accepted",
            f"/requests/{rid}/audit-bundle?tenant_id=tenant-a&tenant_id=tenant-a",
            f"/requests/{rid}/audit-bundle?tenant_id=tenant-b&tenant_id=tenant-a",
        ):
            with self.subTest(path=path):
                status, _, data = self._get(path)
                self.assertEqual((status, data), (400, INVALID_REQUEST))

    def test_malformed_unknown_cross_tenant_ids_are_404(self):
        receipt = self._lifecycle(())
        rid = receipt["request_id"]
        unknown = "00000000-0000-4000-8000-000000000000"
        for path, tenant in (
            ("/requests/not-a-uuid/audit-bundle", "tenant-a"),
            (f"/requests/{unknown}/audit-bundle", "tenant-a"),
            (f"/requests/{rid}/audit-bundle", "tenant-b"),
            (f"/requests/{rid}/audit-bundle?tenant_id=tenant-b", None),
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
            f"/requests/{rid}/audit-bundle/",
            f"/requests/{rid}/audit-bundle/extra",
            "/requests//audit-bundle",
            f"/requests/{rid}/audit_bundle",
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
                    method, f"/requests/{rid}/audit-bundle",
                    body={} if method == "POST" else None,
                )
                self.assertEqual(status, 405)
                self.assertEqual(data, METHOD_NOT_ALLOWED)
                self.assertEqual(headers.get("Allow"), "GET")
        # HEAD answers 405 with headers but no body.
        status, headers, data = self._request(
            "HEAD", f"/requests/{rid}/audit-bundle"
        )
        self.assertEqual(status, 405)
        self.assertEqual(headers.get("Allow"), "GET")
        self.assertEqual(data, b"")

    def test_corrupt_database_is_503(self):
        receipt = self._lifecycle(())
        with open(self.db_path, "wb") as handle:
            handle.write(b"not a sqlite database")
        status, _, data = self._bundle(receipt["request_id"])
        self.assertEqual((status, data), (503, STORAGE_UNAVAILABLE))
        self.assertEqual(set(json.loads(data)), {"error"})

    # -- unavailable and untrusted evidence: 409 -------------------------

    def test_unanchored_chain_is_409(self):
        # A store without an anchor secret can never export proof.
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        db_path = os.path.join(tmp.name, "unanchored.db")
        store = RequestStore(db_path)
        rid = store.submit("tenant-a", "subject-1", ["email"], "key-1")[
            "request_id"
        ]
        with _Server(store) as fixture:
            conn = http.client.HTTPConnection(
                "127.0.0.1", fixture.port, timeout=10
            )
            try:
                conn.request(
                    "GET", f"/requests/{rid}/audit-bundle",
                    headers={"X-Tenant-Id": "tenant-a"},
                )
                resp = conn.getresponse()
                status, data = resp.status, resp.read()
            finally:
                conn.close()
        self.assertEqual((status, data), (409, AUDIT_BUNDLE_UNAVAILABLE))
        self.assertEqual(set(json.loads(data)), {"error"})

    def test_deleted_event_is_409(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        self._tamper(
            "DELETE FROM status_events WHERE request_id = ? AND seq = 1",
            (rid,),
        )
        status, _, data = self._bundle(rid)
        self.assertEqual((status, data), (409, AUDIT_BUNDLE_UNAVAILABLE))

    def test_altered_anchor_is_409(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        self._tamper(
            "UPDATE audit_anchors SET anchor_hmac = ? "
            "WHERE request_id = ? AND seq = 0",
            ("0" * 64, rid),
        )
        status, _, data = self._bundle(rid)
        self.assertEqual((status, data), (409, AUDIT_BUNDLE_UNAVAILABLE))

    def test_unavailable_is_repeatable_and_writes_nothing(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        self._tamper(
            "DELETE FROM audit_anchors WHERE request_id = ?", (rid,)
        )
        _, _, first = self._bundle(rid)
        _, _, second = self._bundle(rid)
        self.assertEqual(first, second)
        self.assertEqual(first, AUDIT_BUNDLE_UNAVAILABLE)

    # -- read-only ------------------------------------------------------

    def test_export_read_never_writes(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        with open(self.db_path, "rb") as handle:
            before = handle.read()
        for _ in range(5):
            status, _, _ = self._bundle(rid)
            self.assertEqual(status, 200)
        with open(self.db_path, "rb") as handle:
            after = handle.read()
        self.assertEqual(before, after)
        # No attempts, tombstones, receipts or inspection batches appeared.
        with self._raw() as conn:
            for table in (
                "claim_attempts",
                "deletion_tombstones",
                "deletion_receipts",
                "inspection_batches",
            ):
                self.assertEqual(
                    conn.execute(
                        f"SELECT count(*) FROM {table} WHERE 1=1"
                    ).fetchone()[0],
                    0,
                )


SUBMIT_A = {"token": "tok-submit-a", "tenant_id": "tenant-a",
            "roles": ["request:submit"]}
READ_A = {"token": "tok-read-a", "tenant_id": "tenant-a",
          "roles": ["request:read"]}
READ_B = {"token": "tok-read-b", "tenant_id": "tenant-b",
          "roles": ["request:read"]}
RECONCILE_A = {"token": "tok-reconcile-a", "tenant_id": "tenant-a",
               "roles": ["request:reconcile"]}


class AuditBundleAuthTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "evidence.db")
        self.store = RequestStore(self.db_path, anchor_secret=SECRET)
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
                    "GET", f"/requests/{self.rid}/audit-bundle",
                    headers={**headers, "X-Tenant-Id": "tenant-a"},
                )
                self.assertEqual((status, data), (401, UNAUTHORIZED))

    def test_wrong_role_is_403(self):
        for token in ("tok-submit-a", "tok-reconcile-a"):
            with self.subTest(token=token):
                status, _, data = self._request(
                    "GET", f"/requests/{self.rid}/audit-bundle",
                    headers={**self._bearer(token),
                             "X-Tenant-Id": "tenant-a"},
                )
                self.assertEqual((status, data), (403, FORBIDDEN))

    def test_tenant_mismatch_is_403_before_id_validation(self):
        for path in (
            f"/requests/{self.rid}/audit-bundle",
            "/requests/not-a-uuid/audit-bundle",
        ):
            with self.subTest(path=path):
                status, _, data = self._request(
                    "GET", path,
                    headers={**self._bearer("tok-read-a"),
                             "X-Tenant-Id": "tenant-b"},
                )
                self.assertEqual((status, data), (403, FORBIDDEN))
        status, _, data = self._request(
            "GET", f"/requests/{self.rid}/audit-bundle?tenant_id=tenant-b",
            headers=self._bearer("tok-read-a"),
        )
        self.assertEqual((status, data), (403, FORBIDDEN))

    def test_missing_tenant_with_valid_token_is_400(self):
        status, _, data = self._request(
            "GET", f"/requests/{self.rid}/audit-bundle",
            headers=self._bearer("tok-read-a"),
        )
        self.assertEqual((status, data), (400, INVALID_REQUEST))

    def test_authorized_read_succeeds(self):
        status, _, data = self._request(
            "GET", f"/requests/{self.rid}/audit-bundle",
            headers={**self._bearer("tok-read-a"),
                     "X-Tenant-Id": "tenant-a"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)["request_id"], self.rid)

    def test_cross_tenant_record_is_404_with_matching_token(self):
        status, _, data = self._request(
            "GET", f"/requests/{self.rid}/audit-bundle",
            headers={**self._bearer("tok-read-b"),
                     "X-Tenant-Id": "tenant-b"},
        )
        self.assertEqual((status, data), (404, NOT_FOUND))

    def test_method_check_precedes_authentication(self):
        status, _, data = self._request(
            "PUT", f"/requests/{self.rid}/audit-bundle"
        )
        self.assertEqual((status, data), (405, METHOD_NOT_ALLOWED))


class BrokenAuditBundleStoreTests(unittest.TestCase):
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
            def export_audit_bundle(self, *a, **k):
                raise RuntimeError(secret)

        fixture = self._serve(BrokenStore())
        try:
            rid = "00000000-0000-4000-8000-000000000000"
            status, data = self._get(
                fixture.port, f"/requests/{rid}/audit-bundle"
            )
            self.assertEqual(status, 503)
            self.assertEqual(data, STORAGE_UNAVAILABLE)
            self.assertNotIn(b"SECRET", data)
        finally:
            fixture.__exit__(None, None, None)

    def test_malformed_bundle_text_becomes_503(self):
        rid = "00000000-0000-4000-8000-000000000000"
        good = (
            '{"request_id":"%s","status":"accepted","events":['
            '{"seq":0,"status":"accepted","occurred_at":"2026-01-01T00:00:00Z",'
            '"chain_hash":"%s"}],"chain":{"tenant_id":"tenant-a",'
            '"event_count":1,"head":"%s"},"anchors":[{"seq":0,'
            '"anchor_hmac":"%s","key_generation":null}],"generations":[]}\n'
        ) % (rid, "a" * 64, "b" * 64, "c" * 64)
        cases = (
            "not json\n",
            good[:-2] + "\n\n",  # duplicated trailing newline
            good.replace('"events"', '\n"events"', 1),  # interior newline
            good.replace('"accepted","events"', '"accepted", "events"'),
            good[:-2] + ',"extra":1}\n',
            good.replace('"generations":[]', '"generations":{}'),
            good.replace('"event_count":1', '"event_count":-1'),
            good.replace('"key_generation":null', '"key_generation":0'),
            good.replace('"head":"' + "b" * 64 + '"', '"head":"nope"'),
            good.replace(
            '"occurred_at":"2026-01-01T00:00:00Z"', '"occurred_at":""'
            ),
            good + "extra",
            '{"request_id":"%s","status":"accepted","events":[],'
            '"chain":{"tenant_id":"tenant-a","event_count":1,"head":"%s"},'
            '"anchors":[],"generations":[]}\n' % (rid, "b" * 64),
        )

        class Store:
            def __init__(self, text):
                self._text = text

            def export_audit_bundle(self, *a, **k):
                return self._text

        for text in cases:
            with self.subTest(text=text[:60]):
                fixture = self._serve(Store(text))
                try:
                    status, data = self._get(
                        fixture.port, f"/requests/{rid}/audit-bundle"
                    )
                    self.assertEqual(status, 503)
                    self.assertEqual(data, STORAGE_UNAVAILABLE)
                finally:
                    fixture.__exit__(None, None, None)

    def test_valid_shaped_text_passes_through_verbatim(self):
        rid = "00000000-0000-4000-8000-000000000000"
        text = (
            '{"request_id":"%s","status":"accepted","events":['
            '{"seq":0,"status":"accepted","occurred_at":"2026-01-01T00:00:00Z",'
            '"chain_hash":"%s"}],"chain":{"tenant_id":"tenant-a",'
            '"event_count":1,"head":"%s"},"anchors":[{"seq":0,'
            '"anchor_hmac":"%s","key_generation":null}],"generations":[]}\n'
        ) % (rid, "a" * 64, "b" * 64, "c" * 64)

        class Store:
            def export_audit_bundle(self, *a, **k):
                return text

        fixture = self._serve(Store())
        try:
            status, data = self._get(
                fixture.port, f"/requests/{rid}/audit-bundle"
            )
            self.assertEqual(status, 200)
            self.assertEqual(data, text.encode())
        finally:
            fixture.__exit__(None, None, None)


if __name__ == "__main__":
    unittest.main()
