import http.client
import json
import os
import sqlite3
import tempfile
import threading
import unittest

from forgetting_evidence.httpapi import AuthConfig, build_server
from forgetting_evidence.requests import RequestStore

LISTING_ERROR = "request_listing_failed"


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


class ListRequestsStoreTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "evidence.db")

    def tearDown(self):
        self._tmp.cleanup()

    def _store(self):
        return RequestStore(self.db_path)

    def _submit_many(self, store, tenant, count, prefix="key"):
        return [
            store.submit(tenant, f"subject-{i}", ["email"], f"{prefix}-{i}")
            for i in range(count)
        ]

    def test_empty_tenant_listing(self):
        store = self._store()
        page = store.list_requests("tenant-a")
        self.assertEqual(set(page), {"items", "next_cursor"})
        self.assertEqual(page["items"], [])
        self.assertIsNone(page["next_cursor"])

    def test_listing_shape_and_order(self):
        store = self._store()
        receipts = self._submit_many(store, "tenant-a", 3)
        page = store.list_requests("tenant-a")
        self.assertEqual(len(page["items"]), 3)
        self.assertIsNone(page["next_cursor"])
        for item, receipt in zip(page["items"], receipts):
            self.assertEqual(set(item), {"request_id", "status", "created_at"})
            self.assertEqual(item["request_id"], receipt["request_id"])
            self.assertEqual(item["status"], "accepted")
            self.assertEqual(item["created_at"], receipt["created_at"])
        keys = [(i["created_at"], i["request_id"]) for i in page["items"]]
        self.assertEqual(keys, sorted(keys))

    def test_listing_is_tenant_scoped(self):
        store = self._store()
        self._submit_many(store, "tenant-a", 2)
        self._submit_many(store, "tenant-b", 1)
        page_a = store.list_requests("tenant-a")
        page_b = store.list_requests("tenant-b")
        self.assertEqual(len(page_a["items"]), 2)
        self.assertEqual(len(page_b["items"]), 1)

    def test_listing_reflects_current_status(self):
        store = self._store()
        first, second = self._submit_many(store, "tenant-a", 2)
        store.transition("tenant-a", first["request_id"], "processing")
        page = store.list_requests("tenant-a")
        by_id = {item["request_id"]: item["status"] for item in page["items"]}
        self.assertEqual(by_id[first["request_id"]], "processing")
        self.assertEqual(by_id[second["request_id"]], "accepted")
        # created_at stays the original acceptance time.
        by_id_created = {
            item["request_id"]: item["created_at"] for item in page["items"]
        }
        self.assertEqual(by_id_created[first["request_id"]], first["created_at"])

    def test_status_filter(self):
        store = self._store()
        first, second, third = self._submit_many(store, "tenant-a", 3)
        store.transition("tenant-a", first["request_id"], "processing")
        store.transition("tenant-a", second["request_id"], "failed")
        page = store.list_requests("tenant-a", statuses=["accepted", "failed"])
        self.assertEqual(
            {item["request_id"] for item in page["items"]},
            {second["request_id"], third["request_id"]},
        )
        # Filter order does not matter: normalization is canonical.
        again = store.list_requests("tenant-a", statuses=["failed", "accepted"])
        self.assertEqual(page, again)
        # A tuple is accepted as well.
        as_tuple = store.list_requests("tenant-a", statuses=("failed", "accepted"))
        self.assertEqual(page, as_tuple)

    def test_status_filter_rejects_bad_values(self):
        store = self._store()
        self._submit_many(store, "tenant-a", 1)
        bad = [
            ["accepted", "accepted"],  # duplicate
            ["bogus"],
            ["Accepted"],
            [],
            ["accepted", ""],
            [None],
            [1],
            "accepted",  # a bare string is not a sequence of statuses
            7,
            {"accepted": True},
        ]
        for value in bad:
            with self.subTest(value=value):
                with self.assertRaises(ValueError) as ctx:
                    store.list_requests("tenant-a", statuses=value)
                self.assertEqual(str(ctx.exception), LISTING_ERROR)

    def test_created_bounds(self):
        store = self._store()
        first, second, third = self._submit_many(store, "tenant-a", 3)
        # created_from is inclusive.
        page = store.list_requests(
            "tenant-a", created_from=second["created_at"]
        )
        self.assertEqual(
            [item["request_id"] for item in page["items"]],
            [second["request_id"], third["request_id"]],
        )
        # created_to is exclusive.
        page = store.list_requests("tenant-a", created_to=second["created_at"])
        self.assertEqual(
            [item["request_id"] for item in page["items"]],
            [first["request_id"]],
        )
        page = store.list_requests(
            "tenant-a",
            created_from=first["created_at"],
            created_to=third["created_at"],
        )
        self.assertEqual(
            [item["request_id"] for item in page["items"]],
            [first["request_id"], second["request_id"]],
        )
        # An explicit zero offset names the same UTC instant.
        zoned = store.list_requests(
            "tenant-a",
            created_from=second["created_at"].replace("Z", "+00:00"),
        )
        self.assertEqual(
            [item["request_id"] for item in zoned["items"]],
            [second["request_id"], third["request_id"]],
        )

    def test_created_bounds_reject_bad_values(self):
        store = self._store()
        self._submit_many(store, "tenant-a", 1)
        bad = [
            "not-a-time",
            "2026-10-02",
            "2026-10-02 12:00:00Z",
            "2026-10-02T12:00:00",  # no offset
            "2026-10-02T12:00:00+01:00",  # not UTC
            "2026-13-02T12:00:00Z",  # no such month
            "",
            7,
            True,
        ]
        for value in bad:
            with self.subTest(value=value):
                with self.assertRaises(ValueError) as ctx:
                    store.list_requests("tenant-a", created_from=value)
                self.assertEqual(str(ctx.exception), LISTING_ERROR)
                with self.assertRaises(ValueError) as ctx:
                    store.list_requests("tenant-a", created_to=value)
                self.assertEqual(str(ctx.exception), LISTING_ERROR)

    def test_limit_validation(self):
        store = self._store()
        self._submit_many(store, "tenant-a", 2)
        self.assertEqual(len(store.list_requests("tenant-a", limit=1)["items"]), 1)
        self.assertEqual(len(store.list_requests("tenant-a", limit=1000)["items"]), 2)
        for value in (0, 1001, -1, True, False, "10", 1.5, None.__class__):
            with self.subTest(value=value):
                with self.assertRaises(ValueError) as ctx:
                    store.list_requests("tenant-a", limit=value)
                self.assertEqual(str(ctx.exception), LISTING_ERROR)

    def test_tenant_validation(self):
        store = self._store()
        for value in ("", None, 7, b"tenant", ["tenant"]):
            with self.subTest(value=value):
                with self.assertRaises(ValueError) as ctx:
                    store.list_requests(value)
                self.assertEqual(str(ctx.exception), LISTING_ERROR)

    def test_pagination_walks_every_item_once(self):
        store = self._store()
        receipts = self._submit_many(store, "tenant-a", 7)
        seen = []
        cursor = None
        pages = 0
        while True:
            page = store.list_requests("tenant-a", limit=3, cursor=cursor)
            seen.extend(item["request_id"] for item in page["items"])
            pages += 1
            cursor = page["next_cursor"]
            if cursor is None:
                break
            self.assertLessEqual(pages, 10)
        self.assertEqual(pages, 3)
        self.assertEqual(seen, [r["request_id"] for r in receipts])

    def test_cursor_binds_tenant_and_filters(self):
        store = self._store()
        self._submit_many(store, "tenant-a", 4)
        self._submit_many(store, "tenant-b", 4)
        page = store.list_requests("tenant-a", limit=2)
        cursor = page["next_cursor"]
        self.assertIsNotNone(cursor)
        # Cross-tenant reuse is caller error.
        with self.assertRaises(ValueError) as ctx:
            store.list_requests("tenant-b", limit=2, cursor=cursor)
        self.assertEqual(str(ctx.exception), LISTING_ERROR)
        # Cross-filter reuse is caller error.
        for kwargs in (
            {"statuses": ["accepted"]},
            {"created_from": "2020-01-01T00:00:00Z"},
            {"created_to": "2030-01-01T00:00:00Z"},
        ):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ValueError) as ctx:
                    store.list_requests("tenant-a", limit=2, cursor=cursor, **kwargs)
                self.assertEqual(str(ctx.exception), LISTING_ERROR)
        # The same normalized filter resumes: limit is not part of the
        # binding, and status order normalizes away.
        filtered = store.list_requests(
            "tenant-a", statuses=["accepted", "failed"], limit=1
        )
        resumed = store.list_requests(
            "tenant-a",
            statuses=["failed", "accepted"],
            limit=5,
            cursor=filtered["next_cursor"],
        )
        walked = filtered["items"] + resumed["items"]
        self.assertEqual(len(walked), 4)

    def test_malformed_cursors_rejected(self):
        store = self._store()
        self._submit_many(store, "tenant-a", 2)
        bad = [
            "",
            "rl1.",
            "rl1.!!!",
            "rl1." + "A" * 3,  # bad padding
            "rc1." + "A" * 4,  # foreign cursor family
            "garbage",
            7,
            None.__class__,
            # Valid envelope, foreign payload shape.
            "rl1.eyJ2IjoxfQ==",
        ]
        for value in bad:
            with self.subTest(value=value):
                with self.assertRaises(ValueError) as ctx:
                    store.list_requests("tenant-a", cursor=value)
                self.assertEqual(str(ctx.exception), LISTING_ERROR)

    def test_static_data_pagination_survives_rebuild(self):
        store = self._store()
        self._submit_many(store, "tenant-a", 5)
        first_store_pages = []
        cursor = None
        while True:
            page = store.list_requests("tenant-a", limit=2, cursor=cursor)
            first_store_pages.append(page)
            cursor = page["next_cursor"]
            if cursor is None:
                break
        del store
        rebuilt = self._store()
        rebuilt_pages = []
        cursor = None
        while True:
            page = rebuilt.list_requests("tenant-a", limit=2, cursor=cursor)
            rebuilt_pages.append(page)
            cursor = page["next_cursor"]
            if cursor is None:
                break
        # Byte-identical pages, including the cursor values themselves.
        self.assertEqual(first_store_pages, rebuilt_pages)

    def test_corrupt_record_fails_whole_listing(self):
        store = self._store()
        self._submit_many(store, "tenant-a", 2)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("UPDATE requests SET status = 'bogus'")
        with self.assertRaises(OSError) as ctx:
            store.list_requests("tenant-a")
        self.assertEqual(str(ctx.exception), LISTING_ERROR)

    def test_storage_fault_is_fixed_oserror(self):
        store = self._store()
        self._submit_many(store, "tenant-a", 1)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DROP TABLE requests")
        with self.assertRaises(OSError) as ctx:
            store.list_requests("tenant-a")
        self.assertEqual(str(ctx.exception), LISTING_ERROR)

    def test_listing_is_read_only(self):
        store = self._store()
        receipt = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        store.list_requests("tenant-a")
        store.list_requests("tenant-a", limit=1)
        # Nothing changed: the frozen receipt and the status read are
        # exactly what they were before the listing.
        self.assertEqual(store.get("tenant-a", receipt["request_id"]), receipt)
        self.assertEqual(
            store.get_status("tenant-a", receipt["request_id"]),
            {
                "request_id": receipt["request_id"],
                "status": "accepted",
                "created_at": receipt["created_at"],
            },
        )

    def test_in_memory_store_listing(self):
        store = RequestStore(":memory:")
        self._submit_many(store, "tenant-a", 3)
        page = store.list_requests("tenant-a", limit=2)
        self.assertEqual(len(page["items"]), 2)
        rest = store.list_requests("tenant-a", limit=2, cursor=page["next_cursor"])
        self.assertEqual(len(rest["items"]), 1)
        self.assertIsNone(rest["next_cursor"])


class ListRequestsHttpTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "evidence.db")
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

    def _submit_many(self, tenant, count):
        return [
            self.store.submit(tenant, f"subject-{i}", ["email"], f"key-{i}")
            for i in range(count)
        ]

    def test_listing_endpoint_shape(self):
        receipts = self._submit_many("tenant-a", 2)
        status, headers, data = self._request(
            "GET", "/requests", {"X-Tenant-Id": "tenant-a"}
        )
        self.assertEqual(status, 200)
        self.assertTrue(data.endswith(b"\n"))
        self.assertNotIn(b"\n", data[:-1])
        page = json.loads(data)
        self.assertEqual(set(page), {"items", "next_cursor"})
        self.assertIsNone(page["next_cursor"])
        self.assertEqual(len(page["items"]), 2)
        for item, receipt in zip(page["items"], receipts):
            self.assertEqual(set(item), {"request_id", "status", "created_at"})
            self.assertEqual(item["request_id"], receipt["request_id"])
        # No request payload field ever appears in the listing body.
        for forbidden in (b"subject", b"scopes", b"idempotency", b"email"):
            self.assertNotIn(forbidden, data)

    def test_listing_tenant_from_query_param(self):
        self._submit_many("tenant-a", 1)
        status, _, data = self._request("GET", "/requests?tenant_id=tenant-a")
        self.assertEqual(status, 200)
        self.assertEqual(len(json.loads(data)["items"]), 1)

    def test_listing_filters_over_http(self):
        first, second, _ = self._submit_many("tenant-a", 3)
        self.store.transition("tenant-a", first["request_id"], "processing")
        status, _, data = self._request(
            "GET",
            "/requests?tenant_id=tenant-a&status=accepted,processing",
        )
        self.assertEqual(status, 200)
        self.assertEqual(len(json.loads(data)["items"]), 3)
        status, _, data = self._request(
            "GET", "/requests?tenant_id=tenant-a&status=processing"
        )
        self.assertEqual(status, 200)
        items = json.loads(data)["items"]
        self.assertEqual([item["request_id"] for item in items],
                         [first["request_id"]])
        bound = second["created_at"]
        status, _, data = self._request(
            "GET", f"/requests?tenant_id=tenant-a&created_from={bound}"
        )
        self.assertEqual(status, 200)
        self.assertEqual(len(json.loads(data)["items"]), 2)
        status, _, data = self._request(
            "GET", f"/requests?tenant_id=tenant-a&created_to={bound}"
        )
        self.assertEqual(status, 200)
        self.assertEqual(len(json.loads(data)["items"]), 1)

    def test_listing_pagination_over_http(self):
        receipts = self._submit_many("tenant-a", 5)
        seen = []
        cursor = None
        for _ in range(10):
            path = "/requests?tenant_id=tenant-a&limit=2"
            if cursor is not None:
                path += f"&cursor={cursor}"
            status, _, data = self._request("GET", path)
            self.assertEqual(status, 200)
            page = json.loads(data)
            seen.extend(item["request_id"] for item in page["items"])
            cursor = page["next_cursor"]
            if cursor is None:
                break
        self.assertEqual(seen, [r["request_id"] for r in receipts])

    def test_listing_invalid_queries_are_400(self):
        self._submit_many("tenant-a", 2)
        page = self.store.list_requests("tenant-a", limit=1)
        cursor = page["next_cursor"]
        bad_paths = [
            "/requests?tenant_id=tenant-a&bogus=1",
            "/requests?tenant_id=tenant-a&status=accepted,accepted",
            "/requests?tenant_id=tenant-a&status=bogus",
            "/requests?tenant_id=tenant-a&status=",
            "/requests?tenant_id=tenant-a&status=accepted,",
            "/requests?tenant_id=tenant-a&limit=0",
            "/requests?tenant_id=tenant-a&limit=1001",
            "/requests?tenant_id=tenant-a&limit=abc",
            "/requests?tenant_id=tenant-a&limit=1.5",
            "/requests?tenant_id=tenant-a&limit=",
            "/requests?tenant_id=tenant-a&limit=1&limit=2",
            "/requests?tenant_id=tenant-a&status=accepted&status=failed",
            "/requests?tenant_id=tenant-a&created_from=not-a-time",
            "/requests?tenant_id=tenant-a&created_to=2026-10-02",
            "/requests?tenant_id=tenant-a&cursor=garbage",
            "/requests?tenant_id=tenant-a&cursor=",
            # Cursor replayed under another tenant or filter.
            f"/requests?tenant_id=tenant-b&cursor={cursor}",
            f"/requests?tenant_id=tenant-a&status=accepted&cursor={cursor}",
        ]
        for path in bad_paths:
            with self.subTest(path=path):
                status, _, data = self._request("GET", path)
                self.assertEqual(status, 400)
                self.assertEqual(data, b'{"error":"invalid_request"}\n')
                self.assertEqual(set(json.loads(data)), {"error"})

    def test_listing_missing_tenant_is_400(self):
        status, _, data = self._request("GET", "/requests")
        self.assertEqual(status, 400)
        self.assertEqual(data, b'{"error":"invalid_request"}\n')

    def test_collection_unsupported_methods_allow_get_and_post(self):
        for method in ("PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                status, headers, data = self._request(method, "/requests")
                self.assertEqual(status, 405)
                self.assertEqual(data, b'{"error":"method_not_allowed"}\n')
                self.assertEqual(headers.get("Allow"), "GET, POST")

    def test_listing_storage_fault_is_503(self):
        self._submit_many("tenant-a", 1)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DROP TABLE requests")
        status, _, data = self._request(
            "GET", "/requests", {"X-Tenant-Id": "tenant-a"}
        )
        self.assertEqual(status, 503)
        self.assertEqual(data, b'{"error":"storage_unavailable"}\n')
        self.assertEqual(set(json.loads(data)), {"error"})


class ListRequestsAuthTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "evidence.db")
        self.store = RequestStore(self.db_path)
        self.auth = AuthConfig([
            {"token": "tok-read-a", "tenant_id": "tenant-a",
             "roles": ["request:read"]},
            {"token": "tok-submit-a", "tenant_id": "tenant-a",
             "roles": ["request:submit"]},
            {"token": "tok-read-b", "tenant_id": "tenant-b",
             "roles": ["request:read"]},
        ])
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
            return resp.status, resp.read()
        finally:
            conn.close()

    def test_listing_requires_authentication(self):
        for headers in (
            {},
            {"Authorization": "Basic tok-read-a"},
            {"Authorization": "Bearer unknown"},
        ):
            with self.subTest(headers=headers):
                status, data = self._request(
                    "GET", "/requests?tenant_id=tenant-a", headers
                )
                self.assertEqual(status, 401)
                self.assertEqual(data, b'{"error":"unauthorized"}\n')

    def test_listing_requires_read_role(self):
        status, data = self._request(
            "GET",
            "/requests?tenant_id=tenant-a",
            {"Authorization": "Bearer tok-submit-a"},
        )
        self.assertEqual(status, 403)
        self.assertEqual(data, b'{"error":"forbidden"}\n')

    def test_listing_cross_tenant_is_forbidden(self):
        status, data = self._request(
            "GET",
            "/requests?tenant_id=tenant-b",
            {"Authorization": "Bearer tok-read-a"},
        )
        self.assertEqual(status, 403)
        self.assertEqual(data, b'{"error":"forbidden"}\n')

    def test_authorized_listing(self):
        self.store.submit("tenant-a", "subject-1", ["email"], "key-1")
        self.store.submit("tenant-b", "subject-2", ["email"], "key-2")
        status, data = self._request(
            "GET",
            "/requests?tenant_id=tenant-a",
            {"Authorization": "Bearer tok-read-a"},
        )
        self.assertEqual(status, 200)
        page = json.loads(data)
        self.assertEqual(len(page["items"]), 1)
        # The tenant header works as well.
        status, data = self._request(
            "GET",
            "/requests",
            {"Authorization": "Bearer tok-read-a", "X-Tenant-Id": "tenant-a"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(len(json.loads(data)["items"]), 1)


if __name__ == "__main__":
    unittest.main()
