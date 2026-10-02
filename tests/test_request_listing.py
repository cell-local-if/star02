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


class ServerFixture:
    def __init__(self, store, auth=None, host="127.0.0.1", port=0):
        self.server = build_server(store, host, port, auth=auth)
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


class RequestListingStorageTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "evidence.db")
        self.store = RequestStore(self.db_path)

    def tearDown(self):
        self._tmp.cleanup()

    def _submit(self, tenant="tenant-a", key=None, subject="subject-1"):
        key = key or f"key-{id(object())}"
        return self.store.submit(tenant, subject, ["email"], key)

    def _submit_many(self, tenant, count):
        return [
            self.store.submit(tenant, f"subject-{i}", ["email"], f"key-{i}")
            for i in range(count)
        ]

    # -- shape and ordering ---------------------------------------------

    def test_empty_tenant_has_empty_page(self):
        page = self.store.list_requests("tenant-a")
        self.assertEqual(set(page), {"items", "next_cursor"})
        self.assertEqual(page, {"items": [], "next_cursor": None})

    def test_items_carry_exactly_the_three_summary_fields(self):
        receipt = self._submit()
        page = self.store.list_requests("tenant-a")
        self.assertIsNone(page["next_cursor"])
        self.assertEqual(len(page["items"]), 1)
        item = page["items"][0]
        self.assertEqual(set(item), {"request_id", "status", "created_at"})
        self.assertEqual(item["request_id"], receipt["request_id"])
        self.assertEqual(item["status"], "accepted")
        self.assertEqual(item["created_at"], receipt["created_at"])

    def test_listing_is_tenant_scoped(self):
        self._submit_many("tenant-a", 2)
        self._submit_many("tenant-b", 3)
        self.assertEqual(len(self.store.list_requests("tenant-a")["items"]), 2)
        self.assertEqual(len(self.store.list_requests("tenant-b")["items"]), 3)

    def test_items_follow_acceptance_order(self):
        receipts = self._submit_many("tenant-a", 5)
        page = self.store.list_requests("tenant-a")
        keys = [(i["created_at"], i["request_id"]) for i in page["items"]]
        self.assertEqual(keys, sorted(keys))
        self.assertEqual(
            [i["request_id"] for i in page["items"]],
            [r["request_id"] for r in receipts],
        )

    def test_listing_reflects_current_status(self):
        first, second, _ = self._submit_many("tenant-a", 3)
        self.store.transition("tenant-a", first["request_id"], "processing")
        self.store.transition("tenant-a", second["request_id"], "processing")
        self.store.transition("tenant-a", second["request_id"], "completed")
        page = self.store.list_requests("tenant-a")
        self.assertEqual(
            [i["status"] for i in page["items"]],
            ["processing", "completed", "accepted"],
        )

    def test_listing_does_not_change_single_request_reads(self):
        receipt = self._submit()
        self.store.list_requests("tenant-a")
        self.assertEqual(self.store.get("tenant-a", receipt["request_id"]), receipt)
        self.assertEqual(
            self.store.get_status("tenant-a", receipt["request_id"]), receipt
        )

    # -- status filter ---------------------------------------------------

    def test_status_filter_selects_matching_requests(self):
        accepted, processing, completed = self._submit_many("tenant-a", 3)
        self.store.transition("tenant-a", processing["request_id"], "processing")
        self.store.transition("tenant-a", completed["request_id"], "processing")
        self.store.transition("tenant-a", completed["request_id"], "completed")
        page = self.store.list_requests("tenant-a", statuses=["accepted"])
        self.assertEqual(
            [i["request_id"] for i in page["items"]], [accepted["request_id"]]
        )
        page = self.store.list_requests(
            "tenant-a", statuses=["completed", "processing"]
        )
        self.assertEqual(
            {i["request_id"] for i in page["items"]},
            {processing["request_id"], completed["request_id"]},
        )
        page = self.store.list_requests("tenant-a", statuses=["failed"])
        self.assertEqual(page, {"items": [], "next_cursor": None})

    def test_status_filter_accepts_any_collection(self):
        self._submit()
        page = self.store.list_requests("tenant-a", statuses=("accepted",))
        self.assertEqual(len(page["items"]), 1)
        page = self.store.list_requests("tenant-a", statuses={"accepted"})
        self.assertEqual(len(page["items"]), 1)

    def test_invalid_status_filters_raise_fixed_value_error(self):
        for statuses in (
            ["unknown"],
            ["accepted", "unknown"],
            ["accepted", "accepted"],
            [],
            "accepted",
            b"accepted",
            {"accepted": True},
            [""],
            [None],
            42,
        ):
            with self.subTest(statuses=statuses):
                with self.assertRaises(ValueError) as caught:
                    self.store.list_requests("tenant-a", statuses=statuses)
                self.assertEqual(str(caught.exception), LISTING_ERROR)

    # -- created_at bounds -----------------------------------------------

    def test_created_from_is_inclusive_and_created_to_exclusive(self):
        first, second, third = self._submit_many("tenant-a", 3)
        lower = second["created_at"]
        upper = third["created_at"]
        page = self.store.list_requests("tenant-a", created_from=lower)
        self.assertEqual(
            [i["request_id"] for i in page["items"]],
            [second["request_id"], third["request_id"]],
        )
        page = self.store.list_requests("tenant-a", created_to=upper)
        self.assertEqual(
            [i["request_id"] for i in page["items"]],
            [first["request_id"], second["request_id"]],
        )
        page = self.store.list_requests(
            "tenant-a", created_from=lower, created_to=upper
        )
        self.assertEqual(
            [i["request_id"] for i in page["items"]], [second["request_id"]]
        )

    def test_timestamp_bounds_accept_any_rfc3339_utc_spelling(self):
        self._submit()
        for moment in (
            "2000-01-01T00:00:00Z",
            "2000-01-01T00:00:00.1Z",
            "2000-01-01T00:00:00.000001Z",
            "2000-01-01T00:00:00+00:00",
            "2000-01-01T00:00:00-00:00",
        ):
            with self.subTest(moment=moment):
                page = self.store.list_requests("tenant-a", created_from=moment)
                self.assertEqual(len(page["items"]), 1)

    def test_invalid_timestamp_bounds_raise_fixed_value_error(self):
        for bound in (
            "not-a-time",
            "2024-01-01",
            "2024-01-01 00:00:00Z",
            "2024-01-01T00:00:00",  # naive
            "2024-01-01T00:00:00+01:00",  # non-UTC offset
            "2024-13-01T00:00:00Z",  # impossible month
            "2024-01-32T00:00:00Z",  # impossible day
            "2024-01-01T00:00:60Z",  # impossible second
            "",
            0,
            None.__class__,
        ):
            with self.subTest(bound=bound):
                with self.assertRaises(ValueError) as caught:
                    self.store.list_requests("tenant-a", created_from=bound)
                self.assertEqual(str(caught.exception), LISTING_ERROR)
                with self.assertRaises(ValueError) as caught:
                    self.store.list_requests("tenant-a", created_to=bound)
                self.assertEqual(str(caught.exception), LISTING_ERROR)

    # -- limit -------------------------------------------------------------

    def test_limit_defaults_to_100(self):
        self._submit_many("tenant-a", 3)
        page = self.store.list_requests("tenant-a")
        self.assertEqual(len(page["items"]), 3)

    def test_limit_bounds_are_enforced(self):
        self._submit_many("tenant-a", 2)
        for limit in (1, 1000):
            page = self.store.list_requests("tenant-a", limit=limit)
            self.assertLessEqual(len(page["items"]), limit)
        for limit in (0, -1, 1001, True, False, "5", 1.5, None.__class__):
            with self.subTest(limit=limit):
                with self.assertRaises(ValueError) as caught:
                    self.store.list_requests("tenant-a", limit=limit)
                self.assertEqual(str(caught.exception), LISTING_ERROR)

    # -- pagination --------------------------------------------------------

    def test_pagination_walks_the_whole_listing_once(self):
        receipts = self._submit_many("tenant-a", 5)
        seen = []
        cursor = None
        pages = 0
        while True:
            page = self.store.list_requests("tenant-a", cursor=cursor, limit=2)
            seen.extend(item["request_id"] for item in page["items"])
            cursor = page["next_cursor"]
            pages += 1
            if cursor is None:
                break
        self.assertEqual(pages, 3)
        self.assertEqual(seen, [r["request_id"] for r in receipts])

    def test_cursor_continues_strictly_after_the_last_item(self):
        first, second, _ = self._submit_many("tenant-a", 3)
        page = self.store.list_requests("tenant-a", limit=2)
        self.assertEqual(
            [i["request_id"] for i in page["items"]],
            [first["request_id"], second["request_id"]],
        )
        rest = self.store.list_requests("tenant-a", cursor=page["next_cursor"])
        self.assertNotIn(first["request_id"], [i["request_id"] for i in rest["items"]])
        self.assertNotIn(
            second["request_id"], [i["request_id"] for i in rest["items"]]
        )

    def test_cursor_is_rejected_across_tenants(self):
        self._submit_many("tenant-a", 3)
        self._submit_many("tenant-b", 3)
        page = self.store.list_requests("tenant-a", limit=1)
        with self.assertRaises(ValueError) as caught:
            self.store.list_requests("tenant-b", cursor=page["next_cursor"])
        self.assertEqual(str(caught.exception), LISTING_ERROR)

    def test_cursor_is_rejected_across_filters(self):
        self._submit_many("tenant-a", 3)
        page = self.store.list_requests("tenant-a", limit=1)
        for changed in (
            {"statuses": ["accepted"]},
            {"created_from": "2000-01-01T00:00:00Z"},
            {"created_to": "2999-01-01T00:00:00Z"},
            {"statuses": ["accepted", "processing"]},
        ):
            with self.subTest(changed=changed):
                with self.assertRaises(ValueError) as caught:
                    self.store.list_requests(
                        "tenant-a", cursor=page["next_cursor"], **changed
                    )
                self.assertEqual(str(caught.exception), LISTING_ERROR)

    def test_cursor_survives_equivalent_filter_spelling(self):
        self._submit_many("tenant-a", 3)
        page = self.store.list_requests(
            "tenant-a", statuses=["processing", "accepted"], limit=1
        )
        # Same normalised filter in a different spelling keeps the cursor.
        rest = self.store.list_requests(
            "tenant-a",
            statuses=("accepted", "processing"),
            cursor=page["next_cursor"],
        )
        self.assertEqual(len(rest["items"]), 2)

    def test_malformed_cursors_raise_fixed_value_error(self):
        self._submit()
        for cursor in (
            "",
            "garbage",
            "rl1.",
            "rl1.!!!",
            "rl1." + "A" * 5,
            "rc1." + "A" * 8,  # foreign cursor family
            42,
            b"rl1.",
            ["rl1."],
        ):
            with self.subTest(cursor=cursor):
                with self.assertRaises(ValueError) as caught:
                    self.store.list_requests("tenant-a", cursor=cursor)
                self.assertEqual(str(caught.exception), LISTING_ERROR)

    def test_empty_tenant_raises_fixed_value_error(self):
        for tenant in ("", None, 42, ["tenant-a"]):
            with self.subTest(tenant=tenant):
                with self.assertRaises(ValueError) as caught:
                    self.store.list_requests(tenant)
                self.assertEqual(str(caught.exception), LISTING_ERROR)

    # -- persistence and failure ------------------------------------------

    def test_pagination_and_cursors_survive_a_store_rebuild(self):
        receipts = self._submit_many("tenant-a", 5)
        first_store_page = self.store.list_requests("tenant-a", limit=2)
        rebuilt = RequestStore(self.db_path)
        page = rebuilt.list_requests("tenant-a", limit=2)
        self.assertEqual(page, first_store_page)
        rest = rebuilt.list_requests(
            "tenant-a", cursor=first_store_page["next_cursor"], limit=2
        )
        self.assertEqual(
            [i["request_id"] for i in rest["items"]],
            [r["request_id"] for r in receipts[2:4]],
        )
        final = rebuilt.list_requests(
            "tenant-a", cursor=rest["next_cursor"], limit=2
        )
        self.assertEqual(
            [i["request_id"] for i in final["items"]],
            [receipts[4]["request_id"]],
        )
        self.assertIsNone(final["next_cursor"])

    def test_corrupt_record_raises_fixed_os_error(self):
        self._submit()
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute("UPDATE requests SET status = 'bogus'")
            conn.commit()
        finally:
            conn.close()
        with self.assertRaises(OSError) as caught:
            self.store.list_requests("tenant-a")
        self.assertEqual(str(caught.exception), LISTING_ERROR)

    def test_corrupt_created_at_raises_fixed_os_error(self):
        self._submit()
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute("UPDATE requests SET created_at = 'garbage'")
            conn.commit()
        finally:
            conn.close()
        with self.assertRaises(OSError) as caught:
            self.store.list_requests("tenant-a")
        self.assertEqual(str(caught.exception), LISTING_ERROR)

    def test_storage_fault_raises_fixed_os_error(self):
        self._submit()
        with open(self.db_path, "r+b") as handle:
            handle.seek(64)
            handle.write(b"\xff" * 256)
        with self.assertRaises(OSError) as caught:
            self.store.list_requests("tenant-a")
        self.assertEqual(str(caught.exception), LISTING_ERROR)


class RequestListingHttpTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "evidence.db")
        self.store = RequestStore(self.db_path)
        self._fixture = ServerFixture(self.store)
        self._fixture.__enter__()
        self.port = self._fixture.port

    def tearDown(self):
        self._fixture.__exit__(None, None, None)
        self._tmp.cleanup()

    def _request(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request(
                method,
                path,
                body=json.dumps(body) if body is not None else None,
                headers=headers or {},
            )
            resp = conn.getresponse()
            data = resp.read()
            return resp.status, dict(resp.getheaders()), data
        finally:
            conn.close()

    def _submit(self, tenant="tenant-a", key=None, subject="subject-1"):
        key = key or f"key-{id(object())}"
        status, _, data = self._request(
            "POST",
            "/requests",
            body={
                "tenant_id": tenant,
                "subject_id": subject,
                "idempotency_key": key,
                "scopes": ["email"],
            },
        )
        self.assertEqual(status, 200)
        return json.loads(data)

    def _list(self, query="", tenant="tenant-a"):
        path = "/requests" + (f"?{query}" if query else "")
        return self._request("GET", path, headers={"X-Tenant-Id": tenant})

    # -- happy path --------------------------------------------------------

    def test_listing_response_shape(self):
        receipt = self._submit()
        status, _, data = self._list()
        self.assertEqual(status, 200)
        self.assertTrue(data.endswith(b"\n") and b"\n" not in data[:-1])
        page = json.loads(data)
        self.assertEqual(set(page), {"items", "next_cursor"})
        self.assertIsNone(page["next_cursor"])
        self.assertEqual(len(page["items"]), 1)
        item = page["items"][0]
        self.assertEqual(set(item), {"request_id", "status", "created_at"})
        self.assertEqual(item["request_id"], receipt["request_id"])

    def test_listing_never_exposes_request_payload(self):
        self._submit(subject="subject-secret")
        status, _, data = self._list()
        self.assertEqual(status, 200)
        for forbidden in (b"subject", b"scope", b"idempotency", b"email"):
            self.assertNotIn(forbidden, data)

    def test_tenant_id_query_parameter_selects_the_tenant(self):
        self._submit(tenant="tenant-a")
        status, _, data = self._request("GET", "/requests?tenant_id=tenant-a")
        self.assertEqual(status, 200)
        self.assertEqual(len(json.loads(data)["items"]), 1)
        status, _, data = self._request("GET", "/requests?tenant_id=tenant-b")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)["items"], [])

    def test_status_created_and_limit_filters(self):
        first = self._submit(key="k1")
        second = self._submit(key="k2")
        self.store.transition("tenant-a", second["request_id"], "processing")
        status, _, data = self._list("status=processing")
        page = json.loads(data)
        self.assertEqual(
            [i["request_id"] for i in page["items"]], [second["request_id"]]
        )
        status, _, data = self._list("status=accepted,processing")
        self.assertEqual(len(json.loads(data)["items"]), 2)
        status, _, data = self._list(
            f"created_from={first['created_at']}&created_to={second['created_at']}"
        )
        page = json.loads(data)
        self.assertEqual(
            [i["request_id"] for i in page["items"]], [first["request_id"]]
        )
        status, _, data = self._list("limit=1")
        page = json.loads(data)
        self.assertEqual(len(page["items"]), 1)
        self.assertIsNotNone(page["next_cursor"])

    def test_pagination_over_http(self):
        receipts = [self._submit(key=f"k{i}") for i in range(5)]
        seen = []
        cursor = None
        for _ in range(4):
            query = "limit=2" + (f"&cursor={cursor}" if cursor else "")
            status, _, data = self._list(query)
            self.assertEqual(status, 200)
            page = json.loads(data)
            seen.extend(i["request_id"] for i in page["items"])
            cursor = page["next_cursor"]
            if cursor is None:
                break
        self.assertIsNone(cursor)
        self.assertEqual(seen, [r["request_id"] for r in receipts])

    def test_pagination_is_stable_across_a_server_rebuild(self):
        for i in range(3):
            self._submit(key=f"k{i}")
        status, _, first_data = self._list("limit=2")
        self.assertEqual(status, 200)
        cursor = json.loads(first_data)["next_cursor"]
        self._fixture.__exit__(None, None, None)
        self.store = RequestStore(self.db_path)
        self._fixture = ServerFixture(self.store)
        self._fixture.__enter__()
        self.port = self._fixture.port
        status, _, data = self._list("limit=2")
        self.assertEqual(status, 200)
        self.assertEqual(data, first_data)
        status, _, data = self._list(f"limit=2&cursor={cursor}")
        self.assertEqual(status, 200)
        page = json.loads(data)
        self.assertEqual(len(page["items"]), 1)
        self.assertIsNone(page["next_cursor"])

    # -- 400 invalid query ---------------------------------------------------

    def test_invalid_queries_are_400(self):
        self._submit()
        bad_queries = [
            "status=bogus",
            "status=accepted,accepted",
            "status=",
            "status=accepted,",
            "unknown=1",
            "limit=0",
            "limit=1001",
            "limit=abc",
            "limit=1.5",
            "limit=",
            "limit=1&limit=2",
            "status=accepted&status=failed",
            "tenant_id=tenant-a&tenant_id=tenant-a",
            "cursor=garbage",
            "cursor=",
            "created_from=nope",
            "created_to=2024-01-01",
            "created_from=2024-01-01T00:00:00%2B01:00",
        ]
        for query in bad_queries:
            with self.subTest(query=query):
                status, _, data = self._list(query)
                self.assertEqual(status, 400)
                self.assertEqual(data, b'{"error":"invalid_request"}\n')
                self.assertEqual(set(json.loads(data)), {"error"})

    def test_missing_tenant_is_400(self):
        status, _, data = self._request("GET", "/requests")
        self.assertEqual(status, 400)
        self.assertEqual(data, b'{"error":"invalid_request"}\n')

    def test_cross_tenant_cursor_is_400(self):
        self._submit(tenant="tenant-a", key="k1")
        self._submit(tenant="tenant-a", key="k2")
        status, _, data = self._list("limit=1")
        cursor = json.loads(data)["next_cursor"]
        status, _, data = self._list(f"cursor={cursor}", tenant="tenant-b")
        self.assertEqual(status, 400)
        self.assertEqual(data, b'{"error":"invalid_request"}\n')

    # -- routing compatibility ----------------------------------------------

    def test_unknown_path_is_still_404(self):
        status, _, data = self._request("GET", "/nope")
        self.assertEqual(status, 404)
        self.assertEqual(data, b'{"error":"not_found"}\n')

    def test_unsupported_methods_on_collection_are_405(self):
        for method in ("PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                status, headers, data = self._request(method, "/requests")
                self.assertEqual(status, 405)
                self.assertEqual(data, b'{"error":"method_not_allowed"}\n')
                self.assertEqual(headers.get("Allow"), "GET, POST")

    def test_existing_endpoints_keep_working(self):
        receipt = self._submit()
        request_id = receipt["request_id"]
        status, _, data = self._request(
            "GET", f"/requests/{request_id}", headers={"X-Tenant-Id": "tenant-a"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data), receipt)
        status, _, data = self._request(
            "GET",
            f"/requests/{request_id}/status",
            headers={"X-Tenant-Id": "tenant-a"},
        )
        self.assertEqual(status, 200)
        status, _, data = self._request(
            "GET",
            f"/requests/{request_id}/execution-log",
            headers={"X-Tenant-Id": "tenant-a"},
        )
        self.assertEqual(status, 200)

    # -- 503 -----------------------------------------------------------------

    def test_storage_fault_is_503(self):
        self._submit()
        with open(self.db_path, "r+b") as handle:
            handle.seek(64)
            handle.write(b"\xff" * 256)
        status, _, data = self._list()
        self.assertEqual(status, 503)
        self.assertEqual(data, b'{"error":"storage_unavailable"}\n')


class RequestListingAuthTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "evidence.db")
        self.store = RequestStore(self.db_path)
        self.auth = AuthConfig(
            [
                {"token": "read-a", "tenant_id": "tenant-a",
                 "roles": ["request:read"]},
                {"token": "submit-a", "tenant_id": "tenant-a",
                 "roles": ["request:submit"]},
                {"token": "read-b", "tenant_id": "tenant-b",
                 "roles": ["request:read"]},
            ]
        )
        self._fixture = ServerFixture(self.store, auth=self.auth)
        self._fixture.__enter__()
        self.port = self._fixture.port

    def tearDown(self):
        self._fixture.__exit__(None, None, None)
        self._tmp.cleanup()

    def _get(self, path, token=None):
        headers = {}
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request("GET", path, headers=headers)
            resp = conn.getresponse()
            return resp.status, resp.read()
        finally:
            conn.close()

    def _submit(self, tenant="tenant-a", key="k1"):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request(
                "POST",
                "/requests",
                body=json.dumps(
                    {
                        "tenant_id": tenant,
                        "subject_id": "subject-1",
                        "idempotency_key": key,
                        "scopes": ["email"],
                    }
                ),
                headers={"Authorization": "Bearer submit-a"},
            )
            resp = conn.getresponse()
            self.assertEqual(resp.status, 200)
            return json.loads(resp.read())
        finally:
            conn.close()

    def test_missing_or_malformed_token_is_401(self):
        for headers_token in (None, "", "unknown"):
            with self.subTest(token=headers_token):
                status, data = self._get(
                    "/requests?tenant_id=tenant-a", token=headers_token
                )
                self.assertEqual(status, 401)
                self.assertEqual(data, b'{"error":"unauthorized"}\n')

    def test_submit_only_principal_is_403(self):
        status, data = self._get("/requests?tenant_id=tenant-a", token="submit-a")
        self.assertEqual(status, 403)
        self.assertEqual(data, b'{"error":"forbidden"}\n')

    def test_cross_tenant_principal_is_403(self):
        status, data = self._get("/requests?tenant_id=tenant-a", token="read-b")
        self.assertEqual(status, 403)
        self.assertEqual(data, b'{"error":"forbidden"}\n')

    def test_read_principal_lists_own_tenant(self):
        self._submit()
        status, data = self._get("/requests?tenant_id=tenant-a", token="read-a")
        self.assertEqual(status, 200)
        page = json.loads(data)
        self.assertEqual(len(page["items"]), 1)
        status, data = self._get("/requests?tenant_id=tenant-b", token="read-b")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)["items"], [])


if __name__ == "__main__":
    unittest.main()
