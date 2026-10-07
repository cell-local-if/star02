"""Tests for the read-only GET /requests/{request_id}/audit-timeline.

The endpoint exposes the request's status-event history in occurrence
order from one committed snapshot, rendered only when that history is
whole: shape, ordering, tenant resolution, method and query gates,
authentication, the read-only guarantee and every corruption ->
503 mapping are all covered.
"""

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

TIMESTAMP_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$"
)
STATUSES = {"accepted", "processing", "completed", "failed"}
EDGES = {
    "accepted": {"processing", "failed"},
    "processing": {"completed", "failed"},
}


class _Server:
    def __init__(self, store, auth=None, host="127.0.0.1", port=0):
        self.server = build_server(store, host, port, auth)
        self.thread = threading.Thread(
            target=self.server.serve_forever, daemon=True
        )

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


class AuditTimelineEndpointTests(unittest.TestCase):
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
            "GET", path,
            headers={"X-Tenant-Id": tenant} if tenant else {},
        )

    def _timeline(self, rid, tenant="tenant-a"):
        return self._get(f"/requests/{rid}/audit-timeline", tenant)

    def _lifecycle(self, statuses=("processing", "completed"), key="key-1"):
        receipt = self.store.submit("tenant-a", "subject-1", ["email"], key)
        rid = receipt["request_id"]
        for target in statuses:
            self.store.transition("tenant-a", rid, target)
        return receipt

    def _raw(self):
        return sqlite3.connect(self.db_path)

    def _tamper(self, sql, params=()):
        with self._raw() as conn:
            conn.execute(sql, params)

    def _assert_well_formed(self, data, rid):
        self.assertTrue(data.endswith(b"\n"))
        self.assertEqual(data.count(b"\n"), 1)
        self.assertTrue(data.startswith(b'{"request_id":"'), data)
        record = json.loads(data)
        self.assertEqual(list(record), ["request_id", "events"])
        self.assertEqual(set(record), {"request_id", "events"})
        self.assertEqual(record["request_id"], rid)
        self.assertEqual(
            data,
            (json.dumps(record, separators=(",", ":")) + "\n").encode(),
        )
        return record

    # -- success shape -----------------------------------------------

    def test_accepted_request_timeline_shape(self):
        receipt = self._lifecycle(())
        rid = receipt["request_id"]
        status, headers, data = self._timeline(rid)
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("Content-Type"), "application/json")
        record = self._assert_well_formed(data, rid)
        events = record["events"]
        self.assertEqual(len(events), 1)
        self.assertEqual(
            events[0],
            {"status": "accepted", "occurred_at": receipt["created_at"]},
        )
        self.assertEqual(list(events[0]), ["status", "occurred_at"])
        # No subject, scope, idempotency key or claim detail leaks.
        self.assertNotIn(b"subject-1", data)
        self.assertNotIn(b"email", data)
        self.assertNotIn(b"key-1", data)
        self.assertNotIn(b"attempt", data)
        self.assertNotIn(b"tombstone", data)
        self.assertNotIn(b"receipt", data)
        self.assertNotIn(b"worker", data)
        self.assertNotIn(b"token", data)

    def test_full_lifecycle_order_fields_and_domains(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        status, _, data = self._timeline(rid)
        self.assertEqual(status, 200)
        record = self._assert_well_formed(data, rid)
        statuses = [e["status"] for e in record["events"]]
        self.assertEqual(statuses, ["accepted", "processing", "completed"])
        for index, event in enumerate(record["events"]):
            self.assertEqual(set(event), {"status", "occurred_at"})
            self.assertIn(event["status"], STATUSES)
            self.assertTrue(TIMESTAMP_RE.match(event["occurred_at"]))
            if index:
                self.assertIn(event["status"], EDGES[statuses[index - 1]])
        stamps = [e["occurred_at"] for e in record["events"]]
        self.assertEqual(stamps, sorted(stamps))
        # The final event is the current persisted status.
        self.assertEqual(
            record["events"][-1]["status"],
            self.store.get_status("tenant-a", rid)["status"],
        )

    def test_failed_lifecycle_timeline(self):
        receipt = self._lifecycle(("failed",))
        status, _, data = self._timeline(receipt["request_id"])
        self.assertEqual(status, 200)
        record = json.loads(data)
        self.assertEqual([e["status"] for e in record["events"]],
                         ["accepted", "failed"])

    def test_idempotent_replays_append_no_event(self):
        receipt = self._lifecycle(
            ("accepted", "processing", "processing",
             "completed", "completed")
        )
        _, _, data = self._timeline(receipt["request_id"])
        self.assertEqual(
            [e["status"] for e in json.loads(data)["events"]],
            ["accepted", "processing", "completed"],
        )

    def test_repeated_reads_are_byte_identical(self):
        receipt = self._lifecycle()
        _, _, first = self._timeline(receipt["request_id"])
        for _ in range(4):
            _, _, again = self._timeline(receipt["request_id"])
            self.assertEqual(again, first)

    def test_timeline_stable_across_restart(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        _, _, first = self._timeline(rid)
        self._fixture.__exit__(None, None, None)
        rebuilt = RequestStore(self.db_path)
        with _Server(rebuilt) as fixture:
            conn = http.client.HTTPConnection(
                "127.0.0.1", fixture.port, timeout=10
            )
            try:
                conn.request(
                    "GET", f"/requests/{rid}/audit-timeline",
                    headers={"X-Tenant-Id": "tenant-a"},
                )
                resp = conn.getresponse()
                status, second = resp.status, resp.read()
            finally:
                conn.close()
        self.assertEqual(status, 200)
        self.assertEqual(second, first)

    # -- tenant location ---------------------------------------------

    def test_tenant_query_parameter_and_header_precedence(self):
        receipt = self._lifecycle(())
        rid = receipt["request_id"]
        status, _, data = self._request(
            "GET", f"/requests/{rid}/audit-timeline?tenant_id=tenant-a"
        )
        self.assertEqual(status, 200)
        self._assert_well_formed(data, rid)
        # The last value still names a single tenant only when the key
        # appears once; a duplicated key is rejected by the query
        # gate (covered separately).
        # A non-empty header overrides the query string.
        status, _, data = self._request(
            "GET", f"/requests/{rid}/audit-timeline?tenant_id=tenant-a",
            headers={"X-Tenant-Id": "tenant-b"},
        )
        self.assertEqual((status, data), (404, NOT_FOUND))

    def test_uppercase_uuid_canonicalises(self):
        receipt = self._lifecycle(())
        _, _, lower = self._timeline(receipt["request_id"])
        status, _, upper = self._get(
            f"/requests/{receipt['request_id'].upper()}/audit-timeline"
        )
        self.assertEqual(status, 200)
        self.assertEqual(upper, lower)

    # -- query / tenant validation ------------------------------------

    def test_unknown_or_duplicated_params_are_400(self):
        receipt = self._lifecycle(())
        rid = receipt["request_id"]
        for query in (
            "cursor=abc",
            "limit=10",
            "status=accepted",
            "tenant_id=tenant-a&x=1",
            "tenant_id=tenant-a&tenant_id=tenant-a",
            "tenant_id=",
            "tenant_id=%20%20",
        ):
            with self.subTest(query=query):
                status, _, data = self._request(
                    "GET", f"/requests/{rid}/audit-timeline?{query}"
                )
                self.assertEqual((status, data), (400, INVALID_REQUEST))

    def test_missing_or_blank_tenant_is_400(self):
        receipt = self._lifecycle(())
        rid = receipt["request_id"]
        for headers in (
            {},
            {"X-Tenant-Id": ""},
            {"X-Tenant-Id": "   "},
        ):
            with self.subTest(headers=headers):
                status, _, data = self._request(
                    "GET", f"/requests/{rid}/audit-timeline",
                    headers=headers,
                )
                self.assertEqual((status, data), (400, INVALID_REQUEST))

    # -- 404 / 405 --------------------------------------------------

    def test_malformed_unknown_cross_tenant_ids_are_404(self):
        receipt = self._lifecycle(())
        rid = receipt["request_id"]
        unknown = "00000000-0000-4000-8000-000000000000"
        for path, tenant in (
            ("/requests/not-a-uuid/audit-timeline", "tenant-a"),
            (f"/requests/{unknown}/audit-timeline", "tenant-a"),
            (f"/requests/{rid}/audit-timeline", "tenant-b"),
            (f"/requests/{rid}/audit-timeline?tenant_id=tenant-b", None),
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
            f"/requests/{rid}/audit-timeline/",
            f"/requests/{rid}/audit-timeline/extra",
            "/requests//audit-timeline",
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
                    method, f"/requests/{rid}/audit-timeline",
                    body={} if method == "POST" else None,
                )
                self.assertEqual(status, 405)
                self.assertEqual(data, METHOD_NOT_ALLOWED)
                self.assertEqual(headers.get("Allow"), "GET")
        # HEAD answers 405 with headers but no body.
        status, headers, data = self._request(
            "HEAD", f"/requests/{rid}/audit-timeline"
        )
        self.assertEqual(status, 405)
        self.assertEqual(headers.get("Allow"), "GET")
        self.assertEqual(data, b"")

    # -- storage failure and corruption -------------------------------

    def test_corrupt_database_is_503(self):
        receipt = self._lifecycle(())
        with open(self.db_path, "wb") as handle:
            handle.write(b"not a sqlite database")
        status, _, data = self._timeline(receipt["request_id"])
        self.assertEqual((status, data), (503, STORAGE_UNAVAILABLE))
        self.assertEqual(set(json.loads(data)), {"error"})

    def _assert_storage_unavailable(self, rid):
        status, _, data = self._timeline(rid)
        self.assertEqual((status, data), (503, STORAGE_UNAVAILABLE))
        self.assertEqual(set(json.loads(data)), {"error"})

    def test_deleted_event_is_503(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        self._tamper(
            "DELETE FROM status_events WHERE request_id = ? AND seq = 0",
            (rid,),
        )
        self._assert_storage_unavailable(rid)

    def test_all_events_deleted_is_503(self):
        receipt = self._lifecycle(())
        rid = receipt["request_id"]
        self._tamper(
            "DELETE FROM status_events WHERE request_id = ?", (rid,)
        )
        self._assert_storage_unavailable(rid)

    def test_altered_event_status_is_503(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        self._tamper(
            "UPDATE status_events SET status = 'failed' "
            "WHERE request_id = ? AND seq = 1",
            (rid,),
        )
        self._assert_storage_unavailable(rid)

    def test_rewound_timestamp_is_503(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        self._tamper(
            "UPDATE status_events SET occurred_at = "
            "'2000-01-01T00:00:00.000000Z' "
            "WHERE request_id = ? AND seq = 1",
            (rid,),
        )
        self._assert_storage_unavailable(rid)

    def test_replaced_head_is_503(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        self._tamper(
            "UPDATE requests SET chain_hash = ? WHERE request_id = ?",
            ("a" * 64, rid),
        )
        self._assert_storage_unavailable(rid)

    def test_split_current_status_is_503(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        self._tamper(
            "UPDATE requests SET status = 'failed' WHERE request_id = ?",
            (rid,),
        )
        self._assert_storage_unavailable(rid)

    # -- read-only ---------------------------------------------------

    def test_timeline_read_never_writes(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        with open(self.db_path, "rb") as handle:
            before = handle.read()
        for _ in range(5):
            status, _, _ = self._timeline(rid)
            self.assertEqual(status, 200)
        with open(self.db_path, "rb") as handle:
            after = handle.read()
        self.assertEqual(before, after)
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
                    "SELECT count(*) FROM deletion_tombstones "
                    "WHERE request_id = ?",
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
            self.assertEqual(
                conn.execute(
                    "SELECT count(*) FROM status_events WHERE request_id = ?",
                    (rid,),
                ).fetchone()[0],
                3,
            )

    # -- snapshot consistency under concurrent writes -------------------

    def test_never_a_torn_timeline_under_concurrent_transitions(self):
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
            # Each response is internally self-consistent: the store
            # only renders a snapshot whose final event equals that same
            # snapshot's current status (and answers 503 otherwise,
            # covered separately). Comparing against a separate
            # get_status while writers move would compare two
            # different committed snapshots, so that cross-check happens
            # only after the writers finish.
            status, _, data = self._timeline(rid)
            self.assertEqual(status, 200)
            record = json.loads(data)
            self.assertEqual(list(record), ["request_id", "events"])
            statuses = [e["status"] for e in record["events"]]
            self.assertEqual(statuses[0], "accepted")
            for previous, current in zip(statuses, statuses[1:]):
                self.assertIn(current, EDGES.get(previous, set()))
            stamps = [e["occurred_at"] for e in record["events"]]
            self.assertEqual(stamps, sorted(stamps))

        with ThreadPoolExecutor(max_workers=8) as pool:
            movers = [pool.submit(move) for _ in range(4)]
            readers = [
                pool.submit(read) for _ in range(4) for _ in range(25)
            ]
            for future in movers + readers:
                future.result()
        status, _, data = self._timeline(rid)
        self.assertEqual(status, 200)
        self.assertEqual(
            json.loads(data)["events"][-1]["status"],
            self.store.get_status("tenant-a", rid)["status"],
        )


SUBMIT_A = {"token": "tok-submit-a", "tenant_id": "tenant-a",
            "roles": ["request:submit"]}
READ_A = {"token": "tok-read-a", "tenant_id": "tenant-a",
          "roles": ["request:read"]}
READ_B = {"token": "tok-read-b", "tenant_id": "tenant-b",
          "roles": ["request:read"]}
RECONCILE_A = {"token": "tok-reconcile-a", "tenant_id": "tenant-a",
               "roles": ["request:reconcile"]}


class AuditTimelineAuthTests(unittest.TestCase):
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

    def _path(self):
        return f"/requests/{self.rid}/audit-timeline"

    def test_missing_malformed_or_unknown_token_is_401(self):
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

    def test_wrong_role_is_403(self):
        for token in ("tok-submit-a", "tok-reconcile-a"):
            with self.subTest(token=token):
                status, _, data = self._request(
                    "GET", self._path(),
                    headers={**self._bearer(token),
                             "X-Tenant-Id": "tenant-a"},
                )
                self.assertEqual((status, data), (403, FORBIDDEN))

    def test_tenant_mismatch_is_403_before_id_validation(self):
        for path in (
            self._path(),
            "/requests/not-a-uuid/audit-timeline",
        ):
            with self.subTest(path=path):
                status, _, data = self._request(
                    "GET", path,
                    headers={**self._bearer("tok-read-a"),
                             "X-Tenant-Id": "tenant-b"},
                )
                self.assertEqual((status, data), (403, FORBIDDEN))
        status, _, data = self._request(
            "GET", f"{self._path()}?tenant_id=tenant-b",
            headers=self._bearer("tok-read-a"),
        )
        self.assertEqual((status, data), (403, FORBIDDEN))

    def test_missing_tenant_with_valid_token_is_400(self):
        status, _, data = self._request(
            "GET", self._path(), headers=self._bearer("tok-read-a")
        )
        self.assertEqual((status, data), (400, INVALID_REQUEST))

    def test_authorized_read_succeeds(self):
        status, _, data = self._request(
            "GET", self._path(),
            headers={**self._bearer("tok-read-a"),
                     "X-Tenant-Id": "tenant-a"},
        )
        self.assertEqual(status, 200)
        record = json.loads(data)
        self.assertEqual(record["request_id"], self.rid)
        self.assertEqual(record["events"][0]["status"], "accepted")

    def test_cross_tenant_record_is_404_with_matching_token(self):
        status, _, data = self._request(
            "GET", self._path(),
            headers={**self._bearer("tok-read-b"),
                     "X-Tenant-Id": "tenant-b"},
        )
        self.assertEqual((status, data), (404, NOT_FOUND))

    def test_method_check_precedes_authentication(self):
        status, _, data = self._request("PUT", self._path())
        self.assertEqual((status, data), (405, METHOD_NOT_ALLOWED))


class BrokenTimelineStoreTests(unittest.TestCase):
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
        secret = "SECRET-SQL-DETAIL-PATH-WORKER"

        class BrokenStore:
            def get_audit_timeline(self, *a, **k):
                raise RuntimeError(secret)

        fixture = self._serve(BrokenStore())
        try:
            rid = "00000000-0000-4000-8000-000000000000"
            status, data = self._get(
                fixture.port, f"/requests/{rid}/audit-timeline"
            )
            self.assertEqual(status, 503)
            self.assertEqual(data, STORAGE_UNAVAILABLE)
            self.assertNotIn(b"SECRET", data)
        finally:
            fixture.__exit__(None, None, None)

    def test_extra_or_malformed_fields_become_503(self):
        rid = "00000000-0000-4000-8000-000000000000"
        ts = "2026-01-01T00:00:00.000000Z"
        ts2 = "2026-01-02T00:00:00.000000Z"
        good = {"status": "accepted", "occurred_at": ts}
        cases = (
            # Extra top-level key / sensitive field.
            {"request_id": rid, "events": [good],
             "subject_id": "subject-SECRET"},
            # Empty timeline.
            {"request_id": rid, "events": []},
            # First event is not the acceptance event.
            {"request_id": rid,
             "events": [{"status": "processing", "occurred_at": ts}]},
            # Event carries an extra field.
            {"request_id": rid, "events": [
                {"status": "accepted", "occurred_at": ts,
                 "claim_token": "SECRET"}]},
            # Unknown status.
            {"request_id": rid,
             "events": [{"status": "cancelled", "occurred_at": ts}]},
            # Malformed timestamp.
            {"request_id": rid,
             "events": [{"status": "accepted", "occurred_at": "soon"}]},
            # Illegal edge (accepted -> completed).
            {"request_id": rid, "events": [
                {"status": "accepted", "occurred_at": ts},
                {"status": "completed", "occurred_at": ts2}]},
            # Repeated current status.
            {"request_id": rid, "events": [
                {"status": "accepted", "occurred_at": ts},
                {"status": "processing", "occurred_at": ts},
                {"status": "processing", "occurred_at": ts2}]},
            # Backwards occurrence time.
            {"request_id": rid, "events": [
                {"status": "accepted", "occurred_at": ts2},
                {"status": "processing", "occurred_at": ts}]},
            # Wrong request id.
            {"request_id": "not-a-uuid", "events": [good]},
            # Wrong types.
            {"request_id": rid, "events": "accepted"},
        )

        class Store:
            def __init__(self, timeline):
                self._timeline = timeline

            def get_audit_timeline(self, *a, **k):
                return self._timeline

        for timeline in cases:
            with self.subTest(timeline=timeline):
                fixture = self._serve(Store(timeline))
                try:
                    status, data = self._get(
                        fixture.port, f"/requests/{rid}/audit-timeline"
                    )
                    self.assertEqual(status, 503)
                    self.assertEqual(data, STORAGE_UNAVAILABLE)
                    self.assertNotIn(b"SECRET", data)
                finally:
                    fixture.__exit__(None, None, None)


if __name__ == "__main__":
    unittest.main()
