"""Tests for the read-only request status timeline HTTP endpoint.

Covers ``GET /requests/{request_id}/audit-timeline`` and the backing
``RequestStore.get_status_timeline`` read: the compact fixed-shape body,
occurrence ordering, acceptance-first and change-only history, the
UTC/non-regressing timestamp guarantees, read-only and restart-stable
behaviour, the tenant/query/method/auth error ordering, the 503 outcome
for every unreadable or inconsistent history, and the no-leak
guarantees (no subject, scope, idempotency key, token, claim
credential, worker, SQL text or path).
"""

import http.client
import json
import os
import re
import sqlite3
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from forgetting_evidence.httpapi import AuthConfig, build_server
from forgetting_evidence.requests import RequestNotFound, RequestStore

NOT_FOUND = b'{"error":"not_found"}\n'
INVALID_REQUEST = b'{"error":"invalid_request"}\n'
METHOD_NOT_ALLOWED = b'{"error":"method_not_allowed"}\n'
STORAGE_UNAVAILABLE = b'{"error":"storage_unavailable"}\n'
UNAUTHORIZED = b'{"error":"unauthorized"}\n'
FORBIDDEN = b'{"error":"forbidden"}\n'

# The canonical UTC shape the store writes: six fractional digits and Z.
UTC_RFC3339 = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
FIELDS = ["request_id", "events"]
EVENT_FIELDS = ["status", "occurred_at"]
STATUSES = {"accepted", "processing", "completed", "failed"}


def _parse_utc(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


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


class TimelineEndpointTests(unittest.TestCase):
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

    def _timeline(self, rid, tenant="tenant-a"):
        return self._get(f"/requests/{rid}/audit-timeline", tenant)

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

    def _assert_valid_timeline(self, data, rid, expected_statuses):
        record = json.loads(data)
        self.assertEqual(list(record), FIELDS)
        self.assertEqual(set(record), set(FIELDS))
        self.assertEqual(record["request_id"], rid)
        events = record["events"]
        self.assertEqual(
            [event["status"] for event in events], list(expected_statuses)
        )
        previous_when = None
        for event in events:
            self.assertEqual(list(event), EVENT_FIELDS)
            self.assertEqual(set(event), set(EVENT_FIELDS))
            self.assertIn(event["status"], STATUSES)
            when = event["occurred_at"]
            self.assertTrue(UTC_RFC3339.match(when), when)
            parsed = _parse_utc(when)
            self.assertEqual(parsed.utcoffset().total_seconds(), 0)
            if previous_when is not None:
                self.assertGreaterEqual(parsed, previous_when)
            previous_when = parsed
        return record

    # -- success shape --------------------------------------------------

    def test_accepted_only_timeline_shape(self):
        receipt = self._lifecycle(())
        rid = receipt["request_id"]
        status, headers, data = self._timeline(rid)
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("Content-Type"), "application/json")
        self.assertTrue(data.endswith(b"\n"))
        self.assertEqual(data.count(b"\n"), 1)
        self.assertTrue(data.startswith(b'{"request_id":"'), data)
        record = self._assert_valid_timeline(data, rid, ["accepted"])
        self.assertEqual(
            data,
            (json.dumps(record, separators=(",", ":")) + "\n").encode(),
        )
        # Only the state-event status and time are exposed.
        self.assertNotIn(b"subject-1", data)
        self.assertNotIn(b"email", data)
        self.assertNotIn(b"key-1", data)
        self.assertNotIn(b"chain_hash", data)
        self.assertNotIn(b"seq", data)
        self.assertNotIn(b"attempt", data)

    def test_timeline_tracks_committed_lifecycle(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        status, _, data = self._timeline(rid)
        self.assertEqual(status, 200)
        self._assert_valid_timeline(
            data, rid, ["accepted", "processing", "completed"]
        )
        # The final entry is the current persisted status.
        _, _, status_data = self._get(f"/requests/{rid}/status")
        self.assertEqual(
            json.loads(data)["events"][-1]["status"],
            json.loads(status_data)["status"],
        )
        # Times are exactly the persisted state-event times.
        audited = self.store.audit("tenant-a", rid)
        self.assertEqual(
            [event["occurred_at"] for event in json.loads(data)["events"]],
            [event["occurred_at"] for event in audited],
        )

    def test_direct_accepted_to_failed_history(self):
        receipt = self._lifecycle(("failed",))
        status, _, data = self._timeline(receipt["request_id"])
        self.assertEqual(status, 200)
        self._assert_valid_timeline(
            data, receipt["request_id"], ["accepted", "failed"]
        )

    def test_idempotent_re_advance_appends_nothing(self):
        receipt = self._lifecycle(("processing",))
        rid = receipt["request_id"]
        _, _, first = self._timeline(rid)
        # Re-advancing to the status already held is an idempotent
        # no-op everywhere, including the persisted history.
        self.store.transition("tenant-a", rid, "processing")
        _, _, second = self._timeline(rid)
        self.assertEqual(second, first)
        self.assertEqual(len(json.loads(second)["events"]), 2)
        # A legal later change is appended once.
        self.store.transition("tenant-a", rid, "completed")
        self.store.transition("tenant-a", rid, "completed")
        _, _, third = self._timeline(rid)
        self._assert_valid_timeline(
            third, rid, ["accepted", "processing", "completed"]
        )

    def test_execution_attempts_never_mix_into_events(self):
        receipt = self.store.submit(
            "tenant-a", "subject-1", ["email"], "key-1"
        )
        rid = receipt["request_id"]
        claimed = self.store.claim_next("tenant-a", "worker-1", 1)
        self.assertEqual(claimed["request_id"], rid)
        # Let the lease expire and reclaim: a second attempt exists but
        # the status never changes again.
        time.sleep(1.15)
        reclaimed = self.store.claim_next("tenant-a", "worker-2", 60)
        self.assertEqual(reclaimed["request_id"], rid)
        attempts = self.store.get_execution_log("tenant-a", rid)
        self.assertEqual(len(attempts), 2)
        status, _, data = self._timeline(rid)
        self.assertEqual(status, 200)
        self._assert_valid_timeline(data, rid, ["accepted", "processing"])
        self.assertNotIn(b"worker-1", data)
        self.assertNotIn(b"worker-2", data)
        self.assertNotIn(claimed["claim_token"].encode(), data)
        self.assertNotIn(reclaimed["claim_token"].encode(), data)

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

    # -- tenant location and query gate ---------------------------------

    def test_tenant_query_parameter_and_header_precedence(self):
        receipt = self._lifecycle(())
        rid = receipt["request_id"]
        status, _, data = self._request(
            "GET", f"/requests/{rid}/audit-timeline?tenant_id=tenant-a"
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)["request_id"], rid)
        # A non-empty header overrides the query string and scopes the read.
        status, _, data = self._request(
            "GET", f"/requests/{rid}/audit-timeline?tenant_id=tenant-a",
            headers={"X-Tenant-Id": "tenant-b"},
        )
        self.assertEqual((status, data), (404, NOT_FOUND))

    def test_duplicate_tenant_query_is_400(self):
        receipt = self._lifecycle(())
        rid = receipt["request_id"]
        # Without the gate the last value would win; the gate rejects any
        # duplicated key before storage is touched.
        status, _, data = self._request(
            "GET",
            f"/requests/{rid}/audit-timeline"
            "?tenant_id=tenant-b&tenant_id=tenant-a",
        )
        self.assertEqual((status, data), (400, INVALID_REQUEST))

    def test_unknown_query_parameter_is_400(self):
        receipt = self._lifecycle(())
        rid = receipt["request_id"]
        for suffix in ("?foo=1", "?tenant_id=tenant-a&foo=1", "?limit=1"):
            with self.subTest(suffix=suffix):
                status, _, data = self._request(
                    "GET", f"/requests/{rid}/audit-timeline{suffix}"
                )
                self.assertEqual((status, data), (400, INVALID_REQUEST))

    def test_uppercase_uuid_canonicalises(self):
        receipt = self._lifecycle(())
        _, _, lower = self._timeline(receipt["request_id"])
        status, _, upper = self._get(
            f"/requests/{receipt['request_id'].upper()}/audit-timeline"
        )
        self.assertEqual(status, 200)
        self.assertEqual(upper, lower)

    # -- error mapping --------------------------------------------------

    def test_missing_or_blank_tenant_is_400(self):
        receipt = self._lifecycle(())
        rid = receipt["request_id"]
        for path, headers in (
            (f"/requests/{rid}/audit-timeline", {}),
            (f"/requests/{rid}/audit-timeline?tenant_id=", {}),
            (
                f"/requests/{rid}/audit-timeline?tenant_id=%20%20",
                {},
            ),
            (f"/requests/{rid}/audit-timeline", {"X-Tenant-Id": "   "}),
        ):
            with self.subTest(path=path):
                status, _, data = self._request("GET", path, headers=headers)
                self.assertEqual((status, data), (400, INVALID_REQUEST))

    def test_malformed_unknown_cross_tenant_ids_are_404(self):
        receipt = self._lifecycle(())
        rid = receipt["request_id"]
        unknown = "00000000-0000-4000-8000-000000000000"
        for path, tenant in (
            ("/requests/not-a-uuid/audit-timeline", "tenant-a"),
            ("/requests//audit-timeline", "tenant-a"),
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

    def test_corrupt_database_file_is_503(self):
        receipt = self._lifecycle(())
        with open(self.db_path, "wb") as handle:
            handle.write(b"not a sqlite database")
        status, _, data = self._timeline(receipt["request_id"])
        self.assertEqual((status, data), (503, STORAGE_UNAVAILABLE))
        self.assertEqual(set(json.loads(data)), {"error"})

    # -- tampering: every inconsistent history is 503 ------------------

    def test_deleted_change_event_is_503(self):
        receipt = self._lifecycle(("failed",))
        rid = receipt["request_id"]
        self._tamper(
            "DELETE FROM status_events WHERE request_id = ? AND seq = 1",
            (rid,),
        )
        status, _, data = self._timeline(rid)
        self.assertEqual((status, data), (503, STORAGE_UNAVAILABLE))

    def test_all_events_deleted_is_503(self):
        receipt = self._lifecycle(())
        rid = receipt["request_id"]
        self._tamper(
            "DELETE FROM status_events WHERE request_id = ?", (rid,)
        )
        status, _, data = self._timeline(rid)
        self.assertEqual((status, data), (503, STORAGE_UNAVAILABLE))

    def test_genesis_not_accepted_is_503(self):
        receipt = self._lifecycle()
        self._tamper(
            "UPDATE status_events SET status = 'failed' "
            "WHERE request_id = ? AND seq = 0",
            (receipt["request_id"],),
        )
        status, _, data = self._timeline(receipt["request_id"])
        self.assertEqual((status, data), (503, STORAGE_UNAVAILABLE))

    def test_unknown_status_value_is_503(self):
        receipt = self._lifecycle(("failed",))
        rid = receipt["request_id"]
        self._tamper(
            "UPDATE status_events SET status = 'cancelled' "
            "WHERE request_id = ? AND seq = 1",
            (rid,),
        )
        status, _, data = self._timeline(rid)
        self.assertEqual((status, data), (503, STORAGE_UNAVAILABLE))

    def test_illegal_edge_between_events_is_503(self):
        # accepted -> processing -> failed is legal; forging an extra
        # repeated processing introduces an edge the graph forbids.
        receipt = self._lifecycle(("processing", "failed"))
        rid = receipt["request_id"]
        events = self.store.audit("tenant-a", rid)
        self._tamper(
            "INSERT INTO status_events "
            "(tenant_id, request_id, seq, status, occurred_at, chain_hash) "
            "VALUES ('tenant-a', ?, 3, 'processing', ?, ?)",
            (rid, events[-1]["occurred_at"], "f" * 64),
        )
        status, _, data = self._timeline(rid)
        self.assertEqual((status, data), (503, STORAGE_UNAVAILABLE))

    def test_malformed_timestamp_is_503(self):
        receipt = self._lifecycle()
        self._tamper(
            "UPDATE status_events SET occurred_at = 'not-a-timestamp' "
            "WHERE request_id = ? AND seq = 0",
            (receipt["request_id"],),
        )
        status, _, data = self._timeline(receipt["request_id"])
        self.assertEqual((status, data), (503, STORAGE_UNAVAILABLE))

    def test_non_utc_offset_timestamp_is_503(self):
        receipt = self._lifecycle()
        self._tamper(
            "UPDATE status_events SET occurred_at = "
            "'2026-01-01T00:00:00.000000+02:00' "
            "WHERE request_id = ? AND seq = 0",
            (receipt["request_id"],),
        )
        status, _, data = self._timeline(receipt["request_id"])
        self.assertEqual((status, data), (503, STORAGE_UNAVAILABLE))

    def test_backwards_timestamps_are_503(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        events = self.store.audit("tenant-a", rid)
        # Swap the processing and completed times so the order regresses.
        self._tamper(
            "UPDATE status_events SET occurred_at = ? "
            "WHERE request_id = ? AND seq = 1",
            (events[2]["occurred_at"], rid),
        )
        self._tamper(
            "UPDATE status_events SET occurred_at = ? "
            "WHERE request_id = ? AND seq = 2",
            (events[1]["occurred_at"], rid),
        )
        status, _, data = self._timeline(rid)
        self.assertEqual((status, data), (503, STORAGE_UNAVAILABLE))

    def test_current_status_split_from_last_event_is_503(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]
        self._tamper(
            "UPDATE requests SET status = 'failed' WHERE request_id = ?",
            (rid,),
        )
        status, _, data = self._timeline(rid)
        self.assertEqual((status, data), (503, STORAGE_UNAVAILABLE))

    def test_tampered_reads_never_partially_render(self):
        receipt = self._lifecycle()
        self._tamper(
            "UPDATE status_events SET occurred_at = occurred_at || 'X' "
            "WHERE request_id = ? AND seq = 0",
            (receipt["request_id"],),
        )
        for _ in range(3):
            status, _, data = self._timeline(receipt["request_id"])
            self.assertEqual((status, data), (503, STORAGE_UNAVAILABLE))

    # -- read-only ------------------------------------------------------

    def test_timeline_read_never_writes(self):
        receipt = self._lifecycle()
        rid = receipt["request_id"]

        def table_counts():
            with self._raw() as conn:
                return {
                    "events": conn.execute(
                        "SELECT count(*) FROM status_events WHERE request_id = ?",
                        (rid,),
                    ).fetchone()[0],
                    "attempts": conn.execute(
                        "SELECT count(*) FROM claim_attempts "
                        "WHERE request_id = ?",
                        (rid,),
                    ).fetchone()[0],
                    "tombstones": conn.execute(
                        "SELECT count(*) FROM deletion_tombstones "
                        "WHERE request_id = ?",
                        (rid,),
                    ).fetchone()[0],
                    "receipts": conn.execute(
                        "SELECT count(*) FROM deletion_receipts "
                        "WHERE request_id = ?",
                        (rid,),
                    ).fetchone()[0],
                    "anchors": conn.execute(
                        "SELECT count(*) FROM audit_anchors WHERE request_id = ?",
                        (rid,),
                    ).fetchone()[0],
                }

        before = table_counts()
        self.assertEqual(before["events"], 3)
        with open(self.db_path, "rb") as handle:
            bytes_before = handle.read()
        for _ in range(5):
            status, _, _ = self._timeline(rid)
            self.assertEqual(status, 200)
        with open(self.db_path, "rb") as handle:
            bytes_after = handle.read()
        self.assertEqual(bytes_before, bytes_after)
        self.assertEqual(table_counts(), before)

    # -- snapshot consistency under concurrent writes -------------------

    def test_never_a_torn_timeline_under_concurrent_transitions(self):
        receipt = self.store.submit(
            "tenant-a", "subject-1", ["email"], "key-1"
        )
        rid = receipt["request_id"]

        def move():
            for target in (
                "processing",
                "completed",
                "accepted",
                "processing",
                "failed",
                "processing",
            ):
                try:
                    self.store.transition("tenant-a", rid, target)
                except Exception:
                    pass

        def read():
            status, _, data = self._timeline(rid)
            self.assertEqual(status, 200)
            record = json.loads(data)
            self.assertEqual(list(record), FIELDS)
            events = record["events"]
            statuses = [event["status"] for event in events]
            # Every rendered history is internally consistent: an
            # acceptance event first, only real lifecycle edges
            # afterwards, and non-regressing occurrence times. The
            # store's 200 additionally proves the final event equals the
            # current status read from that same snapshot -- a
            # mixed-transaction response would be rejected as 503, not
            # rendered with an older final event.
            self.assertEqual(statuses[0], "accepted")
            allowed = {
                "accepted": {"processing", "failed"},
                "processing": {"completed", "failed"},
                "completed": set(),
                "failed": set(),
            }
            for earlier, later in zip(statuses, statuses[1:]):
                self.assertIn(later, allowed[earlier])
            times = [_parse_utc(event["occurred_at"]) for event in events]
            self.assertEqual(times, sorted(times))

        with ThreadPoolExecutor(max_workers=8) as pool:
            movers = [pool.submit(move) for _ in range(4)]
            readers = [
                pool.submit(read) for _ in range(4) for _ in range(25)
            ]
            for future in movers + readers:
                future.result()
        # Final persisted state renders consistently.
        _, _, data = self._timeline(rid)
        final = json.loads(data)
        self.assertEqual(
            final["events"][-1]["status"],
            self.store.get_status("tenant-a", rid)["status"],
        )


SUBMIT_A = {
    "token": "tok-submit-a",
    "tenant_id": "tenant-a",
    "roles": ["request:submit"],
}
READ_A = {"token": "tok-read-a", "tenant_id": "tenant-a",
          "roles": ["request:read"]}
READ_B = {"token": "tok-read-b", "tenant_id": "tenant-b",
          "roles": ["request:read"]}
RECONCILE_A = {
    "token": "tok-reconcile-a",
    "tenant_id": "tenant-a",
    "roles": ["request:reconcile"],
}


class TimelineAuthTests(unittest.TestCase):
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
                    "GET", f"/requests/{self.rid}/audit-timeline",
                    headers={**headers, "X-Tenant-Id": "tenant-a"},
                )
                self.assertEqual((status, data), (401, UNAUTHORIZED))

    def test_wrong_role_is_403(self):
        for token in ("tok-submit-a", "tok-reconcile-a"):
            with self.subTest(token=token):
                status, _, data = self._request(
                    "GET", f"/requests/{self.rid}/audit-timeline",
                    headers={
                        **self._bearer(token),
                        "X-Tenant-Id": "tenant-a",
                    },
                )
                self.assertEqual((status, data), (403, FORBIDDEN))

    def test_tenant_mismatch_is_403_before_id_validation(self):
        for path in (
            f"/requests/{self.rid}/audit-timeline",
            "/requests/not-a-uuid/audit-timeline",
        ):
            with self.subTest(path=path):
                status, _, data = self._request(
                    "GET", path,
                    headers={
                        **self._bearer("tok-read-a"),
                        "X-Tenant-Id": "tenant-b",
                    },
                )
                self.assertEqual((status, data), (403, FORBIDDEN))
        status, _, data = self._request(
            "GET", f"/requests/{self.rid}/audit-timeline?tenant_id=tenant-b",
            headers=self._bearer("tok-read-a"),
        )
        self.assertEqual((status, data), (403, FORBIDDEN))

    def test_missing_tenant_with_valid_token_is_400(self):
        status, _, data = self._request(
            "GET", f"/requests/{self.rid}/audit-timeline",
            headers=self._bearer("tok-read-a"),
        )
        self.assertEqual((status, data), (400, INVALID_REQUEST))

    def test_authorized_read_succeeds(self):
        status, _, data = self._request(
            "GET", f"/requests/{self.rid}/audit-timeline",
            headers={
                **self._bearer("tok-read-a"),
                "X-Tenant-Id": "tenant-a",
            },
        )
        self.assertEqual(status, 200)
        record = json.loads(data)
        self.assertEqual(record["request_id"], self.rid)
        self.assertEqual(
            [event["status"] for event in record["events"]], ["accepted"]
        )

    def test_cross_tenant_record_is_404_with_matching_token(self):
        status, _, data = self._request(
            "GET", f"/requests/{self.rid}/audit-timeline",
            headers={
                **self._bearer("tok-read-b"),
                "X-Tenant-Id": "tenant-b",
            },
        )
        self.assertEqual((status, data), (404, NOT_FOUND))

    def test_method_check_precedes_authentication(self):
        status, _, data = self._request(
            "PUT", f"/requests/{self.rid}/audit-timeline"
        )
        self.assertEqual((status, data), (405, METHOD_NOT_ALLOWED))

    def test_bad_query_with_valid_token_is_400(self):
        status, _, data = self._request(
            "GET", f"/requests/{self.rid}/audit-timeline?foo=1",
            headers={
                **self._bearer("tok-read-a"),
                "X-Tenant-Id": "tenant-a",
            },
        )
        self.assertEqual((status, data), (400, INVALID_REQUEST))


class TimelineStoreTests(unittest.TestCase):
    """Direct storage-layer contract for the backing read."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "evidence.db")
        self.store = RequestStore(self.db_path)

    def tearDown(self):
        self._tmp.cleanup()

    def test_timeline_matches_event_history(self):
        receipt = self.store.submit(
            "tenant-a", "subject-1", ["email"], "key-1"
        )
        rid = receipt["request_id"]
        self.store.transition("tenant-a", rid, "processing")
        self.store.transition("tenant-a", rid, "completed")
        timeline = self.store.get_status_timeline("tenant-a", rid)
        self.assertEqual(set(timeline), {"request_id", "events"})
        self.assertEqual(timeline["request_id"], rid)
        self.assertEqual(
            [event["status"] for event in timeline["events"]],
            ["accepted", "processing", "completed"],
        )
        for event in timeline["events"]:
            self.assertEqual(set(event), {"status", "occurred_at"})
            self.assertTrue(UTC_RFC3339.match(event["occurred_at"]))
        self.assertEqual(
            timeline["events"],
            self.store.audit("tenant-a", rid),
        )

    def test_invalid_tenant_is_value_error(self):
        receipt = self.store.submit(
            "tenant-a", "subject-1", ["email"], "key-1"
        )
        for tenant in (None, ""):
            with self.subTest(tenant=tenant):
                with self.assertRaises(ValueError):
                    self.store.get_status_timeline(
                        tenant, receipt["request_id"]
                    )

    def test_whitespace_tenant_is_not_found_at_storage_layer(self):
        # The storage layer treats a non-empty whitespace tenant as a
        # real tenant that holds no records; the HTTP layer strips it to
        # blank and answers 400 before the store is ever reached.
        receipt = self.store.submit(
            "tenant-a", "subject-1", ["email"], "key-1"
        )
        with self.assertRaises(RequestNotFound):
            self.store.get_status_timeline(
                "   ", receipt["request_id"]
            )

    def test_unknown_and_cross_tenant_are_not_found(self):
        receipt = self.store.submit(
            "tenant-a", "subject-1", ["email"], "key-1"
        )
        rid = receipt["request_id"]
        for tenant, request_id in (
            ("tenant-a", "not-a-uuid"),
            ("tenant-a", "00000000-0000-4000-8000-000000000000"),
            ("tenant-b", rid),
            ("tenant-a", ""),
            ("tenant-a", None),
        ):
            with self.subTest(tenant=tenant, request_id=request_id):
                with self.assertRaises(RequestNotFound):
                    self.store.get_status_timeline(tenant, request_id)

    def test_corrupt_history_is_storage_oserror(self):
        receipt = self.store.submit(
            "tenant-a", "subject-1", ["email"], "key-1"
        )
        rid = receipt["request_id"]
        self.store.transition("tenant-a", rid, "failed")
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "DELETE FROM status_events WHERE request_id = ? AND seq = 1",
                (rid,),
            )
        with self.assertRaises(OSError):
            self.store.get_status_timeline("tenant-a", rid)

    def test_read_is_stable_after_rebuild(self):
        receipt = self.store.submit(
            "tenant-a", "subject-1", ["email"], "key-1"
        )
        rid = receipt["request_id"]
        self.store.transition("tenant-a", rid, "failed")
        first = self.store.get_status_timeline("tenant-a", rid)
        rebuilt = RequestStore(self.db_path)
        second = rebuilt.get_status_timeline("tenant-a", rid)
        self.assertEqual(second, first)


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
        secret = "SECRET-SQL-DETAIL-PATH"

        class BrokenStore:
            def get_status_timeline(self, *a, **k):
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
        when = "2026-01-01T00:00:00.000000Z"
        accepted = {"status": "accepted", "occurred_at": when}
        cases = (
            # Extra top-level field could carry a secret.
            {
                "request_id": rid,
                "events": [accepted],
                "subject_id": "subject-SECRET",
            },
            # Empty or non-list history.
            {"request_id": rid, "events": []},
            {"request_id": rid, "events": None},
            # First entry is not the acceptance event.
            {"request_id": rid, "events": [
                {"status": "processing", "occurred_at": when}
            ]},
            # Event carries an extra/secret field.
            {"request_id": rid, "events": [
                {"status": "accepted", "occurred_at": when,
                 "claim_token": "SECRET"}
            ]},
            # Status outside the lifecycle.
            {"request_id": rid, "events": [
                {"status": "cancelled", "occurred_at": when}
            ]},
            # Malformed or non-UTC timestamp.
            {"request_id": rid, "events": [
                {"status": "accepted", "occurred_at": "not-a-time"}
            ]},
            {"request_id": rid, "events": [
                {"status": "accepted",
                 "occurred_at": "2026-01-01T00:00:00Z"}
            ]},
            {"request_id": rid, "events": [
                {"status": "accepted",
                 "occurred_at": "2026-01-01T00:00:00.000000+00:00"}
            ]},
            # Illegal edge and a backwards occurrence time.
            {"request_id": rid, "events": [
                {"status": "accepted", "occurred_at": when},
                {"status": "accepted",
                 "occurred_at": "2026-01-02T00:00:00.000000Z"},
            ]},
            {"request_id": rid, "events": [
                {"status": "accepted",
                 "occurred_at": "2026-01-02T00:00:00.000000Z"},
                {"status": "failed",
                 "occurred_at": "2026-01-01T00:00:00.000000Z"},
            ]},
        )

        class Store:
            def __init__(self, record):
                self._record = record

            def get_status_timeline(self, *a, **k):
                return self._record

        for record in cases:
            with self.subTest(record=record):
                fixture = self._serve(Store(record))
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
