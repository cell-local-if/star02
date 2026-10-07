"""Tests for the read-only GET /audit-health HTTP endpoint.

The endpoint publishes the storage layer's instantaneous tenant
health snapshot: the single-line compact JSON body carries exactly
``total``, ``statuses``, ``verified``, ``unverified`` and
``reasons`` (one trailing newline), the four lifecycle counts sum to
``total``, the trust counts are complementary, and the merged
reason/count list is ordered by Unicode code point. Covers tenant
resolution (header overrides the single ``tenant_id`` query key), the
400/401/403/404/405/503 error contract and its ordering, the all-zero
snapshot for a tenant without requests, byte-identical strictly
read-only reads, the consistent-snapshot invariants under concurrent
writes and the absence of any tenant, request id, subject, secret, SQL
or path leakage.
"""

import http.client
import json
import os
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor

from forgetting_evidence.httpapi import (
    AuthConfig,
    DeferredRequestStore,
    build_server,
)
from forgetting_evidence.requests import RequestStore

INVALID_REQUEST = b'{"error":"invalid_request"}\n'
UNAUTHORIZED = b'{"error":"unauthorized"}\n'
FORBIDDEN = b'{"error":"forbidden"}\n'
NOT_FOUND = b'{"error":"not_found"}\n'
METHOD_NOT_ALLOWED = b'{"error":"method_not_allowed"}\n'
STORAGE_UNAVAILABLE = b'{"error":"storage_unavailable"}\n'

PATH = "/audit-health"
SECRET = "anchor-secret"
STATUS_NAMES = ("accepted", "processing", "completed", "failed")
ZERO_SNAPSHOT = (
    b'{"total":0,"statuses":{"accepted":0,"processing":0,'
    b'"completed":0,"failed":0},"verified":0,"unverified":0,'
    b'"reasons":[]}\n'
)

READ_A = {"token": "tok-read-a", "tenant_id": "tenant-a",
          "roles": ["request:read"]}
READ_B = {"token": "tok-read-b", "tenant_id": "tenant-b",
          "roles": ["request:read"]}
SUBMIT_A = {"token": "tok-submit-a", "tenant_id": "tenant-a",
            "roles": ["request:submit"]}
RECONCILE_A = {"token": "tok-reconcile-a", "tenant_id": "tenant-a",
               "roles": ["request:reconcile"]}
POLICY_A = {"token": "tok-policy-a", "tenant_id": "tenant-a",
            "roles": ["policy:read"]}


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


class _Base(unittest.TestCase):
    auth = None

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "evidence.db")
        self.store = RequestStore(self.db_path, anchor_secret=SECRET)
        self._fixture = _Server(self.store, self.auth)
        self._fixture.__enter__()
        self.port = self._fixture.port

    def tearDown(self):
        self._fixture.__exit__(None, None, None)
        self._tmp.cleanup()

    def _request(self, method, path, headers=None, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        try:
            conn.request(method, path, headers=headers or {}, body=body)
            resp = conn.getresponse()
            return resp.status, dict(resp.getheaders()), resp.read()
        finally:
            conn.close()

    def _get(self, path=PATH, tenant="tenant-a", headers=None):
        merged = {"X-Tenant-Id": tenant} if tenant is not None else {}
        merged.update(headers or {})
        return self._request("GET", path, headers=merged)

    def _submit_many(self, count, tenant="tenant-a"):
        return [
            self.store.submit(
                tenant, f"subject-{tenant}-{i}", ["email"], f"key-{tenant}-{i}"
            )["request_id"]
            for i in range(count)
        ]

    def _raw(self):
        return sqlite3.connect(self.db_path)

    def _table_dump(self, table):
        with self._raw() as raw:
            return raw.execute(f"SELECT * FROM {table}").fetchall()

    def _assert_snapshot(self, payload, total):
        self.assertEqual(
            list(payload),
            ["total", "statuses", "verified", "unverified", "reasons"],
        )
        self.assertEqual(payload["total"], total)
        statuses = payload["statuses"]
        self.assertEqual(list(statuses), list(STATUS_NAMES))
        self.assertEqual(total, sum(statuses.values()))
        self.assertEqual(
            total, payload["verified"] + payload["unverified"]
        )
        merged = 0
        previous = None
        for entry in payload["reasons"]:
            self.assertEqual(list(entry), ["reason", "count"])
            self.assertIsInstance(entry["reason"], str)
            self.assertTrue(entry["reason"])
            self.assertIsInstance(entry["count"], int)
            self.assertGreater(entry["count"], 0)
            if previous is not None:
                self.assertLess(previous, entry["reason"])
            previous = entry["reason"]
            merged += entry["count"]
        self.assertEqual(merged, payload["unverified"])


class AuditHealthReadTests(_Base):
    def test_nonexistent_tenant_is_all_zero_snapshot(self):
        # No requests anywhere: a missing tenant is a successful
        # all-zero read, never a missing-request error.
        status, headers, body = self._get(tenant="tenant-ghost")
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertEqual(body, ZERO_SNAPSHOT)
        self.assertEqual(
            set(json.loads(body)),
            {"total", "statuses", "verified", "unverified", "reasons"},
        )

    def test_other_tenants_exist_but_unknown_tenant_still_zero(self):
        self._submit_many(3, tenant="tenant-a")
        status, _, body = self._get(tenant="tenant-ghost")
        self.assertEqual(status, 200)
        self.assertEqual(body, ZERO_SNAPSHOT)

    def test_healthy_requests_are_all_verified(self):
        self._submit_many(3)
        status, _, body = self._get()
        self.assertEqual(status, 200)
        self.assertTrue(body.endswith(b"\n"))
        self.assertEqual(body.count(b"\n"), 1)
        payload = json.loads(body)
        self._assert_snapshot(payload, 3)
        self.assertEqual(payload["statuses"]["accepted"], 3)
        self.assertEqual(payload["verified"], 3)
        self.assertEqual(payload["unverified"], 0)
        self.assertEqual(payload["reasons"], [])
        self.assertEqual(
            body,
            b'{"total":3,"statuses":{"accepted":3,"processing":0,'
            b'"completed":0,"failed":0},"verified":3,"unverified":0,'
            b'"reasons":[]}\n',
        )

    def test_four_lifecycle_counts_cover_the_population(self):
        ids = self._submit_many(4)
        claim = self.store.claim_next("tenant-a", "worker-1", 300)
        self.assertEqual(claim["request_id"], ids[0])
        self.store.finish_claim(
            "tenant-a", ids[0], claim["claim_token"], "completed"
        )
        self.store.transition("tenant-a", ids[1], "processing")
        self.store.transition("tenant-a", ids[2], "failed")
        status, _, body = self._get()
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self._assert_snapshot(payload, 4)
        self.assertEqual(
            payload["statuses"],
            {"accepted": 1, "processing": 1, "completed": 1, "failed": 1},
        )
        self.assertEqual(payload["verified"], 4)

    def test_tenants_are_isolated(self):
        self._submit_many(2, tenant="tenant-a")
        self._submit_many(3, tenant="tenant-b")
        for tenant, total in (("tenant-a", 2), ("tenant-b", 3)):
            status, _, body = self._get(tenant=tenant)
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(body)["total"], total)

    def test_reasons_are_merged_and_unicode_sorted(self):
        ids = self._submit_many(4)
        self.store.transition("tenant-a", ids[1], "processing")
        with self._raw() as raw:
            raw.execute(
                "UPDATE requests SET chain_hash = ? WHERE request_id = ?",
                ("0" * 64, ids[0]),
            )
            raw.execute(
                "DELETE FROM status_events WHERE request_id = ? AND seq = 1",
                (ids[1],),
            )
            raw.execute(
                "UPDATE requests SET chain_hash = ? WHERE request_id = ?",
                ("3" * 64, ids[2]),
            )
        status, _, body = self._get()
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self._assert_snapshot(payload, 4)
        self.assertEqual(payload["verified"], 1)
        self.assertEqual(payload["unverified"], 3)
        self.assertEqual(
            payload["reasons"],
            [
                {"reason": "anchor_orphan", "count": 1},
                {"reason": "chain_head_mismatch", "count": 2},
            ],
        )

    def test_body_matches_store_snapshot_verbatim_field_order(self):
        self._submit_many(2)
        status, _, body = self._get()
        self.assertEqual(status, 200)
        snapshot = self.store.audit_health("tenant-a")
        expected = (
            json.dumps(
                {
                    "total": snapshot["total"],
                    "statuses": snapshot["statuses"],
                    "verified": snapshot["verified"],
                    "unverified": snapshot["unverified"],
                    "reasons": snapshot["reasons"],
                },
                ensure_ascii=False,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
        self.assertEqual(body, expected)

    def test_repeated_reads_are_byte_identical_and_read_only(self):
        ids = self._submit_many(3)
        with self._raw() as raw:
            raw.execute(
                "UPDATE requests SET chain_hash = ? WHERE request_id = ?",
                ("0" * 64, ids[0]),
            )
        bodies = [self._get()[2] for _ in range(4)]
        self.assertEqual(len(set(bodies)), 1)
        # The read created no request, event, attempt, batch, receipt,
        # anchor or key record.
        with self._raw() as raw:
            self.assertEqual(
                raw.execute("SELECT count(*) FROM requests").fetchone()[0], 3
            )
            self.assertEqual(
                raw.execute(
                    "SELECT count(*) FROM inspection_batches"
                ).fetchone()[0],
                0,
            )
            self.assertEqual(
                raw.execute(
                    "SELECT count(*) FROM inspection_batch_items"
                ).fetchone()[0],
                0,
            )

    def test_health_read_does_not_advance_an_open_cursor(self):
        self._submit_many(3)
        first = self.store.audit_inspection("tenant-a", limit=2)
        self._get(tenant="tenant-empty")
        self._get()
        tail = self.store.audit_inspection(
            "tenant-a", cursor=first["next_cursor"]
        )
        self.assertEqual(len(tail["items"]), 1)
        self.assertIs(tail["finished"], True)

    def test_health_read_modifies_no_table(self):
        ids = self._submit_many(3)
        self.store.transition("tenant-a", ids[0], "processing")
        self.store.audit_inspection("tenant-a", limit=2)
        tables = (
            "requests",
            "status_events",
            "claim_attempts",
            "claim_tokens",
            "reconcile_batches",
            "reconcile_batch_items",
            "inspection_batches",
            "inspection_batch_items",
            "deletion_receipts",
            "receipt_keys",
            "audit_anchors",
            "audit_anchor_meta",
            "anchor_key_generations",
        )
        before = {table: self._table_dump(table) for table in tables}
        self._get()
        self._get(tenant="tenant-empty")
        after = {table: self._table_dump(table) for table in tables}
        self.assertEqual(before, after)

    def test_body_never_leaks_subject_scope_key_or_secret(self):
        self.store.submit(
            "tenant-a", "subject-SECRETXYZ", ["scope-SECRETXYZ"], "key-SECRETXYZ"
        )
        _, _, body = self._get()
        for leaked in (b"SECRETXYZ", SECRET.encode(), self.db_path.encode()):
            self.assertNotIn(leaked, body)

    def test_concurrent_writes_never_tear_a_response(self):
        stop = threading.Event()

        def write_workload():
            index = 0
            while not stop.is_set():
                for _ in range(10):
                    rid = self.store.submit(
                        "tenant-a",
                        f"subject-{threading.get_ident()}-{index}",
                        ["email"],
                        f"key-{threading.get_ident()}-{index}",
                    )["request_id"]
                    if index % 2 == 0:
                        self.store.transition("tenant-a", rid, "processing")
                    index += 1

        def read_workload():
            seen = []
            while not stop.is_set():
                status, _, body = self._get()
                self.assertEqual(status, 200)
                payload = json.loads(body)
                total = payload["total"]
                self.assertEqual(total, sum(payload["statuses"].values()))
                self.assertEqual(
                    total, payload["verified"] + payload["unverified"]
                )
                self.assertEqual(
                    sum(e["count"] for e in payload["reasons"]),
                    payload["unverified"],
                )
                seen.append(total)
            return seen

        with ThreadPoolExecutor(max_workers=4) as pool:
            writers = [pool.submit(write_workload) for _ in range(2)]
            readers = [pool.submit(read_workload) for _ in range(2)]
            stop.wait(1.0)
            stop.set()
            totals = []
            for future in readers:
                totals.extend(future.result())
            for future in writers:
                future.result()
        self.assertTrue(totals)


class AuditHealthTenantResolutionTests(_Base):
    def test_tenant_via_query_parameter(self):
        self._submit_many(1)
        status, _, body = self._get(PATH + "?tenant_id=tenant-a", tenant=None)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["total"], 1)

    def test_header_overrides_query(self):
        self._submit_many(2, tenant="tenant-a")
        self._submit_many(1, tenant="tenant-b")
        status, _, body = self._request(
            "GET",
            PATH + "?tenant_id=tenant-a",
            headers={"X-Tenant-Id": "tenant-b"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["total"], 1)

    def test_missing_tenant_is_400(self):
        status, _, body = self._get(tenant=None)
        self.assertEqual(status, 400)
        self.assertEqual(body, INVALID_REQUEST)

    def test_empty_or_blank_tenant_is_400(self):
        for headers in ({"X-Tenant-Id": ""}, {"X-Tenant-Id": "   "}):
            status, _, body = self._request("GET", PATH, headers=headers)
            self.assertEqual(status, 400)
            self.assertEqual(body, INVALID_REQUEST)
        for path in (
            PATH + "?tenant_id=",
            PATH + "?tenant_id=%20%20",
        ):
            status, _, body = self._get(path, tenant=None)
            self.assertEqual(status, 400)
            self.assertEqual(body, INVALID_REQUEST)

    def test_unknown_query_parameter_is_400(self):
        for path in (
            PATH + "?tenant_id=tenant-a&cursor=abc",
            PATH + "?tenant_id=tenant-a&limit=10",
            PATH + "?limit=10",
            PATH + "?tenant_id=tenant-a&bogus=",
        ):
            status, _, body = self._get(path, tenant=None)
            self.assertEqual(status, 400, path)
            self.assertEqual(body, INVALID_REQUEST)

    def test_duplicate_query_key_is_400(self):
        for path in (
            PATH + "?tenant_id=tenant-a&tenant_id=tenant-a",
            PATH + "?tenant_id=tenant-a&tenant_id=tenant-b",
        ):
            status, _, body = self._get(path, tenant=None)
            self.assertEqual(status, 400, path)
            self.assertEqual(body, INVALID_REQUEST)


class AuditHealthRoutingTests(_Base):
    def test_non_get_methods_are_405_with_allow_get(self):
        for method in ("POST", "PUT", "DELETE", "PATCH", "OPTIONS"):
            status, headers, body = self._request(method, PATH)
            self.assertEqual(status, 405, method)
            self.assertEqual(headers["Allow"], "GET")
            self.assertEqual(body, METHOD_NOT_ALLOWED)
            self.assertEqual(set(json.loads(body)), {"error"})

    def test_head_is_405_headless_with_allow_get(self):
        status, headers, body = self._request("HEAD", PATH)
        self.assertEqual(status, 405)
        self.assertEqual(headers["Allow"], "GET")
        self.assertEqual(body, b"")
        self.assertEqual(headers["Content-Length"], str(len(METHOD_NOT_ALLOWED)))

    def test_unknown_neighbour_paths_are_404(self):
        for path in (
            "/audit-health/",
            "/audit-health/extra",
            "/audit-healthx",
            "/audit-healt",
            "/nope",
        ):
            status, _, body = self._get(path)
            self.assertEqual(status, 404, path)
            self.assertEqual(body, NOT_FOUND)


class AuditHealthStorageFailureTests(_Base):
    def test_corrupt_database_is_503_without_partial_snapshot(self):
        self._submit_many(1)
        with open(self.db_path, "wb") as handle:
            handle.write(b"not a sqlite database")
        status, _, body = self._get()
        self.assertEqual(status, 503)
        self.assertEqual(body, STORAGE_UNAVAILABLE)
        self.assertEqual(set(json.loads(body)), {"error"})

    def test_dropped_table_is_503(self):
        self._submit_many(1)
        with self._raw() as raw:
            raw.execute("DROP TABLE audit_anchors")
        status, _, body = self._get()
        self.assertEqual(status, 503)
        self.assertEqual(body, STORAGE_UNAVAILABLE)

    def test_unwritable_database_is_503(self):
        blocker = os.path.join(self._tmp.name, "blocker")
        with open(blocker, "w", encoding="utf-8") as handle:
            handle.write("not a directory")
        deferred = DeferredRequestStore(os.path.join(blocker, "evidence.db"))
        with _Server(deferred) as fixture:
            conn = http.client.HTTPConnection(
                "127.0.0.1", fixture.port, timeout=10
            )
            try:
                conn.request(
                    "GET", PATH, headers={"X-Tenant-Id": "tenant-a"}
                )
                resp = conn.getresponse()
                self.assertEqual(resp.status, 503)
                self.assertEqual(resp.read(), STORAGE_UNAVAILABLE)
            finally:
                conn.close()

    def test_storage_exception_becomes_503_without_leak(self):
        secret = "SECRET-SQL-PATH-DETAIL"

        class BrokenStore:
            def audit_health(self, *a, **k):
                raise RuntimeError(secret)

        with _Server(BrokenStore()) as fixture:
            conn = http.client.HTTPConnection(
                "127.0.0.1", fixture.port, timeout=10
            )
            try:
                conn.request(
                    "GET", PATH, headers={"X-Tenant-Id": "tenant-a"}
                )
                resp = conn.getresponse()
                self.assertEqual(resp.status, 503)
                body = resp.read()
                self.assertEqual(body, STORAGE_UNAVAILABLE)
                self.assertNotIn(b"SECRET", body)
            finally:
                conn.close()

    def test_validation_order_keeps_storage_unreachable_on_bad_input(self):
        # A broken store is never touched when the request is invalid.
        class ExplodingStore:
            def audit_health(self, *a, **k):
                raise AssertionError("storage must not be reached")

        with _Server(ExplodingStore()) as fixture:
            conn = http.client.HTTPConnection(
                "127.0.0.1", fixture.port, timeout=10
            )
            try:
                for path in (PATH, PATH + "?bogus=1"):
                    conn.request("GET", path)
                    resp = conn.getresponse()
                    self.assertEqual(resp.status, 400, path)
                    self.assertEqual(resp.read(), INVALID_REQUEST)
            finally:
                conn.close()


class MalformedSnapshotRendererTests(unittest.TestCase):
    """A substitute store must never leak a malformed health body."""

    def _serve(self, store):
        fixture = _Server(store)
        fixture.__enter__()
        return fixture

    def _get(self, port):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        try:
            conn.request("GET", PATH, headers={"X-Tenant-Id": "tenant-a"})
            resp = conn.getresponse()
            return resp.status, resp.read()
        finally:
            conn.close()

    def test_malformed_snapshots_become_503(self):
        zero = {
            "total": 0,
            "statuses": {name: 0 for name in STATUS_NAMES},
            "verified": 0,
            "unverified": 0,
            "reasons": [],
        }

        def variant(**changes):
            snapshot = json.loads(json.dumps(zero))
            snapshot.update(changes)
            return snapshot

        cases = {
            "not a dict": ["not", "a", "dict"],
            "extra key": variant(extra=1),
            "missing key": {k: v for k, v in zero.items() if k != "total"},
            "float total": variant(total=1.0),
            "negative total": variant(total=-1),
            "boolean count": variant(total=True),
            "missing status bucket": variant(
                statuses={name: 0 for name in STATUS_NAMES if name != "failed"}
            ),
            "reordered statuses": variant(
                statuses={
                    "failed": 0,
                    "accepted": 0,
                    "processing": 0,
                    "completed": 0,
                }
            ),
            "foreign status": variant(
                statuses={
                    "accepted": 0,
                    "processing": 0,
                    "completed": 0,
                    "bogus": 0,
                }
            ),
            "status sum mismatch": variant(
                total=1,
                statuses={
                    "accepted": 0,
                    "processing": 0,
                    "completed": 0,
                    "failed": 0,
                },
            ),
            "trust sum mismatch": variant(total=1, verified=0, unverified=0),
            "reasons not a list": variant(total=1, verified=0, unverified=1,
                                          reasons="x"),
            "reason without count": variant(
                total=1,
                verified=0,
                unverified=1,
                reasons=[{"reason": "chain_head_mismatch"}],
            ),
            "empty reason": variant(
                total=1,
                verified=0,
                unverified=1,
                reasons=[{"reason": "", "count": 1}],
            ),
            "zero count": variant(
                total=1,
                verified=0,
                unverified=1,
                reasons=[{"reason": "chain_head_mismatch", "count": 0}],
            ),
            "unsorted reasons": variant(
                total=2,
                statuses={
                    "accepted": 2,
                    "processing": 0,
                    "completed": 0,
                    "failed": 0,
                },
                verified=0,
                unverified=2,
                reasons=[
                    {"reason": "chain_head_mismatch", "count": 1},
                    {"reason": "anchor_orphan", "count": 1},
                ],
            ),
            "duplicate reasons": variant(
                total=2,
                statuses={
                    "accepted": 2,
                    "processing": 0,
                    "completed": 0,
                    "failed": 0,
                },
                verified=0,
                unverified=2,
                reasons=[
                    {"reason": "anchor_orphan", "count": 1},
                    {"reason": "anchor_orphan", "count": 1},
                ],
            ),
            "reason totals mismatch": variant(
                total=1,
                verified=0,
                unverified=1,
                reasons=[
                    {"reason": "anchor_orphan", "count": 1},
                    {"reason": "chain_head_mismatch", "count": 1},
                ],
            ),
        }

        class Store:
            def __init__(self, snapshot):
                self._snapshot = snapshot

            def audit_health(self, *a, **k):
                return self._snapshot

        for label, snapshot in cases.items():
            with self.subTest(label=label):
                fixture = self._serve(Store(snapshot))
                try:
                    status, body = self._get(fixture.port)
                    self.assertEqual(status, 503, label)
                    self.assertEqual(body, STORAGE_UNAVAILABLE)
                finally:
                    fixture.__exit__(None, None, None)

    def test_well_formed_snapshot_is_rendered_compact(self):
        snapshot = {
            "total": 2,
            "statuses": {
                "accepted": 1,
                "processing": 1,
                "completed": 0,
                "failed": 0,
            },
            "verified": 1,
            "unverified": 1,
            "reasons": [{"reason": "chain_head_mismatch", "count": 1}],
        }

        class Store:
            def audit_health(self, *a, **k):
                return snapshot

        fixture = self._serve(Store())
        try:
            status, body = self._get(fixture.port)
            self.assertEqual(status, 200)
            self.assertEqual(
                body,
                b'{"total":2,"statuses":{"accepted":1,"processing":1,'
                b'"completed":0,"failed":0},"verified":1,"unverified":1,'
                b'"reasons":[{"reason":"chain_head_mismatch","count":1}]}\n',
            )
        finally:
            fixture.__exit__(None, None, None)


class AuditHealthAuthTests(_Base):
    auth = AuthConfig([READ_A, READ_B, SUBMIT_A, RECONCILE_A, POLICY_A])

    def _auth_get(self, token, path=PATH, tenant="tenant-a"):
        headers = {}
        if tenant is not None:
            headers["X-Tenant-Id"] = tenant
        if token is not None:
            headers["Authorization"] = token
        return self._request("GET", path, headers=headers)

    def test_missing_malformed_or_unknown_token_is_401(self):
        for header in (
            None,
            "tok-read-a",
            "Bearer",
            "Bearer ",
            "Basic tok-read-a",
            "bearer tok-read-a",
            "Bearer unknown-token",
        ):
            status, _, body = self._auth_get(header)
            self.assertEqual(status, 401, header)
            self.assertEqual(body, UNAUTHORIZED)

    def test_wrong_role_is_403(self):
        for token in ("tok-submit-a", "tok-reconcile-a", "tok-policy-a"):
            status, _, body = self._auth_get(f"Bearer {token}")
            self.assertEqual(status, 403, token)
            self.assertEqual(body, FORBIDDEN)

    def test_read_role_reads_own_tenant(self):
        self._submit_many(2)
        status, _, body = self._auth_get("Bearer tok-read-a")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["total"], 2)

    def test_cross_tenant_is_403(self):
        self._submit_many(1, tenant="tenant-a")
        status, _, body = self._auth_get(
            "Bearer tok-read-b", PATH, tenant="tenant-a"
        )
        self.assertEqual(status, 403)
        self.assertEqual(body, FORBIDDEN)
        # The same via the query-parameter tenant.
        status, _, body = self._auth_get(
            "Bearer tok-read-b", PATH + "?tenant_id=tenant-a", tenant=None
        )
        self.assertEqual(status, 403)
        self.assertEqual(body, FORBIDDEN)

    def test_other_tenant_principal_reads_own_zero_snapshot(self):
        self._submit_many(1, tenant="tenant-a")
        status, _, body = self._auth_get(
            "Bearer tok-read-b", PATH, tenant="tenant-b"
        )
        self.assertEqual(status, 200)
        self.assertEqual(body, ZERO_SNAPSHOT)

    def test_missing_tenant_with_valid_token_is_400(self):
        status, _, body = self._auth_get(
            "Bearer tok-read-a", tenant=None
        )
        self.assertEqual(status, 400)
        self.assertEqual(body, INVALID_REQUEST)

    def test_bad_query_with_valid_token_is_400(self):
        status, _, body = self._auth_get(
            "Bearer tok-read-a",
            PATH + "?tenant_id=tenant-a&bogus=1",
            tenant=None,
        )
        self.assertEqual(status, 400)
        self.assertEqual(body, INVALID_REQUEST)

    def test_method_check_precedes_authentication(self):
        status, headers, body = self._request("PUT", PATH)
        self.assertEqual(status, 405)
        self.assertEqual(headers["Allow"], "GET")
        self.assertEqual(body, METHOD_NOT_ALLOWED)

    def test_unknown_path_stays_404_without_token(self):
        status, _, body = self._request("GET", "/nothing/here")
        self.assertEqual(status, 404)
        self.assertEqual(body, NOT_FOUND)

    def test_error_bodies_never_echo_token(self):
        for header in ("Bearer tok-read-a", "Bearer unknown-token"):
            _, _, body = self._auth_get(header, tenant="tenant-b")
            self.assertNotIn(b"tok-", body)


class AuditHealthUnauthenticatedTests(_Base):
    auth = None

    def test_authorization_header_is_ignored_without_auth_config(self):
        self._submit_many(1)
        status, _, body = self._get(
            headers={"Authorization": "Bearer anything"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["total"], 1)


if __name__ == "__main__":
    unittest.main()
