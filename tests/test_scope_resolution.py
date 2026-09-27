"""Tests for the storage-layer subject/scope resolution entry.

Covers RequestStore.resolve_scopes on the storage layer only: the
business selector grammar (star, whole-collection, single entry), the
canonical normalization (star subsumes everything, a whole-collection
selector subsumes its entries, Unicode code point ordering, exact
duplicates rejected), the conflict listing against the tenant's
already-accepted requests for the same subject (coverage rules,
acceptance-time then request-id ordering, current status only), the
single read-only consistent snapshot, strict read-only behaviour,
validation without writes, the fixed-text ``scope_resolution_failed``
OSError contract, repeatability across rebuilds and the absence of any
HTTP route or health-command change.
"""

import http.client
import json
import os
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from logging import getLogger

from forgetting_evidence import httpapi
from forgetting_evidence.httpapi import build_server
from forgetting_evidence.requests import RequestStore

_LOGGER_NAME = "forgetting_evidence.requests"


class _StoreCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "evidence.db")

    def tearDown(self):
        self._tmp.cleanup()

    def _store(self, secret="anchor-secret", history=None):
        return RequestStore(
            self.db_path, anchor_secret=secret, anchor_history_secrets=history
        )

    def _raw(self):
        return sqlite3.connect(self.db_path)

    def _table_dump(self, table):
        with self._raw() as raw:
            return raw.execute(f"SELECT * FROM {table}").fetchall()

    def _assert_well_formed(self, result):
        # Plain dictionary with exactly the two documented keys in
        # order; nothing else rides along.
        self.assertIsInstance(result, dict)
        self.assertEqual(list(result), ["scopes", "conflicts"])
        scopes = result["scopes"]
        self.assertIsInstance(scopes, list)
        for scope in scopes:
            self.assertIsInstance(scope, str)
            self.assertTrue(scope)
        # Canonical form is deduplicated and code-point ordered.
        self.assertEqual(scopes, sorted(set(scopes)))
        conflicts = result["conflicts"]
        self.assertIsInstance(conflicts, list)
        for entry in conflicts:
            self.assertIsInstance(entry, dict)
            self.assertEqual(list(entry), ["request_id", "status"])
            self.assertIsInstance(entry["request_id"], str)
            self.assertTrue(entry["request_id"])
            self.assertIn(
                entry["status"], ("accepted", "processing", "completed", "failed")
            )
        # Never a float, negative zero or non-finite value anywhere.
        json.dumps(result, allow_nan=False)


class ScopeValidationTests(_StoreCase):
    def test_invalid_tenant_and_subject_raise_value_error_without_writes(self):
        store = self._store()
        store.submit("tenant-a", "subject-1", ["profile:email"], "key-1")
        tables = ("requests", "status_events", "audit_anchors")
        before = {table: self._table_dump(table) for table in tables}
        for bad in ("", None, 5, True, False, ["tenant-a"], b"tenant-a", 1.5):
            with self.assertRaises(ValueError):
                store.resolve_scopes(bad, "subject-1", ["profile:email"])
            with self.assertRaises(ValueError):
                store.resolve_scopes("tenant-a", bad, ["profile:email"])
        # Whitespace-only identifiers are invalid too, whether or not any
        # record exists for them.
        for blank in (" ", "  ", "\t", "\n", " \t "):
            with self.assertRaises(ValueError):
                store.resolve_scopes(blank, "subject-1", ["profile:email"])
            with self.assertRaises(ValueError):
                store.resolve_scopes("tenant-a", blank, ["profile:email"])
            with self.assertRaises(ValueError):
                store.resolve_scopes("tenant-missing", blank, ["profile:email"])
        after = {table: self._table_dump(table) for table in tables}
        self.assertEqual(before, after)

    def test_invalid_scopes_raise_value_error_without_writes(self):
        store = self._store()
        store.submit("tenant-a", "subject-1", ["profile:email"], "key-1")
        before = self._table_dump("requests")
        bad_scopes = (
            [],  # empty
            "profile:email",  # a bare string is not a sequence
            b"profile:email",
            {"profile:email": True},  # a mapping is not a sequence
            None,
            5,
            [None],
            ["profile:email", None],
            [""],  # empty element
            [5],
            [["profile:email"]],
            ["profile:email", "profile:email"],  # exact duplicate
            ["*", "*"],
        )
        for bad in bad_scopes:
            with self.assertRaises(ValueError, msg=repr(bad)):
                store.resolve_scopes("tenant-a", "subject-1", bad)
        self.assertEqual(before, self._table_dump("requests"))

    def test_malformed_selectors_raise_value_error(self):
        store = self._store()
        malformed = (
            "profile",  # bare name is not a selector
            "Profile:email",  # uppercase
            "profile:Email",
            " profile:email",  # leading whitespace
            "profile:email ",  # trailing whitespace
            "profile :email",
            "profile: email",
            "profile:",  # empty second segment
            ":email",  # empty first segment
            ":",  # both segments empty
            "profile:email:extra",  # three segments
            "profile:**",  # star is not a name
            "*:*",
            "profile:email!",
            "profilé:email",
            "**",
            "***",
        )
        for bad in malformed:
            with self.assertRaises(ValueError, msg=repr(bad)):
                store.resolve_scopes("tenant-a", "subject-1", [bad])

    def test_valid_selector_forms_are_accepted(self):
        store = self._store()
        result = store.resolve_scopes(
            "tenant-a",
            "subject-1",
            ["*", "a:*", "a:b", "a_b.c-d:e_f.g-h", "z9:0"],
        )
        # The star subsumes every other selector.
        self.assertEqual(result["scopes"], ["*"])
        self.assertEqual(result["conflicts"], [])


class ScopeNormalizationTests(_StoreCase):
    def test_star_subsumes_everything(self):
        store = self._store()
        for scopes in (["*", "a:b"], ["a:*", "*"], ["a:b", "c:*", "*"]):
            result = store.resolve_scopes("tenant-a", "subject-1", scopes)
            self.assertEqual(result["scopes"], ["*"])

    def test_group_subsumes_same_collection_items(self):
        store = self._store()
        result = store.resolve_scopes(
            "tenant-a",
            "subject-1",
            ["profile:email", "profile:*", "profile:name", "other:item"],
        )
        self.assertEqual(result["scopes"], ["other:item", "profile:*"])

    def test_group_does_not_subsume_other_collections(self):
        store = self._store()
        result = store.resolve_scopes(
            "tenant-a", "subject-1", ["profile:*", "other:item"]
        )
        self.assertEqual(result["scopes"], ["other:item", "profile:*"])

    def test_items_are_sorted_by_unicode_code_point(self):
        store = self._store()
        result = store.resolve_scopes(
            "tenant-a",
            "subject-1",
            ["b:z", "a:z", "a:a", "b:a", "a.m:a", "a-m:a", "a_m:a"],
        )
        self.assertEqual(
            result["scopes"],
            ["a-m:a", "a.m:a", "a:a", "a:z", "a_m:a", "b:a", "b:z"],
        )

    def test_normalization_is_stable_across_instances(self):
        store = self._store()
        scopes = ["profile:email", "profile:*", "other:b", "other:a"]
        first = store.resolve_scopes("tenant-a", "subject-1", scopes)
        rebuilt = self._store()
        second = rebuilt.resolve_scopes("tenant-a", "subject-1", list(reversed(scopes)))
        self.assertEqual(first, second)
        self.assertEqual(
            first["scopes"], ["other:a", "other:b", "profile:*"]
        )


class ScopeConflictTests(_StoreCase):
    def test_star_conflicts_with_everything(self):
        store = self._store()
        rid = store.submit("tenant-a", "subject-1", ["profile:email"], "key-1")[
            "request_id"
        ]
        result = store.resolve_scopes("tenant-a", "subject-1", ["*"])
        self.assertEqual(
            result["conflicts"], [{"request_id": rid, "status": "accepted"}]
        )

    def test_group_covers_same_collection_entries_and_group(self):
        store = self._store()
        rid_item = store.submit(
            "tenant-a", "subject-1", ["profile:email"], "key-1"
        )["request_id"]
        rid_group = store.submit("tenant-a", "subject-1", ["profile:*"], "key-2")[
            "request_id"
        ]
        store.submit("tenant-a", "subject-1", ["other:item"], "key-3")
        result = store.resolve_scopes("tenant-a", "subject-1", ["profile:*"])
        self.assertEqual(
            [entry["request_id"] for entry in result["conflicts"]],
            [rid_item, rid_group],
        )

    def test_identical_items_conflict_and_other_items_do_not(self):
        store = self._store()
        rid = store.submit("tenant-a", "subject-1", ["profile:email"], "key-1")[
            "request_id"
        ]
        result = store.resolve_scopes("tenant-a", "subject-1", ["profile:email"])
        self.assertEqual(
            result["conflicts"], [{"request_id": rid, "status": "accepted"}]
        )
        for scopes in (["profile:name"], ["other:email"], ["other:*"]):
            result = store.resolve_scopes("tenant-a", "subject-1", scopes)
            self.assertEqual(result["conflicts"], [])

    def test_item_does_not_cover_its_own_collection_group(self):
        store = self._store()
        store.submit("tenant-a", "subject-1", ["profile:*"], "key-1")
        # A single entry is narrower than the stored whole-collection
        # selector, but the stored group still covers the new entry.
        result = store.resolve_scopes("tenant-a", "subject-1", ["profile:email"])
        self.assertEqual(len(result["conflicts"]), 1)

    def test_conflicts_are_scoped_to_tenant_and_subject(self):
        store = self._store()
        store.submit("tenant-a", "subject-1", ["profile:email"], "key-1")
        store.submit("tenant-a", "subject-2", ["profile:email"], "key-2")
        store.submit("tenant-b", "subject-1", ["profile:email"], "key-3")
        result = store.resolve_scopes("tenant-a", "subject-1", ["profile:email"])
        self.assertEqual(len(result["conflicts"]), 1)
        self.assertEqual(
            store.resolve_scopes("tenant-a", "subject-2", ["profile:email"])[
                "conflicts"
            ][0]["status"],
            "accepted",
        )
        self.assertEqual(
            store.resolve_scopes("tenant-c", "subject-1", ["profile:email"]),
            {"scopes": ["profile:email"], "conflicts": []},
        )

    def test_conflicts_carry_current_status_only(self):
        store = self._store()
        rid_processing = store.submit(
            "tenant-a", "subject-1", ["profile:a"], "key-1"
        )["request_id"]
        rid_completed = store.submit(
            "tenant-a", "subject-1", ["profile:b"], "key-2"
        )["request_id"]
        rid_failed = store.submit(
            "tenant-a", "subject-1", ["profile:c"], "key-3"
        )["request_id"]
        store.transition("tenant-a", rid_processing, "processing")
        store.transition("tenant-a", rid_completed, "processing")
        store.transition("tenant-a", rid_completed, "completed")
        store.transition("tenant-a", rid_failed, "failed")
        result = store.resolve_scopes("tenant-a", "subject-1", ["profile:*"])
        self.assertEqual(
            result["conflicts"],
            [
                {"request_id": rid_processing, "status": "processing"},
                {"request_id": rid_completed, "status": "completed"},
                {"request_id": rid_failed, "status": "failed"},
            ],
        )

    def test_conflicts_order_by_acceptance_time_then_request_id(self):
        store = self._store()
        ids = [
            store.submit("tenant-a", "subject-1", ["profile:a"], f"key-{i}")[
                "request_id"
            ]
            for i in range(3)
        ]
        result = store.resolve_scopes("tenant-a", "subject-1", ["profile:*"])
        self.assertEqual(
            [entry["request_id"] for entry in result["conflicts"]], ids
        )
        # Raw rows with an identical acceptance time fall back to the
        # request id ordering.
        with self._raw() as raw:
            for rid in ("zzzz", "aaaa", "mmmm"):
                raw.execute(
                    "INSERT INTO requests ("
                    "request_id, tenant_id, idempotency_key, subject_id, "
                    "scopes_json, status, created_at, chain_hash"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        rid,
                        "tenant-a",
                        f"raw-{rid}",
                        "subject-raw",
                        '["profile:a"]',
                        "accepted",
                        "2030-01-01T00:00:00.000000Z",
                        "0" * 64,
                    ),
                )
        result = store.resolve_scopes("tenant-a", "subject-raw", ["profile:*"])
        self.assertEqual(
            [entry["request_id"] for entry in result["conflicts"]],
            ["aaaa", "mmmm", "zzzz"],
        )

    def test_stored_non_selector_scopes_only_conflict_via_star(self):
        store = self._store()
        # Records accepted before the selector grammar may hold arbitrary
        # scope strings; they stay opaque to everything but the star.
        store.submit("tenant-a", "subject-1", ["email"], "key-1")
        result = store.resolve_scopes("tenant-a", "subject-1", ["email:*"])
        self.assertEqual(result["conflicts"], [])
        result = store.resolve_scopes("tenant-a", "subject-1", ["email:all"])
        self.assertEqual(result["conflicts"], [])
        result = store.resolve_scopes("tenant-a", "subject-1", ["*"])
        self.assertEqual(len(result["conflicts"]), 1)

    def test_no_requests_means_no_conflicts(self):
        store = self._store()
        result = store.resolve_scopes("tenant-a", "subject-1", ["profile:email"])
        self.assertEqual(
            result, {"scopes": ["profile:email"], "conflicts": []}
        )
        self._assert_well_formed(result)


class ScopeResolutionShapeTests(_StoreCase):
    def test_result_shape_with_and_without_conflicts(self):
        store = self._store()
        store.submit("tenant-a", "subject-1", ["profile:email"], "key-1")
        hit = store.resolve_scopes("tenant-a", "subject-1", ["profile:*"])
        self._assert_well_formed(hit)
        miss = store.resolve_scopes("tenant-a", "subject-1", ["other:*"])
        self._assert_well_formed(miss)
        self.assertEqual(miss["conflicts"], [])

    def test_in_memory_store_uses_the_same_snapshot_path(self):
        store = RequestStore(":memory:", anchor_secret="anchor-secret")
        rid = store.submit("tenant-a", "subject-1", ["profile:email"], "key-1")[
            "request_id"
        ]
        result = store.resolve_scopes("tenant-a", "subject-1", ["profile:*"])
        self._assert_well_formed(result)
        self.assertEqual(
            result["conflicts"], [{"request_id": rid, "status": "accepted"}]
        )


class ScopeResolutionStabilityTests(_StoreCase):
    def test_repeated_reads_and_rebuilds_return_the_same_dictionary(self):
        store = self._store()
        store.submit("tenant-a", "subject-1", ["profile:email"], "key-1")
        store.submit("tenant-a", "subject-1", ["profile:name"], "key-2")
        first = store.resolve_scopes(
            "tenant-a", "subject-1", ["profile:name", "profile:*"]
        )
        self.assertEqual(store.resolve_scopes("tenant-a", "subject-1", ["profile:*"]), first)
        rebuilt = self._store()
        self.assertEqual(
            rebuilt.resolve_scopes("tenant-a", "subject-1", ["profile:*"]), first
        )

    def test_concurrent_readers_observe_consistent_snapshots(self):
        writer = self._store()
        for i in range(5):
            writer.submit("tenant-a", "subject-1", ["profile:a"], f"key-{i}")
        stop = threading.Event()
        expected = writer.resolve_scopes("tenant-a", "subject-1", ["*"])

        def read_workload():
            local = self._store()
            while not stop.is_set():
                result = local.resolve_scopes("tenant-a", "subject-1", ["*"])
                self.assertEqual(result, expected)

        def write_workload():
            local = self._store()
            index = 0
            while not stop.is_set():
                # Writes for another subject never disturb the snapshot's
                # shape for this subject.
                local.submit(
                    "tenant-a", f"subject-other-{index}", ["profile:a"], f"o-{index}"
                )
                index += 1

        with ThreadPoolExecutor(max_workers=5) as pool:
            readers = [pool.submit(read_workload) for _ in range(3)]
            writers = [pool.submit(write_workload) for _ in range(2)]
            stop.wait(0.5)
            stop.set()
            for future in readers + writers:
                future.result()
        self.assertEqual(
            writer.resolve_scopes("tenant-a", "subject-1", ["*"]), expected
        )


class ScopeResolutionReadOnlyTests(_StoreCase):
    def test_resolution_modifies_no_table(self):
        store = self._store(secret="secret-1")
        rid = store.submit("tenant-a", "subject-1", ["profile:email"], "key-1")[
            "request_id"
        ]
        store.transition("tenant-a", rid, "processing")
        store.audit_inspection("tenant-a", limit=1)
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
        store.resolve_scopes("tenant-a", "subject-1", ["*"])
        store.resolve_scopes("tenant-a", "subject-1", ["profile:*"])
        after = {table: self._table_dump(table) for table in tables}
        self.assertEqual(before, after)

    def test_resolution_creates_no_request_or_batch(self):
        store = self._store()
        store.resolve_scopes("tenant-a", "subject-1", ["*"])
        with self._raw() as raw:
            self.assertEqual(
                raw.execute("SELECT count(*) FROM requests").fetchone()[0], 0
            )
            self.assertEqual(
                raw.execute("SELECT count(*) FROM inspection_batches").fetchone()[0],
                0,
            )


class ScopeResolutionStorageFailureTests(_StoreCase):
    def test_missing_table_raises_scope_resolution_failed(self):
        store = self._store()
        store.submit("tenant-a", "subject-1", ["profile:email"], "key-1")
        with self._raw() as raw:
            raw.execute("DROP TABLE requests")
        with self.assertRaises(OSError) as caught:
            store.resolve_scopes("tenant-a", "subject-1", ["*"])
        self.assertEqual(str(caught.exception), "scope_resolution_failed")

    def test_unreadable_storage_raises_scope_resolution_failed(self):
        store = self._store()
        store.submit("tenant-a", "subject-1", ["profile:email"], "key-1")
        with open(self.db_path, "r+b") as handle:
            handle.write(b"not a sqlite database" + b"\0" * 64)
        with self.assertRaises(OSError) as caught:
            store.resolve_scopes("tenant-a", "subject-1", ["*"])
        self.assertEqual(str(caught.exception), "scope_resolution_failed")

    def test_corrupt_scopes_json_raises_scope_resolution_failed(self):
        store = self._store()
        rid = store.submit("tenant-a", "subject-1", ["profile:email"], "key-1")[
            "request_id"
        ]
        for broken in ("not json", '{"a": 1}', '["a", 5]', '[""]', '"a"'):
            with self._raw() as raw:
                raw.execute(
                    "UPDATE requests SET scopes_json = ? WHERE request_id = ?",
                    (broken, rid),
                )
            with self.assertRaises(OSError, msg=broken) as caught:
                store.resolve_scopes("tenant-a", "subject-1", ["*"])
            self.assertEqual(str(caught.exception), "scope_resolution_failed")
            with self._raw() as raw:
                raw.execute(
                    "UPDATE requests SET scopes_json = ? WHERE request_id = ?",
                    ('["profile:email"]', rid),
                )
        # The store recovers once the record is whole again.
        result = store.resolve_scopes("tenant-a", "subject-1", ["*"])
        self.assertEqual(len(result["conflicts"]), 1)

    def test_unknown_status_value_raises_scope_resolution_failed(self):
        store = self._store()
        rid = store.submit("tenant-a", "subject-1", ["profile:email"], "key-1")[
            "request_id"
        ]
        with self._raw() as raw:
            raw.execute(
                "UPDATE requests SET status = ? WHERE request_id = ?",
                ("bogus", rid),
            )
        with self.assertRaises(OSError) as caught:
            store.resolve_scopes("tenant-a", "subject-1", ["*"])
        self.assertEqual(str(caught.exception), "scope_resolution_failed")

    def test_failure_returns_no_partial_result(self):
        store = self._store()
        store.submit("tenant-a", "subject-1", ["profile:a"], "key-1")
        rid = store.submit("tenant-a", "subject-1", ["profile:b"], "key-2")[
            "request_id"
        ]
        with self._raw() as raw:
            raw.execute(
                "UPDATE requests SET scopes_json = ? WHERE request_id = ?",
                ("broken", rid),
            )
        try:
            store.resolve_scopes("tenant-a", "subject-1", ["*"])
        except OSError as exc:
            self.assertEqual(str(exc), "scope_resolution_failed")
        else:
            self.fail("resolve_scopes should have raised")


class ScopeResolutionLeakageTests(_StoreCase):
    def test_logs_and_errors_carry_only_stable_categories(self):
        store = self._store(secret="very-secret-material")
        rid = store.submit(
            "tenant-a", "subject-secret", ["scope-secret"], "key-secret"
        )["request_id"]
        with self.assertLogs(_LOGGER_NAME, level="INFO") as logs:
            result = store.resolve_scopes("tenant-a", "subject-secret", ["*"])
        self.assertEqual(len(result["conflicts"]), 1)
        text = "\n".join(logs.output)
        for fragment in (
            "very-secret-material",
            "subject-secret",
            "scope-secret",
            "key-secret",
            "tenant-a",
            rid,
            self.db_path,
        ):
            self.assertNotIn(fragment, text)
        # The fixed error text never embeds identifying details either.
        with self._raw() as raw:
            raw.execute("DROP TABLE requests")
        try:
            store.resolve_scopes("tenant-a", "subject-secret", ["*"])
        except OSError as exc:
            self.assertEqual(str(exc), "scope_resolution_failed")
            for fragment in ("subject-secret", "tenant-a", self.db_path):
                self.assertNotIn(fragment, str(exc))
        else:
            self.fail("resolve_scopes should have raised")

    def test_conflicts_never_expose_subject_or_scopes(self):
        store = self._store()
        store.submit("tenant-a", "subject-secret", ["profile:email"], "key-1")
        result = store.resolve_scopes("tenant-a", "subject-secret", ["*"])
        text = json.dumps(result)
        self.assertNotIn("subject-secret", text)
        self.assertNotIn("profile:email", text)
        self.assertNotIn("key-1", text)


class ScopeResolutionHttpSurfaceTests(_StoreCase):
    def _serve(self, store):
        server = build_server(store, "127.0.0.1", 0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server, thread

    def test_no_http_route_or_delegate_is_added(self):
        store = self._store()
        self.assertFalse(hasattr(httpapi.DeferredRequestStore, "resolve_scopes"))
        server, thread = self._serve(store)
        try:
            conn = http.client.HTTPConnection(
                "127.0.0.1", server.server_address[1], timeout=10
            )
            try:
                for path in ("/resolve-scopes", "/scopes/resolve"):
                    conn.request(
                        "GET", path, headers={"X-Tenant-Id": "tenant-a"}
                    )
                    response = conn.getresponse()
                    self.assertEqual(response.status, 404)
                    response.read()
            finally:
                conn.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_health_command_is_unchanged(self):
        from forgetting_evidence.__main__ import main

        self.assertEqual(main(["resolve-scopes"]), 2)


if __name__ == "__main__":
    unittest.main()
