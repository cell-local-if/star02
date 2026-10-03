"""Tests for the read-only deletion-tombstone pagination entry point.

Covers RequestStore.page_deletion_tombstones on the storage layer only:
snapshot (scope, adapter_id) ordering, the fixed page/top-level shapes,
limit validation, opaque cursor encoding and binding to the tenant,
request and issuing snapshot, resume-after-last-item progress that
ignores the following limit, identical repeat reads, restart reuse,
whole-ledger recorded_at/evidence_digest on every page, read-only
guarantees, error precedence and corruption handling. The entry point
is deliberately not exposed over HTTP.
"""

import hashlib
import json
import os
import sqlite3
import struct
import tempfile
import unittest

from forgetting_evidence.requests import RequestNotFound, RequestStore

PAGE_ERROR = "deletion_tombstone_page_failed"
STORAGE_ERROR = "deletion_tombstone_failed"


def _digest(seed):
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


def _item(scope, operation, adapter=None, outcome="deleted", proof=None):
    return {
        "adapter_id": adapter if adapter is not None else f"adapter-{operation}",
        "scope": scope,
        "operation_id": operation,
        "outcome": outcome,
        "proof_digest": proof if proof is not None else _digest(operation),
    }


def _expected_digest(items):
    digest = hashlib.sha256()
    rows = sorted(
        (i["scope"], i["operation_id"], i["adapter_id"], i["outcome"], i["proof_digest"])
        for i in items
    )
    for row in rows:
        for field in row:
            encoded = field.encode("utf-8")
            digest.update(struct.pack(">Q", len(encoded)))
            digest.update(encoded)
    return digest.hexdigest()


class _StoreCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "evidence.db")

    def tearDown(self):
        self._tmp.cleanup()

    def _store(self):
        return RequestStore(self.db_path)

    def _submit(self, store, tenant="tenant-a", key="key-1", scopes=("email", "profile")):
        return store.submit(tenant, "subject-1", list(scopes), key)

    def _claimed(self, scopes=("email", "profile"), tenant="tenant-a", key="key-1"):
        store = self._store()
        receipt = self._submit(store, tenant=tenant, key=key, scopes=scopes)
        claim = store.claim_next(tenant, "worker-1", 3600)
        return store, receipt, claim

    def _recorded(self, store, rid, token, items):
        # Register in chunks so recorded_at can differ between batches.
        for index in range(0, len(items), 3):
            store.record_deletion_tombstones(
                "tenant-a", rid, token, items[index:index + 3]
            )


class PageShapeTest(_StoreCase):
    def test_page_shape_field_order_and_entry_fields(self):
        store, receipt, claim = self._claimed()
        rid = receipt["request_id"]
        items = [
            _item("profile", "op-2", adapter="adapter-b", outcome="absent"),
            _item("email", "op-1", adapter="adapter-a"),
        ]
        store.record_deletion_tombstones("tenant-a", rid, claim["claim_token"], items)
        page = store.page_deletion_tombstones("tenant-a", rid)
        self.assertEqual(
            list(page),
            [
                "request_id",
                "tombstones",
                "recorded_at",
                "evidence_digest",
                "next_cursor",
            ],
        )
        self.assertEqual(page["request_id"], rid)
        self.assertEqual(len(page["tombstones"]), 2)
        for entry in page["tombstones"]:
            # Exactly six fields, in the fixed order; the raw object and
            # the proof body never appear.
            self.assertEqual(
                list(entry),
                [
                    "adapter_id",
                    "scope",
                    "operation_id",
                    "outcome",
                    "proof_digest",
                    "recorded_at",
                ],
            )
        self.assertEqual(
            [(t["scope"], t["adapter_id"]) for t in page["tombstones"]],
            [("email", "adapter-a"), ("profile", "adapter-b")],
        )
        full = store.get_deletion_tombstones("tenant-a", rid)
        self.assertEqual(page["recorded_at"], full["recorded_at"])
        self.assertEqual(page["evidence_digest"], _expected_digest(items))
        self.assertEqual(page["evidence_digest"], full["evidence_digest"])
        self.assertIsNone(page["next_cursor"])

    def test_empty_ledger_page(self):
        store, receipt, _ = self._claimed()
        page = store.page_deletion_tombstones("tenant-a", receipt["request_id"])
        self.assertEqual(page["tombstones"], [])
        self.assertIsNone(page["recorded_at"])
        self.assertIsNone(page["evidence_digest"])
        self.assertIsNone(page["next_cursor"])
        # An empty ledger never issues a cursor, whatever the limit.
        again = store.page_deletion_tombstones(
            "tenant-a", receipt["request_id"], limit=1
        )
        self.assertEqual(again["tombstones"], [])
        self.assertIsNone(again["next_cursor"])

    def test_order_is_scope_codepoint_then_adapter(self):
        store, receipt, claim = self._claimed(
            scopes=("email", "z", "ä")
        )
        rid = receipt["request_id"]
        items = [
            _item("email", "op-3", adapter="adapter-b"),
            _item("z", "op-2", adapter="adapter-a"),
            _item("ä", "op-4", adapter="adapter-a"),
            _item("email", "op-1", adapter="adapter-a"),
        ]
        store.record_deletion_tombstones("tenant-a", rid, claim["claim_token"], items)
        page = store.page_deletion_tombstones("tenant-a", rid)
        # Normalized scope Unicode code point order (z is U+007A, ä is
        # U+00E4), then adapter_id inside the same scope.
        self.assertEqual(
            [(t["scope"], t["adapter_id"], t["operation_id"]) for t in page["tombstones"]],
            [
                ("email", "adapter-a", "op-1"),
                ("email", "adapter-b", "op-3"),
                ("z", "adapter-a", "op-2"),
                ("ä", "adapter-a", "op-4"),
            ],
        )

    def test_one_scope_many_adapters_still_paginates(self):
        store, receipt, claim = self._claimed(scopes=("email",))
        rid = receipt["request_id"]
        items = [
            _item("email", f"op-{i}", adapter=f"adapter-{i:03d}")
            for i in range(5)
        ]
        store.record_deletion_tombstones("tenant-a", rid, claim["claim_token"], items)
        page = store.page_deletion_tombstones("tenant-a", rid, limit=2)
        self.assertEqual(
            [t["adapter_id"] for t in page["tombstones"]],
            ["adapter-000", "adapter-001"],
        )
        self.assertIsNotNone(page["next_cursor"])


class PaginationTest(_StoreCase):
    def _ledger(self, count, scope="email"):
        store, receipt, claim = self._claimed(scopes=(scope,))
        rid = receipt["request_id"]
        items = [
            _item(scope, f"op-{i:04d}", adapter=f"adapter-{i:04d}")
            for i in range(count)
        ]
        self._recorded(store, rid, claim["claim_token"], items)
        return store, receipt, items

    def test_walks_every_item_once(self):
        store, receipt, items = self._ledger(7)
        seen = []
        cursor = None
        pages = 0
        while True:
            page = store.page_deletion_tombstones(
                "tenant-a", receipt["request_id"], cursor=cursor, limit=3
            )
            seen.extend(t["operation_id"] for t in page["tombstones"])
            pages += 1
            cursor = page["next_cursor"]
            if cursor is None:
                break
            self.assertLessEqual(pages, 10)
        self.assertEqual(pages, 3)
        self.assertEqual(
            seen,
            [t["operation_id"] for t in sorted(items, key=lambda i: i["adapter_id"])],
        )

    def test_default_limit_is_100_and_max_is_1000(self):
        store, receipt, _ = self._ledger(150)
        page = store.page_deletion_tombstones("tenant-a", receipt["request_id"])
        self.assertEqual(len(page["tombstones"]), 100)
        self.assertIsNotNone(page["next_cursor"])
        rest = store.page_deletion_tombstones(
            "tenant-a",
            receipt["request_id"],
            cursor=page["next_cursor"],
        )
        self.assertEqual(len(rest["tombstones"]), 50)
        self.assertIsNone(rest["next_cursor"])
        big = store.page_deletion_tombstones(
            "tenant-a", receipt["request_id"], limit=1000
        )
        self.assertEqual(len(big["tombstones"]), 150)
        self.assertIsNone(big["next_cursor"])

    def test_next_cursor_only_when_snapshot_continues(self):
        store, receipt, _ = self._ledger(5)
        exact = store.page_deletion_tombstones(
            "tenant-a", receipt["request_id"], limit=5
        )
        self.assertIsNone(exact["next_cursor"])
        partial = store.page_deletion_tombstones(
            "tenant-a", receipt["request_id"], limit=4
        )
        self.assertIsNotNone(partial["next_cursor"])
        last = store.page_deletion_tombstones(
            "tenant-a",
            receipt["request_id"],
            cursor=partial["next_cursor"],
            limit=4,
        )
        self.assertEqual(len(last["tombstones"]), 1)
        self.assertIsNone(last["next_cursor"])

    def test_following_page_limit_is_not_bound(self):
        store, receipt, _ = self._ledger(7)
        first = store.page_deletion_tombstones(
            "tenant-a", receipt["request_id"], limit=2
        )
        for following_limit in (1, 2, 1000):
            with self.subTest(limit=following_limit):
                page = store.page_deletion_tombstones(
                    "tenant-a",
                    receipt["request_id"],
                    cursor=first["next_cursor"],
                    limit=following_limit,
                )
                self.assertEqual(
                    [t["operation_id"] for t in page["tombstones"]][
                : following_limit],
                    [f"op-{i:04d}" for i in range(2, 2 + min(following_limit, 5))],
                )

    def test_every_page_carries_whole_ledger_digest_and_recorded_at(self):
        store, receipt, items = self._ledger(7)
        full = store.get_deletion_tombstones("tenant-a", receipt["request_id"])
        cursor = None
        page_count = 0
        while True:
            page = store.page_deletion_tombstones(
                "tenant-a", receipt["request_id"], cursor=cursor, limit=3
            )
            self.assertEqual(page["evidence_digest"], full["evidence_digest"])
            self.assertEqual(page["evidence_digest"], _expected_digest(items))
            self.assertEqual(page["recorded_at"], full["recorded_at"])
            page_count += 1
            cursor = page["next_cursor"]
            if cursor is None:
                break
        self.assertEqual(page_count, 3)

    def test_same_cursor_repeats_identical_bytes_and_progress(self):
        store, receipt, _ = self._ledger(5)
        first = store.page_deletion_tombstones(
            "tenant-a", receipt["request_id"], limit=2
        )
        cursor = first["next_cursor"]
        second = store.page_deletion_tombstones(
            "tenant-a", receipt["request_id"], cursor=cursor, limit=2
        )
        # The same cursor with the same limit is byte-identical and makes
        # the same progress, however many times it is replayed.
        repeated = store.page_deletion_tombstones(
            "tenant-a", receipt["request_id"], cursor=cursor, limit=2
        )
        self.assertEqual(repeated, second)
        self.assertEqual(
            json.dumps(repeated, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )
        # A different limit changes only the page size; the resume point
        # stays anchored to the cursor, so the first entries are the same
        # and both walks still cover the ledger exactly once.
        bigger = store.page_deletion_tombstones(
            "tenant-a", receipt["request_id"], cursor=cursor, limit=7
        )
        self.assertEqual(
            bigger["tombstones"][:2], second["tombstones"]
        )
        self.assertEqual(len(bigger["tombstones"]), 3)
        walk_two = first["tombstones"] + second["tombstones"]
        rest = store.page_deletion_tombstones(
            "tenant-a",
            receipt["request_id"],
            cursor=second["next_cursor"],
            limit=2,
        )
        walk_two += rest["tombstones"]
        self.assertEqual(len(walk_two), 5)
        self.assertEqual(len({t["operation_id"] for t in walk_two}), 5)

    def test_cursor_survives_restart(self):
        store, receipt, items = self._ledger(7)
        first_pages = []
        cursor = None
        while True:
            page = store.page_deletion_tombstones(
                "tenant-a", receipt["request_id"], cursor=cursor, limit=2
            )
            first_pages.append(page)
            cursor = page["next_cursor"]
            if cursor is None:
                break
        issued_cursor = first_pages[0]["next_cursor"]
        del store
        rebuilt = self._store()
        resumed = rebuilt.page_deletion_tombstones(
            "tenant-a",
            receipt["request_id"],
            cursor=issued_cursor,
            limit=2,
        )
        self.assertEqual(resumed, first_pages[1])
        # A whole walk on the rebuilt store is identical, cursors
        # included.
        rebuilt_pages = []
        cursor = None
        while True:
            page = rebuilt.page_deletion_tombstones(
                "tenant-a", receipt["request_id"], cursor=cursor, limit=2
            )
            rebuilt_pages.append(page)
            cursor = page["next_cursor"]
            if cursor is None:
                break
        self.assertEqual(rebuilt_pages, first_pages)
        self.assertEqual(len(items), 7)


class SnapshotBindingTest(_StoreCase):
    def test_stale_cursor_after_ledger_grows_is_value_error(self):
        store, receipt, claim = self._claimed(scopes=("email", "profile"))
        rid = receipt["request_id"]
        token = claim["claim_token"]
        store.record_deletion_tombstones(
            "tenant-a",
            rid,
            token,
            [
                _item("email", "op-1", adapter="adapter-a"),
                _item("email", "op-3", adapter="adapter-b"),
            ],
        )
        first = store.page_deletion_tombstones("tenant-a", rid, limit=1)
        self.assertEqual(
            [t["operation_id"] for t in first["tombstones"]], ["op-1"]
        )
        cursor = first["next_cursor"]
        self.assertIsNotNone(cursor)
        # Nothing changed: the cursor resumes at the second item.
        self.assertEqual(
            [t["operation_id"] for t in
             store.page_deletion_tombstones("tenant-a", rid, cursor=cursor)["tombstones"]],
            ["op-3"],
        )
        # The ledger grows after the cursor was generated: continuing the
        # old snapshot is caller error, never an implicit restart.
        store.record_deletion_tombstones(
            "tenant-a", rid, token, [_item("profile", "op-2")]
        )
        with self.assertRaises(ValueError) as ctx:
            store.page_deletion_tombstones("tenant-a", rid, cursor=cursor)
        self.assertEqual(str(ctx.exception), PAGE_ERROR)
        # A fresh first-page read over the new snapshot still works.
        fresh = store.page_deletion_tombstones("tenant-a", rid)
        self.assertEqual(len(fresh["tombstones"]), 3)
        self.assertIsNone(fresh["next_cursor"])

    def test_cursor_binds_tenant_and_request(self):
        store = self._store()
        one = self._submit(store, tenant="tenant-a", key="key-1")
        two = self._submit(store, tenant="tenant-a", key="key-2")
        other = self._submit(store, tenant="tenant-b", key="key-3")
        claim_a1 = store.claim_next("tenant-a", "worker-1", 3600)
        store.record_deletion_tombstones(
            "tenant-a", one["request_id"], claim_a1["claim_token"],
            [_item("email", "op-1"), _item("profile", "op-2")],
        )
        cursor = store.page_deletion_tombstones(
            "tenant-a", one["request_id"], limit=1
        )["next_cursor"]
        self.assertIsNotNone(cursor)
        # Another request of the same tenant is a binding mismatch.
        with self.assertRaises(ValueError) as ctx:
            store.page_deletion_tombstones(
                "tenant-a", two["request_id"], cursor=cursor
            )
        self.assertEqual(str(ctx.exception), PAGE_ERROR)
        # Another tenant is a binding mismatch as well, even though the
        # same coordinates without a cursor are RequestNotFound.
        with self.assertRaises(ValueError) as ctx:
            store.page_deletion_tombstones(
                "tenant-b", other["request_id"], cursor=cursor
            )
        self.assertEqual(str(ctx.exception), PAGE_ERROR)
        with self.assertRaises(ValueError) as ctx:
            store.page_deletion_tombstones(
                "tenant-b", one["request_id"], cursor=cursor
            )
        self.assertEqual(str(ctx.exception), PAGE_ERROR)


class ValidationTest(_StoreCase):
    def test_tenant_validation(self):
        store, receipt, _ = self._claimed()
        rid = receipt["request_id"]
        for value in ("", None, 7, b"tenant-a", ["tenant-a"]):
            with self.subTest(value=value):
                with self.assertRaises(ValueError) as ctx:
                    store.page_deletion_tombstones(value, rid)
                self.assertEqual(str(ctx.exception), PAGE_ERROR)

    def test_limit_validation(self):
        store, receipt, _ = self._claimed()
        rid = receipt["request_id"]
        for value in (0, 1001, -1, True, False, "10", 1.5, None.__class__, 1.0):
            with self.subTest(value=value):
                with self.assertRaises(ValueError) as ctx:
                    store.page_deletion_tombstones("tenant-a", rid, limit=value)
                self.assertEqual(str(ctx.exception), PAGE_ERROR)

    def test_request_id_unknown_malformed_and_cross_tenant(self):
        store, receipt, _ = self._claimed()
        rid = receipt["request_id"]
        for value in ("", None, 7, b"req", ["x"]):
            with self.subTest(value=value):
                with self.assertRaises(RequestNotFound) as ctx:
                    store.page_deletion_tombstones("tenant-a", value)
                self.assertEqual(str(ctx.exception), "request not found")
        with self.assertRaises(RequestNotFound):
            store.page_deletion_tombstones("tenant-a", "missing")
        with self.assertRaises(RequestNotFound):
            store.page_deletion_tombstones("tenant-b", rid)

    def test_malformed_cursors_rejected(self):
        store, receipt, _ = self._claimed()
        rid = receipt["request_id"]
        bad = [
            "",
            "dt1.",
            "dt1.!!!",
            "dt1." + "A" * 3,  # bad padding
            "rc1." + "A" * 4,  # reconcile cursor family
            "rl1." + "A" * 4,  # listing cursor family
            "garbage",
            7,
            None.__class__,
            # Valid envelope, foreign payload shape.
            "dt1.eyJ2IjoxfQ==",
        ]
        for value in bad:
            with self.subTest(value=value):
                with self.assertRaises(ValueError) as ctx:
                    store.page_deletion_tombstones("tenant-a", rid, cursor=value)
                self.assertEqual(str(ctx.exception), PAGE_ERROR)

    def test_in_memory_store_pagination(self):
        store = RequestStore(":memory:")
        receipt = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        claim = store.claim_next("tenant-a", "worker-1", 3600)
        items = [
            _item("email", f"op-{i}", adapter=f"adapter-{i}") for i in range(3)
        ]
        store.record_deletion_tombstones(
            "tenant-a", receipt["request_id"], claim["claim_token"], items
        )
        page = store.page_deletion_tombstones(
            "tenant-a", receipt["request_id"], limit=2
        )
        self.assertEqual(len(page["tombstones"]), 2)
        rest = store.page_deletion_tombstones(
            "tenant-a",
            receipt["request_id"],
            cursor=page["next_cursor"],
            limit=2,
        )
        self.assertEqual(len(rest["tombstones"]), 1)
        self.assertIsNone(rest["next_cursor"])


class ReadOnlyTest(_StoreCase):
    def test_paging_changes_nothing(self):
        store, receipt, claim = self._claimed()
        rid = receipt["request_id"]
        # Paging an empty accepted-then-claimed ledger must not create an
        # attempt, a tombstone or a status event.
        store.page_deletion_tombstones("tenant-a", rid)
        store.page_deletion_tombstones("tenant-a", rid, limit=1)
        self.assertEqual(store.get_status("tenant-a", rid)["status"], "processing")
        log = store.get_execution_log("tenant-a", rid)
        self.assertEqual(len(log), 1)
        self.assertIsNone(log[0]["result"])
        self.assertEqual(
            store.get_deletion_tombstones("tenant-a", rid)["tombstones"], []
        )

        store.record_deletion_tombstones(
            "tenant-a", rid, claim["claim_token"],
            [_item("email", "op-1"), _item("profile", "op-2")],
        )
        before = store.get_deletion_tombstones("tenant-a", rid)
        cursor = None
        for _ in range(5):
            page = store.page_deletion_tombstones(
                "tenant-a", rid, cursor=cursor, limit=1
            )
            cursor = page["next_cursor"]
        # The ledger, its recorded_at and its digest are untouched...
        after = store.get_deletion_tombstones("tenant-a", rid)
        self.assertEqual(after, before)
        # ...the claim is still live and no extra attempt exists...
        self.assertEqual(store.get_status("tenant-a", rid)["status"], "processing")
        self.assertEqual(len(store.get_execution_log("tenant-a", rid)), 1)
        # ...and the finish ledger row was never created.
        with sqlite3.connect(self.db_path) as raw:
            finish_count = raw.execute(
                "SELECT COUNT(*) FROM deletion_tombstone_finishes "
                "WHERE request_id = ?",
                (rid,),
            ).fetchone()[0]
        self.assertEqual(finish_count, 0)

    def test_paging_does_not_distinguish_tenant_partition(self):
        store = self._store()
        one = self._submit(store, tenant="tenant-a", key="key-1")
        two = self._submit(store, tenant="tenant-b", key="key-2")
        claim = store.claim_next("tenant-a", "worker-1", 3600)
        store.record_deletion_tombstones(
            "tenant-a", one["request_id"], claim["claim_token"],
            [_item("email", "op-1"), _item("profile", "op-2")],
        )
        page = store.page_deletion_tombstones("tenant-b", two["request_id"])
        self.assertEqual(page["tombstones"], [])
        self.assertIsNone(page["recorded_at"])
        self.assertIsNone(page["evidence_digest"])
        self.assertIsNone(page["next_cursor"])


class CorruptionTest(_StoreCase):
    def _raw(self):
        conn = sqlite3.connect(self.db_path)
        conn.isolation_level = None
        return conn

    def test_corrupt_tombstone_row_raises_fixed_oserror(self):
        store, receipt, claim = self._claimed()
        rid = receipt["request_id"]
        store.record_deletion_tombstones(
            "tenant-a", rid, claim["claim_token"],
            [_item("email", "op-1"), _item("profile", "op-2")],
        )
        conn = self._raw()
        try:
            conn.execute(
                "UPDATE deletion_tombstones SET outcome = 'purged' "
                "WHERE operation_id = 'op-1'"
            )
        finally:
            conn.close()
        # Corruption anywhere in the snapshot fails the whole page, even
        # when the damaged row would have landed on a later page.
        with self.assertRaises(OSError) as caught:
            store.page_deletion_tombstones("tenant-a", rid, limit=1)
        self.assertEqual(str(caught.exception), STORAGE_ERROR)

    def test_corrupt_finish_row_raises_fixed_oserror(self):
        store, receipt, claim = self._claimed()
        rid = receipt["request_id"]
        token = claim["claim_token"]
        store.record_deletion_tombstones(
            "tenant-a", rid, token,
            [_item("email", "op-1"), _item("profile", "op-2")],
        )
        store.finish_scoped_claim("tenant-a", rid, token, "completed")
        conn = self._raw()
        try:
            conn.execute(
                "UPDATE deletion_tombstone_finishes SET evidence_digest = ? "
                "WHERE request_id = ?",
                (_digest("forged"), rid),
            )
        finally:
            conn.close()
        with self.assertRaises(OSError) as caught:
            store.page_deletion_tombstones("tenant-a", rid)
        self.assertEqual(str(caught.exception), STORAGE_ERROR)

    def test_storage_fault_is_fixed_oserror(self):
        store, receipt, claim = self._claimed()
        rid = receipt["request_id"]
        store.record_deletion_tombstones(
            "tenant-a", rid, claim["claim_token"], [_item("email", "op-1")]
        )
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DROP TABLE deletion_tombstones")
        with self.assertRaises(OSError) as caught:
            store.page_deletion_tombstones("tenant-a", rid)
        self.assertEqual(str(caught.exception), STORAGE_ERROR)

    def test_rejected_calls_leave_no_writes(self):
        store, receipt, claim = self._claimed()
        rid = receipt["request_id"]
        store.record_deletion_tombstones(
            "tenant-a",
            rid,
            claim["claim_token"],
            [_item("email", "op-1"), _item("profile", "op-2")],
        )
        cursor = store.page_deletion_tombstones(
            "tenant-a", rid, limit=1
        )["next_cursor"]
        self.assertIsNotNone(cursor)
        for call in (
            lambda: store.page_deletion_tombstones("", rid),
            lambda: store.page_deletion_tombstones("tenant-a", rid, limit=0),
            lambda: store.page_deletion_tombstones("tenant-a", rid, cursor="garbage"),
            lambda: store.page_deletion_tombstones(
                "tenant-a", "other-request", cursor=cursor
            ),
        ):
            with self.assertRaises((ValueError, RequestNotFound)):
                call()
        with sqlite3.connect(self.db_path) as raw:
            counts = {
                table: raw.execute(
                    f"SELECT COUNT(*) FROM {table}"
                ).fetchone()[0]
                for table in (
                    "deletion_tombstones",
                    "deletion_tombstone_finishes",
                    "claim_attempts",
                )
            }
        self.assertEqual(counts["deletion_tombstones"], 2)
        self.assertEqual(counts["deletion_tombstone_finishes"], 0)
        self.assertEqual(counts["claim_attempts"], 1)


if __name__ == "__main__":
    unittest.main()
