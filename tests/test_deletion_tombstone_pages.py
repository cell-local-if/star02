"""Tests for the read-only deletion-tombstone pagination entry point.

Covers ``RequestStore.page_deletion_tombstones`` only: snapshot-stable
ordering and paging, whole-ledger ``recorded_at``/``evidence_digest``,
opaque cursor binding (tenant, request and issuing snapshot), cursor
reuse across limits and restarts, stale-snapshot rejection, argument
validation with the fixed error texts, read-only guarantees, corruption
handling and the no-object/no-proof-body boundary. The entry point is
storage-layer only and is not exposed over HTTP.
"""

import base64
import hashlib
import json
import os
import sqlite3
import tempfile
import unittest

from forgetting_evidence.requests import RequestNotFound, RequestStore


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

    def _ledger(self, store, receipt, items, tenant="tenant-a", lease_seconds=60):
        claim = store.claim_next(tenant, "worker-1", lease_seconds)
        assert claim is not None
        record = store.record_deletion_tombstones(
            tenant, receipt["request_id"], claim["claim_token"], items
        )
        return claim, record


def _serialized(page):
    return json.dumps(page, sort_keys=True, separators=(",", ":"))


class PagingTest(_StoreCase):
    def _registered(self, items, scopes=("email", "profile"), tenant="tenant-a"):
        store = self._store()
        receipt = self._submit(store, tenant=tenant, scopes=scopes)
        self._ledger(store, receipt, items, tenant=tenant)
        return store, receipt

    def test_page_walks_full_ledger_in_scope_adapter_order(self):
        items = [
            _item("profile", "op-2", adapter="adapter-b"),
            _item("email", "op-1", adapter="adapter-a"),
            _item("email", "op-3", adapter="adapter-c"),
        ]
        store, receipt = self._registered(items)
        rid = receipt["request_id"]
        pages = []
        cursor = None
        for _ in range(10):
            page = store.page_deletion_tombstones("tenant-a", rid, cursor, 2)
            pages.append(page)
            cursor = page["next_cursor"]
            if cursor is None:
                break
        self.assertEqual(len(pages), 2)
        self.assertIsNone(pages[-1]["next_cursor"])
        ordered = [t for page in pages for t in page["tombstones"]]
        self.assertEqual(
            [(t["scope"], t["adapter_id"]) for t in ordered],
            [
                ("email", "adapter-a"),
                ("email", "adapter-c"),
                ("profile", "adapter-b"),
            ],
        )

    def test_page_shape_and_field_sets(self):
        items = [_item("email", "op-1", adapter="adapter-a")]
        store, receipt = self._registered(items)
        page = store.page_deletion_tombstones(
            "tenant-a", receipt["request_id"], None, 10
        )
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
        self.assertEqual(page["request_id"], receipt["request_id"])
        self.assertIsNone(page["next_cursor"])
        entry = page["tombstones"][0]
        self.assertEqual(
            set(entry),
            {
                "adapter_id",
                "scope",
                "operation_id",
                "outcome",
                "proof_digest",
                "recorded_at",
            },
        )
        self.assertEqual(entry["operation_id"], "op-1")
        self.assertEqual(entry["outcome"], "deleted")
        self.assertEqual(entry["proof_digest"], _digest("op-1"))

    def test_headers_describe_whole_ledger_not_the_page(self):
        items = [
            _item("email", "op-1", adapter="adapter-a"),
            _item("profile", "op-2", adapter="adapter-b"),
            _item("profile", "op-3", adapter="adapter-c"),
        ]
        store, receipt = self._registered(items)
        rid = receipt["request_id"]
        full = store.get_deletion_tombstones("tenant-a", rid)
        first = store.page_deletion_tombstones("tenant-a", rid, None, 1)
        last = store.page_deletion_tombstones(
            "tenant-a", rid, first["next_cursor"], 10
        )
        for page in (first, last):
            self.assertEqual(page["recorded_at"], full["recorded_at"])
            self.assertEqual(page["evidence_digest"], full["evidence_digest"])
        self.assertEqual(len(first["tombstones"]), 1)
        self.assertEqual(len(last["tombstones"]), 2)

    def test_empty_ledger_page(self):
        store = self._store()
        receipt = self._submit(store)
        page = store.page_deletion_tombstones(
            "tenant-a", receipt["request_id"], None, 50
        )
        self.assertEqual(page["tombstones"], [])
        self.assertIsNone(page["recorded_at"])
        self.assertIsNone(page["evidence_digest"])
        self.assertIsNone(page["next_cursor"])

    def test_default_limit_is_100_and_max_is_1000(self):
        items = [
            _item("s0", f"op-{i:03d}", adapter=f"adapter-{i:03d}")
            for i in range(101)
        ]
        store, receipt = self._registered(items, scopes=["s0"])
        first = store.page_deletion_tombstones(
            "tenant-a", receipt["request_id"]
        )
        self.assertEqual(len(first["tombstones"]), 100)
        self.assertIsNotNone(first["next_cursor"])
        second = store.page_deletion_tombstones(
            "tenant-a", receipt["request_id"], first["next_cursor"]
        )
        self.assertEqual(len(second["tombstones"]), 1)
        self.assertIsNone(second["next_cursor"])

    def test_unicode_scope_order_is_code_point_order(self):
        # U+00E9 sorts after "z" by code point (and in UTF-8 bytes).
        scopes = ["zebra", "apple", "éclair"]
        items = [
            _item(scope, f"op-{scope}", adapter="adapter-a") for scope in scopes
        ]
        store, receipt = self._registered(items, scopes=scopes)
        page = store.page_deletion_tombstones(
            "tenant-a", receipt["request_id"], None, 10
        )
        self.assertEqual(
            [t["scope"] for t in page["tombstones"]], sorted(scopes)
        )
        self.assertEqual(
            [t["scope"] for t in page["tombstones"]],
            ["apple", "zebra", "éclair"],
        )

    def test_next_cursor_only_when_another_item_exists(self):
        items = [
            _item("email", "op-1", adapter="adapter-a"),
            _item("profile", "op-2", adapter="adapter-b"),
        ]
        store, receipt = self._registered(items)
        rid = receipt["request_id"]
        exact = store.page_deletion_tombstones("tenant-a", rid, None, 2)
        self.assertIsNone(exact["next_cursor"])
        first = store.page_deletion_tombstones("tenant-a", rid, None, 1)
        self.assertIsNotNone(first["next_cursor"])
        second = store.page_deletion_tombstones(
            "tenant-a", rid, first["next_cursor"], 1
        )
        self.assertEqual(len(second["tombstones"]), 1)
        self.assertIsNone(second["next_cursor"])


class CursorTest(_StoreCase):
    def _three(self):
        items = [
            _item("email", "op-1", adapter="adapter-a"),
            _item("profile", "op-2", adapter="adapter-b"),
            _item("profile", "op-3", adapter="adapter-c"),
        ]
        store = self._store()
        receipt = self._submit(store)
        self._ledger(store, receipt, items)
        return store, receipt

    def test_same_cursor_replays_same_bytes_and_position(self):
        store, receipt = self._three()
        rid = receipt["request_id"]
        first = store.page_deletion_tombstones("tenant-a", rid, None, 1)
        cursor = first["next_cursor"]
        replay_a = store.page_deletion_tombstones("tenant-a", rid, cursor, 1)
        replay_b = store.page_deletion_tombstones("tenant-a", rid, cursor, 1)
        self.assertEqual(replay_a, replay_b)
        self.assertEqual(_serialized(replay_a), _serialized(replay_b))
        # The page resumes strictly after the issuing page's last item.
        self.assertEqual(replay_a["tombstones"][0]["operation_id"], "op-2")

    def test_cursor_unaffected_by_later_limit(self):
        store, receipt = self._three()
        rid = receipt["request_id"]
        full = store.get_deletion_tombstones("tenant-a", rid)["tombstones"]
        first = store.page_deletion_tombstones("tenant-a", rid, None, 1)
        with_large_limit = store.page_deletion_tombstones(
            "tenant-a", rid, first["next_cursor"], 1000
        )
        with_small_limit = store.page_deletion_tombstones(
            "tenant-a", rid, first["next_cursor"], 1
        )
        self.assertEqual(
            [t["operation_id"] for t in with_large_limit["tombstones"]],
            ["op-2", "op-3"],
        )
        self.assertEqual(
            with_small_limit["tombstones"][0]["operation_id"],
            full[1]["operation_id"],
        )

    def test_cursor_reusable_after_restart(self):
        store, receipt = self._three()
        rid = receipt["request_id"]
        first = store.page_deletion_tombstones("tenant-a", rid, None, 1)
        rebuilt = self._store()
        second = rebuilt.page_deletion_tombstones(
            "tenant-a", rid, first["next_cursor"], 1
        )
        self.assertEqual(second["tombstones"][0]["operation_id"], "op-2")
        again = rebuilt.page_deletion_tombstones(
            "tenant-a", rid, first["next_cursor"], 1
        )
        self.assertEqual(_serialized(second), _serialized(again))

    def test_ledger_change_invalidates_bound_snapshot(self):
        items = [
            _item("email", "op-1", adapter="adapter-a"),
            _item("profile", "op-2", adapter="adapter-b"),
        ]
        store = self._store()
        receipt = self._submit(store)
        claim, _ = self._ledger(store, receipt, items)
        rid = receipt["request_id"]
        first = store.page_deletion_tombstones("tenant-a", rid, None, 1)
        # A later registration extends the ledger and changes the
        # snapshot the cursor was bound to.
        store.record_deletion_tombstones(
            "tenant-a",
            rid,
            claim["claim_token"],
            [_item("email", "op-9", adapter="adapter-z")],
        )
        with self.assertRaises(ValueError) as caught:
            store.page_deletion_tombstones(
                "tenant-a", rid, first["next_cursor"], 1
            )
        self.assertEqual(str(caught.exception), "deletion_tombstone_page_failed")

    def test_cursor_survives_completion_without_new_tombstones(self):
        items = [
            _item("email", "op-1", adapter="adapter-a"),
            _item("profile", "op-2", adapter="adapter-b"),
        ]
        store = self._store()
        receipt = self._submit(store)
        claim, _ = self._ledger(store, receipt, items)
        rid = receipt["request_id"]
        first = store.page_deletion_tombstones("tenant-a", rid, None, 1)
        store.finish_scoped_claim(
            "tenant-a", rid, claim["claim_token"], "completed"
        )
        second = store.page_deletion_tombstones(
            "tenant-a", rid, first["next_cursor"], 1
        )
        self.assertEqual(second["tombstones"][0]["operation_id"], "op-2")
        full = store.get_deletion_tombstones("tenant-a", rid)
        self.assertEqual(second["evidence_digest"], full["evidence_digest"])

    def test_cursor_binds_tenant_and_request(self):
        store = self._store()
        one = self._submit(store, tenant="tenant-a", key="key-1")
        two = self._submit(store, tenant="tenant-a", key="key-2")
        other = self._submit(store, tenant="tenant-b", key="key-3")
        claim_a = store.claim_next("tenant-a", "worker-1", 60)
        store.record_deletion_tombstones(
            "tenant-a", one["request_id"], claim_a["claim_token"],
            [_item("email", "op-1", adapter="adapter-a")],
        )
        claim_a2 = store.claim_next("tenant-a", "worker-1", 60)
        store.record_deletion_tombstones(
            "tenant-a", two["request_id"], claim_a2["claim_token"],
            [_item("email", "op-2", adapter="adapter-a")],
        )
        cursor = store.page_deletion_tombstones(
            "tenant-a", one["request_id"], None, 1
        )["next_cursor"]
        self.assertIsNone(cursor)
        # Force a cursor to exist by registering a second row on request one.
        store.record_deletion_tombstones(
            "tenant-a", one["request_id"], claim_a["claim_token"],
            [_item("profile", "op-11", adapter="adapter-a")],
        )
        cursor = store.page_deletion_tombstones(
            "tenant-a", one["request_id"], None, 1
        )["next_cursor"]
        self.assertIsNotNone(cursor)
        # Same tenant, different request.
        with self.assertRaises(ValueError) as caught:
            store.page_deletion_tombstones("tenant-a", two["request_id"], cursor, 1)
        self.assertEqual(str(caught.exception), "deletion_tombstone_page_failed")
        # Different tenant (its request exists): binding mismatch wins.
        claim_b = store.claim_next("tenant-b", "worker-1", 60)
        store.record_deletion_tombstones(
            "tenant-b", other["request_id"], claim_b["claim_token"],
            [_item("email", "op-21", adapter="adapter-a")],
        )
        with self.assertRaises(ValueError):
            store.page_deletion_tombstones("tenant-b", other["request_id"], cursor, 1)

    def test_foreign_and_forged_cursors_rejected(self):
        store, receipt = self._three()
        rid = receipt["request_id"]
        bad_cursors = [
            "",
            "garbage",
            "dt1.",
            "dt1.###",
            "dt1.bm90LXBhcnNl",  # valid b64, non-JSON payload
            "rl1.x",
            "rc1.x",
            "ai1.x",
            "em1.x",
            123,
            True,
            b"dt1.x",
            [],
            {},
        ]
        # A listing cursor for this tenant is still a foreign format here.
        listing = store.list_requests("tenant-a")["next_cursor"]
        if listing is not None:
            bad_cursors.append(listing)
        for bad in bad_cursors:
            with self.assertRaises(ValueError) as caught:
                store.page_deletion_tombstones("tenant-a", rid, bad, 1)
            self.assertEqual(
                str(caught.exception), "deletion_tombstone_page_failed"
            )

    def test_cursor_with_tampered_position_rejected(self):
        store, receipt = self._three()
        rid = receipt["request_id"]
        cursor = store.page_deletion_tombstones(
            "tenant-a", rid, None, 1
        )["next_cursor"]
        # Decode the envelope, move the resume position to a scope that
        # does not exist in the bound snapshot, re-encode it.
        body = cursor[len("dt1."):]
        payload = json.loads(base64.urlsafe_b64decode(body.encode("ascii")))
        payload["c"] = "no-such-scope"
        payload["a"] = "adapter-a"
        forged = "dt1." + base64.urlsafe_b64encode(
            json.dumps(payload, separators=(",", ":")).encode("utf-8")
        ).decode("ascii")
        with self.assertRaises(ValueError) as caught:
            store.page_deletion_tombstones("tenant-a", rid, forged, 1)
        self.assertEqual(str(caught.exception), "deletion_tombstone_page_failed")


class ValidationTest(_StoreCase):
    def setUp(self):
        super().setUp()
        store = self._store()
        self.store = store
        self.receipt = self._submit(store)

    def test_bad_tenant_is_value_error(self):
        rid = self.receipt["request_id"]
        for bad in ("", None, 7, True, b"tenant-a", []):
            with self.assertRaises(ValueError) as caught:
                self.store.page_deletion_tombstones(bad, rid, None, 1)
            self.assertEqual(
                str(caught.exception), "deletion_tombstone_page_failed"
            )

    def test_bad_request_is_not_found(self):
        rid = self.receipt["request_id"]
        for bad in ("", None, 7, b"x", []):
            with self.assertRaises(RequestNotFound):
                self.store.page_deletion_tombstones("tenant-a", bad, None, 1)
        with self.assertRaises(RequestNotFound):
            self.store.page_deletion_tombstones("tenant-a", "missing", None, 1)
        with self.assertRaises(RequestNotFound):
            self.store.page_deletion_tombstones("tenant-b", rid, None, 1)

    def test_bad_limit_is_value_error_without_touching_store(self):
        rid = self.receipt["request_id"]
        bad_limits = [0, -1, 1001, 1.5, "10", b"10", True, False, [], {}]
        for bad in bad_limits:
            with self.assertRaises(ValueError) as caught:
                self.store.page_deletion_tombstones("tenant-a", rid, None, bad)
            self.assertEqual(
                str(caught.exception), "deletion_tombstone_page_failed"
            )
        # Boundary values are accepted.
        self.assertEqual(
            len(
                self.store.page_deletion_tombstones("tenant-a", rid, None, 1)[
                    "tombstones"
                ]
            ),
            0,
        )
        self.store.page_deletion_tombstones("tenant-a", rid, None, 1000)


class ReadOnlyTest(_StoreCase):
    def test_paging_does_not_advance_state(self):
        items = [
            _item("email", "op-1", adapter="adapter-a"),
            _item("profile", "op-2", adapter="adapter-b"),
        ]
        store = self._store()
        receipt = self._submit(store)
        claim, _ = self._ledger(store, receipt, items)
        rid = receipt["request_id"]
        before_log = store.get_execution_log("tenant-a", rid)
        for cursor in (None,):
            page = store.page_deletion_tombstones("tenant-a", rid, cursor, 1)
            store.page_deletion_tombstones(
                "tenant-a", rid, page["next_cursor"], 1
            )
        self.assertEqual(
            store.get_status("tenant-a", rid)["status"], "processing"
        )
        self.assertEqual(
            store.get_execution_log("tenant-a", rid), before_log
        )
        # The lease is still live and usable for a scoped completion.
        store.finish_scoped_claim(
            "tenant-a", rid, claim["claim_token"], "completed"
        )
        self.assertEqual(
            store.get_status("tenant-a", rid)["status"], "completed"
        )
        ledger = store.get_deletion_tombstones("tenant-a", rid)
        self.assertEqual(len(ledger["tombstones"]), 2)


class CorruptionTest(_StoreCase):
    def _raw(self):
        conn = sqlite3.connect(self.db_path)
        conn.isolation_level = None
        return conn

    def test_corrupt_tombstone_row_raises_fixed_oserror(self):
        store = self._store()
        receipt = self._submit(store)
        self._ledger(store, receipt, [_item("email", "op-1", adapter="adapter-a")])
        conn = self._raw()
        try:
            conn.execute(
                "UPDATE deletion_tombstones SET outcome = 'purged' "
                "WHERE operation_id = 'op-1'"
            )
        finally:
            conn.close()
        with self.assertRaises(OSError) as caught:
            store.page_deletion_tombstones(
                "tenant-a", receipt["request_id"], None, 10
            )
        self.assertEqual(str(caught.exception), "deletion_tombstone_failed")

    def test_corrupt_finish_row_raises_fixed_oserror(self):
        store = self._store()
        receipt = self._submit(store)
        claim, _ = self._ledger(
            store,
            receipt,
            [
                _item("email", "op-1", adapter="adapter-a"),
                _item("profile", "op-2", adapter="adapter-b"),
            ],
        )
        rid = receipt["request_id"]
        store.finish_scoped_claim(
            "tenant-a", rid, claim["claim_token"], "completed"
        )
        conn = self._raw()
        try:
            conn.execute(
                "UPDATE deletion_tombstone_finishes SET result = 'purged' "
                "WHERE request_id = ?",
                (rid,),
            )
        finally:
            conn.close()
        with self.assertRaises(OSError) as caught:
            store.page_deletion_tombstones("tenant-a", rid, None, 10)
        self.assertEqual(str(caught.exception), "deletion_tombstone_failed")

    def test_divergent_finish_digest_raises_fixed_oserror(self):
        store = self._store()
        receipt = self._submit(store)
        claim, _ = self._ledger(
            store,
            receipt,
            [
                _item("email", "op-1", adapter="adapter-a"),
                _item("profile", "op-2", adapter="adapter-b"),
            ],
        )
        rid = receipt["request_id"]
        store.finish_scoped_claim(
            "tenant-a", rid, claim["claim_token"], "completed"
        )
        conn = self._raw()
        try:
            conn.execute(
                "UPDATE deletion_tombstone_finishes SET evidence_digest = ? "
                "WHERE request_id = ?",
                ("a" * 64, rid),
            )
        finally:
            conn.close()
        with self.assertRaises(OSError) as caught:
            store.page_deletion_tombstones("tenant-a", rid, None, 10)
        self.assertEqual(str(caught.exception), "deletion_tombstone_failed")


if __name__ == "__main__":
    unittest.main()
