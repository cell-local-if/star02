"""Tests for the storage-layer subject/data-scope resolution entry.

``RequestStore.resolve_scopes`` reads the same tenant's already accepted
requests for one subject from a single read-only snapshot and returns the
normalized selectors together with a stable, detail-free conflict list.
It never creates a request or writes anything.
"""

import os
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor

from forgetting_evidence.requests import RequestStore


class ScopeResolutionTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "evidence.db")
        self.store = RequestStore(self.db_path)

    def tearDown(self):
        self._tmp.cleanup()

    def _submit(self, subject, scopes, key, tenant="tenant-a"):
        return self.store.submit(tenant, subject, scopes, key)

    # -- normalization -------------------------------------------------

    def test_concrete_entries_sort_by_unicode_code_point(self):
        result = self.store.resolve_scopes(
            "tenant-a", "subject-1", ["b:x", "a_b:x", "a.b:x", "a-b:x"]
        )
        self.assertEqual(
            result["scopes"], ["a-b:x", "a.b:x", "a_b:x", "b:x"]
        )
        self.assertEqual(result["conflicts"], [])

    def test_whole_collection_dominates_its_entries(self):
        result = self.store.resolve_scopes(
            "tenant-a",
            "subject-1",
            ["users:a", "users*", "users:b", "orders:o1"],
        )
        self.assertEqual(result["scopes"], ["orders:o1", "users*"])

    def test_whole_data_dominates_every_other_selector(self):
        result = self.store.resolve_scopes(
            "tenant-a",
            "subject-1",
            ["users:a", "users*", "orders:o1", "*"],
        )
        self.assertEqual(result["scopes"], ["*"])

    def test_selector_alphabet_and_shapes_accepted(self):
        accepted = [
            "*",
            "users*",
            "users:alice",
            "a-b.c_d:x-y.z_w",
            "0:1",
            "orders_2026:item-9.1",
        ]
        for selector in accepted:
            result = self.store.resolve_scopes(
                "tenant-a", "empty-subject", [selector, "other:keep"]
                if selector != "*"
                else [selector]
            )
            self.assertIn(selector if selector == "*" else "other:keep",
                          result["scopes"])

    def test_repeated_resolution_and_rebuild_are_stable(self):
        scopes = ["users:b", "users*", "orders:o1"]
        first = self.store.resolve_scopes("tenant-a", "subject-1", scopes)
        second = self.store.resolve_scopes("tenant-a", "subject-1", scopes)
        rebuilt = RequestStore(self.db_path).resolve_scopes(
            "tenant-a", "subject-1", scopes
        )
        self.assertEqual(first, second)
        self.assertEqual(first, rebuilt)
        self.assertEqual(list(first), ["scopes", "conflicts"])

    def test_result_uses_only_fixed_keys_and_json_safe_values(self):
        receipt = self._submit("subject-1", ["users:a"], "key-1")
        self.store.transition("tenant-a", receipt["request_id"], "processing")
        self.store.transition("tenant-a", receipt["request_id"], "completed")
        result = self.store.resolve_scopes(
            "tenant-a", "subject-1", ["users:a"]
        )
        self.assertEqual(list(result), ["scopes", "conflicts"])
        self.assertIsInstance(result["scopes"], list)
        self.assertIsInstance(result["conflicts"], list)
        for item in result["conflicts"]:
            self.assertEqual(list(item), ["request_id", "status"])
            self.assertIsInstance(item["request_id"], str)
            self.assertIsInstance(item["status"], str)
        import json

        # Round-trips through JSON with only strings/ints/bools/None and
        # no float can ever appear in this shape.
        encoded = json.dumps(result)
        self.assertEqual(json.loads(encoded), result)

    # -- conflicts -----------------------------------------------------

    def test_same_concrete_entry_conflicts(self):
        self._submit("subject-1", ["users:a", "users:b"], "key-1")
        result = self.store.resolve_scopes(
            "tenant-a", "subject-1", ["users:a"]
        )
        self.assertEqual(len(result["conflicts"]), 1)
        self.assertEqual(result["conflicts"][0]["status"], "accepted")

    def test_different_entries_do_not_conflict(self):
        self._submit("subject-1", ["users:a"], "key-1")
        result = self.store.resolve_scopes(
            "tenant-a", "subject-1", ["users:b"]
        )
        self.assertEqual(result["conflicts"], [])

    def test_whole_collection_conflicts_with_group_and_entries(self):
        group = self._submit("subject-1", ["orders*"], "key-1")
        entry = self._submit("subject-1", ["media:one"], "key-2")
        self.store.transition("tenant-a", group["request_id"], "processing")

        incoming_group = self.store.resolve_scopes(
            "tenant-a", "subject-1", ["orders:fresh"]
        )
        self.assertEqual(
            incoming_group["conflicts"],
            [{"request_id": group["request_id"], "status": "processing"}],
        )

        outgoing_group = self.store.resolve_scopes(
            "tenant-a", "subject-1", ["media*"]
        )
        self.assertEqual(
            outgoing_group["conflicts"],
            [{"request_id": entry["request_id"], "status": "accepted"}],
        )

        same_group = self.store.resolve_scopes(
            "tenant-a", "subject-1", ["orders*"]
        )
        self.assertEqual(
            same_group["conflicts"],
            [{"request_id": group["request_id"], "status": "processing"}],
        )
        # Different collections never conflict.
        self.assertEqual(
            self.store.resolve_scopes(
                "tenant-a", "subject-1", ["archive*", "media:other"]
            )["conflicts"],
            [],
        )

    def test_whole_data_conflicts_with_every_range(self):
        first = self._submit("subject-1", ["users:a"], "key-1")
        second = self._submit("subject-1", ["orders*"], "key-2")
        result = self.store.resolve_scopes(
            "tenant-a", "subject-1", ["*"]
        )
        self.assertEqual(
            [item["request_id"] for item in result["conflicts"]],
            [first["request_id"], second["request_id"]],
        )

    def test_conflicts_ignore_other_subjects_and_tenants(self):
        self._submit("subject-1", ["users:a"], "key-1")
        self._submit("subject-2", ["users:a"], "key-2")
        self._submit("subject-1", ["users:a"], "key-3", tenant="tenant-b")
        result = self.store.resolve_scopes(
            "tenant-a", "subject-1", ["users:a"]
        )
        self.assertEqual(len(result["conflicts"]), 1)

    def test_conflicts_ordered_by_acceptance_time_then_request_id(self):
        receipts = [
            self._submit("subject-1", [f"coll:item-{i}"], f"key-{i}")
            for i in range(5)
        ]
        # Resolve with the whole-data selector so every request conflicts;
        # the SQL order is (created_at, request_id), the same stable order
        # every other sweep uses.
        result = self.store.resolve_scopes("tenant-a", "subject-1", ["*"])
        self.assertEqual(
            [item["request_id"] for item in result["conflicts"]],
            [receipt["request_id"] for receipt in receipts],
        )
        for receipt in receipts:
            self.assertNotIn("subject_id", result)
            self.assertNotIn("scopes_json", result)

    def test_conflict_reflects_current_status(self):
        receipt = self._submit("subject-1", ["users:a"], "key-1")
        self.store.transition("tenant-a", receipt["request_id"], "processing")
        self.store.transition("tenant-a", receipt["request_id"], "completed")
        result = self.store.resolve_scopes(
            "tenant-a", "subject-1", ["users:a"]
        )
        self.assertEqual(
            result["conflicts"],
            [{"request_id": receipt["request_id"], "status": "completed"}],
        )

    def test_legacy_free_form_scope_only_conflicts_with_whole_data(self):
        # A database written before the selector grammar may carry a
        # non-empty free-form scope; such a range can only be covered by
        # the whole-data selector.
        receipt = self._submit("subject-1", ["legacy_email"], "key-1")
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE requests SET scopes_json = ? WHERE request_id = ?",
                ('["legacy_email"]', receipt["request_id"]),
            )
            conn.commit()
        self.assertEqual(
            self.store.resolve_scopes(
                "tenant-a", "subject-1", ["users:a"]
            )["conflicts"],
            [],
        )
        self.assertEqual(
            self.store.resolve_scopes(
                "tenant-a", "subject-1", ["*"]
            )["conflicts"],
            [{"request_id": receipt["request_id"], "status": "accepted"}],
        )

    # -- read-only / snapshot behaviour --------------------------------

    def test_resolution_never_writes(self):
        self._submit("subject-1", ["users:a"], "key-1")
        with sqlite3.connect(self.db_path) as conn:
            before = {
                table: conn.execute(
                    f"SELECT count(*) FROM {table}"
                ).fetchone()[0]
                for table in (
                    "requests",
                    "status_events",
                    "claim_attempts",
                    "claim_tokens",
                    "inspection_batches",
                    "inspection_batch_items",
                    "audit_anchors",
                    "deletion_receipts",
                )
            }
        for _ in range(3):
            self.store.resolve_scopes(
                "tenant-a", "subject-1", ["users:a", "users*"]
            )
        with sqlite3.connect(self.db_path) as conn:
            after = {
                table: conn.execute(
                    f"SELECT count(*) FROM {table}"
                ).fetchone()[0]
                for table in before
            }
        self.assertEqual(before, after)

    def test_concurrent_read_only_calls_share_consistent_results(self):
        for i in range(20):
            self._submit("subject-1", [f"coll:item-{i}"], f"key-{i}")
        scopes = ["*"]
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(
                pool.map(
                    lambda _: self.store.resolve_scopes(
                        "tenant-a", "subject-1", scopes
                    ),
                    range(16),
                )
            )
        for result in results:
            self.assertEqual(result, results[0])
            self.assertEqual(len(result["conflicts"]), 20)

    def test_snapshot_excludes_requests_from_other_subjects(self):
        self._submit("subject-1", ["users:a"], "key-1")
        result = self.store.resolve_scopes(
            "tenant-a", "missing-subject", ["*"]
        )
        self.assertEqual(result, {"scopes": ["*"], "conflicts": []})

    # -- ValueError contract -------------------------------------------

    def test_blank_tenant_or_subject_rejected(self):
        bad_identities = [None, "", "   ", "\t\n", 7, b"x", True, ["x"]]
        for bad in bad_identities:
            with self.assertRaises(ValueError):
                self.store.resolve_scopes(bad, "subject-1", ["users:a"])
            with self.assertRaises(ValueError):
                self.store.resolve_scopes("tenant-a", bad, ["users:a"])
        # Identity validation never depends on whether records exist.
        with self.assertRaises(ValueError):
            self.store.resolve_scopes("   ", "ghost", ["users:a"])

    def test_invalid_scope_sequences_rejected_without_writes(self):
        bad_scopes = [
            [],
            (),
            ["users:a", "users:a"],
            ["*", "*"],
            [None],
            [""],
            ["users:a", ""],
            [7],
            [True],
            [1.5],
            ["users:a", 3],
            "users:a",
            b"users:a",
            [b"users:a"],
            {"users:a": 1},
        ]
        for bad in bad_scopes:
            with self.assertRaises(ValueError):
                self.store.resolve_scopes("tenant-a", "subject-1", bad)
        with sqlite3.connect(self.db_path) as conn:
            self.assertEqual(
                conn.execute("SELECT count(*) FROM requests").fetchone()[0], 0
            )

    def test_illegal_selectors_rejected(self):
        bad_selectors = [
            ["users"],
            ["users:"],
            [":entry"],
            ["Users:a"],
            ["users:A"],
            [" users:a"],
            ["users:a "],
            ["users:a:b"],
            ["*x"],
            ["users**"],
            ["users:a*"],
            ["users :a"],
            ["users: a"],
            ["用户:a"],
            ["users:a\t"],
            ["-"],
            ["a:"],
        ]
        for bad in bad_selectors:
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    self.store.resolve_scopes("tenant-a", "subject-1", bad)

    def test_star_with_illegal_extra_selector_still_rejected(self):
        # Grammar validation precedes whole-data collapse: an illegal
        # element can never be silently dropped.
        with self.assertRaises(ValueError):
            self.store.resolve_scopes(
                "tenant-a", "subject-1", ["*", "illegal"]
            )

    def test_validation_errors_do_not_depend_on_existing_records(self):
        self._submit("subject-1", ["users:a"], "key-1")
        with self.assertRaises(ValueError):
            self.store.resolve_scopes("tenant-a", "subject-1", [])
        with self.assertRaises(ValueError):
            self.store.resolve_scopes("tenant-a", " ", ["users:a"])

    # -- OSError contract ----------------------------------------------

    def test_corrupt_scopes_json_raises_fixed_text_oserror(self):
        receipt = self._submit("subject-1", ["users:a"], "key-1")
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE requests SET scopes_json = 'not-json' "
                "WHERE request_id = ?",
                (receipt["request_id"],),
            )
            conn.commit()
        with self.assertRaises(OSError) as caught:
            self.store.resolve_scopes("tenant-a", "subject-1", ["users:a"])
        self.assertEqual(str(caught.exception), "scope_resolution_failed")

    def test_non_list_scopes_json_raises_fixed_text_oserror(self):
        receipt = self._submit("subject-1", ["users:a"], "key-1")
        for corrupted in ['"users:a"', "[]", '["users:a", 7]', "[null]"]:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "UPDATE requests SET scopes_json = ? WHERE request_id = ?",
                    (corrupted, receipt["request_id"]),
                )
                conn.commit()
            with self.assertRaises(OSError) as caught:
                self.store.resolve_scopes(
                    "tenant-a", "subject-1", ["users:a"]
                )
            self.assertEqual(
                str(caught.exception), "scope_resolution_failed"
            )

    def test_unknown_status_value_raises_fixed_text_oserror(self):
        receipt = self._submit("subject-1", ["users:a"], "key-1")
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE requests SET status = 'archived' WHERE request_id = ?",
                (receipt["request_id"],),
            )
            conn.commit()
        with self.assertRaises(OSError) as caught:
            self.store.resolve_scopes("tenant-a", "subject-1", ["users:a"])
        self.assertEqual(str(caught.exception), "scope_resolution_failed")

    def test_missing_requests_table_raises_fixed_text_oserror(self):
        receipt = self._submit("subject-1", ["users:a"], "key-1")
        self.assertTrue(receipt["request_id"])
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DROP TABLE requests")
            conn.commit()
        with self.assertRaises(OSError) as caught:
            self.store.resolve_scopes("tenant-a", "subject-1", ["users:a"])
        self.assertEqual(str(caught.exception), "scope_resolution_failed")


if __name__ == "__main__":
    unittest.main()
