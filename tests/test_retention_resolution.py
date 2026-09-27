"""Tests for the storage-layer retention policy resolution entry.

``RequestStore.resolve_retention`` normalizes the requested scopes,
reads the subject's accepted requests from a single read-only snapshot
and resolves the effective retention from the ordinary rule catalog and
the subject exception catalog alone. It never creates a request or
writes anything.
"""

import json
import os
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor

from forgetting_evidence.requests import RequestStore


def _rule(selector, days, reason="ordinary reason"):
    return {"selector": selector, "days": days, "reason": reason}


def _exception(subject, selector, days, reason="exception reason"):
    return {
        "subject": subject,
        "selector": selector,
        "days": days,
        "reason": reason,
    }


class RetentionResolutionTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "evidence.db")
        self.store = RequestStore(self.db_path)
        self.rules = {
            "p-default": _rule("*", 30, "default retention"),
        }

    def tearDown(self):
        self._tmp.cleanup()

    def _submit(self, subject, scopes, key, tenant="tenant-a"):
        return self.store.submit(tenant, subject, scopes, key)

    def _resolve(self, scopes, rules=None, exceptions=None,
                 tenant="tenant-a", subject="subject-1"):
        return self.store.resolve_retention(
            tenant,
            subject,
            scopes,
            self.rules if rules is None else rules,
            {} if exceptions is None else exceptions,
        )

    # -- basic resolution ----------------------------------------------

    def test_default_rule_governs_plain_scope(self):
        result = self._resolve(["users:alice"])
        self.assertEqual(
            result,
            {
                "retention_days": 30,
                "policy_id": "p-default",
                "exceptions": [],
                "reason": "default retention",
            },
        )
        self.assertEqual(
            list(result), ["retention_days", "policy_id", "exceptions", "reason"]
        )

    def test_result_uses_only_json_safe_values(self):
        rules = {
            "p-default": _rule("*", 30),
            "p-entry": _rule("users:alice", 90),
        }
        exceptions = {
            "x-1": _exception("subject-1", "users*", 180),
        }
        result = self._resolve(["users:alice"], rules=rules,
                               exceptions=exceptions)
        self.assertEqual(json.loads(json.dumps(result)), result)
        for item in result["exceptions"]:
            self.assertEqual(
                list(item), ["subject", "scope", "retention_days", "reason"]
            )

    def test_entry_rule_beats_collection_and_default(self):
        rules = {
            "p-default": _rule("*", 30),
            "p-group": _rule("users*", 60),
            "p-entry": _rule("users:alice", 90),
        }
        result = self._resolve(["users:alice"], rules=rules)
        self.assertEqual(result["retention_days"], 90)
        self.assertEqual(result["policy_id"], "p-entry")
        self.assertEqual(result["reason"], "ordinary reason")

    def test_collection_rule_beats_default_for_group_scope(self):
        rules = {
            "p-default": _rule("*", 30),
            "p-group": _rule("users*", 60),
            "p-entry": _rule("users:alice", 90),
        }
        # An entry rule never covers a whole-collection scope.
        result = self._resolve(["users*"], rules=rules)
        self.assertEqual(result["retention_days"], 60)
        self.assertEqual(result["policy_id"], "p-group")

    def test_whole_data_scope_only_matches_default(self):
        rules = {
            "p-default": _rule("*", 30),
            "p-group": _rule("users*", 60),
            "p-entry": _rule("users:alice", 90),
        }
        result = self._resolve(["*"], rules=rules)
        self.assertEqual(result["retention_days"], 30)
        self.assertEqual(result["policy_id"], "p-default")

    def test_effective_retention_is_max_across_scopes(self):
        rules = {
            "p-default": _rule("*", 30),
            "p-users": _rule("users*", 60),
            "p-entry": _rule("orders:o1", 120),
        }
        result = self._resolve(["orders:o1", "users:alice"], rules=rules)
        self.assertEqual(result["retention_days"], 120)
        self.assertEqual(result["policy_id"], "p-entry")

    def test_same_precedence_tie_breaks_by_policy_code_point(self):
        # Passing order is irrelevant: the smallest policy number by
        # Unicode code point wins inside one precedence level.
        rules = {
            "p-zulu": _rule("users:alice", 10, "z rule"),
            "p-alpha": _rule("users:alice", 20, "a rule"),
            "p-default": _rule("*", 30),
        }
        result = self._resolve(["users:alice"], rules=rules)
        self.assertEqual(result["policy_id"], "p-alpha")
        self.assertEqual(result["retention_days"], 20)
        self.assertEqual(result["reason"], "a rule")
        reversed_rules = dict(reversed(list(rules.items())))
        self.assertEqual(
            self._resolve(["users:alice"], rules=reversed_rules), result
        )

    # -- subject exceptions --------------------------------------------

    def test_exception_beats_ordinary_rule(self):
        exceptions = {"x-1": _exception("subject-1", "*", 365, "legal hold")}
        result = self._resolve(["users:alice"], exceptions=exceptions)
        self.assertEqual(result["retention_days"], 365)
        self.assertEqual(result["policy_id"], "x-1")
        self.assertEqual(result["reason"], "legal hold")
        self.assertEqual(
            result["exceptions"],
            [
                {
                    "subject": "subject-1",
                    "scope": "users:alice",
                    "retention_days": 365,
                    "reason": "legal hold",
                }
            ],
        )

    def test_default_level_exception_beats_entry_level_rule(self):
        rules = {
            "p-default": _rule("*", 30),
            "p-entry": _rule("users:alice", 90),
        }
        exceptions = {"x-1": _exception("subject-1", "*", 45, "hold")}
        result = self._resolve(["users:alice"], rules=rules,
                               exceptions=exceptions)
        self.assertEqual(result["retention_days"], 45)
        self.assertEqual(result["policy_id"], "x-1")

    def test_exception_precedence_and_tie_break(self):
        exceptions = {
            "x-z": _exception("subject-1", "users*", 100, "group hold"),
            "x-b": _exception("subject-1", "users:alice", 50, "b hold"),
            "x-a": _exception("subject-1", "users:alice", 75, "a hold"),
        }
        result = self._resolve(["users:alice"], exceptions=exceptions)
        # Entry-level exceptions beat the group-level one; the two entry
        # exceptions tie-break by policy number code point.
        self.assertEqual(result["policy_id"], "x-a")
        self.assertEqual(result["retention_days"], 75)

    def test_exceptions_for_other_subjects_do_not_apply(self):
        exceptions = {"x-1": _exception("subject-2", "*", 365)}
        result = self._resolve(["users:alice"], exceptions=exceptions)
        self.assertEqual(result["retention_days"], 30)
        self.assertEqual(result["policy_id"], "p-default")
        self.assertEqual(result["exceptions"], [])

    def test_exceptions_for_other_tenants_do_not_apply(self):
        exceptions = {"x-1": _exception("subject-1", "*", 365)}
        result = self._resolve(
            ["users:alice"], exceptions=exceptions, tenant="tenant-b"
        )
        self.assertEqual(result["retention_days"], 365)
        # The catalog is per call; the same call for another tenant with
        # no exceptions falls back to the ordinary rules.
        self.assertEqual(
            self._resolve(["users:alice"], tenant="tenant-b")["exceptions"],
            [],
        )

    def test_hit_exceptions_ordered_by_normalized_scope(self):
        exceptions = {
            "x-users": _exception("subject-1", "users*", 60, "users hold"),
            "x-orders": _exception("subject-1", "orders:o1", 90, "order hold"),
        }
        result = self._resolve(
            ["users:alice", "orders:o1", "media:m1"], exceptions=exceptions
        )
        self.assertEqual(
            [item["scope"] for item in result["exceptions"]],
            ["orders:o1", "users:alice"],
        )
        self.assertEqual(result["retention_days"], 90)
        self.assertEqual(result["reason"], "order hold")

    def test_reason_comes_from_max_determining_record(self):
        rules = {
            "p-default": _rule("*", 30),
            "p-big": _rule("users*", 400, "big ordinary"),
        }
        exceptions = {
            "x-1": _exception("subject-1", "orders:o1", 45, "small hold"),
        }
        result = self._resolve(
            ["orders:o1", "users:alice"], rules=rules, exceptions=exceptions
        )
        # The exception hits one scope but the ordinary 400-day rule
        # determines the maximum and therefore the reason.
        self.assertEqual(result["retention_days"], 400)
        self.assertEqual(result["policy_id"], "p-big")
        self.assertEqual(result["reason"], "big ordinary")
        self.assertEqual(len(result["exceptions"]), 1)

    # -- normalization reuse -------------------------------------------

    def test_scopes_normalize_like_scope_resolution(self):
        rules = {
            "p-default": _rule("*", 30),
            "p-group": _rule("users*", 60),
        }
        result = self._resolve(["users:a", "users*", "users:b"], rules=rules)
        self.assertEqual(result["retention_days"], 60)
        self.assertEqual(result["policy_id"], "p-group")

    def test_tuple_scope_sequence_accepted(self):
        result = self._resolve(("users:alice", "orders:o1"))
        self.assertEqual(result["retention_days"], 30)

    def test_unordered_or_iterator_scope_sets_rejected(self):
        bad_scopes = [
            "users:alice",
            b"users:alice",
            {"users:alice"},
            frozenset({"users:alice"}),
            {"users:alice": 1},
            iter(["users:alice"]),
            (s for s in ["users:alice"]),
        ]
        for bad in bad_scopes:
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(ValueError) as caught:
                    self._resolve(bad)
                self.assertEqual(
                    str(caught.exception),
                    "retention_policy_resolution_failed",
                )

    # -- ValueError contract -------------------------------------------

    def test_blank_tenant_or_subject_rejected(self):
        for bad in [None, "", "   ", "\t\n", 7, b"x", True, ["x"]]:
            with self.assertRaises(ValueError):
                self.store.resolve_retention(
                    bad, "subject-1", ["users:a"], self.rules, {}
                )
            with self.assertRaises(ValueError):
                self.store.resolve_retention(
                    "tenant-a", bad, ["users:a"], self.rules, {}
                )

    def test_invalid_scope_contents_rejected(self):
        bad_scopes = [
            [],
            (),
            ["users:a", "users:a"],
            [None],
            [""],
            [7],
            [True],
            ["users"],
            ["Users:a"],
            ["users:a", "illegal"],
            ["*", "*"],
        ]
        for bad in bad_scopes:
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    self._resolve(bad)

    def test_missing_default_rule_rejected(self):
        with self.assertRaises(ValueError) as caught:
            self._resolve(["users:a"], rules={"p-1": _rule("users*", 10)})
        self.assertEqual(
            str(caught.exception), "retention_policy_resolution_failed"
        )
        with self.assertRaises(ValueError):
            self._resolve(["users:a"], rules={})

    def test_non_mapping_catalogs_rejected(self):
        for bad in [None, [], "rules", 7, True, [("p", _rule("*", 1))]]:
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(ValueError):
                    self.store.resolve_retention(
                        "tenant-a", "subject-1", ["users:a"], bad, {}
                    )
                with self.assertRaises(ValueError):
                    self.store.resolve_retention(
                        "tenant-a", "subject-1", ["users:a"], self.rules, bad
                    )

    def test_illegal_policy_numbers_rejected(self):
        for bad_id in [None, "", 7, True, b"p"]:
            with self.subTest(bad_id=repr(bad_id)):
                with self.assertRaises(ValueError):
                    self._resolve(["users:a"], rules={bad_id: _rule("*", 1)})
                with self.assertRaises(ValueError):
                    self._resolve(
                        ["users:a"],
                        exceptions={bad_id: _exception("subject-1", "*", 1)},
                    )

    def test_duplicate_policy_number_across_catalogs_rejected(self):
        exceptions = {"p-default": _exception("subject-1", "*", 5)}
        with self.assertRaises(ValueError) as caught:
            self._resolve(["users:a"], exceptions=exceptions)
        self.assertEqual(
            str(caught.exception), "retention_policy_resolution_failed"
        )

    def test_illegal_selectors_rejected(self):
        for bad_selector in ["users", "users:", ":e", "Users:a", "*x",
                             "users**", "users:a*", " users:a", "", 7, None]:
            with self.subTest(bad_selector=repr(bad_selector)):
                with self.assertRaises(ValueError):
                    self._resolve(
                        ["users:a"],
                        rules={"p-1": _rule(bad_selector, 1),
                               "p-d": _rule("*", 1)},
                    )
                with self.assertRaises(ValueError):
                    self._resolve(
                        ["users:a"],
                        exceptions={
                            "x-1": _exception("subject-1", bad_selector, 1)
                        },
                    )

    def test_out_of_domain_days_rejected(self):
        for bad_days in [-1, -100, 1.5, "30", True, False, None, [30]]:
            with self.subTest(bad_days=repr(bad_days)):
                with self.assertRaises(ValueError):
                    self._resolve(
                        ["users:a"], rules={"p-d": _rule("*", bad_days)}
                    )
                with self.assertRaises(ValueError):
                    self._resolve(
                        ["users:a"],
                        exceptions={
                            "x-1": _exception("subject-1", "*", bad_days)
                        },
                    )
        # Zero days is a valid non-negative count.
        result = self._resolve(["users:a"], rules={"p-d": _rule("*", 0)})
        self.assertEqual(result["retention_days"], 0)

    def test_empty_reason_or_bad_shape_rejected(self):
        for bad_reason in ["", None, 7, ["r"]]:
            with self.subTest(bad_reason=repr(bad_reason)):
                with self.assertRaises(ValueError):
                    self._resolve(
                        ["users:a"], rules={"p-d": _rule("*", 1, bad_reason)}
                    )
        bad_shapes = [
            {"selector": "*", "days": 1},
            {"selector": "*", "days": 1, "reason": "r", "extra": 1},
            {"selector": "*"},
            "rule",
            None,
            ["*", 1, "r"],
        ]
        for bad in bad_shapes:
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(ValueError):
                    self._resolve(["users:a"], rules={"p-d": bad})

    def test_exception_subject_binding_validated(self):
        for bad_subject in [None, "", "   ", 7, True]:
            with self.subTest(bad_subject=repr(bad_subject)):
                with self.assertRaises(ValueError):
                    self._resolve(
                        ["users:a"],
                        exceptions={
                            "x-1": _exception(bad_subject, "*", 1)
                        },
                    )

    def test_validation_errors_never_write(self):
        with sqlite3.connect(self.db_path) as conn:
            before = conn.execute("SELECT count(*) FROM requests").fetchone()
        for call in (
            lambda: self._resolve([]),
            lambda: self._resolve(["users:a"], rules={}),
            lambda: self.store.resolve_retention(
                "tenant-a", "subject-1", ["users:a"], self.rules, None
            ),
        ):
            with self.assertRaises(ValueError):
                call()
        with sqlite3.connect(self.db_path) as conn:
            after = conn.execute("SELECT count(*) FROM requests").fetchone()
        self.assertEqual(before, after)

    # -- read-only / snapshot behaviour --------------------------------

    def test_resolution_never_writes(self):
        self._submit("subject-1", ["users:a"], "key-1")
        tables = (
            "requests",
            "status_events",
            "claim_attempts",
            "claim_tokens",
            "inspection_batches",
            "inspection_batch_items",
            "audit_anchors",
            "deletion_receipts",
        )
        with sqlite3.connect(self.db_path) as conn:
            before = {
                table: conn.execute(
                    f"SELECT count(*) FROM {table}"
                ).fetchone()[0]
                for table in tables
            }
        exceptions = {"x-1": _exception("subject-1", "users*", 60)}
        for _ in range(3):
            self._resolve(["users:a", "users*"], exceptions=exceptions)
        with sqlite3.connect(self.db_path) as conn:
            after = {
                table: conn.execute(
                    f"SELECT count(*) FROM {table}"
                ).fetchone()[0]
                for table in tables
            }
        self.assertEqual(before, after)

    def test_repeated_resolution_and_rebuild_are_stable(self):
        self._submit("subject-1", ["users:a"], "key-1")
        rules = {
            "p-default": _rule("*", 30),
            "p-entry": _rule("users:a", 90),
        }
        exceptions = {"x-1": _exception("subject-1", "users*", 120)}
        first = self._resolve(["users:a"], rules=rules, exceptions=exceptions)
        second = self._resolve(["users:a"], rules=rules, exceptions=exceptions)
        rebuilt = RequestStore(self.db_path).resolve_retention(
            "tenant-a", "subject-1", ["users:a"], rules, exceptions
        )
        self.assertEqual(first, second)
        self.assertEqual(first, rebuilt)

    def test_concurrent_read_only_calls_share_consistent_results(self):
        for i in range(10):
            self._submit("subject-1", [f"coll:item-{i}"], f"key-{i}")
        rules = {
            "p-default": _rule("*", 30),
            "p-group": _rule("coll*", 60),
        }
        exceptions = {"x-1": _exception("subject-1", "coll:item-3", 90)}
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(
                pool.map(
                    lambda _: self.store.resolve_retention(
                        "tenant-a",
                        "subject-1",
                        ["coll:item-3", "coll:item-4"],
                        rules,
                        exceptions,
                    ),
                    range(16),
                )
            )
        for result in results:
            self.assertEqual(result, results[0])
        self.assertEqual(results[0]["retention_days"], 90)

    def test_resolution_independent_of_existing_records(self):
        plain = self._resolve(["users:a"])
        self._submit("subject-1", ["users:a"], "key-1")
        self._submit("subject-1", ["users*"], "key-2")
        self.assertEqual(self._resolve(["users:a"]), plain)

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
            self._resolve(["users:a"])
        self.assertEqual(
            str(caught.exception), "retention_policy_resolution_failed"
        )

    def test_corrupt_status_raises_fixed_text_oserror(self):
        receipt = self._submit("subject-1", ["users:a"], "key-1")
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE requests SET status = 'archived' WHERE request_id = ?",
                (receipt["request_id"],),
            )
            conn.commit()
        with self.assertRaises(OSError) as caught:
            self._resolve(["users:a"])
        self.assertEqual(
            str(caught.exception), "retention_policy_resolution_failed"
        )

    def test_missing_requests_table_raises_fixed_text_oserror(self):
        self._submit("subject-1", ["users:a"], "key-1")
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DROP TABLE requests")
            conn.commit()
        with self.assertRaises(OSError) as caught:
            self._resolve(["users:a"])
        self.assertEqual(
            str(caught.exception), "retention_policy_resolution_failed"
        )

    def test_oserror_returns_no_partial_result(self):
        receipt = self._submit("subject-1", ["users:a"], "key-1")
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE requests SET scopes_json = '[null]' "
                "WHERE request_id = ?",
                (receipt["request_id"],),
            )
            conn.commit()
        try:
            self._resolve(["users:a"])
        except OSError as exc:
            self.assertEqual(
                str(exc), "retention_policy_resolution_failed"
            )
        else:
            self.fail("expected OSError")


if __name__ == "__main__":
    unittest.main()
