"""Tests for the read-only retention resolution trace entry.

``RequestStore.resolve_retention_trace`` decides exactly what
``resolve_retention`` decides but renders the decision evidence as one
compact JSON line: the catalog source, the queried subject, the
normalized scopes, the aggregate verdict and per-scope evidence. It is
strictly read-only and never returns the caller's raw scope sequence.
"""

import json
import os
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor

from forgetting_evidence.requests import (
    PolicyCatalogNotFound,
    RequestStore,
)

_FAILURE = "retention_policy_resolution_failed"
_HEADER_KEYS = [
    "catalog_source",
    "subject_id",
    "scopes",
    "retention_days",
    "policy_id",
    "reason",
    "exception",
    "scope_evidence",
]
_EVIDENCE_KEYS = ["scope", "level", "policy_id", "exception", "retention_days"]

_UNSET = object()


def _rule(selector, days, reason="ordinary reason"):
    return {"selector": selector, "days": days, "reason": reason}


def _exception(subject, selector, days, reason="exception reason"):
    return {
        "subject": subject,
        "selector": selector,
        "days": days,
        "reason": reason,
    }


class RetentionTraceTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "evidence.db")
        self.store = RequestStore(self.db_path)
        self.rules = {
            "p-default": _rule("*", 30, "default retention"),
            "p-users": _rule("users*", 60, "users group"),
        }
        self.exceptions = {
            "x-alice": _exception("subject-1", "users:alice", 365, "legal hold"),
        }

    def tearDown(self):
        self._tmp.cleanup()

    def _publish(self, tenant="tenant-a", rules=None, exceptions=None):
        return self.store.publish_policy_catalog(
            tenant,
            self.rules if rules is None else rules,
            self.exceptions if exceptions is None else exceptions,
        )

    def _trace(self, scopes, rules=_UNSET, exceptions=_UNSET, version=None,
               tenant="tenant-a", subject="subject-1"):
        kwargs = {}
        if version is not None:
            kwargs["version"] = version
        else:
            kwargs["rules"] = self.rules if rules is _UNSET else rules
            kwargs["exceptions"] = (
                {} if exceptions is _UNSET else exceptions
            )
        return self.store.resolve_retention_trace(
            tenant, subject, scopes, **kwargs
        )

    def _doc(self, *args, **kwargs):
        text = self._trace(*args, **kwargs)
        self.assertIsInstance(text, str)
        # Exactly one trailing newline, no other line break, and the
        # whole body is canonical compact JSON: no presentation
        # whitespace outside string values, field order preserved.
        self.assertTrue(text.endswith("\n"))
        self.assertFalse(text.endswith("\n\n"))
        self.assertNotIn("\n", text[:-1])
        doc = json.loads(text)
        canonical = (
            json.dumps(doc, ensure_ascii=False, separators=(",", ":")) + "\n"
        )
        self.assertEqual(text, canonical)
        return doc

    # -- text and shape -------------------------------------------------

    def test_text_shape_and_field_order(self):
        doc = self._doc(["users:alice"], exceptions=self.exceptions)
        self.assertEqual(list(doc), _HEADER_KEYS)
        self.assertIsInstance(doc["retention_days"], int)
        self.assertIsInstance(doc["exception"], bool)
        for item in doc["scope_evidence"]:
            self.assertEqual(list(item), _EVIDENCE_KEYS)
            self.assertIsInstance(item["retention_days"], int)
            self.assertIsInstance(item["exception"], bool)

    def test_header_values_for_call_time_source(self):
        doc = self._doc(["users:alice"], exceptions=self.exceptions)
        self.assertEqual(doc["catalog_source"], "call_time")
        self.assertEqual(doc["subject_id"], "subject-1")
        self.assertEqual(doc["scopes"], ["users:alice"])
        self.assertEqual(doc["retention_days"], 365)
        self.assertEqual(doc["policy_id"], "x-alice")
        self.assertEqual(doc["reason"], "legal hold")
        self.assertIs(doc["exception"], True)

    def test_raw_scope_sequence_is_never_returned(self):
        # A different passing order and a group/entry collapse never
        # surface; only normalized scopes come back.
        doc = self._doc(["users:bob", "users:alice", "users*"],
                        exceptions=self.exceptions)
        self.assertEqual(doc["scopes"], ["users*"])
        self.assertEqual(
            [item["scope"] for item in doc["scope_evidence"]], ["users*"]
        )
        doc = self._doc(["users:bob", "users:alice"])
        self.assertEqual(doc["scopes"], ["users:alice", "users:bob"])

    def test_values_are_plain_json_types(self):
        doc = self._doc(["users:alice", "orders:o1"],
                        exceptions=self.exceptions)
        encoded = json.dumps(doc)
        self.assertEqual(json.loads(encoded), doc)
        # Booleans must never render as 0/1 and counts never as floats.
        text = self._trace(["users:alice"], exceptions=self.exceptions)
        self.assertIn('"exception":true', text)
        self.assertNotIn("365.0", text)

    def test_strings_keep_their_original_text(self):
        rules = {
            "p-default": _rule("*", 30, " 默认 理由 "),
        }
        text = self._trace(["media:m1"], rules=rules, exceptions={})
        self.assertIn(" 默认 理由 ", text)
        exceptions = {
            "x-1": _exception("subject-1", "*", 90, 'quote "x" ünicode'),
        }
        text = self._trace(["users:alice"], rules=rules, exceptions=exceptions)
        self.assertIn('quote \\"x\\" ünicode', text)
        doc = json.loads(text)
        self.assertEqual(doc["reason"], 'quote "x" ünicode')

    # -- per-scope evidence --------------------------------------------

    def test_levels_entry_group_and_all(self):
        rules = {
            "p-default": _rule("*", 30, "def"),
            "p-users": _rule("users*", 60, "grp"),
            "p-alice": _rule("users:alice", 90, "ent"),
        }
        entry = self._doc(["users:alice"], rules=rules)
        self.assertEqual(entry["scope_evidence"][0]["level"], "entry")
        group = self._doc(["users*"], rules=rules)
        self.assertEqual(group["scope_evidence"][0]["level"], "group")
        whole = self._doc(["*"], rules=rules)
        self.assertEqual(whole["scope_evidence"][0]["level"], "all")
        other = self._doc(["media:m1"], rules=rules)
        self.assertEqual(other["scope_evidence"][0]["level"], "all")

    def test_exception_flag_follows_the_scope_winner(self):
        rules = {
            "p-default": _rule("*", 30, "def"),
            "p-big": _rule("media*", 400, "big"),
        }
        doc = self._doc(
            ["users:alice", "media:m1"], rules=rules, exceptions=self.exceptions
        )
        by_scope = {
            item["scope"]: item for item in doc["scope_evidence"]
        }
        self.assertIs(by_scope["media:m1"]["exception"], False)
        self.assertEqual(by_scope["media:m1"]["policy_id"], "p-big")
        self.assertIs(by_scope["users:alice"]["exception"], True)
        self.assertEqual(by_scope["users:alice"]["policy_id"], "x-alice")

    def test_exception_outranks_ordinary_rule_in_evidence(self):
        rules = {
            "p-default": _rule("*", 30, "def"),
            "p-alice": _rule("users:alice", 90, "ent"),
        }
        doc = self._doc(["users:alice"], rules=rules, exceptions=self.exceptions)
        item = doc["scope_evidence"][0]
        self.assertEqual(item["policy_id"], "x-alice")
        self.assertEqual(item["level"], "entry")
        self.assertEqual(item["retention_days"], 365)
        self.assertIs(item["exception"], True)

    def test_same_priority_tie_breaks_by_policy_code_point(self):
        rules = {
            "p-default": _rule("*", 30, "def"),
            "p-z": _rule("users:alice", 10, "z"),
            "p-a": _rule("users:alice", 20, "a"),
        }
        doc = self._doc(["users:alice"], rules=rules)
        self.assertEqual(doc["scope_evidence"][0]["policy_id"], "p-a")
        # Catalog passing order cannot change the winner.
        reversed_rules = dict(reversed(list(rules.items())))
        self.assertEqual(
            self._doc(["users:alice"], rules=reversed_rules), doc
        )

    def test_other_subject_exceptions_never_mark_evidence(self):
        exceptions = {"x-2": _exception("subject-2", "*", 365, "hold")}
        doc = self._doc(["users:alice"], exceptions=exceptions)
        item = doc["scope_evidence"][0]
        self.assertEqual(item["policy_id"], "p-users")
        self.assertIs(item["exception"], False)
        self.assertIs(doc["exception"], False)

    def test_evidence_ordered_by_normalized_scope(self):
        exceptions = {
            "x-users": _exception("subject-1", "users*", 60, "users hold"),
            "x-order": _exception("subject-1", "orders:o1", 90, "order hold"),
        }
        doc = self._doc(
            ["users:alice", "orders:o1", "media:m1"], exceptions=exceptions
        )
        self.assertEqual(
            [item["scope"] for item in doc["scope_evidence"]],
            ["media:m1", "orders:o1", "users:alice"],
        )
        self.assertEqual(
            [item["exception"] for item in doc["scope_evidence"]],
            [False, True, True],
        )
        self.assertEqual(
            [item["level"] for item in doc["scope_evidence"]],
            ["all", "entry", "group"],
        )

    # -- aggregate verdict ---------------------------------------------

    def test_aggregate_is_max_with_first_winner_on_tie(self):
        rules = {
            "p-default": _rule("*", 30, "def"),
            "p-a": _rule("a:x", 30, "reason a"),
            "p-b": _rule("b:y", 30, "reason b"),
            "p-big": _rule("media*", 400, "big"),
        }
        doc = self._doc(["b:y", "media:m1", "a:x"], rules=rules)
        self.assertEqual(doc["retention_days"], 400)
        self.assertEqual(doc["policy_id"], "p-big")
        self.assertEqual(doc["reason"], "big")
        self.assertIs(doc["exception"], False)
        # All scopes tie on 30 days; the first normalized scope wins.
        tied = self._doc(["b:y", "a:x"], rules=rules)
        self.assertEqual(tied["retention_days"], 30)
        self.assertEqual(tied["policy_id"], "p-a")
        self.assertEqual(tied["reason"], "reason a")

    def test_aggregate_winner_matches_its_evidence_item(self):
        rules = {
            "p-default": _rule("*", 30, "def"),
            "p-big": _rule("media*", 400, "big"),
        }
        doc = self._doc(
            ["users:alice", "media:m1"], rules=rules, exceptions=self.exceptions
        )
        winner = next(
            item for item in doc["scope_evidence"]
            if item["scope"] == "media:m1"
        )
        self.assertEqual(doc["policy_id"], winner["policy_id"])
        self.assertEqual(doc["retention_days"], winner["retention_days"])
        self.assertIs(doc["exception"], winner["exception"])

    def test_lower_day_exception_does_not_mark_aggregate(self):
        rules = {
            "p-default": _rule("*", 30, "def"),
            "p-big": _rule("media*", 400, "big"),
        }
        doc = self._doc(
            ["users:alice", "media:m1"], rules=rules, exceptions=self.exceptions
        )
        self.assertEqual(doc["retention_days"], 400)
        self.assertEqual(doc["policy_id"], "p-big")
        self.assertIs(doc["exception"], False)

    def test_trace_matches_aggregate_decision(self):
        rules = {
            "p-default": _rule("*", 30, "def"),
            "p-big": _rule("media*", 400, "big"),
        }
        scopes = ["users:alice", "orders:o1", "media:m1"]
        aggregate = self.store.resolve_retention(
            "tenant-a", "subject-1", scopes, rules, self.exceptions
        )
        doc = self._doc(scopes, rules=rules, exceptions=self.exceptions)
        self.assertEqual(doc["retention_days"], aggregate["retention_days"])
        self.assertEqual(doc["policy_id"], aggregate["policy_id"])
        self.assertEqual(doc["reason"], aggregate["reason"])

    # -- published version source --------------------------------------

    def test_published_version_source(self):
        self._publish()
        doc = self._doc(["users:alice"], version=1)
        self.assertEqual(doc["catalog_source"], "published_version")
        self.assertEqual(doc["retention_days"], 365)
        self.assertEqual(doc["policy_id"], "x-alice")
        self.assertEqual(doc["reason"], "legal hold")
        self.assertIs(doc["exception"], True)
        self.assertEqual(doc["scope_evidence"][0]["level"], "entry")

    def test_versioned_trace_matches_input_trace_and_aggregate(self):
        self._publish()
        scopes = ["users:alice", "users*"]
        from_version = json.loads(self._trace(scopes, version=1))
        from_inputs = json.loads(self._trace(scopes))
        # Only the source label distinguishes the two renderings.
        self.assertEqual(from_version.pop("catalog_source"),
                         "published_version")
        self.assertEqual(from_inputs.pop("catalog_source"), "call_time")
        self.assertEqual(from_version, from_inputs)
        aggregate = self.store.resolve_retention(
            "tenant-a", "subject-1", scopes, version=1
        )
        self.assertEqual(
            (from_version["retention_days"], from_version["policy_id"],
             from_version["reason"]),
            (aggregate["retention_days"], aggregate["policy_id"],
             aggregate["reason"]),
        )

    def test_pinned_version_trace_is_stable_after_republication(self):
        self._publish()
        pinned = self._trace(["users:alice"], version=1)
        self.store.publish_policy_catalog(
            "tenant-a", {"p-default": _rule("*", 7, "short")}, {}
        )
        self.assertEqual(self._trace(["users:alice"], version=1), pinned)
        self.assertEqual(
            json.loads(self._trace(["users:alice"], version=2))["retention_days"],
            7,
        )

    def test_versioned_trace_keeps_scope_normalization(self):
        self._publish(rules=self.rules, exceptions={})
        doc = self._doc(["users:a", "users*", "users:b"], version=1)
        self.assertEqual(doc["scopes"], ["users*"])
        self.assertEqual(doc["scope_evidence"][0]["level"], "group")
        self.assertEqual(doc["retention_days"], 60)

    # -- ValueError contract -------------------------------------------

    def test_blank_tenant_or_subject_rejected(self):
        for bad in [None, "", "   ", "\t\n", 7, b"x", True, ["x"]]:
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(ValueError) as caught:
                    self.store.resolve_retention_trace(
                        bad, "subject-1", ["users:a"], self.rules, {}
                    )
                self.assertEqual(str(caught.exception), _FAILURE)
                with self.assertRaises(ValueError):
                    self.store.resolve_retention_trace(
                        "tenant-a", bad, ["users:a"], self.rules, {}
                    )

    def test_bad_scopes_rejected(self):
        bad_scopes = [
            [], (), "users:a", {"users:a"}, frozenset({"users:a"}),
            {"users:a": 1}, iter(["users:a"]), (s for s in ["users:a"]),
            [""], [None], [7], [True], ["users"], ["Users:a"],
            ["users:a", "users:a"], ["*", "*"], b"users:a",
        ]
        for bad in bad_scopes:
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(ValueError) as caught:
                    self._trace(bad)
                self.assertEqual(str(caught.exception), _FAILURE)

    def test_sources_mutually_exclusive_and_required(self):
        self._publish()
        calls = [
            lambda: self.store.resolve_retention_trace(
                "tenant-a", "subject-1", ["*"]
            ),
            lambda: self.store.resolve_retention_trace(
                "tenant-a", "subject-1", ["*"], rules=self.rules
            ),
            lambda: self.store.resolve_retention_trace(
                "tenant-a", "subject-1", ["*"], exceptions={}
            ),
            lambda: self.store.resolve_retention_trace(
                "tenant-a", "subject-1", ["*"], self.rules, {}, 1
            ),
            lambda: self.store.resolve_retention_trace(
                "tenant-a", "subject-1", ["*"], version=1, rules=self.rules
            ),
        ]
        for call in calls:
            with self.assertRaises(ValueError) as caught:
                call()
            self.assertEqual(str(caught.exception), _FAILURE)

    def test_invalid_version_rejected(self):
        self._publish()
        for bad in [True, False, 0, -1, 1.5, "1", [], (1,)]:
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(ValueError):
                    self._trace(["*"], version=bad)

    def test_illegal_catalog_shape_rejected(self):
        for bad_rules in [
            None, {}, [], "x", 7, True,
            {"p": _rule("users*", 1)},
            {"p": _rule("*", -1)},
            {"p": _rule("bad", 1)},
            {"p": _rule("*", 1, "")},
        ]:
            with self.subTest(bad=repr(bad_rules)):
                with self.assertRaises(ValueError):
                    self._trace(["*"], rules=bad_rules, exceptions={})
        with self.assertRaises(ValueError):
            self._trace(
                ["*"],
                rules=self.rules,
                exceptions={"p-default": _exception("subject-1", "*", 1)},
            )
        with self.assertRaises(ValueError):
            self._trace(
                ["*"],
                rules=self.rules,
                exceptions={"x": _exception("   ", "*", 1)},
            )

    # -- not found / storage failure -----------------------------------

    def test_unknown_and_cross_tenant_version_raise_not_found(self):
        self._publish()
        self.store.publish_policy_catalog(
            "tenant-b", {"p-default": _rule("*", 1, "x")}, {}
        )
        for tenant, version in [
            ("tenant-a", 99),
            ("tenant-other", 1),
            ("never-published", 1),
        ]:
            with self.subTest(tenant=tenant, version=version):
                with self.assertRaises(PolicyCatalogNotFound):
                    self._trace(["*"], version=version, tenant=tenant)

    def test_not_found_message_has_no_detail(self):
        try:
            self._trace(["*"], version=4)
        except PolicyCatalogNotFound as exc:
            message = str(exc)
            self.assertNotIn("tenant", message.lower())
            self.assertNotIn("/", message)
        else:
            self.fail("expected PolicyCatalogNotFound")

    def test_corrupt_catalog_raises_retention_oserror(self):
        self._publish()
        self.assertEqual(
            json.loads(self._trace(["*"], version=1))["retention_days"], 30
        )
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("UPDATE policy_catalog_rules SET days = 31")
            conn.commit()
        with self.assertRaises(OSError) as caught:
            self._trace(["*"], version=1)
        self.assertEqual(str(caught.exception), _FAILURE)

    def test_corrupt_request_record_raises_retention_oserror(self):
        self._publish()
        receipt = self.store.submit(
            "tenant-a", "subject-1", ["users:a"], "key-1"
        )
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE requests SET scopes_json = 'not-json' WHERE request_id = ?",
                (receipt["request_id"],),
            )
            conn.commit()
        with self.assertRaises(OSError) as caught:
            self._trace(["users:a"], version=1)
        self.assertEqual(str(caught.exception), _FAILURE)

    def test_missing_catalog_table_raises_retention_oserror(self):
        self._publish()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DROP TABLE policy_catalog_versions")
            conn.commit()
        with self.assertRaises(OSError) as caught:
            self._trace(["*"], version=1)
        self.assertEqual(str(caught.exception), _FAILURE)

    def test_missing_requests_table_raises_retention_oserror(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DROP TABLE requests")
            conn.commit()
        with self.assertRaises(OSError) as caught:
            self._trace(["users:a"])
        self.assertEqual(str(caught.exception), _FAILURE)

    # -- read-only and determinism -------------------------------------

    def test_trace_never_writes(self):
        self._publish()
        self.store.submit("tenant-a", "subject-1", ["users:a"], "key-1")
        tables = (
            "requests",
            "status_events",
            "claim_attempts",
            "claim_tokens",
            "inspection_batches",
            "inspection_batch_items",
            "audit_anchors",
            "deletion_receipts",
            "policy_catalog_versions",
            "policy_catalog_rules",
            "policy_catalog_exceptions",
        )
        with sqlite3.connect(self.db_path) as conn:
            before = {
                table: conn.execute(
                    f"SELECT count(*) FROM {table}"
                ).fetchone()[0]
                for table in tables
            }
        for _ in range(3):
            self._trace(["users:a", "users*"], exceptions=self.exceptions)
            self._trace(["users:alice"], version=1)
            try:
                self._trace(["*"], version=99)
            except PolicyCatalogNotFound:
                pass
            try:
                self._trace([], version=1)
            except ValueError:
                pass
        with sqlite3.connect(self.db_path) as conn:
            after = {
                table: conn.execute(
                    f"SELECT count(*) FROM {table}"
                ).fetchone()[0]
                for table in tables
            }
        self.assertEqual(before, after)

    def test_repeat_and_rebuild_are_byte_stable(self):
        self._publish()
        scopes = ["users:bob", "users:alice", "orders:o1"]
        first = self._trace(scopes, exceptions=self.exceptions)
        second = self._trace(list(reversed(scopes)),
                             exceptions=self.exceptions)
        rebuilt = RequestStore(self.db_path).resolve_retention_trace(
            "tenant-a", "subject-1", scopes, version=1
        )
        self.assertEqual(first, second)
        self.assertEqual(
            rebuilt,
            self.store.resolve_retention_trace(
                "tenant-a", "subject-1", scopes, version=1
            ),
        )

    def test_concurrent_read_only_calls_agree(self):
        self._publish()
        with ThreadPoolExecutor(max_workers=8) as pool:
            texts = list(
                pool.map(
                    lambda _: self.store.resolve_retention_trace(
                        "tenant-a",
                        "subject-1",
                        ["users:alice", "orders:o1"],
                        version=1,
                    ),
                    range(16),
                )
            )
        self.assertTrue(all(text == texts[0] for text in texts))

    def test_in_memory_store_trace(self):
        store = RequestStore(":memory:")
        store.publish_policy_catalog(
            "t", self.rules, self.exceptions
        )
        text = store.resolve_retention_trace(
            "t", "subject-1", ["users:alice"], version=1
        )
        doc = json.loads(text)
        self.assertEqual(doc["catalog_source"], "published_version")
        self.assertEqual(doc["retention_days"], 365)
        self.assertTrue(text.endswith("\n"))
        with self.assertRaises(PolicyCatalogNotFound):
            store.resolve_retention_trace("other", "s", ["*"], version=1)


if __name__ == "__main__":
    unittest.main()
