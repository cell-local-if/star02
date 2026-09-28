"""Tests for the versioned policy catalog storage entries.

``RequestStore.publish_policy_catalog`` freezes the ordinary rule
catalog and the subject exception catalog as an immutable,
tenant-scoped, positive-integer version with a UTC RFC3339 effective
time; ``read_policy_catalog`` reads one version (or the current one)
back as a single compact JSON line and ``audit_policy_catalogs``
lists the tenant's history summaries in ascending version order.
All three entries are storage-layer only, never change acceptance,
status, execution, receipts, evidence, anchors or inspection
progress, and never gain an HTTP route.
"""

import json
import os
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from forgetting_evidence.requests import (
    PolicyCatalogConflict,
    PolicyCatalogNotFound,
    RequestStore,
)

_FAILURE = "policy_catalog_failed"
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


def _assert_compact_line(testcase, text):
    testcase.assertTrue(text.endswith("\n"))
    testcase.assertEqual(len(text.splitlines()), 1)
    # Re-rendering the parsed document reproduces the exact bytes, so
    # the line carries no presentation whitespace outside string values.
    testcase.assertEqual(
        json.dumps(
            json.loads(text), ensure_ascii=False, separators=(",", ":")
        )
        + "\n",
        text,
    )


class PolicyCatalogPublishTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "evidence.db")
        self.store = RequestStore(self.db_path)
        self.rules = {
            "p-group": _rule("users*", 60, "group reason"),
            "p-default": _rule("*", 30, "default retention"),
        }
        self.exceptions = {
            "x-1": _exception("subject-1", "users:a", 90, "legal hold"),
        }

    def tearDown(self):
        self._tmp.cleanup()

    def _publish(self, rules=None, exceptions=None, tenant="tenant-a"):
        return self.store.publish_policy_catalog(
            tenant,
            self.rules if rules is None else rules,
            self.exceptions if exceptions is None else exceptions,
        )

    def test_first_publish_returns_version_one_and_utc_time(self):
        result = self._publish()
        self.assertEqual(list(result), ["version", "effective_at"])
        self.assertEqual(result["version"], 1)
        self.assertIsInstance(result["version"], int)
        self.assertNotIsInstance(result["version"], bool)
        self.assertIsInstance(result["effective_at"], str)
        self.assertTrue(result["effective_at"].endswith("Z"))
        datetime.fromisoformat(result["effective_at"][:-1] + "+00:00")

    def test_normalization_sorts_policy_numbers_independent_of_order(self):
        first = self._publish()
        read = json.loads(self.store.read_policy_catalog("tenant-a"))
        self.assertEqual(
            [entry["policy_id"] for entry in read["rules"]],
            ["p-default", "p-group"],
        )
        self.assertEqual(
            [entry["policy_id"] for entry in read["exceptions"]], ["x-1"]
        )
        # Reversed passing order normalizes to the same frozen version.
        again = self.store.publish_policy_catalog(
            "tenant-a",
            dict(reversed(list(self.rules.items()))),
            dict(reversed(list(self.exceptions.items()))),
        )
        self.assertEqual(again, first)

    def test_same_normalized_catalog_reuses_first_version(self):
        first = self._publish()
        second = self._publish()
        third = self.store.publish_policy_catalog(
            "tenant-a",
            dict(self.rules),
            {"x-1": dict(self.exceptions["x-1"])},
        )
        self.assertEqual(second, first)
        self.assertEqual(third, first)
        with sqlite3.connect(self.db_path) as conn:
            count = conn.execute(
                "SELECT count(*) FROM policy_catalog_versions "
                "WHERE tenant_id = 'tenant-a'"
            ).fetchone()[0]
        self.assertEqual(count, 1)

    def test_different_catalog_mints_next_positive_integer(self):
        first = self._publish()
        second = self._publish(exceptions={})
        third = self._publish(
            rules={"p-default": _rule("*", 7, "shorter")}, exceptions={}
        )
        self.assertEqual([first["version"], second["version"], third["version"]],
                         [1, 2, 3])
        self.assertNotEqual(first["effective_at"], third["effective_at"])

    def test_same_rules_with_different_exceptions_is_new_version(self):
        first = self._publish(exceptions={})
        second = self._publish(exceptions=self.exceptions)
        self.assertEqual(second["version"], first["version"] + 1)

    def test_empty_exception_catalog_is_allowed(self):
        result = self._publish(exceptions={})
        self.assertEqual(result["version"], 1)
        read = json.loads(self.store.read_policy_catalog("tenant-a"))
        self.assertEqual(read["exceptions"], [])

    def test_zero_days_kept_as_integer(self):
        self._publish(
            rules={"p-default": _rule("*", 0, "zero")}, exceptions={}
        )
        read = json.loads(self.store.read_policy_catalog("tenant-a"))
        self.assertEqual(read["rules"][0]["days"], 0)
        self.assertIsInstance(read["rules"][0]["days"], int)

    def test_published_catalog_is_usable_by_retention_resolution(self):
        self._publish()
        read = json.loads(self.store.read_policy_catalog("tenant-a"))
        rules = {
            entry["policy_id"]: {
                "selector": entry["selector"],
                "days": entry["days"],
                "reason": entry["reason"],
            }
            for entry in read["rules"]
        }
        exceptions = {
            entry["policy_id"]: {
                "subject": entry["subject"],
                "selector": entry["selector"],
                "days": entry["days"],
                "reason": entry["reason"],
            }
            for entry in read["exceptions"]
        }
        resolved = self.store.resolve_retention(
            "tenant-a", "subject-1", ["users:a"], rules, exceptions
        )
        self.assertEqual(resolved["retention_days"], 90)
        self.assertEqual(resolved["policy_id"], "x-1")

    def test_retention_result_independent_of_publish_order(self):
        rules_a = {
            "p-default": _rule("*", 30),
            "p-group": _rule("users*", 60),
        }
        rules_b = {"p-default": _rule("*", 45, "other default")}
        exceptions = {"x-1": _exception("subject-1", "users:a", 120)}

        def resolve_with(catalog_rules, catalog_exceptions):
            read_rules = {
                entry["policy_id"]: {
                    "selector": entry["selector"],
                    "days": entry["days"],
                    "reason": entry["reason"],
                }
                for entry in catalog_rules
            }
            read_exceptions = {
                entry["policy_id"]: {
                    "subject": entry["subject"],
                    "selector": entry["selector"],
                    "days": entry["days"],
                    "reason": entry["reason"],
                }
                for entry in catalog_exceptions
            }
            return self.store.resolve_retention(
                "tenant-a", "subject-1", ["users:a"],
                read_rules, read_exceptions,
            )

        v1 = json.loads(
            self.store.publish_policy_catalog(
                "tenant-a", rules_a, exceptions
            ) and self.store.read_policy_catalog("tenant-a", 1)
        )
        self.store.publish_policy_catalog("tenant-a", rules_b, {})
        v2 = json.loads(self.store.read_policy_catalog("tenant-a", 1))
        self.assertEqual(v1["rules"], v2["rules"])
        self.assertEqual(
            resolve_with(v2["rules"], v2["exceptions"])["retention_days"],
            120,
        )


class PolicyCatalogReadTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "evidence.db")
        self.store = RequestStore(self.db_path)
        self.rules = {
            "p-default": _rule("*", 30, "default retention"),
            "p-entry": _rule("users:alice", 90, "entry reason"),
        }
        self.exceptions = {
            "x-1": _exception("subject-1", "users*", 180, "hold reason"),
        }
        self.first = self.store.publish_policy_catalog(
            "tenant-a", self.rules, self.exceptions
        )
        self.second = self.store.publish_policy_catalog(
            "tenant-a", self.rules, {}
        )

    def tearDown(self):
        self._tmp.cleanup()

    def test_read_omitted_version_returns_latest(self):
        payload = json.loads(self.store.read_policy_catalog("tenant-a"))
        self.assertEqual(payload["version"], self.second["version"])
        self.assertEqual(payload["effective_at"], self.second["effective_at"])
        self.assertEqual(payload["exceptions"], [])

    def test_read_explicit_version_returns_that_snapshot(self):
        text = self.store.read_policy_catalog("tenant-a", 1)
        payload = json.loads(text)
        self.assertEqual(payload["tenant_id"], "tenant-a")
        self.assertEqual(payload["version"], 1)
        self.assertEqual(payload["effective_at"], self.first["effective_at"])
        self.assertEqual(len(payload["exceptions"]), 1)
        # After a newer publish the old version stays frozen.
        self.assertEqual(
            self.store.read_policy_catalog("tenant-a", 1), text
        )

    def test_read_line_shape_is_compact_json_with_one_newline(self):
        text = self.store.read_policy_catalog("tenant-a", 1)
        _assert_compact_line(self, text)
        payload = json.loads(text)
        self.assertEqual(
            list(payload),
            ["tenant_id", "version", "effective_at", "rules", "exceptions"],
        )
        self.assertEqual(
            list(payload["rules"][0]), ["policy_id", "selector", "days", "reason"]
        )
        self.assertEqual(
            list(payload["exceptions"][0]),
            ["policy_id", "subject", "selector", "days", "reason"],
        )

    def test_read_keeps_rule_order_exception_order_and_reason_text(self):
        payload = json.loads(self.store.read_policy_catalog("tenant-a", 1))
        self.assertEqual(
            [entry["policy_id"] for entry in payload["rules"]],
            ["p-default", "p-entry"],
        )
        self.assertEqual(payload["rules"][1]["reason"], "entry reason")
        self.assertEqual(payload["exceptions"][0]["reason"], "hold reason")
        # Repeated reads are byte-identical.
        self.assertEqual(
            self.store.read_policy_catalog("tenant-a", 1),
            self.store.read_policy_catalog("tenant-a", 1),
        )

    def test_read_rebuilt_instance_is_stable(self):
        rebuilt = RequestStore(self.db_path)
        self.assertEqual(
            rebuilt.read_policy_catalog("tenant-a", 1),
            self.store.read_policy_catalog("tenant-a", 1),
        )
        self.assertEqual(
            rebuilt.read_policy_catalog("tenant-a"),
            self.store.read_policy_catalog("tenant-a"),
        )

    def test_read_uses_only_json_safe_scalar_types(self):
        payload = json.loads(self.store.read_policy_catalog("tenant-a", 1))
        for entry in payload["rules"] + payload["exceptions"]:
            self.assertNotIsInstance(entry["days"], bool)
            self.assertIsInstance(entry["days"], int)
            self.assertGreaterEqual(entry["days"], 0)
        self.assertEqual(json.loads(json.dumps(payload)), payload)

    def test_read_unknown_version_and_cross_tenant_are_indistinguishable(self):
        cases = [
            ("tenant-a", 99),
            ("tenant-b", 1),
            ("never-seen", 1),
        ]
        for tenant, version in cases:
            with self.subTest(tenant=tenant, version=version):
                with self.assertRaises(PolicyCatalogNotFound) as caught:
                    self.store.read_policy_catalog(tenant, version)
                self.assertEqual(str(caught.exception), _FAILURE)

    def test_read_latest_for_tenant_without_versions_is_not_found(self):
        with self.assertRaises(PolicyCatalogNotFound) as caught:
            self.store.read_policy_catalog("never-seen")
        self.assertEqual(str(caught.exception), _FAILURE)

    def test_invalid_version_shape_is_value_error(self):
        for bad in [0, -1, 1.5, True, False, "1", [1]]:
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(ValueError) as caught:
                    self.store.read_policy_catalog("tenant-a", bad)
                self.assertEqual(str(caught.exception), _FAILURE)

    def test_invalid_tenant_is_value_error(self):
        for bad in [None, "", "   ", 7, True, b"t"]:
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(ValueError) as caught:
                    self.store.read_policy_catalog(bad)
                self.assertEqual(str(caught.exception), _FAILURE)


class PolicyCatalogAuditTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "evidence.db")
        self.store = RequestStore(self.db_path)
        self.rules = {"p-default": _rule("*", 30, "default retention")}

    def tearDown(self):
        self._tmp.cleanup()

    def test_history_ascending_with_counts_and_boolean_status(self):
        first = self.store.publish_policy_catalog(
            "tenant-a", self.rules,
            {"x-1": _exception("subject-1", "*", 5, "hold")},
        )
        second = self.store.publish_policy_catalog("tenant-a", self.rules, {})
        text = self.store.audit_policy_catalogs("tenant-a")
        _assert_compact_line(self, text)
        payload = json.loads(text)
        self.assertEqual(list(payload), ["tenant_id", "versions"])
        self.assertEqual(payload["tenant_id"], "tenant-a")
        entries = payload["versions"]
        self.assertEqual([entry["version"] for entry in entries], [1, 2])
        for entry in entries:
            self.assertEqual(
                list(entry),
                [
                    "version",
                    "effective_at",
                    "rule_count",
                    "exception_count",
                    "current",
                ],
            )
            self.assertNotIsInstance(entry["version"], bool)
            self.assertIsInstance(entry["rule_count"], int)
            self.assertIsInstance(entry["exception_count"], int)
            self.assertGreaterEqual(entry["rule_count"], 1)
            self.assertGreaterEqual(entry["exception_count"], 0)
            self.assertIsInstance(entry["current"], bool)
        self.assertEqual(entries[0]["exception_count"], 1)
        self.assertFalse(entries[0]["current"])
        self.assertTrue(entries[1]["current"])
        self.assertEqual(entries[0]["effective_at"], first["effective_at"])
        self.assertEqual(entries[1]["effective_at"], second["effective_at"])

    def test_history_contains_no_subject_or_rule_detail(self):
        self.store.publish_policy_catalog(
            "tenant-a",
            self.rules,
            {"x-secret": _exception("subject-secret", "users*", 9, "secret reason")},
        )
        text = self.store.audit_policy_catalogs("tenant-a")
        self.assertNotIn("subject-secret", text)
        self.assertNotIn("users*", text)
        self.assertNotIn("secret reason", text)
        self.assertNotIn("x-secret", text)

    def test_history_tenant_scoped(self):
        self.store.publish_policy_catalog("tenant-a", self.rules, {})
        self.store.publish_policy_catalog("tenant-b", self.rules, {})
        self.store.publish_policy_catalog("tenant-b", self.rules,
                                          {"x-1": _exception("s", "*", 1)})
        entries = json.loads(
            self.store.audit_policy_catalogs("tenant-a")
        )["versions"]
        self.assertEqual(len(entries), 1)
        self.assertTrue(entries[0]["current"])

    def test_history_empty_for_unknown_tenant_and_writes_nothing(self):
        with sqlite3.connect(self.db_path) as conn:
            before = conn.execute(
                "SELECT count(*) FROM policy_catalog_versions"
            ).fetchone()[0]
        text = self.store.audit_policy_catalogs("never-seen")
        self.assertEqual(text, '{"tenant_id":"never-seen","versions":[]}\n')
        with sqlite3.connect(self.db_path) as conn:
            after = conn.execute(
                "SELECT count(*) FROM policy_catalog_versions"
            ).fetchone()[0]
        self.assertEqual(before, after)

    def test_invalid_tenant_is_value_error(self):
        for bad in [None, "", "  ", 7, True]:
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(ValueError) as caught:
                    self.store.audit_policy_catalogs(bad)
                self.assertEqual(str(caught.exception), _FAILURE)

    def test_repeated_audit_is_byte_identical(self):
        self.store.publish_policy_catalog("tenant-a", self.rules, {})
        self.assertEqual(
            self.store.audit_policy_catalogs("tenant-a"),
            self.store.audit_policy_catalogs("tenant-a"),
        )


class PolicyCatalogValidationTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "evidence.db")
        self.store = RequestStore(self.db_path)
        self.rules = {"p-default": _rule("*", 30, "default")}

    def tearDown(self):
        self._tmp.cleanup()

    def _publish(self, tenant="tenant-a", rules=_UNSET, exceptions=_UNSET):
        return self.store.publish_policy_catalog(
            tenant,
            self.rules if rules is _UNSET else rules,
            {} if exceptions is _UNSET else exceptions,
        )

    def test_blank_tenant_rejected_with_fixed_text(self):
        for bad in [None, "", "   ", "\t\n", 7, True, b"t", ["t"]]:
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(ValueError) as caught:
                    self._publish(tenant=bad)
                self.assertEqual(str(caught.exception), _FAILURE)

    def test_non_mapping_catalogs_rejected(self):
        for bad in [None, [], "rules", 7, True, [("p", _rule("*", 1))]]:
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(ValueError) as caught:
                    self._publish(rules=bad)
                self.assertEqual(str(caught.exception), _FAILURE)
                with self.assertRaises(ValueError) as caught:
                    self._publish(exceptions=bad)
                self.assertEqual(str(caught.exception), _FAILURE)

    def test_missing_default_rule_rejected(self):
        with self.assertRaises(ValueError) as caught:
            self._publish(rules={"p-1": _rule("users*", 10)})
        self.assertEqual(str(caught.exception), _FAILURE)
        with self.assertRaises(ValueError):
            self._publish(rules={})

    def test_bad_rule_and_exception_shapes_rejected(self):
        bad_rules = [
            {"p": None},
            {"p": ["*", 1, "r"]},
            {"p": {"selector": "*", "days": 1}},
            {"p": {"selector": "*", "days": 1, "reason": "r", "x": 1}},
        ]
        for rules in bad_rules:
            with self.subTest(rules=rules):
                with self.assertRaises(ValueError):
                    self._publish(rules=rules)
        with self.assertRaises(ValueError):
            self._publish(
                exceptions={"x-1": {"subject": "s", "selector": "*", "days": 1}}
            )

    def test_out_of_domain_days_rejected(self):
        for bad_days in [-1, -9, 1.5, "30", True, False, None]:
            with self.subTest(bad_days=repr(bad_days)):
                with self.assertRaises(ValueError):
                    self._publish(rules={"p-d": _rule("*", bad_days)})
                with self.assertRaises(ValueError):
                    self._publish(
                        exceptions={"x-1": _exception("s", "*", bad_days)}
                    )

    def test_illegal_selectors_reasons_numbers_and_bindings_rejected(self):
        with self.assertRaises(ValueError):
            self._publish(
                rules={"p": _rule("users", 1), "p-d": _rule("*", 1)}
            )
        with self.assertRaises(ValueError):
            self._publish(rules={"": _rule("*", 1)})
        with self.assertRaises(ValueError):
            self._publish(rules={"p-d": _rule("*", 1, "")})
        # A policy number shared by a rule and an exception is illegal.
        with self.assertRaises(ValueError):
            self._publish(
                exceptions={"p-default": _exception("s", "*", 1)}
            )
        for bad_subject in [None, "", "   ", 7, True]:
            with self.subTest(bad_subject=repr(bad_subject)):
                with self.assertRaises(ValueError):
                    self._publish(
                        exceptions={"x-1": _exception(bad_subject, "*", 1)}
                    )

    def test_validation_failures_never_write(self):
        with sqlite3.connect(self.db_path) as conn:
            before = conn.execute(
                "SELECT count(*) FROM policy_catalog_versions"
            ).fetchone()[0]
        bad_calls = [
            lambda: self._publish(tenant="  "),
            lambda: self._publish(rules={}),
            lambda: self._publish(exceptions=None),
            lambda: self._publish(rules={"p": _rule("*", True, "r")}),
            lambda: self._publish(
                exceptions={"p-default": _exception("s", "*", 1, "r")}
            ),
        ]
        for call in bad_calls:
            with self.assertRaises(ValueError):
                call()
        with sqlite3.connect(self.db_path) as conn:
            after = conn.execute(
                "SELECT count(*) FROM policy_catalog_versions"
            ).fetchone()[0]
        self.assertEqual(before, after)


class PolicyCatalogCorruptionTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "evidence.db")
        self.store = RequestStore(self.db_path)
        self.rules = {"p-default": _rule("*", 30, "default")}
        self.exceptions = {"x-1": _exception("subject-1", "*", 9, "hold")}
        self.store.publish_policy_catalog(
            "tenant-a", self.rules, self.exceptions
        )
        self.store.publish_policy_catalog("tenant-a", self.rules, {})

    def tearDown(self):
        self._tmp.cleanup()

    def _raw(self, sql, params=()):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(sql, params)
            conn.commit()

    def test_corrupt_rules_json_raises_fixed_text_oserror(self):
        self._raw(
            "UPDATE policy_catalog_versions SET rules_json = "
            "rules_json || ' ' WHERE version = 1"
        )
        for call in (
            lambda: self.store.read_policy_catalog("tenant-a", 1),
            lambda: self.store.read_policy_catalog("tenant-a"),
            lambda: self.store.audit_policy_catalogs("tenant-a"),
            lambda: self.store.publish_policy_catalog(
                "tenant-a", self.rules, self.exceptions
            ),
        ):
            with self.assertRaises(OSError) as caught:
                call()
            self.assertEqual(str(caught.exception), _FAILURE)

    def test_corrupt_exceptions_json_raises_fixed_text_oserror(self):
        self._raw(
            "UPDATE policy_catalog_versions SET exceptions_json = 'broken' "
            "WHERE version = 1"
        )
        for call in (
            lambda: self.store.read_policy_catalog("tenant-a", 1),
            lambda: self.store.audit_policy_catalogs("tenant-a"),
        ):
            with self.assertRaises(OSError) as caught:
                call()
            self.assertEqual(str(caught.exception), _FAILURE)

    def test_stored_rules_without_default_is_corruption(self):
        replacement = json.dumps(
            [{"policy_id": "p", "selector": "users*", "days": 1, "reason": "r"}],
            separators=(",", ":"),
        )
        self._raw(
            "UPDATE policy_catalog_versions SET rules_json = ?, "
            "rule_count = 1 WHERE version = 1",
            (replacement,),
        )
        with self.assertRaises(OSError) as caught:
            self.store.audit_policy_catalogs("tenant-a")
        self.assertEqual(str(caught.exception), _FAILURE)

    def test_wrong_count_is_corruption(self):
        self._raw(
            "UPDATE policy_catalog_versions SET rule_count = 9 WHERE version = 1"
        )
        with self.assertRaises(OSError) as caught:
            self.store.read_policy_catalog("tenant-a", 1)
        self.assertEqual(str(caught.exception), _FAILURE)

    def test_version_gap_is_corruption(self):
        self._raw(
            "UPDATE policy_catalog_versions SET version = 5 WHERE version = 2"
        )
        with self.assertRaises(OSError) as caught:
            self.store.audit_policy_catalogs("tenant-a")
        self.assertEqual(str(caught.exception), _FAILURE)

    def test_empty_effective_at_is_corruption(self):
        self._raw(
            "UPDATE policy_catalog_versions SET effective_at = '' "
            "WHERE version = 1"
        )
        with self.assertRaises(OSError) as caught:
            self.store.read_policy_catalog("tenant-a", 1)
        self.assertEqual(str(caught.exception), _FAILURE)

    def test_child_row_mismatch_is_corruption(self):
        self._raw(
            "UPDATE policy_catalog_rules SET days = 777 "
            "WHERE version = 1 AND position = 0"
        )
        for call in (
            lambda: self.store.read_policy_catalog("tenant-a", 1),
            lambda: self.store.audit_policy_catalogs("tenant-a"),
        ):
            with self.assertRaises(OSError) as caught:
                call()
            self.assertEqual(str(caught.exception), _FAILURE)

    def test_missing_child_row_is_corruption(self):
        self._raw("DELETE FROM policy_catalog_exceptions WHERE version = 1")
        with self.assertRaises(OSError) as caught:
            self.store.read_policy_catalog("tenant-a", 1)
        self.assertEqual(str(caught.exception), _FAILURE)

    def test_missing_table_raises_fixed_text_oserror(self):
        self._raw("DROP TABLE policy_catalog_versions")
        for call in (
            lambda: self.store.read_policy_catalog("tenant-a"),
            lambda: self.store.audit_policy_catalogs("tenant-a"),
            lambda: self.store.publish_policy_catalog(
                "tenant-a", self.rules, {"x": _exception("s", "*", 3)}
            ),
        ):
            with self.assertRaises(OSError) as caught:
                call()
            self.assertEqual(str(caught.exception), _FAILURE)

    def test_failed_publish_leaves_no_half_version(self):
        self._raw("DROP TABLE policy_catalog_rules")
        with self.assertRaises(OSError):
            self.store.publish_policy_catalog(
                "tenant-a", self.rules, {"x": _exception("s", "*", 3)}
            )
        # Recreate the table to inspect the still-consistent versions.
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "CREATE TABLE policy_catalog_rules ("
                "tenant_id TEXT NOT NULL, version INTEGER NOT NULL, "
                "position INTEGER NOT NULL, policy_id TEXT NOT NULL, "
                "selector TEXT NOT NULL, days INTEGER NOT NULL, "
                "reason TEXT NOT NULL, "
                "PRIMARY KEY (tenant_id, version, position))"
            )
            versions = conn.execute(
                "SELECT version FROM policy_catalog_versions "
                "WHERE tenant_id = 'tenant-a' ORDER BY version"
            ).fetchall()
        self.assertEqual(versions, [(1,), (2,)])


class PolicyCatalogConcurrencyTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "evidence.db")

    def tearDown(self):
        self._tmp.cleanup()

    def test_concurrent_same_catalog_lands_once_in_memory(self):
        store = RequestStore(":memory:")
        rules = {"p-default": _rule("*", 30, "default")}
        with ThreadPoolExecutor(max_workers=12) as pool:
            results = list(
                pool.map(
                    lambda _: store.publish_policy_catalog(
                        "tenant-a", rules, {}
                    ),
                    range(24),
                )
            )
        self.assertTrue(all(result == results[0] for result in results))
        self.assertEqual(results[0]["version"], 1)
        self.assertEqual(
            len(json.loads(store.audit_policy_catalogs("tenant-a"))["versions"]),
            1,
        )

    def test_concurrent_same_catalog_lands_once_across_stores(self):
        store_a = RequestStore(self.db_path)
        store_b = RequestStore(self.db_path)
        rules = {"p-default": _rule("*", 30, "default")}
        barrier = threading.Barrier(2)

        def publish(store):
            barrier.wait()
            return store.publish_policy_catalog("tenant-a", rules, {})

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(publish, [store_a, store_b]))
        self.assertEqual(results[0], results[1])
        audit = json.loads(store_a.audit_policy_catalogs("tenant-a"))
        self.assertEqual(len(audit["versions"]), 1)
        self.assertEqual(audit["versions"][0]["version"], 1)

    def test_single_instance_serializes_distinct_catalogs(self):
        # One in-memory connection is inherently serialized: distinct
        # catalogs land in arrival order as versions 1 and 2 rather than
        # racing; overlapping races are a multi-instance concern covered
        # by the cross-store test below.
        store = RequestStore(":memory:")
        one = {"p-default": _rule("*", 1, "a")}
        two = {"p-default": _rule("*", 2, "b")}

        def publish(index):
            return store.publish_policy_catalog(
                "tenant-a", one if index % 2 == 0 else two, {}
            )

        with ThreadPoolExecutor(max_workers=16) as pool:
            results = list(pool.map(publish, range(16)))
        one_versions = {
            result["version"]
            for index, result in enumerate(results)
            if index % 2 == 0
        }
        two_versions = {
            result["version"]
            for index, result in enumerate(results)
            if index % 2 == 1
        }
        # Every call of one catalog converges on one version and every
        # call of the other on exactly one distinct later-or-earlier
        # version; serialized distinct catalogs never collide, and the
        # overlapping case is covered by the cross-store test below.
        self.assertEqual(len(one_versions), 1)
        self.assertEqual(len(two_versions), 1)
        self.assertEqual(one_versions | two_versions, {1, 2})
        audit = json.loads(store.audit_policy_catalogs("tenant-a"))
        self.assertEqual([entry["version"] for entry in audit["versions"]],
                         [1, 2])

    def test_concurrent_different_catalogs_single_winner_across_stores(self):
        store_a = RequestStore(self.db_path)
        store_b = RequestStore(self.db_path)
        one = {"p-default": _rule("*", 1, "a")}
        two = {"p-default": _rule("*", 2, "b")}
        barrier = threading.Barrier(2)

        def publish(argument):
            store, catalog = argument
            barrier.wait()
            try:
                return store.publish_policy_catalog("tenant-a", catalog, {})
            except PolicyCatalogConflict:
                return None

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(publish, [(store_a, one), (store_b, two)]))
        winners = [result for result in results if result is not None]
        self.assertEqual(len(winners), 1)
        self.assertEqual(len([r for r in results if r is None]), 1)
        audit = json.loads(store_a.audit_policy_catalogs("tenant-a"))
        self.assertEqual(len(audit["versions"]), 1)
        self.assertEqual(audit["versions"][0]["version"], 1)

    def test_parallel_reads_and_audits_are_identical(self):
        store = RequestStore(self.db_path)
        rules = {"p-default": _rule("*", 30, "default")}
        store.publish_policy_catalog(
            "tenant-a", rules, {"x-1": _exception("s", "*", 2)}
        )
        with ThreadPoolExecutor(max_workers=12) as pool:
            reads = list(
                pool.map(
                    lambda _: store.read_policy_catalog("tenant-a"),
                    range(24),
                )
            )
            audits = list(
                pool.map(
                    lambda _: store.audit_policy_catalogs("tenant-a"),
                    range(24),
                )
            )
        self.assertTrue(all(read == reads[0] for read in reads))
        self.assertTrue(all(audit == audits[0] for audit in audits))


class PolicyCatalogIsolationTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "evidence.db")
        self.store = RequestStore(self.db_path)

    def tearDown(self):
        self._tmp.cleanup()

    def test_catalog_entries_never_touch_other_state(self):
        receipt = self.store.submit(
            "tenant-a", "subject-1", ["users:a"], "key-1"
        )
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
            "audit_anchors",
        )
        with sqlite3.connect(self.db_path) as conn:
            before = {
                table: conn.execute(
                    f"SELECT count(*) FROM {table}"
                ).fetchone()[0]
                for table in tables
            }
        rules = {"p-default": _rule("*", 30, "default")}
        self.store.publish_policy_catalog(
            "tenant-a", rules, {"x-1": _exception("s", "*", 2)}
        )
        self.store.read_policy_catalog("tenant-a")
        self.store.read_policy_catalog("tenant-a", 1)
        self.store.audit_policy_catalogs("tenant-a")
        self.store.audit_policy_catalogs("other-tenant")
        with sqlite3.connect(self.db_path) as conn:
            after = {
                table: conn.execute(
                    f"SELECT count(*) FROM {table}"
                ).fetchone()[0]
                for table in tables
            }
        self.assertEqual(before, after)
        self.assertEqual(
            self.store.get("tenant-a", receipt["request_id"])["status"],
            "accepted",
        )

    def test_reads_and_audits_write_nothing(self):
        rules = {"p-default": _rule("*", 30, "default")}
        self.store.publish_policy_catalog("tenant-a", rules, {})
        with sqlite3.connect(self.db_path) as conn:
            before = {
                table: conn.execute(
                    f"SELECT count(*) FROM {table}"
                ).fetchone()[0]
                for table in (
                    "policy_catalog_versions",
                    "policy_catalog_rules",
                    "policy_catalog_exceptions",
                )
            }
        for _ in range(3):
            self.store.read_policy_catalog("tenant-a")
            self.store.read_policy_catalog("tenant-a", 1)
            self.store.audit_policy_catalogs("tenant-a")
        with sqlite3.connect(self.db_path) as conn:
            after = {
                table: conn.execute(
                    f"SELECT count(*) FROM {table}"
                ).fetchone()[0]
                for table in (
                    "policy_catalog_versions",
                    "policy_catalog_rules",
                    "policy_catalog_exceptions",
                )
            }
        self.assertEqual(before, after)

    def test_unicode_reason_text_round_trips(self):
        rules = {"p-default": _rule("*", 30, "默认保留 理由")}
        self.store.publish_policy_catalog("tenant-a", rules, {})
        text = self.store.read_policy_catalog("tenant-a")
        self.assertIn("默认保留 理由", text)
        payload = json.loads(text)
        self.assertEqual(payload["rules"][0]["reason"], "默认保留 理由")


if __name__ == "__main__":
    unittest.main()
