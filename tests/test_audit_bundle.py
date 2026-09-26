"""Tests for the off-database audit evidence bundle export and verification."""

import json
import os
import re
import sqlite3
import tempfile
import unittest

from forgetting_evidence.requests import (
    AuditBundleUnavailable,
    RequestNotFound,
    RequestStore,
    verify_audit_bundle,
)

SECRET = "anchor-secret-one"
HEX64 = re.compile(r"^[0-9a-f]{64}$")


class AuditBundleExportTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "bundle.db")

    def tearDown(self):
        self._tmp.cleanup()

    def _store(self, secret=SECRET, history=None):
        kwargs = {}
        if history is not None:
            kwargs["anchor_history_secrets"] = history
        return RequestStore(self.db_path, anchor_secret=secret, **kwargs)

    def _lifecycle(self, statuses=("processing", "completed"), secret=SECRET, tenant="tenant-a"):
        store = self._store(secret)
        receipt = store.submit(tenant, "subject-1", ["email"], "idem-1")
        for status in statuses:
            store.transition(tenant, receipt["request_id"], status)
        return store, receipt

    def _raw(self):
        return sqlite3.connect(self.db_path)

    def _snapshot(self):
        with open(self.db_path, "rb") as handle:
            return handle.read()

    # -- shape and content ----------------------------------------------

    def test_bundle_is_single_compact_json_line(self):
        store, receipt = self._lifecycle()
        text = store.export_audit_bundle("tenant-a", receipt["request_id"])
        self.assertIsInstance(text, str)
        self.assertTrue(text.endswith("\n"))
        self.assertFalse(text.endswith("\n\n"))
        self.assertNotIn("\n", text[:-1])
        self.assertNotIn("\r", text)
        # Compact: no incidental whitespace outside string values.
        self.assertNotIn('": ', text)
        self.assertNotIn(", ", text)
        parsed = json.loads(text[:-1])
        self.assertEqual(
            list(parsed),
            ["request_id", "tenant_id", "snapshot", "events", "chain", "anchors", "generations"],
        )

    def test_bundle_field_shapes(self):
        store, receipt = self._lifecycle()
        text = store.export_audit_bundle("tenant-a", receipt["request_id"])
        bundle = json.loads(text[:-1])
        self.assertEqual(bundle["request_id"], receipt["request_id"])
        self.assertEqual(bundle["tenant_id"], "tenant-a")
        self.assertEqual(
            list(bundle["snapshot"]), ["status", "event_count"]
        )
        self.assertEqual(bundle["snapshot"]["status"], "completed")
        self.assertIsInstance(bundle["snapshot"]["event_count"], int)
        self.assertNotIsInstance(bundle["snapshot"]["event_count"], bool)
        self.assertEqual(bundle["snapshot"]["event_count"], 3)
        self.assertEqual(
            [event["seq"] for event in bundle["events"]], [0, 1, 2]
        )
        for event in bundle["events"]:
            self.assertEqual(
                list(event), ["seq", "status", "occurred_at", "chain_hash"]
            )
            self.assertIsInstance(event["seq"], int)
            self.assertNotIsInstance(event["seq"], bool)
            self.assertTrue(HEX64.match(event["chain_hash"]))
        self.assertEqual(list(bundle["chain"]), ["head", "anchor_head"])
        self.assertTrue(HEX64.match(bundle["chain"]["head"]))
        self.assertTrue(HEX64.match(bundle["chain"]["anchor_head"]))
        self.assertEqual(
            bundle["chain"]["head"], bundle["events"][-1]["chain_hash"]
        )
        for anchor in bundle["anchors"]:
            self.assertEqual(list(anchor), ["seq", "generation", "anchor"])
            self.assertIsInstance(anchor["generation"], int)
            self.assertNotIsInstance(anchor["generation"], bool)
            self.assertGreaterEqual(anchor["generation"], 1)
            self.assertTrue(HEX64.match(anchor["anchor"]))
        self.assertEqual(
            [anchor["seq"] for anchor in bundle["anchors"]], [0, 1, 2]
        )
        self.assertEqual(
            [record["generation"] for record in bundle["generations"]], [1]
        )
        record = bundle["generations"][0]
        self.assertEqual(
            list(record), ["generation", "key_fingerprint", "effective_at"]
        )
        self.assertTrue(HEX64.match(record["key_fingerprint"]))
        # No floats, negative zero or non-finite numbers anywhere:
        # walk the parsed value -- a timestamp fraction is a string.
        def walk(value):
            if isinstance(value, bool) or value is None:
                return
            if isinstance(value, float):
                self.fail(f"float leaked into bundle: {value!r}")
            if isinstance(value, int):
                pass
            elif isinstance(value, dict):
                for child in value.values():
                    walk(child)
            elif isinstance(value, list):
                for child in value:
                    walk(child)

        walk(bundle)
        self.assertNotIn("NaN", text)
        self.assertNotIn("Infinity", text)

    def test_bundle_matches_persisted_evidence(self):
        store, receipt = self._lifecycle()
        rid = receipt["request_id"]
        bundle = json.loads(
            store.export_audit_bundle("tenant-a", rid)[:-1]
        )
        evidence = store.evidence("tenant-a", rid)
        self.assertEqual(bundle["chain"]["head"], evidence["chain_hash"])
        self.assertEqual(bundle["snapshot"]["event_count"], evidence["event_count"])
        self.assertEqual(bundle["snapshot"]["status"], evidence["status"])
        timeline = store.audit("tenant-a", rid)
        self.assertEqual(
            [event["status"] for event in bundle["events"]],
            [event["status"] for event in timeline],
        )
        self.assertEqual(
            [event["occurred_at"] for event in bundle["events"]],
            [event["occurred_at"] for event in timeline],
        )

    def test_bundle_does_not_leak_sensitive_data(self):
        subject = "subject-SECRET"
        scope = "scope-SECRET"
        idem = "idem-SECRET"
        store = self._store()
        receipt = store.submit("tenant-a", subject, [scope, "email"], idem)
        store.transition("tenant-a", receipt["request_id"], "processing")
        text = store.export_audit_bundle("tenant-a", receipt["request_id"])
        self.assertNotIn(subject, text)
        self.assertNotIn(scope, text)
        self.assertNotIn(idem, text)
        self.assertNotIn(SECRET, text)

    # -- freeze and determinism ------------------------------------------

    def test_repeated_export_same_head_is_byte_identical(self):
        store, receipt = self._lifecycle()
        rid = receipt["request_id"]
        first = store.export_audit_bundle("tenant-a", rid)
        for _ in range(3):
            self.assertEqual(store.export_audit_bundle("tenant-a", rid), first)
        rebuilt = self._store()
        self.assertEqual(rebuilt.export_audit_bundle("tenant-a", rid), first)

    def test_export_freezes_chain_head_later_events_do_not_change_bundle(self):
        store = self._store()
        receipt = store.submit("tenant-a", "subject-1", ["email"], "idem-1")
        rid = receipt["request_id"]
        store.transition("tenant-a", rid, "processing")
        frozen = store.export_audit_bundle("tenant-a", rid)
        store.transition("tenant-a", rid, "completed")
        # The frozen bundle is unchanged and still authenticates.
        self.assertTrue(verify_audit_bundle(frozen, {1: SECRET}))
        extended = store.export_audit_bundle("tenant-a", rid)
        self.assertNotEqual(frozen, extended)
        self.assertTrue(verify_audit_bundle(extended, {1: SECRET}))
        # The frozen bundle's head is the pre-completion head.
        frozen_head = json.loads(frozen[:-1])["chain"]["head"]
        extended_head = json.loads(extended[:-1])["chain"]["head"]
        self.assertNotEqual(frozen_head, extended_head)

    def test_export_is_read_only(self):
        store, receipt = self._lifecycle()
        before = self._snapshot()
        for _ in range(3):
            store.export_audit_bundle("tenant-a", receipt["request_id"])
        self.assertEqual(before, self._snapshot())

    def test_rotation_does_not_change_frozen_export(self):
        store = self._store()
        receipt = store.submit("tenant-a", "subject-1", ["email"], "idem-1")
        rid = receipt["request_id"]
        store.transition("tenant-a", rid, "processing")
        frozen = store.export_audit_bundle("tenant-a", rid)
        store.rotate_anchor_key(SECRET, "secret-two")
        # No new event for this request: the export is byte-identical.
        store_b = RequestStore(
            self.db_path,
            anchor_secret="secret-two",
            anchor_history_secrets={1: SECRET},
        )
        self.assertEqual(store_b.export_audit_bundle("tenant-a", rid), frozen)
        self.assertTrue(verify_audit_bundle(frozen, {1: SECRET}))

    # -- availability -----------------------------------------------------

    def test_unanchored_chain_is_unavailable(self):
        plain_path = os.path.join(self._tmp.name, "plain.db")
        store = RequestStore(plain_path)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "idem-1")
        with self.assertRaises(AuditBundleUnavailable) as caught:
            store.export_audit_bundle("tenant-a", receipt["request_id"])
        self.assertEqual(str(caught.exception), "audit bundle is not available")

    def test_secretless_store_on_anchored_db_is_unavailable(self):
        store, receipt = self._lifecycle()
        secretless = RequestStore(self.db_path)
        with self.assertRaises(AuditBundleUnavailable):
            secretless.export_audit_bundle("tenant-a", receipt["request_id"])

    def test_missing_historical_secret_is_unavailable(self):
        store = self._store()
        receipt = store.submit("tenant-a", "subject-1", ["email"], "idem-1")
        rid = receipt["request_id"]
        store.transition("tenant-a", rid, "processing")
        store.rotate_anchor_key(SECRET, "secret-two")
        store.transition("tenant-a", rid, "completed")
        # The rebuilt store holds only the active generation.
        rebuilt = RequestStore(self.db_path, anchor_secret="secret-two")
        with self.assertRaises(AuditBundleUnavailable):
            rebuilt.export_audit_bundle("tenant-a", rid)
        # With the historical secret handed over the export succeeds.
        with_history = RequestStore(
            self.db_path,
            anchor_secret="secret-two",
            anchor_history_secrets={1: SECRET},
        )
        text = with_history.export_audit_bundle("tenant-a", rid)
        self.assertTrue(
            verify_audit_bundle(text, {1: SECRET, 2: "secret-two"})
        )

    def test_tampered_evidence_is_unavailable(self):
        store, receipt = self._lifecycle()
        rid = receipt["request_id"]
        with self._raw() as raw:
            raw.execute(
                "UPDATE status_events SET occurred_at = occurred_at || 'X' "
                "WHERE request_id = ? AND seq = 1",
                (rid,),
            )
        with self.assertRaises(AuditBundleUnavailable):
            store.export_audit_bundle("tenant-a", rid)

    def test_deleted_anchor_is_unavailable(self):
        store, receipt = self._lifecycle()
        rid = receipt["request_id"]
        with self._raw() as raw:
            raw.execute(
                "DELETE FROM audit_anchors WHERE request_id = ? AND seq = 1",
                (rid,),
            )
        with self.assertRaises(AuditBundleUnavailable):
            store.export_audit_bundle("tenant-a", rid)

    def test_forged_anchor_is_unavailable(self):
        store, receipt = self._lifecycle()
        rid = receipt["request_id"]
        with self._raw() as raw:
            raw.execute(
                "UPDATE audit_anchors SET anchor_hmac = ? "
                "WHERE request_id = ? AND seq = 0",
                ("0" * 64, rid),
            )
        with self.assertRaises(AuditBundleUnavailable):
            store.export_audit_bundle("tenant-a", rid)

    # -- argument and access errors ---------------------------------------

    def test_invalid_tenant_raises_value_error_without_writes(self):
        store, receipt = self._lifecycle()
        before = self._snapshot()
        for bad in ("", None, 7, 3.14, b"tenant", ["tenant"], {"t": 1}):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    store.export_audit_bundle(bad, receipt["request_id"])
        self.assertEqual(before, self._snapshot())

    def test_missing_and_cross_tenant_raise_not_found(self):
        store, receipt = self._lifecycle()
        for bad in ("", None, 7, 3.14, b"id", ["id"], "does-not-exist"):
            with self.subTest(bad=bad):
                with self.assertRaises(RequestNotFound):
                    store.export_audit_bundle("tenant-a", bad)
        with self.assertRaises(RequestNotFound):
            store.export_audit_bundle("tenant-b", receipt["request_id"])

    def test_errors_do_not_leak(self):
        secret_subject = "subject-SECRETZZZ"
        store = self._store()
        receipt = store.submit("tenant-a", secret_subject, ["email"], "idem-1")
        try:
            store.export_audit_bundle("tenant-a", secret_subject)
        except RequestNotFound as exc:
            self.assertNotIn(secret_subject, str(exc))
        else:
            self.fail("expected RequestNotFound")
        self.assertNotIn("tenant-a", str(RequestNotFound("request not found")))

    def test_storage_failure_raises_fixed_os_error(self):
        store, receipt = self._lifecycle()
        rid = receipt["request_id"]
        with open(self.db_path, "wb") as handle:
            handle.write(b"this is not a sqlite database")
        with self.assertRaises(OSError) as caught:
            store.export_audit_bundle("tenant-a", rid)
        self.assertEqual(str(caught.exception), "request store is unavailable")

    def test_in_memory_store(self):
        store = RequestStore(":memory:", anchor_secret=SECRET)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "idem-1")
        store.transition("tenant-a", receipt["request_id"], "processing")
        text = store.export_audit_bundle("tenant-a", receipt["request_id"])
        self.assertTrue(verify_audit_bundle(text, {1: SECRET}))


class AuditBundleVerifyTests(unittest.TestCase):
    """Offline verification needs no database at all."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "bundle.db")
        store = RequestStore(self.db_path, anchor_secret=SECRET)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "idem-1")
        self.rid = receipt["request_id"]
        store.transition("tenant-a", self.rid, "processing")
        store.transition("tenant-a", self.rid, "completed")
        self.text = store.export_audit_bundle("tenant-a", self.rid)
        self.bundle = json.loads(self.text[:-1])

    def tearDown(self):
        self._tmp.cleanup()

    def _render(self, bundle):
        return json.dumps(bundle, ensure_ascii=False, separators=(",", ":")) + "\n"

    def _tampered(self, mutate):
        bundle = json.loads(self.text[:-1])
        mutate(bundle)
        return self._render(bundle)

    def test_valid_bundle_verifies_without_database(self):
        os.unlink(self.db_path)
        self.assertTrue(verify_audit_bundle(self.text, {1: SECRET}))
        self.assertTrue(RequestStore.verify_audit_bundle(self.text, {1: SECRET}))

    def test_verify_is_repeatable_and_writes_nothing(self):
        for _ in range(5):
            self.assertTrue(verify_audit_bundle(self.text, {1: SECRET}))
        # No database file is created or consulted by verification.
        self.assertFalse(os.path.exists(self.db_path + ".verify"))

    def test_extra_unrelated_secrets_are_ignored(self):
        self.assertTrue(
            verify_audit_bundle(self.text, {1: SECRET, 7: "other", 9: "keys"})
        )

    def test_missing_secret_returns_false(self):
        self.assertFalse(verify_audit_bundle(self.text, {}))
        self.assertFalse(verify_audit_bundle(self.text, {2: SECRET}))

    def test_wrong_secret_returns_false(self):
        self.assertFalse(verify_audit_bundle(self.text, {1: "wrong-secret"}))

    def test_recomputed_events_return_false(self):
        import forgetting_evidence.requests as mod

        def mutate(bundle):
            bundle["events"][1]["status"] = "failed"
            predecessor = (
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            )
            for event in bundle["events"]:
                digest = mod._chain_hash(
                    bundle["tenant_id"],
                    bundle["request_id"],
                    event["seq"],
                    event["status"],
                    event["occurred_at"],
                    predecessor,
                )
                event["chain_hash"] = digest
                predecessor = digest
            bundle["chain"]["head"] = predecessor

        self.assertFalse(verify_audit_bundle(self._tampered(mutate), {1: SECRET}))

    def test_replaced_chain_summary_returns_false(self):
        def mutate(bundle):
            bundle["chain"]["head"] = "0" * 64

        self.assertFalse(verify_audit_bundle(self._tampered(mutate), {1: SECRET}))

    def test_replaced_anchor_returns_false(self):
        def mutate(bundle):
            bundle["anchors"][0]["anchor"] = "1" * 64

        self.assertFalse(verify_audit_bundle(self._tampered(mutate), {1: SECRET}))

    def test_replaced_event_anchor_digest_returns_false(self):
        def mutate(bundle):
            bundle["events"][2]["chain_hash"] = "a" * 64

        self.assertFalse(verify_audit_bundle(self._tampered(mutate), {1: SECRET}))

    def test_reordered_events_return_false(self):
        def mutate(bundle):
            bundle["events"][1], bundle["events"][2] = (
                bundle["events"][2],
                bundle["events"][1],
            )

        self.assertFalse(verify_audit_bundle(self._tampered(mutate), {1: SECRET}))

    def test_replaced_request_association_returns_false(self):
        def mutate(bundle):
            bundle["tenant_id"] = "tenant-b"

        self.assertFalse(verify_audit_bundle(self._tampered(mutate), {1: SECRET}))

    def test_replaced_snapshot_status_returns_false(self):
        def mutate(bundle):
            bundle["snapshot"]["status"] = "failed"

        self.assertFalse(verify_audit_bundle(self._tampered(mutate), {1: SECRET}))

    def test_replaced_generation_binding_returns_false(self):
        def mutate(bundle):
            bundle["anchors"][0]["generation"] = 2
            bundle["generations"].append(
                {
                    "generation": 2,
                    "key_fingerprint": "b" * 64,
                    "effective_at": bundle["generations"][0]["effective_at"],
                }
            )

        self.assertFalse(verify_audit_bundle(self._tampered(mutate), {1: SECRET}))

    def test_cross_request_splice_returns_false(self):
        store = RequestStore(self.db_path, anchor_secret=SECRET)
        other = store.submit("tenant-a", "subject-2", ["email"], "idem-2")
        other_text = store.export_audit_bundle("tenant-a", other["request_id"])
        other_bundle = json.loads(other_text[:-1])

        def mutate(bundle):
            bundle["events"][0] = other_bundle["events"][0]
            bundle["anchors"][0] = other_bundle["anchors"][0]

        self.assertFalse(verify_audit_bundle(self._tampered(mutate), {1: SECRET}))

    # -- format errors ------------------------------------------------------

    def test_non_string_text_raises_value_error(self):
        for bad in (None, 7, 3.14, b"bytes", ["x"], {"k": "v"}):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    verify_audit_bundle(bad, {1: SECRET})

    def test_missing_or_duplicated_newline_raises_value_error(self):
        with self.assertRaises(ValueError):
            verify_audit_bundle(self.text[:-1], {1: SECRET})
        with self.assertRaises(ValueError):
            verify_audit_bundle(self.text + "\n", {1: SECRET})

    def test_unparsable_json_raises_value_error(self):
        with self.assertRaises(ValueError):
            verify_audit_bundle("not json\n", {1: SECRET})
        with self.assertRaises(ValueError):
            verify_audit_bundle('{"request_id":\n', {1: SECRET})

    def test_missing_or_extra_field_raises_value_error(self):
        bundle = json.loads(self.text[:-1])
        del bundle["chain"]
        with self.assertRaises(ValueError):
            verify_audit_bundle(self._render(bundle), {1: SECRET})
        bundle = json.loads(self.text[:-1])
        bundle["extra"] = "field"
        with self.assertRaises(ValueError):
            verify_audit_bundle(self._render(bundle), {1: SECRET})
        bundle = json.loads(self.text[:-1])
        del bundle["events"][0]["chain_hash"]
        with self.assertRaises(ValueError):
            verify_audit_bundle(self._render(bundle), {1: SECRET})

    def test_wrong_types_raise_value_error(self):
        def check(mutate):
            bundle = json.loads(self.text[:-1])
            mutate(bundle)
            with self.assertRaises(ValueError):
                verify_audit_bundle(self._render(bundle), {1: SECRET})

        check(lambda b: b["snapshot"].update(event_count="3"))
        check(lambda b: b["snapshot"].update(event_count=True))
        check(lambda b: b["snapshot"].update(event_count=3.0))
        check(lambda b: b["events"][0].update(seq="0"))
        check(lambda b: b["events"][0].update(chain_hash="zz" * 32))
        check(lambda b: b["anchors"][0].update(generation=0))
        check(lambda b: b["anchors"][0].update(generation=1.5))
        check(lambda b: b["events"][0].update(occurred_at="not-a-time"))
        check(lambda b: b.update(request_id=""))

    def test_noncanonical_rendering_raises_value_error(self):
        # Reordered keys, extra spacing or escaped text are malformed
        # presentation, never an authentication outcome.
        bundle = json.loads(self.text[:-1])
        reordered = {
            "tenant_id": bundle["tenant_id"],
            "request_id": bundle["request_id"],
            "snapshot": bundle["snapshot"],
            "events": bundle["events"],
            "chain": bundle["chain"],
            "anchors": bundle["anchors"],
            "generations": bundle["generations"],
        }
        with self.assertRaises(ValueError):
            verify_audit_bundle(
                json.dumps(reordered, ensure_ascii=False, separators=(",", ":")) + "\n",
                {1: SECRET},
            )
        spaced = json.dumps(bundle, ensure_ascii=False) + "\n"
        with self.assertRaises(ValueError):
            verify_audit_bundle(spaced, {1: SECRET})

    def test_illegal_secret_mapping_raises_value_error(self):
        for bad in (
            None,
            7,
            "secret",
            [SECRET],
            {0: SECRET},
            {-1: SECRET},
            {True: SECRET},
            {1.0: SECRET},
            {"1": SECRET},
            {1: ""},
            {1: None},
            {1: 7},
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    verify_audit_bundle(self.text, bad)

    def test_verify_never_writes_to_any_database(self):
        before = os.path.getsize(self.db_path)
        with open(self.db_path, "rb") as handle:
            content = handle.read()
        self.assertTrue(verify_audit_bundle(self.text, {1: SECRET}))
        self.assertFalse(verify_audit_bundle(self.text, {1: "wrong"}))
        with open(self.db_path, "rb") as handle:
            self.assertEqual(content, handle.read())
        self.assertEqual(before, os.path.getsize(self.db_path))


class AuditBundleRotationTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "rotated.db")

    def tearDown(self):
        self._tmp.cleanup()

    def test_bundle_spanning_generations_verifies_with_history(self):
        store = RequestStore(self.db_path, anchor_secret="gen-one")
        receipt = store.submit("tenant-a", "subject-1", ["email"], "idem-1")
        rid = receipt["request_id"]
        store.transition("tenant-a", rid, "processing")
        store.rotate_anchor_key("gen-one", "gen-two")
        store.transition("tenant-a", rid, "completed")
        rebuilt = RequestStore(
            self.db_path,
            anchor_secret="gen-two",
            anchor_history_secrets={1: "gen-one"},
        )
        text = rebuilt.export_audit_bundle("tenant-a", rid)
        bundle = json.loads(text[:-1])
        self.assertEqual(
            [anchor["generation"] for anchor in bundle["anchors"]], [1, 1, 2]
        )
        self.assertEqual(
            [record["generation"] for record in bundle["generations"]], [1, 2]
        )
        self.assertTrue(
            verify_audit_bundle(text, {1: "gen-one", 2: "gen-two"})
        )
        # Either historical secret missing fails closed, never guessed.
        self.assertFalse(verify_audit_bundle(text, {2: "gen-two"}))
        self.assertFalse(verify_audit_bundle(text, {1: "gen-one"}))
        # A wrong historical secret fails the generation binding.
        self.assertFalse(
            verify_audit_bundle(text, {1: "gen-WRONG", 2: "gen-two"})
        )

    def test_legacy_null_generation_anchors_export_as_generation_one(self):
        store = RequestStore(self.db_path, anchor_secret=SECRET)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "idem-1")
        rid = receipt["request_id"]
        store.transition("tenant-a", rid, "processing")
        # Simulate the pre-rotation legacy shape: NULL attributions and
        # no generations table rows.
        with sqlite3.connect(self.db_path) as raw:
            raw.execute("UPDATE audit_anchors SET key_generation = NULL")
            raw.execute("DELETE FROM anchor_key_generations")
        text = store.export_audit_bundle("tenant-a", rid)
        bundle = json.loads(text[:-1])
        self.assertEqual(bundle["generations"], [])
        self.assertEqual(
            [anchor["generation"] for anchor in bundle["anchors"]], [1, 1]
        )
        self.assertTrue(verify_audit_bundle(text, {1: SECRET}))
        self.assertFalse(verify_audit_bundle(text, {1: "wrong"}))


if __name__ == "__main__":
    unittest.main()
