"""Tests for portable audit evidence bundles.

Covers ``RequestStore.export_audit_bundle`` and the fully offline
``RequestStore.verify_audit_bundle`` on the storage layer only: the
single-line compact JSON shape (fixed field order, exactly one trailing
newline, no floats or non-finite values), the freeze at the request
chain head (byte-identical repeat exports, later events never
invalidating an exported bundle), the business-fields-only content,
offline authentication (text boundaries, field completeness, event
order, request association, chain hashes, per-event anchors and
generation binding), the False-only forgery outcomes, the
ValueError/RequestNotFound/AuditBundleUnavailable/OSError error
contract, rotation and legacy-generation scenarios, strictly read-only
behaviour and the absence of any HTTP route or health-command change.
"""

import hashlib
import hmac
import http.client
import json
import os
import re
import sqlite3
import struct
import tempfile
import threading
import unittest

from forgetting_evidence.httpapi import build_server
from forgetting_evidence.requests import (
    AuditBundleUnavailable,
    RequestNotFound,
    RequestStore,
)

SECRET_A = "anchor-secret-alpha-0001"
SECRET_B = "anchor-secret-bravo-0002"
SECRET_C = "anchor-secret-charlie-0003"

RFC3339 = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$"
)
HEX64 = re.compile(r"^[0-9a-f]{64}$")
GENESIS = hashlib.sha256(b"").hexdigest()
STATUSES = ("accepted", "processing", "completed", "failed")


def _chain_hash(tenant_id, request_id, seq, status, occurred_at, predecessor):
    digest = hashlib.sha256()
    for field in (tenant_id, request_id, str(seq), status, occurred_at, predecessor):
        encoded = field.encode("utf-8")
        digest.update(struct.pack(">Q", len(encoded)))
        digest.update(encoded)
    return digest.hexdigest()


def _render(payload):
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"


class _StoreCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "evidence.db")

    def tearDown(self):
        self._tmp.cleanup()

    def _store(self, secret=SECRET_A, history=None):
        return RequestStore(
            self.db_path, anchor_secret=secret, anchor_history_secrets=history
        )

    def _submit(self, store, tenant="tenant-a", idem="key-1"):
        return store.submit(tenant, "subject-1", ["email", "files"], idem)[
            "request_id"
        ]

    def _raw(self):
        return sqlite3.connect(self.db_path)

    def _table_dump(self, table):
        with self._raw() as raw:
            return raw.execute(f"SELECT * FROM {table}").fetchall()

    def _all_tables(self):
        return {
            name: self._table_dump(name)
            for name in (
                "requests",
                "status_events",
                "audit_anchors",
                "audit_anchor_meta",
                "anchor_key_generations",
                "inspection_batches",
                "inspection_batch_items",
            )
        }

    def _exported(self, store=None, tenant="tenant-a", advance=2):
        store = store or self._store()
        request_id = self._submit(store, tenant)
        for status in ("processing", "completed")[:advance]:
            store.transition(tenant, request_id, status)
        return store, request_id, store.export_audit_bundle(tenant, request_id)

    def _assert_well_formed(self, text, request_id, tenant="tenant-a"):
        # Exactly one trailing newline and no other line break.
        self.assertIsInstance(text, str)
        self.assertTrue(text.endswith("\n"))
        self.assertFalse(text.endswith("\n\n"))
        body = text[:-1]
        self.assertNotIn("\n", body)
        self.assertNotIn("\r", body)
        # Compact: no insignificant whitespace anywhere.
        self.assertEqual(body, json.dumps(json.loads(body), ensure_ascii=False,
                                          separators=(",", ":")))
        payload = json.loads(body)
        self.assertEqual(
            list(payload),
            ["request_id", "status", "events", "chain", "anchors", "generations"],
        )
        self.assertEqual(payload["request_id"], request_id)
        self.assertIn(payload["status"], STATUSES)
        events = payload["events"]
        self.assertIsInstance(events, list)
        self.assertTrue(events)
        for index, event in enumerate(events):
            self.assertEqual(list(event), ["seq", "status", "occurred_at", "chain_hash"])
            self.assertEqual(event["seq"], index)
            self.assertNotIsInstance(event["seq"], bool)
            self.assertIn(event["status"], STATUSES)
            self.assertRegex(event["occurred_at"], RFC3339)
            self.assertRegex(event["chain_hash"], HEX64)
        chain = payload["chain"]
        self.assertEqual(list(chain), ["tenant_id", "event_count", "head"])
        self.assertEqual(chain["tenant_id"], tenant)
        self.assertEqual(chain["event_count"], len(events))
        self.assertNotIsInstance(chain["event_count"], bool)
        self.assertGreaterEqual(chain["event_count"], 1)
        self.assertEqual(chain["head"], events[-1]["chain_hash"])
        self.assertEqual(payload["status"], events[-1]["status"])
        anchors = payload["anchors"]
        self.assertEqual(len(anchors), len(events))
        for index, anchor in enumerate(anchors):
            self.assertEqual(list(anchor), ["seq", "anchor_hmac", "key_generation"])
            self.assertEqual(anchor["seq"], index)
            self.assertRegex(anchor["anchor_hmac"], HEX64)
            generation = anchor["key_generation"]
            if generation is not None:
                self.assertIsInstance(generation, int)
                self.assertNotIsInstance(generation, bool)
                self.assertGreaterEqual(generation, 1)
        generations = payload["generations"]
        self.assertIsInstance(generations, list)
        referenced = {
            anchor["key_generation"] if anchor["key_generation"] is not None else 1
            for anchor in anchors
        }
        recorded = set()
        for record in generations:
            self.assertEqual(
                list(record), ["generation", "key_fingerprint", "effective_at"]
            )
            self.assertIsInstance(record["generation"], int)
            self.assertNotIsInstance(record["generation"], bool)
            self.assertGreaterEqual(record["generation"], 1)
            self.assertRegex(record["key_fingerprint"], HEX64)
            self.assertRegex(record["effective_at"], RFC3339)
            recorded.add(record["generation"])
        # Exactly the generations this request's anchors name, ascending.
        self.assertEqual(recorded, referenced & recorded)
        self.assertEqual(
            [record["generation"] for record in generations],
            sorted(recorded),
        )
        self.assertTrue(referenced <= recorded or not recorded)
        # Never a float, a negative zero or a non-finite number anywhere.
        json.dumps(payload, allow_nan=False)
        self.assertNotRegex(body, r":\s*-\d")
        return payload


class BundleShapeTests(_StoreCase):
    def test_export_shape_and_content(self):
        store, request_id, text = self._exported()
        payload = self._assert_well_formed(text, request_id)
        self.assertEqual(payload["status"], "completed")
        self.assertEqual(
            [event["status"] for event in payload["events"]],
            ["accepted", "processing", "completed"],
        )
        self.assertEqual(len(payload["generations"]), 1)
        self.assertEqual(payload["generations"][0]["generation"], 1)

    def test_repeat_export_is_byte_identical(self):
        store, request_id, text = self._exported()
        again = store.export_audit_bundle("tenant-a", request_id)
        self.assertEqual(text, again)
        rebuilt = self._store()
        self.assertEqual(text, rebuilt.export_audit_bundle("tenant-a", request_id))

    def test_export_freezes_chain_head(self):
        store, request_id, text = self._exported(advance=1)
        store.transition("tenant-a", request_id, "completed")
        # The frozen bundle is unchanged and still verifies; the new
        # head exports a different bundle.
        self.assertEqual(store.export_audit_bundle("tenant-a", request_id) != text, True)
        self.assertEqual(
            store.export_audit_bundle("tenant-a", request_id),
            self._store().export_audit_bundle("tenant-a", request_id),
        )
        self.assertTrue(
            RequestStore.verify_audit_bundle(text, {1: SECRET_A})
        )

    def test_other_requests_and_tenants_do_not_change_bundle(self):
        store, request_id, text = self._exported()
        other = self._submit(store, "tenant-a", "key-other")
        store.transition("tenant-a", other, "processing")
        foreign = self._submit(store, "tenant-b", "key-foreign")
        store.transition("tenant-b", foreign, "failed")
        self.assertEqual(text, store.export_audit_bundle("tenant-a", request_id))

    def test_rotation_does_not_change_existing_bundle(self):
        store, request_id, text = self._exported()
        store.rotate_anchor_key(SECRET_A, SECRET_B)
        rotated = self._store(secret=SECRET_B, history={1: SECRET_A})
        self.assertEqual(text, rotated.export_audit_bundle("tenant-a", request_id))
        self.assertTrue(
            RequestStore.verify_audit_bundle(text, {1: SECRET_A})
        )

    def test_bundle_contains_only_business_fields(self):
        store, request_id, text = self._exported()
        # Subject, raw scopes and the idempotency key never appear.
        self.assertNotIn("subject-1", text)
        self.assertNotIn("email", text)
        self.assertNotIn("files", text)
        self.assertNotIn("key-1", text)
        self.assertNotIn(SECRET_A, text)

    def test_unicode_strings_keep_original_values(self):
        store = self._store()
        request_id = store.submit("租户-甲", "subject-1", ["email"], "键-1")[
            "request_id"
        ]
        text = store.export_audit_bundle("租户-甲", request_id)
        payload = self._assert_well_formed(text, request_id, tenant="租户-甲")
        self.assertEqual(payload["chain"]["tenant_id"], "租户-甲")
        self.assertIn("租户-甲", text)
        self.assertTrue(
            RequestStore.verify_audit_bundle(text, {1: SECRET_A})
        )


class OfflineVerifyTests(_StoreCase):
    def test_valid_bundle_verifies_without_database(self):
        store, request_id, text = self._exported()
        os.unlink(self.db_path)
        self.assertTrue(RequestStore.verify_audit_bundle(text, {1: SECRET_A}))

    def test_verify_is_static_and_needs_no_store(self):
        _store, _request_id, text = self._exported()
        self.assertTrue(RequestStore.verify_audit_bundle(text, {1: SECRET_A}))

    def test_recomputed_chain_forgery_is_false(self):
        # An attacker can recompute the keyless chain hashes after
        # altering an event, but cannot re-seal the anchors.
        _store, request_id, text = self._exported()
        payload = json.loads(text)
        payload["status"] = "failed"
        payload["events"][1]["status"] = "failed"
        predecessor = payload["events"][0]["chain_hash"]
        payload["events"][1]["chain_hash"] = _chain_hash(
            "tenant-a", request_id, 1, "failed",
            payload["events"][1]["occurred_at"], predecessor,
        )
        payload["chain"]["head"] = payload["events"][1]["chain_hash"]
        self.assertFalse(
            RequestStore.verify_audit_bundle(_render(payload), {1: SECRET_A})
        )

    def test_event_tampering_is_false(self):
        _store, _request_id, text = self._exported()
        payload = json.loads(text)
        payload["events"][0]["occurred_at"] = "2020-01-01T00:00:00.000000Z"
        self.assertFalse(
            RequestStore.verify_audit_bundle(_render(payload), {1: SECRET_A})
        )

    def test_chain_summary_tampering_is_false(self):
        _store, _request_id, text = self._exported()
        for mutate in (
            lambda p: p["chain"].update(head="0" * 64),
            lambda p: p["chain"].update(event_count=p["chain"]["event_count"] + 1),
            lambda p: p["chain"].update(tenant_id="tenant-b"),
            lambda p: p.update(status="failed"),
        ):
            payload = json.loads(text)
            mutate(payload)
            self.assertFalse(
                RequestStore.verify_audit_bundle(_render(payload), {1: SECRET_A})
            )

    def test_anchor_tampering_is_false(self):
        _store, _request_id, text = self._exported()
        payload = json.loads(text)
        payload["anchors"][0]["anchor_hmac"] = "0" * 64
        self.assertFalse(
            RequestStore.verify_audit_bundle(_render(payload), {1: SECRET_A})
        )

    def test_event_reorder_is_false(self):
        _store, _request_id, text = self._exported()
        payload = json.loads(text)
        payload["events"] = payload["events"][::-1]
        self.assertFalse(
            RequestStore.verify_audit_bundle(_render(payload), {1: SECRET_A})
        )

    def test_missing_and_wrong_secret_are_false_not_guessed(self):
        _store, _request_id, text = self._exported()
        self.assertFalse(RequestStore.verify_audit_bundle(text, {}))
        self.assertFalse(RequestStore.verify_audit_bundle(text, {1: "wrong"}))
        self.assertFalse(RequestStore.verify_audit_bundle(text, {2: SECRET_A}))

    def test_generation_proof_inconsistency_is_false(self):
        _store, _request_id, text = self._exported()
        # Anchor naming a generation the bundle does not record.
        payload = json.loads(text)
        payload["anchors"][0]["key_generation"] = 9
        self.assertFalse(
            RequestStore.verify_audit_bundle(_render(payload), {1: SECRET_A})
        )
        # Recorded fingerprint replaced.
        payload = json.loads(text)
        payload["generations"][0]["key_fingerprint"] = "1" * 64
        self.assertFalse(
            RequestStore.verify_audit_bundle(_render(payload), {1: SECRET_A})
        )
        # Duplicate generation records.
        payload = json.loads(text)
        payload["generations"].append(dict(payload["generations"][0]))
        self.assertFalse(
            RequestStore.verify_audit_bundle(_render(payload), {1: SECRET_A})
        )
        # Non-null generation with no generation records at all.
        payload = json.loads(text)
        payload["generations"] = []
        self.assertFalse(
            RequestStore.verify_audit_bundle(_render(payload), {1: SECRET_A})
        )

    def test_verify_never_writes_anywhere(self):
        store, request_id, text = self._exported()
        before = self._all_tables()
        self.assertTrue(RequestStore.verify_audit_bundle(text, {1: SECRET_A}))
        self.assertFalse(RequestStore.verify_audit_bundle(text, {1: "wrong"}))
        self.assertEqual(before, self._all_tables())


class VerifyValidationTests(_StoreCase):
    def setUp(self):
        super().setUp()
        _store, _request_id, self.text = self._exported()
        self.payload = json.loads(self.text)

    def _assert_value_error(self, text, secrets={1: SECRET_A}):
        with self.assertRaises(ValueError):
            RequestStore.verify_audit_bundle(text, secrets)

    def test_non_string_text(self):
        for bad in (None, 123, b"{}", 1.5, [], {}):
            self._assert_value_error(bad)

    def test_text_boundaries(self):
        self._assert_value_error("")
        self._assert_value_error(self.text[:-1])          # missing newline
        self._assert_value_error(self.text + "\n")        # doubled newline
        self._assert_value_error(self.text[:-1] + "\n\n") # doubled newline
        # Interior line break (pretty-printed) is damage.
        self._assert_value_error(json.dumps(self.payload, indent=2) + "\n")
        self._assert_value_error("not json\n")
        self._assert_value_error('{"request_id": 1}\n')

    def test_field_completeness(self):
        for key in ("request_id", "status", "events", "chain", "anchors",
                    "generations"):
            payload = dict(self.payload)
            del payload[key]
            self._assert_value_error(_render(payload))
        payload = dict(self.payload)
        payload["extra"] = 1
        self._assert_value_error(_render(payload))
        # Nested field completeness.
        payload = json.loads(self.text)
        del payload["events"][0]["chain_hash"]
        self._assert_value_error(_render(payload))
        payload = json.loads(self.text)
        payload["chain"]["subject_id"] = "x"
        self._assert_value_error(_render(payload))
        payload = json.loads(self.text)
        del payload["anchors"][0]["key_generation"]
        self._assert_value_error(_render(payload))
        payload = json.loads(self.text)
        payload["generations"][0]["extra"] = 1
        self._assert_value_error(_render(payload))

    def test_value_shapes(self):
        def mutated(mutate):
            payload = json.loads(self.text)
            mutate(payload)
            return _render(payload)

        self._assert_value_error(mutated(lambda p: p.update(request_id="")))
        self._assert_value_error(mutated(lambda p: p.update(request_id=1)))
        self._assert_value_error(mutated(lambda p: p.update(status="bogus")))
        self._assert_value_error(mutated(lambda p: p.update(events=[])))
        self._assert_value_error(mutated(lambda p: p["events"][0].update(seq=-1)))
        self._assert_value_error(mutated(lambda p: p["events"][0].update(seq=True)))
        self._assert_value_error(mutated(lambda p: p["events"][0].update(seq=0.0)))
        self._assert_value_error(
            mutated(lambda p: p["events"][0].update(occurred_at="yesterday"))
        )
        self._assert_value_error(
            mutated(lambda p: p["events"][0].update(chain_hash="z" * 64))
        )
        self._assert_value_error(mutated(lambda p: p["chain"].update(tenant_id="")))
        self._assert_value_error(mutated(lambda p: p["chain"].update(event_count=0)))
        self._assert_value_error(
            mutated(lambda p: p["chain"].update(event_count=1.5))
        )
        self._assert_value_error(mutated(lambda p: p.update(anchors=[])))
        self._assert_value_error(
            mutated(lambda p: p["anchors"][0].update(key_generation=0))
        )
        self._assert_value_error(
            mutated(lambda p: p["anchors"][0].update(key_generation=1.0))
        )
        self._assert_value_error(
            mutated(lambda p: p["generations"][0].update(generation=-2))
        )
        self._assert_value_error(
            mutated(lambda p: p["generations"][0].update(effective_at="now"))
        )

    def test_invalid_secret_mapping(self):
        for bad in (None, 123, "secret", [], {0: "x"}, {-1: "x"}, {True: "x"},
                    {1.0: "x"}, {"1": "x"}, {1: ""}, {1: None}, {1: 2}):
            self._assert_value_error(self.text, secrets=bad)

    def test_validation_never_writes(self):
        before = self._all_tables()
        for bad in (None, "", "x\n"):
            with self.assertRaises(ValueError):
                RequestStore.verify_audit_bundle(bad, {1: SECRET_A})
        with self.assertRaises(ValueError):
            RequestStore.verify_audit_bundle(self.text, None)
        self.assertEqual(before, self._all_tables())


class ExportErrorTests(_StoreCase):
    def test_invalid_tenant_is_value_error_and_writes_nothing(self):
        store = self._store()
        self._submit(store)
        before = self._all_tables()
        for bad in ("", None, 123, b"tenant-a"):
            with self.assertRaises(ValueError):
                store.export_audit_bundle(bad, "whatever")
        self.assertEqual(before, self._all_tables())

    def test_request_id_errors_are_not_found(self):
        store = self._store()
        request_id = self._submit(store)
        for bad in (None, 123, "", "not-a-request", str(__import__("uuid").uuid4())):
            with self.assertRaises(RequestNotFound):
                store.export_audit_bundle("tenant-a", bad)
        # Cross-tenant lookup shares the same detail-free outcome.
        with self.assertRaises(RequestNotFound):
            store.export_audit_bundle("tenant-b", request_id)

    def test_unanchored_chain_is_unavailable(self):
        store = RequestStore(self.db_path)  # no anchor secret configured
        request_id = self._submit(store)
        with self.assertRaises(AuditBundleUnavailable) as caught:
            store.export_audit_bundle("tenant-a", request_id)
        self.assertEqual(str(caught.exception), "audit bundle is not available")

    def test_missing_secret_on_anchored_chain_is_unavailable(self):
        store, request_id, _text = self._exported()
        no_secret = RequestStore(self.db_path)
        with self.assertRaises(AuditBundleUnavailable):
            no_secret.export_audit_bundle("tenant-a", request_id)

    def test_missing_historical_secret_is_unavailable(self):
        store = self._store()
        request_id = self._submit(store)
        store.rotate_anchor_key(SECRET_A, SECRET_B)
        # Rebuilt without the historical generation-1 secret.
        rebuilt = self._store(secret=SECRET_B)
        with self.assertRaises(AuditBundleUnavailable):
            rebuilt.export_audit_bundle("tenant-a", request_id)
        # With the historical secret the export succeeds.
        complete = self._store(secret=SECRET_B, history={1: SECRET_A})
        text = complete.export_audit_bundle("tenant-a", request_id)
        self.assertTrue(
            RequestStore.verify_audit_bundle(text, {1: SECRET_A, 2: SECRET_B})
        )

    def test_damaged_evidence_is_unavailable(self):
        store, request_id, _text = self._exported()
        with self._raw() as raw:
            raw.execute(
                "UPDATE status_events SET status = 'failed' "
                "WHERE tenant_id = 'tenant-a' AND seq = 1"
            )
        with self.assertRaises(AuditBundleUnavailable):
            self._store().export_audit_bundle("tenant-a", request_id)

    def test_export_failure_produces_no_bundle_and_writes_nothing(self):
        store, request_id, _text = self._exported()
        before = self._all_tables()
        with self.assertRaises(AuditBundleUnavailable):
            RequestStore(self.db_path).export_audit_bundle("tenant-a", request_id)
        with self.assertRaises(RequestNotFound):
            store.export_audit_bundle("tenant-a", "unknown")
        self.assertEqual(before, self._all_tables())

    def test_storage_failure_is_fixed_text_oserror(self):
        store, request_id, _text = self._exported()
        with self._raw() as raw:
            raw.execute("DROP TABLE audit_anchors")
        with self.assertRaises(OSError) as caught:
            store.export_audit_bundle("tenant-a", request_id)
        self.assertEqual(str(caught.exception), "request store is unavailable")

    def test_export_is_read_only(self):
        store, request_id, _text = self._exported()
        before = self._all_tables()
        store.export_audit_bundle("tenant-a", request_id)
        store.export_audit_bundle("tenant-a", request_id)
        self.assertEqual(before, self._all_tables())


class RotationAndLegacyTests(_StoreCase):
    def test_bundle_spans_secret_generations(self):
        store = self._store()
        request_id = self._submit(store)
        store.rotate_anchor_key(SECRET_A, SECRET_B)
        rotated = self._store(secret=SECRET_B, history={1: SECRET_A})
        rotated.transition("tenant-a", request_id, "processing")
        rotated.rotate_anchor_key(SECRET_B, SECRET_C)
        current = self._store(secret=SECRET_C, history={1: SECRET_A, 2: SECRET_B})
        current.transition("tenant-a", request_id, "completed")
        text = current.export_audit_bundle("tenant-a", request_id)
        payload = self._assert_well_formed(text, request_id)
        self.assertEqual(
            [anchor["key_generation"] for anchor in payload["anchors"]],
            [1, 2, 3],
        )
        self.assertEqual(
            [record["generation"] for record in payload["generations"]],
            [1, 2, 3],
        )
        secrets = {1: SECRET_A, 2: SECRET_B, 3: SECRET_C}
        self.assertTrue(RequestStore.verify_audit_bundle(text, secrets))
        # Any single generation's secret missing or wrong fails closed.
        for generation in (1, 2, 3):
            incomplete = dict(secrets)
            del incomplete[generation]
            self.assertFalse(RequestStore.verify_audit_bundle(text, incomplete))
            wrong = dict(secrets)
            wrong[generation] = "wrong-secret"
            self.assertFalse(RequestStore.verify_audit_bundle(text, wrong))

    def test_bundle_records_only_referenced_generations(self):
        store = self._store()
        request_id = self._submit(store)
        store.rotate_anchor_key(SECRET_A, SECRET_B)
        rotated = self._store(secret=SECRET_B, history={1: SECRET_A})
        # This request's events all predate the rotation: only
        # generation 1 is referenced even though 2 exists.
        text = rotated.export_audit_bundle("tenant-a", request_id)
        payload = json.loads(text)
        self.assertEqual(
            [record["generation"] for record in payload["generations"]], [1]
        )
        self.assertTrue(RequestStore.verify_audit_bundle(text, {1: SECRET_A}))

    def test_legacy_null_generation_bundle(self):
        store = self._store()
        request_id = self._submit(store)
        store.transition("tenant-a", request_id, "processing")
        # Simulate a pre-rotation database: NULL attributions and no
        # generation records.
        with self._raw() as raw:
            raw.execute("DELETE FROM anchor_key_generations")
            raw.execute("UPDATE audit_anchors SET key_generation = NULL")
        legacy = self._store()
        text = legacy.export_audit_bundle("tenant-a", request_id)
        payload = self._assert_well_formed(text, request_id)
        self.assertEqual(payload["generations"], [])
        self.assertEqual(
            [anchor["key_generation"] for anchor in payload["anchors"]],
            [None, None],
        )
        self.assertTrue(RequestStore.verify_audit_bundle(text, {1: SECRET_A}))
        self.assertFalse(RequestStore.verify_audit_bundle(text, {1: "wrong"}))
        self.assertFalse(RequestStore.verify_audit_bundle(text, {}))


class HttpSurfaceUnchangedTests(_StoreCase):
    def setUp(self):
        super().setUp()
        self.store = self._store()
        self.server = build_server(self.store, "127.0.0.1", 0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_address[1]

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        super().tearDown()

    def _request(self, method, path, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            conn.request(method, path, body=body, headers={"Content-Type": "application/json"} if body is not None else {})
            response = conn.getresponse()
            return response.status, response.read()
        finally:
            conn.close()

    def test_no_bundle_http_routes(self):
        request_id = self._submit(self.store)
        for method, path in (
            ("GET", f"/requests/{request_id}/bundle"),
            ("POST", "/requests/export"),
            ("POST", "/audit-bundles/verify"),
            ("GET", "/audit_bundles"),
        ):
            status, body = self._request(method, path, body=b"{}")
            self.assertIn(status, (404, 405), (method, path, status))
            self.assertEqual(set(json.loads(body)), {"error"})

    def test_two_documented_endpoints_still_work(self):
        status, body = self._request(
            "POST",
            "/requests",
            body=json.dumps({
                "tenant_id": "tenant-a",
                "subject_id": "subject-1",
                "scopes": ["email"],
                "idempotency_key": "key-1",
            }).encode(),
        )
        self.assertEqual(status, 200)
        receipt = json.loads(body)
        status, body = self._request(
            "GET", f"/requests/{receipt['request_id']}?tenant_id=tenant-a"
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), receipt)


if __name__ == "__main__":
    unittest.main()
