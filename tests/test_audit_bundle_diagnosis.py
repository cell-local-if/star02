"""Tests for the offline audit bundle diagnosis.

Covers ``RequestStore.diagnose_audit_bundle`` on the storage layer
only: the single-line compact JSON verdict (``trusted`` flag then
``reasons``, exactly one trailing newline, no floats or non-finite
values), the trusted-with-empty-reasons verdict for a genuine bundle
with the database gone, the stable deduplicated code-point-sorted
reason codes for every independent proof failure, the all-determinable-
reasons rule (one problem never masks another), the exact ValueError
contract shared with ``verify_audit_bundle``, the strictly read-only
behaviour and the absence of any HTTP route, database entry or secret
leakage.
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
from forgetting_evidence.requests import RequestStore

SECRET_A = "anchor-secret-alpha-0001"
SECRET_B = "anchor-secret-bravo-0002"
SECRET_C = "anchor-secret-charlie-0003"

HEX64 = re.compile(r"^[0-9a-f]{64}$")

EVENT_ORDER_INVALID = "event_order_invalid"
CHAIN_HASH_MISMATCH = "chain_hash_mismatch"
REQUEST_ASSOCIATION_MISMATCH = "request_association_mismatch"
CHAIN_HEAD_MISMATCH = "chain_head_mismatch"
ANCHOR_KEY_MISSING = "anchor_key_missing"
ANCHOR_GENERATION_MISMATCH = "anchor_generation_mismatch"
ANCHOR_AUTH_FAILED = "anchor_auth_failed"


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

    def _all_tables(self):
        with self._raw() as raw:
            names = [
                row[0]
                for row in raw.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            ]
            return {
                name: raw.execute(f"SELECT * FROM {name}").fetchall()
                for name in names
            }

    def _exported(self, store=None, tenant="tenant-a", advance=2):
        store = store or self._store()
        request_id = self._submit(store, tenant)
        for status in ("processing", "completed")[:advance]:
            store.transition(tenant, request_id, status)
        return store, request_id, store.export_audit_bundle(tenant, request_id)

    def _diagnose(self, text, secrets={1: SECRET_A}):
        return RequestStore.diagnose_audit_bundle(text, secrets)

    def _reasons(self, text, secrets={1: SECRET_A}):
        verdict = self._diagnose(text, secrets)
        return json.loads(verdict)["reasons"]

    def _assert_verdict_shape(self, verdict):
        # Exactly one trailing newline and no other line break.
        self.assertIsInstance(verdict, str)
        self.assertTrue(verdict.endswith("\n"))
        self.assertFalse(verdict.endswith("\n\n"))
        body = verdict[:-1]
        self.assertNotIn("\n", body)
        self.assertNotIn("\r", body)
        # Compact: no insignificant whitespace anywhere.
        self.assertEqual(
            body,
            json.dumps(json.loads(body), ensure_ascii=False, separators=(",", ":")),
        )
        payload = json.loads(body)
        # The trusted flag first, then the reasons array.
        self.assertEqual(list(payload), ["trusted", "reasons"])
        self.assertIsInstance(payload["trusted"], bool)
        self.assertIsInstance(payload["reasons"], list)
        for reason in payload["reasons"]:
            self.assertIsInstance(reason, str)
        # Deduplicated and sorted by Unicode code point.
        self.assertEqual(payload["reasons"], sorted(set(payload["reasons"])))
        # The trusted flag is exactly "no reasons".
        self.assertEqual(payload["trusted"], not payload["reasons"])
        # Never a float, a negative zero or a non-finite number anywhere.
        json.dumps(payload, allow_nan=False)
        self.assertNotRegex(body, r":\s*-\d")
        return payload


class TrustedVerdictTests(_StoreCase):
    def test_valid_bundle_is_trusted_with_empty_reasons(self):
        _store, _request_id, text = self._exported()
        verdict = self._diagnose(text)
        self.assertEqual(verdict, '{"trusted":true,"reasons":[]}\n')
        self._assert_verdict_shape(verdict)

    def test_valid_bundle_diagnoses_without_database(self):
        _store, _request_id, text = self._exported()
        os.unlink(self.db_path)
        self.assertEqual(
            self._diagnose(text), '{"trusted":true,"reasons":[]}\n'
        )

    def test_diagnose_is_static_and_needs_no_store(self):
        _store, _request_id, text = self._exported()
        self.assertEqual(
            RequestStore.diagnose_audit_bundle(text, {1: SECRET_A}),
            '{"trusted":true,"reasons":[]}\n',
        )

    def test_verdict_agrees_with_boolean_verify(self):
        _store, _request_id, text = self._exported()
        mutations = (
            lambda p: p["events"][0].update(
                occurred_at="2020-01-01T00:00:00.000000Z"
            ),
            lambda p: p["chain"].update(head="0" * 64),
            lambda p: p["chain"].update(event_count=9),
            lambda p: p.update(status="failed"),
            lambda p: p["anchors"][0].update(anchor_hmac="0" * 64),
            lambda p: p["anchors"][0].update(key_generation=9),
            lambda p: p["generations"][0].update(key_fingerprint="1" * 64),
            lambda p: p.update(events=p["events"][::-1]),
        )
        candidates = [(text, {1: SECRET_A}), (text, {}), (text, {1: "wrong"})]
        for mutate in mutations:
            payload = json.loads(text)
            mutate(payload)
            candidates.append((_render(payload), {1: SECRET_A}))
        for bundle_text, secrets in candidates:
            verdict = json.loads(self._diagnose(bundle_text, secrets))
            self.assertEqual(
                verdict["trusted"],
                RequestStore.verify_audit_bundle(bundle_text, secrets),
            )
            self.assertEqual(verdict["trusted"], not verdict["reasons"])

    def test_unicode_bundle_diagnoses_trusted(self):
        store = self._store()
        request_id = store.submit("租户-甲", "subject-1", ["email"], "键-1")[
            "request_id"
        ]
        store.transition("租户-甲", request_id, "processing")
        text = store.export_audit_bundle("租户-甲", request_id)
        self.assertEqual(
            self._diagnose(text), '{"trusted":true,"reasons":[]}\n'
        )


class ReasonCodeTests(_StoreCase):
    def setUp(self):
        super().setUp()
        _store, self.request_id, self.text = self._exported()

    def _mutated(self, mutate):
        payload = json.loads(self.text)
        mutate(payload)
        return _render(payload)

    def test_event_order_invalid(self):
        # Renumbered sequence: order, link hashes and anchor seals all
        # break independently and every one is reported.
        text = self._mutated(lambda p: p["events"][1].update(seq=5))
        self.assertEqual(
            self._reasons(text),
            [ANCHOR_AUTH_FAILED, CHAIN_HASH_MISMATCH, EVENT_ORDER_INVALID],
        )

    def test_event_reorder_reports_order_chain_and_anchor(self):
        # A full reversal also moves the final event, so the chain head
        # and the snapshot status association break independently too.
        text = self._mutated(lambda p: p.update(events=p["events"][::-1]))
        self.assertEqual(
            self._reasons(text),
            [
                ANCHOR_AUTH_FAILED,
                CHAIN_HASH_MISMATCH,
                CHAIN_HEAD_MISMATCH,
                EVENT_ORDER_INVALID,
                REQUEST_ASSOCIATION_MISMATCH,
            ],
        )

    def test_chain_hash_mismatch(self):
        text = self._mutated(
            lambda p: p["events"][0].update(
                occurred_at="2020-01-01T00:00:00.000000Z"
            )
        )
        self.assertEqual(
            self._reasons(text), [ANCHOR_AUTH_FAILED, CHAIN_HASH_MISMATCH]
        )

    def test_recomputed_chain_forgery_is_anchor_auth_failed(self):
        # An attacker can recompute the keyless chain hashes after
        # altering an inner event, but cannot re-seal the anchors.
        def forge(payload):
            payload["events"][1]["status"] = "failed"
            predecessor = payload["events"][0]["chain_hash"]
            for index in (1, 2):
                event = payload["events"][index]
                predecessor = _chain_hash(
                    "tenant-a", self.request_id, index, event["status"],
                    event["occurred_at"], predecessor,
                )
                event["chain_hash"] = predecessor
            payload["chain"]["head"] = predecessor

        text = self._mutated(forge)
        self.assertEqual(self._reasons(text), [ANCHOR_AUTH_FAILED])

    def test_request_association_mismatch(self):
        text = self._mutated(
            lambda p: p["chain"].update(event_count=p["chain"]["event_count"] + 1)
        )
        self.assertEqual(self._reasons(text), [REQUEST_ASSOCIATION_MISMATCH])
        text = self._mutated(lambda p: p.update(status="failed"))
        self.assertEqual(self._reasons(text), [REQUEST_ASSOCIATION_MISMATCH])

    def test_anchor_population_mismatch_is_association(self):
        text = self._mutated(lambda p: p["anchors"].pop(0))
        reasons = self._reasons(text)
        self.assertIn(REQUEST_ASSOCIATION_MISMATCH, reasons)
        text = self._mutated(lambda p: p["anchors"][1].update(seq=7))
        reasons = self._reasons(text)
        self.assertIn(REQUEST_ASSOCIATION_MISMATCH, reasons)

    def test_chain_head_mismatch(self):
        text = self._mutated(lambda p: p["chain"].update(head="0" * 64))
        self.assertEqual(self._reasons(text), [CHAIN_HEAD_MISMATCH])

    def test_anchor_key_missing(self):
        self.assertEqual(self._reasons(self.text, {}), [ANCHOR_KEY_MISSING])
        self.assertEqual(
            self._reasons(self.text, {2: SECRET_A}), [ANCHOR_KEY_MISSING]
        )

    def test_anchor_generation_mismatch(self):
        # The handed secret does not match the recorded fingerprint.
        self.assertEqual(
            self._reasons(self.text, {1: "wrong"}),
            [ANCHOR_GENERATION_MISMATCH],
        )
        # The anchor names a generation the bundle does not record.
        text = self._mutated(lambda p: p["anchors"][0].update(key_generation=9))
        self.assertEqual(self._reasons(text), [ANCHOR_GENERATION_MISMATCH])
        # The recorded fingerprint was replaced.
        text = self._mutated(
            lambda p: p["generations"][0].update(key_fingerprint="1" * 64)
        )
        self.assertEqual(self._reasons(text), [ANCHOR_GENERATION_MISMATCH])
        # Duplicate generation records.
        text = self._mutated(
            lambda p: p["generations"].append(dict(p["generations"][0]))
        )
        self.assertEqual(self._reasons(text), [ANCHOR_GENERATION_MISMATCH])
        # Non-null generation with no generation records at all.
        text = self._mutated(lambda p: p.update(generations=[]))
        self.assertEqual(self._reasons(text), [ANCHOR_GENERATION_MISMATCH])

    def test_anchor_auth_failed(self):
        text = self._mutated(
            lambda p: p["anchors"][0].update(anchor_hmac="0" * 64)
        )
        self.assertEqual(self._reasons(text), [ANCHOR_AUTH_FAILED])

    def test_multiple_independent_problems_all_reported(self):
        def mutate(payload):
            payload["status"] = "failed"
            payload["chain"]["head"] = "0" * 64
            payload["events"][0]["occurred_at"] = "2020-01-01T00:00:00.000000Z"

        text = self._mutated(mutate)
        self.assertEqual(
            self._reasons(text),
            [
                ANCHOR_AUTH_FAILED,
                CHAIN_HASH_MISMATCH,
                CHAIN_HEAD_MISMATCH,
                REQUEST_ASSOCIATION_MISMATCH,
            ],
        )

    def test_one_problem_does_not_mask_others(self):
        # A missing secret for one anchor never cascades into spurious
        # authentication failures for the anchors that can be proven.
        store = self._store()
        request_id = self._submit(store, idem="key-rotated")
        store.rotate_anchor_key(SECRET_A, SECRET_B)
        rotated = self._store(secret=SECRET_B, history={1: SECRET_A})
        rotated.transition("tenant-a", request_id, "processing")
        rotated.transition("tenant-a", request_id, "completed")
        text = rotated.export_audit_bundle("tenant-a", request_id)
        # Only generation 1's secret is missing: exactly one reason.
        self.assertEqual(self._reasons(text, {2: SECRET_B}), [ANCHOR_KEY_MISSING])
        # Both secrets present: fully trusted.
        self.assertEqual(
            self._diagnose(text, {1: SECRET_A, 2: SECRET_B}),
            '{"trusted":true,"reasons":[]}\n',
        )


class RotationAndLegacyDiagnosisTests(_StoreCase):
    def _rotated_bundle(self):
        store = self._store()
        request_id = self._submit(store)
        store.rotate_anchor_key(SECRET_A, SECRET_B)
        rotated = self._store(secret=SECRET_B, history={1: SECRET_A})
        rotated.transition("tenant-a", request_id, "processing")
        rotated.rotate_anchor_key(SECRET_B, SECRET_C)
        current = self._store(secret=SECRET_C, history={1: SECRET_A, 2: SECRET_B})
        current.transition("tenant-a", request_id, "completed")
        return current.export_audit_bundle("tenant-a", request_id)

    def test_spanning_bundle_diagnoses_per_generation(self):
        text = self._rotated_bundle()
        secrets = {1: SECRET_A, 2: SECRET_B, 3: SECRET_C}
        self.assertEqual(
            self._diagnose(text, secrets), '{"trusted":true,"reasons":[]}\n'
        )
        for generation in (1, 2, 3):
            incomplete = dict(secrets)
            del incomplete[generation]
            self.assertEqual(self._reasons(text, incomplete), [ANCHOR_KEY_MISSING])
            wrong = dict(secrets)
            wrong[generation] = "wrong-secret"
            self.assertEqual(
                self._reasons(text, wrong), [ANCHOR_GENERATION_MISMATCH]
            )

    def test_legacy_null_generation_bundle(self):
        store = self._store()
        request_id = self._submit(store)
        store.transition("tenant-a", request_id, "processing")
        with self._raw() as raw:
            raw.execute("DELETE FROM anchor_key_generations")
            raw.execute("UPDATE audit_anchors SET key_generation = NULL")
        text = self._store().export_audit_bundle("tenant-a", request_id)
        self.assertEqual(
            self._diagnose(text), '{"trusted":true,"reasons":[]}\n'
        )
        self.assertEqual(self._reasons(text, {}), [ANCHOR_KEY_MISSING])
        # The legacy shape binds no fingerprint: a wrong handed secret
        # simply fails to authenticate the tags.
        self.assertEqual(self._reasons(text, {1: "wrong"}), [ANCHOR_AUTH_FAILED])


class DiagnoseValidationTests(_StoreCase):
    def setUp(self):
        super().setUp()
        _store, _request_id, self.text = self._exported()
        self.payload = json.loads(self.text)

    def _assert_value_error(self, text, secrets={1: SECRET_A}):
        with self.assertRaises(ValueError):
            RequestStore.diagnose_audit_bundle(text, secrets)

    def test_non_string_text(self):
        for bad in (None, 123, b"{}", 1.5, [], {}):
            self._assert_value_error(bad)

    def test_text_boundaries(self):
        self._assert_value_error("")
        self._assert_value_error(self.text[:-1])          # missing newline
        self._assert_value_error(self.text + "\n")        # doubled newline
        self._assert_value_error(self.text[:-1] + "\n\n")  # doubled newline
        self._assert_value_error(json.dumps(self.payload, indent=2) + "\n")
        self._assert_value_error("not json\n")
        self._assert_value_error('{"request_id": 1}\n')

    def test_field_completeness_and_shapes(self):
        def mutated(mutate):
            payload = json.loads(self.text)
            mutate(payload)
            return _render(payload)

        for key in ("request_id", "status", "events", "chain", "anchors",
                    "generations"):
            self._assert_value_error(
                mutated(lambda p, key=key: p.pop(key))
            )
        self._assert_value_error(mutated(lambda p: p.update(extra=1)))
        self._assert_value_error(mutated(lambda p: p.update(request_id="")))
        self._assert_value_error(mutated(lambda p: p.update(status="bogus")))
        self._assert_value_error(mutated(lambda p: p.update(events=[])))
        self._assert_value_error(
            mutated(lambda p: p["events"][0].update(seq=True))
        )
        self._assert_value_error(
            mutated(lambda p: p["events"][0].update(seq=0.0))
        )
        self._assert_value_error(
            mutated(lambda p: p["events"][0].update(chain_hash="z" * 64))
        )
        self._assert_value_error(
            mutated(lambda p: p["chain"].update(event_count=1.5))
        )
        self._assert_value_error(mutated(lambda p: p.update(anchors=[])))
        self._assert_value_error(
            mutated(lambda p: p["anchors"][0].update(key_generation=0))
        )
        self._assert_value_error(
            mutated(lambda p: p["generations"][0].update(generation=-2))
        )

    def test_invalid_secret_mapping(self):
        for bad in (None, 123, "secret", [], {0: "x"}, {-1: "x"}, {True: "x"},
                    {1.0: "x"}, {"1": "x"}, {1: ""}, {1: None}, {1: 2}):
            self._assert_value_error(self.text, secrets=bad)

    def test_validation_failure_produces_no_partial_result(self):
        # A validation failure raises before any verdict exists: there
        # is no partial output to observe, and nothing is written.
        before = self._all_tables()
        for bad in (None, "", "x\n", self.text + "\n"):
            with self.assertRaises(ValueError):
                RequestStore.diagnose_audit_bundle(bad, {1: SECRET_A})
        with self.assertRaises(ValueError):
            RequestStore.diagnose_audit_bundle(self.text, None)
        self.assertEqual(before, self._all_tables())


class DiagnoseBoundaryTests(_StoreCase):
    def test_diagnosis_never_writes_anywhere(self):
        _store, _request_id, text = self._exported()
        before = self._all_tables()
        self._diagnose(text)
        self._diagnose(text, {})
        payload = json.loads(text)
        payload["anchors"][0]["anchor_hmac"] = "0" * 64
        self._diagnose(_render(payload))
        self.assertEqual(before, self._all_tables())

    def test_secrets_never_reach_result_or_exception(self):
        _store, _request_id, text = self._exported()
        for secrets in ({1: SECRET_A}, {}, {1: "wrong"}):
            verdict = self._diagnose(text, secrets)
            self.assertNotIn(SECRET_A, verdict)
            self.assertNotIn("wrong", verdict)
        try:
            RequestStore.diagnose_audit_bundle(text, {1: ""})
        except ValueError as caught:
            self.assertNotIn(SECRET_A, str(caught))
        else:
            self.fail("expected ValueError")

    def test_no_new_http_route(self):
        store = self._store()
        server = build_server(store, "127.0.0.1", 0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            port = server.server_address[1]
            for method, path in (
                ("POST", "/audit-bundles/diagnose"),
                ("GET", "/audit-bundles/diagnose"),
                ("POST", "/diagnose"),
            ):
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                try:
                    conn.request(method, path, body=b"{}")
                    response = conn.getresponse()
                    status, body = response.status, response.read()
                finally:
                    conn.close()
                self.assertIn(status, (404, 405), (method, path, status))
                self.assertEqual(set(json.loads(body)), {"error"})
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
