"""Tests for fully offline, recoverable audit bundle diagnosis.

Covers ``RequestStore.diagnose_audit_bundle`` on the storage layer
only: the single-line compact JSON shape (``trusted`` then ``reasons``,
fixed order, exactly one trailing newline, no floats or non-finite
values), trusted output without any database, every stable reason code,
independent problems reported together, Unicode code-point sorting and
deduplication, ValueError parity with ``verify_audit_bundle`` for every
malformed presentation and secret mapping, exact agreement with the
boolean check, rotation and legacy-generation shapes, strictly
read-only behaviour and the absence of any HTTP route, health command
or secret-material leakage.
"""

import hashlib
import http.client
import itertools
import json
import os
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

HEX64 = "0" * 64
_IDEM_COUNTER = itertools.count()


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

    def _submit(self, store, tenant="tenant-a", idem=None):
        if idem is None:
            idem = f"key-{next(_IDEM_COUNTER)}"
        return store.submit(tenant, "subject-1", ["email", "files"], idem)[
            "request_id"
        ]

    def _raw(self):
        return sqlite3.connect(self.db_path)

    def _all_tables(self):
        tables = (
            "requests",
            "status_events",
            "audit_anchors",
            "audit_anchor_meta",
            "anchor_key_generations",
            "inspection_batches",
            "inspection_batch_items",
        )
        with self._raw() as raw:
            return {
                name: raw.execute(f"SELECT * FROM {name}").fetchall()
                for name in tables
            }

    def _exported(self, tenant="tenant-a", advance=2):
        store = self._store()
        request_id = self._submit(store, tenant)
        for status in ("processing", "completed")[:advance]:
            store.transition(tenant, request_id, status)
        return store, request_id, store.export_audit_bundle(tenant, request_id)


class TrustedDiagnosisTests(_StoreCase):
    def test_trusted_output_is_compact_line_with_exact_shape(self):
        _store, request_id, text = self._exported()
        result = RequestStore.diagnose_audit_bundle(text, {1: SECRET_A})
        self.assertIsInstance(result, str)
        self.assertTrue(result.endswith("\n"))
        self.assertFalse(result.endswith("\n\n"))
        body = result[:-1]
        self.assertNotIn("\n", body)
        self.assertNotIn("\r", body)
        self.assertEqual(body, json.dumps(json.loads(body),
                                          separators=(",", ":")))
        self.assertEqual(list(json.loads(body)), ["trusted", "reasons"])
        self.assertEqual(result, '{"trusted":true,"reasons":[]}\n')

    def test_trusted_without_database_or_store(self):
        _store, _request_id, text = self._exported()
        os.unlink(self.db_path)
        self.assertEqual(
            RequestStore.diagnose_audit_bundle(text, {1: SECRET_A}),
            '{"trusted":true,"reasons":[]}\n',
        )

    def test_reasons_sorted_by_unicode_code_point_and_deduplicated(self):
        _store, _request_id, text = self._exported()
        payload = json.loads(text)
        # Four independent defects at once: event order, a tampered
        # hash, the summary head and the snapshot status.
        payload["events"] = payload["events"][::-1]
        payload["events"][1]["chain_hash"] = HEX64
        payload["chain"]["head"] = HEX64
        payload["status"] = "failed"
        result = RequestStore.diagnose_audit_bundle(_render(payload),
                                                    {1: SECRET_A})
        parsed = json.loads(result)
        self.assertFalse(parsed["trusted"])
        self.assertEqual(parsed["reasons"], sorted(set(parsed["reasons"])))
        # Python's default sort is Unicode code-point order.
        self.assertEqual(
            parsed["reasons"],
            sorted(parsed["reasons"], key=lambda s: [ord(c) for c in s]),
        )
        self.assertEqual(
            set(parsed["reasons"]),
            {
                "event_order_invalid",
                "chain_hash_mismatch",
                "chain_head_mismatch",
                "request_association_mismatch",
                "anchor_auth_failed",
            },
        )
        self.assertEqual(result, _render(parsed))
        self.assertTrue(result.endswith("\n"))
        self.assertFalse(result.endswith("\n\n"))

    def test_result_contains_only_booleans_and_strings(self):
        _store, _request_id, text = self._exported()
        payload = json.loads(text)
        payload["anchors"][0]["anchor_hmac"] = HEX64
        result = RequestStore.diagnose_audit_bundle(_render(payload),
                                                    {1: SECRET_A})
        json.dumps(json.loads(result), allow_nan=False)
        parsed = json.loads(result)
        self.assertIsInstance(parsed["trusted"], bool)
        for reason in parsed["reasons"]:
            self.assertIsInstance(reason, str)
            self.assertTrue(reason)
        self.assertNotRegex(result[:-1], r":\s*-\d")

    def test_agrees_with_boolean_verify_on_randomish_tamperings(self):
        _store, _request_id, text = self._exported()
        original = json.loads(text)
        mutations = (
            lambda p: p["events"][0].update(occurred_at="2020-01-01T00:00:00Z"),
            lambda p: p["chain"].update(head=HEX64),
            lambda p: p["chain"].update(event_count=99),
            lambda p: p["chain"].update(tenant_id="tenant-b"),
            lambda p: p.update(status="failed"),
            lambda p: p["anchors"][0].update(anchor_hmac=HEX64),
            lambda p: p["events"].__setitem__(
                slice(None), p["events"][::-1]),
            lambda p: p["generations"][0].update(key_fingerprint=HEX64),
        )
        for mutate in mutations:
            payload = json.loads(json.dumps(original))
            mutate(payload)
            rendered = _render(payload)
            for secrets in ({1: SECRET_A}, {1: "wrong"}, {}, {2: SECRET_A}):
                expected = RequestStore.verify_audit_bundle(rendered, secrets)
                parsed = json.loads(
                    RequestStore.diagnose_audit_bundle(rendered, secrets)
                )
                self.assertEqual(parsed["trusted"], expected,
                                 (mutate.__doc__, secrets, parsed))
                self.assertEqual(parsed["reasons"] == [], expected)


class ReasonCodeTests(_StoreCase):
    def _tamper(self, mutate, secrets=None):
        _store, _request_id, text = self._exported()
        payload = json.loads(text)
        mutate(payload)
        result = RequestStore.diagnose_audit_bundle(
            _render(payload), {1: SECRET_A} if secrets is None else secrets
        )
        return json.loads(result)["reasons"]

    def test_event_order_invalid_on_reorder_gap_and_duplicate(self):
        self.assertIn(
            "event_order_invalid",
            self._tamper(lambda p: p["events"].__setitem__(
                slice(None), p["events"][::-1])),
        )
        self.assertIn(
            "event_order_invalid",
            self._tamper(lambda p: p["events"].__setitem__(
                slice(None), [dict(p["events"][0], seq=0),
                               dict(p["events"][2], seq=2)])),
        )
        # Anchors in a broken order (events intact) is the same order
        # defect, not a hash or association defect.
        reasons = self._tamper(lambda p: p["anchors"].__setitem__(
            slice(None), p["anchors"][::-1]))
        self.assertIn("event_order_invalid", reasons)

    def test_chain_hash_mismatch_on_tampered_event_hash(self):
        reasons = self._tamper(
            lambda p: p["events"][1].update(chain_hash=HEX64)
        )
        self.assertIn("chain_hash_mismatch", reasons)
        # The anchors were not recomputed: the anchor chain also fails,
        # but no spurious order or association reason appears.
        self.assertNotIn("event_order_invalid", reasons)
        self.assertNotIn("request_association_mismatch", reasons)

    def test_chain_hash_mismatch_on_tampered_event_field(self):
        reasons = self._tamper(
            lambda p: p["events"][0].update(occurred_at="2020-01-01T00:00:00Z")
        )
        self.assertIn("chain_hash_mismatch", reasons)
        self.assertIn("anchor_auth_failed", reasons)

    def test_request_association_mismatch_cases(self):
        # Snapshot status disagrees with the final event.
        reasons = self._tamper(lambda p: p.update(status="failed"))
        self.assertIn("request_association_mismatch", reasons)
        # Event count disagrees.
        reasons = self._tamper(
            lambda p: p["chain"].update(event_count=p["chain"]["event_count"] + 1)
        )
        self.assertIn("request_association_mismatch", reasons)
        # Anchor/event population disagreement.
        reasons = self._tamper(lambda p: p["anchors"].pop())
        self.assertIn("request_association_mismatch", reasons)

    def test_chain_head_mismatch_only_on_summary_head(self):
        reasons = self._tamper(lambda p: p["chain"].update(head=HEX64))
        self.assertIn("chain_head_mismatch", reasons)
        self.assertNotIn("request_association_mismatch", reasons)

    def test_anchor_key_missing_never_guesses_current_secret(self):
        store = self._store()
        request_id = self._submit(store)
        store.rotate_anchor_key(SECRET_A, SECRET_B)
        rotated = self._store(secret=SECRET_B, history={1: SECRET_A})
        rotated.transition("tenant-a", request_id, "processing")
        text = rotated.export_audit_bundle("tenant-a", request_id)

        # The generation-1 secret is absent from the handed map.
        reasons = json.loads(
            RequestStore.diagnose_audit_bundle(text, {2: SECRET_B})
        )["reasons"]
        self.assertIn("anchor_key_missing", reasons)
        # Handing the current secret under a historical generation must
        # not authenticate the old anchors: its fingerprint disagrees
        # with generation 1's binding, and it is never guessed as a
        # fallback trial.
        parsed = json.loads(
            RequestStore.diagnose_audit_bundle(
                text, {1: SECRET_B, 2: SECRET_B}
            )
        )
        self.assertFalse(parsed["trusted"])
        self.assertIn("anchor_generation_mismatch", parsed["reasons"])
        # A fully empty map reports the missing material, and the
        # complete map trusts the bundle.
        reasons = json.loads(
            RequestStore.diagnose_audit_bundle(text, {})
        )["reasons"]
        self.assertIn("anchor_key_missing", reasons)
        self.assertEqual(
            RequestStore.diagnose_audit_bundle(
                text, {1: SECRET_A, 2: SECRET_B}
            ),
            '{"trusted":true,"reasons":[]}\n',
        )

    def test_anchor_generation_mismatch_cases(self):
        # Handed secret for a locatable generation has the wrong
        # fingerprint.
        reasons = self._tamper(lambda p: None, secrets={1: "wrong-secret"})
        self.assertIn("anchor_generation_mismatch", reasons)
        self.assertNotIn("anchor_auth_failed", reasons)
        # Anchor naming a generation the bundle does not record.
        reasons = self._tamper(
            lambda p: p["anchors"][0].update(key_generation=9)
        )
        self.assertIn("anchor_generation_mismatch", reasons)
        # Duplicate generation records.
        reasons = self._tamper(
            lambda p: p["generations"].append(dict(p["generations"][0]))
        )
        self.assertIn("anchor_generation_mismatch", reasons)
        # Replaced fingerprint.
        reasons = self._tamper(
            lambda p: p["generations"][0].update(key_fingerprint=HEX64)
        )
        self.assertIn("anchor_generation_mismatch", reasons)
        # Non-null attribution on a legacy (generation-less) bundle.
        _store = self._store()
        request_id = self._submit(_store)
        _store.transition("tenant-a", request_id, "processing")
        with self._raw() as raw:
            raw.execute("DELETE FROM anchor_key_generations")
            raw.execute("UPDATE audit_anchors SET key_generation = NULL")
        text = _store.export_audit_bundle("tenant-a", request_id)
        payload = json.loads(text)
        payload["anchors"][0]["key_generation"] = 2
        reasons = json.loads(
            RequestStore.diagnose_audit_bundle(_render(payload),
                                               {1: SECRET_A, 2: SECRET_B})
        )["reasons"]
        self.assertIn("anchor_generation_mismatch", reasons)

    def test_anchor_auth_failed_when_secret_is_right_but_anchor_forged(self):
        # An attacker recomputes an anchor value without the secret: the
        # fingerprint still matches SECRET_A, so the generation locates
        # and binds, but the MAC does not authenticate.
        reasons = self._tamper(
            lambda p: p["anchors"][1].update(anchor_hmac=HEX64)
        )
        self.assertEqual(reasons, ["anchor_auth_failed"])

    def test_multiple_independent_problems_all_reported(self):
        _store, _request_id, text = self._exported()
        payload = json.loads(text)
        # Independent defects aimed at distinct anchors/fields:
        #  - anchor 0's HMAC forged (right generation/fingerprint)
        #  - anchor 1's generation recorded but absent from the secret map
        #  - a duplicate generation record binding a generation twice
        #  - the chain summary head replaced
        payload["anchors"][0]["anchor_hmac"] = HEX64
        payload["anchors"][1]["key_generation"] = 7
        payload["generations"].append(
            {"generation": 7,
             "key_fingerprint": hashlib.sha256(b"other").hexdigest(),
             "effective_at": payload["generations"][0]["effective_at"]}
        )
        payload["generations"].append(dict(payload["generations"][0]))
        payload["chain"]["head"] = HEX64
        parsed = json.loads(
            RequestStore.diagnose_audit_bundle(_render(payload),
                                               {1: SECRET_A})
        )
        self.assertFalse(parsed["trusted"])
        self.assertEqual(
            set(parsed["reasons"]),
            {
                "anchor_auth_failed",
                "anchor_key_missing",
                "anchor_generation_mismatch",
                "chain_head_mismatch",
            },
        )

    def test_rotation_bundle_diagnoses_per_generation(self):
        store = self._store()
        request_id = self._submit(store)
        store.rotate_anchor_key(SECRET_A, SECRET_B)
        rotated = self._store(secret=SECRET_B, history={1: SECRET_A})
        rotated.transition("tenant-a", request_id, "processing")
        rotated.rotate_anchor_key(SECRET_B, SECRET_C)
        current = self._store(secret=SECRET_C,
                              history={1: SECRET_A, 2: SECRET_B})
        current.transition("tenant-a", request_id, "completed")
        text = current.export_audit_bundle("tenant-a", request_id)
        secrets = {1: SECRET_A, 2: SECRET_B, 3: SECRET_C}
        self.assertEqual(
            RequestStore.diagnose_audit_bundle(text, secrets),
            '{"trusted":true,"reasons":[]}\n',
        )
        for missing in (1, 2, 3):
            incomplete = dict(secrets)
            del incomplete[missing]
            parsed = json.loads(
                RequestStore.diagnose_audit_bundle(text, incomplete)
            )
            self.assertFalse(parsed["trusted"])
            self.assertIn("anchor_key_missing", parsed["reasons"])
        wrong = dict(secrets)
        wrong[2] = "wrong-secret"
        reasons = json.loads(
            RequestStore.diagnose_audit_bundle(text, wrong)
        )["reasons"]
        self.assertIn("anchor_generation_mismatch", reasons)

    def test_legacy_null_generation_bundle(self):
        store = self._store()
        request_id = self._submit(store)
        store.transition("tenant-a", request_id, "processing")
        with self._raw() as raw:
            raw.execute("DELETE FROM anchor_key_generations")
            raw.execute("UPDATE audit_anchors SET key_generation = NULL")
        text = store.export_audit_bundle("tenant-a", request_id)
        self.assertEqual(
            RequestStore.diagnose_audit_bundle(text, {1: SECRET_A}),
            '{"trusted":true,"reasons":[]}\n',
        )
        parsed = json.loads(
            RequestStore.diagnose_audit_bundle(text, {})
        )
        self.assertFalse(parsed["trusted"])
        self.assertIn("anchor_key_missing", parsed["reasons"])
        reasons = json.loads(
            RequestStore.diagnose_audit_bundle(text, {1: "wrong"})
        )["reasons"]
        self.assertIn("anchor_auth_failed", reasons)

    def test_recomputed_replacement_attack_is_untrusted_but_well_formed(self):
        # Attacker alters the last event and recomputes every keyless
        # chain hash plus the summary, but cannot re-seal anchors.
        _store, request_id, text = self._exported(advance=1)
        payload = json.loads(text)
        payload["status"] = "failed"
        payload["events"][1]["status"] = "failed"
        predecessor = payload["events"][0]["chain_hash"]
        payload["events"][1]["chain_hash"] = _chain_hash(
            "tenant-a", request_id, 1, "failed",
            payload["events"][1]["occurred_at"], predecessor,
        )
        payload["chain"]["head"] = payload["events"][1]["chain_hash"]
        parsed = json.loads(
            RequestStore.diagnose_audit_bundle(_render(payload),
                                               {1: SECRET_A})
        )
        self.assertFalse(parsed["trusted"])
        # The keyless proof was recomputed consistently: only the
        # unforgeable anchor fails.
        self.assertEqual(parsed["reasons"], ["anchor_auth_failed"])


class DiagnosisValidationTests(_StoreCase):
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
        self._assert_value_error(self.text[:-1] + "\n\n")
        self._assert_value_error(json.dumps(self.payload, indent=2) + "\n")
        self._assert_value_error("not json\n")
        self._assert_value_error('{"request_id": 1}\n')

    def test_only_compact_presentation_is_accepted(self):
        body = self.text[:-1]
        # Any insignificant whitespace beyond the single required
        # trailing newline is malformed and yields ValueError, never a
        # partial untrusted diagnosis.
        self._assert_value_error(" " + body + "\n")          # leading
        self._assert_value_error(body + " \n")               # trailing
        self._assert_value_error(body + "\t\n")              # tab padding
        self._assert_value_error(
            body.replace(',"', ', "', 1) + "\n"
        )                                                    # indentation
        self._assert_value_error(
            body.replace('":', '": ', 1) + "\n"
        )                                                    # space after colon
        # A non-canonical \u spelling is rejected though json.loads
        # accepts it; the genuine compact export still diagnoses trusted.
        self._assert_value_error(
            body.replace('"tenant-a"', '"\\u0074enant-a"', 1) + "\n"
        )
        self.assertEqual(
            RequestStore.diagnose_audit_bundle(self.text, {1: "anchor-secret-alpha-0001"}),
            '{"trusted":true,"reasons":[]}\n',
        )

    def test_field_completeness(self):
        for key in ("request_id", "status", "events", "chain", "anchors",
                    "generations"):
            payload = dict(self.payload)
            del payload[key]
            self._assert_value_error(_render(payload))
        payload = dict(self.payload)
        payload["extra"] = 1
        self._assert_value_error(_render(payload))
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
        self._assert_value_error(
            mutated(lambda p: p["events"][0].update(seq=-1)))
        self._assert_value_error(
            mutated(lambda p: p["events"][0].update(seq=True)))
        self._assert_value_error(
            mutated(lambda p: p["events"][0].update(seq=0.0)))
        self._assert_value_error(
            mutated(lambda p: p["events"][0].update(chain_hash="z" * 64)))
        self._assert_value_error(
            mutated(lambda p: p["chain"].update(event_count=0)))
        self._assert_value_error(
            mutated(lambda p: p["chain"].update(event_count=1.5)))
        self._assert_value_error(mutated(lambda p: p.update(anchors=[])))
        self._assert_value_error(
            mutated(lambda p: p["anchors"][0].update(key_generation=0)))
        self._assert_value_error(
            mutated(lambda p: p["generations"][0].update(generation=-2)))

    def test_invalid_secret_mapping(self):
        for bad in (None, 123, "secret", [], {0: "x"}, {-1: "x"}, {True: "x"},
                    {1.0: "x"}, {"1": "x"}, {1: ""}, {1: None}, {1: 2}):
            self._assert_value_error(self.text, secrets=bad)

    def test_validation_produces_no_partial_result_and_writes_nothing(self):
        before = self._all_tables()
        for bad in (None, "", "x\n", self.text[:-1], self.text + "\n"):
            with self.assertRaises(ValueError):
                RequestStore.diagnose_audit_bundle(bad, {1: SECRET_A})
        with self.assertRaises(ValueError):
            RequestStore.diagnose_audit_bundle(self.text, None)
        self.assertEqual(before, self._all_tables())


class OfflineAndSafetyTests(_StoreCase):
    def test_diagnosis_is_static_and_never_touches_storage(self):
        store, request_id, text = self._exported()
        before = self._all_tables()
        self.assertTrue(
            json.loads(
                RequestStore.diagnose_audit_bundle(text, {1: SECRET_A})
            )["trusted"]
        )
        payload = json.loads(text)
        payload["anchors"][0]["anchor_hmac"] = HEX64
        RequestStore.diagnose_audit_bundle(_render(payload), {1: SECRET_A})
        # Every table is byte-for-byte unchanged.
        self.assertEqual(before, self._all_tables())
        # And with the database gone the diagnosis still runs, without
        # recreating the file.
        os.unlink(self.db_path)
        RequestStore.diagnose_audit_bundle(text, {1: SECRET_A})
        RequestStore.diagnose_audit_bundle(text, {})
        self.assertFalse(os.path.exists(self.db_path))

    def test_diagnosis_never_leaks_secret_material(self):
        _store, _request_id, text = self._exported()
        secret = "super-secret-material-4242"
        for presented in (
            {1: secret},
            {1: "wrong-but-present"},
            {},
        ):
            try:
                result = RequestStore.diagnose_audit_bundle(text, presented)
            except ValueError as exc:  # pragma: no cover - no parse failure
                self.fail(str(exc))
            self.assertNotIn(secret, result)
        # A wrong secret scenario: the reason text carries no material.
        result = RequestStore.diagnose_audit_bundle(text, {1: secret + "x"})
        self.assertNotIn(secret, result)
        for bad_mapping in (None, 123, {0: secret}, {True: secret}):
            try:
                RequestStore.diagnose_audit_bundle(text, bad_mapping)
            except ValueError as exc:
                self.assertNotIn(secret, str(exc))

    def test_diagnosis_does_not_change_verify_or_export(self):
        store, request_id, text = self._exported()
        RequestStore.diagnose_audit_bundle(text, {1: SECRET_A})
        RequestStore.diagnose_audit_bundle(text, {})
        self.assertTrue(
            RequestStore.verify_audit_bundle(text, {1: SECRET_A})
        )
        self.assertEqual(
            store.export_audit_bundle("tenant-a", request_id), text
        )


class HttpSurfaceUnchangedTests(_StoreCase):
    def setUp(self):
        super().setUp()
        self.store = self._store()
        self.server = build_server(self.store, "127.0.0.1", 0)
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       daemon=True)
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
            conn.request(
                method, path, body=body,
                headers={"Content-Type": "application/json"}
                if body is not None else {},
            )
            response = conn.getresponse()
            return response.status, response.read()
        finally:
            conn.close()

    def test_no_diagnosis_http_routes(self):
        request_id = self._submit(self.store)
        for method, path in (
            ("POST", "/audit-bundles/diagnose"),
            ("POST", "/audit_bundles/diagnose"),
            ("GET", f"/requests/{request_id}/diagnose"),
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
