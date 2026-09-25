"""Tests for externally verifiable deletion receipts.

Covers the two storage-layer entry points RequestStore.generate_receipt
and RequestStore.verify_receipt: eligibility (only settled completions),
document shape/field order/commitments, HMAC authentication, earliest
terminal binding, byte-identical idempotency across repeats/concurrency/
rebuilds, the full tamper matrix for verification (field/tag/time/
request/tenant substitution), error semantics (ValueError /
RequestNotFound / ReceiptUnavailable / fixed-text OSError), no key
material leakage, read-only verification and atomic persistence. These
entry points are deliberately not exposed over HTTP.
"""

import json
import os
import re
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor

from forgetting_evidence import receipts as receipt_format
from forgetting_evidence.requests import (
    ReceiptUnavailable,
    RequestNotFound,
    RequestStore,
)

HEX64 = re.compile(r"^[0-9a-f]{64}$")
RFC3339 = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$"
)

KEY = b"receipt-master-key"
KEY_2 = b"receipt-master-key-two"
STORAGE_MESSAGE = "request store is unavailable"


class _StoreCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "evidence.db")

    def tearDown(self):
        self._tmp.cleanup()

    def store(self):
        return RequestStore(self.db_path)

    def raw(self):
        return sqlite3.connect(self.db_path)

    def submit(self, store=None, tenant="tenant-a", key="k1", scopes=("email",)):
        store = store if store is not None else self.store()
        return store, store.submit(tenant, "subject-1", list(scopes), key)

    def complete(self, store, rid, lease=3600, result="completed"):
        """Drive a request through claim + finish and return the claim."""
        claim = store.claim_next("tenant-a", "worker-1", lease)
        assert claim["request_id"] == rid
        store.finish_claim("tenant-a", rid, claim["claim_token"], result)
        return claim

    def completed_request(self, scopes=("email",)):
        store = self.store()
        _, receipt = self.submit(store, scopes=scopes)
        rid = receipt["request_id"]
        self.complete(store, rid)
        return store, receipt


def parse_doc(document):
    assert isinstance(document, bytes)
    return json.loads(document)


class ReceiptShapeTests(_StoreCase):
    def test_document_field_order_and_trailing_newline(self):
        store, receipt = self.completed_request()
        document = store.generate_receipt("tenant-a", receipt["request_id"], KEY)
        self.assertIsInstance(document, bytes)
        self.assertTrue(document.endswith(b"\n"))
        self.assertEqual(document.count(b"\n"), 1)
        # Compact JSON: no insignificant whitespace.
        self.assertNotIn(b" ", document)
        head = document[: document.index(b"auth_tag")]
        self.assertIn(b",", head)
        # Order is fixed and exactly these nine fields.
        fields = list(parse_doc(document))
        self.assertEqual(
            fields,
            [
                "receipt_version",
                "receipt_type",
                "tenant_id",
                "request_id",
                "accepted_at",
                "completed_at",
                "scope_commitment",
                "completion_commitment",
                "auth_tag",
            ],
        )

    def test_document_values(self):
        store, receipt = self.completed_request(scopes=("email", "profile"))
        rid = receipt["request_id"]
        document = parse_doc(
            store.generate_receipt("tenant-a", rid, KEY)
        )
        self.assertEqual(document["receipt_version"], 1)
        self.assertEqual(document["receipt_type"], "deletion_confirmation")
        self.assertEqual(document["tenant_id"], "tenant-a")
        self.assertEqual(document["request_id"], rid)
        self.assertEqual(document["accepted_at"], receipt["created_at"])
        for time_field in ("accepted_at", "completed_at"):
            self.assertTrue(RFC3339.match(document[time_field]))
        self.assertTrue(HEX64.match(document["scope_commitment"]))
        self.assertTrue(HEX64.match(document["completion_commitment"]))
        self.assertTrue(HEX64.match(document["auth_tag"]))
        status = store.get_status("tenant-a", rid)
        self.assertEqual(status["status"], "completed")
        log = store.get_execution_log("tenant-a", rid)
        self.assertEqual(log[-1]["result"], "completed")
        self.assertEqual(document["completed_at"], log[-1]["completed_at"])

    def test_scope_commitment_matches_canonical_scopes(self):
        store, receipt = self.completed_request(scopes=("zeta", "alpha", "mid"))
        rid = receipt["request_id"]
        document = parse_doc(store.generate_receipt("tenant-a", rid, KEY))
        canonical = json.dumps(
            sorted(["zeta", "alpha", "mid"]), separators=(",", ":")
        )
        import hashlib

        self.assertEqual(
            document["scope_commitment"],
            hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        )

    def test_completion_commitment_binds_earliest_attempt(self):
        store = self.store()
        _, receipt = self.submit(store, key="k1")
        rid = receipt["request_id"]
        self.complete(store, rid)
        document = parse_doc(store.generate_receipt("tenant-a", rid, KEY))
        log = store.get_execution_log("tenant-a", rid)
        self.assertEqual(
            document["completion_commitment"],
            receipt_format.completion_commitment(
                log[0]["attempt_number"],
                log[0]["result"],
                log[0]["completed_at"],
            ),
        )


class ReceiptEligibilityTests(_StoreCase):
    def test_accepted_request_is_unavailable(self):
        store, receipt = self.submit()
        with self.assertRaises(ReceiptUnavailable):
            store.generate_receipt("tenant-a", receipt["request_id"], KEY)

    def test_processing_request_is_unavailable(self):
        store = self.store()
        _, receipt = self.submit(store)
        rid = receipt["request_id"]
        claim = store.claim_next("tenant-a", "worker-1", 3600)
        self.assertEqual(claim["request_id"], rid)
        with self.assertRaises(ReceiptUnavailable):
            store.generate_receipt("tenant-a", rid, KEY)

    def test_failed_request_is_unavailable(self):
        store = self.store()
        _, receipt = self.submit(store)
        rid = receipt["request_id"]
        self.complete(store, rid, result="failed")
        with self.assertRaises(ReceiptUnavailable):
            store.generate_receipt("tenant-a", rid, KEY)

    def test_completed_status_without_execution_record_is_unavailable(self):
        # A terminal reached purely through the status machine, with no
        # settled execution attempt to bind, cannot yield a receipt.
        store = self.store()
        _, receipt = self.submit(store)
        rid = receipt["request_id"]
        store.transition("tenant-a", rid, "processing")
        store.transition("tenant-a", rid, "completed")
        with self.assertRaises(ReceiptUnavailable):
            store.generate_receipt("tenant-a", rid, KEY)

    def test_unavailable_writes_no_receipt_row(self):
        store, receipt = self.submit()
        with self.assertRaises(ReceiptUnavailable):
            store.generate_receipt("tenant-a", receipt["request_id"], KEY)
        with self.raw() as conn:
            self.assertEqual(
                conn.execute("SELECT count(*) FROM deletion_receipts").fetchone()[0],
                0,
            )

    def test_missing_foreign_and_never_accepted_raise_not_found(self):
        store, receipt = self.completed_request()
        rid = receipt["request_id"]
        with self.assertRaises(RequestNotFound):
            store.generate_receipt("tenant-a", "no-such-request", KEY)
        with self.assertRaises(RequestNotFound):
            store.generate_receipt("tenant-b", rid, KEY)
        for bad in ("", None, 7, b"rid", ["rid"], 3.14):
            with self.subTest(bad=bad):
                with self.assertRaises(RequestNotFound):
                    store.generate_receipt("tenant-a", bad, KEY)


class ReceiptValidationTests(_StoreCase):
    def test_invalid_tenant_raises_value_error(self):
        store, receipt = self.completed_request()
        for bad in ("", None, 7, b"tenant", ["t"], 3.14, True):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    store.generate_receipt(bad, receipt["request_id"], KEY)

    def test_invalid_key_raises_value_error(self):
        store, receipt = self.completed_request()
        rid = receipt["request_id"]
        for bad in (None, "", "str-key", 1, 1.5, [], b"", bytearray(), True):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    store.generate_receipt("tenant-a", rid, bad)

    def test_bytearray_key_is_accepted(self):
        store, receipt = self.completed_request()
        rid = receipt["request_id"]
        doc_a = store.generate_receipt("tenant-a", rid, KEY)
        doc_b = store.generate_receipt("tenant-a", rid, bytearray(KEY))
        self.assertEqual(doc_a, doc_b)

    def test_invalid_arguments_never_write(self):
        store, receipt = self.completed_request()
        rid = receipt["request_id"]
        with open(self.db_path, "rb") as handle:
            before = handle.read()
        for bad_key in (None, "", "x", b""):
            try:
                store.generate_receipt("tenant-a", rid, bad_key)
            except ValueError:
                pass
        for bad_tenant in ("", None):
            try:
                store.generate_receipt(bad_tenant, rid, KEY)
            except ValueError:
                pass
        # The failed first call must not have stored a receipt, so the
        # next valid call genuinely issues the first document.
        document = store.generate_receipt("tenant-a", rid, KEY)
        with open(self.db_path, "rb") as handle:
            after = handle.read()
        self.assertNotEqual(before, after)
        self.assertTrue(document.endswith(b"\n"))


class ReceiptIdempotencyTests(_StoreCase):
    def test_repeat_generation_is_byte_identical(self):
        store, receipt = self.completed_request()
        rid = receipt["request_id"]
        first = store.generate_receipt("tenant-a", rid, KEY)
        for _ in range(5):
            self.assertEqual(
                store.generate_receipt("tenant-a", rid, KEY), first
            )
        # A different presented key never changes the first document.
        self.assertEqual(
            store.generate_receipt("tenant-a", rid, KEY_2), first
        )

    def test_rebuild_and_restart_keep_bytes(self):
        store, receipt = self.completed_request()
        rid = receipt["request_id"]
        first = store.generate_receipt("tenant-a", rid, KEY)
        rebuilt = self.store()
        self.assertEqual(rebuilt.generate_receipt("tenant-a", rid, KEY), first)
        # A fresh store over the same file after "restart".
        again = RequestStore(self.db_path)
        self.assertEqual(again.generate_receipt("tenant-a", rid, KEY), first)
        self.assertTrue(again.verify_receipt(first, KEY))

    def test_concurrent_generation_persists_one_row(self):
        store, receipt = self.completed_request()
        rid = receipt["request_id"]

        def issue(_):
            return self.store().generate_receipt("tenant-a", rid, KEY)

        with ThreadPoolExecutor(max_workers=16) as pool:
            documents = list(pool.map(issue, range(32)))
        self.assertTrue(all(doc == documents[0] for doc in documents))
        with self.raw() as conn:
            rows = conn.execute(
                "SELECT count(*), count(DISTINCT receipt_bytes) "
                "FROM deletion_receipts"
            ).fetchone()
        self.assertEqual(rows, (1, 1))

    def test_exactly_one_receipt_row_per_request(self):
        store, receipt = self.completed_request()
        rid = receipt["request_id"]
        store.generate_receipt("tenant-a", rid, KEY)
        store.generate_receipt("tenant-a", rid, KEY_2)
        with self.raw() as conn:
            count = conn.execute(
                "SELECT count(*) FROM deletion_receipts "
                "WHERE tenant_id = ? AND request_id = ?",
                ("tenant-a", rid),
            ).fetchone()[0]
        self.assertEqual(count, 1)


class EarliestTerminalBindingTests(_StoreCase):
    def _two_completed_attempts(self):
        """Force two completed attempts (earliest wins) out of band.

        Normal execution can only ever finish one live lease; a second
        completed row is the duplicate-terminal condition reconcile
        normalises. We construct it directly so receipt binding can be
        checked against the same earliest-completion rule.
        """
        store = self.store()
        _, receipt = self.submit(store)
        rid = receipt["request_id"]
        self.complete(store, rid)
        first = store.get_execution_log("tenant-a", rid)[0]
        with self.raw() as conn:
            conn.execute(
                "INSERT INTO claim_attempts ("
                "tenant_id, request_id, attempt_number, claimed_at, "
                "lease_expires_at, result, completed_at"
                ") VALUES (?, ?, 2, ?, ?, 'completed', ?)",
                (
                    "tenant-a",
                    rid,
                    "2027-02-02T00:00:00.000000Z",
                    "2027-02-02T01:00:00.000000Z",
                    "2027-02-02T02:00:00.000000Z",
                ),
            )
        return store, receipt, first

    def test_receipt_binds_earliest_completion(self):
        store, receipt, first = self._two_completed_attempts()
        rid = receipt["request_id"]
        document = parse_doc(store.generate_receipt("tenant-a", rid, KEY))
        self.assertEqual(document["completed_at"], first["completed_at"])
        self.assertEqual(
            document["completion_commitment"],
            receipt_format.completion_commitment(
                first["attempt_number"],
                "completed",
                first["completed_at"],
            ),
        )

    def test_later_duplicate_terminal_does_not_change_receipt(self):
        store, receipt, first = self._two_completed_attempts()
        rid = receipt["request_id"]
        before = store.generate_receipt("tenant-a", rid, KEY)
        # Normalising the duplicate (downgrading attempt 2) and reading
        # again leaves the first receipt byte-identical.
        store.reconcile_execution("tenant-a", rid)
        after = store.generate_receipt("tenant-a", rid, KEY)
        self.assertEqual(before, after)


class VerifySuccessTests(_StoreCase):
    def test_verify_true_for_issued_receipt(self):
        store, receipt = self.completed_request()
        rid = receipt["request_id"]
        document = store.generate_receipt("tenant-a", rid, KEY)
        self.assertTrue(store.verify_receipt(document, KEY))
        # str input is accepted as well.
        self.assertTrue(store.verify_receipt(document.decode("utf-8"), KEY))
        # After rebuild.
        self.assertTrue(self.store().verify_receipt(document, KEY))

    def test_verify_without_receipt_being_issued_is_false(self):
        # A well-formed, correctly-tagged document for a genuinely
        # completed request that never had a receipt persisted must not
        # authenticate: request existence is not enough.
        store = self.store()
        _, receipt = self.submit(store)
        rid = receipt["request_id"]
        self.complete(store, rid)
        log = store.get_execution_log("tenant-a", rid)[0]
        with self.raw() as conn:
            scopes_json = conn.execute(
                "SELECT scopes_json FROM requests WHERE request_id = ?", (rid,)
            ).fetchone()[0]
        document = receipt_format.build_receipt(
            "tenant-a",
            rid,
            receipt["created_at"],
            log["completed_at"],
            receipt_format.scope_commitment(scopes_json),
            log["attempt_number"],
            "completed",
            KEY,
        )
        self.assertFalse(store.verify_receipt(document, KEY))


class VerifyTamperTests(_StoreCase):
    def _issued(self):
        store, receipt = self.completed_request()
        rid = receipt["request_id"]
        document = store.generate_receipt("tenant-a", rid, KEY)
        return store, rid, document

    def _retag(self, obj, key=KEY):
        obj = dict(obj)
        obj["auth_tag"] = receipt_format.expected_tag(obj, key)
        return (json.dumps(obj, separators=(",", ":")) + "\n").encode("utf-8")

    def test_wrong_key_returns_false(self):
        store, rid, document = self._issued()
        self.assertFalse(store.verify_receipt(document, KEY_2))

    def test_tag_substitution_returns_false(self):
        store, rid, document = self._issued()
        obj = parse_doc(document)
        flipped = ("0" if obj["auth_tag"][0] != "0" else "1") + obj["auth_tag"][1:]
        obj["auth_tag"] = flipped
        forged = (json.dumps(obj, separators=(",", ":")) + "\n").encode("utf-8")
        self.assertFalse(store.verify_receipt(forged, KEY))

    def _swap(self, document, **changes):
        obj = parse_doc(document)
        obj.update(changes)
        # Re-sign with the same key: a valid tag over altered content.
        body = json.dumps(
            {k: v for k, v in obj.items() if k != "auth_tag"},
            separators=(",", ":"),
        )
        obj["auth_tag"] = receipt_format.expected_tag(obj, KEY)
        return (json.dumps(obj, separators=(",", ":")) + "\n").encode("utf-8")

    def test_tenant_substitution_valid_tag_returns_false(self):
        store, rid, document = self._issued()
        forged = self._swap(document, tenant_id="tenant-b")
        self.assertTrue(receipt_format.parse_receipt(forged))
        self.assertFalse(store.verify_receipt(forged, KEY))

    def test_request_substitution_valid_tag_returns_false(self):
        store, rid, document = self._issued()
        other = self.submit(store, key="k2")[1]["request_id"]
        forged = self._swap(document, request_id=other)
        self.assertFalse(store.verify_receipt(forged, KEY))

    def test_timestamp_substitution_returns_false(self):
        store, rid, document = self._issued()
        forged = self._swap(
            document, accepted_at="2020-01-01T00:00:00.000000Z"
        )
        self.assertFalse(store.verify_receipt(forged, KEY))
        forged2 = self._swap(
            document, completed_at="2030-01-01T00:00:00.000000Z"
        )
        self.assertFalse(store.verify_receipt(forged2, KEY))

    def test_scope_commitment_substitution_returns_false(self):
        store, rid, document = self._issued()
        forged = self._swap(document, scope_commitment="a" * 64)
        self.assertFalse(store.verify_receipt(forged, KEY))

    def test_completion_commitment_substitution_returns_false(self):
        store, rid, document = self._issued()
        forged = self._swap(document, completion_commitment="b" * 64)
        self.assertFalse(store.verify_receipt(forged, KEY))

    def test_well_formed_but_unauthenticated_is_false_not_error(self):
        store, rid, document = self._issued()
        obj = parse_doc(document)
        obj["auth_tag"] = "f" * 64
        forged = (json.dumps(obj, separators=(",", ":")) + "\n").encode("utf-8")
        # The request exists, yet authentication failure is a bare False.
        self.assertFalse(store.verify_receipt(forged, KEY))

    def test_receipt_for_unknown_request_valid_tag_is_false(self):
        store, rid, document = self._issued()
        forged = self._swap(
            document, request_id="11111111-1111-4111-8111-111111111111"
        )
        self.assertFalse(store.verify_receipt(forged, KEY))


class VerifyFormatTests(_StoreCase):
    def test_malformed_documents_raise_value_error(self):
        store, _receipt = self.completed_request()
        bad_values = [
            None,
            123,
            1.5,
            [],
            {},
            b"",
            b"\x00\xff",
            "no-newline",
            "two\nlines\n",
            b"{not json}\n",
            b"[]\n",
            b"null\n",
            json.dumps({"a": 1}).encode() + b"\n",
        ]
        for bad in bad_values:
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    store.verify_receipt(bad, KEY)

    def test_reordered_fields_raise_value_error(self):
        store, receipt = self.completed_request()
        rid = receipt["request_id"]
        document = store.generate_receipt("tenant-a", rid, KEY)
        obj = parse_doc(document)
        reordered = dict(reversed(list(obj.items())))
        text = (json.dumps(reordered, separators=(",", ":")) + "\n").encode()
        with self.assertRaises(ValueError):
            store.verify_receipt(text, KEY)

    def test_pretty_json_raises_value_error(self):
        store, receipt = self.completed_request()
        rid = receipt["request_id"]
        document = store.generate_receipt("tenant-a", rid, KEY)
        obj = parse_doc(document)
        pretty = (json.dumps(obj, indent=2) + "\n").encode("utf-8")
        with self.assertRaises(ValueError):
            store.verify_receipt(pretty, KEY)

    def test_duplicate_key_raises_value_error(self):
        store, receipt = self.completed_request()
        rid = receipt["request_id"]
        document = store.generate_receipt("tenant-a", rid, KEY)
        obj = parse_doc(document)
        body = json.dumps(obj, separators=(",", ":"))
        tampered = body.replace(
            '"receipt_version":1',
            '"receipt_version":1,"tenant_id":"x"',
            1,
        )
        with self.assertRaises(ValueError):
            store.verify_receipt((tampered + "\n").encode(), KEY)

    def test_bad_timestamp_inside_raises_value_error(self):
        store, receipt = self.completed_request()
        rid = receipt["request_id"]
        document = store.generate_receipt("tenant-a", rid, KEY)
        obj = parse_doc(document)
        obj["accepted_at"] = "2026-13-40T25:61:00.000000Z"
        text = (json.dumps(obj, separators=(",", ":")) + "\n").encode()
        with self.assertRaises(ValueError):
            store.verify_receipt(text, KEY)

    def test_invalid_key_raises_value_error(self):
        store, receipt = self.completed_request()
        rid = receipt["request_id"]
        document = store.generate_receipt("tenant-a", rid, KEY)
        for bad in (None, "", "str", 1, b"", bytearray(), True):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    store.verify_receipt(document, bad)


class VerifyReadOnlyTests(_StoreCase):
    def test_verify_never_writes(self):
        store, receipt = self.completed_request()
        rid = receipt["request_id"]
        document = store.generate_receipt("tenant-a", rid, KEY)
        with open(self.db_path, "rb") as handle:
            before = handle.read()
        for _ in range(5):
            self.assertTrue(store.verify_receipt(document, KEY))
        self.assertFalse(store.verify_receipt(document, KEY_2))
        # Tampered documents of every kind.
        obj = parse_doc(document)
        obj["auth_tag"] = "0" * 64
        self.assertFalse(
            store.verify_receipt(
                (json.dumps(obj, separators=(",", ":")) + "\n").encode(), KEY
            )
        )
        with self.assertRaises(ValueError):
            store.verify_receipt(b"garbage\n", KEY)
        with open(self.db_path, "rb") as handle:
            after = handle.read()
        self.assertEqual(before, after)

    def test_generation_does_not_change_status_attempts_or_audit(self):
        store, receipt = self.completed_request()
        rid = receipt["request_id"]
        status_before = store.get_status("tenant-a", rid)
        log_before = store.get_execution_log("tenant-a", rid)
        audit_before = store.audit("tenant-a", rid)
        evidence_before = store.evidence("tenant-a", rid)
        store.generate_receipt("tenant-a", rid, KEY)
        store.generate_receipt("tenant-a", rid, KEY_2)
        self.assertEqual(store.get_status("tenant-a", rid), status_before)
        self.assertEqual(store.get_execution_log("tenant-a", rid), log_before)
        self.assertEqual(store.audit("tenant-a", rid), audit_before)
        self.assertEqual(store.evidence("tenant-a", rid), evidence_before)
        self.assertTrue(store.verify_evidence("tenant-a", rid))


class LeakageTests(_StoreCase):
    def test_receipt_and_db_never_contain_secret_material(self):
        secret_subject = "subject-SECRET"
        secret_scope = "scope-SECRET"
        secret_idem = "idem-SECRET"
        secret_key = b"key-SECRET-material"
        store = self.store()
        receipt = store.submit(
            "tenant-a", secret_subject, [secret_scope, "email"], secret_idem
        )
        rid = receipt["request_id"]
        self.complete(store, rid)
        document = store.generate_receipt("tenant-a", rid, secret_key)
        text = document.decode("utf-8")
        self.assertNotIn(secret_subject, text)
        self.assertNotIn(secret_scope, text)
        self.assertNotIn(secret_idem, text)
        self.assertNotIn("worker-1", text)
        self.assertNotIn("claim", text.lower().replace("completed", ""))
        # Raw key bytes must not occur in the document or anywhere in the
        # database file.
        self.assertNotIn(secret_key, document)
        with open(self.db_path, "rb") as handle:
            db_bytes = handle.read()
        self.assertNotIn(secret_key, db_bytes)

    def test_exceptions_and_reprs_do_not_leak(self):
        store, receipt = self.submit()
        rid = receipt["request_id"]
        secret_key = b"key-SECRET-exception"
        try:
            store.generate_receipt("tenant-a", rid, secret_key)
        except ReceiptUnavailable as exc:
            self.assertNotIn(secret_key.decode(), str(exc))
        claim = store.claim_next("tenant-a", "worker-secret", 3600)
        try:
            store.verify_receipt(claim["claim_token"], secret_key)
        except ValueError as exc:
            self.assertNotIn(secret_key.decode(), str(exc))


class CorruptionTests(_StoreCase):
    def test_corrupt_receipt_blob_generate_raises_fixed_oserror(self):
        store, receipt = self.completed_request()
        rid = receipt["request_id"]
        document = store.generate_receipt("tenant-a", rid, KEY)
        with self.raw() as conn:
            conn.execute(
                "UPDATE deletion_receipts SET receipt_bytes = x'00' "
                "WHERE request_id = ?",
                (rid,),
            )
        with self.assertRaises(OSError) as ctx:
            store.generate_receipt("tenant-a", rid, KEY)
        self.assertEqual(str(ctx.exception), STORAGE_MESSAGE)
        # The corrupt row is never repaired, recomputed or overwritten.
        with self.raw() as conn:
            value = conn.execute(
                "SELECT receipt_bytes FROM deletion_receipts WHERE request_id = ?",
                (rid,),
            ).fetchone()[0]
        self.assertEqual(value, b"\x00")

    def test_corrupt_receipt_blob_verify_raises_fixed_oserror(self):
        store, receipt = self.completed_request()
        rid = receipt["request_id"]
        document = store.generate_receipt("tenant-a", rid, KEY)
        with self.raw() as conn:
            conn.execute(
                "UPDATE deletion_receipts SET receipt_bytes = 'broken' "
                "WHERE request_id = ?",
                (rid,),
            )
        with self.assertRaises(OSError) as ctx:
            store.verify_receipt(document, KEY)
        self.assertEqual(str(ctx.exception), STORAGE_MESSAGE)

    def test_storage_unavailable_when_db_unqueryable(self):
        store, receipt = self.completed_request()
        rid = receipt["request_id"]
        document = store.generate_receipt("tenant-a", rid, KEY)
        # Break the receipt table out of band: every storage access must
        # surface the fixed message, never the engine's own text, and the
        # fault must not silently (re)create or refill a receipt row.
        with self.raw() as conn:
            conn.execute("DROP TABLE deletion_receipts")
        with self.assertRaises(OSError) as ctx:
            store.generate_receipt("tenant-a", rid, KEY)
        self.assertEqual(str(ctx.exception), STORAGE_MESSAGE)
        with self.assertRaises(OSError):
            store.verify_receipt(document, KEY)
        with self.raw() as conn:
            # The failed call never backfilled a replacement table row.
            self.assertEqual(
                conn.execute(
                    "SELECT count(*) FROM sqlite_master "
                    "WHERE type='table' AND name='deletion_receipts'"
                ).fetchone()[0],
                0,
            )
        # Malformed input is still a caller error before storage is
        # touched, even while the database is broken.
        with self.assertRaises(ValueError):
            store.verify_receipt(b"garbage\n", KEY)

    def test_unopenable_path_raises_fixed_oserror(self):
        # A storage path that cannot be created fails with the fixed
        # message; the engine/path text must never surface.
        blocker = os.path.join(self._tmp.name, "afile")
        with open(blocker, "wb") as handle:
            handle.write(b"x")
        with self.assertRaises(OSError) as ctx:
            RequestStore(os.path.join(blocker, "nested", "t.db"))
        self.assertEqual(str(ctx.exception), STORAGE_MESSAGE)


class CrossTenantTests(_StoreCase):
    def test_other_tenant_cannot_read_or_verify_binding(self):
        store = self.store()
        a = store.submit("tenant-a", "s", ["email"], "k1")
        self.complete(store, a["request_id"])
        document = store.generate_receipt("tenant-a", a["request_id"], KEY)
        # tenant-b cannot generate for tenant-a's request.
        with self.assertRaises(RequestNotFound):
            store.generate_receipt("tenant-b", a["request_id"], KEY)
        # A receipt re-signed naming tenant-b fails verification because
        # tenant-b holds no such request.
        obj = parse_doc(document)
        obj["tenant_id"] = "tenant-b"
        obj["auth_tag"] = receipt_format.expected_tag(obj, KEY)
        forged = (json.dumps(obj, separators=(",", ":")) + "\n").encode()
        self.assertFalse(store.verify_receipt(forged, KEY))


class InMemoryStoreTests(_StoreCase):
    def test_receipt_round_trip_in_memory(self):
        store = RequestStore(":memory:")
        receipt = store.submit("tenant-a", "s", ["email"], "k1")
        rid = receipt["request_id"]
        claim = store.claim_next("tenant-a", "w", 3600)
        store.finish_claim("tenant-a", rid, claim["claim_token"], "completed")
        document = store.generate_receipt("tenant-a", rid, KEY)
        self.assertTrue(store.verify_receipt(document, KEY))
        self.assertEqual(
            store.generate_receipt("tenant-a", rid, KEY_2), document
        )


if __name__ == "__main__":
    unittest.main()
