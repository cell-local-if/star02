import json
import os
import re
import sqlite3
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor

from forgetting_evidence.requests import (
    ReceiptUnavailable,
    RequestNotFound,
    RequestStore,
)


HEX64 = re.compile(r"^[0-9a-f]{64}$")
RFC3339 = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$"
)
FIELDS = [
    "tenant_id",
    "request_id",
    "created_at",
    "completed_at",
    "scope_digest",
    "attempt_digest",
    "tag",
]
KEY = "receipt-key-0001"
OTHER_KEY = "receipt-key-9999"


class ReceiptTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "receipt.db")

    def tearDown(self):
        self._tmp.cleanup()

    def _store(self):
        return RequestStore(self.db_path)

    def _completed(self, tenant="tenant-a", key="idem-1", scopes=("email", "profile")):
        store = self._store()
        accepted = store.submit(tenant, "subject-1", list(scopes), key)
        request_id = accepted["request_id"]
        claim = store.claim_next(tenant, "worker-1", 60)
        store.finish_claim(tenant, request_id, claim["claim_token"], "completed")
        return store, accepted

    def _raw(self):
        return sqlite3.connect(self.db_path)

    # --- shape and content ---------------------------------------------

    def test_receipt_shape_order_and_formats(self):
        store, accepted = self._completed()
        text = store.generate_receipt("tenant-a", accepted["request_id"], KEY)
        self.assertIsInstance(text, str)
        self.assertTrue(text.endswith("\n"))
        self.assertEqual(text.count("\n"), 1)
        body = text[:-1]
        parsed = json.loads(body)
        # Exactly the fixed fields, in the fixed order, compactly rendered.
        self.assertEqual(list(parsed), FIELDS)
        self.assertEqual(
            body, json.dumps(parsed, ensure_ascii=False, separators=(",", ":"))
        )
        self.assertEqual(parsed["tenant_id"], "tenant-a")
        self.assertEqual(parsed["request_id"], accepted["request_id"])
        self.assertEqual(parsed["created_at"], accepted["created_at"])
        self.assertTrue(RFC3339.match(parsed["created_at"]))
        self.assertTrue(RFC3339.match(parsed["completed_at"]))
        for name in ("scope_digest", "attempt_digest", "tag"):
            self.assertTrue(HEX64.match(parsed[name]), name)

    def test_completed_at_is_the_completing_attempt(self):
        store, accepted = self._completed()
        text = store.generate_receipt("tenant-a", accepted["request_id"], KEY)
        parsed = json.loads(text)
        log = store.get_execution_log("tenant-a", accepted["request_id"])
        finishing = [a for a in log if a["result"] == "completed"]
        self.assertEqual(len(finishing), 1)
        self.assertEqual(parsed["completed_at"], finishing[0]["completed_at"])

    def test_receipt_binds_earliest_terminal_attempt(self):
        # Attempt 1 expires unfinished; attempt 2 completes. The receipt
        # must bind attempt 2's completion, the earliest (and only)
        # terminal result.
        store = self._store()
        accepted = store.submit("tenant-a", "subject-1", ["email"], "idem-1")
        request_id = accepted["request_id"]
        first = store.claim_next("tenant-a", "worker-1", 1)
        self.assertEqual(first["request_id"], request_id)
        time.sleep(1.1)
        second = store.claim_next("tenant-a", "worker-2", 60)
        self.assertEqual(second["request_id"], request_id)
        store.finish_claim("tenant-a", request_id, second["claim_token"], "completed")
        text = store.generate_receipt("tenant-a", request_id, KEY)
        parsed = json.loads(text)
        log = store.get_execution_log("tenant-a", request_id)
        self.assertEqual(len(log), 2)
        self.assertIsNone(log[0]["result"])
        self.assertEqual(log[1]["result"], "completed")
        self.assertEqual(parsed["completed_at"], log[1]["completed_at"])

    # --- idempotency and durability -------------------------------------

    def test_regeneration_returns_first_receipt_byte_identical(self):
        store, accepted = self._completed()
        first = store.generate_receipt("tenant-a", accepted["request_id"], KEY)
        for _ in range(3):
            self.assertEqual(
                store.generate_receipt("tenant-a", accepted["request_id"], KEY), first
            )

    def test_regeneration_with_other_key_returns_first_receipt(self):
        store, accepted = self._completed()
        first = store.generate_receipt("tenant-a", accepted["request_id"], KEY)
        again = store.generate_receipt("tenant-a", accepted["request_id"], OTHER_KEY)
        self.assertEqual(again, first)
        # The first receipt still authenticates under the first key only.
        self.assertTrue(store.verify_receipt(first, KEY))
        self.assertFalse(store.verify_receipt(first, OTHER_KEY))

    def test_receipt_survives_store_rebuild(self):
        store, accepted = self._completed()
        first = store.generate_receipt("tenant-a", accepted["request_id"], KEY)
        rebuilt = self._store()
        self.assertEqual(
            rebuilt.generate_receipt("tenant-a", accepted["request_id"], KEY), first
        )
        self.assertTrue(rebuilt.verify_receipt(first, KEY))

    def test_concurrent_generation_persists_exactly_one_receipt(self):
        store, accepted = self._completed()
        request_id = accepted["request_id"]

        def generate(index):
            key = KEY if index % 2 == 0 else OTHER_KEY
            return store.generate_receipt("tenant-a", request_id, key)

        with ThreadPoolExecutor(max_workers=8) as pool:
            texts = list(pool.map(generate, range(32)))
        self.assertEqual(len(set(texts)), 1)
        with self._raw() as conn:
            count = conn.execute(
                "SELECT count(*) FROM deletion_receipts WHERE request_id = ?",
                (request_id,),
            ).fetchone()[0]
        self.assertEqual(count, 1)

    def test_generation_does_not_change_state_or_evidence(self):
        store, accepted = self._completed()
        request_id = accepted["request_id"]
        status_before = store.get_status("tenant-a", request_id)
        audit_before = store.audit("tenant-a", request_id)
        log_before = store.get_execution_log("tenant-a", request_id)
        evidence_before = store.evidence("tenant-a", request_id)
        store.generate_receipt("tenant-a", request_id, KEY)
        self.assertEqual(store.get_status("tenant-a", request_id), status_before)
        self.assertEqual(store.audit("tenant-a", request_id), audit_before)
        self.assertEqual(store.get_execution_log("tenant-a", request_id), log_before)
        self.assertEqual(store.evidence("tenant-a", request_id), evidence_before)
        self.assertTrue(store.verify_evidence("tenant-a", request_id))

    # --- availability rules ----------------------------------------------

    def test_unfinished_or_failed_requests_raise_unavailable(self):
        store = self._store()
        # processing with a live lease
        processing = store.submit("tenant-a", "subject-1", ["email"], "k-processing")
        store.claim_next("tenant-a", "worker-1", 60)
        # failed via finish_claim
        failed = store.submit("tenant-a", "subject-1", ["email"], "k-failed")
        claim = store.claim_next("tenant-a", "worker-1", 60)
        self.assertEqual(claim["request_id"], failed["request_id"])
        store.finish_claim(
            "tenant-a", failed["request_id"], claim["claim_token"], "failed"
        )
        # completed status without any execution record
        bare = store.submit("tenant-a", "subject-1", ["email"], "k-bare")
        store.transition("tenant-a", bare["request_id"], "processing")
        store.transition("tenant-a", bare["request_id"], "completed")
        # accepted, never claimed
        accepted = store.submit("tenant-a", "subject-1", ["email"], "k-accepted")
        for receipt in (accepted, processing, failed, bare):
            with self.subTest(receipt=receipt["request_id"]):
                with self.assertRaises(ReceiptUnavailable):
                    store.generate_receipt("tenant-a", receipt["request_id"], KEY)
        # None of the rejections persisted a receipt.
        with self._raw() as conn:
            count = conn.execute("SELECT count(*) FROM deletion_receipts").fetchone()[0]
        self.assertEqual(count, 0)

    def test_unknown_and_cross_tenant_raise_not_found(self):
        store, accepted = self._completed()
        with self.assertRaises(RequestNotFound):
            store.generate_receipt("tenant-a", "does-not-exist", KEY)
        with self.assertRaises(RequestNotFound):
            store.generate_receipt("tenant-b", accepted["request_id"], KEY)
        # A cross-tenant probe must not create anything either.
        with self._raw() as conn:
            count = conn.execute("SELECT count(*) FROM deletion_receipts").fetchone()[0]
        self.assertEqual(count, 0)

    def test_invalid_tenant_and_key_raise_value_error_without_writing(self):
        store, accepted = self._completed()
        request_id = accepted["request_id"]
        for bad in ("", None, 7, b"x", ["x"], 3.14):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    store.generate_receipt(bad, request_id, KEY)
                with self.assertRaises(ValueError):
                    store.generate_receipt("tenant-a", request_id, bad)
        with self._raw() as conn:
            count = conn.execute("SELECT count(*) FROM deletion_receipts").fetchone()[0]
        self.assertEqual(count, 0)

    def test_invalid_unknown_request_id_raises_not_found(self):
        # Empty, non-string or malformed request ids are indistinguishable
        # from unknown ones and raise RequestNotFound, so the validation
        # layer can never probe which ids exist.
        store, accepted = self._completed()
        for bad in ("", None, 7, b"x", ["x"], 3.14, "does-not-exist"):
            with self.subTest(bad=bad):
                with self.assertRaises(RequestNotFound):
                    store.generate_receipt("tenant-a", bad, KEY)
        with self._raw() as conn:
            count = conn.execute("SELECT count(*) FROM deletion_receipts").fetchone()[0]
        self.assertEqual(count, 0)

    # --- verification ------------------------------------------------------

    def test_verify_roundtrip(self):
        store, accepted = self._completed()
        text = store.generate_receipt("tenant-a", accepted["request_id"], KEY)
        self.assertTrue(store.verify_receipt(text, KEY))
        # Verification is a complete match: the trailing newline is part
        # of the receipt text, so an incomplete copy does not match.
        self.assertFalse(store.verify_receipt(text.rstrip("\n"), KEY))
        # Repeated verification is stable.
        self.assertTrue(store.verify_receipt(text, KEY))

    def test_verify_wrong_key_is_false(self):
        store, accepted = self._completed()
        text = store.generate_receipt("tenant-a", accepted["request_id"], KEY)
        self.assertFalse(store.verify_receipt(text, OTHER_KEY))

    def test_verify_requires_exact_bytes_not_just_same_fields(self):
        store, accepted = self._completed()
        text = store.generate_receipt("tenant-a", accepted["request_id"], KEY)
        parsed = json.loads(text)
        # Same fields and an authentic tag, but not the stored bytes:
        # pretty-printed, re-spaced, duplicate newline or with a BOM.
        variants = [
            json.dumps(parsed, ensure_ascii=False, indent=2) + "\n",
            json.dumps(parsed, ensure_ascii=False) + "\n",  # default spaces
            text + "\n",
        ]
        for variant in variants:
            with self.subTest(variant=variant[:20]):
                self.assertFalse(store.verify_receipt(variant, KEY))

    def test_verify_field_substitutions_are_false(self):
        store, accepted = self._completed()
        other = store.submit("tenant-a", "subject-2", ["email"], "idem-2")
        text = store.generate_receipt("tenant-a", accepted["request_id"], KEY)
        parsed = json.loads(text)
        replacements = {
            "tenant_id": "tenant-b",
            "request_id": other["request_id"],
            "created_at": "2020-01-01T00:00:00.000000Z",
            "completed_at": "2020-01-01T00:00:00.000000Z",
            "scope_digest": "0" * 64,
            "attempt_digest": "1" * 64,
            "tag": "2" * 64,
        }
        for field, value in replacements.items():
            with self.subTest(field=field):
                forged = dict(parsed)
                forged[field] = value
                forged_text = json.dumps(
                    forged, ensure_ascii=False, separators=(",", ":")
                ) + "\n"
                self.assertFalse(store.verify_receipt(forged_text, KEY))

    def test_verify_request_existence_does_not_substitute_for_auth(self):
        store, accepted = self._completed()
        text = store.generate_receipt("tenant-a", accepted["request_id"], KEY)
        parsed = json.loads(text)
        # Well-formed, names an existing request, but the tag is invented.
        parsed["tag"] = "f" * 64
        forged = json.dumps(parsed, ensure_ascii=False, separators=(",", ":")) + "\n"
        self.assertFalse(store.verify_receipt(forged, KEY))
        # A receipt that was never generated for an existing completed
        # request is False as well: craft one under a different key.
        other = store.submit("tenant-a", "subject-2", ["email"], "idem-2")
        claim = store.claim_next("tenant-a", "worker-1", 60)
        store.finish_claim("tenant-a", other["request_id"], claim["claim_token"], "completed")
        self.assertFalse(store.verify_receipt(forged, OTHER_KEY))

    def test_verify_unknown_receipt_is_false_not_error(self):
        store, accepted = self._completed()
        text = store.generate_receipt("tenant-a", accepted["request_id"], KEY)
        parsed = json.loads(text)
        parsed["request_id"] = "00000000-0000-0000-0000-000000000000"
        forged = json.dumps(parsed, ensure_ascii=False, separators=(",", ":")) + "\n"
        self.assertFalse(store.verify_receipt(forged, KEY))
        parsed["request_id"] = accepted["request_id"]
        parsed["tenant_id"] = "tenant-b"
        forged = json.dumps(parsed, ensure_ascii=False, separators=(",", ":")) + "\n"
        self.assertFalse(store.verify_receipt(forged, KEY))

    def test_verify_malformed_arguments_raise_value_error(self):
        store, accepted = self._completed()
        text = store.generate_receipt("tenant-a", accepted["request_id"], KEY)
        parsed = json.loads(text)
        bad_texts = [
            "",
            None,
            7,
            b"{}",
            "not json",
            "{}",
            "[]",
            json.dumps({k: v for k, v in parsed.items() if k != "tag"}),
            json.dumps(dict(parsed, extra="x")),
            json.dumps(dict(parsed, tag="0" * 63)),
            json.dumps(dict(parsed, tag="0" * 65)),
            json.dumps(dict(parsed, tag="Z" * 64)),
            json.dumps(dict(parsed, scope_digest="ABC")),
            json.dumps(dict(parsed, created_at="yesterday")),
            json.dumps(dict(parsed, completed_at="")),
            json.dumps(dict(parsed, tenant_id="")),
            json.dumps(dict(parsed, request_id=7)),
        ]
        for bad in bad_texts:
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    store.verify_receipt(bad, KEY)
        for bad_key in ("", None, 7, b"k"):
            with self.subTest(bad_key=bad_key):
                with self.assertRaises(ValueError):
                    store.verify_receipt(text, bad_key)

    def test_verify_never_writes(self):
        store, accepted = self._completed()
        text = store.generate_receipt("tenant-a", accepted["request_id"], KEY)
        before = snapshot(self.db_path)
        self.assertTrue(store.verify_receipt(text, KEY))
        self.assertFalse(store.verify_receipt(text, OTHER_KEY))
        for bad in ("", "not json"):
            with self.assertRaises(ValueError):
                store.verify_receipt(bad, KEY)
        self.assertEqual(before, snapshot(self.db_path))

    # --- corruption and storage failures -----------------------------------

    def test_corrupt_receipt_record_raises_storage_error(self):
        store, accepted = self._completed()
        request_id = accepted["request_id"]
        text = store.generate_receipt("tenant-a", request_id, KEY)
        for corrupted in (
            "not json",
            "{}",
            json.dumps({"tenant_id": "tenant-a"}),
            # Valid receipt JSON but not the canonical rendering.
            json.dumps(json.loads(text), indent=2) + "\n",
        ):
            with self.subTest(corrupted=corrupted):
                with self._raw() as conn:
                    conn.execute(
                        "UPDATE deletion_receipts SET receipt_json = ? "
                        "WHERE request_id = ?",
                        (corrupted, request_id),
                    )
                with self.assertRaises(OSError) as caught:
                    store.generate_receipt("tenant-a", request_id, KEY)
                self.assertEqual(str(caught.exception), "request store is unavailable")
                with self.assertRaises(OSError):
                    store.verify_receipt(text, KEY)
                # The corrupt record is never repaired or overwritten.
                with self._raw() as conn:
                    stored = conn.execute(
                        "SELECT receipt_json FROM deletion_receipts "
                        "WHERE request_id = ?",
                        (request_id,),
                    ).fetchone()[0]
                self.assertEqual(stored, corrupted)

    def test_unwritable_database_raises_storage_error(self):
        store, accepted = self._completed()
        request_id = accepted["request_id"]
        os.chmod(self.db_path, 0o444)
        try:
            with self.assertRaises(OSError) as caught:
                store.generate_receipt("tenant-a", request_id, KEY)
            self.assertEqual(str(caught.exception), "request store is unavailable")
        finally:
            os.chmod(self.db_path, 0o644)

    # --- confidentiality -----------------------------------------------------

    def test_receipt_does_not_leak_sensitive_data(self):
        secret_subject = "subject-SECRET"
        secret_scope = "scope-SECRET"
        secret_key = "idem-SECRET"
        worker = "worker-SECRET"
        store = self._store()
        accepted = store.submit(
            "tenant-a", secret_subject, [secret_scope, "email"], secret_key
        )
        claim = store.claim_next("tenant-a", worker, 60)
        store.finish_claim(
            "tenant-a", accepted["request_id"], claim["claim_token"], "completed"
        )
        text = store.generate_receipt("tenant-a", accepted["request_id"], KEY)
        for secret in (secret_subject, secret_scope, secret_key, worker,
                       claim["claim_token"], KEY):
            self.assertNotIn(secret, text)

    def test_key_material_never_enters_database(self):
        store, accepted = self._completed()
        store.generate_receipt("tenant-a", accepted["request_id"], KEY)
        with open(self.db_path, "rb") as handle:
            content = handle.read()
        self.assertNotIn(KEY.encode(), content)
        self.assertNotIn(OTHER_KEY.encode(), content)

    def test_errors_do_not_leak(self):
        store, accepted = self._completed()
        try:
            store.generate_receipt("tenant-a", accepted["request_id"], "")
        except ValueError as exc:
            self.assertNotIn(KEY, str(exc))
        else:
            self.fail()
        try:
            store.generate_receipt("tenant-b", accepted["request_id"], KEY)
        except RequestNotFound as exc:
            self.assertNotIn("tenant-b", str(exc))
        else:
            self.fail()

    # --- in-memory store ------------------------------------------------------

    def test_in_memory_receipt_lifecycle(self):
        store = RequestStore(":memory:")
        accepted = store.submit("tenant-a", "subject-1", ["email"], "idem-1")
        request_id = accepted["request_id"]
        claim = store.claim_next("tenant-a", "worker-1", 60)
        store.finish_claim("tenant-a", request_id, claim["claim_token"], "completed")
        text = store.generate_receipt("tenant-a", request_id, KEY)
        self.assertTrue(store.verify_receipt(text, KEY))
        self.assertFalse(store.verify_receipt(text, OTHER_KEY))
        self.assertEqual(store.generate_receipt("tenant-a", request_id, KEY), text)


def snapshot(path):
    with open(path, "rb") as handle:
        return handle.read()


if __name__ == "__main__":
    unittest.main()
