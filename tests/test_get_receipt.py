import json
import os
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor

from forgetting_evidence.requests import (
    ReceiptUnavailable,
    RequestNotFound,
    RequestStore,
)


KEY = "receipt-key-0001"
NEW_KEY = "receipt-key-0002"
FOREIGN_KEY = "receipt-key-9999"


def snapshot(path):
    with open(path, "rb") as handle:
        return handle.read()


class GetReceiptTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "receipt.db")

    def tearDown(self):
        self._tmp.cleanup()

    def _store(self):
        return RequestStore(self.db_path)

    def _raw(self):
        return sqlite3.connect(self.db_path)

    def _submit(self, tenant="tenant-a", key="idem-1", scopes=("email", "profile")):
        store = self._store()
        return store, store.submit(tenant, "subject-1", list(scopes), key)

    def _completed(self, tenant="tenant-a", key="idem-1", scopes=("email", "profile")):
        store, accepted = self._submit(tenant, key, scopes)
        request_id = accepted["request_id"]
        claim = store.claim_next(tenant, "worker-1", 60)
        store.finish_claim(tenant, request_id, claim["claim_token"], "completed")
        return store, accepted

    # --- happy path: byte-identical recovery without a key ---------------

    def test_returns_first_receipt_byte_identical_without_key(self):
        store, accepted = self._completed()
        request_id = accepted["request_id"]
        first = store.generate_receipt("tenant-a", request_id, KEY)
        recovered = store.get_receipt("tenant-a", request_id)
        self.assertEqual(recovered, first)
        self.assertIsInstance(recovered, str)
        self.assertTrue(recovered.endswith("\n"))
        self.assertEqual(recovered.count("\n"), 1)
        body = recovered[:-1]
        parsed = json.loads(body)
        self.assertEqual(
            list(parsed),
            [
                "tenant_id",
                "request_id",
                "created_at",
                "completed_at",
                "scope_digest",
                "attempt_digest",
                "tag",
            ],
        )
        self.assertEqual(
            body, json.dumps(parsed, ensure_ascii=False, separators=(",", ":"))
        )

    def test_repeated_reads_are_stable(self):
        store, accepted = self._completed()
        first = store.generate_receipt("tenant-a", accepted["request_id"], KEY)
        for _ in range(5):
            self.assertEqual(
                store.get_receipt("tenant-a", accepted["request_id"]), first
            )

    def test_survives_store_rebuild_without_any_key(self):
        store, accepted = self._completed()
        first = store.generate_receipt("tenant-a", accepted["request_id"], KEY)
        rebuilt = self._store()
        self.assertEqual(
            rebuilt.get_receipt("tenant-a", accepted["request_id"]), first
        )
        # Rebuilt twice more; bytes never drift.
        self.assertEqual(
            self._store().get_receipt("tenant-a", accepted["request_id"]), first
        )

    # --- rotation invariance ---------------------------------------------

    def test_same_bytes_before_and_after_rotation(self):
        store, accepted = self._completed()
        request_id = accepted["request_id"]
        first = store.generate_receipt("tenant-a", request_id, KEY)
        self.assertEqual(store.get_receipt("tenant-a", request_id), first)
        store.rotate_receipt_key("tenant-a", KEY, NEW_KEY)
        # The active generation changed; the recovered first bytes did not.
        self.assertEqual(store.get_receipt("tenant-a", request_id), first)
        rebuilt = self._store()
        self.assertEqual(rebuilt.get_receipt("tenant-a", request_id), first)
        # The historical receipt still verifies only under the old key.
        self.assertTrue(rebuilt.verify_receipt(first, KEY))
        self.assertFalse(rebuilt.verify_receipt(first, NEW_KEY))
        self.assertFalse(rebuilt.verify_receipt(first, FOREIGN_KEY))

    def test_historical_generation_receipt_recovers_identically(self):
        # Rotate first (establishes generations 1 and 2), mint under the
        # active key, rotate again: the receipt is verifiable only under
        # its own (now historical) generation but still recovers.
        store = self._store()
        accepted = store.submit("tenant-a", "subject-1", ["email"], "idem-1")
        request_id = accepted["request_id"]
        store.rotate_receipt_key("tenant-a", KEY, NEW_KEY)
        claim = store.claim_next("tenant-a", "worker-1", 60)
        store.finish_claim("tenant-a", request_id, claim["claim_token"], "completed")
        first = store.generate_receipt("tenant-a", request_id, NEW_KEY)
        store.rotate_receipt_key("tenant-a", NEW_KEY, FOREIGN_KEY)
        self.assertEqual(store.get_receipt("tenant-a", request_id), first)
        self.assertTrue(store.verify_receipt(first, NEW_KEY))
        self.assertFalse(store.verify_receipt(first, KEY))
        self.assertFalse(store.verify_receipt(first, FOREIGN_KEY))

    # --- availability boundaries -----------------------------------------

    def test_unavailable_request_states(self):
        store = self._store()
        # processing with a live lease (claimed first, while it is the
        # oldest claimable request)
        processing = store.submit("tenant-a", "subject-1", ["email"], "k-processing")
        store.claim_next("tenant-a", "worker-1", 60)
        # failed
        failed = store.submit("tenant-a", "subject-1", ["email"], "k-failed")
        claim = store.claim_next("tenant-a", "worker-1", 60)
        self.assertEqual(claim["request_id"], failed["request_id"])
        store.finish_claim(
            "tenant-a", failed["request_id"], claim["claim_token"], "failed"
        )
        # completed status without any settled execution record
        bare = store.submit("tenant-a", "subject-1", ["email"], "k-bare")
        store.transition("tenant-a", bare["request_id"], "processing")
        store.transition("tenant-a", bare["request_id"], "completed")
        # completed with a settled record but no receipt ever generated
        completed = store.submit("tenant-a", "subject-1", ["email"], "k-completed")
        claim = store.claim_next("tenant-a", "worker-1", 60)
        self.assertEqual(claim["request_id"], completed["request_id"])
        store.finish_claim(
            "tenant-a", completed["request_id"], claim["claim_token"], "completed"
        )
        # accepted, never claimed -- submitted last so earlier claims
        # could not pick it up
        accepted = store.submit("tenant-a", "subject-1", ["email"], "k-accepted")
        for record in (accepted, processing, failed, bare, completed):
            with self.subTest(request_id=record["request_id"]):
                with self.assertRaises(ReceiptUnavailable) as caught:
                    store.get_receipt("tenant-a", record["request_id"])
                self.assertEqual(
                    str(caught.exception), "receipt is not available"
                )
        # None of the unavailable reads produced a receipt row.
        with self._raw() as conn:
            count = conn.execute(
                "SELECT count(*) FROM deletion_receipts"
            ).fetchone()[0]
        self.assertEqual(count, 0)

    def test_unknown_cross_tenant_and_malformed_raise_not_found(self):
        store, accepted = self._completed()
        request_id = accepted["request_id"]
        # Unknown id.
        with self.assertRaises(RequestNotFound):
            store.get_receipt("tenant-a", "00000000-0000-0000-0000-000000000000")
        # Cross-tenant id.
        with self.assertRaises(RequestNotFound):
            store.get_receipt("tenant-b", request_id)
        # Empty, non-string and malformed values all share one outcome.
        for bad in ("", None, 7, b"x", ["x"], 3.14, "not-a-uuid", "!!!"):
            with self.subTest(bad=bad):
                with self.assertRaises(RequestNotFound):
                    store.get_receipt("tenant-a", bad)

    def test_bad_tenant_raises_value_error(self):
        store, accepted = self._completed()
        for bad in ("", None, 7, b"tenant-a", ["tenant-a"], 3.14):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    store.get_receipt(bad, accepted["request_id"])

    def test_takes_no_key_argument(self):
        import inspect

        signature = inspect.signature(RequestStore.get_receipt)
        self.assertEqual(list(signature.parameters), ["self", "tenant_id", "request_id"])

    # --- strict read-only behavior ---------------------------------------

    def test_read_does_not_change_any_state(self):
        store, accepted = self._completed()
        request_id = accepted["request_id"]
        # Read before generation: unavailable, nothing is written.
        with self.assertRaises(ReceiptUnavailable):
            store.get_receipt("tenant-a", request_id)
        first = store.generate_receipt("tenant-a", request_id, KEY)
        status_before = store.get_status("tenant-a", request_id)
        audit_before = store.audit("tenant-a", request_id)
        log_before = store.get_execution_log("tenant-a", request_id)
        evidence_before = store.evidence("tenant-a", request_id)
        bytes_before = snapshot(self.db_path)
        for _ in range(5):
            self.assertEqual(store.get_receipt("tenant-a", request_id), first)
        self.assertEqual(snapshot(self.db_path), bytes_before)
        self.assertEqual(store.get_status("tenant-a", request_id), status_before)
        self.assertEqual(store.audit("tenant-a", request_id), audit_before)
        self.assertEqual(
            store.get_execution_log("tenant-a", request_id), log_before
        )
        self.assertEqual(store.evidence("tenant-a", request_id), evidence_before)
        self.assertTrue(store.verify_evidence("tenant-a", request_id))

    def test_unavailable_read_never_registers_generation_one(self):
        store = self._store()
        # A completed, receiptable-but-never-minted request: a read must
        # not bootstrap generation 1 either.
        pending = store.submit("tenant-a", "subject-2", ["email"], "idem-pending")
        with self.assertRaises(ReceiptUnavailable):
            store.get_receipt("tenant-a", pending["request_id"])
        claim = store.claim_next("tenant-a", "worker-1", 60)
        store.finish_claim(
            "tenant-a", pending["request_id"], claim["claim_token"], "completed"
        )
        with self.assertRaises(ReceiptUnavailable):
            store.get_receipt("tenant-a", pending["request_id"])
        with self._raw() as conn:
            key_rows = conn.execute("SELECT count(*) FROM receipt_keys").fetchone()[0]
            receipt_rows = conn.execute(
                "SELECT count(*) FROM deletion_receipts"
            ).fetchone()[0]
        self.assertEqual(key_rows, 0)
        self.assertEqual(receipt_rows, 0)
        # The pending request can still be minted normally later.
        minted = store.generate_receipt(
            "tenant-a", pending["request_id"], KEY
        )
        self.assertEqual(store.get_receipt("tenant-a", pending["request_id"]), minted)

    def test_read_does_not_register_key_for_failed_request(self):
        store = self._store()
        failed = store.submit("tenant-a", "subject-1", ["email"], "k-failed")
        claim = store.claim_next("tenant-a", "worker-1", 60)
        store.finish_claim(
            "tenant-a", failed["request_id"], claim["claim_token"], "failed"
        )
        with self.assertRaises(ReceiptUnavailable):
            store.get_receipt("tenant-a", failed["request_id"])
        with self._raw() as conn:
            self.assertEqual(
                conn.execute("SELECT count(*) FROM receipt_keys").fetchone()[0], 0
            )
            self.assertEqual(
                conn.execute("SELECT count(*) FROM deletion_receipts").fetchone()[0],
                0,
            )

    def test_read_after_corruption_raises_storage_error_and_keeps_record(self):
        store, accepted = self._completed()
        request_id = accepted["request_id"]
        text = store.generate_receipt("tenant-a", request_id, KEY)
        for corrupted in (
            "not json\n",
            json.dumps(json.loads(text), indent=2) + "\n",
        ):
            with self._raw() as conn:
                conn.execute(
                    "UPDATE deletion_receipts SET receipt_json = ? "
                    "WHERE request_id = ?",
                    (corrupted, request_id),
                )
            with self.assertRaises(OSError) as caught:
                store.get_receipt("tenant-a", request_id)
            self.assertEqual(str(caught.exception), "request store is unavailable")
            # The corrupt record is never repaired or overwritten.
            with self._raw() as conn:
                stored = conn.execute(
                    "SELECT receipt_json FROM deletion_receipts "
                    "WHERE request_id = ?",
                    (request_id,),
                ).fetchone()[0]
            self.assertEqual(stored, corrupted)
            # Restore the canonical record for the next subtest.
            with self._raw() as conn:
                conn.execute(
                    "UPDATE deletion_receipts SET receipt_json = ? "
                    "WHERE request_id = ?",
                    (text, request_id),
                )
            self.assertEqual(store.get_receipt("tenant-a", request_id), text)

    # --- concurrency: interleave with generation -------------------------

    def test_concurrent_reads_interleaved_with_generation(self):
        store, accepted = self._completed()
        request_id = accepted["request_id"]
        outcomes: list[object] = []

        def read(index):
            try:
                return store.get_receipt("tenant-a", request_id)
            except ReceiptUnavailable:
                return None

        def generate():
            return store.generate_receipt("tenant-a", request_id, KEY)

        with ThreadPoolExecutor(max_workers=8) as pool:
            # A batch of readers starts before the generator; every result
            # is either the pre-commit None (unavailable) or exactly the
            # committed full text -- never an exception or partial text.
            reader_futures = [pool.submit(read, i) for i in range(16)]
            generator = pool.submit(generate)
            first = generator.result()
            reader_futures += [pool.submit(read, i) for i in range(16)]
            for future in reader_futures:
                outcomes.append(future.result())
        for outcome in outcomes:
            self.assertIn(outcome, (None, first))
        self.assertIn(first, outcomes)
        # Every successful read is a complete line: parseable body with
        # all fields, never a partial prefix.
        for outcome in outcomes:
            if outcome is not None:
                parsed = json.loads(outcome[:-1])
                self.assertEqual(
                    set(parsed),
                    {
                        "tenant_id",
                        "request_id",
                        "created_at",
                        "completed_at",
                        "scope_digest",
                        "attempt_digest",
                        "tag",
                    },
                )
        with self._raw() as conn:
            count = conn.execute(
                "SELECT count(*) FROM deletion_receipts WHERE request_id = ?",
                (request_id,),
            ).fetchone()[0]
        self.assertEqual(count, 1)
        self.assertEqual(store.get_receipt("tenant-a", request_id), first)

    # --- confidentiality --------------------------------------------------

    def test_errors_do_not_leak_tenant_or_request(self):
        store, accepted = self._completed()
        try:
            store.get_receipt("", accepted["request_id"])
        except ValueError as exc:
            self.assertNotIn(accepted["request_id"], str(exc))
        else:
            self.fail()
        try:
            store.get_receipt("tenant-b", accepted["request_id"])
        except RequestNotFound as exc:
            self.assertNotIn("tenant-b", str(exc))
            self.assertNotIn(accepted["request_id"], str(exc))
        else:
            self.fail()
        try:
            store.get_receipt("tenant-a", "00000000-0000-0000-0000-000000000000")
        except RequestNotFound as exc:
            self.assertEqual(str(exc), "request not found")
        else:
            self.fail()

    def test_recovered_receipt_carries_no_secret_material(self):
        store, accepted = self._completed()
        store.generate_receipt("tenant-a", accepted["request_id"], KEY)
        recovered = store.get_receipt("tenant-a", accepted["request_id"])
        self.assertNotIn(KEY, recovered)
        self.assertNotIn(NEW_KEY, recovered)
        self.assertNotIn("subject-1", recovered)

    # --- in-memory store --------------------------------------------------

    def test_in_memory_lifecycle(self):
        store = RequestStore(":memory:")
        accepted = store.submit("tenant-a", "subject-1", ["email"], "idem-1")
        request_id = accepted["request_id"]
        with self.assertRaises(ReceiptUnavailable):
            store.get_receipt("tenant-a", request_id)
        claim = store.claim_next("tenant-a", "worker-1", 60)
        store.finish_claim("tenant-a", request_id, claim["claim_token"], "completed")
        with self.assertRaises(ReceiptUnavailable):
            store.get_receipt("tenant-a", request_id)
        first = store.generate_receipt("tenant-a", request_id, KEY)
        self.assertEqual(store.get_receipt("tenant-a", request_id), first)
        store.rotate_receipt_key("tenant-a", KEY, NEW_KEY)
        self.assertEqual(store.get_receipt("tenant-a", request_id), first)


if __name__ == "__main__":
    unittest.main()
