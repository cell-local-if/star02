"""Tests for the read-only ``RequestStore.get_receipt`` recovery entry."""

import json
import os
import sqlite3
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor

from forgetting_evidence.httpapi import DeferredRequestStore
from forgetting_evidence.requests import (
    ReceiptUnavailable,
    RequestNotFound,
    RequestStore,
)


KEY = "receipt-key-0001"
KEY_A = "receipt-key-AAAA"
KEY_B = "receipt-key-BBBB"
OTHER_KEY = "receipt-key-9999"


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

    def _submit(self, store, tenant="tenant-a", key="idem-1",
                scopes=("email", "profile")):
        return store.submit(tenant, "subject-1", list(scopes), key)

    def _complete(self, store, accepted, tenant="tenant-a", worker="worker-1"):
        claim = store.claim_next(tenant, worker, 60)
        store.finish_claim(
            tenant, accepted["request_id"], claim["claim_token"], "completed"
        )
        return claim

    def _completed_request(self, tenant="tenant-a", idem="idem-1"):
        store = self._store()
        accepted = self._submit(store, tenant=tenant, key=idem)
        self._complete(store, accepted)
        return store, accepted

    # --- exact recovery ---------------------------------------------------

    def test_returns_first_receipt_byte_for_byte_without_key(self):
        store, accepted = self._completed_request()
        first = store.generate_receipt("tenant-a", accepted["request_id"], KEY)
        # The entry takes no key at all.
        recovered = store.get_receipt("tenant-a", accepted["request_id"])
        self.assertEqual(recovered, first)
        self.assertIsInstance(recovered, str)
        self.assertEqual(recovered.count("\n"), 1)
        self.assertTrue(recovered.endswith("\n"))
        self.assertFalse(recovered.endswith("\n\n"))
        parsed = json.loads(recovered[:-1])
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

    def test_repeated_reads_are_identical_and_never_regenerate(self):
        store, accepted = self._completed_request()
        first = store.generate_receipt("tenant-a", accepted["request_id"], KEY)
        raw_before = snapshot(self.db_path)
        for _ in range(5):
            self.assertEqual(
                store.get_receipt("tenant-a", accepted["request_id"]), first
            )
        # Pure reads do not touch the database file at all.
        self.assertEqual(snapshot(self.db_path), raw_before)

    def test_same_bytes_before_and_after_key_rotation_and_across_generations(self):
        store = self._store()
        first_req = self._submit(store, key="idem-1")
        self._complete(store, first_req)
        old_receipt = store.generate_receipt(
            "tenant-a", first_req["request_id"], KEY_A
        )
        rotation = store.rotate_receipt_key("tenant-a", KEY_A, KEY_B)
        self.assertEqual(rotation["generation"], 2)
        # A receipt signed under generation 1 keeps recovering to the same
        # bytes once generation 2 is active; the active generation never
        # causes a re-sign or re-render.
        self.assertEqual(
            store.get_receipt("tenant-a", first_req["request_id"]), old_receipt
        )
        second_req = self._submit(store, key="idem-2")
        self._complete(store, second_req, worker="worker-2")
        new_receipt = store.generate_receipt(
            "tenant-a", second_req["request_id"], KEY_B
        )
        self.assertEqual(
            store.get_receipt("tenant-a", second_req["request_id"]), new_receipt
        )
        self.assertEqual(
            store.get_receipt("tenant-a", first_req["request_id"]), old_receipt
        )
        # Old and new receipts still authenticate only under their own
        # historical/current key generations; recovery itself needs none.
        self.assertTrue(store.verify_receipt(old_receipt, KEY_A))
        self.assertFalse(store.verify_receipt(old_receipt, KEY_B))
        self.assertTrue(store.verify_receipt(new_receipt, KEY_B))
        self.assertFalse(store.verify_receipt(new_receipt, KEY_A))

    def test_recovery_survives_store_rebuild(self):
        store, accepted = self._completed_request()
        first = store.generate_receipt("tenant-a", accepted["request_id"], KEY)
        rebuilt = self._store()
        self.assertEqual(
            rebuilt.get_receipt("tenant-a", accepted["request_id"]), first
        )
        rebuilt_again = self._store()
        self.assertEqual(
            rebuilt_again.get_receipt("tenant-a", accepted["request_id"]), first
        )

    def test_in_memory_recovery(self):
        store = RequestStore(":memory:")
        accepted = self._submit(store)
        self._complete(store, accepted)
        first = store.generate_receipt("tenant-a", accepted["request_id"], KEY)
        self.assertEqual(
            store.get_receipt("tenant-a", accepted["request_id"]), first
        )

    # --- availability: existing request without a first receipt ----------

    def test_unfinished_failed_and_bare_completed_raise_unavailable(self):
        store = self._store()
        processing = self._submit(store, key="k-processing")
        store.claim_next("tenant-a", "worker-1", 60)
        failed = self._submit(store, key="k-failed")
        claim = store.claim_next("tenant-a", "worker-1", 60)
        self.assertEqual(claim["request_id"], failed["request_id"])
        store.finish_claim(
            "tenant-a", failed["request_id"], claim["claim_token"], "failed"
        )
        bare = self._submit(store, key="k-bare")
        store.transition("tenant-a", bare["request_id"], "processing")
        store.transition("tenant-a", bare["request_id"], "completed")
        accepted = self._submit(store, key="k-accepted")
        for receipt in (accepted, processing, failed, bare):
            with self.subTest(receipt=receipt["request_id"]):
                with self.assertRaises(ReceiptUnavailable):
                    store.get_receipt("tenant-a", receipt["request_id"])

    def test_unavailable_even_when_tenant_already_has_key_generation(self):
        # Once a generation exists generate_receipt would raise
        # ReceiptKeyConflict for a receipt-less failed request (key
        # admission precedes availability). The keyless read must still
        # report ReceiptUnavailable -- it has no key to admit.
        store, accepted = self._completed_request(idem="idem-done")
        store.generate_receipt("tenant-a", accepted["request_id"], KEY_A)
        failed = self._submit(store, key="k-failed")
        claim = store.claim_next("tenant-a", "worker-2", 60)
        store.finish_claim(
            "tenant-a", failed["request_id"], claim["claim_token"], "failed"
        )
        with self.assertRaises(ReceiptUnavailable):
            store.get_receipt("tenant-a", failed["request_id"])
        bare = self._submit(store, key="k-bare")
        store.transition("tenant-a", bare["request_id"], "processing")
        store.transition("tenant-a", bare["request_id"], "completed")
        with self.assertRaises(ReceiptUnavailable):
            # completed status without a settled execution record
            store.get_receipt("tenant-a", bare["request_id"])

    def test_unavailable_read_does_not_register_generation_or_receipt(self):
        store, accepted = self._completed_request()
        request_id = accepted["request_id"]
        raw_before = snapshot(self.db_path)
        with self.assertRaises(ReceiptUnavailable):
            store.get_receipt("tenant-a", request_id)
        self.assertEqual(snapshot(self.db_path), raw_before)
        with self._raw() as conn:
            self.assertEqual(
                conn.execute("SELECT count(*) FROM receipt_keys").fetchone()[0], 0
            )
            self.assertEqual(
                conn.execute("SELECT count(*) FROM deletion_receipts").fetchone()[0],
                0,
            )
        # The first real generation still bootstraps generation 1
        # normally: the failed read left no bookkeeping behind.
        first = store.generate_receipt("tenant-a", request_id, KEY)
        self.assertEqual(
            store.get_receipt("tenant-a", request_id), first
        )

    # --- identity boundaries ----------------------------------------------

    def test_unknown_cross_tenant_and_malformed_ids_raise_not_found(self):
        store, accepted = self._completed_request()
        store.generate_receipt("tenant-a", accepted["request_id"], KEY)
        with self.assertRaises(RequestNotFound):
            store.get_receipt("tenant-a", "does-not-exist")
        with self.assertRaises(RequestNotFound):
            # A receipt does exist, but it belongs to another tenant.
            store.get_receipt("tenant-b", accepted["request_id"])
        for bad in ("", None, 7, b"x", ["x"], 3.14):
            with self.subTest(bad=bad):
                with self.assertRaises(RequestNotFound):
                    store.get_receipt("tenant-a", bad)

    def test_bad_tenant_raises_value_error(self):
        store, accepted = self._completed_request()
        for bad in ("", None, 7, b"x", ["x"], 3.14):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    store.get_receipt(bad, accepted["request_id"])

    def test_identity_failures_write_nothing(self):
        store, accepted = self._completed_request()
        store.generate_receipt("tenant-a", accepted["request_id"], KEY)
        raw_before = snapshot(self.db_path)
        for bad_tenant in ("", None, 7):
            with self.assertRaises(ValueError):
                store.get_receipt(bad_tenant, accepted["request_id"])
        for bad_id in ("", None, 7, "missing"):
            with self.assertRaises(RequestNotFound):
                store.get_receipt("tenant-a", bad_id)
        with self.assertRaises(RequestNotFound):
            store.get_receipt("tenant-b", accepted["request_id"])
        self.assertEqual(snapshot(self.db_path), raw_before)

    # --- strict read-only behaviour ---------------------------------------

    def test_read_changes_no_state_evidence_lease_or_listing(self):
        store, accepted = self._completed_request()
        request_id = accepted["request_id"]
        store.generate_receipt("tenant-a", request_id, KEY)
        status_before = store.get_status("tenant-a", request_id)
        get_before = store.get("tenant-a", request_id)
        audit_before = store.audit("tenant-a", request_id)
        log_before = store.get_execution_log("tenant-a", request_id)
        evidence_before = store.evidence("tenant-a", request_id)
        listing_before = store.list_requests("tenant-a")
        store.get_receipt("tenant-a", request_id)
        self.assertEqual(store.get_status("tenant-a", request_id), status_before)
        self.assertEqual(store.get("tenant-a", request_id), get_before)
        self.assertEqual(store.audit("tenant-a", request_id), audit_before)
        self.assertEqual(
            store.get_execution_log("tenant-a", request_id), log_before
        )
        self.assertEqual(store.evidence("tenant-a", request_id), evidence_before)
        self.assertEqual(store.list_requests("tenant-a"), listing_before)
        self.assertTrue(store.verify_evidence("tenant-a", request_id))

    def test_read_leaves_receipt_and_key_bookkeeping_untouched(self):
        store, accepted = self._completed_request()
        request_id = accepted["request_id"]
        store.generate_receipt("tenant-a", request_id, KEY)
        with self._raw() as conn:
            receipts_before = conn.execute(
                "SELECT tenant_id, request_id, receipt_json FROM deletion_receipts"
            ).fetchall()
            keys_before = conn.execute(
                "SELECT tenant_id, generation, key_fingerprint, effective_at "
                "FROM receipt_keys ORDER BY tenant_id, generation"
            ).fetchall()
        for _ in range(3):
            store.get_receipt("tenant-a", request_id)
        with self._raw() as conn:
            receipts_after = conn.execute(
                "SELECT tenant_id, request_id, receipt_json FROM deletion_receipts"
            ).fetchall()
            keys_after = conn.execute(
                "SELECT tenant_id, generation, key_fingerprint, effective_at "
                "FROM receipt_keys ORDER BY tenant_id, generation"
            ).fetchall()
        self.assertEqual(receipts_after, receipts_before)
        self.assertEqual(keys_after, keys_before)

    def test_unavailable_read_leaves_everything_untouched(self):
        store = self._store()
        accepted = self._submit(store, key="k-1")
        store.claim_next("tenant-a", "worker-1", 60)  # processing
        raw_before = snapshot(self.db_path)
        with self.assertRaises(ReceiptUnavailable):
            store.get_receipt("tenant-a", accepted["request_id"])
        self.assertEqual(snapshot(self.db_path), raw_before)

    # --- corruption and storage failures ----------------------------------

    def test_corrupt_receipt_record_raises_storage_error(self):
        store, accepted = self._completed_request()
        request_id = accepted["request_id"]
        text = store.generate_receipt("tenant-a", request_id, KEY)
        for corrupted in (
            "not json\n",
            "{}\n",
            json.dumps({"tenant_id": "tenant-a"}) + "\n",
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
                    store.get_receipt("tenant-a", request_id)
                self.assertEqual(
                    str(caught.exception), "request store is unavailable"
                )
                # The corrupt record is never repaired, regenerated or
                # overwritten by the read.
                with self._raw() as conn:
                    stored = conn.execute(
                        "SELECT receipt_json FROM deletion_receipts "
                        "WHERE request_id = ?",
                        (request_id,),
                    ).fetchone()[0]
                self.assertEqual(stored, corrupted)
            # Restore the genuine receipt before the next corruption.
            with self._raw() as conn:
                conn.execute(
                    "UPDATE deletion_receipts SET receipt_json = ? "
                    "WHERE request_id = ?",
                    (text, request_id),
                )

    def test_unreadable_store_raises_fixed_storage_error(self):
        store, accepted = self._completed_request()
        request_id = accepted["request_id"]
        store.generate_receipt("tenant-a", request_id, KEY)
        os.chmod(self.db_path, 0o000)
        try:
            with self.assertRaises(OSError) as caught:
                store.get_receipt("tenant-a", request_id)
            self.assertEqual(
                str(caught.exception), "request store is unavailable"
            )
        finally:
            os.chmod(self.db_path, 0o644)

    # --- concurrency -------------------------------------------------------

    def test_concurrent_reads_interleaved_with_generation_never_see_partial(self):
        store, accepted = self._completed_request()
        request_id = accepted["request_id"]
        first_box: list[str] = []
        outcomes: list[object] = []
        barrier: list[object] = []

        def read_once(index):
            # Hold the first readers at the barrier until generation is
            # in flight, then all reads fan out while it commits.
            if index < 8:
                while not barrier:
                    time.sleep(0.0005)
            try:
                return store.get_receipt("tenant-a", request_id)
            except ReceiptUnavailable:
                return None
            except OSError:
                return "storage-failure"

        def generate_once():
            barrier.append(True)
            text = store.generate_receipt("tenant-a", request_id, KEY)
            first_box.append(text)
            return text

        with ThreadPoolExecutor(max_workers=12) as pool:
            reads = [pool.submit(read_once, i) for i in range(24)]
            writer = pool.submit(generate_once)
            first = writer.result()
            for future in reads:
                outcomes.append(future.result())
            # Readers that arrive after the commit all see the complete
            # first text; pre-commit readers see None. Every non-None
            # outcome is the full first text, never a fragment.
            for outcome in outcomes:
                if outcome is not None:
                    self.assertEqual(outcome, first)
                    self.assertEqual(outcome.count("\n"), 1)
                    json.loads(outcome[:-1])
        self.assertEqual(first_box, [first])
        with self._raw() as conn:
            count = conn.execute(
                "SELECT count(*) FROM deletion_receipts WHERE request_id = ?",
                (request_id,),
            ).fetchone()[0]
        self.assertEqual(count, 1)
        # After the commit every read is the complete first text.
        for _ in range(8):
            self.assertEqual(
                store.get_receipt("tenant-a", request_id), first
            )

    # --- storage-layer-only boundary --------------------------------------

    def test_not_proxied_by_deferred_store_or_http_layer(self):
        # The recovery entry exists solely on the storage layer.
        self.assertTrue(hasattr(RequestStore, "get_receipt"))
        self.assertFalse(hasattr(DeferredRequestStore, "get_receipt"))
        deferred = DeferredRequestStore(self.db_path)
        with self.assertRaises(AttributeError):
            deferred.get_receipt("tenant-a", "anything")

    # --- confidentiality ---------------------------------------------------

    def test_errors_and_results_do_not_leak_sensitive_values(self):
        store = self._store()
        secret_tenant = "tenant-SECRET"
        accepted = self._submit(store, tenant=secret_tenant, key="idem-SECRET")
        self._complete(store, accepted, tenant=secret_tenant, worker="worker-SECRET")
        try:
            store.get_receipt(secret_tenant, "missing-id")
        except RequestNotFound as exc:
            message = str(exc)
            self.assertNotIn(secret_tenant, message)
            self.assertNotIn("missing-id", message)
        else:
            self.fail()
        try:
            store.get_receipt(None, accepted["request_id"])
        except ValueError:
            pass
        else:
            self.fail()
        first = store.generate_receipt(
            secret_tenant, accepted["request_id"], KEY
        )
        recovered = store.get_receipt(secret_tenant, accepted["request_id"])
        self.assertEqual(recovered, first)
        for secret in ("subject-1", "idem-SECRET", KEY, "worker-SECRET"):
            self.assertNotIn(secret, recovered)
        with open(self.db_path, "rb") as handle:
            content = handle.read()
        self.assertNotIn(KEY.encode(), content)


if __name__ == "__main__":
    unittest.main()
