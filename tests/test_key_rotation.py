"""Tests for recoverable receipt key rotation.

Covers ``rotate_receipt_key`` and the generation-aware boundaries of
``generate_receipt`` / ``verify_receipt``: first-generation bootstrap,
the first-rotation generations 1-and-2 commit, idempotent replay,
conflict precedence, concurrency (one active generation ever),
restart durability, cross-generation verification, the request-id
boundary on generation, atomic commit failures and key-material
confidentiality.
"""

import os
import re
import sqlite3
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor

from forgetting_evidence.requests import (
    ReceiptKeyConflict,
    ReceiptUnavailable,
    RequestNotFound,
    RequestStore,
)


RFC3339 = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$"
)
KEY_A = "receipt-key-alpha-0001"
KEY_B = "receipt-key-bravo-0002"
KEY_C = "receipt-key-charlie-0003"
KEY_D = "receipt-key-delta-0004"


class _CommitFailingConnection:
    """Connection proxy whose first COMMIT raises an engine error."""

    def __init__(self, real):
        self._real = real

    def __getattr__(self, name):
        return getattr(self._real, name)

    def execute(self, sql, *args, **kwargs):
        if sql.strip().upper().startswith("COMMIT"):
            raise sqlite3.OperationalError("simulated commit failure")
        return self._real.execute(sql, *args, **kwargs)


class _CommitFailingStore(RequestStore):
    def _connect(self):
        return _CommitFailingConnection(super()._connect())

    def _release(self, conn):
        super()._release(conn._real)


class KeyRotationTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "rotation.db")

    def tearDown(self):
        self._tmp.cleanup()

    def _store(self):
        return RequestStore(self.db_path)

    def _raw(self):
        return sqlite3.connect(self.db_path)

    def _completed(self, store, tenant="tenant-a", idem="idem-1", key_idem=None):
        key_idem = idem if key_idem is None else key_idem
        accepted = store.submit(tenant, "subject-1", ["email", "profile"], key_idem)
        claim = store.claim_next(tenant, "worker-1", 60)
        store.finish_claim(
            tenant, accepted["request_id"], claim["claim_token"], "completed"
        )
        return accepted

    def _generations(self, tenant="tenant-a"):
        with self._raw() as conn:
            return conn.execute(
                "SELECT generation, key_fingerprint, effective_at "
                "FROM receipt_keys WHERE tenant_id = ? ORDER BY generation",
                (tenant,),
            ).fetchall()

    # -- rotation result shape ------------------------------------------

    def test_first_rotation_without_generations_registers_one_and_two(self):
        store = self._store()
        result = store.rotate_receipt_key("tenant-a", KEY_A, KEY_B)
        self.assertEqual(set(result), {"generation", "effective_at"})
        self.assertEqual(result["generation"], 2)
        self.assertIsInstance(result["generation"], int)
        self.assertNotIsInstance(result["generation"], bool)
        self.assertIsInstance(result["effective_at"], str)
        self.assertTrue(RFC3339.match(result["effective_at"]))
        rows = self._generations()
        self.assertEqual(len(rows), 2)
        self.assertEqual([row[0] for row in rows], [1, 2])
        # Generations 1 and 2 of the bootstrap rotation share the one
        # rotation commit time.
        self.assertEqual(rows[0][2], rows[1][2])
        self.assertEqual(rows[1][2], result["effective_at"])
        for row in rows:
            self.assertRegex(row[1], r"^[0-9a-f]{64}$")

    def test_first_receipt_generation_registers_generation_one(self):
        store = self._store()
        accepted = self._completed(store)
        receipt = store.generate_receipt("tenant-a", accepted["request_id"], KEY_A)
        rows = self._generations()
        self.assertEqual([row[0] for row in rows], [1])
        self.assertTrue(RFC3339.match(rows[0][2]))
        # Rotating after a bootstrap generation promotes to gen 2.
        result = store.rotate_receipt_key("tenant-a", KEY_A, KEY_B)
        self.assertEqual(result["generation"], 2)
        self.assertEqual([row[0] for row in self._generations()], [1, 2])
        # The pre-rotation receipt is byte-identical and still readable.
        self.assertEqual(
            store.generate_receipt("tenant-a", accepted["request_id"], KEY_B),
            receipt,
        )

    # -- idempotency ------------------------------------------------------

    def test_same_rotation_is_idempotent_with_first_generation_and_time(self):
        store = self._store()
        first = store.rotate_receipt_key("tenant-a", KEY_A, KEY_B)
        time.sleep(0.01)
        for _ in range(3):
            self.assertEqual(
                store.rotate_receipt_key("tenant-a", KEY_A, KEY_B), first
            )
        # Idempotency inserts no extra generations.
        self.assertEqual(len(self._generations()), 2)

    def test_same_rotation_is_idempotent_after_generation_bootstrap(self):
        store = self._store()
        accepted = self._completed(store)
        store.generate_receipt("tenant-a", accepted["request_id"], KEY_A)
        rotation = store.rotate_receipt_key("tenant-a", KEY_A, KEY_B)
        time.sleep(0.01)
        self.assertEqual(
            store.rotate_receipt_key("tenant-a", KEY_A, KEY_B), rotation
        )
        self.assertEqual([row[0] for row in self._generations()], [1, 2])

    def test_rotation_chain_advances_and_replays(self):
        store = self._store()
        r2 = store.rotate_receipt_key("tenant-a", KEY_A, KEY_B)
        self.assertEqual(r2["generation"], 2)
        r3 = store.rotate_receipt_key("tenant-a", KEY_B, KEY_C)
        self.assertEqual(r3["generation"], 3)
        r4 = store.rotate_receipt_key("tenant-a", KEY_C, KEY_D)
        self.assertEqual(r4["generation"], 4)
        self.assertEqual([row[0] for row in self._generations()], [1, 2, 3, 4])
        self.assertTrue(r2["effective_at"] <= r3["effective_at"] <= r4["effective_at"])
        # Only the pair that produced the CURRENT active generation is
        # idempotent; once superseded the same pair becomes a conflict.
        self.assertEqual(store.rotate_receipt_key("tenant-a", KEY_C, KEY_D), r4)
        with self.assertRaises(ReceiptKeyConflict):
            store.rotate_receipt_key("tenant-a", KEY_A, KEY_B)
        with self.assertRaises(ReceiptKeyConflict):
            store.rotate_receipt_key("tenant-a", KEY_B, KEY_C)

    # -- conflicts ---------------------------------------------------------

    def test_retired_key_not_active_raises_conflict_unchanged(self):
        store = self._store()
        store.rotate_receipt_key("tenant-a", KEY_A, KEY_B)
        store.rotate_receipt_key("tenant-a", KEY_B, KEY_C)
        # KEY_A is registered but retired two generations ago.
        with self.assertRaises(ReceiptKeyConflict):
            store.rotate_receipt_key("tenant-a", KEY_A, KEY_D)
        self.assertEqual([row[0] for row in self._generations()], [1, 2, 3])

    def test_superseded_rotation_pair_raises_conflict(self):
        store = self._store()
        store.rotate_receipt_key("tenant-a", KEY_A, KEY_B)
        store.rotate_receipt_key("tenant-a", KEY_B, KEY_C)
        # The exact pair A->B already produced gen 2 and was superseded.
        with self.assertRaises(ReceiptKeyConflict):
            store.rotate_receipt_key("tenant-a", KEY_A, KEY_B)
        # A pair whose keys are both historical but were never adjacent
        # in that direction is the same conflict.
        with self.assertRaises(ReceiptKeyConflict):
            store.rotate_receipt_key("tenant-a", KEY_A, KEY_C)
        self.assertEqual([row[0] for row in self._generations()], [1, 2, 3])

    def test_new_key_already_registered_raises_conflict(self):
        store = self._store()
        store.rotate_receipt_key("tenant-a", KEY_A, KEY_B)
        # Rotating the active key back onto an already-registered
        # predecessor would alias generations and is rejected unchanged.
        with self.assertRaises(ReceiptKeyConflict):
            store.rotate_receipt_key("tenant-a", KEY_B, KEY_A)
        # Identical retired/new keys are a ValueError instead (see the
        # invalid-arguments case), never a new generation.
        with self.assertRaises(ValueError):
            store.rotate_receipt_key("tenant-a", KEY_B, KEY_B)
        self.assertEqual([row[0] for row in self._generations()], [1, 2])

    def test_unknown_retired_key_with_existing_generations_is_value_error(self):
        store = self._store()
        store.rotate_receipt_key("tenant-a", KEY_A, KEY_B)
        with self.assertRaises(ValueError):
            store.rotate_receipt_key("tenant-a", "never-registered-key", KEY_C)
        self.assertEqual([row[0] for row in self._generations()], [1, 2])

    def test_invalid_rotation_arguments_raise_value_error_without_writing(self):
        store = self._store()
        bad_values = ("", None, 7, b"k", ["k"], 3.14)
        for bad in bad_values:
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    store.rotate_receipt_key(bad, KEY_A, KEY_B)
                with self.assertRaises(ValueError):
                    store.rotate_receipt_key("tenant-a", bad, KEY_B)
                with self.assertRaises(ValueError):
                    store.rotate_receipt_key("tenant-a", KEY_A, bad)
        # Identical keys are caller error even when no generation exists.
        with self.assertRaises(ValueError):
            store.rotate_receipt_key("tenant-a", KEY_A, KEY_A)
        self.assertEqual(self._generations(), [])

    # -- generation-aware minting and verification -------------------------

    def test_old_key_cannot_mint_new_receipt_after_rotation(self):
        store = self._store()
        first = self._completed(store, idem="idem-1")
        old_receipt = store.generate_receipt(
            "tenant-a", first["request_id"], KEY_A
        )
        store.rotate_receipt_key("tenant-a", KEY_A, KEY_B)
        second = self._completed(store, idem="idem-2")
        with self.assertRaises(ReceiptKeyConflict):
            store.generate_receipt("tenant-a", second["request_id"], KEY_A)
        # The rejected mint wrote neither a receipt nor a generation.
        with self._raw() as conn:
            receipt_count = conn.execute(
                "SELECT count(*) FROM deletion_receipts"
            ).fetchone()[0]
            gen_count = conn.execute(
                "SELECT count(*) FROM receipt_keys"
            ).fetchone()[0]
        self.assertEqual(receipt_count, 1)
        self.assertEqual(gen_count, 2)
        # The new receipt is signed by the active (generation 2) key.
        new_receipt = store.generate_receipt(
            "tenant-a", second["request_id"], KEY_B
        )
        self.assertTrue(store.verify_receipt(new_receipt, KEY_B))
        self.assertTrue(store.verify_receipt(old_receipt, KEY_A))
        # Cross-generation authentication never matches.
        self.assertFalse(store.verify_receipt(new_receipt, KEY_A))
        self.assertFalse(store.verify_receipt(old_receipt, KEY_B))

    def test_unknown_key_never_verifies_any_receipt(self):
        store = self._store()
        accepted = self._completed(store)
        receipt = store.generate_receipt("tenant-a", accepted["request_id"], KEY_A)
        store.rotate_receipt_key("tenant-a", KEY_A, KEY_B)
        self.assertFalse(store.verify_receipt(receipt, "some-foreign-key-9999"))

    def test_other_tenant_registered_key_does_not_authenticate(self):
        store = self._store()
        accepted_a = self._completed(store, tenant="tenant-a", idem="ia")
        accepted_b = self._completed(store, tenant="tenant-b", idem="ib")
        receipt_a = store.generate_receipt(
            "tenant-a", accepted_a["request_id"], "tenant-a-secret-key"
        )
        store.generate_receipt(
            "tenant-b", accepted_b["request_id"], "tenant-b-secret-key"
        )
        # tenant-b's active key is not a generation of tenant-a.
        self.assertFalse(
            store.verify_receipt(receipt_a, "tenant-b-secret-key")
        )
        self.assertTrue(
            store.verify_receipt(receipt_a, "tenant-a-secret-key")
        )

    def test_tenants_sharing_key_text_have_independent_generations(self):
        store = self._store()
        # Both tenants bootstrap with the same key text; rotation state
        # stays per-tenant and the per-tenant fingerprint index lets each
        # register the same fingerprints independently.
        a = self._completed(store, tenant="tenant-a", idem="ia")
        b = self._completed(store, tenant="tenant-b", idem="ib")
        store.generate_receipt("tenant-a", a["request_id"], KEY_A)
        store.generate_receipt("tenant-b", b["request_id"], KEY_A)
        rotated_a = store.rotate_receipt_key("tenant-a", KEY_A, KEY_B)
        self.assertEqual(rotated_a["generation"], 2)
        # tenant-b is unaffected: its own A->B promotion succeeds as a
        # distinct gen-2 commit even though the key texts are identical.
        rotated_b = store.rotate_receipt_key("tenant-b", KEY_A, KEY_B)
        self.assertEqual(rotated_b["generation"], 2)
        rows_a = self._generations("tenant-a")
        rows_b = self._generations("tenant-b")
        self.assertEqual([row[0] for row in rows_a], [1, 2])
        self.assertEqual([row[0] for row in rows_b], [1, 2])
        self.assertEqual(
            [row[1] for row in rows_a], [row[1] for row in rows_b]
        )
        # Rotating one tenant's chain does not move the other's.
        self.assertEqual(
            store.rotate_receipt_key("tenant-a", KEY_B, KEY_C)["generation"], 3
        )
        self.assertEqual(
            [row[0] for row in self._generations("tenant-a")], [1, 2, 3]
        )
        self.assertEqual(
            [row[0] for row in self._generations("tenant-b")], [1, 2]
        )

    def test_rotation_chain_keeps_every_old_receipt_verifiable(self):
        store = self._store()
        accepted_1 = self._completed(store, idem="i1")
        receipt_1 = store.generate_receipt(
            "tenant-a", accepted_1["request_id"], KEY_A
        )
        store.rotate_receipt_key("tenant-a", KEY_A, KEY_B)
        accepted_2 = self._completed(store, idem="i2")
        receipt_2 = store.generate_receipt(
            "tenant-a", accepted_2["request_id"], KEY_B
        )
        store.rotate_receipt_key("tenant-a", KEY_B, KEY_C)
        accepted_3 = self._completed(store, idem="i3")
        receipt_3 = store.generate_receipt(
            "tenant-a", accepted_3["request_id"], KEY_C
        )
        # Each receipt authenticates under its own signing generation.
        self.assertTrue(store.verify_receipt(receipt_1, KEY_A))
        self.assertTrue(store.verify_receipt(receipt_2, KEY_B))
        self.assertTrue(store.verify_receipt(receipt_3, KEY_C))
        # Every other key/generation is an authentication mismatch.
        for receipt, signer in (
            (receipt_1, KEY_A),
            (receipt_2, KEY_B),
            (receipt_3, KEY_C),
        ):
            for wrong in (KEY_A, KEY_B, KEY_C):
                if wrong != signer:
                    self.assertFalse(
                        store.verify_receipt(receipt, wrong),
                        (signer, wrong),
                    )

    def test_first_rotation_then_receipts_are_generation_two(self):
        store = self._store()
        store.rotate_receipt_key("tenant-a", KEY_A, KEY_B)
        accepted = self._completed(store)
        # Gen-2 key signs; the retired gen-1 key cannot mint because no
        # receipt predates the rotation for this tenant.
        with self.assertRaises(ReceiptKeyConflict):
            store.generate_receipt("tenant-a", accepted["request_id"], KEY_A)
        receipt = store.generate_receipt("tenant-a", accepted["request_id"], KEY_B)
        self.assertTrue(store.verify_receipt(receipt, KEY_B))
        self.assertFalse(store.verify_receipt(receipt, KEY_A))

    def test_existing_receipt_replay_ignores_presented_key_and_never_rewrites(self):
        store = self._store()
        accepted = self._completed(store)
        first = store.generate_receipt("tenant-a", accepted["request_id"], KEY_A)
        store.rotate_receipt_key("tenant-a", KEY_A, KEY_B)
        with self._raw() as conn:
            stored_before = conn.execute(
                "SELECT receipt_json FROM deletion_receipts"
            ).fetchone()[0]
        # Re-generation replays the first bytes even under the new key,
        # a retired key or an unregistered key, and rewrites nothing.
        for presented in (KEY_A, KEY_B, "never-registered-key"):
            self.assertEqual(
                store.generate_receipt("tenant-a", accepted["request_id"], presented),
                first,
            )
        with self._raw() as conn:
            stored_after = conn.execute(
                "SELECT receipt_json FROM deletion_receipts"
            ).fetchone()[0]
        self.assertEqual(stored_before, stored_after)
        self.assertEqual(stored_after, first)

    def test_generation_request_id_boundary_raises_not_found(self):
        store = self._store()
        store.rotate_receipt_key("tenant-a", KEY_A, KEY_B)
        for bad in ("", None, 7, b"x", ["x"], 3.14):
            with self.subTest(bad=bad):
                with self.assertRaises(RequestNotFound):
                    store.generate_receipt("tenant-a", bad, KEY_B)
        # Unknown and cross-tenant ids keep the not-found boundary.
        with self.assertRaises(RequestNotFound):
            store.generate_receipt("tenant-a", "does-not-exist", KEY_B)
        other = self._completed(store, tenant="tenant-b", idem="ib")
        with self.assertRaises(RequestNotFound):
            store.generate_receipt("tenant-a", other["request_id"], KEY_B)

    def test_generation_unavailable_precedence_unchanged(self):
        store = self._store()
        accepted = store.submit("tenant-a", "subject-1", ["email"], "k")
        # Not completed: ReceiptUnavailable, regardless of key state.
        with self.assertRaises(ReceiptUnavailable):
            store.generate_receipt("tenant-a", accepted["request_id"], KEY_A)
        self.assertEqual(self._generations(), [])

    def test_old_key_conflict_precedes_availability_for_receiptless(self):
        # Once a generation exists, a retired or foreign key on ANY
        # receipt-less request raises ReceiptKeyConflict before the
        # request's own availability is assessed, and changes nothing.
        store = self._store()
        seed = self._completed(store, idem="idem-seed")
        store.generate_receipt("tenant-a", seed["request_id"], KEY_A)
        store.rotate_receipt_key("tenant-a", KEY_A, KEY_B)

        # States that need a claim are prepared before any stray
        # accepted request exists, so claim_next always picks the
        # intended request.
        other_completed = self._completed(store, idem="idem-other")
        processing = store.submit("tenant-a", "subject-p", ["email"], "k-proc")
        claim = store.claim_next("tenant-a", "worker-1", 60)
        self.assertEqual(claim["request_id"], processing["request_id"])
        failed = store.submit("tenant-a", "subject-f", ["email"], "k-fail")
        claim = store.claim_next("tenant-a", "worker-1", 60)
        self.assertEqual(claim["request_id"], failed["request_id"])
        store.finish_claim(
            "tenant-a", failed["request_id"], claim["claim_token"], "failed"
        )
        bare = store.submit("tenant-a", "subject-b", ["email"], "k-bare")
        store.transition("tenant-a", bare["request_id"], "processing")
        store.transition("tenant-a", bare["request_id"], "completed")
        accepted = store.submit("tenant-a", "subject-a", ["email"], "k-acc")

        for key in (KEY_A, "never-registered-foreign-key"):
            for receipt in (accepted, processing, failed, bare, other_completed):
                with self.subTest(key=key, request_id=receipt["request_id"]):
                    with self.assertRaises(ReceiptKeyConflict):
                        store.generate_receipt(
                            "tenant-a", receipt["request_id"], key
                        )
        # The rejected mints wrote neither receipts nor generations and
        # left statuses and execution records untouched.
        with self._raw() as conn:
            self.assertEqual(
                conn.execute("SELECT count(*) FROM deletion_receipts").fetchone()[0],
                1,
            )
            self.assertEqual(
                conn.execute("SELECT count(*) FROM receipt_keys").fetchone()[0],
                2,
            )
            statuses = dict(
                conn.execute(
                    "SELECT request_id, status FROM requests WHERE tenant_id = ?",
                    ("tenant-a",),
                ).fetchall()
            )
        self.assertEqual(statuses[accepted["request_id"]], "accepted")
        self.assertEqual(statuses[processing["request_id"]], "processing")
        self.assertEqual(statuses[failed["request_id"]], "failed")
        # The active key still mints the other completed request.
        new_receipt = store.generate_receipt(
            "tenant-a", other_completed["request_id"], KEY_B
        )
        self.assertTrue(store.verify_receipt(new_receipt, KEY_B))
        self.assertFalse(store.verify_receipt(new_receipt, KEY_A))

    def test_unknown_request_with_old_key_still_not_found(self):
        # The request-id boundary stays ahead of the key check: an
        # unknown or cross-tenant id is RequestNotFound even with a
        # retired key, so existence is never revealed.
        store = self._store()
        seed = self._completed(store, idem="idem-seed")
        store.generate_receipt("tenant-a", seed["request_id"], KEY_A)
        store.rotate_receipt_key("tenant-a", KEY_A, KEY_B)
        with self.assertRaises(RequestNotFound):
            store.generate_receipt("tenant-a", "does-not-exist", KEY_A)
        other = self._completed(store, tenant="tenant-b", idem="idem-b")
        with self.assertRaises(RequestNotFound):
            store.generate_receipt("tenant-a", other["request_id"], KEY_A)

    # -- concurrency -------------------------------------------------------

    def test_concurrent_identical_rotation_produces_one_generation(self):
        def rotate(_):
            return RequestStore(self.db_path).rotate_receipt_key(
                "tenant-a", KEY_A, KEY_B
            )

        with ThreadPoolExecutor(max_workers=12) as pool:
            results = list(pool.map(rotate, range(32)))
        distinct = {(r["generation"], r["effective_at"]) for r in results}
        self.assertEqual(len(distinct), 1)
        self.assertEqual(results[0]["generation"], 2)
        self.assertEqual([row[0] for row in self._generations()], [1, 2])

    def test_concurrent_distinct_successors_single_winner(self):
        store = self._store()
        store.rotate_receipt_key("tenant-a", KEY_A, KEY_B)

        def rotate(index):
            try:
                return (
                    "ok",
                    RequestStore(self.db_path).rotate_receipt_key(
                        "tenant-a", KEY_B, f"candidate-{index:03d}-key"
                    ),
                )
            except ReceiptKeyConflict:
                return ("conflict", None)

        with ThreadPoolExecutor(max_workers=12) as pool:
            outcomes = list(pool.map(rotate, range(24)))
        winners = [outcome for outcome in outcomes if outcome[0] == "ok"]
        self.assertEqual(len(winners), 1)
        winning_result = winners[0][1]
        self.assertEqual(winning_result["generation"], 3)
        self.assertEqual(
            [row[0] for row in self._generations()], [1, 2, 3]
        )
        # The winning pair replays idempotently; every losing candidate
        # remains a conflict and cannot establish a second gen 3.
        winner_key = None
        replay_store = self._store()
        for index in range(24):
            candidate = f"candidate-{index:03d}-key"
            try:
                replayed = replay_store.rotate_receipt_key(
                    "tenant-a", KEY_B, candidate
                )
            except ReceiptKeyConflict:
                continue
            if replayed == winning_result:
                winner_key = candidate
        self.assertIsNotNone(winner_key)
        for index in range(24):
            candidate = f"candidate-{index:03d}-key"
            if candidate != winner_key:
                with self.assertRaises(ReceiptKeyConflict):
                    replay_store.rotate_receipt_key("tenant-a", KEY_B, candidate)
        self.assertEqual(
            [row[0] for row in self._generations()], [1, 2, 3]
        )

    # -- durability ---------------------------------------------------------

    def test_generations_times_and_receipts_survive_restart(self):
        store = self._store()
        accepted = self._completed(store)
        receipt_1 = store.generate_receipt(
            "tenant-a", accepted["request_id"], KEY_A
        )
        rotation = store.rotate_receipt_key("tenant-a", KEY_A, KEY_B)
        second = self._completed(store, idem="i2")
        receipt_2 = store.generate_receipt("tenant-a", second["request_id"], KEY_B)

        rebuilt = self._store()
        self.assertEqual(
            rebuilt.rotate_receipt_key("tenant-a", KEY_A, KEY_B), rotation
        )
        self.assertTrue(rebuilt.verify_receipt(receipt_1, KEY_A))
        self.assertTrue(rebuilt.verify_receipt(receipt_2, KEY_B))
        self.assertFalse(rebuilt.verify_receipt(receipt_1, KEY_B))
        self.assertFalse(rebuilt.verify_receipt(receipt_2, KEY_A))
        # A further rotation chains off the persisted active generation.
        next_rotation = rebuilt.rotate_receipt_key("tenant-a", KEY_B, KEY_C)
        self.assertEqual(next_rotation["generation"], 3)

    def test_rotation_leaves_receipt_bytes_and_state_untouched(self):
        store = self._store()
        accepted = self._completed(store)
        receipt = store.generate_receipt("tenant-a", accepted["request_id"], KEY_A)
        status_before = store.get_status("tenant-a", accepted["request_id"])
        audit_before = store.audit("tenant-a", accepted["request_id"])
        log_before = store.get_execution_log("tenant-a", accepted["request_id"])
        with self._raw() as conn:
            stored_before = conn.execute(
                "SELECT receipt_json FROM deletion_receipts"
            ).fetchone()[0]
        store.rotate_receipt_key("tenant-a", KEY_A, KEY_B)
        self.assertEqual(
            store.get_status("tenant-a", accepted["request_id"]), status_before
        )
        self.assertEqual(
            store.audit("tenant-a", accepted["request_id"]), audit_before
        )
        self.assertEqual(
            store.get_execution_log("tenant-a", accepted["request_id"]),
            log_before,
        )
        with self._raw() as conn:
            stored_after = conn.execute(
                "SELECT receipt_json FROM deletion_receipts"
            ).fetchone()[0]
        self.assertEqual(stored_before, stored_after)
        self.assertEqual(stored_after, receipt)
        self.assertTrue(store.verify_evidence("tenant-a", accepted["request_id"]))

    # -- atomicity ----------------------------------------------------------

    def test_failed_rotation_commit_persists_no_generation(self):
        store = _CommitFailingStore(self.db_path)
        with self.assertRaises(OSError) as caught:
            store.rotate_receipt_key("tenant-a", KEY_A, KEY_B)
        self.assertEqual(str(caught.exception), "request store is unavailable")
        # The transaction rolled back as a whole: neither generation is
        # visible, and a healthy store afterwards starts from scratch.
        self.assertEqual(self._generations(), [])
        healthy = self._store()
        result = healthy.rotate_receipt_key("tenant-a", KEY_A, KEY_B)
        self.assertEqual(result["generation"], 2)

    def test_failed_mint_commit_persists_neither_receipt_nor_generation(self):
        store = self._store()
        accepted = self._completed(store)
        failing = _CommitFailingStore(self.db_path)
        with self.assertRaises(OSError):
            failing.generate_receipt("tenant-a", accepted["request_id"], KEY_A)
        with self._raw() as conn:
            self.assertEqual(
                conn.execute("SELECT count(*) FROM receipt_keys").fetchone()[0], 0
            )
            self.assertEqual(
                conn.execute("SELECT count(*) FROM deletion_receipts").fetchone()[0],
                0,
            )
        # The healthy retry bootstraps generation 1 normally.
        healthy = self._store()
        receipt = healthy.generate_receipt(
            "tenant-a", accepted["request_id"], KEY_A
        )
        self.assertTrue(healthy.verify_receipt(receipt, KEY_A))

    # -- corruption and storage failure -------------------------------------

    def test_corrupt_key_record_raises_storage_error(self):
        import hashlib

        store = self._store()
        store.rotate_receipt_key("tenant-a", KEY_A, KEY_B)
        accepted = self._completed(store)

        def restore_clean():
            with self._raw() as conn:
                conn.execute("DELETE FROM receipt_keys")
                conn.execute(
                    "INSERT INTO receipt_keys VALUES "
                    "('tenant-a', 1, ?, '2026-01-01T00:00:00.000000Z'), "
                    "('tenant-a', 2, ?, '2026-01-01T00:00:00.000000Z')",
                    (
                        hashlib.sha256(KEY_A.encode()).hexdigest(),
                        hashlib.sha256(KEY_B.encode()).hexdigest(),
                    ),
                )

        corruptions = [
            # Generation gap: the history no longer starts at 1.
            "UPDATE receipt_keys SET generation = 3 WHERE generation = 1",
            # A fingerprint outside the 64-lowercase-hex shape.
            "UPDATE receipt_keys SET key_fingerprint = 'not-a-fingerprint' "
            "WHERE generation = 1",
            # An unparsable effective time.
            "UPDATE receipt_keys SET effective_at = 'yesterday' "
            "WHERE generation = 2",
            # A missing predecessor leaves a gap.
            "DELETE FROM receipt_keys WHERE generation = 1",
        ]
        for corruption in corruptions:
            restore_clean()
            with self._raw() as conn:
                conn.execute(corruption)
            with self.subTest(corruption=corruption):
                with self.assertRaises(OSError) as caught:
                    store.rotate_receipt_key("tenant-a", KEY_B, KEY_C)
                self.assertEqual(
                    str(caught.exception), "request store is unavailable"
                )
                with self.assertRaises(OSError):
                    store.generate_receipt(
                        "tenant-a", accepted["request_id"], KEY_B
                    )
        # A healthy history is accepted again after repair.
        restore_clean()
        self.assertEqual(
            store.rotate_receipt_key("tenant-a", KEY_B, KEY_C)["generation"], 3
        )

    def test_unwritable_database_raises_storage_error(self):
        store = self._store()
        store.rotate_receipt_key("tenant-a", KEY_A, KEY_B)
        os.chmod(self.db_path, 0o444)
        try:
            with self.assertRaises(OSError) as caught:
                store.rotate_receipt_key("tenant-a", KEY_B, KEY_C)
            self.assertEqual(str(caught.exception), "request store is unavailable")
        finally:
            os.chmod(self.db_path, 0o644)

    def test_historical_database_without_key_rows_keeps_verifying(self):
        # A database written before key generations existed has receipts
        # but no receipt_keys rows; the receipt verifies on its tag alone.
        store = self._store()
        accepted = self._completed(store)
        receipt = store.generate_receipt("tenant-a", accepted["request_id"], KEY_A)
        with self._raw() as conn:
            conn.execute("DROP TABLE receipt_keys")
        rebuilt = self._store()  # additive migration recreates the table
        self.assertTrue(rebuilt.verify_receipt(receipt, KEY_A))
        self.assertFalse(rebuilt.verify_receipt(receipt, KEY_B))

    # -- confidentiality -----------------------------------------------------

    def test_key_material_never_persisted(self):
        store = self._store()
        accepted = self._completed(store)
        store.generate_receipt("tenant-a", accepted["request_id"], KEY_A)
        store.rotate_receipt_key("tenant-a", KEY_A, KEY_B)
        second = self._completed(store, idem="i2")
        store.generate_receipt("tenant-a", second["request_id"], KEY_B)
        store.rotate_receipt_key("tenant-a", KEY_B, KEY_C)
        with open(self.db_path, "rb") as handle:
            content = handle.read()
        for secret in (KEY_A, KEY_B, KEY_C):
            self.assertNotIn(secret.encode(), content)

    def test_rotation_errors_and_logs_do_not_leak_key_material(self):
        store = self._store()
        store.rotate_receipt_key("tenant-a", KEY_A, KEY_B)
        try:
            store.rotate_receipt_key("tenant-a", KEY_A, KEY_C)
        except ReceiptKeyConflict as exc:
            self.assertNotIn(KEY_A, str(exc))
            self.assertNotIn(KEY_B, str(exc))
            self.assertNotIn(KEY_C, str(exc))
        else:
            self.fail("expected ReceiptKeyConflict")
        try:
            store.rotate_receipt_key("tenant-a", "missing-key", KEY_C)
        except ValueError as exc:
            self.assertNotIn(KEY_A, str(exc))
            self.assertNotIn("missing-key", str(exc))
        else:
            self.fail("expected ValueError")

    # -- in-memory store ------------------------------------------------------

    def test_in_memory_rotation_lifecycle(self):
        store = RequestStore(":memory:")
        accepted = store.submit("tenant-a", "subject-1", ["email"], "idem-1")
        claim = store.claim_next("tenant-a", "worker-1", 60)
        store.finish_claim(
            "tenant-a", accepted["request_id"], claim["claim_token"], "completed"
        )
        receipt_1 = store.generate_receipt("tenant-a", accepted["request_id"], KEY_A)
        rotation = store.rotate_receipt_key("tenant-a", KEY_A, KEY_B)
        self.assertEqual(rotation["generation"], 2)
        self.assertTrue(store.verify_receipt(receipt_1, KEY_A))
        self.assertFalse(store.verify_receipt(receipt_1, KEY_B))
        second = store.submit("tenant-a", "subject-2", ["email"], "idem-2")
        claim = store.claim_next("tenant-a", "worker-1", 60)
        store.finish_claim(
            "tenant-a", second["request_id"], claim["claim_token"], "completed"
        )
        with self.assertRaises(ReceiptKeyConflict):
            store.generate_receipt("tenant-a", second["request_id"], KEY_A)
        receipt_2 = store.generate_receipt("tenant-a", second["request_id"], KEY_B)
        self.assertTrue(store.verify_receipt(receipt_2, KEY_B))
        self.assertEqual(
            store.rotate_receipt_key("tenant-a", KEY_A, KEY_B), rotation
        )


if __name__ == "__main__":
    unittest.main()
