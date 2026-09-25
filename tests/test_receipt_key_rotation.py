import hashlib
import json
import os
import re
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor

from forgetting_evidence.requests import (
    ReceiptKeyConflict,
    RequestNotFound,
    RequestStore,
)


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
K1 = "rotation-key-0001"
K2 = "rotation-key-0002"
K3 = "rotation-key-0003"
CONFLICT_TEXT = "receipt key conflict"


class RotationTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "rotation.db")

    def tearDown(self):
        self._tmp.cleanup()

    def _store(self):
        return RequestStore(self.db_path)

    def _raw(self):
        return sqlite3.connect(self.db_path)

    def _completed(self, store, tenant="tenant-a", idem="idem-1",
                   scopes=("email", "profile")):
        accepted = store.submit(tenant, "subject-1", list(scopes), idem)
        claim = store.claim_next(tenant, "worker-1", 60)
        store.finish_claim(
            tenant, accepted["request_id"], claim["claim_token"], "completed"
        )
        return accepted

    # --- first generation registration -----------------------------------

    def test_first_receipt_registers_generation_one(self):
        store = self._store()
        accepted = self._completed(store)
        text = store.generate_receipt("tenant-a", accepted["request_id"], K1)
        with self._raw() as conn:
            active = conn.execute(
                "SELECT active_generation FROM receipt_key_state"
            ).fetchone()[0]
            rows = conn.execute(
                "SELECT generation, key_fingerprint, rotated_at "
                "FROM receipt_key_generations ORDER BY generation"
            ).fetchall()
        self.assertEqual(active, 1)
        self.assertEqual([r[0] for r in rows], [1])
        self.assertTrue(re.fullmatch(r"[0-9a-f]{64}", rows[0][1]))
        self.assertTrue(RFC3339.match(rows[0][2]))
        # No new key-identifier field is ever added to the receipt.
        self.assertEqual(list(json.loads(text)), FIELDS)
        self.assertTrue(store.verify_receipt(text, K1))

    def test_first_rotation_before_any_receipt_registers_generations_one_and_two(self):
        store = self._store()
        result = store.rotate_receipt_key("tenant-a", K1, K2)
        self.assertEqual(set(result), {"generation", "rotated_at"})
        self.assertEqual(result["generation"], 2)
        self.assertTrue(RFC3339.match(result["rotated_at"]))
        with self._raw() as conn:
            rows = conn.execute(
                "SELECT generation FROM receipt_key_generations ORDER BY generation"
            ).fetchall()
            active = conn.execute(
                "SELECT active_generation FROM receipt_key_state"
            ).fetchone()[0]
        self.assertEqual([r[0] for r in rows], [1, 2])
        self.assertEqual(active, 2)
        # With generation 2 active, the retired K1 cannot mint but K2 can.
        accepted = self._completed(store)
        with self.assertRaises(ReceiptKeyConflict):
            store.generate_receipt("tenant-a", accepted["request_id"], K1)
        text = store.generate_receipt("tenant-a", accepted["request_id"], K2)
        self.assertTrue(store.verify_receipt(text, K2))

    def test_rotation_after_generation_one_advances_to_two(self):
        store = self._store()
        accepted = self._completed(store)
        store.generate_receipt("tenant-a", accepted["request_id"], K1)
        result = store.rotate_receipt_key("tenant-a", K1, K2)
        self.assertEqual(result["generation"], 2)
        with self._raw() as conn:
            gens = [
                r[0]
                for r in conn.execute(
                    "SELECT generation FROM receipt_key_generations ORDER BY generation"
                )
            ]
        self.assertEqual(gens, [1, 2])

    # --- idempotency ------------------------------------------------------

    def test_identical_rotation_is_idempotent(self):
        store = self._store()
        store.rotate_receipt_key("tenant-a", K1, K2)
        first = store.rotate_receipt_key("tenant-a", K1, K2)
        again = store.rotate_receipt_key("tenant-a", K1, K2)
        self.assertEqual(again, first)
        self.assertEqual(first["generation"], 2)
        with self._raw() as conn:
            count = conn.execute(
                "SELECT count(*) FROM receipt_key_generations"
            ).fetchone()[0]
        self.assertEqual(count, 2)

    def test_idempotent_replay_after_several_rotations(self):
        store = self._store()
        store.rotate_receipt_key("tenant-a", K1, K2)
        to_three = store.rotate_receipt_key("tenant-a", K2, K3)
        self.assertEqual(to_three["generation"], 3)
        # Replaying the rotation that established gen 2 is now a
        # superseded combination and conflicts; only the rotation that
        # established the active gen 3 replays idempotently.
        with self.assertRaises(ReceiptKeyConflict):
            store.rotate_receipt_key("tenant-a", K1, K2)
        self.assertEqual(store.rotate_receipt_key("tenant-a", K2, K3), to_three)

    # --- old vs new receipt boundaries ------------------------------------

    def test_old_receipt_stays_verifiable_under_original_key(self):
        store = self._store()
        first = self._completed(store, idem="i1")
        old_text = store.generate_receipt("tenant-a", first["request_id"], K1)
        store.rotate_receipt_key("tenant-a", K1, K2)

        second = self._completed(store, idem="i2")
        new_text = store.generate_receipt("tenant-a", second["request_id"], K2)

        # Old receipt: its own key verifies, the new key does not.
        self.assertTrue(store.verify_receipt(old_text, K1))
        self.assertFalse(store.verify_receipt(old_text, K2))
        # New receipt: the current key verifies, the retired key does not.
        self.assertTrue(store.verify_receipt(new_text, K2))
        self.assertFalse(store.verify_receipt(new_text, K1))

    def test_retired_key_cannot_mint_new_receipt(self):
        store = self._store()
        store.rotate_receipt_key("tenant-a", K1, K2)
        accepted = self._completed(store)
        with self.assertRaises(ReceiptKeyConflict):
            store.generate_receipt("tenant-a", accepted["request_id"], K1)
        # The failed mint wrote no receipt.
        with self._raw() as conn:
            count = conn.execute(
                "SELECT count(*) FROM deletion_receipts"
            ).fetchone()[0]
        self.assertEqual(count, 0)

    def test_unknown_key_cannot_mint_new_receipt(self):
        store = self._store()
        accepted = self._completed(store)
        store.generate_receipt("tenant-a", accepted["request_id"], K1)
        store.rotate_receipt_key("tenant-a", K1, K2)
        second = self._completed(store, idem="i2")
        with self.assertRaises(ReceiptKeyConflict):
            store.generate_receipt("tenant-a", second["request_id"], "no-such-key")

    def test_old_receipt_is_never_rewritten_or_reissued(self):
        store = self._store()
        accepted = self._completed(store)
        old_text = store.generate_receipt("tenant-a", accepted["request_id"], K1)
        store.rotate_receipt_key("tenant-a", K1, K2)
        # Regenerating the old receipt after rotation still returns the
        # byte-identical first receipt regardless of the presented key and
        # never a freshly tagged copy.
        for key in (K1, K2):
            self.assertEqual(
                store.generate_receipt("tenant-a", accepted["request_id"], key),
                old_text,
            )
        self.assertTrue(store.verify_receipt(old_text, K1))
        self.assertFalse(store.verify_receipt(old_text, K2))

    def test_multi_generation_history_all_verifiable(self):
        store = self._store()
        texts = {}
        accepted = self._completed(store, idem="i0")
        texts[1] = store.generate_receipt("tenant-a", accepted["request_id"], K1)
        store.rotate_receipt_key("tenant-a", K1, K2)
        accepted = self._completed(store, idem="i1")
        texts[2] = store.generate_receipt("tenant-a", accepted["request_id"], K2)
        store.rotate_receipt_key("tenant-a", K2, K3)
        accepted = self._completed(store, idem="i2")
        texts[3] = store.generate_receipt("tenant-a", accepted["request_id"], K3)
        keys = {1: K1, 2: K2, 3: K3}
        # Each receipt verifies only under the key of its own generation.
        for gen, text in texts.items():
            for other_gen, key in keys.items():
                self.assertIs(
                    store.verify_receipt(text, key),
                    gen == other_gen,
                    (gen, other_gen),
                )

    def test_receipt_fields_and_bytes_unchanged_after_rotation(self):
        store = self._store()
        accepted = self._completed(store)
        before = store.generate_receipt("tenant-a", accepted["request_id"], K1)
        store.rotate_receipt_key("tenant-a", K1, K2)
        after = store.generate_receipt("tenant-a", accepted["request_id"], K2)
        self.assertEqual(after, before)
        self.assertTrue(before.endswith("\n"))
        self.assertEqual(before.count("\n"), 1)
        self.assertEqual(list(json.loads(before)), FIELDS)

    # --- conflicts --------------------------------------------------------

    def test_rotation_with_non_current_retired_key_conflicts(self):
        store = self._store()
        store.rotate_receipt_key("tenant-a", K1, K2)
        # K1 is retired; it cannot retire anything anymore.
        with self.assertRaises(ReceiptKeyConflict) as caught:
            store.rotate_receipt_key("tenant-a", K1, K3)
        self.assertEqual(str(caught.exception), CONFLICT_TEXT)
        with self.assertRaises(ReceiptKeyConflict):
            store.rotate_receipt_key("tenant-a", "unknown", K3)

    def test_reusing_retained_key_as_new_conflicts(self):
        store = self._store()
        store.rotate_receipt_key("tenant-a", K1, K2)
        store.rotate_receipt_key("tenant-a", K2, K3)
        # Reusing the generation-1 key as a "new" key is rejected.
        with self.assertRaises(ReceiptKeyConflict):
            store.rotate_receipt_key("tenant-a", K3, K1)

    def test_conflict_leaves_active_generation_unchanged(self):
        store = self._store()
        result = store.rotate_receipt_key("tenant-a", K1, K2)
        for args in ((K1, K3), ("unknown", K3), (K2, K1)):
            with self.assertRaises(ReceiptKeyConflict):
                store.rotate_receipt_key("tenant-a", *args)
        with self._raw() as conn:
            active = conn.execute(
                "SELECT active_generation FROM receipt_key_state"
            ).fetchone()[0]
            gens = [
                r[0]
                for r in conn.execute(
                    "SELECT generation FROM receipt_key_generations ORDER BY generation"
                )
            ]
        self.assertEqual(active, result["generation"])
        self.assertEqual(gens, [1, 2])

    def test_concurrent_distinct_enabling_keys_single_winner(self):
        # Separate store instances sharing one file exercise real
        # cross-connection SQLite arbitration (BEGIN IMMEDIATE), not only
        # the in-process lock.
        first = self._store()
        first.rotate_receipt_key("tenant-a", K1, K2)

        def attempt(index):
            store = self._store()
            try:
                return ("ok", store.rotate_receipt_key("tenant-a", K2, f"N{index}"))
            except ReceiptKeyConflict:
                return ("conflict", None)

        with ThreadPoolExecutor(max_workers=12) as pool:
            outcomes = list(pool.map(attempt, range(12)))
        winners = [out for out in outcomes if out[0] == "ok"]
        self.assertEqual(len(winners), 1)
        self.assertEqual(winners[0][1]["generation"], 3)
        with self._raw() as conn:
            active = conn.execute(
                "SELECT active_generation FROM receipt_key_state"
            ).fetchone()[0]
            gens = [
                r[0]
                for r in conn.execute(
                    "SELECT generation FROM receipt_key_generations ORDER BY generation"
                )
            ]
        self.assertEqual(active, 3)
        self.assertEqual(gens, [1, 2, 3])

    def test_concurrent_identical_rotations_all_return_first_result(self):
        first = self._store()
        first.rotate_receipt_key("tenant-a", K1, K2)
        expected = None

        def rotate(_):
            store = self._store()
            return store.rotate_receipt_key("tenant-a", K2, K3)

        with ThreadPoolExecutor(max_workers=10) as pool:
            results = list(pool.map(rotate, range(10)))
        self.assertEqual(len({json.dumps(r, sort_keys=True) for r in results}), 1)
        self.assertEqual(results[0]["generation"], 3)
        with self._raw() as conn:
            gens = [
                r[0]
                for r in conn.execute(
                    "SELECT generation FROM receipt_key_generations ORDER BY generation"
                )
            ]
        self.assertEqual(gens, [1, 2, 3])

    # --- validation -------------------------------------------------------

    def test_invalid_rotation_arguments_raise_value_error_without_writing(self):
        store = self._store()
        bad_values = ("", None, 7, b"k", ["k"], 3.14)
        for bad in bad_values:
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    store.rotate_receipt_key(bad, K2, K3)
                with self.assertRaises(ValueError):
                    store.rotate_receipt_key("tenant-a", bad, K3)
                with self.assertRaises(ValueError):
                    store.rotate_receipt_key("tenant-a", K2, bad)
        # Identical retired and enabling keys are caller error, not a
        # no-op rotation.
        with self.assertRaises(ValueError):
            store.rotate_receipt_key("tenant-a", K1, K1)
        with self._raw() as conn:
            self.assertEqual(
                conn.execute(
                    "SELECT count(*) FROM receipt_key_generations"
                ).fetchone()[0],
                0,
            )
            self.assertIsNone(
                conn.execute(
                    "SELECT active_generation FROM receipt_key_state"
                ).fetchone()
            )

    def test_generate_request_id_boundary_is_not_found(self):
        store = self._store()
        store.rotate_receipt_key("tenant-a", K1, K2)
        for bad in ("", None, 7, b"x", ["x"], 3.14, "missing-id"):
            with self.subTest(bad=bad):
                with self.assertRaises(RequestNotFound):
                    store.generate_receipt("tenant-a", bad, K2)

    # --- durability --------------------------------------------------------

    def test_generations_times_and_receipts_survive_restart(self):
        store = self._store()
        accepted = self._completed(store, idem="i1")
        old_text = store.generate_receipt("tenant-a", accepted["request_id"], K1)
        gen_two = store.rotate_receipt_key("tenant-a", K1, K2)
        accepted = self._completed(store, idem="i2")
        new_text = store.generate_receipt("tenant-a", accepted["request_id"], K2)

        rebuilt = self._store()
        self.assertEqual(
            rebuilt.rotate_receipt_key("tenant-a", K1, K2), gen_two
        )
        self.assertTrue(rebuilt.verify_receipt(old_text, K1))
        self.assertTrue(rebuilt.verify_receipt(new_text, K2))
        self.assertFalse(rebuilt.verify_receipt(old_text, K2))
        # The active key after restart still mints receipts; K1 cannot.
        accepted = self._completed(rebuilt, idem="i3")
        with self.assertRaises(ReceiptKeyConflict):
            rebuilt.generate_receipt("tenant-a", accepted["request_id"], K1)
        third = rebuilt.generate_receipt("tenant-a", accepted["request_id"], K2)
        self.assertTrue(rebuilt.verify_receipt(third, K2))

    def test_failed_rotation_is_never_visible_as_effective(self):
        store = self._store()
        store.rotate_receipt_key("tenant-a", K1, K2)
        with self.assertRaises(ReceiptKeyConflict):
            store.rotate_receipt_key("tenant-a", K1, K3)
        with self.assertRaises(ValueError):
            store.rotate_receipt_key("tenant-a", K2, K2)
        # The active generation is still 2 and points at an existing row.
        with self._raw() as conn:
            active = conn.execute(
                "SELECT active_generation FROM receipt_key_state"
            ).fetchone()[0]
            orphan = conn.execute(
                "SELECT count(*) FROM receipt_key_state s "
                "LEFT JOIN receipt_key_generations g "
                "ON g.tenant_id = s.tenant_id "
                "AND g.generation = s.active_generation "
                "WHERE g.generation IS NULL"
            ).fetchone()[0]
        self.assertEqual(active, 2)
        self.assertEqual(orphan, 0)

    def test_rotation_does_not_change_state_or_evidence(self):
        store = self._store()
        accepted = self._completed(store)
        request_id = accepted["request_id"]
        store.generate_receipt("tenant-a", request_id, K1)
        status_before = store.get_status("tenant-a", request_id)
        audit_before = store.audit("tenant-a", request_id)
        evidence_before = store.evidence("tenant-a", request_id)
        store.rotate_receipt_key("tenant-a", K1, K2)
        self.assertEqual(store.get_status("tenant-a", request_id), status_before)
        self.assertEqual(store.audit("tenant-a", request_id), audit_before)
        self.assertEqual(store.evidence("tenant-a", request_id), evidence_before)
        self.assertTrue(store.verify_evidence("tenant-a", request_id))

    def test_tenant_isolation(self):
        store = self._store()
        store.rotate_receipt_key("tenant-a", K1, K2)
        # Tenant B is untouched: its first presented key is still gen 1.
        accepted_b = self._completed(store, tenant="tenant-b", idem="b1")
        text_b = store.generate_receipt(
            "tenant-b", accepted_b["request_id"], "BKEY1"
        )
        self.assertTrue(store.verify_receipt(text_b, "BKEY1"))
        with self._raw() as conn:
            active_b = conn.execute(
                "SELECT active_generation FROM receipt_key_state WHERE tenant_id = ?",
                ("tenant-b",),
            ).fetchone()[0]
            active_a = conn.execute(
                "SELECT active_generation FROM receipt_key_state WHERE tenant_id = ?",
                ("tenant-a",),
            ).fetchone()[0]
        self.assertEqual(active_b, 1)
        self.assertEqual(active_a, 2)

    # --- corruption --------------------------------------------------------

    def test_corrupt_key_state_raises_storage_error(self):
        store = self._store()
        store.rotate_receipt_key("tenant-a", K1, K2)
        # A second completed request exists but has no receipt yet, so the
        # next generate must read the active key and hit the corrupt state.
        accepted = self._completed(store, idem="i2")
        # State pointer naming a generation that does not exist.
        with self._raw() as conn:
            conn.execute(
                "UPDATE receipt_key_state SET active_generation = 99"
            )
        with self.assertRaises(OSError) as caught:
            store.rotate_receipt_key("tenant-a", K2, K3)
        self.assertEqual(str(caught.exception), "request store is unavailable")
        with self.assertRaises(OSError):
            store.generate_receipt("tenant-a", accepted["request_id"], K3)

    def test_corrupt_generation_row_raises_storage_error(self):
        store = self._store()
        accepted = self._completed(store)
        store.generate_receipt("tenant-a", accepted["request_id"], K1)
        second = self._completed(store, idem="i2")
        with self._raw() as conn:
            conn.execute(
                "UPDATE receipt_key_generations SET key_fingerprint = 'zzz'"
            )
        with self.assertRaises(OSError):
            store.rotate_receipt_key("tenant-a", K1, K2)
        with self.assertRaises(OSError):
            store.generate_receipt("tenant-a", second["request_id"], K1)

    # --- confidentiality ---------------------------------------------------

    def test_key_material_never_persisted(self):
        store = self._store()
        accepted = self._completed(store)
        store.generate_receipt("tenant-a", accepted["request_id"], K1)
        store.rotate_receipt_key("tenant-a", K1, K2)
        store.rotate_receipt_key("tenant-a", K2, K3)
        with open(self.db_path, "rb") as handle:
            content = handle.read()
        for key in (K1, K2, K3):
            self.assertNotIn(key.encode(), content)
        # The stored fingerprint is not a bare hash of the key either.
        with self._raw() as conn:
            fingerprints = [
                r[0]
                for r in conn.execute(
                    "SELECT key_fingerprint FROM receipt_key_generations"
                )
            ]
        for key, fp in zip((K1, K2, K3), fingerprints):
            self.assertNotEqual(fp, hashlib.sha256(key.encode()).hexdigest())

    def test_results_and_errors_never_carry_key_material(self):
        store = self._store()
        result = store.rotate_receipt_key("tenant-a", K1, K2)
        self.assertEqual(set(result), {"generation", "rotated_at"})
        for key in (K1, K2):
            self.assertNotIn(key, result["rotated_at"])
        try:
            store.rotate_receipt_key("tenant-a", K1, K3)
        except ReceiptKeyConflict as exc:
            message = str(exc)
        else:
            self.fail("expected ReceiptKeyConflict")
        self.assertEqual(message, CONFLICT_TEXT)
        for key in (K1, K2, K3):
            self.assertNotIn(key, message)

    def test_receipt_still_carries_no_secret_after_rotation(self):
        secret_worker = "worker-SECRET"
        store = self._store()
        accepted = store.submit(
            "tenant-a", "subject-SECRET", ["scope-SECRET", "email"], "idem-SECRET"
        )
        claim = store.claim_next("tenant-a", secret_worker, 60)
        store.finish_claim(
            "tenant-a", accepted["request_id"], claim["claim_token"], "completed"
        )
        store.generate_receipt("tenant-a", accepted["request_id"], K1)
        store.rotate_receipt_key("tenant-a", K1, K2)
        text = store.generate_receipt("tenant-a", accepted["request_id"], K2)
        for secret in (
            "subject-SECRET",
            "scope-SECRET",
            "idem-SECRET",
            secret_worker,
            claim["claim_token"],
            K1,
            K2,
        ):
            self.assertNotIn(secret, text)

    # --- in-memory store ---------------------------------------------------

    def test_in_memory_rotation_lifecycle(self):
        store = RequestStore(":memory:")
        accepted = store.submit("tenant-a", "subject-1", ["email"], "idem-1")
        claim = store.claim_next("tenant-a", "worker-1", 60)
        store.finish_claim(
            "tenant-a", accepted["request_id"], claim["claim_token"], "completed"
        )
        old_text = store.generate_receipt("tenant-a", accepted["request_id"], K1)
        self.assertEqual(
            store.rotate_receipt_key("tenant-a", K1, K2)["generation"], 2
        )
        self.assertTrue(store.verify_receipt(old_text, K1))
        self.assertFalse(store.verify_receipt(old_text, K2))
        accepted = store.submit("tenant-a", "subject-1", ["email"], "idem-2")
        claim = store.claim_next("tenant-a", "worker-1", 60)
        store.finish_claim(
            "tenant-a", accepted["request_id"], claim["claim_token"], "completed"
        )
        with self.assertRaises(ReceiptKeyConflict):
            store.generate_receipt("tenant-a", accepted["request_id"], K1)
        new_text = store.generate_receipt("tenant-a", accepted["request_id"], K2)
        self.assertTrue(store.verify_receipt(new_text, K2))


if __name__ == "__main__":
    unittest.main()
