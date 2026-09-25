"""Tests for recoverable anchor secret generation rotation.

Covers ``rotate_anchor_key`` and the generation-aware boundaries of
``verify_chain`` / ``diagnose_chain``: constructor validation of
``anchor_history_secrets``, first-rotation bootstrap (before and after
the first anchor), idempotent replay, conflict precedence, concurrency
(one active generation ever), per-generation anchor attribution with no
rewriting, restart recovery with and without historical secrets,
legacy-database migration, corrupt generation records, atomic commit
failures and secret-material confidentiality.
"""

import hashlib
import os
import re
import sqlite3
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor

from forgetting_evidence.requests import (
    AnchorKeyConflict,
    RequestStore,
)


RFC3339 = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$"
)
SECRET_A = "anchor-secret-alpha-0001"
SECRET_B = "anchor-secret-bravo-0002"
SECRET_C = "anchor-secret-charlie-0003"
SECRET_D = "anchor-secret-delta-0004"


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


class AnchorKeyRotationTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "anchor-rotation.db")

    def tearDown(self):
        self._tmp.cleanup()

    def _store(self, secret=SECRET_A, history=None):
        return RequestStore(
            self.db_path,
            anchor_secret=secret,
            anchor_history_secrets=history,
        )

    def _raw(self):
        return sqlite3.connect(self.db_path)

    def _anchored(self, store=None, secret=SECRET_A, idem="idem-1"):
        store = store or self._store(secret)
        accepted = store.submit("tenant-a", "subject-1", ["email"], idem)
        store.transition("tenant-a", accepted["request_id"], "processing")
        return store, accepted

    def _generations(self):
        with self._raw() as conn:
            return conn.execute(
                "SELECT generation, key_fingerprint, effective_at "
                "FROM anchor_key_generations ORDER BY generation"
            ).fetchall()

    # -- constructor validation -----------------------------------------

    def test_history_container_must_be_mapping(self):
        for bad in ([], (), "x", 5, {0: "x"}.keys()):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    RequestStore(self.db_path, anchor_secret=SECRET_A,
                                 anchor_history_secrets=bad)

    def test_history_generations_must_be_positive_non_bool_ints(self):
        for bad_generation in (0, -1, 1.5, "1", True, False, None):
            with self.subTest(bad=bad_generation):
                with self.assertRaises(ValueError):
                    self._store(history={bad_generation: "old-secret"})

    def test_history_secrets_must_be_non_empty_strings(self):
        for bad_secret in ("", 7, b"x", ["x"], None):
            with self.subTest(bad=bad_secret):
                with self.assertRaises(ValueError):
                    self._store(history={1: bad_secret})

    def test_history_requires_current_secret(self):
        with self.assertRaises(ValueError):
            RequestStore(self.db_path, anchor_history_secrets={1: SECRET_A})
        # None and an empty mapping are both accepted.
        self._store(history=None)
        self._store(history={})

    def test_invalid_constructor_arguments_write_nothing(self):
        for bad_history in ("x", [7], {0: "x"}, {1: 5}):
            with self.assertRaises(ValueError):
                self._store(history=bad_history)
        self.assertFalse(os.path.exists(self.db_path))

    # -- result shape and per-generation attribution --------------------

    def test_rotation_result_shape(self):
        store, _accepted = self._anchored()
        result = store.rotate_anchor_key(SECRET_A, SECRET_B)
        self.assertEqual(set(result), {"generation", "effective_at"})
        self.assertIsInstance(result["generation"], int)
        self.assertNotIsInstance(result["generation"], bool)
        self.assertEqual(result["generation"], 2)
        self.assertIsInstance(result["effective_at"], str)
        self.assertTrue(RFC3339.match(result["effective_at"]))
        rows = self._generations()
        self.assertEqual([row[0] for row in rows], [1, 2])
        for row in rows:
            self.assertRegex(row[1], r"^[0-9a-f]{64}$")
            self.assertTrue(RFC3339.match(row[2]))

    def test_new_anchors_use_new_generation_existing_are_untouched(self):
        store, accepted = self._anchored()
        store.rotate_anchor_key(SECRET_A, SECRET_B)
        store.transition("tenant-a", accepted["request_id"], "completed")
        with self._raw() as conn:
            attributions = conn.execute(
                "SELECT seq, key_generation FROM audit_anchors ORDER BY seq"
            ).fetchall()
        # The accepted and processing anchors stay on generation 1; the
        # post-rotation completed anchor is generation 2. Nothing is
        # rewritten.
        self.assertEqual(attributions, [(0, 1), (1, 1), (2, 2)])
        self.assertTrue(store.verify_chain())

    def test_same_rotation_replays_first_generation_and_time(self):
        store, _accepted = self._anchored()
        first = store.rotate_anchor_key(SECRET_A, SECRET_B)
        time.sleep(0.01)
        for _ in range(3):
            self.assertEqual(
                store.rotate_anchor_key(SECRET_A, SECRET_B), first
            )
        self.assertEqual([row[0] for row in self._generations()], [1, 2])

    def test_rotation_chain_advances(self):
        store, accepted = self._anchored()
        r2 = store.rotate_anchor_key(SECRET_A, SECRET_B)
        r3 = store.rotate_anchor_key(SECRET_B, SECRET_C)
        r4 = store.rotate_anchor_key(SECRET_C, SECRET_D)
        self.assertEqual([r2["generation"], r3["generation"], r4["generation"]],
                         [2, 3, 4])
        self.assertTrue(
            r2["effective_at"] <= r3["effective_at"] <= r4["effective_at"]
        )
        self.assertEqual([row[0] for row in self._generations()], [1, 2, 3, 4])
        # The pair producing the active generation still replays.
        self.assertEqual(store.rotate_anchor_key(SECRET_C, SECRET_D), r4)

    # -- restart recovery ------------------------------------------------

    def test_rebuilt_with_history_verifies_old_and_active_anchors(self):
        store, accepted = self._anchored()
        store.rotate_anchor_key(SECRET_A, SECRET_B)
        store.transition("tenant-a", accepted["request_id"], "completed")
        second = store.submit("tenant-a", "subject-2", ["email"], "idem-2")
        rebuilt = self._store(SECRET_B, history={1: SECRET_A})
        self.assertTrue(rebuilt.verify_chain())
        self.assertEqual(rebuilt.diagnose_chain(), [])
        self.assertTrue(rebuilt.verify_chain("tenant-a", accepted["request_id"]))
        self.assertTrue(rebuilt.verify_chain("tenant-a", second["request_id"]))

    def test_missing_historical_generation_is_false_with_key_missing(self):
        store, accepted = self._anchored()
        store.rotate_anchor_key(SECRET_A, SECRET_B)
        store.transition("tenant-a", accepted["request_id"], "completed")
        rebuilt = self._store(SECRET_B)
        self.assertFalse(rebuilt.verify_chain())
        reasons = rebuilt.diagnose_chain()
        self.assertIn("anchor_key_missing", reasons)
        self.assertNotIn("anchor_auth_failed", reasons)

    def test_wrong_historical_secret_is_false_with_auth_failed(self):
        store, accepted = self._anchored()
        store.rotate_anchor_key(SECRET_A, SECRET_B)
        store.transition("tenant-a", accepted["request_id"], "completed")
        rebuilt = self._store(SECRET_B, history={1: "a-wrong-old-secret"})
        self.assertFalse(rebuilt.verify_chain())
        self.assertIn("anchor_auth_failed", rebuilt.diagnose_chain())
        self.assertNotIn("anchor_key_missing", rebuilt.diagnose_chain())

    def test_wrong_current_secret_fails_after_rotation(self):
        store, accepted = self._anchored()
        store.rotate_anchor_key(SECRET_A, SECRET_B)
        store.transition("tenant-a", accepted["request_id"], "completed")
        rebuilt = self._store("not-the-active-secret", history={1: SECRET_A})
        self.assertFalse(rebuilt.verify_chain())
        self.assertIn("anchor_auth_failed", rebuilt.diagnose_chain())

    def test_generations_times_and_conclusions_survive_restart(self):
        store, accepted = self._anchored()
        rotation = store.rotate_anchor_key(SECRET_A, SECRET_B)
        store.transition("tenant-a", accepted["request_id"], "completed")
        rebuilt = self._store(SECRET_B, history={1: SECRET_A})
        # The rotation itself replays to the first generation and time.
        self.assertEqual(
            rebuilt.rotate_anchor_key(SECRET_A, SECRET_B), rotation
        )
        self.assertTrue(rebuilt.verify_chain())
        # A further rotation chains off the persisted active generation.
        self.assertEqual(
            rebuilt.rotate_anchor_key(SECRET_B, SECRET_C)["generation"], 3
        )

    def test_repeated_verification_is_strictly_read_only(self):
        store, accepted = self._anchored()
        store.rotate_anchor_key(SECRET_A, SECRET_B)
        store.transition("tenant-a", accepted["request_id"], "completed")
        rebuilt = self._store(SECRET_B, history={1: SECRET_A})
        with open(self.db_path, "rb") as handle:
            before = handle.read()
        for _ in range(5):
            self.assertTrue(rebuilt.verify_chain())
            self.assertEqual(rebuilt.diagnose_chain(), [])
        with open(self.db_path, "rb") as handle:
            after = handle.read()
        self.assertEqual(before, after)

    # -- bootstrap rotation before the first anchor ---------------------

    def test_rotation_before_any_anchor_registers_one_and_two(self):
        store = self._store()
        result = store.rotate_anchor_key(SECRET_A, SECRET_B)
        self.assertEqual(result["generation"], 2)
        rows = self._generations()
        self.assertEqual([row[0] for row in rows], [1, 2])
        self.assertEqual(rows[0][2], rows[1][2])
        accepted = store.submit("tenant-a", "subject-1", ["email"], "idem-1")
        store.transition("tenant-a", accepted["request_id"], "failed")
        with self._raw() as conn:
            attributions = conn.execute(
                "SELECT key_generation FROM audit_anchors ORDER BY seq"
            ).fetchall()
        self.assertEqual(attributions, [(2,), (2,)])
        self.assertTrue(store.verify_chain())

    def test_bootstrap_rotation_survives_restart_with_history(self):
        store = self._store()
        store.rotate_anchor_key(SECRET_A, SECRET_B)
        accepted = store.submit("tenant-a", "subject-1", ["email"], "idem-1")
        rebuilt = self._store(SECRET_B, history={1: SECRET_A})
        self.assertTrue(rebuilt.verify_chain())
        # Without the retired generation's secret the history is simply
        # absent (no gen-1 anchor exists), so the chain still verifies.
        no_history = self._store(SECRET_B)
        self.assertTrue(no_history.verify_chain())
        self.assertTrue(no_history.verify_chain("tenant-a", accepted["request_id"]))

    # -- conflicts and invalid arguments ---------------------------------

    def test_retired_secret_two_generations_old_is_value_error(self):
        store, _accepted = self._anchored()
        store.rotate_anchor_key(SECRET_A, SECRET_B)
        store.rotate_anchor_key(SECRET_B, SECRET_C)
        # SECRET_A is registered but no longer the active generation or
        # its immediate predecessor.
        with self.assertRaises(ValueError):
            store.rotate_anchor_key(SECRET_A, SECRET_D)
        self.assertEqual([row[0] for row in self._generations()], [1, 2, 3])

    def test_enabled_secret_already_registered_is_value_error(self):
        store, _accepted = self._anchored()
        store.rotate_anchor_key(SECRET_A, SECRET_B)
        with self.assertRaises(ValueError):
            store.rotate_anchor_key(SECRET_B, SECRET_A)
        self.assertEqual([row[0] for row in self._generations()], [1, 2])

    def test_invalid_rotation_arguments_raise_value_error_without_writing(self):
        store, _accepted = self._anchored()
        for bad in ("", None, 7, b"k", ["k"], 3.14):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    store.rotate_anchor_key(bad, SECRET_B)
                with self.assertRaises(ValueError):
                    store.rotate_anchor_key(SECRET_A, bad)
        with self.assertRaises(ValueError):
            store.rotate_anchor_key(SECRET_A, SECRET_A)
        # Only the first-anchor generation-1 bootstrap row exists.
        self.assertEqual([row[0] for row in self._generations()], [1])

    def test_no_secret_store_cannot_rotate(self):
        self._anchored()
        with self.assertRaises(ValueError):
            RequestStore(self.db_path).rotate_anchor_key(SECRET_A, SECRET_B)

    # -- concurrency ------------------------------------------------------

    def test_concurrent_same_pair_returns_one_result(self):
        self._anchored()

        def rotate(_):
            return RequestStore(self.db_path, anchor_secret=SECRET_A).rotate_anchor_key(
                SECRET_A, SECRET_B
            )

        with ThreadPoolExecutor(max_workers=12) as pool:
            results = list(pool.map(rotate, range(32)))
        distinct = {(r["generation"], r["effective_at"]) for r in results}
        self.assertEqual(len(distinct), 1)
        self.assertEqual(results[0]["generation"], 2)
        self.assertEqual([row[0] for row in self._generations()], [1, 2])

    def test_concurrent_distinct_enabled_secrets_single_winner(self):
        store, _accepted = self._anchored()
        store.rotate_anchor_key(SECRET_A, SECRET_B)

        def rotate(index):
            try:
                return (
                    "ok",
                    RequestStore(self.db_path, anchor_secret=SECRET_B).rotate_anchor_key(
                        SECRET_B, f"candidate-{index:03d}-secret"
                    ),
                )
            except AnchorKeyConflict:
                return ("conflict", None)

        with ThreadPoolExecutor(max_workers=12) as pool:
            outcomes = list(pool.map(rotate, range(24)))
        winners = [outcome for outcome in outcomes if outcome[0] == "ok"]
        self.assertEqual(len(winners), 1)
        self.assertEqual(winners[0][1]["generation"], 3)
        self.assertEqual([row[0] for row in self._generations()], [1, 2, 3])
        # Every losing candidate still raises the conflict afterwards
        # and can never establish a second generation 3.
        replay = self._store(SECRET_B, history={1: SECRET_A})
        winner = None
        for index in range(24):
            candidate = f"candidate-{index:03d}-secret"
            try:
                replay.rotate_anchor_key(SECRET_B, candidate)
            except AnchorKeyConflict:
                continue
            winner = candidate
        self.assertIsNotNone(winner)
        for index in range(24):
            candidate = f"candidate-{index:03d}-secret"
            if candidate != winner:
                with self.assertRaises(AnchorKeyConflict):
                    replay.rotate_anchor_key(SECRET_B, candidate)
        self.assertEqual([row[0] for row in self._generations()], [1, 2, 3])

    # -- write gating after rotation --------------------------------------

    def test_stale_instance_cannot_anchor_after_rotation(self):
        store, accepted = self._anchored()
        RequestStore(self.db_path, anchor_secret=SECRET_A).rotate_anchor_key(
            SECRET_A, SECRET_B
        )
        stale = self._store(SECRET_A)
        self.assertFalse(stale.verify_chain())
        with self.assertRaises(OSError) as caught:
            stale.transition("tenant-a", accepted["request_id"], "completed")
        self.assertEqual(str(caught.exception), "request store is unavailable")
        # The active instance is unaffected.
        active = self._store(SECRET_B, history={1: SECRET_A})
        active.transition("tenant-a", accepted["request_id"], "completed")
        self.assertTrue(active.verify_chain())

    def test_forged_anchor_under_old_generation_does_not_authenticate(self):
        store = self._store()
        accepted = store.submit("tenant-a", "subject-1", ["email"], "idem-1")
        store.rotate_anchor_key(SECRET_A, SECRET_B)
        store.transition("tenant-a", accepted["request_id"], "processing")
        # Tamper with the new anchor's attribution: claim it was sealed
        # under generation 1. It was not, so it cannot authenticate.
        with self._raw() as conn:
            conn.execute(
                "UPDATE audit_anchors SET key_generation = 1 "
                "WHERE request_id = ? AND seq = 1",
                (accepted["request_id"],),
            )
        rebuilt = self._store(SECRET_B, history={1: SECRET_A})
        self.assertFalse(rebuilt.verify_chain())
        self.assertIn("anchor_auth_failed", rebuilt.diagnose_chain())

    # -- legacy database ---------------------------------------------------

    def _downgrade_to_legacy_shape(self):
        """Strip the generations table and per-anchor attributions."""
        with self._raw() as conn:
            conn.execute("DELETE FROM anchor_key_generations")
            conn.execute("UPDATE audit_anchors SET key_generation = NULL")

    def test_legacy_anchored_database_verifies_under_configured_secret(self):
        store, accepted = self._anchored()
        self._downgrade_to_legacy_shape()
        rebuilt = self._store(SECRET_A)
        self.assertTrue(rebuilt.verify_chain())
        self.assertEqual(rebuilt.diagnose_chain(), [])
        # Appending lazily registers generation 1, the new anchor joins
        # that generation and no past anchor is rewritten.
        rebuilt.transition("tenant-a", accepted["request_id"], "completed")
        self.assertTrue(rebuilt.verify_chain())
        with self._raw() as conn:
            self.assertEqual(
                conn.execute(
                    "SELECT generation FROM anchor_key_generations"
                ).fetchall(),
                [(1,)],
            )
            self.assertEqual(
                conn.execute(
                    "SELECT seq, key_generation FROM audit_anchors ORDER BY seq"
                ).fetchall(),
                [(0, None), (1, None), (2, 1)],
            )

    def test_rotation_on_legacy_anchored_database_requires_correct_secret(self):
        self._anchored()
        self._downgrade_to_legacy_shape()
        with self.assertRaises(OSError) as caught:
            self._store("a-different-secret").rotate_anchor_key(
                "a-different-secret", SECRET_B
            )
        self.assertEqual(str(caught.exception), "request store is unavailable")
        # Nothing was written by the refused rotation.
        self.assertEqual(self._generations(), [])

    def test_rotation_on_unanchored_legacy_database_refused(self):
        legacy_path = os.path.join(self._tmp.name, "unanchored.db")
        old = RequestStore(legacy_path)
        accepted = old.submit("tenant-a", "subject-1", ["email"], "k1")
        old.transition("tenant-a", accepted["request_id"], "processing")
        with self.assertRaises(OSError):
            RequestStore(legacy_path, anchor_secret=SECRET_A).rotate_anchor_key(
                SECRET_A, SECRET_B
            )

    def test_legacy_rotation_then_restart_full_verification(self):
        store, accepted = self._anchored()
        self._downgrade_to_legacy_shape()
        rebuilt = self._store(SECRET_A)
        result = rebuilt.rotate_anchor_key(SECRET_A, SECRET_B)
        self.assertEqual(result["generation"], 2)
        second = rebuilt.submit("tenant-a", "subject-2", ["email"], "idem-2")
        final = self._store(SECRET_B, history={1: SECRET_A})
        self.assertTrue(final.verify_chain())
        self.assertTrue(final.verify_chain("tenant-a", accepted["request_id"]))
        self.assertTrue(final.verify_chain("tenant-a", second["request_id"]))
        self.assertFalse(self._store(SECRET_B).verify_chain())

    # -- corruption and storage failure ------------------------------------

    def test_corrupt_generation_record_raises_storage_error(self):
        store, accepted = self._anchored()
        store.rotate_anchor_key(SECRET_A, SECRET_B)
        corruptions = [
            "UPDATE anchor_key_generations SET generation = 9 WHERE generation = 1",
            "UPDATE anchor_key_generations SET key_fingerprint = 'nope' "
            "WHERE generation = 1",
            "UPDATE anchor_key_generations SET effective_at = 'yesterday' "
            "WHERE generation = 2",
            "DELETE FROM anchor_key_generations WHERE generation = 1",
        ]
        for corruption in corruptions:
            self._restore_clean_generations()
            with self._raw() as conn:
                conn.execute(corruption)
            with self.subTest(corruption=corruption):
                with self.assertRaises(OSError) as caught:
                    self._store(SECRET_B, history={1: SECRET_A}).rotate_anchor_key(
                        SECRET_B, SECRET_C
                    )
                self.assertEqual(
                    str(caught.exception), "request store is unavailable"
                )
                self.assertFalse(
                    self._store(SECRET_B, history={1: SECRET_A}).verify_chain()
                )

    def _restore_clean_generations(self):
        with self._raw() as conn:
            conn.execute("DELETE FROM anchor_key_generations")
            conn.execute(
                "INSERT INTO anchor_key_generations VALUES "
                "(1, ?, '2026-01-01T00:00:00.000000Z'), "
                "(2, ?, '2026-01-02T00:00:00.000000Z')",
                (
                    hashlib.sha256(SECRET_A.encode()).hexdigest(),
                    hashlib.sha256(SECRET_B.encode()).hexdigest(),
                ),
            )

    def test_failed_rotation_commit_persists_no_generation(self):
        store, _accepted = self._anchored()
        failing = _CommitFailingStore(self.db_path, anchor_secret=SECRET_A)
        with self.assertRaises(OSError) as caught:
            failing.rotate_anchor_key(SECRET_A, SECRET_B)
        self.assertEqual(str(caught.exception), "request store is unavailable")
        # Only the generation-1 bootstrap row (from the first anchor) is
        # present; the failed rotation left nothing behind.
        self.assertEqual([row[0] for row in self._generations()], [1])
        healthy = self._store(SECRET_A)
        self.assertEqual(
            healthy.rotate_anchor_key(SECRET_A, SECRET_B)["generation"], 2
        )

    def test_unwritable_database_raises_storage_error(self):
        store, _accepted = self._anchored()
        store.rotate_anchor_key(SECRET_A, SECRET_B)
        os.chmod(self.db_path, 0o444)
        try:
            with self.assertRaises(OSError) as caught:
                self._store(SECRET_B, history={1: SECRET_A}).rotate_anchor_key(
                    SECRET_B, SECRET_C
                )
            self.assertEqual(str(caught.exception), "request store is unavailable")
        finally:
            os.chmod(self.db_path, 0o644)

    # -- confidentiality ----------------------------------------------------

    def test_secret_material_never_persisted(self):
        store, _accepted = self._anchored()
        store.rotate_anchor_key(SECRET_A, SECRET_B)
        store.rotate_anchor_key(SECRET_B, SECRET_C)
        with open(self.db_path, "rb") as handle:
            content = handle.read()
        for secret in (SECRET_A, SECRET_B, SECRET_C):
            self.assertNotIn(secret.encode(), content)

    def test_rotation_conflict_does_not_leak_secret_material(self):
        store, _accepted = self._anchored()
        store.rotate_anchor_key(SECRET_A, SECRET_B)
        try:
            store.rotate_anchor_key(SECRET_A, SECRET_C)
        except AnchorKeyConflict as exc:
            message = str(exc)
            self.assertNotIn(SECRET_A, message)
            self.assertNotIn(SECRET_B, message)
            self.assertNotIn(SECRET_C, message)
        else:
            self.fail("expected AnchorKeyConflict")

    # -- in-memory store ----------------------------------------------------

    def test_in_memory_rotation_lifecycle(self):
        store = RequestStore(":memory:", anchor_secret=SECRET_A)
        accepted = store.submit("tenant-a", "subject-1", ["email"], "idem-1")
        store.transition("tenant-a", accepted["request_id"], "processing")
        rotation = store.rotate_anchor_key(SECRET_A, SECRET_B)
        self.assertEqual(rotation["generation"], 2)
        store.transition("tenant-a", accepted["request_id"], "completed")
        self.assertTrue(store.verify_chain())
        # The same instance keeps sealing under the new generation and
        # remembers the retired secret in memory.
        accepted_2 = store.submit("tenant-a", "subject-2", ["email"], "idem-2")
        self.assertTrue(store.verify_chain())
        self.assertTrue(store.verify_chain("tenant-a", accepted_2["request_id"]))


if __name__ == "__main__":
    unittest.main()
