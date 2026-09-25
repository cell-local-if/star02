"""Tests for recoverable anchor-key generation rotation.

Covers ``rotate_anchor_key`` and the generation-aware boundaries of
anchor sealing / verification: first-rotation generations 1-and-2
commit, the per-anchor generation association, idempotent replay,
rebuild with current plus historical secrets, ``anchor_key_missing``
versus ``anchor_auth_failed`` diagnosis, conflict precedence
(concurrent losers versus caller errors), restart durability, the
additive migration of a pre-rotation anchored file, atomic commit
failures and secret-material confidentiality.
"""

import os
import re
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor

from forgetting_evidence.requests import (
    AnchorKeyConflict,
    RequestNotFound,
    RequestStore,
)

RFC3339 = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$"
)
SECRET_A = "anchor-secret-alpha-0001"
SECRET_B = "anchor-secret-bravo-0002"
SECRET_C = "anchor-secret-charlie-0003"
STORAGE_MESSAGE = "request store is unavailable"


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
    def __init__(self, path, **kwargs):
        super().__init__(path, **kwargs)

    def _connect(self):
        return _CommitFailingConnection(super()._connect())

    def _release(self, conn):
        super()._release(conn._real)


class AnchorKeyRotationTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "anchors.db")

    def tearDown(self):
        self._tmp.cleanup()

    def _store(self, secret=SECRET_A, history=None):
        return RequestStore(
            self.db_path, anchor_secret=secret, anchor_history_secrets=history
        )

    def _raw(self):
        return sqlite3.connect(self.db_path)

    def _anchored_request(self, store=None, tenant="tenant-a", idem="idem-1",
                          secret=SECRET_A):
        store = store or self._store(secret)
        accepted = store.submit(tenant, "subject-1", ["email", "profile"], idem)
        store.transition(tenant, accepted["request_id"], "processing")
        store.transition(tenant, accepted["request_id"], "completed")
        return store, accepted

    def _generations(self):
        with self._raw() as conn:
            return conn.execute(
                "SELECT generation, key_fingerprint, effective_at "
                "FROM anchor_key_generations ORDER BY generation"
            ).fetchall()

    # -- construction / history validation ------------------------------

    def test_history_container_validation(self):
        # A mapping of positive-int generations to non-empty strings is
        # accepted; generation 1 supplied alongside the active secret is
        # the normal rebuild shape.
        store = self._store(SECRET_B, {1: SECRET_A})
        self.assertTrue(isinstance(store, RequestStore))
        # Non-mapping containers, non-positive/non-int generations,
        # boolean generations and non-string/empty secrets are all
        # caller errors raised before the database is used.
        for bad in (
            [(1, SECRET_A)],
            "not-a-mapping",
            {0: SECRET_A},
            {-1: SECRET_A},
            {1.0: SECRET_A},
            {True: SECRET_A},
            {"1": SECRET_A},
            {1: ""},
            {1: None},
            {1: 7},
            {1: b"secret"},
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    RequestStore(self.db_path, anchor_secret=SECRET_B,
                                 anchor_history_secrets=bad)

    # -- rotation result shape ------------------------------------------

    def test_first_rotation_registers_one_and_two(self):
        store = self._store()
        result = store.rotate_anchor_key(SECRET_A, SECRET_B)
        self.assertEqual(set(result), {"generation", "effective_at"})
        self.assertEqual(result["generation"], 2)
        self.assertNotIsInstance(result["generation"], bool)
        self.assertTrue(RFC3339.match(result["effective_at"]))
        rows = self._generations()
        self.assertEqual([row[0] for row in rows], [1, 2])
        # The bootstrap pair shares the one rotation commit time.
        self.assertEqual(rows[0][2], rows[1][2])
        self.assertEqual(rows[1][2], result["effective_at"])
        for row in rows:
            self.assertRegex(row[1], r"^[0-9a-f]{64}$")

    def test_rotation_on_empty_db_then_first_anchor_uses_generation_two(self):
        store = self._store(SECRET_A)
        result = store.rotate_anchor_key(SECRET_A, SECRET_B)
        self.assertEqual(result["generation"], 2)
        accepted = store.submit("tenant-a", "subject-1", ["email"], "k1")
        with self._raw() as conn:
            anchor_generation = conn.execute(
                "SELECT anchor_generation FROM audit_anchors"
            ).fetchone()[0]
        self.assertEqual(anchor_generation, 2)
        self.assertTrue(store.verify_chain())
        self.assertTrue(store.verify_chain("tenant-a", accepted["request_id"]))

    # -- idempotency -----------------------------------------------------

    def test_same_rotation_is_idempotent_with_first_generation_and_time(self):
        store = self._store()
        first = store.rotate_anchor_key(SECRET_A, SECRET_B)
        for _ in range(3):
            self.assertEqual(
                store.rotate_anchor_key(SECRET_A, SECRET_B), first
            )
        self.assertEqual([row[0] for row in self._generations()], [1, 2])

    def test_rotation_chain_advances_and_only_latest_pair_replays(self):
        store = self._store()
        r2 = store.rotate_anchor_key(SECRET_A, SECRET_B)
        r3 = store.rotate_anchor_key(SECRET_B, SECRET_C)
        self.assertEqual(r2["generation"], 2)
        self.assertEqual(r3["generation"], 3)
        self.assertEqual(
            store.rotate_anchor_key(SECRET_B, SECRET_C), r3
        )
        self.assertEqual([row[0] for row in self._generations()], [1, 2, 3])

    # -- new anchors use the active generation, old ones stay ------------

    def test_anchors_keep_their_birth_generation_after_rotation(self):
        store, first = self._anchored_request(idem="i1")
        self.assertTrue(store.verify_chain())
        store.rotate_anchor_key(SECRET_A, SECRET_B)
        second = store.submit("tenant-a", "subject-2", ["email"], "i2")
        store.transition("tenant-a", second["request_id"], "failed")
        # The rotating instance is re-keyed in memory and stays whole.
        self.assertTrue(store.verify_chain())
        with self._raw() as conn:
            gens = conn.execute(
                "SELECT anchor_generation, count(*) FROM audit_anchors "
                "GROUP BY anchor_generation ORDER BY anchor_generation"
            ).fetchall()
        self.assertEqual(gens, [(1, 3), (2, 2)])
        self.assertTrue(store.verify_chain("tenant-a", first["request_id"]))
        self.assertTrue(store.verify_chain("tenant-a", second["request_id"]))

    def test_execution_and_reconcile_paths_anchor_under_active_generation(self):
        store = self._store()
        accepted = store.submit("tenant-a", "subject-1", ["email"], "k1")
        store.rotate_anchor_key(SECRET_A, SECRET_B)
        claim = store.claim_next("tenant-a", "worker-1", 60)
        store.finish_claim(
            "tenant-a", accepted["request_id"], claim["claim_token"], "completed"
        )
        self.assertTrue(store.verify_chain())
        with self._raw() as conn:
            self.assertEqual(
                conn.execute(
                    "SELECT DISTINCT anchor_generation FROM audit_anchors "
                    "WHERE seq >= 1"
                ).fetchone()[0],
                2,
            )

    # -- rebuild with current plus historical secrets -------------------

    def test_rebuilt_with_history_verifies_old_and_active_anchors(self):
        store, first = self._anchored_request(idem="i1")
        store.rotate_anchor_key(SECRET_A, SECRET_B)
        second = store.submit("tenant-a", "subject-2", ["email"], "i2")
        store.transition("tenant-a", second["request_id"], "failed")
        rebuilt = self._store(SECRET_B, {1: SECRET_A})
        self.assertTrue(rebuilt.verify_chain())
        self.assertEqual(rebuilt.diagnose_chain(), [])
        self.assertTrue(rebuilt.verify_chain("tenant-a", first["request_id"]))
        self.assertTrue(rebuilt.verify_chain("tenant-a", second["request_id"]))

    def test_rebuilt_without_history_reports_missing_generation(self):
        store, _first = self._anchored_request()
        store.rotate_anchor_key(SECRET_A, SECRET_B)
        store.submit("tenant-a", "subject-2", ["email"], "i2")
        rebuilt = self._store(SECRET_B)  # no generation-1 secret supplied
        self.assertFalse(rebuilt.verify_chain())
        reasons = rebuilt.diagnose_chain()
        self.assertIn("anchor_key_missing", reasons)
        # A store that simply holds no secret at all is the distinct
        # "no secret" case, not a missing historical generation.
        self.assertNotIn("anchor_secret_missing", reasons)

    def test_wrong_historical_secret_reports_auth_failure_not_missing(self):
        store, _first = self._anchored_request()
        store.rotate_anchor_key(SECRET_A, SECRET_B)
        store.submit("tenant-a", "subject-2", ["email"], "i2")
        rebuilt = self._store(SECRET_B, {1: "a-wrong-old-secret"})
        self.assertFalse(rebuilt.verify_chain())
        reasons = rebuilt.diagnose_chain()
        self.assertIn("anchor_auth_failed", reasons)
        self.assertNotIn("anchor_key_missing", reasons)

    def test_multi_generation_rebuild_requires_each_history_secret(self):
        store, first = self._anchored_request()
        store.rotate_anchor_key(SECRET_A, SECRET_B)
        store.submit("tenant-a", "s2", ["email"], "i2")
        store.rotate_anchor_key(SECRET_B, SECRET_C)
        third = store.submit("tenant-a", "s3", ["email"], "i3")
        # Full history plus active secret verifies every anchor.
        full = self._store(SECRET_C, {1: SECRET_A, 2: SECRET_B})
        self.assertTrue(full.verify_chain())
        self.assertTrue(full.verify_chain("tenant-a", third["request_id"]))
        # Missing only the generation-2 secret is a missing key, not a
        # forgery.
        partial = self._store(SECRET_C, {1: SECRET_A})
        self.assertFalse(partial.verify_chain())
        self.assertIn("anchor_key_missing", partial.diagnose_chain())

    def test_no_secret_store_reports_anchored_database_secret_missing(self):
        store, _first = self._anchored_request()
        store.rotate_anchor_key(SECRET_A, SECRET_B)
        blind = RequestStore(self.db_path)
        self.assertFalse(blind.verify_chain())
        self.assertEqual(blind.diagnose_chain(), ["anchor_secret_missing"])

    # -- conflicts and caller errors -------------------------------------

    def test_concurrent_distinct_successors_single_winner(self):
        store = self._store()
        store.rotate_anchor_key(SECRET_A, SECRET_B)

        def rotate(index):
            try:
                return (
                    "ok",
                    RequestStore(self.db_path, anchor_secret=SECRET_B)
                    .rotate_anchor_key(SECRET_B, f"candidate-{index:03d}"),
                )
            except AnchorKeyConflict:
                return ("conflict", None)

        with ThreadPoolExecutor(max_workers=12) as pool:
            outcomes = list(pool.map(rotate, range(24)))
        winners = [outcome for outcome in outcomes if outcome[0] == "ok"]
        self.assertEqual(len(winners), 1)
        self.assertEqual(winners[0][1]["generation"], 3)
        self.assertEqual(
            [row[0] for row in self._generations()], [1, 2, 3]
        )

    def test_predecessor_retired_with_fresh_successor_is_conflict(self):
        # Deterministic, sequential shape of a promotion that lost to the
        # committed successor: the retiring secret is the immediate
        # predecessor and the successor is unrecorded.
        store = self._store()
        store.rotate_anchor_key(SECRET_A, SECRET_B)
        store.rotate_anchor_key(SECRET_B, SECRET_C)
        with self.assertRaises(AnchorKeyConflict):
            store.rotate_anchor_key(SECRET_B, "a-different-successor")

    def test_concurrent_identical_rotation_converges(self):
        self._anchored_request()

        def rotate(_):
            return (
                RequestStore(self.db_path, anchor_secret=SECRET_A)
                .rotate_anchor_key(SECRET_A, SECRET_B)
            )

        with ThreadPoolExecutor(max_workers=12) as pool:
            results = list(pool.map(rotate, range(24)))
        distinct = {(r["generation"], r["effective_at"]) for r in results}
        self.assertEqual(len(distinct), 1)
        self.assertEqual(results[0]["generation"], 2)
        self.assertEqual([row[0] for row in self._generations()], [1, 2])

    def test_invalid_rotation_arguments_raise_value_error_without_writing(self):
        store = self._store()
        store.rotate_anchor_key(SECRET_A, SECRET_B)
        for bad in ("", None, 7, b"k", ["k"], 3.14):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    store.rotate_anchor_key(bad, SECRET_B)
                with self.assertRaises(ValueError):
                    store.rotate_anchor_key(SECRET_B, bad)
        with self.assertRaises(ValueError):
            store.rotate_anchor_key(SECRET_B, SECRET_B)
        # An older-than-predecessor retiring secret is caller error.
        store.rotate_anchor_key(SECRET_B, SECRET_C)
        with self.assertRaises(ValueError):
            store.rotate_anchor_key(SECRET_A, "fresh-successor")
        # A never-registered retiring secret is caller error too.
        with self.assertRaises(ValueError):
            store.rotate_anchor_key("never-registered", "fresh-successor-2")
        # A successor already on record is caller error.
        with self.assertRaises(ValueError):
            store.rotate_anchor_key(SECRET_C, SECRET_B)
        # No rejected call changed the generations.
        self.assertEqual([row[0] for row in self._generations()], [1, 2, 3])

    # -- durability -------------------------------------------------------

    def test_generations_and_times_survive_restart(self):
        store, first = self._anchored_request()
        rotation = store.rotate_anchor_key(SECRET_A, SECRET_B)
        second = store.submit("tenant-a", "s2", ["email"], "i2")
        rebuilt = self._store(SECRET_B, {1: SECRET_A})
        self.assertEqual(
            rebuilt.rotate_anchor_key(SECRET_A, SECRET_B), rotation
        )
        self.assertTrue(rebuilt.verify_chain("tenant-a", first["request_id"]))
        self.assertTrue(rebuilt.verify_chain("tenant-a", second["request_id"]))
        self.assertEqual(
            rebuilt.rotate_anchor_key(SECRET_B, SECRET_C)["generation"], 3
        )

    def test_rotation_leaves_events_and_anchors_untouched(self):
        store, accepted = self._anchored_request()
        chain_before = store.audit("tenant-a", accepted["request_id"])
        store.rotate_anchor_key(SECRET_A, SECRET_B)
        self.assertEqual(
            store.audit("tenant-a", accepted["request_id"]), chain_before
        )
        with self._raw() as conn:
            existing = conn.execute(
                "SELECT commit_seq, anchor_hmac, anchor_generation "
                "FROM audit_anchors ORDER BY commit_seq"
            ).fetchall()
        self.assertEqual([row[2] for row in existing], [1, 1, 1])
        self.assertTrue(store.verify_chain("tenant-a", accepted["request_id"]))

    # -- atomicity, corruption and storage failure -----------------------

    def test_failed_rotation_commit_persists_no_generation(self):
        failing = _CommitFailingStore(self.db_path, anchor_secret=SECRET_A)
        with self.assertRaises(OSError) as caught:
            failing.rotate_anchor_key(SECRET_A, SECRET_B)
        self.assertEqual(str(caught.exception), STORAGE_MESSAGE)
        self.assertEqual(self._generations(), [])
        # A healthy retry starts the generations from scratch.
        self.assertEqual(
            self._store().rotate_anchor_key(SECRET_A, SECRET_B)["generation"],
            2,
        )

    def test_corrupt_generation_record_raises_storage_error(self):
        import hashlib

        store = self._store()
        store.rotate_anchor_key(SECRET_A, SECRET_B)
        accepted = store.submit("tenant-a", "s", ["email"], "k")

        def restore_clean():
            with self._raw() as conn:
                conn.execute("DELETE FROM anchor_key_generations")
                conn.execute(
                    "INSERT INTO anchor_key_generations VALUES "
                    "(1, ?, '2026-01-01T00:00:00.000000Z'), "
                    "(2, ?, '2026-01-01T00:00:00.000000Z')",
                    (
                        hashlib.sha256(
                            b"forgetting-evidence:anchor-key:" + SECRET_A.encode()
                        ).hexdigest(),
                        hashlib.sha256(
                            b"forgetting-evidence:anchor-key:" + SECRET_B.encode()
                        ).hexdigest(),
                    ),
                )

        corruptions = [
            "UPDATE anchor_key_generations SET generation = 3 WHERE generation = 1",
            "UPDATE anchor_key_generations SET key_fingerprint = 'not-a-fp' "
            "WHERE generation = 1",
            "UPDATE anchor_key_generations SET effective_at = 'yesterday' "
            "WHERE generation = 2",
            "DELETE FROM anchor_key_generations WHERE generation = 1",
        ]
        for corruption in corruptions:
            restore_clean()
            with self._raw() as conn:
                conn.execute(corruption)
            with self.subTest(corruption=corruption):
                with self.assertRaises(OSError) as caught:
                    store.rotate_anchor_key(SECRET_B, SECRET_C)
                self.assertEqual(str(caught.exception), STORAGE_MESSAGE)
                with self.assertRaises(OSError):
                    store.verify_chain()
                with self.assertRaises(OSError):
                    store.transition("tenant-a", accepted["request_id"], "failed")
        restore_clean()
        self.assertEqual(
            store.rotate_anchor_key(SECRET_B, SECRET_C)["generation"], 3
        )

    # -- additive migration of a pre-rotation anchored file --------------

    def test_pre_rotation_anchored_file_migrates_and_rotates(self):
        store, accepted = self._anchored_request()
        self.assertTrue(store.verify_chain())
        # Rewrite the on-disk shape to what a pre-rotation version wrote:
        # audit anchors without a generation column and no key table rows.
        with self._raw() as conn:
            conn.execute(
                "CREATE TABLE audit_anchors_old AS SELECT commit_seq, tenant_id, "
                "request_id, seq, event_hash, anchor_hmac FROM audit_anchors"
            )
            conn.execute("DROP TABLE audit_anchors")
            conn.execute(
                "ALTER TABLE audit_anchors_old RENAME TO audit_anchors"
            )
            conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_anchors_commit_seq "
                "ON audit_anchors(commit_seq)"
            )
            conn.execute("DELETE FROM anchor_key_generations")
        # Opening the file additively restores the generation column
        # (backfilled to 1); historical anchors still verify.
        migrated = self._store(SECRET_A)
        self.assertTrue(migrated.verify_chain())
        self.assertEqual(migrated.diagnose_chain(), [])
        # The first rotation authenticates the legacy anchors under A and
        # promotes B; a wrong retiring secret is refused without writing.
        with self.assertRaises(ValueError):
            RequestStore(self.db_path, anchor_secret="bogus").rotate_anchor_key(
                "bogus", SECRET_B
            )
        result = migrated.rotate_anchor_key(SECRET_A, SECRET_B)
        self.assertEqual(result["generation"], 2)
        migrated.submit("tenant-a", "s2", ["email"], "i2")
        rebuilt = self._store(SECRET_B, {1: SECRET_A})
        self.assertTrue(rebuilt.verify_chain())
        self.assertTrue(
            rebuilt.verify_chain("tenant-a", accepted["request_id"])
        )

    # -- confidentiality ---------------------------------------------------

    def test_secret_material_never_persisted(self):
        store, _accepted = self._anchored_request()
        store.rotate_anchor_key(SECRET_A, SECRET_B)
        store.rotate_anchor_key(SECRET_B, SECRET_C)
        with open(self.db_path, "rb") as handle:
            content = handle.read()
        for secret in (SECRET_A, SECRET_B, SECRET_C):
            self.assertNotIn(secret.encode(), content)

    def test_rotation_errors_do_not_leak_material(self):
        store = self._store()
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
        try:
            store.rotate_anchor_key(SECRET_B, SECRET_B)
        except ValueError as exc:
            self.assertNotIn(SECRET_B, str(exc))
        else:
            self.fail("expected ValueError")

    # -- scope/access semantics stay intact --------------------------------

    def test_verify_scope_validation_unchanged(self):
        store, accepted = self._anchored_request()
        store.rotate_anchor_key(SECRET_A, SECRET_B)
        with self.assertRaises(ValueError):
            store.verify_chain("", accepted["request_id"])
        with self.assertRaises(RequestNotFound):
            store.verify_chain("tenant-a", "does-not-exist")
        with self.assertRaises(RequestNotFound):
            store.verify_chain("tenant-b", accepted["request_id"])

    # -- in-memory store ----------------------------------------------------

    def test_in_memory_rotation_lifecycle(self):
        store = RequestStore(":memory:", anchor_secret=SECRET_A)
        accepted = store.submit("tenant-a", "s", ["email"], "k1")
        rotation = store.rotate_anchor_key(SECRET_A, SECRET_B)
        self.assertEqual(rotation["generation"], 2)
        store.transition("tenant-a", accepted["request_id"], "processing")
        store.transition("tenant-a", accepted["request_id"], "completed")
        self.assertTrue(store.verify_chain())
        self.assertEqual(store.diagnose_chain(), [])
        # The genesis anchor predates the rotation and stays generation 1.
        # A fresh in-memory rebuild cannot share the file; this only
        # asserts the rotating instance itself verifies end to end.
        self.assertEqual(
            store.rotate_anchor_key(SECRET_A, SECRET_B), rotation
        )


if __name__ == "__main__":
    unittest.main()
