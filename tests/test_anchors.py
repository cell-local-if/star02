"""Tests for the external cross-restart trust anchor and full-chain verification."""

import hashlib
import hmac
import os
import re
import sqlite3
import struct
import tempfile
import unittest

from forgetting_evidence.requests import RequestNotFound, RequestStore

SECRET = "anchor-secret-one"
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _chain_hash(tenant_id, request_id, seq, status, occurred_at, predecessor):
    """Independent reimplementation of the database link hash."""
    digest = hashlib.sha256()
    for field in (tenant_id, request_id, str(seq), status, occurred_at, predecessor):
        raw = field.encode("utf-8")
        digest.update(struct.pack(">Q", len(raw)))
        digest.update(raw)
    return digest.hexdigest()


def _anchor_mac(secret, tenant_id, request_id, seq, status, occurred_at, event_hash, predecessor):
    mac = hmac.new(secret.encode("utf-8"), digestmod=hashlib.sha256)
    for field in (tenant_id, request_id, str(seq), status, occurred_at, event_hash, predecessor):
        raw = field.encode("utf-8")
        mac.update(struct.pack(">Q", len(raw)))
        mac.update(raw)
    return mac.hexdigest()


def _global_mac(secret, predecessor, anchor_hmac, tenant_id, request_id, seq):
    mac = hmac.new(secret.encode("utf-8"), digestmod=hashlib.sha256)
    for field in (predecessor, anchor_hmac, tenant_id, request_id, str(seq)):
        raw = field.encode("utf-8")
        mac.update(struct.pack(">Q", len(raw)))
        mac.update(raw)
    return mac.hexdigest()


GENESIS = hashlib.sha256(b"").hexdigest()
ANCHOR_GENESIS = hashlib.sha256(b"forgetting-evidence:anchor:request-genesis").hexdigest()
GLOBAL_GENESIS = hashlib.sha256(b"forgetting-evidence:anchor:global-genesis").hexdigest()


class AnchorTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "anchored.db")

    def tearDown(self):
        self._tmp.cleanup()

    def _store(self, secret=SECRET):
        return RequestStore(self.db_path, anchor_secret=secret)

    def _lifecycle(self, statuses=("processing", "completed"), secret=SECRET, tenant="tenant-a"):
        store = self._store(secret)
        receipt = store.submit(tenant, "subject-1", ["email"], "idem-1")
        for status in statuses:
            store.transition(tenant, receipt["request_id"], status)
        return store, receipt

    def _raw(self):
        return sqlite3.connect(self.db_path)

    def _snapshot(self):
        with open(self.db_path, "rb") as handle:
            return handle.read()

    # -- clean verification --------------------------------------------

    def test_anchored_submit_only_verifies(self):
        store, receipt = self._lifecycle(statuses=())
        self.assertTrue(store.verify_chain())
        self.assertTrue(store.verify_chain("tenant-a", receipt["request_id"]))
        self.assertEqual(store.diagnose_chain(), [])
        self.assertEqual(store.diagnose_chain("tenant-a", receipt["request_id"]), [])

    def test_every_lifecycle_verifies(self):
        for index, path in enumerate(
            (("processing", "completed"), ("failed",), ("processing", "failed"))
        ):
            # A different secret per iteration needs a fresh file: an
            # already anchored database rejects a foreign-secret writer.
            per_path = os.path.join(self._tmp.name, f"life-{index}.db")
            store = RequestStore(per_path, anchor_secret=f"secret-{index}")
            receipt = store.submit("tenant-a", "subject-1", ["email"], "idem-1")
            for status in path:
                store.transition("tenant-a", receipt["request_id"], status)
            self.assertTrue(store.verify_chain(), path)

    def test_verification_survives_restart(self):
        store, receipt = self._lifecycle()
        rebuilt = self._store()
        self.assertTrue(rebuilt.verify_chain())
        self.assertTrue(rebuilt.verify_chain("tenant-a", receipt["request_id"]))
        self.assertEqual(rebuilt.diagnose_chain(), [])

    def test_verify_and_diagnose_never_write(self):
        store, _receipt = self._lifecycle()
        before = self._snapshot()
        for _ in range(5):
            self.assertTrue(store.verify_chain())
            self.assertEqual(store.diagnose_chain(), [])
        rebuilt = self._store()
        for _ in range(5):
            self.assertTrue(rebuilt.verify_chain())
        self.assertEqual(before, self._snapshot())

    def test_repeated_queries_do_not_change_records(self):
        store, receipt = self._lifecycle()
        store.audit("tenant-a", receipt["request_id"])
        store.evidence("tenant-a", receipt["request_id"])
        store.verify_evidence("tenant-a", receipt["request_id"])
        store.verify_chain()
        store.diagnose_chain()
        before = self._snapshot()
        store.audit("tenant-a", receipt["request_id"])
        store.evidence("tenant-a", receipt["request_id"])
        store.verify_evidence("tenant-a", receipt["request_id"])
        store.verify_chain()
        store.diagnose_chain()
        self.assertEqual(before, self._snapshot())

    def test_in_memory_anchored_chain(self):
        store = RequestStore(":memory:", anchor_secret=SECRET)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "k1")
        store.transition("tenant-a", receipt["request_id"], "processing")
        self.assertTrue(store.verify_chain())
        self.assertEqual(store.diagnose_chain(), [])

    def test_existing_per_request_chain_still_verifies(self):
        store, receipt = self._lifecycle()
        self.assertTrue(store.verify_evidence("tenant-a", receipt["request_id"]))

    # -- anchor material never at rest ---------------------------------

    def test_secret_material_never_stored(self):
        store, _receipt = self._lifecycle()
        blob = b""
        with self._raw() as conn:
            tables = [
                row[0]
                for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
            ]
            for table in tables:
                for row in conn.execute(f"SELECT * FROM {table}"):
                    for value in row:
                        if isinstance(value, str):
                            blob += value.encode("utf-8", "replace")
                        elif isinstance(value, bytes):
                            blob += value
        self.assertNotIn(SECRET.encode("utf-8"), blob)

    def test_anchor_rows_match_events_one_to_one(self):
        store, _receipt = self._lifecycle(("processing", "failed"))
        with self._raw() as conn:
            events = conn.execute("SELECT count(*) FROM status_events").fetchone()[0]
            anchors = conn.execute("SELECT count(*) FROM audit_anchors").fetchone()[0]
            meta = conn.execute("SELECT count(*) FROM audit_anchor_meta").fetchone()[0]
            seqs = [
                row[0]
                for row in conn.execute("SELECT commit_seq FROM audit_anchors ORDER BY commit_seq")
            ]
        self.assertEqual(events, anchors)
        self.assertEqual(meta, 1)
        self.assertEqual(seqs, list(range(1, events + 1)))
        self.assertTrue(store.verify_chain())

    # -- multi-tenant global seal --------------------------------------

    def test_global_head_seals_multiple_tenants_and_requests(self):
        store = self._store()
        a1 = store.submit("tenant-a", "s", ["email"], "ka1")
        b1 = store.submit("tenant-b", "s", ["email"], "kb1")
        a2 = store.submit("tenant-a", "s", ["phone"], "ka2")
        store.transition("tenant-a", a1["request_id"], "processing")
        store.transition("tenant-b", b1["request_id"], "failed")
        store.transition("tenant-a", a2["request_id"], "processing")
        self.assertTrue(store.verify_chain())
        self.assertTrue(store.verify_chain("tenant-a", a1["request_id"]))
        self.assertTrue(store.verify_chain("tenant-b", b1["request_id"]))

    # -- tampering: database-only forgery never validates --------------

    def test_modify_event_breaks_full_chain(self):
        store, receipt = self._lifecycle()
        with self._raw() as conn:
            conn.execute(
                "UPDATE status_events SET status = 'failed' WHERE request_id = ? AND seq = 1",
                (receipt["request_id"],),
            )
        self.assertFalse(store.verify_chain("tenant-a", receipt["request_id"]))
        self.assertFalse(store.verify_chain())
        self.assertIn("anchor_auth_failed", store.diagnose_chain())

    def test_delete_event_breaks_full_chain(self):
        store, receipt = self._lifecycle()
        with self._raw() as conn:
            conn.execute(
                "DELETE FROM status_events WHERE request_id = ? AND seq = 1",
                (receipt["request_id"],),
            )
        self.assertFalse(store.verify_chain())
        self.assertTrue(
            {"anchor_orphan", "anchor_state_split"} & set(store.diagnose_chain())
        )

    def test_insert_event_breaks_full_chain(self):
        store, receipt = self._lifecycle(("failed",))
        with self._raw() as conn:
            conn.execute(
                "INSERT INTO status_events "
                "(tenant_id, request_id, seq, status, occurred_at, chain_hash) "
                "VALUES ('tenant-a', ?, 2, 'processing', '2026-01-01T00:00:00Z', ?)",
                (receipt["request_id"], "0" * 64),
            )
        self.assertFalse(store.verify_chain())

    def test_reorder_events_breaks_full_chain(self):
        store, receipt = self._lifecycle()
        with self._raw() as conn:
            conn.execute(
                "UPDATE status_events SET seq = 5 WHERE request_id = ? AND seq = 1",
                (receipt["request_id"],),
            )
        self.assertFalse(store.verify_chain())

    def test_cross_request_substitution_breaks_full_chain(self):
        store = self._store()
        one = store.submit("tenant-a", "s1", ["email"], "k1")
        two = store.submit("tenant-a", "s2", ["email"], "k2")
        store.transition("tenant-a", one["request_id"], "processing")
        store.transition("tenant-a", two["request_id"], "processing")
        with self._raw() as conn:
            forged = conn.execute(
                "SELECT status, occurred_at, chain_hash FROM status_events "
                "WHERE request_id = ? AND seq = 0",
                (two["request_id"],),
            ).fetchone()
            conn.execute(
                "UPDATE status_events SET status = ?, occurred_at = ?, chain_hash = ? "
                "WHERE request_id = ? AND seq = 0",
                (*forged, one["request_id"]),
            )
        self.assertFalse(store.verify_chain())
        self.assertTrue(
            {"anchor_auth_failed", "request_association_mismatch"}
            & set(store.diagnose_chain())
        )

    def test_cross_tenant_substitution_breaks_full_chain(self):
        store = self._store()
        a = store.submit("tenant-a", "s", ["email"], "k1")
        b = store.submit("tenant-b", "s", ["email"], "k2")
        store.transition("tenant-a", a["request_id"], "processing")
        store.transition("tenant-b", b["request_id"], "processing")
        with self._raw() as conn:
            forged = conn.execute(
                "SELECT status, occurred_at, chain_hash FROM status_events "
                "WHERE tenant_id = 'tenant-b' AND request_id = ? AND seq = 0",
                (b["request_id"],),
            ).fetchone()
            conn.execute(
                "UPDATE status_events SET status = ?, occurred_at = ?, chain_hash = ? "
                "WHERE tenant_id = 'tenant-a' AND request_id = ? AND seq = 0",
                (*forged, a["request_id"]),
            )
        self.assertFalse(store.verify_chain())

    def test_anchor_row_tamper_breaks_chain(self):
        store, receipt = self._lifecycle()
        with self._raw() as conn:
            row = conn.execute(
                "SELECT anchor_hmac FROM audit_anchors WHERE request_id = ? AND seq = 0",
                (receipt["request_id"],),
            ).fetchone()
            flipped = ("0" if row[0][0] != "0" else "1") + row[0][1:]
            conn.execute(
                "UPDATE audit_anchors SET anchor_hmac = ? WHERE request_id = ? AND seq = 0",
                (flipped, receipt["request_id"]),
            )
        self.assertFalse(store.verify_chain())
        self.assertIn("anchor_auth_failed", store.diagnose_chain())

    def test_anchor_reorder_by_commit_seq_breaks_global_head(self):
        store, _receipt = self._lifecycle()
        with self._raw() as conn:
            conn.execute("UPDATE audit_anchors SET commit_seq = commit_seq + 100")
        self.assertFalse(store.verify_chain())
        self.assertIn("anchor_sequence_gap", store.diagnose_chain())

    def test_global_head_tamper_breaks_chain(self):
        store, _receipt = self._lifecycle()
        with self._raw() as conn:
            conn.execute("UPDATE audit_anchor_meta SET head_hmac = ?", ("1" * 64,))
        self.assertFalse(store.verify_chain())
        self.assertIn("anchor_head_mismatch", store.diagnose_chain())

    def test_malformed_anchor_value_fails(self):
        store, _receipt = self._lifecycle()
        with self._raw() as conn:
            conn.execute(
                "UPDATE audit_anchors SET anchor_hmac = 'not-a-digest' WHERE seq = 0"
            )
        self.assertFalse(store.verify_chain())

    def test_missing_global_head_fails(self):
        store, _receipt = self._lifecycle()
        with self._raw() as conn:
            conn.execute("DELETE FROM audit_anchor_meta")
        self.assertFalse(store.verify_chain())
        self.assertIn("anchor_meta_corrupt", store.diagnose_chain())

    def test_attacker_full_recompute_without_secret_still_fails(self):
        """The decisive attack: rewrite every DB-derivable value, anchors
        and global head included, using only public content. Without the
        external secret the forged chain must never validate."""
        store, receipt = self._lifecycle(("processing", "completed"))
        rid = receipt["request_id"]
        forged_secret = "attacker-guess"
        with self._raw() as conn:
            conn.execute(
                "UPDATE status_events SET status = 'failed' WHERE request_id = ? AND seq = 1",
                (rid,),
            )
            events = conn.execute(
                "SELECT tenant_id, request_id, seq, status, occurred_at "
                "FROM status_events ORDER BY tenant_id, request_id, seq"
            ).fetchall()
            pred = GENESIS
            for tenant, request, seq, status, ts in events:
                link = _chain_hash(tenant, request, seq, status, ts, pred)
                conn.execute(
                    "UPDATE status_events SET chain_hash = ? "
                    "WHERE tenant_id = ? AND request_id = ? AND seq = ?",
                    (link, tenant, request, seq),
                )
                pred = link
            conn.execute(
                "UPDATE requests SET status = 'failed', chain_hash = ? WHERE request_id = ?",
                (pred, rid),
            )
            ap = ANCHOR_GENESIS
            gp = GLOBAL_GENESIS
            anchors = conn.execute(
                "SELECT commit_seq, tenant_id, request_id, seq "
                "FROM audit_anchors ORDER BY commit_seq"
            ).fetchall()
            for _cs, tenant, request, seq in anchors:
                status, ts, link = conn.execute(
                    "SELECT status, occurred_at, chain_hash FROM status_events "
                    "WHERE tenant_id = ? AND request_id = ? AND seq = ?",
                    (tenant, request, seq),
                ).fetchone()
                ah = _anchor_mac(forged_secret, tenant, request, seq, status, ts, link, ap)
                conn.execute(
                    "UPDATE audit_anchors SET event_hash = ?, anchor_hmac = ? "
                    "WHERE tenant_id = ? AND request_id = ? AND seq = ?",
                    (link, ah, tenant, request, seq),
                )
                gp = _global_mac(forged_secret, gp, ah, tenant, request, seq)
                ap = ah
            conn.execute("UPDATE audit_anchor_meta SET head_hmac = ?", (gp,))

        rebuilt = self._store()
        self.assertFalse(rebuilt.verify_chain())
        reasons = set(rebuilt.diagnose_chain())
        self.assertIn("anchor_auth_failed", reasons)
        self.assertIn("anchor_head_mismatch", reasons)

    # -- legacy / corrupt / interrupted --------------------------------

    def test_legacy_unanchored_database_verifies_false(self):
        legacy_path = os.path.join(self._tmp.name, "legacy.db")
        old = RequestStore(legacy_path)
        receipt = old.submit("tenant-a", "subject-1", ["email"], "k1")
        old.transition("tenant-a", receipt["request_id"], "processing")
        anchored = RequestStore(legacy_path, anchor_secret=SECRET)
        self.assertFalse(anchored.verify_chain())
        self.assertEqual(anchored.diagnose_chain(), ["unanchored_database"])
        self.assertFalse(RequestStore(legacy_path).verify_chain())

    def test_no_secret_store_reports_anchored_database_unverifiable(self):
        store, _receipt = self._lifecycle()
        blind = self._store(secret=None)
        self.assertFalse(blind.verify_chain())
        self.assertEqual(blind.diagnose_chain(), ["anchor_secret_missing"])

    def test_wrong_secret_verifies_false(self):
        store, _receipt = self._lifecycle()
        wrong = self._store(secret="a-different-secret")
        self.assertFalse(wrong.verify_chain())
        self.assertIn("anchor_auth_failed", wrong.diagnose_chain())

    def test_interrupted_commit_leaves_unverifiable_state(self):
        store, receipt = self._lifecycle()
        # Crash after the event landed but before its anchor: an
        # anchor-less event with a valid-looking database link.
        with self._raw() as conn:
            last = conn.execute(
                "SELECT seq, occurred_at, chain_hash FROM status_events "
                "WHERE request_id = ? ORDER BY seq DESC LIMIT 1",
                (receipt["request_id"],),
            ).fetchone()
            link = _chain_hash(
                "tenant-a", receipt["request_id"], last[0] + 1, "failed", last[1], last[2]
            )
            conn.execute(
                "INSERT INTO status_events "
                "(tenant_id, request_id, seq, status, occurred_at, chain_hash) "
                "VALUES ('tenant-a', ?, ?, 'failed', ?, ?)",
                (receipt["request_id"], last[0] + 1, last[1], link),
            )
        self.assertFalse(store.verify_chain())
        self.assertIn("event_unanchored", store.diagnose_chain())

    def test_head_and_event_count_split_fails(self):
        store, _receipt = self._lifecycle()
        with self._raw() as conn:
            conn.execute("DELETE FROM audit_anchors WHERE seq = 0")
        self.assertFalse(store.verify_chain())

    # -- diagnosis never repairs ---------------------------------------

    def test_diagnosis_does_not_modify_database(self):
        store, receipt = self._lifecycle()
        with self._raw() as conn:
            conn.execute(
                "UPDATE status_events SET status = 'failed' WHERE request_id = ? AND seq = 1",
                (receipt["request_id"],),
            )
        before = self._snapshot()
        first = store.diagnose_chain()
        second = store.diagnose_chain()
        self.assertEqual(first, second)
        self.assertTrue(first)
        self.assertEqual(before, self._snapshot())
        self.assertFalse(store.verify_chain())

    # -- write gating ---------------------------------------------------

    def test_wrong_secret_store_cannot_append(self):
        store, receipt = self._lifecycle(statuses=())
        wrong = self._store(secret="a-different-secret")
        with self.assertRaises(OSError) as ctx:
            wrong.transition("tenant-a", receipt["request_id"], "processing")
        self.assertEqual(str(ctx.exception), "request store is unavailable")
        good = self._store()
        self.assertTrue(good.verify_chain())
        self.assertEqual(
            good.get_status("tenant-a", receipt["request_id"])["status"], "accepted"
        )

    def test_no_secret_store_cannot_extend_anchored_database(self):
        store, receipt = self._lifecycle(statuses=())
        blind = self._store(secret=None)
        with self.assertRaises(OSError):
            blind.transition("tenant-a", receipt["request_id"], "processing")
        with self.assertRaises(OSError):
            blind.submit("tenant-a", "other", ["email"], "k-other")
        self.assertTrue(self._store().verify_chain())

    def test_secret_store_cannot_anchor_legacy_database(self):
        legacy_path = os.path.join(self._tmp.name, "legacy2.db")
        old = RequestStore(legacy_path)
        receipt = old.submit("tenant-a", "subject-1", ["email"], "k1")
        anchored = RequestStore(legacy_path, anchor_secret=SECRET)
        with self.assertRaises(OSError):
            anchored.transition("tenant-a", receipt["request_id"], "processing")
        # The historical store keeps working as before.
        RequestStore(legacy_path).transition("tenant-a", receipt["request_id"], "processing")

    def test_idempotent_replay_without_secret_unchanged(self):
        store = self._store()
        first = store.submit("tenant-a", "subject-1", ["email"], "same-key")
        replay = self._store(secret=None).submit(
            "tenant-a", "subject-1", ["email"], "same-key"
        )
        self.assertEqual(first, replay)
        self.assertTrue(store.verify_chain())

    def test_failed_anchor_commit_rolls_back_everything(self):
        store, receipt = self._lifecycle(statuses=())
        with self._raw() as conn:
            conn.execute("UPDATE audit_anchor_meta SET head_hmac = ?", ("f" * 64,))
        with self.assertRaises(OSError):
            self._store().transition("tenant-a", receipt["request_id"], "processing")
        with self._raw() as conn:
            status = conn.execute(
                "SELECT status FROM requests WHERE request_id = ?",
                (receipt["request_id"],),
            ).fetchone()[0]
            events = conn.execute(
                "SELECT count(*) FROM status_events WHERE request_id = ?",
                (receipt["request_id"],),
            ).fetchone()[0]
        self.assertEqual(status, "accepted")
        self.assertEqual(events, 1)

    # -- execution paths are anchored -----------------------------------

    def test_claim_and_finish_are_anchored(self):
        store = self._store()
        receipt = store.submit("tenant-a", "subject-1", ["email"], "k1")
        claim = store.claim_next("tenant-a", "worker-1", 300)
        store.finish_claim("tenant-a", receipt["request_id"], claim["claim_token"], "completed")
        self.assertTrue(store.verify_chain())
        rebuilt = self._store()
        self.assertTrue(rebuilt.verify_chain())
        self.assertEqual(
            rebuilt.get_status("tenant-a", receipt["request_id"])["status"], "completed"
        )

    def test_reconcile_compensation_is_anchored(self):
        store = self._store()
        receipt = store.submit("tenant-a", "subject-1", ["email"], "k1")
        store.claim_next("tenant-a", "worker-1", 1)
        import time

        time.sleep(1.1)
        store.reconcile_execution("tenant-a", receipt["request_id"])
        self.assertEqual(
            store.get_status("tenant-a", receipt["request_id"])["status"], "failed"
        )
        self.assertTrue(store.verify_chain())
        self.assertTrue(self._store().verify_chain())

    def test_batch_reconcile_is_anchored(self):
        store = self._store()
        receipt = store.submit("tenant-a", "subject-1", ["email"], "k1")
        store.claim_next("tenant-a", "worker-1", 1)
        # Wait out the 1-second lease so the batch converges the request.
        import time

        time.sleep(1.1)
        result = store.reconcile_batch("tenant-a")
        self.assertTrue(store.verify_chain())
        self.assertTrue(self._store().verify_chain())
        self.assertEqual(result["items"][0]["status"], "failed")

    # -- argument / access semantics ------------------------------------

    def test_invalid_arguments_raise_value_error(self):
        store, receipt = self._lifecycle()
        for bad in ("", None, 7, b"tenant", ["tenant"], 3.14):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    store.verify_chain(bad, receipt["request_id"])
                with self.assertRaises(ValueError):
                    store.diagnose_chain(bad, receipt["request_id"])
                with self.assertRaises(RequestNotFound):
                    store.verify_chain("tenant-a", bad)
                with self.assertRaises(RequestNotFound):
                    store.diagnose_chain("tenant-a", bad)
        # A present tenant with a missing request id is indistinguishable
        # from a bad id (RequestNotFound), matching audit()/evidence(); a
        # missing tenant is caller error (ValueError).
        with self.assertRaises(RequestNotFound):
            store.verify_chain("tenant-a")
        with self.assertRaises(ValueError):
            store.verify_chain(None, receipt["request_id"])

    def test_unknown_and_cross_tenant_raise_not_found(self):
        store, receipt = self._lifecycle()
        with self.assertRaises(RequestNotFound):
            store.verify_chain("tenant-a", "does-not-exist")
        with self.assertRaises(RequestNotFound):
            store.verify_chain("tenant-b", receipt["request_id"])
        with self.assertRaises(RequestNotFound):
            store.diagnose_chain("tenant-b", receipt["request_id"])

    def test_invalid_secret_constructor_raises_value_error(self):
        for bad in ("", 0, b"secret", ["secret"]):
            with self.assertRaises(ValueError):
                RequestStore(self.db_path, anchor_secret=bad)

    def test_validation_errors_do_not_change_evidence(self):
        store, receipt = self._lifecycle()
        before = self._snapshot()
        with self.assertRaises(ValueError):
            store.verify_chain("", receipt["request_id"])
        with self.assertRaises(RequestNotFound):
            store.verify_chain("tenant-a", None)
        self.assertEqual(before, self._snapshot())
        self.assertTrue(store.verify_chain())

    def test_fixed_storage_error_text(self):
        store, receipt = self._lifecycle(statuses=())
        with self._raw() as conn:
            conn.execute("UPDATE audit_anchor_meta SET head_hmac = ?", ("9" * 64,))
        try:
            self._store().transition("tenant-a", receipt["request_id"], "processing")
        except OSError as exc:
            self.assertEqual(str(exc), "request store is unavailable")
        else:
            self.fail("expected OSError")

    def test_alias_methods(self):
        store, receipt = self._lifecycle()
        self.assertEqual(store.verify_audit_chain(), store.verify_chain())
        self.assertEqual(
            store.diagnose_audit_chain("tenant-a", receipt["request_id"]),
            store.diagnose_chain("tenant-a", receipt["request_id"]),
        )


if __name__ == "__main__":
    unittest.main()
