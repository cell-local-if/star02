"""Tests for the external sidecar anchor and recoverable commits."""

import json
import os
import secrets
import sqlite3
import tempfile
import unittest
from unittest import mock

from forgetting_evidence.requests import (
    AnchorUnavailable,
    RequestNotFound,
    RequestStore,
)


class AnchorLifecycleTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "evidence.db")

    def tearDown(self):
        self._tmp.cleanup()

    def _sidecar(self, store):
        return store._sidecar  # noqa: SLF001

    def _paths(self):
        directory = os.path.dirname(os.path.abspath(self.db_path))
        base = os.path.basename(self.db_path)
        return {
            "anchor": os.path.join(directory, "." + base + ".anchor.json"),
            "pending": os.path.join(
                directory, "." + base + ".anchor.json.pending"
            ),
            "lock": os.path.join(directory, "." + base + ".anchor.lock"),
        }

    def _anchor_root(self):
        with open(self._paths()["anchor"], "rb") as handle:
            return json.load(handle)["root"]

    # -- happy path -----------------------------------------------------

    def test_sidecar_created_next_to_database_outside_sqlite(self):
        store = RequestStore(self.db_path)
        paths = self._paths()
        self.assertTrue(os.path.exists(paths["anchor"]))
        # The anchor is an ordinary JSON file separate from the database.
        with open(paths["anchor"], "rb") as handle:
            payload = json.loads(handle.read())
        self.assertEqual(payload["version"], 1)
        self.assertIn("key", payload)
        self.assertIn("hmac", payload)
        self.assertIn("root", payload)
        self.assertEqual(len(payload["db_identity"]), 4)
        with sqlite3.connect(self.db_path) as conn:
            # Nothing anchor-related lives inside the SQLite database.
            names = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
        self.assertEqual(names, {"requests", "status_events"})
        self.assertEqual(store.recover(), "valid")

    def test_no_staging_or_temp_files_left_after_commit(self):
        store = RequestStore(self.db_path)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        store.transition("tenant-a", receipt["request_id"], "processing")
        directory = os.path.dirname(os.path.abspath(self.db_path))
        leftovers = [
            name
            for name in os.listdir(directory)
            if name.startswith(".anchor-tmp-") or name.endswith(".pending")
        ]
        self.assertEqual(leftovers, [])

    def test_anchor_renewed_on_each_submit_and_actual_transition(self):
        store = RequestStore(self.db_path)
        paths = self._paths()
        roots = []
        roots.append(self._anchor_root())
        receipt = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        roots.append(self._anchor_root())
        store.transition("tenant-a", receipt["request_id"], "processing")
        roots.append(self._anchor_root())
        # Idempotent replay must not renew the anchor.
        store.transition("tenant-a", receipt["request_id"], "processing")
        roots.append(self._anchor_root())
        self.assertEqual(len(set(roots)), 3)
        self.assertEqual(store.recover(), "valid")
        self.assertTrue(store.verify_evidence("tenant-a", receipt["request_id"]))

    def test_rebuild_without_key_still_verifies(self):
        store = RequestStore(self.db_path)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        store.transition("tenant-a", receipt["request_id"], "processing")
        store.transition("tenant-a", receipt["request_id"], "completed")
        rebuilt = RequestStore(self.db_path)
        self.assertEqual(rebuilt.recover(), "valid")
        self.assertTrue(rebuilt.verify_evidence("tenant-a", receipt["request_id"]))
        ev = rebuilt.evidence("tenant-a", receipt["request_id"])
        self.assertEqual(ev["status"], "completed")

    def test_custom_anchor_path(self):
        anchor = os.path.join(self._tmp.name, "elsewhere", "audit.anchor")
        store = RequestStore(self.db_path, anchor_path=anchor)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        self.assertTrue(os.path.exists(anchor))
        rebuilt = RequestStore(self.db_path, anchor_path=anchor)
        self.assertTrue(rebuilt.verify_evidence("tenant-a", receipt["request_id"]))

    def test_anchor_path_equal_to_database_rejected(self):
        with self.assertRaises(ValueError):
            RequestStore(self.db_path, anchor_path=self.db_path)

    def test_explicit_key_never_persisted_and_required_to_rebuild(self):
        key = secrets.token_bytes(32)
        store = RequestStore(self.db_path, integrity_key=key)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        paths = self._paths()
        with open(paths["anchor"], "rb") as handle:
            raw = handle.read()
        self.assertNotIn(key.hex().encode(), raw)
        payload = json.loads(raw)
        self.assertNotIn("key", payload)
        # Rebuild with the same key verifies...
        rebuilt = RequestStore(self.db_path, integrity_key=key)
        self.assertEqual(rebuilt.recover(), "valid")
        self.assertTrue(rebuilt.verify_evidence("tenant-a", receipt["request_id"]))
        # ...a wrong key does not...
        wrong = RequestStore(self.db_path, integrity_key=secrets.token_bytes(32))
        self.assertIn(wrong.recover(), ("invalid", "incomplete"))
        self.assertFalse(wrong.verify_evidence("tenant-a", receipt["request_id"]))
        with self.assertRaises(AnchorUnavailable):
            wrong.submit("tenant-a", "subject-2", ["email"], "key-2")
        # ...and rebuilding with no key cannot recover the secret.
        keyless = RequestStore(self.db_path)
        self.assertIn(keyless.recover(), ("invalid", "incomplete"))
        self.assertFalse(
            keyless.verify_evidence("tenant-a", receipt["request_id"])
        )

    def test_explicit_key_accepted_as_hex_string(self):
        key = secrets.token_bytes(32).hex()
        store = RequestStore(self.db_path, integrity_key=key)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        rebuilt = RequestStore(self.db_path, integrity_key=key)
        self.assertTrue(rebuilt.verify_evidence("tenant-a", receipt["request_id"]))

    def test_bad_key_shape_rejected(self):
        for bad in (b"short", "not-hex", "00" * 16, 123, b""):
            with self.assertRaises(ValueError):
                RequestStore(self.db_path, integrity_key=bad)

    def test_memory_store_reports_valid(self):
        store = RequestStore(":memory:")
        self.assertEqual(store.recover(), "valid")
        receipt = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        self.assertTrue(store.verify_evidence("tenant-a", receipt["request_id"]))
        with self.assertRaises(ValueError):
            RequestStore(":memory:", anchor_path=self._paths()["anchor"])

    # -- invalid / incomplete states ------------------------------------

    def _lifecycle(self):
        store = RequestStore(self.db_path)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        store.transition("tenant-a", receipt["request_id"], "processing")
        return store, receipt

    def test_missing_anchor_is_incomplete_and_blocks_everything(self):
        store, receipt = self._lifecycle()
        os.unlink(self._paths()["anchor"])
        rebuilt = RequestStore(self.db_path)
        self.assertEqual(rebuilt.recover(), "incomplete")
        self.assertFalse(rebuilt.verify_evidence("tenant-a", receipt["request_id"]))
        with self.assertRaises(AnchorUnavailable):
            rebuilt.submit("tenant-a", "subject-2", ["email"], "key-2")
        with self.assertRaises(AnchorUnavailable):
            rebuilt.transition("tenant-a", receipt["request_id"], "completed")
        # Read-only operations keep working with their baseline semantics.
        self.assertEqual(
            rebuilt.get("tenant-a", receipt["request_id"])["status"], "processing"
        )

    def test_corrupt_anchor_is_incomplete(self):
        _store, receipt = self._lifecycle()
        with open(self._paths()["anchor"], "wb") as handle:
            handle.write(b"{not json")
        rebuilt = RequestStore(self.db_path)
        self.assertEqual(rebuilt.recover(), "incomplete")
        self.assertFalse(rebuilt.verify_evidence("tenant-a", receipt["request_id"]))
        with self.assertRaises(AnchorUnavailable):
            rebuilt.submit("tenant-a", "subject-2", ["email"], "key-2")

    def test_tampered_anchor_hmac_is_incomplete(self):
        _store, receipt = self._lifecycle()
        path = self._paths()["anchor"]
        with open(path) as handle:
            payload = json.load(handle)
        payload["hmac"] = "0" * 64
        with open(path, "w") as handle:
            json.dump(payload, handle)
        rebuilt = RequestStore(self.db_path)
        self.assertEqual(rebuilt.recover(), "incomplete")
        self.assertFalse(rebuilt.verify_evidence("tenant-a", receipt["request_id"]))

    def test_pending_file_means_incomplete(self):
        _store, receipt = self._lifecycle()
        paths = self._paths()
        # Simulate a crash after staging but before promotion: the
        # pending file holds the new seal while SQLite already advanced.
        with open(paths["anchor"]) as handle:
            payload = json.load(handle)
        with open(paths["pending"], "w") as handle:
            json.dump(payload, handle)
        rebuilt = RequestStore(self.db_path)
        self.assertEqual(rebuilt.recover(), "incomplete")
        self.assertFalse(rebuilt.verify_evidence("tenant-a", receipt["request_id"]))
        with self.assertRaises(AnchorUnavailable):
            rebuilt.submit("tenant-a", "subject-2", ["email"], "key-2")

    def test_database_row_tamper_is_invalid(self):
        _store, receipt = self._lifecycle()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE status_events SET status = 'failed' "
                "WHERE request_id = ? AND seq = 1",
                (receipt["request_id"],),
            )
        rebuilt = RequestStore(self.db_path)
        self.assertEqual(rebuilt.recover(), "invalid")
        self.assertFalse(rebuilt.verify_evidence("tenant-a", receipt["request_id"]))
        with self.assertRaises(AnchorUnavailable):
            rebuilt.transition("tenant-a", receipt["request_id"], "completed")

    def test_unrelated_database_substituted_is_invalid(self):
        store, receipt = self._lifecycle()
        other_db = os.path.join(self._tmp.name, "other.db")
        other = RequestStore(other_db)
        other_receipt = other.submit(
            "tenant-a", "subject-1", ["email"], "key-1"
        )
        # Replace the database bytes with a different database while
        # keeping the original sidecar in place.
        with open(other_db, "rb") as src, open(self.db_path, "wb") as dst:
            dst.write(src.read())
        rebuilt = RequestStore(self.db_path)
        self.assertEqual(rebuilt.recover(), "invalid")
        # The original request is gone from the substituted file...
        with self.assertRaises(RequestNotFound):
            rebuilt.verify_evidence("tenant-a", receipt["request_id"])
        # ...and the request that came in with the substitute still
        # cannot verify because the sidecar seals a different file.
        self.assertFalse(
            rebuilt.verify_evidence("tenant-a", other_receipt["request_id"])
        )

    def test_whole_database_recomputation_cannot_forge_validity(self):
        # Attacker rewrites rows AND recomputes every per-request chain
        # hash consistently. The external root still binds the physical
        # file revision and must reject it.
        _store, receipt = self._lifecycle()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE status_events SET status = 'failed' "
                "WHERE request_id = ? AND seq = 1",
                (receipt["request_id"],),
            )
            conn.execute(
                "UPDATE requests SET status = 'failed' WHERE request_id = ?",
                (receipt["request_id"],),
            )
            # Recompute the per-request chain so it is internally sound.
            import hashlib
            import struct

            genesis = hashlib.sha256(b"").hexdigest()

            def chain(tenant, rid, seq, status, ts, predecessor):
                digest = hashlib.sha256()
                for field in (tenant, rid, str(seq), status, ts, predecessor):
                    raw = field.encode()
                    digest.update(struct.pack(">Q", len(raw)))
                    digest.update(raw)
                return digest.hexdigest()

            rows = conn.execute(
                "SELECT tenant_id, request_id, seq, status, occurred_at "
                "FROM status_events WHERE request_id = ? ORDER BY seq",
                (receipt["request_id"],),
            ).fetchall()
            pred = genesis
            for tenant, rid, seq, status, ts in rows:
                link = chain(tenant, rid, seq, status, ts, pred)
                conn.execute(
                    "UPDATE status_events SET chain_hash = ? "
                    "WHERE request_id = ? AND seq = ?",
                    (link, rid, seq),
                )
                pred = link
            conn.execute(
                "UPDATE requests SET chain_hash = ? WHERE request_id = ?",
                (pred, receipt["request_id"]),
            )
        rebuilt = RequestStore(self.db_path)
        self.assertEqual(rebuilt.recover(), "invalid")
        self.assertFalse(rebuilt.verify_evidence("tenant-a", receipt["request_id"]))

    def test_sidecar_root_tamper_is_invalid(self):
        _store, receipt = self._lifecycle()
        path = self._paths()["anchor"]
        with open(path) as handle:
            payload = json.load(handle)
        payload["root"] = "a" * 64
        # Re-seal with the embedded key so HMAC alone would pass: the
        # stored root still cannot match the database content.
        import hmac as hmac_mod
        import hashlib

        key = bytes.fromhex(payload["key"])
        identity = ",".join(str(x) for x in payload["db_identity"])
        message = (
            b"fe-anchor-v1|" + payload["root"].encode()
            + b"|" + identity.encode()
            + b"|" + payload["nonce"].encode()
        )
        payload["hmac"] = hmac_mod.new(key, message, hashlib.sha256).hexdigest()
        with open(path, "w") as handle:
            json.dump(payload, handle)
        rebuilt = RequestStore(self.db_path)
        self.assertEqual(rebuilt.recover(), "invalid")
        self.assertFalse(rebuilt.verify_evidence("tenant-a", receipt["request_id"]))

    # -- recover() is strictly read-only --------------------------------

    def test_recover_never_repairs_or_backfills(self):
        _store, receipt = self._lifecycle()
        paths = self._paths()

        # Missing anchor: recover must not create one.
        os.unlink(paths["anchor"])
        store = RequestStore(self.db_path)
        for _ in range(3):
            self.assertEqual(store.recover(), "incomplete")
        self.assertFalse(os.path.exists(paths["anchor"]))

        # Damaged anchor: recover must not rewrite it.
        with open(paths["anchor"], "wb") as handle:
            handle.write(b"broken")
        with open(paths["anchor"], "rb") as handle:
            before = handle.read()
        self.assertEqual(store.recover(), "incomplete")
        with open(paths["anchor"], "rb") as handle:
            self.assertEqual(handle.read(), before)

    def test_recover_does_not_migrate_or_write(self):
        # A modern, populated database without a sidecar must not gain
        # one merely by calling recover().
        _store, receipt = self._lifecycle()
        os.unlink(self._paths()["anchor"])
        with open(self.db_path, "rb") as handle:
            db_bytes_before = handle.read()
        store = RequestStore(self.db_path)
        self.assertEqual(store.recover(), "incomplete")
        with open(self.db_path, "rb") as handle:
            self.assertEqual(handle.read(), db_bytes_before)
        self.assertFalse(os.path.exists(self._paths()["anchor"]))

    # -- commit failure semantics ----------------------------------------

    def test_failure_after_sqlite_commit_never_reports_success(self):
        store = RequestStore(self.db_path)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        # Crash right after the SQLite commit, before staging: the
        # database advanced but the anchor did not. The call must fail
        # (never report success) and the discrepancy is observable.
        with mock.patch.object(
            type(self._sidecar(store)),
            "stage",
            side_effect=OSError("simulated crash"),
        ):
            with self.assertRaises(RuntimeError):
                store.transition(
                    "tenant-a", receipt["request_id"], "processing"
                )
        self.assertEqual(store.recover(), "invalid")
        self.assertFalse(store.verify_evidence("tenant-a", receipt["request_id"]))
        # The committed SQLite state is visible but explicitly not
        # trustworthy: reads work, evidence does not verify.
        self.assertEqual(
            store.get("tenant-a", receipt["request_id"])["status"], "processing"
        )
        # Further anchored writes are refused until an out-of-band
        # resolution; nothing self-heals.
        with self.assertRaises(AnchorUnavailable):
            store.transition("tenant-a", receipt["request_id"], "failed")

    def test_failure_between_stage_and_promote_is_incomplete(self):
        store = RequestStore(self.db_path)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        sidecar = self._sidecar(store)
        original_promote = sidecar.promote

        def crash_promote(self_inner):
            raise OSError("simulated crash")

        with mock.patch.object(type(sidecar), "promote", crash_promote):
            with self.assertRaises(RuntimeError):
                store.transition(
                    "tenant-a", receipt["request_id"], "processing"
                )
        self.assertTrue(os.path.exists(self._paths()["pending"]))
        self.assertEqual(store.recover(), "incomplete")
        self.assertFalse(store.verify_evidence("tenant-a", receipt["request_id"]))

    def test_failed_write_attempt_leaves_consistent_state(self):
        store = RequestStore(self.db_path)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        # A rejected transition performs no SQLite commit, so the anchor
        # stays exactly valid and no staging file remains.
        with self.assertRaises(Exception):
            store.transition("tenant-a", receipt["request_id"], "completed")
        self.assertEqual(store.recover(), "valid")
        self.assertFalse(os.path.exists(self._paths()["pending"]))

    # -- unanchored modern databases are never trusted -------------------

    def test_modern_database_without_anchor_is_not_silently_trusted(self):
        # Hand-craft a modern-schema database with evidence but no
        # sidecar; opening it must never mint a trust anchor.
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "CREATE TABLE requests ("
                "request_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, "
                "idempotency_key TEXT NOT NULL, subject_id TEXT NOT NULL, "
                "scopes_json TEXT NOT NULL, status TEXT NOT NULL, "
                "created_at TEXT NOT NULL, chain_hash TEXT NOT NULL)"
            )
            conn.execute(
                "CREATE UNIQUE INDEX idx_requests_tenant_idempotency "
                "ON requests(tenant_id, idempotency_key)"
            )
            conn.execute(
                "CREATE TABLE status_events ("
                "tenant_id TEXT NOT NULL, request_id TEXT NOT NULL, "
                "seq INTEGER NOT NULL, status TEXT NOT NULL, "
                "occurred_at TEXT NOT NULL, chain_hash TEXT NOT NULL, "
                "PRIMARY KEY (tenant_id, request_id, seq))"
            )
            conn.execute(
                "INSERT INTO requests VALUES "
                "('rid-1', 'tenant-a', 'k1', 's1', '[\"email\"]', "
                "'accepted', '2026-01-01T00:00:00Z', ?)",
                ("a" * 64,),
            )
            conn.execute(
                "INSERT INTO status_events VALUES "
                "('tenant-a', 'rid-1', 0, 'accepted', "
                "'2026-01-01T00:00:00Z', ?)",
                ("a" * 64,),
            )
        store = RequestStore(self.db_path)
        # No sidecar must have been minted for pre-existing evidence...
        self.assertEqual(store.recover(), "incomplete")
        self.assertFalse(os.path.exists(self._paths()["anchor"]))
        self.assertFalse(store.verify_evidence("tenant-a", "rid-1"))
        with self.assertRaises(AnchorUnavailable):
            store.submit("tenant-a", "subject-2", ["email"], "key-2")
        with self.assertRaises(AnchorUnavailable):
            store.transition("tenant-a", "rid-1", "processing")

    def test_legacy_upgrade_does_not_overwrite_audit_records(self):
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "CREATE TABLE requests ("
                "request_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, "
                "idempotency_key TEXT NOT NULL, subject_id TEXT NOT NULL, "
                "scopes_json TEXT NOT NULL, status TEXT NOT NULL, "
                "created_at TEXT NOT NULL)"
            )
            conn.execute(
                "CREATE UNIQUE INDEX idx_requests_tenant_idempotency "
                "ON requests(tenant_id, idempotency_key)"
            )
            conn.execute(
                "CREATE TABLE status_events ("
                "tenant_id TEXT NOT NULL, request_id TEXT NOT NULL, "
                "seq INTEGER NOT NULL, status TEXT NOT NULL, "
                "occurred_at TEXT NOT NULL, "
                "PRIMARY KEY (tenant_id, request_id, seq))"
            )
            conn.execute(
                "INSERT INTO requests VALUES "
                "('rid-1', 'tenant-a', 'k1', 's1', '[\"email\"]', "
                "'processing', '2026-01-01T00:00:00Z')"
            )
            conn.executemany(
                "INSERT INTO status_events VALUES (?, ?, ?, ?, ?)",
                [
                    ("tenant-a", "rid-1", 0, "accepted", "2026-01-01T00:00:00Z"),
                    ("tenant-a", "rid-1", 1, "processing", "2026-01-01T00:00:01Z"),
                ],
            )
        store = RequestStore(self.db_path)
        self.assertEqual(store.recover(), "valid")
        # Original audit columns survive byte-for-byte.
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT seq, status, occurred_at FROM status_events "
                "WHERE request_id = 'rid-1' ORDER BY seq"
            ).fetchall()
        self.assertEqual(
            rows,
            [
                (0, "accepted", "2026-01-01T00:00:00Z"),
                (1, "processing", "2026-01-01T00:00:01Z"),
            ],
        )
        self.assertTrue(store.verify_evidence("tenant-a", "rid-1"))
        receipt = store.transition("tenant-a", "rid-1", "completed")
        self.assertEqual(receipt["status"], "completed")
        self.assertTrue(store.verify_evidence("tenant-a", "rid-1"))

    # -- cross-request / cross-tenant substitution -----------------------

    def test_cross_request_and_cross_tenant_substitution_rejected(self):
        store = RequestStore(self.db_path)
        a = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        b = store.submit("tenant-a", "subject-2", ["email"], "key-2")
        c = store.submit("tenant-b", "subject-1", ["email"], "key-1")
        store.transition("tenant-a", a["request_id"], "processing")
        store.transition("tenant-a", b["request_id"], "processing")
        store.transition("tenant-b", c["request_id"], "processing")
        with sqlite3.connect(self.db_path) as conn:
            forged = conn.execute(
                "SELECT status, occurred_at, chain_hash FROM status_events "
                "WHERE request_id = ? AND seq = 0",
                (b["request_id"],),
            ).fetchone()
            conn.execute(
                "UPDATE status_events SET status = ?, occurred_at = ?, chain_hash = ? "
                "WHERE request_id = ? AND seq = 0",
                (*forged, a["request_id"]),
            )
        rebuilt = RequestStore(self.db_path)
        self.assertEqual(rebuilt.recover(), "invalid")
        self.assertFalse(
            rebuilt.verify_evidence("tenant-a", a["request_id"])
        )

    # -- error semantics --------------------------------------------------

    def test_unknown_request_still_raises_not_found_even_when_unsealed(self):
        store, _receipt = self._lifecycle()
        os.unlink(self._paths()["anchor"])
        rebuilt = RequestStore(self.db_path)
        with self.assertRaises(RequestNotFound):
            rebuilt.verify_evidence("tenant-a", "does-not-exist")

    def test_row_tamper_invalidates_every_request_not_just_the_target(self):
        store = RequestStore(self.db_path)
        one = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        two = store.submit("tenant-a", "subject-2", ["email"], "key-2")
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "DELETE FROM status_events WHERE request_id = ? AND seq = 0",
                (one["request_id"],),
            )
        rebuilt = RequestStore(self.db_path)
        self.assertEqual(rebuilt.recover(), "invalid")
        self.assertFalse(rebuilt.verify_evidence("tenant-a", one["request_id"]))
        # The untouched request cannot verify either: the global anchor
        # covers the whole database.
        self.assertFalse(rebuilt.verify_evidence("tenant-a", two["request_id"]))

    def test_out_of_band_inserted_row_is_invalid(self):
        _store, receipt = self._lifecycle()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO status_events "
                "(tenant_id, request_id, seq, status, occurred_at, chain_hash) "
                "VALUES ('tenant-a', ?, 9, 'failed', '2026-01-01T00:00:00Z', ?)",
                (receipt["request_id"], "b" * 64),
            )
        rebuilt = RequestStore(self.db_path)
        self.assertEqual(rebuilt.recover(), "invalid")
        self.assertFalse(rebuilt.verify_evidence("tenant-a", receipt["request_id"]))

    def test_vacuum_rewrite_is_invalid(self):
        _store, receipt = self._lifecycle()
        # A whole-file rewrite (which an attacker might use to rebuild a
        # internally-consistent database) changes the file revision and
        # must not match the sealed anchor.
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("VACUUM")
        rebuilt = RequestStore(self.db_path)
        self.assertEqual(rebuilt.recover(), "invalid")
        self.assertFalse(rebuilt.verify_evidence("tenant-a", receipt["request_id"]))

    def test_sidecar_substituted_from_other_database_is_invalid(self):
        _store, receipt = self._lifecycle()
        other_db = os.path.join(self._tmp.name, "other.db")
        other = RequestStore(other_db)
        other.submit("tenant-a", "subject-1", ["email"], "key-1")
        other_dir = os.path.dirname(other_db)
        other_anchor = os.path.join(other_dir, ".other.db.anchor.json")
        # Replace the sidecar with one that authenticates a different
        # database under its own key.
        with open(other_anchor, "rb") as src, open(
            self._paths()["anchor"], "wb"
        ) as dst:
            dst.write(src.read())
        rebuilt = RequestStore(self.db_path)
        self.assertEqual(rebuilt.recover(), "invalid")
        self.assertFalse(rebuilt.verify_evidence("tenant-a", receipt["request_id"]))

    def test_corrupt_pending_file_is_incomplete(self):
        _store, receipt = self._lifecycle()
        paths = self._paths()
        with open(paths["anchor"], "rb") as handle:
            anchor_raw = handle.read()
        with open(paths["pending"], "wb") as handle:
            handle.write(b"garbage")
        rebuilt = RequestStore(self.db_path)
        self.assertEqual(rebuilt.recover(), "incomplete")
        self.assertFalse(rebuilt.verify_evidence("tenant-a", receipt["request_id"]))
        with open(paths["anchor"], "rb") as handle:
            self.assertEqual(handle.read(), anchor_raw)


class CrossProcessAnchorTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "evidence.db")

    def tearDown(self):
        self._tmp.cleanup()

    def test_concurrent_writers_from_multiple_processes_end_valid(self):
        import multiprocessing

        store = RequestStore(self.db_path)
        receipts = []
        for index in range(6):
            receipts.append(
                store.submit(
                    "tenant-a",
                    f"subject-{index}",
                    ["email"],
                    f"key-{index}",
                )["request_id"]
            )

        ctx = multiprocessing.get_context("spawn")
        workers = [
            ctx.Process(
                target=_worker_transition,
                args=(self.db_path, rid, "processing"),
            )
            for rid in receipts
        ]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=60)
            self.assertEqual(worker.exitcode, 0)

        rebuilt = RequestStore(self.db_path)
        self.assertEqual(rebuilt.recover(), "valid")
        for rid in receipts:
            self.assertTrue(rebuilt.verify_evidence("tenant-a", rid))
            self.assertEqual(
                rebuilt.get("tenant-a", rid)["status"], "processing"
            )


def _worker_transition(db_path, request_id, target):
    import sys

    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
    store = RequestStore(db_path)
    store.transition("tenant-a", request_id, target)


if __name__ == "__main__":
    unittest.main()
