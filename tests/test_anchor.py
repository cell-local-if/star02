import json
import os
import re
import sqlite3
import tempfile
import unittest

from forgetting_evidence.requests import (
    InvalidStatusTransition,
    RequestNotFound,
    RequestStore,
    _ANCHOR_GENESIS,
    _ANCHOR_VERSION,
    _anchor_digest,
    _record_mac,
)

HEX64 = re.compile(r"^[0-9a-f]{64}$")
KEY = "super-secret-integrity-key"
SUBJECT_SECRET = "subject-SECRET-zzz"
SCOPE_SECRET = "scope-SECRET-zzz"
IDEMPOTENCY_SECRET = "key-SECRET-zzz"


def _read_envelopes(path):
    with open(path, "rb") as handle:
        raw = handle.read()
    records = [json.loads(line) for line in raw.decode().splitlines()]
    return raw, records


def _tip_after(records):
    tip = _ANCHOR_GENESIS
    for record in records:
        tip = _anchor_digest(tip, record["mac"])
    return tip


def _append_envelope(path, key, records, kind, head, nonce, *, ref=None):
    """Append a MAC-valid envelope using the caller-held key."""
    envelope = {
        "v": _ANCHOR_VERSION,
        "a": kind,
        "h": head,
        "p": _tip_after(records),
        "n": nonce,
    }
    if ref is not None:
        envelope["ref"] = ref
    envelope["mac"] = _record_mac(
        key.encode() if isinstance(key, str) else key,
        {field: value for field, value in envelope.items()},
    )
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(envelope, sort_keys=True, separators=(",", ":")) + "\n")
    return envelope


class TrustedAnchorTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "evidence.db")
        self.anchor_path = self.db_path + ".anchor"

    def tearDown(self):
        self._tmp.cleanup()

    def _store(self, *, key=KEY, anchor_path=None, db_path=None):
        return RequestStore(
            db_path or self.db_path,
            anchor_path=anchor_path,
            integrity_key=key,
        )

    def _lifecycle(self, store, tenant="tenant-a", key="k-1"):
        receipt = store.submit(
            tenant, SUBJECT_SECRET, [SCOPE_SECRET, "email"], key
        )
        store.transition(tenant, receipt["request_id"], "processing")
        store.transition(tenant, receipt["request_id"], "completed")
        return receipt

    # -- happy path ----------------------------------------------------

    def test_sidecar_created_next_to_database(self):
        store = self._store()
        self.assertFalse(os.path.exists(self.anchor_path))
        store.submit("tenant-a", "subject-1", ["email"], "k-1")
        self.assertTrue(os.path.exists(self.anchor_path))
        mode = os.stat(self.anchor_path).st_mode & 0o777
        self.assertEqual(mode, 0o600)

    def test_explicit_anchor_path(self):
        custom = os.path.join(self._tmp.name, "elsewhere", "a.log")
        store = self._store(anchor_path=custom)
        store.submit("tenant-a", "subject-1", ["email"], "k-1")
        self.assertTrue(os.path.exists(custom))
        self.assertFalse(os.path.exists(self.anchor_path))

    def test_anchor_path_without_key_rejected(self):
        with self.assertRaises(ValueError):
            RequestStore(self.db_path, anchor_path=self.anchor_path)

    def test_bad_key_types_rejected(self):
        for bad in ("", b"", 123, None):
            with self.subTest(bad=bad):
                if bad is None:
                    continue
                with self.assertRaises(ValueError):
                    self._store(key=bad)

    def test_bytes_key_accepted(self):
        store = self._store(key=KEY.encode())
        receipt = store.submit("tenant-a", "subject-1", ["email"], "k-1")
        self.assertTrue(store.verify_evidence("tenant-a", receipt["request_id"]))

    def test_clean_lifecycle_verifies_with_anchor(self):
        store = self._store()
        receipt = self._lifecycle(store)
        self.assertTrue(store.verify_evidence("tenant-a", receipt["request_id"]))
        ev = store.evidence("tenant-a", receipt["request_id"])
        self.assertEqual(set(ev), {"request_id", "status", "event_count", "chain_hash"})
        self.assertEqual(ev["event_count"], 3)

    def test_sidecar_holds_intent_confirmed_pairs(self):
        store = self._store()
        receipt = self._lifecycle(store)
        _raw, records = _read_envelopes(self.anchor_path)
        kinds = [record["a"] for record in records]
        self.assertEqual(
            kinds,
            ["intent", "confirmed"] * 3,
        )
        # Each confirmed closes the immediately preceding intent via ref.
        for index in range(0, len(records), 2):
            self.assertEqual(records[index + 1]["ref"], records[index]["n"])
            self.assertEqual(records[index + 1]["h"], records[index]["h"])
        # Envelopes expose only fixed public fields: never the event
        # payload, timestamps, tenant or preimage material.
        for record in records:
            self.assertIn(
                set(record),
                (
                    {"v", "a", "h", "p", "n", "mac"},
                    {"v", "a", "h", "p", "n", "ref", "mac"},
                ),
            )
            for value in record.values():
                self.assertNotIn(SUBJECT_SECRET, str(value))

    def test_rebuild_verifies_with_same_key(self):
        store = self._store()
        receipt = self._lifecycle(store)
        head_before = store.evidence("tenant-a", receipt["request_id"])["chain_hash"]
        rebuilt = self._store()
        self.assertTrue(rebuilt.verify_evidence("tenant-a", receipt["request_id"]))
        self.assertEqual(
            rebuilt.evidence("tenant-a", receipt["request_id"])["chain_hash"],
            head_before,
        )
        # The rebuilt store can extend the anchored chain.
        rebuilt.submit("tenant-a", "subject-2", ["email"], "k-2")
        other = rebuilt.get("tenant-a", receipt["request_id"])
        self.assertEqual(other["status"], "completed")

    def test_in_memory_keyed_store(self):
        store = self._store(db_path=":memory:")
        receipt = store.submit("tenant-a", "subject-1", ["email"], "k-1")
        store.transition("tenant-a", receipt["request_id"], "failed")
        self.assertTrue(store.verify_evidence("tenant-a", receipt["request_id"]))

    # -- secrecy boundary ---------------------------------------------

    def test_key_and_payload_never_persisted(self):
        store = self._store()
        self._lifecycle(store, key=IDEMPOTENCY_SECRET)
        with open(self.anchor_path, "rb") as handle:
            sidecar = handle.read()
        with open(self.db_path, "rb") as handle:
            database = handle.read()
        # The caller-held key (and anything from which it could be
        # substituted) must appear in neither store. The request payload
        # legitimately lives in SQLite by design but must never cross
        # into the sidecar, which binds only keyed head hashes.
        self.assertNotIn(KEY.encode(), sidecar)
        self.assertNotIn(KEY.encode(), database)
        for secret in (SUBJECT_SECRET, SCOPE_SECRET, IDEMPOTENCY_SECRET):
            self.assertNotIn(secret.encode(), sidecar)
        # The sidecar contains only hash-shaped values; the raw key or a
        # recognizable derivative can never be recovered from it.
        _, records = _read_envelopes(self.anchor_path)
        for record in records:
            for field in ("h", "p", "mac"):
                self.assertTrue(HEX64.match(record[field]))

    def test_key_absent_from_receipts_exceptions_and_logs(self):
        import io
        import logging

        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        logger = logging.getLogger("forgetting_evidence.requests")
        logger.addHandler(handler)
        old_level = logger.level
        logger.setLevel(logging.DEBUG)
        try:
            store = self._store()
            receipt = store.submit(
                "tenant-a", SUBJECT_SECRET, ["email"], "k-1"
            )
            try:
                store.transition("tenant-a", receipt["request_id"], "completed")
            except InvalidStatusTransition as exc:
                self.assertNotIn(KEY, str(exc))
            # Force an anchor durability failure deterministically: the
            # surfaced exception is the module's own and carries no key.
            original = type(store)._append_sidecar

            def boom(self, payload):
                raise RuntimeError("failed to persist audit anchor")

            type(store)._append_sidecar = boom
            try:
                with self.assertRaises(RuntimeError) as ctx:
                    store.transition(
                        "tenant-a", receipt["request_id"], "processing"
                    )
                self.assertNotIn(KEY, str(ctx.exception))
            finally:
                type(store)._append_sidecar = original
            # The failed anchored transition must not have moved the row.
            self.assertEqual(
                store.get("tenant-a", receipt["request_id"])["status"],
                "accepted",
            )
        finally:
            logger.removeHandler(handler)
            logger.setLevel(old_level)
        rendered = repr(receipt) + stream.getvalue()
        self.assertNotIn(KEY, rendered)

    # -- missing / corrupt / wrong key --------------------------------

    def test_missing_sidecar_fails_and_is_not_recreated(self):
        store = self._store()
        receipt = self._lifecycle(store)
        os.remove(self.anchor_path)
        self.assertFalse(store.verify_evidence("tenant-a", receipt["request_id"]))
        self.assertFalse(os.path.exists(self.anchor_path))
        rebuilt = self._store()
        self.assertFalse(rebuilt.verify_evidence("tenant-a", receipt["request_id"]))

    def test_corrupt_sidecar_fails(self):
        store = self._store()
        receipt = self._lifecycle(store)
        with open(self.anchor_path, "r+b") as handle:
            handle.seek(0)
            handle.write(b"X")
        self.assertFalse(store.verify_evidence("tenant-a", receipt["request_id"]))

    def test_tampered_mac_fails(self):
        store = self._store()
        receipt = self._lifecycle(store)
        _raw, records = _read_envelopes(self.anchor_path)
        flipped = ("0" if records[0]["mac"][0] != "0" else "1") + records[0]["mac"][1:]
        records[0]["mac"] = flipped
        with open(self.anchor_path, "w", encoding="utf-8") as handle:
            for record in records:
                handle.write(
                    json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
                )
        self.assertFalse(store.verify_evidence("tenant-a", receipt["request_id"]))

    def test_wrong_key_verify_false(self):
        store = self._store()
        receipt = store.submit("tenant-a", "subject-1", ["email"], "k-1")
        wrong = self._store(key="a-totally-different-key")
        self.assertFalse(wrong.verify_evidence("tenant-a", receipt["request_id"]))

    def test_legacy_unanchored_database_fails_trusted_verification(self):
        # Database written before trusted anchoring existed.
        legacy = RequestStore(self.db_path)
        receipt = legacy.submit("tenant-a", "subject-1", ["email"], "k-1")
        legacy.transition("tenant-a", receipt["request_id"], "processing")
        self.assertFalse(os.path.exists(self.anchor_path))
        trusted = self._store()
        self.assertFalse(
            trusted.verify_evidence("tenant-a", receipt["request_id"])
        )
        # New anchored writes never retroactively validate legacy heads.
        second = trusted.submit("tenant-a", "subject-2", ["email"], "k-2")
        self.assertTrue(trusted.verify_evidence("tenant-a", second["request_id"]))
        self.assertFalse(
            trusted.verify_evidence("tenant-a", receipt["request_id"])
        )

    # -- database tamper defeats recompute attack ---------------------

    def _raw_db(self):
        return sqlite3.connect(self.db_path)

    def test_full_recompute_attack_without_key_fails(self):
        from forgetting_evidence.requests import (
            _GENESIS_PREDECESSOR,
            _chain_hash,
        )

        store = self._store()
        receipt = self._lifecycle(store)
        target = receipt["request_id"]

        # Attacker rewrites the timeline and recomputes every public
        # chain link in SQLite (the keyless algorithm is visible), ...
        with self._raw_db() as conn:
            conn.execute(
                "UPDATE status_events SET status = 'failed', "
                "occurred_at = occurred_at || 'X' "
                "WHERE request_id = ? AND seq = 1",
                (target,),
            )
            rows = conn.execute(
                "SELECT tenant_id, request_id, seq, status, occurred_at "
                "FROM status_events WHERE request_id = ? ORDER BY seq",
                (target,),
            ).fetchall()
            predecessor = _GENESIS_PREDECESSOR
            for tenant_id, request_id, seq, status, occurred_at in rows:
                link = _chain_hash(
                    tenant_id, request_id, seq, status, occurred_at, predecessor
                )
                conn.execute(
                    "UPDATE status_events SET chain_hash = ? "
                    "WHERE request_id = ? AND seq = ?",
                    (link, target, seq),
                )
                predecessor = link
            conn.execute(
                "UPDATE requests SET status = 'failed', chain_hash = ? "
                "WHERE request_id = ?",
                (predecessor, target),
            )
        # ... but without the caller-held key the sidecar cannot be made
        # to confirm the forged head.
        self.assertFalse(store.verify_evidence("tenant-a", target))

    def test_forged_sidecar_records_without_key_fail(self):
        store = self._store()
        receipt = self._lifecycle(store)
        target = receipt["request_id"]
        with self._raw_db() as conn:
            forged_head = conn.execute(
                "SELECT chain_hash FROM status_events "
                "WHERE request_id = ? AND seq = 0",
                (target,),
            ).fetchone()[0]
        # Attacker appends "confirmed" envelopes carrying a guessed MAC.
        _raw, records = _read_envelopes(self.anchor_path)
        for nonce in ("forgery-1", "forgery-2"):
            bogus = {
                "v": _ANCHOR_VERSION,
                "a": "confirmed",
                "h": forged_head,
                "p": _tip_after(records),
                "n": nonce,
                "ref": "whatever",
                "mac": "0" * 64,
            }
            records.append(bogus)
        with open(self.anchor_path, "w", encoding="utf-8") as handle:
            for record in records:
                handle.write(
                    json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
                )
        self.assertFalse(store.verify_evidence("tenant-a", target))

    def test_swap_heads_across_requests_fails(self):
        store = self._store()
        one = store.submit("tenant-a", "subject-1", ["email"], "k-1")
        two = store.submit("tenant-a", "subject-2", ["email"], "k-2")
        with self._raw_db() as conn:
            head_one = conn.execute(
                "SELECT chain_hash FROM status_events WHERE request_id = ? AND seq = 0",
                (one["request_id"],),
            ).fetchone()[0]
            head_two = conn.execute(
                "SELECT chain_hash FROM status_events WHERE request_id = ? AND seq = 0",
                (two["request_id"],),
            ).fetchone()[0]
            conn.execute(
                "UPDATE status_events SET chain_hash = ? WHERE request_id = ? AND seq = 0",
                (head_two, one["request_id"]),
            )
            conn.execute(
                "UPDATE requests SET chain_hash = ? WHERE request_id = ?",
                (head_two, one["request_id"]),
            )
        self.assertFalse(store.verify_evidence("tenant-a", one["request_id"]))

    # -- interrupted commit -------------------------------------------

    def _drop_last_record(self):
        _raw, records = _read_envelopes(self.anchor_path)
        with open(self.anchor_path, "w", encoding="utf-8") as handle:
            for record in records[:-1]:
                handle.write(
                    json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
                )
        return records

    def test_interrupted_after_commit_reconciles_to_valid(self):
        store = self._store()
        stuck = store.submit("tenant-a", "subject-1", ["email"], "stuck")
        store.transition("tenant-a", stuck["request_id"], "processing")
        other = store.submit("tenant-a", "subject-2", ["email"], "other")
        self.assertTrue(store.verify_evidence("tenant-a", stuck["request_id"]))
        # Crash after COMMIT but before the "confirmed" record landed:
        # remove the closer, leaving a dangling intent whose head is in
        # the durable database.
        self._drop_last_record()
        self.assertFalse(store.verify_evidence("tenant-a", stuck["request_id"]))
        self.assertEqual(store.recover(), "incomplete")
        # A later mutation reconciles the dangling intent as committed.
        store.transition("tenant-a", other["request_id"], "processing")
        self.assertEqual(store.recover(), "valid")
        self.assertTrue(store.verify_evidence("tenant-a", stuck["request_id"]))
        self.assertTrue(store.verify_evidence("tenant-a", other["request_id"]))
        rebuilt = self._store()
        self.assertTrue(rebuilt.verify_evidence("tenant-a", stuck["request_id"]))

    def test_interrupted_after_intent_with_rollback_reconciles_aborted(self):
        store = self._store()
        keep = store.submit("tenant-a", "subject-1", ["email"], "keep")
        # Dangling intent naming a head that never committed.
        _raw, records = _read_envelopes(self.anchor_path)
        _append_envelope(
            self.anchor_path,
            KEY,
            records,
            "intent",
            "a" * 64,
            "ghost-intent",
        )
        self.assertEqual(store.recover(), "incomplete")
        self.assertFalse(store.verify_evidence("tenant-a", keep["request_id"]))
        # Next mutation reconciles the ghost as aborted, then proceeds.
        store.transition("tenant-a", keep["request_id"], "processing")
        self.assertEqual(store.recover(), "valid")
        self.assertTrue(store.verify_evidence("tenant-a", keep["request_id"]))
        _raw2, records2 = _read_envelopes(self.anchor_path)
        kinds = [record["a"] for record in records2]
        self.assertIn("aborted", kinds)
        self.assertEqual(kinds.count("confirmed"), 2)

    def test_torn_physical_append_is_incomplete_until_reconciled(self):
        store = self._store()
        receipt = store.submit("tenant-a", "subject-1", ["email"], "keep")
        # Simulate a crash mid-write of the trailing confirmation.
        with open(self.anchor_path, "r+b") as handle:
            handle.seek(-5, os.SEEK_END)
            handle.truncate()
        self.assertFalse(store.verify_evidence("tenant-a", receipt["request_id"]))
        self.assertEqual(store.recover(), "incomplete")
        # Read-only triage must not truncate or heal anything.
        with open(self.anchor_path, "rb") as handle:
            size_before = len(handle.read())
        for _ in range(3):
            self.assertEqual(store.recover(), "incomplete")
        with open(self.anchor_path, "rb") as handle:
            self.assertEqual(len(handle.read()), size_before)
        # The next successful mutation truncates the partial record,
        # reconciles the committed intent as confirmed, and the affected
        # request verifies again.
        store.transition("tenant-a", receipt["request_id"], "processing")
        self.assertEqual(store.recover(), "valid")
        self.assertTrue(store.verify_evidence("tenant-a", receipt["request_id"]))
        rebuilt = self._store()
        self.assertTrue(rebuilt.verify_evidence("tenant-a", receipt["request_id"]))

    def test_corrupt_complete_record_refuses_success(self):
        store = self._store()
        receipt = store.submit("tenant-a", "subject-1", ["email"], "keep")
        _raw, records = _read_envelopes(self.anchor_path)
        # Corrupt an already-complete record (not a physical tear): MAC
        # verification fails and no later record can safely follow.
        corrupt = dict(records[0])
        corrupt["n"] = corrupt["n"][:-1] + (
            "0" if corrupt["n"][-1] != "0" else "1"
        )
        lines = []
        for record in records:
            chosen = corrupt if record is records[0] else record
            lines.append(
                json.dumps(chosen, sort_keys=True, separators=(",", ":"))
            )
        with open(self.anchor_path, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
        self.assertEqual(store.recover(), "invalid")
        with self.assertRaises(RuntimeError):
            store.transition("tenant-a", receipt["request_id"], "processing")
        # The failed mutation changed neither status nor evidence state.
        self.assertEqual(
            store.get("tenant-a", receipt["request_id"])["status"], "accepted"
        )
        self.assertFalse(store.verify_evidence("tenant-a", receipt["request_id"]))

    # -- recover() tri-state, strictly read-only ----------------------

    def test_recover_requires_trusted_mode(self):
        plain = RequestStore(self.db_path)
        plain.submit("tenant-a", "subject-1", ["email"], "k-1")
        with self.assertRaises(RuntimeError):
            plain.recover()

    def test_recover_valid_on_clean_store_and_empty_store(self):
        store = self._store()
        # No sidecar yet and an empty database is a valid (vacuous) state.
        self.assertEqual(store.recover(), "valid")
        self.assertFalse(os.path.exists(self.anchor_path))
        receipt = self._lifecycle(store)
        self.assertEqual(store.recover(), "valid")
        rebuilt = self._store()
        self.assertEqual(rebuilt.recover(), "valid")

    def test_recover_invalid_on_missing_or_corrupt_sidecar(self):
        store = self._store()
        self._lifecycle(store)
        os.remove(self.anchor_path)
        self.assertEqual(store.recover(), "invalid")
        self._store().submit("tenant-a", "subject-x", ["email"], "kx")
        with open(self.anchor_path, "r+b") as handle:
            handle.seek(0)
            handle.write(b"!")
        self.assertEqual(store.recover(), "invalid")

    def test_recover_invalid_on_database_tamper(self):
        store = self._store()
        receipt = self._lifecycle(store)
        with self._raw_db() as conn:
            conn.execute(
                "UPDATE status_events SET status = 'failed' "
                "WHERE request_id = ? AND seq = 1",
                (receipt["request_id"],),
            )
        self.assertEqual(store.recover(), "invalid")

    def test_recover_is_read_only_in_every_state(self):
        store = self._store()
        receipt = self._lifecycle(store)

        def snapshots():
            with open(self.db_path, "rb") as handle:
                db = handle.read()
            with open(self.anchor_path, "rb") as handle:
                side = handle.read()
            return db, side

        db_before, side_before = snapshots()
        for _ in range(3):
            self.assertEqual(store.recover(), "valid")
        db_after, side_after = snapshots()
        self.assertEqual(db_before, db_after)
        self.assertEqual(side_before, side_after)

        # Dangling state: recover still writes nothing.
        self._drop_last_record()
        db_before, side_before = snapshots()
        self.assertEqual(store.recover(), "incomplete")
        self.assertEqual(store.recover(), "incomplete")
        db_after, side_after = snapshots()
        self.assertEqual(db_before, db_after)
        self.assertEqual(side_before, side_after)

        # Corrupt state: recover still writes nothing.
        with open(self.anchor_path, "r+b") as handle:
            handle.seek(0)
            handle.write(b"?")
        db_before, side_before = snapshots()
        self.assertEqual(store.recover(), "invalid")
        db_after, side_after = snapshots()
        self.assertEqual(db_before, db_after)
        self.assertEqual(side_before, side_after)

    # -- no-write / no-anchor-change guarantees ------------------------

    def _snapshot_pair(self):
        with open(self.db_path, "rb") as handle:
            db = handle.read()
        with open(self.anchor_path, "rb") as handle:
            side = handle.read()
        return db, side

    def test_replays_and_errors_do_not_change_anchor(self):
        store = self._store()
        receipt = store.submit("tenant-a", SUBJECT_SECRET, ["email"], "k-1")
        store.transition("tenant-a", receipt["request_id"], "processing")
        before = self._snapshot_pair()

        # Same-status replays.
        store.transition("tenant-a", receipt["request_id"], "processing")
        store.submit("tenant-a", SUBJECT_SECRET, ["email"], "k-1")
        # Illegal / unknown transitions (current state is processing).
        with self.assertRaises(InvalidStatusTransition):
            store.transition("tenant-a", receipt["request_id"], "accepted")
        with self.assertRaises(InvalidStatusTransition):
            store.transition("tenant-a", receipt["request_id"], "cancelled")
        # Parameter errors.
        for bad in ("", None, 7, b"x"):
            with self.assertRaises(ValueError):
                store.submit(bad, "s", ["email"], "k")
            with self.assertRaises(ValueError):
                store.transition(bad, receipt["request_id"], "failed")
        # Missing record and cross-tenant access.
        with self.assertRaises(RequestNotFound):
            store.transition("tenant-a", "does-not-exist", "failed")
        with self.assertRaises(RequestNotFound):
            store.transition("tenant-b", receipt["request_id"], "failed")
        with self.assertRaises(RequestNotFound):
            store.audit("tenant-b", receipt["request_id"])
        with self.assertRaises(RequestNotFound):
            store.verify_evidence("tenant-b", receipt["request_id"])

        self.assertEqual(self._snapshot_pair(), before)
        self.assertTrue(store.verify_evidence("tenant-a", receipt["request_id"]))

    def test_verify_and_recover_never_write(self):
        store = self._store()
        receipt = self._lifecycle(store)
        before = self._snapshot_pair()
        for _ in range(5):
            self.assertTrue(store.verify_evidence("tenant-a", receipt["request_id"]))
            store.recover()
        self.assertEqual(self._snapshot_pair(), before)

    def test_evidence_unchanged_shape_and_secrecy(self):
        store = self._store()
        receipt = store.submit(
            "tenant-a", SUBJECT_SECRET, [SCOPE_SECRET], IDEMPOTENCY_SECRET
        )
        rendered = repr(store.evidence("tenant-a", receipt["request_id"]))
        for secret in (KEY, SUBJECT_SECRET, SCOPE_SECRET, IDEMPOTENCY_SECRET):
            self.assertNotIn(secret, rendered)
        self.assertEqual(
            set(store.evidence("tenant-a", receipt["request_id"])),
            {"request_id", "status", "event_count", "chain_hash"},
        )

    # -- multi-tenant isolation with the anchor -----------------------

    def test_anchors_partition_tenants_through_heads(self):
        store = self._store()
        a = store.submit("tenant-a", "subject-1", ["email"], "shared")
        b = store.submit("tenant-b", "subject-1", ["email"], "shared")
        store.transition("tenant-a", a["request_id"], "failed")
        store.transition("tenant-b", b["request_id"], "processing")
        self.assertTrue(store.verify_evidence("tenant-a", a["request_id"]))
        self.assertTrue(store.verify_evidence("tenant-b", b["request_id"]))
        with self.assertRaises(RequestNotFound):
            store.verify_evidence("tenant-b", a["request_id"])
        self.assertEqual(store.recover(), "valid")


if __name__ == "__main__":
    unittest.main()
