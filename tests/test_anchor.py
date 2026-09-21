"""Tests for protected (off-database) evidence anchoring.

These tests target the threat the keyless SQLite hash chain cannot stop:
an attacker who rewrites the whole database and recomputes every digest.
They prove the external key file and append-only anchor journal are
required for verification and never leak into SQLite, receipts,
exceptions or logs.
"""

import hashlib
import io
import json
import logging
import os
import re
import sqlite3
import struct
import tempfile
import unittest

from forgetting_evidence.requests import (
    InvalidStatusTransition,
    RequestNotFound,
    RequestStore,
)

HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _chain_hash(tenant_id, request_id, seq, status, occurred_at, predecessor):
    digest = hashlib.sha256()
    for field in (tenant_id, request_id, str(seq), status, occurred_at, predecessor):
        raw = field.encode("utf-8")
        digest.update(struct.pack(">Q", len(raw)))
        digest.update(raw)
    return digest.hexdigest()


GENESIS = hashlib.sha256(b"").hexdigest()


class AnchorBasicsTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "evidence.db")

    def tearDown(self):
        self._tmp.cleanup()

    def test_default_sidecars_created_next_to_database(self):
        store = RequestStore(self.db_path)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "k")
        store.transition("tenant-a", receipt["request_id"], "processing")
        self.assertTrue(os.path.exists(self.db_path + ".key"))
        self.assertTrue(os.path.exists(self.db_path + ".anchorlog"))
        # Key material is restricted to the owner.
        self.assertEqual(
            stat_mode(self.db_path + ".key") & 0o777, 0o600
        )
        self.assertEqual(
            stat_mode(self.db_path + ".anchorlog") & 0o777, 0o600
        )

    def test_verifies_after_instance_rebuild_default_config(self):
        store = RequestStore(self.db_path)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "k")
        store.transition("tenant-a", receipt["request_id"], "processing")
        store.transition("tenant-a", receipt["request_id"], "completed")
        rebuilt = RequestStore(self.db_path)
        self.assertTrue(
            rebuilt.verify_evidence("tenant-a", receipt["request_id"])
        )
        # A brand new request created by the rebuilt instance verifies
        # both before and after another rebuild.
        new_receipt = rebuilt.submit("tenant-a", "subject-2", ["email"], "k2")
        self.assertTrue(
            rebuilt.verify_evidence("tenant-a", new_receipt["request_id"])
        )
        rebuilt_again = RequestStore(self.db_path)
        self.assertTrue(
            rebuilt_again.verify_evidence("tenant-a", new_receipt["request_id"])
        )
        self.assertTrue(
            rebuilt_again.verify_evidence("tenant-a", receipt["request_id"])
        )

    def test_explicit_key_survives_rebuild(self):
        key = b"a-distinct-master-key-value-32B!"
        s1 = RequestStore(
            self.db_path,
            anchor_key=key,
            anchor_journal_file=os.path.join(self._tmp.name, "j.log"),
        )
        receipt = s1.submit("tenant-a", "subject-1", ["email"], "k")
        s1.transition("tenant-a", receipt["request_id"], "failed")
        s2 = RequestStore(
            self.db_path,
            anchor_key=key,
            anchor_journal_file=os.path.join(self._tmp.name, "j.log"),
        )
        self.assertTrue(s2.verify_evidence("tenant-a", receipt["request_id"]))

    def test_wrong_key_fails_verification(self):
        s1 = RequestStore(self.db_path, anchor_key=b"key-one-32-bytes-long-aaaaaaaa")
        receipt = s1.submit("tenant-a", "subject-1", ["email"], "k")
        s1.transition("tenant-a", receipt["request_id"], "processing")
        # Different key, same database and default journal location:
        # every keyed tag fails.
        s2 = RequestStore(self.db_path, anchor_key=b"key-two-32-bytes-long-bbbbbbbb")
        self.assertFalse(
            s2.verify_evidence("tenant-a", receipt["request_id"])
        )

    def test_key_file_location_configurable(self):
        key_file = os.path.join(self._tmp.name, "secrets", "master.key")
        journal = os.path.join(self._tmp.name, "audit", "anchors.log")
        s1 = RequestStore(
            self.db_path,
            anchor_key_file=key_file,
            anchor_journal_file=journal,
        )
        receipt = s1.submit("tenant-a", "subject-1", ["email"], "k")
        self.assertTrue(os.path.exists(key_file))
        self.assertTrue(os.path.exists(journal))
        s2 = RequestStore(
            self.db_path,
            anchor_key_file=key_file,
            anchor_journal_file=journal,
        )
        self.assertTrue(s2.verify_evidence("tenant-a", receipt["request_id"]))

    def test_in_memory_store_verifies_within_process(self):
        store = RequestStore(":memory:")
        receipt = store.submit("tenant-a", "subject-1", ["email"], "k")
        store.transition("tenant-a", receipt["request_id"], "processing")
        store.transition("tenant-a", receipt["request_id"], "completed")
        self.assertTrue(
            store.verify_evidence("tenant-a", receipt["request_id"])
        )


def stat_mode(path):
    return os.stat(path).st_mode


class AnchorNoLeakTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "evidence.db")

    def tearDown(self):
        self._tmp.cleanup()

    def test_no_key_material_in_sqlite(self):
        key = b"master-key-pattern-AAAAAAAAAAAAAA"
        store = RequestStore(self.db_path, anchor_key=key)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "k")
        store.transition("tenant-a", receipt["request_id"], "processing")
        with open(self.db_path, "rb") as handle:
            db_bytes = handle.read()
        # The raw master key and the HMAC key derivation label must not
        # appear in the database file.
        self.assertNotIn(key, db_bytes)
        self.assertNotIn(b"fe-anchor-event-v1", db_bytes)
        self.assertNotIn(b"fe-anchor-head-v1", db_bytes)
        self.assertNotIn(b"fe-anchor-journal-v1", db_bytes)
        # Anchor columns hold only hex digests, never preimages.
        with sqlite3.connect(self.db_path) as conn:
            for (mac,) in conn.execute(
                "SELECT anchor_mac FROM status_events WHERE anchor_mac IS NOT NULL"
            ):
                self.assertTrue(HEX64.match(mac))
            for (mac,) in conn.execute(
                "SELECT anchor_mac FROM requests WHERE anchor_mac IS NOT NULL"
            ):
                self.assertTrue(HEX64.match(mac))

    def test_receipts_and_evidence_exclude_anchor_material(self):
        store = RequestStore(self.db_path)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "k")
        moved = store.transition(
            "tenant-a", receipt["request_id"], "processing"
        )
        ev = store.evidence("tenant-a", receipt["request_id"])
        for rendered in (repr(receipt), repr(moved), repr(ev)):
            self.assertNotIn("anchor", rendered.lower())
            self.assertNotIn("mac", rendered.lower())
        self.assertEqual(set(ev), {"request_id", "status", "event_count", "chain_hash"})
        self.assertEqual(set(receipt), {"request_id", "status", "created_at"})

    def test_journal_does_not_contain_key(self):
        key = b"master-key-pattern-BBBBBBBBBBBBBB"
        store = RequestStore(self.db_path, anchor_key=key)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "k")
        store.transition("tenant-a", receipt["request_id"], "processing")
        store.transition("tenant-a", receipt["request_id"], "completed")
        with open(self.db_path + ".anchorlog", "rb") as handle:
            journal = handle.read()
        self.assertNotIn(key, journal)
        # Each line is self-describing JSON and carries only hex tags.
        for line in journal.splitlines():
            record = json.loads(line)
            self.assertTrue(HEX64.match(record["mac"]))
            self.assertTrue(HEX64.match(record["event_mac"]))
            self.assertTrue(HEX64.match(record["head_mac"]))

    def test_logs_do_not_contain_key_or_journal_path(self):
        key = b"master-key-pattern-CCCCCCCCCCCCCC"
        store = RequestStore(self.db_path, anchor_key=key)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "k")
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        logger = logging.getLogger("forgetting_evidence.requests")
        logger.addHandler(handler)
        old_level = logger.level
        logger.setLevel(logging.DEBUG)
        try:
            store.transition("tenant-a", receipt["request_id"], "failed")
        finally:
            logger.removeHandler(handler)
            logger.setLevel(old_level)
        out = stream.getvalue()
        self.assertNotIn(key.decode(), out)
        self.assertNotIn("anchorlog", out)
        self.assertNotIn(".key", out)


class FullDatabaseRewriteTests(unittest.TestCase):
    """The headline threat: recompute everything inside SQLite."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "evidence.db")

    def tearDown(self):
        self._tmp.cleanup()

    def _raw(self):
        return sqlite3.connect(self.db_path)

    def test_recompute_all_hashes_without_key_still_fails(self):
        store = RequestStore(self.db_path)
        rid = store.submit("tenant-a", "subject-1", ["email"], "k")["request_id"]
        store.transition("tenant-a", rid, "processing")
        # Attacker rewrites an event field and recomputes EVERY keyless
        # hash -- events, request head -- exactly as the store would.
        with self._raw() as conn:
            conn.execute(
                "UPDATE status_events SET status='completed' "
                "WHERE request_id=? AND seq=1",
                (rid,),
            )
            conn.execute(
                "UPDATE requests SET status='completed' WHERE request_id=?",
                (rid,),
            )
            rows = conn.execute(
                "SELECT seq, status, occurred_at FROM status_events "
                "WHERE request_id=? ORDER BY seq",
                (rid,),
            ).fetchall()
            pred = GENESIS
            for seq, status, occurred_at in rows:
                link = _chain_hash(
                    "tenant-a", rid, seq, status, occurred_at, pred
                )
                conn.execute(
                    "UPDATE status_events SET chain_hash=? "
                    "WHERE request_id=? AND seq=?",
                    (link, rid, seq),
                )
                pred = link
            conn.execute(
                "UPDATE requests SET chain_hash=? WHERE request_id=?",
                (pred, rid),
            )
        # The attacker cannot recompute anchor_mac or forge journal
        # records without the external key, so verification fails.
        self.assertFalse(store.verify_evidence("tenant-a", rid))
        self.assertFalse(
            RequestStore(self.db_path).verify_evidence("tenant-a", rid)
        )

    def test_drop_and_rebuild_events_with_recomputed_hashes_fails(self):
        store = RequestStore(self.db_path)
        rid = store.submit("tenant-a", "subject-1", ["email"], "k")["request_id"]
        store.transition("tenant-a", rid, "processing")
        with self._raw() as conn:
            # Attacker deletes the processing event and recomputes the
            # request head to the genesis link.
            conn.execute(
                "DELETE FROM status_events WHERE request_id=? AND seq=1",
                (rid,),
            )
            genesis = conn.execute(
                "SELECT chain_hash FROM status_events "
                "WHERE request_id=? AND seq=0",
                (rid,),
            ).fetchone()[0]
            conn.execute(
                "UPDATE requests SET status='accepted', chain_hash=? "
                "WHERE request_id=?",
                (genesis, rid),
            )
        self.assertFalse(store.verify_evidence("tenant-a", rid))

    def test_copy_entire_sqlite_content_under_second_key_fails(self):
        # Build a second, attacker-controlled database with its own valid
        # anchor material, then splice its event/request rows into the
        # victim database. The victim journal never recorded them.
        victim = os.path.join(self._tmp.name, "victim.db")
        attacker = os.path.join(self._tmp.name, "attacker.db")
        vs = RequestStore(victim)
        as_ = RequestStore(attacker)
        vrid = vs.submit("tenant-a", "subject-1", ["email"], "k")["request_id"]
        vs.transition("tenant-a", vrid, "processing")
        arid = as_.submit("tenant-a", "subject-1", ["email"], "k")["request_id"]
        as_.transition("tenant-a", arid, "processing")
        as_.transition("tenant-a", arid, "completed")
        # Replace the victim's rows wholesale with the attacker's rows
        # (including attacker-valid anchor_mac values and heads), keeping
        # the victim request id.
        with sqlite3.connect(attacker) as ac, sqlite3.connect(victim) as vc:
            req = ac.execute(
                "SELECT tenant_id,idempotency_key,subject_id,scopes_json,"
                "status,created_at,chain_hash,anchor_mac FROM requests "
                "WHERE request_id=?",
                (arid,),
            ).fetchone()
            vc.execute(
                "UPDATE requests SET tenant_id=?,idempotency_key=?,"
                "subject_id=?,scopes_json=?,status=?,created_at=?,"
                "chain_hash=?,anchor_mac=? WHERE request_id=?",
                (*req, vrid),
            )
            vc.execute("DELETE FROM status_events WHERE request_id=?", (vrid,))
            for seq, status, occurred_at, ch, mac in ac.execute(
                "SELECT seq,status,occurred_at,chain_hash,anchor_mac "
                "FROM status_events WHERE request_id=? ORDER BY seq",
                (arid,),
            ):
                vc.execute(
                    "INSERT INTO status_events VALUES (?,?,?,?,?,?,?)",
                    ("tenant-a", vrid, seq, status, occurred_at, ch, mac),
                )
        self.assertFalse(
            RequestStore(victim).verify_evidence("tenant-a", vrid)
        )


class ExternalJournalAttackTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "evidence.db")
        self.journal = self.db_path + ".anchorlog"

    def tearDown(self):
        self._tmp.cleanup()

    def _build(self, statuses=("processing", "completed")):
        store = RequestStore(self.db_path)
        rid = store.submit("tenant-a", "subject-1", ["email"], "k")["request_id"]
        for status in statuses:
            store.transition("tenant-a", rid, status)
        return store, rid

    def test_delete_journal_fails(self):
        _, rid = self._build()
        os.remove(self.journal)
        self.assertFalse(
            RequestStore(self.db_path).verify_evidence("tenant-a", rid)
        )

    def test_truncate_journal_fails(self):
        _, rid = self._build()
        with open(self.journal, "r+b") as handle:
            handle.truncate(0)
        self.assertFalse(
            RequestStore(self.db_path).verify_evidence("tenant-a", rid)
        )

    def test_delete_one_journal_record_fails(self):
        _, rid = self._build(("processing", "completed"))
        with open(self.journal, "rb") as handle:
            lines = handle.read().splitlines(keepends=True)
        self.assertEqual(len(lines), 3)
        # Drop the middle record; the trailing MAC chain breaks and the
        # request record set no longer matches.
        with open(self.journal, "wb") as handle:
            handle.write(lines[0] + lines[2])
        self.assertFalse(
            RequestStore(self.db_path).verify_evidence("tenant-a", rid)
        )

    def test_reorder_journal_records_fails(self):
        _, rid = self._build(("processing", "failed"))
        with open(self.journal, "rb") as handle:
            lines = handle.read().splitlines(keepends=True)
        with open(self.journal, "wb") as handle:
            handle.write(lines[0] + lines[2] + lines[1])
        self.assertFalse(
            RequestStore(self.db_path).verify_evidence("tenant-a", rid)
        )

    def test_append_garbage_to_journal_fails(self):
        _, rid = self._build()
        with open(self.journal, "ab") as handle:
            handle.write(b'{"not":"a valid record"}\n')
        self.assertFalse(
            RequestStore(self.db_path).verify_evidence("tenant-a", rid)
        )

    def test_swap_journal_between_databases_fails(self):
        other = os.path.join(self._tmp.name, "other.db")
        _, rid = self._build()
        other_store = RequestStore(other)
        orid = other_store.submit(
            "tenant-a", "subject-2", ["email"], "k2"
        )["request_id"]
        other_store.transition("tenant-a", orid, "processing")
        # Give the first database the other database's journal by
        # overwriting it (keys are per-database sidecars, so MACs do not
        # even validate).
        with open(other + ".anchorlog", "rb") as src, open(
            self.journal, "wb"
        ) as dst:
            dst.write(src.read())
        self.assertFalse(
            RequestStore(self.db_path).verify_evidence("tenant-a", rid)
        )

    def test_replace_key_file_fails(self):
        _, rid = self._build()
        # Attacker removes the real key and lets a fresh one be generated.
        os.remove(self.db_path + ".key")
        rebuilt = RequestStore(self.db_path)  # generates a new key
        self.assertFalse(rebuilt.verify_evidence("tenant-a", rid))

    def test_corrupted_journal_fails_closed(self):
        self._build()
        with open(self.journal, "ab") as handle:
            handle.write(b"corrupt-line\n")
        # Opening still succeeds, but verification is False and further
        # anchored writes are refused rather than forking the chain.
        rebuilt = RequestStore(self.db_path)
        with sqlite3.connect(self.db_path) as conn:
            target = conn.execute(
                "SELECT request_id FROM requests LIMIT 1"
            ).fetchone()[0]
        self.assertFalse(rebuilt.verify_evidence("tenant-a", target))
        with self.assertRaises(RuntimeError):
            rebuilt.submit("tenant-a", "subject-9", ["email"], "kx")

    def test_missing_journal_but_present_database_fails(self):
        # Simulate an attacker copying only the database file elsewhere
        # without the protected sidecars.
        _, rid = self._build()
        elsewhere = os.path.join(self._tmp.name, "copy", "evidence.db")
        os.makedirs(os.path.dirname(elsewhere), exist_ok=True)
        with open(self.db_path, "rb") as src, open(elsewhere, "wb") as dst:
            dst.write(src.read())
        # A fresh key and journal are generated for the copy.
        copy_store = RequestStore(elsewhere)
        self.assertFalse(copy_store.verify_evidence("tenant-a", rid))

    def test_reset_all_protected_material_and_recompute_fails(self):
        # The strongest rewrite: attacker deletes BOTH sidecars (so a new
        # key and empty journal are generated), rewrites the database and
        # recomputes every keyless hash and head. They still cannot mint
        # journal records matching the new (or any) chain for old rows.
        import sqlite3 as _sq
        _, rid = self._build(("processing", "failed"))
        os.remove(self.db_path + ".key")
        os.remove(self.journal)
        with _sq.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE status_events SET status='completed' "
                "WHERE request_id=? AND seq=1",
                (rid,),
            )
            conn.execute(
                "UPDATE requests SET status='completed' WHERE request_id=?",
                (rid,),
            )
            rows = conn.execute(
                "SELECT seq,status,occurred_at FROM status_events "
                "WHERE request_id=? ORDER BY seq",
                (rid,),
            ).fetchall()
            pred = GENESIS
            for seq, status, occurred_at in rows:
                link = _chain_hash(
                    "tenant-a", rid, seq, status, occurred_at, pred
                )
                conn.execute(
                    "UPDATE status_events SET chain_hash=? "
                    "WHERE request_id=? AND seq=?",
                    (link, rid, seq),
                )
                pred = link
            conn.execute(
                "UPDATE requests SET chain_hash=? WHERE request_id=?",
                (pred, rid),
            )
        rebuilt = RequestStore(self.db_path)
        self.assertFalse(rebuilt.verify_evidence("tenant-a", rid))

    def test_rebuild_from_other_working_directory(self):
        # Default sidecar paths are resolved next to the database itself,
        # so a rebuilt instance launched from a different current
        # directory reuses the same key and journal.
        _, rid = self._build()
        cwd = os.getcwd()
        try:
            os.chdir("/")
            rebuilt = RequestStore(self.db_path)
            self.assertTrue(rebuilt.verify_evidence("tenant-a", rid))
        finally:
            os.chdir(cwd)


class CrossRecordAnchorTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "evidence.db")

    def tearDown(self):
        self._tmp.cleanup()

    def test_cross_request_anchor_tag_substitution_fails(self):
        store = RequestStore(self.db_path)
        one = store.submit("tenant-a", "subject-1", ["email"], "k1")["request_id"]
        two = store.submit("tenant-a", "subject-2", ["email"], "k2")["request_id"]
        store.transition("tenant-a", one, "processing")
        store.transition("tenant-a", two, "processing")
        with sqlite3.connect(self.db_path) as conn:
            tag = conn.execute(
                "SELECT anchor_mac FROM status_events "
                "WHERE request_id=? AND seq=0",
                (two,),
            ).fetchone()[0]
            conn.execute(
                "UPDATE status_events SET anchor_mac=? "
                "WHERE request_id=? AND seq=0",
                (tag, one),
            )
        self.assertFalse(store.verify_evidence("tenant-a", one))

    def test_cross_tenant_anchor_tag_substitution_fails(self):
        store = RequestStore(self.db_path)
        a = store.submit("tenant-a", "subject-1", ["email"], "k")["request_id"]
        b = store.submit("tenant-b", "subject-1", ["email"], "k")["request_id"]
        store.transition("tenant-a", a, "processing")
        store.transition("tenant-b", b, "processing")
        with sqlite3.connect(self.db_path) as conn:
            # Copy tenant-b's genesis row (including its keyed tag) over
            # tenant-a's seq-0 row. The tag is bound to tenant-b.
            forgery = conn.execute(
                "SELECT status, occurred_at, chain_hash, anchor_mac "
                "FROM status_events "
                "WHERE tenant_id='tenant-b' AND request_id=? AND seq=0",
                (b,),
            ).fetchone()
            conn.execute(
                "UPDATE status_events SET status=?, occurred_at=?, "
                "chain_hash=?, anchor_mac=? "
                "WHERE tenant_id='tenant-a' AND request_id=? AND seq=0",
                (*forgery, a),
            )
        self.assertFalse(store.verify_evidence("tenant-a", a))

    def test_head_mac_binds_final_status_and_count(self):
        store = RequestStore(self.db_path)
        rid = store.submit("tenant-a", "subject-1", ["email"], "k")["request_id"]
        store.transition("tenant-a", rid, "processing")
        # Flip the request status without touching events; the head MAC
        # binds status and count, so verification fails.
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE requests SET status='failed' WHERE request_id=?",
                (rid,),
            )
        self.assertFalse(store.verify_evidence("tenant-a", rid))

    def test_forge_head_mac_from_event_mac_fails(self):
        store = RequestStore(self.db_path)
        rid = store.submit("tenant-a", "subject-1", ["email"], "k")["request_id"]
        with sqlite3.connect(self.db_path) as conn:
            event_mac = conn.execute(
                "SELECT anchor_mac FROM status_events "
                "WHERE request_id=? AND seq=0",
                (rid,),
            ).fetchone()[0]
            # The head key is domain-separated from the event key, so an
            # event tag is never a valid head tag.
            conn.execute(
                "UPDATE requests SET anchor_mac=? WHERE request_id=?",
                (event_mac, rid),
            )
        self.assertFalse(store.verify_evidence("tenant-a", rid))


class NoEvidenceChangeTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "evidence.db")
        self.journal = self.db_path + ".anchorlog"

    def tearDown(self):
        self._tmp.cleanup()

    def _journal_bytes(self):
        with open(self.journal, "rb") as handle:
            return handle.read()

    def test_replay_illegal_and_validation_do_not_append_journal(self):
        store = RequestStore(self.db_path)
        rid = store.submit("tenant-a", "subject-1", ["email"], "k")["request_id"]
        after_submit = self._journal_bytes()
        store.transition("tenant-a", rid, "accepted")  # same-state replay
        store.transition("tenant-a", rid, "processing")
        after_first = self._journal_bytes()
        store.transition("tenant-a", rid, "processing")  # replay
        with self.assertRaises(InvalidStatusTransition):
            # processing -> accepted is not an edge.
            store.transition("tenant-a", rid, "accepted")
        with self.assertRaises(InvalidStatusTransition):
            store.transition("tenant-a", rid, "nope")
        with self.assertRaises(RequestNotFound):
            store.transition("tenant-a", "missing", "processing")
        with self.assertRaises(ValueError):
            store.transition("", rid, "completed")
        with self.assertRaises(ValueError):
            store.submit("", "subject", ["email"], "k2")
        self.assertEqual(self._journal_bytes(), after_first)
        self.assertNotEqual(after_submit, after_first)
        # Legitimate chain still verifies.
        self.assertTrue(store.verify_evidence("tenant-a", rid))

    def test_verify_is_strictly_read_only(self):
        store = RequestStore(self.db_path)
        rid = store.submit("tenant-a", "subject-1", ["email"], "k")["request_id"]
        store.transition("tenant-a", rid, "processing")
        store.transition("tenant-a", rid, "completed")
        with open(self.db_path, "rb") as a, open(self.journal, "rb") as b:
            db_before, journal_before = a.read(), b.read()
        for _ in range(5):
            self.assertTrue(store.verify_evidence("tenant-a", rid))
        with open(self.db_path, "rb") as a, open(self.journal, "rb") as b:
            db_after, journal_after = a.read(), b.read()
        self.assertEqual(db_before, db_after)
        self.assertEqual(journal_before, journal_after)

    def test_legacy_unanchored_records_remain_after_new_writes(self):
        # A legacy database opened by the upgraded store must keep its
        # original audit rows untouched even after new anchored writes.
        db_path = self.db_path
        with sqlite3.connect(db_path) as conn:
            conn.execute(
                "CREATE TABLE requests (request_id TEXT PRIMARY KEY, "
                "tenant_id TEXT NOT NULL, idempotency_key TEXT NOT NULL, "
                "subject_id TEXT NOT NULL, scopes_json TEXT NOT NULL, "
                "status TEXT NOT NULL, created_at TEXT NOT NULL)"
            )
            conn.execute(
                "CREATE UNIQUE INDEX idx_requests_tenant_idempotency "
                "ON requests(tenant_id, idempotency_key)"
            )
            conn.execute(
                "CREATE TABLE status_events (tenant_id TEXT NOT NULL, "
                "request_id TEXT NOT NULL, seq INTEGER NOT NULL, "
                "status TEXT NOT NULL, occurred_at TEXT NOT NULL, "
                "PRIMARY KEY (tenant_id, request_id, seq))"
            )
            conn.execute(
                "INSERT INTO requests VALUES "
                "('rid-old','tenant-a','ko','s','[\"email\"]','accepted',"
                "'2026-01-01T00:00:00Z')"
            )
            conn.execute(
                "INSERT INTO status_events VALUES "
                "('tenant-a','rid-old',0,'accepted','2026-01-01T00:00:00Z')"
            )
        store = RequestStore(db_path)
        with sqlite3.connect(db_path) as conn:
            # Legacy event row keeps its original timestamp and gains no
            # fabricated keyed tag.
            row = conn.execute(
                "SELECT status, occurred_at, anchor_mac FROM status_events "
                "WHERE request_id='rid-old'"
            ).fetchone()
        self.assertEqual(
            row, ("accepted", "2026-01-01T00:00:00Z", None)
        )
        self.assertFalse(store.verify_evidence("tenant-a", "rid-old"))
        rid = store.submit("tenant-a", "subject-1", ["email"], "kn")["request_id"]
        self.assertTrue(store.verify_evidence("tenant-a", rid))
        # The old record's columns were not rewritten by the new write.
        with sqlite3.connect(db_path) as conn:
            row = conn.execute(
                "SELECT occurred_at, anchor_mac FROM status_events "
                "WHERE request_id='rid-old'"
            ).fetchone()
        self.assertEqual(row, ("2026-01-01T00:00:00Z", None))


if __name__ == "__main__":
    unittest.main()
