"""Security tests for the protected, outside-SQLite audit anchoring.

These tests cover the trust boundary the plain hash chain cannot
provide: the anchor material lives outside SQLite, is reproducible
across rebuilt instances, and an attacker who can arbitrarily rewrite
the database (including recomputing every chain hash and adding
anchor-looking tables of their own) still cannot make
``verify_evidence`` return ``True``.
"""

import hashlib
import io
import logging
import os
import re
import shutil
import sqlite3
import struct
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor

from forgetting_evidence.anchors import AnchorConfig
from forgetting_evidence.requests import (
    EvidenceNotAnchored,
    InvalidStatusTransition,
    RequestNotFound,
    RequestStore,
)

HEX64 = re.compile(r"^[0-9a-f]{64}$")
GENESIS = hashlib.sha256(b"").hexdigest()


def _chain_hash(tenant, request_id, seq, status, occurred_at, predecessor):
    digest = hashlib.sha256()
    for field in (tenant, request_id, str(seq), status, occurred_at, predecessor):
        raw = field.encode("utf-8")
        digest.update(struct.pack(">Q", len(raw)))
        digest.update(raw)
    return digest.hexdigest()


def _file_sha(path):
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def _read_journal(path):
    import json

    with open(path, "rb") as handle:
        return json.loads(handle.read())


def _read_bytes(path):
    with open(path, "rb") as handle:
        return handle.read()


class ProtectedAnchorBasicsTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "nested", "evidence.db")

    def tearDown(self):
        self._tmp.cleanup()

    def test_protected_files_provisioned_next_to_database(self):
        store = RequestStore(self.db_path)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        store.transition("tenant-a", receipt["request_id"], "processing")
        key_path = self.db_path + ".anchor.key"
        journal_path = self.db_path + ".anchor"
        self.assertTrue(os.path.exists(key_path))
        self.assertTrue(os.path.exists(journal_path))
        # Secret material must not be world/group readable.
        self.assertEqual(os.stat(key_path).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(journal_path).st_mode & 0o777, 0o600)

    def test_default_rebuild_verifies_new_requests(self):
        store = RequestStore(self.db_path)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        store.transition("tenant-a", receipt["request_id"], "processing")
        store.transition("tenant-a", receipt["request_id"], "completed")
        rebuilt = RequestStore(self.db_path)
        self.assertTrue(rebuilt.verify_evidence("tenant-a", receipt["request_id"]))

    def test_database_copied_without_protected_files_is_untrusted(self):
        store = RequestStore(self.db_path)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        clone_dir = tempfile.mkdtemp(dir=self._tmp.name)
        clone_db = os.path.join(clone_dir, "evidence.db")
        shutil.copy(self.db_path, clone_db)
        cloned = RequestStore(clone_db)
        with self.assertRaises(EvidenceNotAnchored):
            cloned.verify_evidence("tenant-a", receipt["request_id"])

    def test_database_copied_with_protected_files_verifies(self):
        store = RequestStore(self.db_path)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        store.transition("tenant-a", receipt["request_id"], "failed")
        clone_dir = tempfile.mkdtemp(dir=self._tmp.name)
        clone_db = os.path.join(clone_dir, "evidence.db")
        shutil.copy(self.db_path, clone_db)
        shutil.copy(self.db_path + ".anchor", clone_db + ".anchor")
        shutil.copy(self.db_path + ".anchor.key", clone_db + ".anchor.key")
        cloned = RequestStore(clone_db)
        self.assertTrue(cloned.verify_evidence("tenant-a", receipt["request_id"]))

    def test_journal_holds_no_key_or_head_or_sensitive_data(self):
        secret_subject = "subject-SECRET"
        secret_scope = "scope-SECRET"
        store = RequestStore(self.db_path)
        receipt = store.submit("tenant-a", secret_subject, [secret_scope], "key-1")
        head = store.evidence("tenant-a", receipt["request_id"])["chain_hash"]
        key_bytes = _read_bytes(self.db_path + ".anchor.key")
        journal = _read_bytes(self.db_path + ".anchor")
        # The head is anchored by HMAC, never stored in cleartext form.
        self.assertNotIn(head.encode(), journal)
        # No fragment of the master key leaks into the journal.
        self.assertNotIn(key_bytes, journal)
        for chunk in (key_bytes[:8], key_bytes[-8:]):
            self.assertNotIn(chunk, journal)
        # Coordinates are non-sensitive; payload data is not present.
        self.assertNotIn(secret_subject.encode(), journal)
        self.assertNotIn(secret_scope.encode(), journal)
        self.assertIn(b"version", journal)

    def test_receipts_evidence_audit_and_logs_never_contain_material(self):
        import json

        store = RequestStore(self.db_path)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        store.transition("tenant-a", receipt["request_id"], "processing")
        rid = receipt["request_id"]
        key_bytes = _read_bytes(self.db_path + ".anchor.key")
        doc = _read_journal(self.db_path + ".anchor")
        mac = next(m for t, r, m in doc["entries"] if r == rid)
        self.assertTrue(HEX64.match(mac))

        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        logger = logging.getLogger("forgetting_evidence.requests")
        logger.addHandler(handler)
        old_level = logger.level
        logger.setLevel(logging.DEBUG)
        try:
            rendered = repr(receipt) + repr(store.get("tenant-a", rid))
            rendered += repr(store.audit("tenant-a", rid))
            rendered += repr(store.evidence("tenant-a", rid))
            store.transition("tenant-a", rid, "completed")
        finally:
            logger.removeHandler(handler)
            logger.setLevel(old_level)
        logs = stream.getvalue()
        for secret in (key_bytes, mac.encode()):
            self.assertNotIn(secret, rendered.encode())
            self.assertNotIn(secret, logs.encode())


class FullDatabaseRewriteTests(unittest.TestCase):
    """The decisive threat: attacker rewrites everything inside SQLite."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "evidence.db")
        store = RequestStore(self.db_path)
        self.receipt = store.submit("tenant-a", "subject-1", ["email"], "key-1")
        store.transition("tenant-a", self.receipt["request_id"], "processing")
        self.rid = self.receipt["request_id"]

    def tearDown(self):
        self._tmp.cleanup()

    def _rewrite_entire_database(self, status_for_all="failed"):
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT seq, occurred_at FROM status_events "
                "WHERE request_id = ? ORDER BY seq",
                (self.rid,),
            ).fetchall()
            predecessor = GENESIS
            for seq, occurred_at in rows:
                link = _chain_hash(
                    "tenant-a",
                    self.rid,
                    seq,
                    status_for_all,
                    occurred_at,
                    predecessor,
                )
                conn.execute(
                    "UPDATE status_events SET status = ?, chain_hash = ? "
                    "WHERE request_id = ? AND seq = ?",
                    (status_for_all, link, self.rid, seq),
                )
                predecessor = link
            conn.execute(
                "UPDATE requests SET status = ?, chain_hash = ? WHERE request_id = ?",
                (status_for_all, predecessor, self.rid),
            )

    def test_full_recompute_after_rewrite_still_returns_false(self):
        self._rewrite_entire_database()
        # Rebuilt instance, as an attacker's verifier would use.
        self.assertFalse(
            RequestStore(self.db_path).verify_evidence("tenant-a", self.rid)
        )

    def test_rewrite_plus_attacker_anchor_table_in_sqlite_still_false(self):
        self._rewrite_entire_database()
        with sqlite3.connect(self.db_path) as conn:
            # Any anchor state the attacker can put *inside* the database
            # must be irrelevant to the trust decision.
            conn.execute(
                "CREATE TABLE forged_anchors (tenant_id TEXT, request_id TEXT, mac TEXT)"
            )
            conn.execute(
                "INSERT INTO forged_anchors VALUES ('tenant-a', ?, ?)",
                (self.rid, "a" * 64),
            )
        self.assertFalse(
            RequestStore(self.db_path).verify_evidence("tenant-a", self.rid)
        )

    def test_delete_anchor_journal_is_explicitly_untrusted(self):
        os.unlink(self.db_path + ".anchor")
        with self.assertRaises(EvidenceNotAnchored):
            RequestStore(self.db_path).verify_evidence("tenant-a", self.rid)

    def test_delete_key_is_explicitly_untrusted(self):
        os.unlink(self.db_path + ".anchor.key")
        with self.assertRaises(EvidenceNotAnchored):
            RequestStore(self.db_path).verify_evidence("tenant-a", self.rid)

    def test_replace_key_with_different_secret_fails(self):
        # Attacker "rotates" the key file to a value they chose.
        with open(self.db_path + ".anchor.key", "wb") as handle:
            handle.write(b"attacker-chosen-secret-passphrase-1234")
        self.assertFalse(
            RequestStore(self.db_path).verify_evidence("tenant-a", self.rid)
        )

    def test_corrupt_journal_fails_closed(self):
        with open(self.db_path + ".anchor", "wb") as handle:
            handle.write(b"{not valid json")
        with self.assertRaises(EvidenceNotAnchored):
            RequestStore(self.db_path).verify_evidence("tenant-a", self.rid)

    def test_modify_journal_mac_fails(self):
        import json

        path = self.db_path + ".anchor"
        doc = _read_journal(path)
        tenant, request_id, mac = doc["entries"][0]
        flipped = ("0" if mac[0] != "0" else "1") + mac[1:]
        doc["entries"][0] = [tenant, request_id, flipped]
        with open(path, "w") as handle:
            json.dump(doc, handle)
        self.assertFalse(
            RequestStore(self.db_path).verify_evidence("tenant-a", self.rid)
        )

    def test_foreign_journal_and_key_from_another_database_fail(self):
        other_dir = tempfile.mkdtemp(dir=self._tmp.name)
        other_db = os.path.join(other_dir, "other.db")
        other = RequestStore(other_db)
        other.submit("tenant-a", "subject-1", ["email"], "key-1")
        shutil.copy(other_db + ".anchor", self.db_path + ".anchor")
        shutil.copy(other_db + ".anchor.key", self.db_path + ".anchor.key")
        # The foreign journal carries no anchor for this request id.
        with self.assertRaises(EvidenceNotAnchored):
            RequestStore(self.db_path).verify_evidence("tenant-a", self.rid)


class AnchorBindingTests(unittest.TestCase):
    """Anchors bind tenant AND request AND head; none is substitutable."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "evidence.db")
        self.store = RequestStore(self.db_path)

    def tearDown(self):
        self._tmp.cleanup()

    def test_head_substitution_between_requests_fails(self):
        one = self.store.submit("tenant-a", "subject-1", ["email"], "key-1")
        two = self.store.submit("tenant-a", "subject-2", ["email"], "key-2")
        with sqlite3.connect(self.db_path) as conn:
            head_one = conn.execute(
                "SELECT chain_hash FROM requests WHERE request_id = ?",
                (one["request_id"],),
            ).fetchone()[0]
            conn.execute(
                "UPDATE requests SET chain_hash = ? WHERE request_id = ?",
                (head_one, two["request_id"]),
            )
        self.assertFalse(
            self.store.verify_evidence("tenant-a", two["request_id"])
        )
        self.assertTrue(
            self.store.verify_evidence("tenant-a", one["request_id"])
        )

    def test_head_substitution_between_tenants_fails(self):
        a = self.store.submit("tenant-a", "subject-1", ["email"], "k")
        b = self.store.submit("tenant-b", "subject-1", ["email"], "k")
        with sqlite3.connect(self.db_path) as conn:
            head_a = conn.execute(
                "SELECT chain_hash FROM requests WHERE request_id = ?",
                (a["request_id"],),
            ).fetchone()[0]
            conn.execute(
                "UPDATE requests SET chain_hash = ? WHERE request_id = ?",
                (head_a, b["request_id"]),
            )
        self.assertFalse(
            self.store.verify_evidence("tenant-b", b["request_id"])
        )

    def test_copying_anchor_entry_under_another_coordinate_fails(self):
        # Even if an attacker can write the anchor journal, moving a
        # valid mac to another (tenant, request) coordinate must not
        # authenticate that coordinate's head: the preimage binds both.
        one = self.store.submit("tenant-a", "subject-1", ["email"], "k1")
        two = self.store.submit("tenant-a", "subject-2", ["email"], "k2")
        import json

        path = self.db_path + ".anchor"
        doc = _read_journal(path)
        by_coord = {(t, r): mac for t, r, mac in doc["entries"]}
        mac_one = by_coord[("tenant-a", one["request_id"])]
        doc["entries"] = [
            ["tenant-a", two["request_id"], mac_one]
        ]
        with open(path, "wb") as handle:
            handle.write(json.dumps(doc, separators=(",", ":")).encode())
        self.assertFalse(
            RequestStore(self.db_path).verify_evidence(
                "tenant-a", two["request_id"]
            )
        )


class NoEvidenceMutationTests(unittest.TestCase):
    """Failed/replayed calls must never alter protected evidence."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "evidence.db")
        self.store = RequestStore(self.db_path)
        self.receipt = self.store.submit(
            "tenant-a", "subject-1", ["email"], "key-1"
        )
        self.rid = self.receipt["request_id"]

    def tearDown(self):
        self._tmp.cleanup()

    def _journal_hash(self):
        return _file_sha(self.db_path + ".anchor")

    def test_same_status_replay_does_not_advance_anchor(self):
        before = self._journal_hash()
        self.store.transition("tenant-a", self.rid, "accepted")
        self.assertEqual(before, self._journal_hash())
        self.store.transition("tenant-a", self.rid, "processing")
        after_processing = self._journal_hash()
        self.assertNotEqual(before, after_processing)
        self.store.transition("tenant-a", self.rid, "processing")
        self.assertEqual(after_processing, self._journal_hash())

    def test_illegal_transitions_and_validation_do_not_touch_anchor(self):
        before = self._journal_hash()
        with self.assertRaises(InvalidStatusTransition):
            self.store.transition("tenant-a", self.rid, "completed")
        with self.assertRaises(InvalidStatusTransition):
            self.store.transition("tenant-a", self.rid, "cancelled")
        for bad in ("", None, 7, b"x"):
            with self.assertRaises(ValueError):
                self.store.transition(bad, self.rid, "processing")
            with self.assertRaises(ValueError):
                self.store.transition("tenant-a", self.rid, bad)
        for bad in ("", None, 7):
            with self.assertRaises(ValueError):
                self.store.submit(bad, "subject-1", ["email"], "k")
        with self.assertRaises(RequestNotFound):
            self.store.transition("tenant-a", "missing-id", "processing")
        self.assertEqual(before, self._journal_hash())

    def test_verify_and_evidence_and_reads_never_write(self):
        db_before = _file_sha(self.db_path)
        journal_before = self._journal_hash()
        key_before = _file_sha(self.db_path + ".anchor.key")
        for _ in range(5):
            self.assertTrue(self.store.verify_evidence("tenant-a", self.rid))
        self.store.evidence("tenant-a", self.rid)
        self.store.audit("tenant-a", self.rid)
        self.store.get("tenant-a", self.rid)
        with self.assertRaises(RequestNotFound):
            self.store.verify_evidence("tenant-a", "missing")
        with self.assertRaises(RequestNotFound):
            self.store.verify_evidence("tenant-b", self.rid)
        self.assertEqual(db_before, _file_sha(self.db_path))
        self.assertEqual(journal_before, self._journal_hash())
        self.assertEqual(key_before, _file_sha(self.db_path + ".anchor.key"))

    def test_missing_anchor_on_transition_changes_nothing(self):
        # With the journal removed, a transition must be refused before
        # any mutation: status, events and journal state stay as they
        # were.
        os.unlink(self.db_path + ".anchor")
        self.assertFalse(os.path.exists(self.db_path + ".anchor"))
        with self.assertRaises(EvidenceNotAnchored):
            self.store.transition("tenant-a", self.rid, "processing")
        self.assertEqual(
            self.store.get("tenant-a", self.rid)["status"], "accepted"
        )
        self.assertEqual(
            [e["status"] for e in self.store.audit("tenant-a", self.rid)],
            ["accepted"],
        )
        self.assertFalse(os.path.exists(self.db_path + ".anchor"))

    def test_idempotent_replay_works_even_without_anchor_journal(self):
        # A same-status replay performs no write at all, so it must not
        # require protected material and must not create any.
        os.unlink(self.db_path + ".anchor")
        replay = self.store.transition("tenant-a", self.rid, "accepted")
        self.assertEqual(replay["status"], "accepted")
        self.assertFalse(os.path.exists(self.db_path + ".anchor"))


class AnchorConfigTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self._tmp.cleanup()

    def test_injected_bytes_key_across_rebuilds(self):
        db_path = os.path.join(self._tmp.name, "a.db")
        cfg = AnchorConfig(key=b"shared-master-secret-value")
        store = RequestStore(db_path, anchor_config=cfg)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "k")
        store.transition("tenant-a", receipt["request_id"], "processing")
        rebuilt = RequestStore(
            db_path, anchor_config=AnchorConfig(key=b"shared-master-secret-value")
        )
        self.assertTrue(rebuilt.verify_evidence("tenant-a", receipt["request_id"]))
        # The default key file must not be created when a key is injected.
        self.assertFalse(os.path.exists(db_path + ".anchor.key"))

    def test_wrong_injected_key_fails(self):
        db_path = os.path.join(self._tmp.name, "b.db")
        store = RequestStore(db_path, anchor_config=AnchorConfig(key=b"right-key"))
        receipt = store.submit("tenant-a", "subject-1", ["email"], "k")
        rebuilt = RequestStore(
            db_path, anchor_config=AnchorConfig(key=b"wrong-key")
        )
        self.assertFalse(rebuilt.verify_evidence("tenant-a", receipt["request_id"]))

    def test_key_file_configuration(self):
        db_path = os.path.join(self._tmp.name, "c.db")
        key_file = os.path.join(self._tmp.name, "secrets", "master.key")
        cfg = AnchorConfig(key_file=key_file)
        store = RequestStore(db_path, anchor_config=cfg)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "k")
        self.assertTrue(os.path.exists(key_file))
        rebuilt = RequestStore(db_path, anchor_config=AnchorConfig(key_file=key_file))
        self.assertTrue(rebuilt.verify_evidence("tenant-a", receipt["request_id"]))

    def test_key_hex_configuration(self):
        db_path = os.path.join(self._tmp.name, "d.db")
        secret = hashlib.sha256(b"passphrase").hexdigest()
        store = RequestStore(db_path, anchor_config=AnchorConfig(key_hex=secret))
        receipt = store.submit("tenant-a", "subject-1", ["email"], "k")
        rebuilt = RequestStore(
            db_path, anchor_config=AnchorConfig(key_hex=secret)
        )
        self.assertTrue(rebuilt.verify_evidence("tenant-a", receipt["request_id"]))

    def test_external_anchor_file_location(self):
        db_path = os.path.join(self._tmp.name, "e.db")
        anchor_file = os.path.join(self._tmp.name, "elsewhere", "anchors.json")
        store = RequestStore(
            db_path, anchor_config=AnchorConfig(anchor_file=anchor_file)
        )
        receipt = store.submit("tenant-a", "subject-1", ["email"], "k")
        self.assertTrue(os.path.exists(anchor_file))
        self.assertFalse(os.path.exists(db_path + ".anchor"))
        rebuilt = RequestStore(
            db_path, anchor_config=AnchorConfig(anchor_file=anchor_file)
        )
        self.assertTrue(rebuilt.verify_evidence("tenant-a", receipt["request_id"]))

    def test_auto_init_false_refuses_to_provision(self):
        db_path = os.path.join(self._tmp.name, "f.db")
        store = RequestStore(db_path, anchor_config=AnchorConfig(auto_init=False))
        with self.assertRaises(RuntimeError):
            store.submit("tenant-a", "subject-1", ["email"], "k")
        self.assertFalse(os.path.exists(db_path + ".anchor"))
        self.assertFalse(os.path.exists(db_path + ".anchor.key"))

    def test_invalid_config_rejected(self):
        with self.assertRaises(ValueError):
            AnchorConfig(key=b"", key_hex="aa")
        with self.assertRaises(ValueError):
            AnchorConfig(key_hex="not-hex")
        with self.assertRaises(ValueError):
            AnchorConfig(key=b"")
        with self.assertRaises(ValueError):
            AnchorConfig(key=b"x" * 5000)


class InMemoryAnchorTests(unittest.TestCase):
    def test_in_memory_anchors_protect_within_process(self):
        store = RequestStore(":memory:")
        receipt = store.submit("tenant-a", "subject-1", ["email"], "k")
        store.transition("tenant-a", receipt["request_id"], "processing")
        self.assertTrue(store.verify_evidence("tenant-a", receipt["request_id"]))
        # Direct connection tampering still cannot pass verification.
        conn = store._mem_conn
        conn.execute(
            "UPDATE status_events SET occurred_at = occurred_at || 'X' "
            "WHERE request_id = ? AND seq = 0",
            (receipt["request_id"],),
        )
        self.assertFalse(store.verify_evidence("tenant-a", receipt["request_id"]))


class MultiWriterAnchorTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "evidence.db")

    def tearDown(self):
        self._tmp.cleanup()

    def test_concurrent_writers_keep_a_single_consistent_journal(self):
        first = RequestStore(self.db_path)
        receipts = [
            first.submit("tenant-a", f"subject-{i}", ["email"], f"key-{i}")
            for i in range(8)
        ]

        def worker(item):
            index, receipt = item
            store = RequestStore(self.db_path)  # independent connection
            for target in ("processing", "completed"):
                try:
                    store.transition("tenant-a", receipt["request_id"], target)
                except InvalidStatusTransition:
                    pass
            return store.verify_evidence("tenant-a", receipt["request_id"])

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(worker, enumerate(receipts)))
        self.assertTrue(all(results))
        rebuilt = RequestStore(self.db_path)
        for receipt in receipts:
            self.assertTrue(
                rebuilt.verify_evidence("tenant-a", receipt["request_id"])
            )
        # The journal still contains exactly one anchor per request.
        import json

        doc = _read_journal(self.db_path + ".anchor")
        coords = [(t, r) for t, r, _ in doc["entries"]]
        self.assertEqual(len(coords), len(set(coords)))
        self.assertEqual(len(coords), len(receipts))

    def test_concurrent_verify_during_transitions_never_falsely_fails(self):
        store = RequestStore(self.db_path)
        receipt = store.submit("tenant-a", "subject-1", ["email"], "k")
        failures = []

        def writer():
            for target in ("processing", "completed"):
                store.transition("tenant-a", receipt["request_id"], target)

        def reader(_):
            for _ in range(50):
                try:
                    if not store.verify_evidence(
                        "tenant-a", receipt["request_id"]
                    ):
                        failures.append("false")
                except EvidenceNotAnchored:
                    failures.append("unanchored")

        with ThreadPoolExecutor(max_workers=6) as pool:
            jobs = [pool.submit(writer)]
            jobs += [pool.submit(reader, i) for i in range(5)]
            for job in jobs:
                job.result()
        self.assertEqual(failures, [])
        self.assertTrue(
            RequestStore(self.db_path).verify_evidence(
                "tenant-a", receipt["request_id"]
            )
        )


if __name__ == "__main__":
    unittest.main()
