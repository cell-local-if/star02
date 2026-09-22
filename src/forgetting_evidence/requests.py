"""SQLite-backed acceptance store for deletion requests.

The store records deletion requests without retaining any identifying
payload in logs, return values beyond the fixed receipt fields, or
exception messages. SQLite integrity conflicts are translated into the
module's own idempotency semantics and never surface to callers.

Every accepted request carries a persistent, append-only status timeline
in ``status_events``. Events are written in the same transaction as the
request row or status change they describe, so the final timeline entry
always matches the request's current status.

Each event additionally carries a tamper-evident ``chain_hash``: a
SHA-256 value binding the tenant, request, sequence number, status,
occurrence time and the previous event's hash. The hash of the final
event is also stored on the request row, so deleting, modifying,
inserting or reordering persisted events breaks verification. The hash
preimage is never exposed in return values, exceptions or logs.

External anchoring (trusted mode)
---------------------------------

A keyless store only attests itself: the chain and the row that anchors
it live in the same SQLite file, so a party able to rewrite the database
can recompute every link. When ``integrity_key`` is supplied (and an
optional explicit ``anchor_path``) the store additionally maintains a
write-ahead *anchor sidecar* outside SQLite:

* Every sidecar record is an HMAC-SHA256 envelope keyed with the
  caller-held ``integrity_key`` and binds one audit-chain head hash. The
  key lives only in process memory: it is never written to SQLite, the
  sidecar, receipts, exceptions or logs, and neither is the assembled
  chain preimage nor any material from which the key could be derived.
* Each accepted request or actual status transition is persisted with a
  recoverable intent/commit protocol: an authenticated ``intent`` record
  naming the new chain head is fsynced to the sidecar *before* the SQLite
  transaction commits, and an authenticated ``confirmed`` record follows
  the commit; a rolled-back transaction gets an ``aborted`` marker.
  Recomputing or replacing all public SQLite/sidecar content cannot
  forge a valid envelope without the key.
* ``verify_evidence`` therefore succeeds only when the internal chain
  recomputes *and* every one of its heads is covered by an authenticated,
  confirmed sidecar record, with the sidecar tip carrying no unclosed
  intent. A missing or corrupt sidecar, a head/anchor mismatch, a
  database created before trusted anchoring, or an interrupted commit
  all yield ``False``.
* ``recover()`` is strictly read-only and reports ``"valid"``,
  ``"invalid"`` or ``"incomplete"``; it never repairs, backfills or
  writes evidence.

Stores constructed without ``integrity_key`` keep the legacy,
self-attested behaviour unchanged.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import hmac
import json
import logging
import os
import sqlite3
import struct
import threading
import uuid
from collections.abc import Mapping
from datetime import datetime, timezone

__all__ = [
    "RequestStore",
    "IdempotencyConflict",
    "RequestNotFound",
    "InvalidStatusTransition",
]

_log = logging.getLogger(__name__)


class IdempotencyConflict(Exception):
    """Raised when an idempotency key is reused with a different payload."""


class RequestNotFound(Exception):
    """Raised when no request visible to the tenant matches the id."""


class InvalidStatusTransition(Exception):
    """Raised when a requested status change is unknown or not permitted."""


class _PrimaryKeyConflict(Exception):
    """Internal signal: retry insertion with a freshly generated id."""


_SCHEMA = """
CREATE TABLE IF NOT EXISTS requests (
    request_id      TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    subject_id      TEXT NOT NULL,
    scopes_json     TEXT NOT NULL,
    status          TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    chain_hash      TEXT NOT NULL
);
"""

_UNIQUE_TENANT_KEY = """
CREATE UNIQUE INDEX IF NOT EXISTS idx_requests_tenant_idempotency
    ON requests(tenant_id, idempotency_key);
"""

_EVENT_TABLE = """
CREATE TABLE IF NOT EXISTS status_events (
    tenant_id   TEXT NOT NULL,
    request_id  TEXT NOT NULL,
    seq         INTEGER NOT NULL,
    status      TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    chain_hash  TEXT NOT NULL,
    PRIMARY KEY (tenant_id, request_id, seq)
);
"""

# The composite primary key already indexes (tenant_id, request_id, seq),
# which serves both the ordered timeline read and the latest-event lookup.

# Column probes used to upgrade database files created before chain
# hashes existed. The upgrade is purely additive (nullable columns plus a
# one-time backfill derived from the already-persisted timeline); it never
# overwrites existing chain evidence.
_REQUEST_CHAIN_COLUMN = (
    "SELECT 1 FROM pragma_table_info('requests') WHERE name = 'chain_hash'"
)
_EVENT_CHAIN_COLUMN = (
    "SELECT 1 FROM pragma_table_info('status_events') WHERE name = 'chain_hash'"
)

_BUSY_TIMEOUT_MS = 30_000
# A UUIDv4 primary-key collision is astronomically unlikely; the bound
# only keeps that conflict distinct from idempotency conflicts.
_MAX_INSERT_ATTEMPTS = 3

# Allowed request lifecycle. completed and failed are terminal; moving a
# request to the status it already holds is an idempotent no-op.
_STATUS_ACCEPTED = "accepted"
_STATUS_PROCESSING = "processing"
_STATUS_COMPLETED = "completed"
_STATUS_FAILED = "failed"
_ALLOWED_TRANSITIONS: dict[str, frozenset[str]] = {
    _STATUS_ACCEPTED: frozenset({_STATUS_PROCESSING, _STATUS_FAILED}),
    _STATUS_PROCESSING: frozenset({_STATUS_COMPLETED, _STATUS_FAILED}),
    _STATUS_COMPLETED: frozenset(),
    _STATUS_FAILED: frozenset(),
}


def _require_nonempty_str(value: object, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _normalize_scopes(scopes: object) -> list[str]:
    # Strings, bytes and mappings are iterable but are not scope sequences.
    if isinstance(scopes, (str, bytes)) or isinstance(scopes, Mapping):
        raise ValueError("scopes must be a non-empty sequence of distinct strings")
    try:
        items = list(scopes)  # type: ignore[arg-type]
    except TypeError as exc:
        raise ValueError("scopes must be a non-empty sequence of distinct strings") from exc
    if not items or not all(isinstance(item, str) for item in items):
        raise ValueError("scopes must be a non-empty sequence of distinct strings")
    if len(set(items)) != len(items):
        raise ValueError("scopes must be a non-empty sequence of distinct strings")
    # Canonical order so scope ordering never affects comparison.
    return sorted(items)


def _utc_now_rfc3339() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _occurred_at_not_before(latest: str) -> str:
    """Return a UTC timestamp that is never earlier than ``latest``.

    ISO-8601 timestamps produced by :func:`_utc_now_rfc3339` sort
    lexicographically, so the comparison stays purely textual. If the
    clock produces a value earlier than the previous event's, reuse the
    previous timestamp so the timeline can never go backwards.
    """
    now = _utc_now_rfc3339()
    return now if now >= latest else latest


# SHA-256 of the empty string: the predecessor of the genesis event.
# A fixed non-derived sentinel keeps the first event distinguishable
# from an event chained onto a forged 64-character predecessor.
_GENESIS_PREDECESSOR = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
_HEX = "0123456789abcdef"


def _chain_hash(
    tenant_id: str,
    request_id: str,
    seq: int,
    status: str,
    occurred_at: str,
    predecessor: str,
) -> str:
    """Hash one audit-chain link.

    The digest binds the tenant, request, per-request event sequence,
    status and occurrence time together with the preceding link's hash.
    Every field is length-prefixed so no concatenation can be re-parsed
    two ways, and UTF-8 encoding is fixed so stored text round-trips
    byte-for-byte. The preimage itself is never persisted or returned.
    """
    digest = hashlib.sha256()
    for field in (tenant_id, request_id, str(seq), status, occurred_at, predecessor):
        encoded = field.encode("utf-8")
        digest.update(struct.pack(">Q", len(encoded)))
        digest.update(encoded)
    return digest.hexdigest()


def _is_chain_hash(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in _HEX for char in value)
    )


# ---------------------------------------------------------------------------
# Trusted anchor sidecar
# ---------------------------------------------------------------------------

# Sidecar envelope version and record kinds.
_ANCHOR_VERSION = 1
_ANCHOR_INTENT = "intent"
_ANCHOR_CONFIRMED = "confirmed"
_ANCHOR_ABORTED = "aborted"
_ANCHOR_CLOSE_KINDS = frozenset({_ANCHOR_CONFIRMED, _ANCHOR_ABORTED})

# Fixed predecessor of the first sidecar record, independent of the
# audit-chain genesis so the two ledgers cannot be spliced together.
_ANCHOR_GENESIS = hashlib.sha256(
    b"forgetting-evidence/anchor-genesis/v1"
).hexdigest()

# Envelopes deliberately name only the event's chain head. The head is a
# hash output and already commits to every event field, so none of the
# chain-preimage inputs (and no key-derived material) is duplicated here.
_INTENT_FIELDS = ("v", "a", "h", "p", "n")
_CLOSER_FIELDS = ("v", "a", "h", "p", "n", "ref")


def _normalize_integrity_key(integrity_key: object) -> bytes:
    """Return the raw key bytes without ever copying them to storage."""
    if isinstance(integrity_key, str):
        material = integrity_key.encode("utf-8")
    elif isinstance(integrity_key, bytes):
        material = integrity_key
    else:
        raise ValueError("integrity_key must be a non-empty str or bytes")
    if not material:
        raise ValueError("integrity_key must be a non-empty str or bytes")
    return material


def _anchor_digest(predecessor: str, mac: str) -> str:
    """Public ordering link between consecutive sidecar records.

    Unlike the record MAC this value is unkeyed: it only detects
    reordering/truncation of records and can never substitute for the
    key. Length framing prevents ambiguous concatenation.
    """
    digest = hashlib.sha256()
    for piece in (predecessor, mac):
        encoded = piece.encode("ascii")
        digest.update(struct.pack(">Q", len(encoded)))
        digest.update(encoded)
    return digest.hexdigest()


def _record_mac(key_material: bytes, payload: Mapping[str, object]) -> str:
    # Canonical, locale-independent serialization so the authenticated
    # bytes are identical across processes and dict orderings.
    message = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hmac.new(key_material, message, hashlib.sha256).hexdigest()


class RequestStore:
    """Persist and retrieve accepted deletion requests.

    Construct with ``integrity_key`` (and, optionally, an explicit
    ``anchor_path``) to enable trusted external anchoring. The key is
    supplied by the caller and held only outside SQLite and the sidecar;
    verification of such a store is impossible without it. Without a key
    the store keeps its legacy self-attested behaviour.
    """

    def __init__(
        self,
        db_path: str | os.PathLike[str],
        *,
        anchor_path: str | os.PathLike[str] | None = None,
        integrity_key: str | bytes | None = None,
    ):
        self._db_path = os.fspath(db_path)
        if anchor_path is not None and not isinstance(
            anchor_path, (str, os.PathLike)
        ):
            raise ValueError("anchor_path must be a path or None")
        if anchor_path is not None and integrity_key is None:
            raise ValueError(
                "anchor_path requires integrity_key to enable trusted anchoring"
            )
        # In-process serialization; the unique index additionally guards
        # other processes sharing the same database file.
        self._write_lock = threading.Lock()

        # Trusted anchoring configuration. The key material lives only on
        # the instance; it is never rendered into a file, return value,
        # exception or log record.
        self._integrity_key: bytes | None = (
            _normalize_integrity_key(integrity_key)
            if integrity_key is not None
            else None
        )
        self._anchored = self._integrity_key is not None
        self._anchor_fd: int | None = None
        self._anchor_mem: bytearray | None = None
        # Once an append cannot be made durable the sidecar tip may hold
        # a partial envelope that no later record can safely follow.
        self._anchor_broken = False
        if self._anchored:
            if anchor_path is not None:
                self._anchor_path = os.fspath(anchor_path)
            elif self._db_path == ":memory:":
                self._anchor_path = None
                self._anchor_mem = bytearray()
            else:
                self._anchor_path = self._db_path + ".anchor"
            # The file itself is opened lazily so that merely opening a
            # trusted store (or calling recover() on an empty one) never
            # creates evidence files.

        if self._db_path == ":memory:":
            self._mem_conn: sqlite3.Connection | None = self._open_connection()
        else:
            self._mem_conn = None
            parent = os.path.dirname(os.path.abspath(self._db_path))
            os.makedirs(parent, exist_ok=True)
        conn = self._connect()
        try:
            conn.execute(_SCHEMA)
            conn.execute(_UNIQUE_TENANT_KEY)
            conn.execute(_EVENT_TABLE)
            self._migrate_schema(conn)
        finally:
            self._release(conn)

    # -- sidecar primitives --------------------------------------------

    @contextlib.contextmanager
    def _anchor_lock(self):
        """Hold the cross-process anchor lock across the commit window.

        The caller already holds SQLite's ``BEGIN IMMEDIATE`` reservation
        (which excludes every other writer through the commit) and only
        reaches this point for an actual state change, so opening the
        sidecar here -- with ``O_CREAT`` -- both creates it on the first
        anchored mutation and is skipped entirely by rejected calls. The
        lock is then retained until the post-commit confirmation lands,
        closing the only window that falls outside SQLite's own lock.
        """
        if not self._anchored or self._anchor_mem is not None:
            yield
            return
        fd = self._ensure_anchor_fd()
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)

    def _ensure_anchor_fd(self) -> int:
        """Open (creating) the sidecar file exactly when a write begins."""
        if self._anchor_fd is None:
            parent = os.path.dirname(os.path.abspath(self._anchor_path))
            try:
                os.makedirs(parent, exist_ok=True)
                # Owner-only permissions; O_APPEND makes every durable record
                # a single trailing append, and the persistent fd is also the
                # lock object serializing writer processes.
                flags = os.O_RDWR | os.O_CREAT | os.O_APPEND
                flags |= getattr(os, "O_CLOEXEC", 0)
                self._anchor_fd = os.open(self._anchor_path, flags, 0o600)
            except OSError:
                self._anchor_broken = True
                raise RuntimeError("failed to persist audit anchor") from None
        return self._anchor_fd

    def _read_sidecar_bytes(self) -> bytes | None:
        """Read the sidecar without creating, truncating or writing it."""
        if not self._anchored:
            return None
        if self._anchor_mem is not None:
            return bytes(self._anchor_mem)
        try:
            with open(self._anchor_path, "rb") as handle:
                return handle.read()
        except OSError:
            return None

    def _append_sidecar(self, payload: Mapping[str, object]) -> str:
        """Append and fsync one MAC'd envelope; return its anchor digest.

        Raises RuntimeError on any durability failure; the caller is
        responsible for resolving the SQLite transaction consistently.
        """
        if self._anchor_broken:
            raise RuntimeError("anchor sidecar is unavailable")
        envelope = dict(payload)
        mac = _record_mac(self._integrity_key, envelope)
        envelope["mac"] = mac
        line = (
            json.dumps(
                envelope,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            )
            + "\n"
        ).encode("utf-8")
        try:
            if self._anchor_mem is not None:
                self._anchor_mem.extend(line)
            else:
                fd = self._ensure_anchor_fd()
                view = memoryview(line)
                while view:
                    written = os.write(fd, view)
                    view = view[written:]
                os.fsync(fd)
        except OSError:
            # The on-disk tip may now contain a partial envelope that
            # cannot be safely appended past in this process.
            self._anchor_broken = True
            raise RuntimeError("failed to persist audit anchor") from None
        return _anchor_digest(str(payload["p"]), mac)

    @staticmethod
    def _well_formed_envelope(record: object) -> bool:
        if not isinstance(record, dict):
            return False
        kind = record.get("a")
        if kind == _ANCHOR_INTENT:
            required = set(_INTENT_FIELDS)
        elif kind in _ANCHOR_CLOSE_KINDS:
            required = set(_CLOSER_FIELDS)
        else:
            return False
        required.add("mac")
        if set(record) != required:
            return False
        if record["v"] != _ANCHOR_VERSION:
            return False
        for key in ("h", "p", "n", "mac"):
            value = record[key]
            if not isinstance(value, str) or not value:
                return False
        if not (
            _is_chain_hash(record["h"])
            and _is_chain_hash(record["p"])
            and _is_chain_hash(record["mac"])
        ):
            return False
        if kind in _ANCHOR_CLOSE_KINDS:
            ref = record["ref"]
            if not isinstance(ref, str) or not ref:
                return False
        return True

    def _parse_sidecar(
        self,
    ) -> tuple[list[dict[str, object]] | None, bool]:
        """Parse, authenticate and order every sidecar envelope.

        Returns ``(records, torn)``. ``records`` is ``None`` if the log is
        absent or fails any structural, MAC or ordering check; a single
        physically-torn final line (a write interrupted mid-record) is
        reported as ``torn=True`` with the preceding records returned.
        """
        raw = self._read_sidecar_bytes()
        if raw is None:
            return None, False
        return self._parse_sidecar_from_bytes(raw)

    def _parse_sidecar_from_bytes(
        self, raw: bytes
    ) -> tuple[list[dict[str, object]] | None, bool]:
        if not raw:
            return [], False
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return None, False
        lines = text.split("\n")
        # A trailing "" after the final newline is expected. Any other
        # empty line is tampering.
        if lines and lines[-1] == "":
            lines.pop()
        records: list[dict[str, object]] = []
        for index, line in enumerate(lines):
            if not line:
                return None, False
            try:
                record = json.loads(line)
            except ValueError:
                # Only the last line may be a physically torn append.
                if index == len(lines) - 1:
                    return records, True
                return None, False
            if not self._well_formed_envelope(record):
                return None, False
            records.append(record)

        expected_prev = _ANCHOR_GENESIS
        seen_nonces: set[str] = set()
        for record in records:
            nonce = record["n"]
            if nonce in seen_nonces:
                return None, False
            seen_nonces.add(nonce)
            if record["p"] != expected_prev:
                return None, False
            payload = {key: record[key] for key in record if key != "mac"}
            if not hmac.compare_digest(
                _record_mac(self._integrity_key, payload), record["mac"]
            ):
                return None, False
            expected_prev = _anchor_digest(record["p"], record["mac"])
        return records, False

    def _sidecar_snapshot(
        self,
    ) -> tuple[list[str], str | None, bool] | None:
        """Return the sidecar's confirmed anchors and open state.

        Returns ``(confirmed_heads, dangling_head, torn)``:

        * ``dangling_head is None`` and ``torn`` false -- the log ends in
          a closed pair;
        * ``dangling_head`` is a hash -- an authenticated intent at the
          tip was never closed (an interrupted commit); the value is the
          head it named;
        * ``torn`` true -- the physical final append is incomplete.

        Returns ``None`` when the sidecar is absent or fails any
        structural, MAC or pairing check.
        """
        records, torn = self._parse_sidecar()
        if records is None:
            return None
        confirmed: list[str] = []
        index = 0
        while index + 1 < len(records):
            opener = records[index]
            closer = records[index + 1]
            if opener["a"] != _ANCHOR_INTENT or closer["a"] not in _ANCHOR_CLOSE_KINDS:
                return None
            if closer.get("ref") != opener["n"] or closer["h"] != opener["h"]:
                return None
            if closer["a"] == _ANCHOR_CONFIRMED:
                confirmed.append(opener["h"])
            index += 2
        if index < len(records):
            opener = records[index]
            if opener["a"] != _ANCHOR_INTENT:
                return None
            return confirmed, opener["h"], torn
        return confirmed, None, torn

    def _tip_anchor(self, records: list[dict[str, object]]) -> str:
        """Append-point anchor after the given authenticated records."""
        tip = _ANCHOR_GENESIS
        for record in records:
            tip = _anchor_digest(tip, record["mac"])
        return tip

    def _head_committed(
        self, conn: sqlite3.Connection, head: str
    ) -> bool:
        """Whether an event carrying exactly ``head`` durably committed.

        The event row and its request-row update share one transaction,
        so the presence of the authenticated head among persisted events
        is equivalent to that transaction having committed.
        """
        try:
            row = conn.execute(
                "SELECT 1 FROM status_events WHERE chain_hash = ? LIMIT 1",
                (head,),
            ).fetchone()
        except sqlite3.Error:
            raise RuntimeError("failed to reconcile audit anchor") from None
        return row is not None

    def _reconcile_tip(
        self, conn: sqlite3.Connection
    ) -> list[dict[str, object]]:
        """Recover an interrupted tip; return the authenticated records.

        Two interruptions are healed (never fabricated): a physically
        torn final append is truncated back to the last complete record,
        and a fully-written but unclosed intent is closed from the
        durable SQLite state -- ``confirmed`` when its exact head is
        present, ``aborted`` otherwise. A log that fails structural or
        MAC verification at any complete record is unrecoverable.
        """
        raw = self._read_sidecar_bytes()
        if raw is None or not raw:
            # The sidecar has never been created: this is the first
            # anchored mutation for this database.
            return []
        records, torn = self._parse_sidecar_from_bytes(raw)
        if records is None:
            self._anchor_broken = True
            raise RuntimeError("anchor sidecar is unrecoverable")
        if torn:
            self._truncate_torn_tail(raw, len(records))
            raw = self._read_sidecar_bytes() or b""
            records, torn = self._parse_sidecar_from_bytes(raw)
            if records is None or torn:
                self._anchor_broken = True
                raise RuntimeError("anchor sidecar is unrecoverable")
        if len(records) % 2 == 0:
            return records
        opener = records[-1]
        if opener["a"] != _ANCHOR_INTENT:
            self._anchor_broken = True
            raise RuntimeError("anchor sidecar is unrecoverable")
        kind = (
            _ANCHOR_CONFIRMED
            if self._head_committed(conn, opener["h"])
            else _ANCHOR_ABORTED
        )
        closer = {
            "v": _ANCHOR_VERSION,
            "a": kind,
            "h": opener["h"],
            "p": self._tip_anchor(records),
            "n": uuid.uuid4().hex,
            "ref": opener["n"],
        }
        self._append_sidecar(closer)
        records.append(dict(closer, mac=_record_mac(self._integrity_key, closer)))
        return records

    def _truncate_torn_tail(self, raw: bytes, valid_record_count: int) -> None:
        """Drop bytes after the last complete newline-terminated record.

        Complete records occupy the first ``valid_record_count`` lines;
        truncating there removes a partial append atomically before any
        new record is written. Only ever called while holding the anchor
        lock and SQLite's write reservation.
        """
        valid_len = 0
        remaining = raw
        for _ in range(valid_record_count):
            newline = remaining.find(b"\n")
            if newline < 0:
                self._anchor_broken = True
                raise RuntimeError("anchor sidecar is unrecoverable")
            valid_len += newline + 1
            remaining = remaining[newline + 1:]
        try:
            fd = os.open(
                self._anchor_path,
                os.O_RDWR | getattr(os, "O_CLOEXEC", 0),
            )
            try:
                os.ftruncate(fd, valid_len)
                os.fsync(fd)
            finally:
                os.close(fd)
        except OSError:
            self._anchor_broken = True
            raise RuntimeError("anchor sidecar is unrecoverable") from None

    def _anchor_intent(self, conn: sqlite3.Connection, head: str) -> dict[str, object]:
        """Reconcile an interrupted tip, then persist the new intent."""
        records = self._reconcile_tip(conn)
        envelope = {
            "v": _ANCHOR_VERSION,
            "a": _ANCHOR_INTENT,
            "h": head,
            "p": self._tip_anchor(records),
            "n": uuid.uuid4().hex,
        }
        anchor = self._append_sidecar(envelope)
        intent = dict(envelope)
        intent["mac"] = _record_mac(self._integrity_key, envelope)
        intent["_anchor"] = anchor
        return intent

    def _anchor_close(
        self, intent: Mapping[str, object], *, committed: bool
    ) -> None:
        """Append the post-commit confirmation (or an abort marker)."""
        closer = {
            "v": _ANCHOR_VERSION,
            "a": _ANCHOR_CONFIRMED if committed else _ANCHOR_ABORTED,
            "h": intent["h"],
            "p": intent["_anchor"],
            "n": uuid.uuid4().hex,
            "ref": intent["n"],
        }
        self._append_sidecar(closer)

    # -- SQLite plumbing -----------------------------------------------

    def _migrate_schema(self, conn: sqlite3.Connection) -> None:
        """Add chain columns to a database written by an older version.

        The upgrade is additive and runs at most once: the columns start
        nullable, existing events are backfilled in sequence order, and
        each request head is anchored at its final event. Existing chain
        values are never recomputed or overwritten.
        """
        if conn.execute(_REQUEST_CHAIN_COLUMN).fetchone() and conn.execute(
            _EVENT_CHAIN_COLUMN
        ).fetchone():
            return
        with self._write_lock:
            try:
                conn.execute("BEGIN IMMEDIATE")
                # Re-probe inside the transaction: another process may
                # have completed the upgrade while we waited on the lock.
                if not conn.execute(_REQUEST_CHAIN_COLUMN).fetchone():
                    conn.execute("ALTER TABLE requests ADD COLUMN chain_hash TEXT")
                if not conn.execute(_EVENT_CHAIN_COLUMN).fetchone():
                    conn.execute(
                        "ALTER TABLE status_events ADD COLUMN chain_hash TEXT"
                    )
                current_request: tuple[str, str] | None = None
                predecessor = _GENESIS_PREDECESSOR
                event_rows = conn.execute(
                    "SELECT tenant_id, request_id, seq, status, occurred_at "
                    "FROM status_events ORDER BY tenant_id, request_id, seq"
                ).fetchall()
                for tenant_id, request_id, seq, status, occurred_at in event_rows:
                    key = (tenant_id, request_id)
                    if key != current_request:
                        current_request = key
                        predecessor = _GENESIS_PREDECESSOR
                    link = _chain_hash(
                        tenant_id, request_id, seq, status, occurred_at, predecessor
                    )
                    conn.execute(
                        "UPDATE status_events SET chain_hash = ? "
                        "WHERE tenant_id = ? AND request_id = ? AND seq = ?",
                        (link, tenant_id, request_id, seq),
                    )
                    predecessor = link
                # Anchor each request head at its final event. A request
                # with no events keeps NULL and fails verification rather
                # than receiving a fabricated anchor.
                conn.execute(
                    "UPDATE requests SET chain_hash = ( "
                    "SELECT e.chain_hash FROM status_events e "
                    "WHERE e.tenant_id = requests.tenant_id "
                    "  AND e.request_id = requests.request_id "
                    "ORDER BY e.seq DESC LIMIT 1 "
                    ") WHERE chain_hash IS NULL"
                )
                conn.execute("COMMIT")
            except sqlite3.Error:
                try:
                    conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise RuntimeError("failed to initialize request store") from None

    def _open_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            self._db_path,
            timeout=_BUSY_TIMEOUT_MS / 1000,
            check_same_thread=False,
        )
        conn.isolation_level = None  # explicit transaction control
        conn.execute(f"PRAGMA busy_timeout = {_BUSY_TIMEOUT_MS}")
        return conn

    def _connect(self) -> sqlite3.Connection:
        if self._mem_conn is not None:
            return self._mem_conn
        return self._open_connection()

    def _release(self, conn: sqlite3.Connection) -> None:
        if conn is not self._mem_conn:
            conn.close()

    def submit(
        self,
        tenant_id: str,
        subject_id: str,
        scopes: object,
        idempotency_key: str,
    ) -> dict[str, str]:
        # Validate everything before touching the database so rejected
        # input can never create a record.
        tenant_id = _require_nonempty_str(tenant_id, "tenant_id")
        subject_id = _require_nonempty_str(subject_id, "subject_id")
        idempotency_key = _require_nonempty_str(idempotency_key, "idempotency_key")
        scope_list = _normalize_scopes(scopes)
        scopes_json = json.dumps(scope_list, ensure_ascii=False, separators=(",", ":"))

        with self._write_lock:
            return self._insert_or_reuse(
                tenant_id, subject_id, scope_list, idempotency_key, scopes_json
            )

    def _insert_or_reuse(
        self,
        tenant_id: str,
        subject_id: str,
        scope_list: list[str],
        idempotency_key: str,
        scopes_json: str,
    ) -> dict[str, str]:
        conn = self._connect()
        try:
            for _ in range(_MAX_INSERT_ATTEMPTS):
                request_id = str(uuid.uuid4())
                created_at = _utc_now_rfc3339()
                genesis_hash = _chain_hash(
                    tenant_id,
                    request_id,
                    0,
                    _STATUS_ACCEPTED,
                    created_at,
                    _GENESIS_PREDECESSOR,
                )
                with contextlib.nullcontext():
                    conn.execute("BEGIN IMMEDIATE")
                    try:
                        conn.execute(
                            "INSERT INTO requests ("
                            "request_id, tenant_id, idempotency_key, subject_id, "
                            "scopes_json, status, created_at, chain_hash"
                            ") VALUES (?, ?, ?, ?, ?, 'accepted', ?, ?)",
                            (
                                request_id,
                                tenant_id,
                                idempotency_key,
                                subject_id,
                                scopes_json,
                                created_at,
                                genesis_hash,
                            ),
                        )
                    except sqlite3.IntegrityError:
                        conn.execute("ROLLBACK")
                        try:
                            return self._load_idempotent(
                                conn, tenant_id, idempotency_key, subject_id, scope_list
                            )
                        except _PrimaryKeyConflict:
                            # Collision was on request_id; retry with a new UUID.
                            continue
                    try:
                        # The first timeline entry shares the acceptance
                        # transaction: a request can never exist without its
                        # accepted event, nor an event without its request. The
                        # genesis chain link is written in the same transaction
                        # and its hash anchors the request row.
                        conn.execute(
                            "INSERT INTO status_events ("
                            "tenant_id, request_id, seq, status, occurred_at, chain_hash"
                            ") VALUES (?, ?, 0, 'accepted', ?, ?)",
                            (tenant_id, request_id, created_at, genesis_hash),
                        )
                        if self._anchored:
                            # The narrow window that escapes SQLite's own
                            # write reservation (commit -> confirmation) is
                            # held under the process-wide anchor lock, so a
                            # second process can never interleave records.
                            with self._anchor_lock():
                                # Durable authenticated intent BEFORE commit.
                                intent = self._anchor_intent(conn, genesis_hash)
                                try:
                                    conn.execute("COMMIT")
                                except BaseException:
                                    try:
                                        conn.execute("ROLLBACK")
                                    except sqlite3.Error:
                                        pass
                                    with contextlib.suppress(Exception):
                                        self._anchor_close(intent, committed=False)
                                    raise
                                # Failure after this point leaves a dangling
                                # intent for the next mutation to reconcile;
                                # this call still never reports success.
                                self._anchor_close(intent, committed=True)
                        else:
                            conn.execute("COMMIT")
                    except BaseException:
                        # Never report success: discard any still-open
                        # SQLite transaction. An intent already resolved
                        # inside the anchor lock above is handled there; a
                        # process crash instead leaves a dangling intent
                        # that the next writer reconciles from the durable
                        # database state.
                        try:
                            conn.execute("ROLLBACK")
                        except sqlite3.Error:
                            pass
                        raise
                return {
                    "request_id": request_id,
                    "status": "accepted",
                    "created_at": created_at,
                }
        finally:
            self._release(conn)
        raise RuntimeError("unable to allocate a unique request id")

    def _load_idempotent(
        self,
        conn: sqlite3.Connection,
        tenant_id: str,
        idempotency_key: str,
        subject_id: str,
        scope_list: list[str],
    ) -> dict[str, str]:
        row = conn.execute(
            "SELECT request_id, status, created_at, subject_id, scopes_json "
            "FROM requests WHERE tenant_id = ? AND idempotency_key = ?",
            (tenant_id, idempotency_key),
        ).fetchone()
        if row is None:
            # The conflict came from the primary key rather than the
            # idempotency index; signal a fresh-UUID retry.
            raise _PrimaryKeyConflict
        existing_request_id, status, created_at, existing_subject, existing_scopes_json = row
        try:
            existing_scopes = json.loads(existing_scopes_json)
        except (TypeError, ValueError):
            existing_scopes = None
        same_payload = (
            existing_subject == subject_id
            and isinstance(existing_scopes, list)
            and all(isinstance(item, str) for item in existing_scopes)
            and set(existing_scopes) == set(scope_list)
        )
        if not same_payload:
            raise IdempotencyConflict(
                "idempotency key was already submitted with a different payload"
            )
        return {
            "request_id": existing_request_id,
            "status": status,
            "created_at": created_at,
        }

    def get(self, tenant_id: str, request_id: str) -> dict[str, str]:
        # The in-memory connection is shared across threads; serialize it
        # against writes. File-backed stores use a fresh connection per
        # call and rely on SQLite's own concurrency.
        if self._mem_conn is not None:
            with self._write_lock:
                return self._get(tenant_id, request_id)
        return self._get(tenant_id, request_id)

    def _get(self, tenant_id: str, request_id: str) -> dict[str, str]:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT request_id, status, created_at FROM requests "
                "WHERE tenant_id = ? AND request_id = ?",
                (tenant_id, request_id),
            ).fetchone()
        finally:
            self._release(conn)
        if row is None:
            # Identical outcome for unknown ids and cross-tenant lookups:
            # the response must not reveal that another tenant owns a record.
            raise RequestNotFound("request not found")
        return {
            "request_id": row[0],
            "status": row[1],
            "created_at": row[2],
        }

    def transition(
        self,
        tenant_id: str,
        request_id: str,
        target_status: str,
    ) -> dict[str, str]:
        """Move a request to ``target_status`` according to the lifecycle.

        Moving a request to the status it already holds is idempotent and
        returns the current receipt. Unknown statuses and illegal moves
        raise :class:`InvalidStatusTransition` without writing; unknown or
        cross-tenant ids raise :class:`RequestNotFound`.
        """
        # Validate before touching the database, mirroring submit(): no
        # rejected call may perform a write.
        tenant_id = _require_nonempty_str(tenant_id, "tenant_id")
        request_id = _require_nonempty_str(request_id, "request_id")
        target_status = _require_nonempty_str(target_status, "target_status")
        if target_status not in _ALLOWED_TRANSITIONS:
            raise InvalidStatusTransition("unknown target status")

        with self._write_lock:
            conn = self._connect()
            try:
                with contextlib.nullcontext():
                    try:
                        conn.execute("BEGIN IMMEDIATE")
                    except sqlite3.Error:
                        # Never surface the database engine's own error text.
                        raise RuntimeError(
                            "failed to persist status transition"
                        ) from None
                    try:
                        row = conn.execute(
                            "SELECT status, created_at FROM requests "
                            "WHERE tenant_id = ? AND request_id = ?",
                            (tenant_id, request_id),
                        ).fetchone()
                        if row is None:
                            # Same outcome for unknown ids and cross-tenant lookups.
                            conn.execute("ROLLBACK")
                            raise RequestNotFound("request not found")
                        current_status, created_at = row
                        if current_status == target_status:
                            # Idempotent replay: nothing to persist, and in
                            # particular nothing appended to the anchor log.
                            conn.execute("ROLLBACK")
                            return {
                                "request_id": request_id,
                                "status": current_status,
                                "created_at": created_at,
                            }
                        allowed = _ALLOWED_TRANSITIONS.get(current_status, frozenset())
                        if target_status not in allowed:
                            conn.execute("ROLLBACK")
                            raise InvalidStatusTransition("illegal status transition")
                        # Read the predecessor link before writing so the new
                        # link binds the exact persisted predecessor. BEGIN
                        # IMMEDIATE serializes writers, so two transitions can
                        # neither claim the same seq nor read a stale predecessor.
                        latest = conn.execute(
                            "SELECT seq, occurred_at, chain_hash FROM status_events "
                            "WHERE tenant_id = ? AND request_id = ? "
                            "ORDER BY seq DESC LIMIT 1",
                            (tenant_id, request_id),
                        ).fetchone()
                        if latest is None or not _is_chain_hash(latest[2]):
                            # Defensive only: every accepted request owns its
                            # seq-0 event with a valid link, so reaching here
                            # means the timeline invariant was broken out of
                            # band. Never fabricate a replacement link.
                            conn.execute("ROLLBACK")
                            raise RuntimeError(
                                "failed to persist status transition"
                            )
                        next_seq, latest_occurred_at, predecessor_hash = latest
                        occurred_at = _occurred_at_not_before(latest_occurred_at)
                        next_link_hash = _chain_hash(
                            tenant_id,
                            request_id,
                            next_seq + 1,
                            target_status,
                            occurred_at,
                            predecessor_hash,
                        )
                        cursor = conn.execute(
                            "UPDATE requests SET status = ?, chain_hash = ? "
                            "WHERE tenant_id = ? AND request_id = ? AND status = ?",
                            (
                                target_status,
                                next_link_hash,
                                tenant_id,
                                request_id,
                                current_status,
                            ),
                        )
                        if cursor.rowcount != 1:
                            # The row vanished or changed under us; refuse rather
                            # than persisting a state that breaks the transition
                            # graph observed at read time.
                            conn.execute("ROLLBACK")
                            raise InvalidStatusTransition("illegal status transition")
                        # The event is appended in the same transaction as the
                        # status update. The event's chain link binds the
                        # predecessor hash and is itself anchored on the request
                        # row by the UPDATE above.
                        conn.execute(
                            "INSERT INTO status_events ("
                            "tenant_id, request_id, seq, status, occurred_at, chain_hash"
                            ") VALUES (?, ?, ?, ?, ?, ?)",
                            (
                                tenant_id,
                                request_id,
                                next_seq + 1,
                                target_status,
                                occurred_at,
                                next_link_hash,
                            ),
                        )
                        if self._anchored:
                            # Hold the process-wide anchor lock across the
                            # only window outside SQLite's own reservation:
                            # intent -> commit -> confirmation.
                            with self._anchor_lock():
                                intent = self._anchor_intent(conn, next_link_hash)
                                try:
                                    conn.execute("COMMIT")
                                except BaseException:
                                    try:
                                        conn.execute("ROLLBACK")
                                    except sqlite3.Error:
                                        pass
                                    with contextlib.suppress(Exception):
                                        self._anchor_close(intent, committed=False)
                                    raise RuntimeError(
                                        "failed to persist status transition"
                                    ) from None
                                # Failure here leaves a dangling intent for
                                # the next mutation to reconcile; success is
                                # never reported for this call.
                                self._anchor_close(intent, committed=True)
                        else:
                            try:
                                conn.execute("COMMIT")
                            except BaseException:
                                try:
                                    conn.execute("ROLLBACK")
                                except sqlite3.Error:
                                    pass
                                raise RuntimeError(
                                    "failed to persist status transition"
                                ) from None
                    except InvalidStatusTransition:
                        raise
                    except RequestNotFound:
                        raise
                    except RuntimeError:
                        # The anchor protocol may have failed with the SQLite
                        # transaction still open.
                        try:
                            conn.execute("ROLLBACK")
                        except sqlite3.Error:
                            pass
                        raise
                    except sqlite3.Error:
                        # Best-effort cleanup; the rollback failure must not mask
                        # the original problem or leak engine text.
                        try:
                            conn.execute("ROLLBACK")
                        except sqlite3.Error:
                            pass
                        raise RuntimeError(
                            "failed to persist status transition"
                        ) from None
            finally:
                self._release(conn)
        _log.info(
            "status transition persisted request_id=%s status=%s",
            request_id,
            target_status,
        )
        return {
            "request_id": request_id,
            "status": target_status,
            "created_at": created_at,
        }

    def audit(
        self,
        tenant_id: str,
        request_id: str,
    ) -> list[dict[str, str]]:
        """Return the request's status timeline in occurrence order.

        Each entry contains only ``status`` and ``occurred_at`` (a UTC
        RFC3339 string). The final entry's status always equals the result
        of :meth:`get`. Unknown ids and cross-tenant lookups raise
        :class:`RequestNotFound` with identical behaviour, so the call
        cannot reveal another tenant's records.
        """
        tenant_id = _require_nonempty_str(tenant_id, "tenant_id")
        request_id = _require_nonempty_str(request_id, "request_id")
        if self._mem_conn is not None:
            with self._write_lock:
                return self._audit(tenant_id, request_id)
        return self._audit(tenant_id, request_id)

    def _audit(self, tenant_id: str, request_id: str) -> list[dict[str, str]]:
        conn = self._connect()
        try:
            # Resolve ownership first: filtering the event query by tenant
            # alone would still distinguish "missing" from "foreign record"
            # via an empty timeline, so gate on the request row exactly
            # like get().
            owner = conn.execute(
                "SELECT 1 FROM requests WHERE tenant_id = ? AND request_id = ?",
                (tenant_id, request_id),
            ).fetchone()
            if owner is None:
                raise RequestNotFound("request not found")
            rows = conn.execute(
                "SELECT status, occurred_at FROM status_events "
                "WHERE tenant_id = ? AND request_id = ? ORDER BY seq",
                (tenant_id, request_id),
            ).fetchall()
        finally:
            self._release(conn)
        return [
            {"status": status, "occurred_at": occurred_at}
            for status, occurred_at in rows
        ]

    def evidence(
        self,
        tenant_id: str,
        request_id: str,
    ) -> dict[str, object]:
        """Return the persisted integrity evidence for a request.

        The result contains exactly ``request_id``, ``status`` (identical
        to :meth:`get`), ``event_count`` (identical to the length of
        :meth:`audit`) and ``chain_hash`` (the SHA-256 head of the audit
        chain as persisted, never recomputed). Unknown ids and cross-
        tenant lookups raise :class:`RequestNotFound`; non-string or
        empty arguments raise :class:`ValueError`.
        """
        tenant_id = _require_nonempty_str(tenant_id, "tenant_id")
        request_id = _require_nonempty_str(request_id, "request_id")
        if self._mem_conn is not None:
            with self._write_lock:
                return self._evidence(tenant_id, request_id)
        return self._evidence(tenant_id, request_id)

    def _evidence(self, tenant_id: str, request_id: str) -> dict[str, object]:
        status, head_hash, event_count = self._load_chain_head(
            tenant_id, request_id
        )
        # The stored head must be a well-formed digest; a malformed value
        # means the row was altered out of band and must not be reported
        # as evidence.
        if not _is_chain_hash(head_hash):
            raise RequestNotFound("request not found")
        return {
            "request_id": request_id,
            "status": status,
            "event_count": event_count,
            "chain_hash": head_hash,
        }

    def verify_evidence(self, tenant_id: str, request_id: str) -> bool:
        """Verify the persisted audit chain (and trusted anchor) for a request.

        Every link is checked against the stored rows only; verification
        never recomputes-and-overwrites persisted evidence. Deleting,
        altering, inserting or reordering events, tampering with the
        request head, or substituting events from another request or
        tenant all yield ``False``. In trusted mode the request's heads
        must additionally appear, in order, among the authenticated
        ``confirmed`` records in the keyed sidecar, whose tip must carry
        no unclosed intent; a missing/corrupt sidecar, an anchor/database
        mismatch, an unanchored (legacy) database or an interrupted commit
        therefore also yield ``False``. Returns ``True`` only when every
        link recomputes to its stored hash from the genesis predecessor,
        the sequences are gap-free from zero, the final link matches the
        request's anchored head and current status, and every external
        anchor checks out. Unknown ids and cross-tenant lookups raise
        :class:`RequestNotFound`; non-string or empty arguments raise
        :class:`ValueError`.
        """
        tenant_id = _require_nonempty_str(tenant_id, "tenant_id")
        request_id = _require_nonempty_str(request_id, "request_id")
        if self._mem_conn is not None:
            with self._write_lock:
                return self._verify_evidence(tenant_id, request_id)
        return self._verify_evidence(tenant_id, request_id)

    def _verify_evidence(
        self, tenant_id: str, request_id: str
    ) -> bool:
        conn = self._connect()
        try:
            # Gate on the request row exactly like audit(): an empty
            # timeline must not distinguish "missing" from "foreign".
            try:
                owner = conn.execute(
                    "SELECT status, chain_hash FROM requests "
                    "WHERE tenant_id = ? AND request_id = ?",
                    (tenant_id, request_id),
                ).fetchone()
                if owner is None:
                    raise RequestNotFound("request not found")
                current_status, anchored_head = owner
                rows = conn.execute(
                    "SELECT seq, status, occurred_at, chain_hash "
                    "FROM status_events "
                    "WHERE tenant_id = ? AND request_id = ? ORDER BY seq",
                    (tenant_id, request_id),
                ).fetchall()
            except RequestNotFound:
                raise
            except sqlite3.Error:
                # Never surface the database engine's own error text.
                raise RuntimeError("failed to verify request evidence") from None
        finally:
            self._release(conn)

        # Internal chain: every link recomputes from the genesis
        # predecessor, sequences are gap-free from zero, and the final
        # link matches the anchored head and current status.
        if not self._chain_recomputes(
            tenant_id, request_id, rows, current_status, anchored_head
        ):
            return False

        if self._anchored:
            return self._verify_external_anchor(
                [stored_hash for _seq, _status, _at, stored_hash in rows],
                anchored_head,
            )
        return True

    def _verify_external_anchor(
        self,
        own_heads: list[str],
        anchored_head: str,
    ) -> bool:
        snapshot = self._sidecar_snapshot()
        if snapshot is None:
            # Missing or structurally/authentically invalid sidecar,
            # including legacy databases that predate trusted anchoring.
            return False
        confirmed, dangling_head, torn = snapshot
        if torn or dangling_head is not None:
            # An unclosed intent (or torn append) at the tip marks an
            # interrupted commit window.
            return False
        own = set(own_heads)
        # Heads are collision-free hashes committing to tenant, request
        # and event content, so the in-order subsequence of globally
        # confirmed anchors belonging to this request must equal the
        # request's chain exactly: nothing missing, nothing substituted
        # from another request or tenant, nothing unanchored trailing.
        anchored_subsequence = [head for head in confirmed if head in own]
        if anchored_subsequence != own_heads:
            return False
        return hmac.compare_digest(own_heads[-1], anchored_head)

    def _load_chain_head(
        self, tenant_id: str, request_id: str
    ) -> tuple[str, str, int]:
        conn = self._connect()
        try:
            try:
                row = conn.execute(
                    "SELECT r.status, r.chain_hash, "
                    "(SELECT count(*) FROM status_events e "
                    " WHERE e.tenant_id = r.tenant_id "
                    "   AND e.request_id = r.request_id) "
                    "FROM requests r WHERE r.tenant_id = ? AND r.request_id = ?",
                    (tenant_id, request_id),
                ).fetchone()
            except sqlite3.Error:
                raise RuntimeError("failed to read request evidence") from None
        finally:
            self._release(conn)
        if row is None:
            # Identical outcome for unknown ids and cross-tenant lookups.
            raise RequestNotFound("request not found")
        return row[0], row[1], row[2]

    # -- recovery ------------------------------------------------------

    def recover(self) -> str:
        """Read-only triage of the trusted evidence store.

        Returns one of:

        * ``"valid"`` -- every request's internal audit chain recomputes
          and is covered, head for head, by authenticated ``confirmed``
          sidecar records, with no foreign anchors and a closed tip;
        * ``"incomplete"`` -- the confirmed ledger and the database agree
          but the sidecar ends in an unclosed intent or torn append (an
          interrupted commit);
        * ``"invalid"`` -- the sidecar is missing while evidence exists,
          is corrupt or fails MAC verification, disagrees with the
          database, an internal chain fails to recompute, or a database
          event lacks trusted anchoring.

        The method never creates, modifies or deletes anything. Trusted
        anchoring must be enabled (``integrity_key`` supplied).
        """
        if not self._anchored:
            raise RuntimeError("trusted anchoring is not enabled")

        raw = self._read_sidecar_bytes()
        conn = self._connect()
        try:
            try:
                request_rows = conn.execute(
                    "SELECT tenant_id, request_id, status, chain_hash FROM requests"
                ).fetchall()
                chains: list[tuple[list[tuple[object, ...]], str, str]] = []
                for tenant_id, request_id, current_status, anchored_head in request_rows:
                    rows = conn.execute(
                        "SELECT seq, status, occurred_at, chain_hash "
                        "FROM status_events "
                        "WHERE tenant_id = ? AND request_id = ? ORDER BY seq",
                        (tenant_id, request_id),
                    ).fetchall()
                    chains.append(
                        (tenant_id, request_id, rows, current_status, anchored_head)
                    )
            except sqlite3.Error:
                raise RuntimeError("failed to recover request evidence") from None
        finally:
            self._release(conn)

        # First validate every internal audit chain independently; this
        # catches pure-SQLite tampering (e.g. a flipped status) that
        # leaves the sidecar bytes untouched.
        db_heads: set[str] = set()
        for tenant_id, request_id, rows, current_status, anchored_head in chains:
            if not self._chain_recomputes(
                tenant_id, request_id, rows, current_status, anchored_head
            ):
                return "invalid"
            db_heads.update(stored_hash for _s, _u, _o, stored_hash in rows)

        if raw is None:
            # Sidecar absent: only an entirely empty database is valid;
            # any pre-existing (e.g. legacy) database lacks anchoring.
            return "valid" if not db_heads else "invalid"
        if not raw:
            return "valid" if not db_heads else "invalid"
        snapshot = self._sidecar_snapshot()
        if snapshot is None:
            return "invalid"
        confirmed, dangling_head, torn = snapshot
        confirmed_set = set(confirmed)
        # Confirmed heads are unique anchors for unique events.
        if len(confirmed) != len(confirmed_set):
            return "invalid"

        # A single unclosed intent is the recoverable commit window. Its
        # fate is determined by the durable database: a head present in
        # SQLite will be confirmed, an absent one aborted; either way the
        # store is merely "incomplete" while the open record exists.
        if dangling_head is not None:
            if dangling_head in confirmed_set:
                # Protocol never re-anchors an already-anchored head.
                return "invalid"
            effective = set(confirmed_set)
            if dangling_head in db_heads:
                effective.add(dangling_head)
            if effective != db_heads:
                return "invalid"
            return "incomplete"
        # No open intent: a physically torn final append is the only
        # remaining interruption, recoverable only once the ledgers
        # already agree on everything durable.
        if set(confirmed) != db_heads:
            return "invalid"
        return "incomplete" if torn else "valid"

    @staticmethod
    def _chain_recomputes(
        tenant_id: str,
        request_id: str,
        rows: list[tuple[object, ...]],
        current_status: str,
        anchored_head: str,
    ) -> bool:
        """Replay the internal audit chain exactly like verify_evidence().

        Every link must recompute to its stored hash from the genesis
        predecessor, sequences must be gap-free from zero, the final
        link must equal the anchored head, and its status must equal the
        request's authoritative current status.
        """
        if not rows or not _is_chain_hash(anchored_head):
            return False
        predecessor = _GENESIS_PREDECESSOR
        for expected_seq, row in enumerate(rows):
            seq, status, occurred_at, stored_hash = row
            if (
                not isinstance(seq, int)
                or isinstance(seq, bool)
                or seq != expected_seq
                or not isinstance(status, str)
                or not isinstance(occurred_at, str)
                or not _is_chain_hash(stored_hash)
            ):
                return False
            recomputed = _chain_hash(
                tenant_id, request_id, seq, status, occurred_at, predecessor
            )
            if not hmac.compare_digest(recomputed, stored_hash):
                return False
            predecessor = stored_hash
        return (
            hmac.compare_digest(predecessor, anchored_head)
            and rows[-1][1] == current_status
        )
