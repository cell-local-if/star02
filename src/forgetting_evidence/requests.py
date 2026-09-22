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
event is also stored on the request row. The plain hash preimage is
never exposed in return values, exceptions or logs.

Trust anchor
------------

A plain hash chain living entirely inside SQLite cannot be trusted: an
attacker who can rewrite the database can recompute every link and the
chain head. When the store is constructed with an ``integrity_key`` held
by the caller (and never persisted by this module), every committed
event is additionally anchored in an append-only *sidecar* file
(``anchor_path``, defaulting to ``<db>.anchor``; an in-memory sidecar
for ``:memory:`` databases).

Each sidecar frame is a fixed binary record carrying the frame number,
tenant, request id, per-request event sequence, the event's
``chain_hash`` and the previous frame's authentication label, sealed
with HMAC-SHA256 under the caller's key. Frames form a global
authenticated chain: the sidecar cannot be extended, truncated and
rebuilt, reordered, or transplanted without the key, and every frame
binds the tenant and request so events cannot be moved across requests
or tenants.

Commit protocol
---------------

Writes follow a decidable two-phase protocol, serialized by an
in-process lock and an inter-process file lock:

1. ``BEGIN IMMEDIATE`` and perform every SQLite change (request row,
   event row, anchored chain head) inside the transaction.
2. Append the HMAC-sealed anchor frame and force it to stable storage.
3. ``COMMIT`` SQLite.

A crash can therefore leave only two outcomes: the frame is missing
(nothing was committed) or the frame is durable while the SQLite
commit did not land. :meth:`recover` distinguishes a clean store
(``consistent``) from ``interrupted`` (anchor ahead of SQLite) and
``diverged`` (any other disagreement); a missing key, a missing or
malformed sidecar yield ``no_key``, ``no_sidecar`` and
``corrupt_anchor`` respectively. Recovery never repairs, backfills or
rewrites evidence, and :meth:`verify_evidence` returns ``False`` for
every non-``consistent`` state. The key, any key-equivalent material
and plaintext hash preimages are never written to SQLite, the sidecar,
receipts, exceptions or logs.
"""

from __future__ import annotations

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

try:  # POSIX file locking serializes the commit protocol across processes.
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX platforms
    fcntl = None  # type: ignore[assignment]

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

# Recovery statuses returned by RequestStore.recover(). Only "consistent"
# is a valid state; every other status is explicit and non-valid.
_RECOVERY_CONSISTENT = "consistent"
_RECOVERY_NO_KEY = "no_key"
_RECOVERY_NO_SIDECAR = "no_sidecar"
_RECOVERY_CORRUPT = "corrupt_anchor"
_RECOVERY_INTERRUPTED = "interrupted"
_RECOVERY_DIVERGED = "diverged"


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


# --- Key-anchored sidecar -------------------------------------------------

_ANCHOR_MAGIC = b"FEANCHR1"
_ANCHOR_DOMAIN = b"forgetting-evidence-anchor-v1"
_ANCHOR_VERSION = 1
_LABEL_SIZE = hashlib.sha256().digest_size  # 32
# version B, frame_seq Q, two length prefixes H each.
_ANCHOR_HEADER = struct.Struct(">BQHHq")


class _AnchorMissing(Exception):
    """The sidecar file does not exist yet."""


class _AnchorCorrupt(Exception):
    """The sidecar exists but cannot be authenticated or parsed."""


class _AnchorLog:
    """Append-only, HMAC-sealed anchor log.

    Frame layout (all integers big-endian)::

        payload = version(1) | frame_seq(8) | len(tenant)(2) | tenant
                  | len(request)(2) | request | event_seq(8 signed)
                  | chain_hash(32 raw bytes) | prev_label(32 bytes)
        frame   = payload | HMAC_sha256(key, DOMAIN || payload)

    The first frame's ``prev_label`` is 32 zero bytes; every later label
    chains over its predecessor, so frames cannot be reordered or
    transplanted. Neither the key nor any plaintext chain preimage is
    stored -- only the 32-byte event digest is sealed.
    """

    def __init__(self, path: str | None, key: bytes):
        self._path = path
        self._key = key
        self._lock_fd: int | None = None
        if path is None:
            # In-memory sidecar for :memory: databases.
            self._buffer = bytearray()
        else:
            self._buffer = None
            parent = os.path.dirname(os.path.abspath(path))
            os.makedirs(parent, exist_ok=True)

    # -- framing -------------------------------------------------------

    @staticmethod
    def _encode_frame(
        frame_seq: int,
        tenant_id: str,
        request_id: str,
        event_seq: int,
        chain_hash_hex: str,
        prev_label: bytes,
        key: bytes,
    ) -> bytes:
        tenant_bytes = tenant_id.encode("utf-8")
        request_bytes = request_id.encode("utf-8")
        if len(tenant_bytes) > 0xFFFF or len(request_bytes) > 0xFFFF:
            # Identifiers are realistically far shorter; refuse rather
            # than truncate the authenticated identity binding.
            raise ValueError("invalid anchor identifier")
        payload = _ANCHOR_HEADER.pack(
            _ANCHOR_VERSION,
            frame_seq,
            len(tenant_bytes),
            len(request_bytes),
            event_seq,
        )
        payload += tenant_bytes + request_bytes
        payload += bytes.fromhex(chain_hash_hex)
        payload += prev_label
        label = hmac.new(key, _ANCHOR_DOMAIN + payload, hashlib.sha256).digest()
        return payload + label

    @staticmethod
    def _frame_size(tenant_len: int, request_len: int) -> int:
        # chain_hash(32) + prev_label(32) + sealing label(32)
        return _ANCHOR_HEADER.size + tenant_len + request_len + _LABEL_SIZE * 3

    # -- reading -------------------------------------------------------

    def _read_bytes(self) -> bytes:
        if self._buffer is not None:
            return bytes(self._buffer)
        try:
            with open(self._path, "rb") as handle:  # type: ignore[arg-type]
                return handle.read()
        except FileNotFoundError:
            raise _AnchorMissing from None
        except OSError:
            raise _AnchorCorrupt from None

    def replay(self) -> tuple[list[tuple[str, str, int, str]], bool]:
        """Authenticate and parse every frame.

        Returns ``(frames, partial_trailing)`` where each frame is
        ``(tenant_id, request_id, event_seq, chain_hash_hex)`` in frame
        order. ``partial_trailing`` means the file ends in the middle of
        a frame (a crash during append, indistinguishable from malicious
        truncation -- never trusted either way). Raises
        :class:`_AnchorMissing` when no sidecar exists and
        :class:`_AnchorCorrupt` on any structural or authentication
        failure.
        """
        data = self._read_bytes()
        if not data:
            return [], False
        if not data.startswith(_ANCHOR_MAGIC):
            raise _AnchorCorrupt
        offset = len(_ANCHOR_MAGIC)
        frames: list[tuple[str, str, int, str]] = []
        expected_seq = 0
        prev_label = b"\x00" * _LABEL_SIZE
        partial = False
        try:
            while offset < len(data):
                if len(data) - offset < _ANCHOR_HEADER.size:
                    partial = True
                    break
                version, frame_seq, tenant_len, request_len, event_seq = (
                    _ANCHOR_HEADER.unpack_from(data, offset)
                )
                frame_size = self._frame_size(tenant_len, request_len)
                if frame_seq != expected_seq:
                    raise _AnchorCorrupt
                if len(data) - offset < frame_size:
                    partial = True
                    break
                end = offset + frame_size
                payload = data[offset : end - _LABEL_SIZE]
                label = data[end - _LABEL_SIZE : end]
                expected_label = hmac.new(
                    self._key, _ANCHOR_DOMAIN + payload, hashlib.sha256
                ).digest()
                if version != _ANCHOR_VERSION:
                    raise _AnchorCorrupt
                identity_end = _ANCHOR_HEADER.size + tenant_len + request_len
                chain_start = offset + identity_end
                chain_end = chain_start + _LABEL_SIZE
                claimed_prev = data[chain_end : chain_end + _LABEL_SIZE]
                if not hmac.compare_digest(claimed_prev, prev_label):
                    raise _AnchorCorrupt
                if not hmac.compare_digest(label, expected_label):
                    raise _AnchorCorrupt
                tenant_id = data[
                    offset + _ANCHOR_HEADER.size : offset + _ANCHOR_HEADER.size + tenant_len
                ].decode("utf-8")
                request_id = data[
                    offset + _ANCHOR_HEADER.size + tenant_len : offset + identity_end
                ].decode("utf-8")
                chain_hex = data[chain_start:chain_end].hex()
                frames.append((tenant_id, request_id, event_seq, chain_hex))
                prev_label = label
                expected_seq += 1
                offset = end
        except (UnicodeDecodeError, struct.error):
            raise _AnchorCorrupt from None
        return frames, partial

    # -- writing -------------------------------------------------------

    def initialize_locked(self) -> None:
        """Create the file and magic header if the log is absent/empty."""
        if self._buffer is not None:
            if not self._buffer:
                self._buffer += _ANCHOR_MAGIC
            return
        assert self._path is not None
        new_file = not os.path.exists(self._path) or os.path.getsize(self._path) == 0
        with open(self._path, "ab") as handle:
            if new_file:
                handle.write(_ANCHOR_MAGIC)
                handle.flush()
                os.fsync(handle.fileno())
        if new_file:
            self._fsync_directory()

    def append_locked(
        self,
        frame_seq: int,
        tenant_id: str,
        request_id: str,
        event_seq: int,
        chain_hash_hex: str,
        prev_label: bytes,
    ) -> None:
        frame = self._encode_frame(
            frame_seq,
            tenant_id,
            request_id,
            event_seq,
            chain_hash_hex,
            prev_label,
            self._key,
        )
        if self._buffer is not None:
            if not self._buffer:
                self._buffer += _ANCHOR_MAGIC
            self._buffer += frame
            return
        assert self._path is not None
        with open(self._path, "ab") as handle:
            handle.write(frame)
            handle.flush()
            os.fsync(handle.fileno())

    def last_label(self) -> bytes:
        """Return the sealing label of the final frame (zeros if empty)."""
        frames, partial = self.replay()
        if partial:
            raise _AnchorCorrupt
        if not frames:
            return b"\x00" * _LABEL_SIZE
        data = self._read_bytes()
        # The label is the final _LABEL_SIZE bytes of the last frame.
        return bytes(data[-_LABEL_SIZE:])

    def _fsync_directory(self) -> None:
        assert self._path is not None
        directory = os.path.dirname(os.path.abspath(self._path)) or "."
        try:
            descriptor = os.open(directory, os.O_RDONLY)
        except OSError:
            return
        try:
            os.fsync(descriptor)
        except OSError:
            pass
        finally:
            os.close(descriptor)

    # -- inter-process serialization of the commit protocol ------------

    def acquire(self, shared: bool = False) -> None:
        if fcntl is None or self._path is None:
            return
        operation = fcntl.LOCK_SH if shared else fcntl.LOCK_EX
        descriptor = os.open(self._path + ".lock", os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(descriptor, operation)
        except OSError:
            os.close(descriptor)
            raise RuntimeError("failed to persist request") from None
        self._lock_fd = descriptor

    def release(self) -> None:
        if self._lock_fd is None:
            return
        try:
            fcntl.flock(self._lock_fd, fcntl.LOCK_UN)  # type: ignore[union-attr]
        except OSError:
            pass
        os.close(self._lock_fd)
        self._lock_fd = None


class RequestStore:
    """Persist and retrieve accepted deletion requests.

    Construct with ``integrity_key`` (and optionally ``anchor_path``)
    to enable key-anchored evidence. The key must be provisioned and
    stored by the caller, outside SQLite and the sidecar; without it
    evidence can never verify. A store opened without a key keeps full
    read/write behavior, but its chains carry no trust anchor and
    :meth:`verify_evidence` always returns ``False``.
    """

    def __init__(
        self,
        db_path: str | os.PathLike[str],
        *,
        anchor_path: str | os.PathLike[str] | None = None,
        integrity_key: str | bytes | None = None,
    ):
        self._db_path = os.fspath(db_path)
        self._integrity_key = self._normalize_key(integrity_key)
        if anchor_path is not None:
            anchor_file = os.fspath(anchor_path)
        elif self._db_path == ":memory:":
            anchor_file = None
        else:
            anchor_file = self._db_path + ".anchor"
        self._anchor_path = anchor_file
        self._anchor: _AnchorLog | None = (
            _AnchorLog(anchor_file, self._integrity_key)
            if self._integrity_key is not None
            else None
        )
        # In-process serialization; the unique index and anchor file lock
        # additionally guard other processes sharing the same files.
        self._write_lock = threading.Lock()
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

    @staticmethod
    def _normalize_key(integrity_key: str | bytes | None) -> bytes | None:
        if integrity_key is None:
            return None
        if isinstance(integrity_key, str):
            key = integrity_key.encode("utf-8")
        elif isinstance(integrity_key, bytes):
            key = integrity_key
        else:
            raise ValueError("integrity_key must be a non-empty string or bytes")
        if not key:
            raise ValueError("integrity_key must be a non-empty string or bytes")
        return key

    def _migrate_schema(self, conn: sqlite3.Connection) -> None:
        """Add chain columns to a database written by an older version.

        The upgrade is additive and runs at most once: the columns start
        nullable, existing events are backfilled in sequence order, and
        each request head is anchored at its final event. Existing chain
        values are never recomputed or overwritten. The key-based trust
        anchor is never backfilled: legacy chains have no caller-held key
        to seal them, so they can never verify.
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

    # -- recovery / trust state ----------------------------------------

    def _load_sqlite_chains(
        self, conn: sqlite3.Connection
    ) -> dict[tuple[str, str], dict[str, object]]:
        """Snapshot every request row and its event hashes from SQLite."""
        chains: dict[tuple[str, str], dict[str, object]] = {}
        request_rows = conn.execute(
            "SELECT tenant_id, request_id, status, chain_hash FROM requests"
        ).fetchall()
        for tenant_id, request_id, status, head in request_rows:
            chains[(tenant_id, request_id)] = {
                "status": status,
                "head": head,
                "events": [],
            }
        event_rows = conn.execute(
            "SELECT tenant_id, request_id, seq, status, chain_hash "
            "FROM status_events ORDER BY tenant_id, request_id, seq"
        ).fetchall()
        for tenant_id, request_id, seq, status, chain_hash in event_rows:
            chain = chains.get((tenant_id, request_id))
            if chain is None:
                # An event without its request row breaks the invariant
                # that rows and events share a transaction: mark by
                # attaching a sentinel the caller treats as divergence.
                chains[(tenant_id, request_id)] = {
                    "status": None,
                    "head": None,
                    "events": [(seq, status, chain_hash)],
                    "orphan": True,
                }
            else:
                chain["events"].append((seq, status, chain_hash))  # type: ignore[union-attr]
        return chains

    @staticmethod
    def _anchor_groups(
        frames: list[tuple[str, str, int, str]],
    ) -> dict[tuple[str, str], list[tuple[int, str]]]:
        groups: dict[tuple[str, str], list[tuple[int, str]]] = {}
        for tenant_id, request_id, event_seq, chain_hash in frames:
            groups.setdefault((tenant_id, request_id), []).append(
                (event_seq, chain_hash)
            )
        return groups

    def _recovery_state(
        self, conn: sqlite3.Connection | None = None
    ) -> tuple[str, dict[tuple[str, str], list[tuple[int, str]]]]:
        """Classify the persisted store without modifying anything.

        Returns ``(status, anchored_groups)``. ``status`` is
        ``consistent`` only when an authenticated sidecar agrees with
        SQLite for every request; every other status is explicit and
        non-valid. This method is strictly read-only.
        """
        if self._anchor is None or self._integrity_key is None:
            return _RECOVERY_NO_KEY, {}
        own_conn = conn is None
        if own_conn:
            conn = self._connect()
        try:
            try:
                frames, partial = self._anchor.replay()
            except _AnchorMissing:
                # An empty database with no sidecar is simply a fresh
                # store; persisted rows without an anchor are legacy data
                # with no trust anchor and can never be verified.
                count = conn.execute("SELECT count(*) FROM requests").fetchone()[0]
                if count == 0:
                    return _RECOVERY_CONSISTENT, {}
                return _RECOVERY_NO_SIDECAR, {}
            except _AnchorCorrupt:
                return _RECOVERY_CORRUPT, {}
            groups = self._anchor_groups(frames)
            chains = self._load_sqlite_chains(conn)

            # A torn trailing frame cannot be authenticated: it is never
            # treated as evidence of a merely-interrupted commit.
            if partial:
                return _RECOVERY_CORRUPT, groups
            interrupted = False
            for identity, chain in chains.items():
                if chain.get("orphan"):
                    # Event rows without a request row cannot be a valid
                    # commit under the protocol.
                    return _RECOVERY_DIVERGED, groups
            # SQLite must not contain requests the anchor knows nothing
            # about (unanchored/legacy rows, or rows written without the
            # committed anchor frame).
            for identity in chains:
                if identity not in groups:
                    return _RECOVERY_DIVERGED, groups
            for identity, anchored in groups.items():
                chain = chains.get(identity)
                if chain is None:
                    # Anchor frame(s) without a SQLite row: the SQLite
                    # commit did not survive after the durable frame.
                    interrupted = True
                    continue
                events = chain["events"]  # type: ignore[index]
                anchored_seqs = [event_seq for event_seq, _ in anchored]
                # Per-request frames must be gap-free from zero and in
                # frame order.
                if anchored_seqs != list(range(len(anchored))):
                    return _RECOVERY_DIVERGED, groups
                if [seq for seq, _status, _hash in events] != list(
                    range(len(events))
                ):
                    return _RECOVERY_DIVERGED, groups
                common = min(len(anchored), len(events))
                for index in range(common):
                    if anchored[index][1] != events[index][2]:
                        return _RECOVERY_DIVERGED, groups
                if len(anchored) == len(events):
                    final_status = events[-1][1]
                    # The request row must carry the final event's status
                    # and the final event's digest as its head.
                    if (
                        chain["status"] != final_status  # type: ignore[index]
                        or chain["head"] != anchored[-1][1]  # type: ignore[index]
                    ):
                        return _RECOVERY_DIVERGED, groups
                elif len(anchored) > len(events):
                    # Durable anchor frames whose SQLite commit did not
                    # land (or landed fewer events): interrupted commit.
                    interrupted = True
                else:
                    # SQLite holds events that were never anchored: the
                    # sidecar was rolled back/replaced, or writes bypassed
                    # the protocol.
                    return _RECOVERY_DIVERGED, groups
            if interrupted:
                return _RECOVERY_INTERRUPTED, groups
            return _RECOVERY_CONSISTENT, groups
        finally:
            if own_conn:
                self._release(conn)  # type: ignore[arg-type]

    def recover(self) -> dict[str, str]:
        """Report the persisted evidence state without changing it.

        Returns ``{"status": status}`` where status is one of
        ``consistent``, ``no_key``, ``no_sidecar``, ``corrupt_anchor``,
        ``interrupted`` or ``diverged``. Only ``consistent`` is valid;
        recovery never repairs, backfills or rewrites evidence, and no
        key material, preimage or payload is included.
        """
        with self._write_lock:
            conn = self._connect()
            anchor = self._anchor
            try:
                if anchor is not None:
                    anchor.acquire(shared=True)
                try:
                    status, _groups = self._recovery_state(conn)
                finally:
                    if anchor is not None:
                        anchor.release()
            finally:
                self._release(conn)
        return {"status": status}

    # -- write protocol -------------------------------------------------

    def _require_consistent_for_write(self, conn: sqlite3.Connection) -> None:
        """Refuse keyed writes onto anything but a clean store.

        Appending frames to an interrupted or diverged anchor could hide
        an unresolved commit; fail closed instead.
        """
        if self._anchor is None:
            return
        status, _groups = self._recovery_state(conn)
        if status != _RECOVERY_CONSISTENT:
            raise RuntimeError("request store evidence is not consistent")

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
        anchor = self._anchor
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
                if anchor is not None:
                    anchor.acquire()
                try:
                    self._require_consistent_for_write(conn)
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
                        # accepted event, nor an event without its request.
                        conn.execute(
                            "INSERT INTO status_events ("
                            "tenant_id, request_id, seq, status, occurred_at, chain_hash"
                            ") VALUES (?, ?, 0, 'accepted', ?, ?)",
                            (tenant_id, request_id, created_at, genesis_hash),
                        )
                    except sqlite3.Error:
                        conn.execute("ROLLBACK")
                        raise RuntimeError(
                            "failed to persist accepted request"
                        ) from None
                    if anchor is not None:
                        # Phase 2: seal the frame durably *before* the
                        # SQLite commit. A crash here leaves at worst a
                        # frame ahead of SQLite (recover() = interrupted),
                        # never a committed request without its anchor.
                        try:
                            anchor.initialize_locked()
                            frame_seq = self._anchor_frame_count()
                            prev_label = anchor.last_label()
                            anchor.append_locked(
                                frame_seq,
                                tenant_id,
                                request_id,
                                0,
                                genesis_hash,
                                prev_label,
                            )
                        except (OSError, _AnchorCorrupt, ValueError):
                            try:
                                conn.execute("ROLLBACK")
                            except sqlite3.Error:
                                pass
                            raise RuntimeError(
                                "failed to persist accepted request"
                            ) from None
                    conn.execute("COMMIT")
                finally:
                    if anchor is not None:
                        anchor.release()
                return {
                    "request_id": request_id,
                    "status": "accepted",
                    "created_at": created_at,
                }
        finally:
            self._release(conn)
        raise RuntimeError("unable to allocate a unique request id")

    def _anchor_frame_count(self) -> int:
        assert self._anchor is not None
        frames, partial = self._anchor.replay()
        if partial:
            raise _AnchorCorrupt
        return len(frames)

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
            anchor = self._anchor
            try:
                if anchor is not None:
                    anchor.acquire()
                try:
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
                            # Idempotent replay: nothing to persist.
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
                        if anchor is not None:
                            # The durable anchor must already agree with the
                            # predecessor about to be extended. Otherwise the
                            # chain was interrupted or tampered with; refuse
                            # rather than append onto a broken trust anchor.
                            status, _groups = self._recovery_state(conn)
                            if status != _RECOVERY_CONSISTENT:
                                conn.execute("ROLLBACK")
                                raise RuntimeError(
                                    "request store evidence is not consistent"
                                )
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
                        if anchor is not None:
                            # Phase 2: seal the new link durably before the
                            # SQLite commit. A crash leaves at worst an
                            # interrupted (anchor-ahead) state, never a
                            # committed transition without its anchor.
                            try:
                                anchor.initialize_locked()
                                frame_seq = self._anchor_frame_count()
                                prev_label = anchor.last_label()
                                anchor.append_locked(
                                    frame_seq,
                                    tenant_id,
                                    request_id,
                                    next_seq + 1,
                                    next_link_hash,
                                    prev_label,
                                )
                            except (OSError, _AnchorCorrupt, ValueError):
                                try:
                                    conn.execute("ROLLBACK")
                                except sqlite3.Error:
                                    pass
                                raise RuntimeError(
                                    "failed to persist status transition"
                                ) from None
                        conn.execute("COMMIT")
                    except InvalidStatusTransition:
                        raise
                    except RequestNotFound:
                        raise
                    except RuntimeError:
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
                    if anchor is not None:
                        anchor.release()
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
        empty arguments raise :class:`ValueError`. The receipt never
        contains key material or anchor internals.
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
        """Verify the key-anchored audit chain for a request.

        Returns ``True`` only when *all* of the following hold:

        * the store was opened with a caller-held ``integrity_key``;
        * the sidecar exists, is complete, and every frame
          authenticates under that key in an unbroken global chain;
        * the sidecar agrees with SQLite for every request (frame
          counts, per-event digests and anchored heads);
        * the request's own links recompute from the genesis
          predecessor over gap-free sequences, its final link is the
          anchored head, and its current status matches the final
          event.

        Deleting, altering, inserting, reordering or substituting
        events across requests or tenants, tampering with the request
        head or status, truncating or replacing the sidecar, or
        recomputing and replacing *all* public SQLite and sidecar
        content without the caller's key all yield ``False``. A
        missing key, a missing or corrupt sidecar, legacy data with no
        trusted anchor, and an interrupted commit likewise yield
        ``False``. Verification is strictly read-only. Unknown ids and
        cross-tenant lookups raise :class:`RequestNotFound`; non-string
        or empty arguments raise :class:`ValueError`.
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
        if self._anchor is None or self._integrity_key is None:
            # No caller-held key means no trust anchor. Still resolve
            # ownership so unknown/cross-tenant access raises identically.
            self._assert_owner(tenant_id, request_id)
            return False
        conn = self._connect()
        anchor = self._anchor
        assert anchor is not None
        try:
            anchor.acquire(shared=True)
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
                    if not _is_chain_hash(anchored_head):
                        return False
                except RequestNotFound:
                    raise
                except sqlite3.Error:
                    raise RuntimeError(
                        "failed to verify request evidence"
                    ) from None

                # Global trust gate: the authenticated sidecar must agree
                # with SQLite for every request, not just the one being
                # queried. An interrupted commit anywhere invalidates the
                # evidence of every request (fail closed).
                try:
                    status, groups = self._recovery_state(conn)
                except sqlite3.Error:
                    raise RuntimeError(
                        "failed to verify request evidence"
                    ) from None
                if status != _RECOVERY_CONSISTENT:
                    return False
                anchored = groups.get((tenant_id, request_id))
                if not anchored:
                    return False

                try:
                    rows = conn.execute(
                        "SELECT seq, status, occurred_at, chain_hash "
                        "FROM status_events "
                        "WHERE tenant_id = ? AND request_id = ? ORDER BY seq",
                        (tenant_id, request_id),
                    ).fetchall()
                except sqlite3.Error:
                    raise RuntimeError(
                        "failed to verify request evidence"
                    ) from None
            finally:
                anchor.release()
        finally:
            self._release(conn)

        predecessor = _GENESIS_PREDECESSOR
        for expected_seq, row in enumerate(rows):
            seq, event_status, occurred_at, stored_hash = row
            # Gap-free sequences from zero: a deleted, inserted or
            # renumbered event cannot reach here unnoticed. Strict type
            # checks keep malformed (e.g. NULL) tampered rows from
            # reaching the hash preimage as anything but a failure.
            if (
                not isinstance(seq, int)
                or isinstance(seq, bool)
                or seq != expected_seq
                or not isinstance(event_status, str)
                or not isinstance(occurred_at, str)
                or not _is_chain_hash(stored_hash)
            ):
                return False
            # The HMAC anchor seals exactly this per-event digest.
            if expected_seq >= len(anchored) or anchored[expected_seq][0] != seq:
                return False
            if not hmac.compare_digest(anchored[expected_seq][1], stored_hash):
                return False
            recomputed = _chain_hash(
                tenant_id,
                request_id,
                seq,
                event_status,
                occurred_at,
                predecessor,
            )
            # Constant-time comparison; either mismatch breaks the chain.
            if not hmac.compare_digest(recomputed, stored_hash):
                return False
            predecessor = stored_hash

        # At least the genesis event must exist, the frame count must
        # match the event count, the final link must be the head anchored
        # on the request row, and its status must match the authoritative
        # current status.
        if not rows or len(anchored) != len(rows):
            return False
        if not hmac.compare_digest(predecessor, anchored_head):
            return False
        return rows[-1][1] == current_status

    def _assert_owner(self, tenant_id: str, request_id: str) -> None:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT 1 FROM requests WHERE tenant_id = ? AND request_id = ?",
                (tenant_id, request_id),
            ).fetchone()
        finally:
            self._release(conn)
        if row is None:
            raise RequestNotFound("request not found")

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
