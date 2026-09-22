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

Per-request chains alone cannot expose a wholesale recomputation of the
database: deleting, inserting, reordering or substituting events (even
across requests or tenants) and then recomputing every stored hash
leaves internally consistent chains. The store therefore keeps an
*external anchor* in a sidecar file outside SQLite. The anchor holds an
HMAC key (generated randomly on first use and stored nowhere else) and a
hash-chain link authenticating the complete, canonicalised database
state after every committed write.

The two stores are advanced by a recoverable two-phase commit:

1. while the SQLite write transaction is open (so its own connection can
   see the pending state) a signed *intent* file describing the next
   anchor link is published via temp file + atomic replace;
2. the SQLite transaction is durably committed (``synchronous=FULL``);
3. the anchor sidecar is advanced with the prepared link, again via temp
   file + atomic replace and a directory fsync; the intent is unlinked.

A crash between phases leaves evidence that lets :meth:`recover` tell an
interrupted commit (``"incomplete"``) apart from genuine disagreement
(``"invalid"``). The next write resumes (rolls the prepared anchor
forward or discards an intent for a transaction SQLite never committed);
:meth:`recover` itself never repairs or backfills anything. A database
that existed before anchoring and has no sidecar is never silently
trusted: an operator may adopt it explicitly by supplying an
``integrity_key``, otherwise it stays ``"incomplete"`` and all writes are
refused. Additive chain-column migration still runs, but no audit record
is ever recomputed or overwritten.
"""

from __future__ import annotations

import base64
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
from contextlib import contextmanager
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


class _AnchorCorrupt(Exception):
    """Raised when a sidecar file cannot be parsed into a valid document."""


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

# SHA-256 of the empty string: predecessor of the first per-request link
# and the genesis state of the external anchor chain.
_GENESIS_PREDECESSOR = (
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)
_HEX = "0123456789abcdef"

# Sidecar layout: the anchor defaults to ``<database>.anchor`` next to
# the database file; the two-phase commit additionally stages an
# ``<database>.anchor.intent`` document. Both are updated through a
# sibling temporary file plus atomic replacement.
_ANCHOR_SUFFIX = ".anchor"
_INTENT_SUFFIX = ".intent"
_LOCK_SUFFIX = ".lock"
_TMP_SUFFIX = ".tmp"
_ANCHOR_VERSION = 1


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


def _is_hex64(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in _HEX for char in value)
    )


# Backwards-compatible alias used by the verification helpers.
_is_chain_hash = _is_hex64


def _fsync_dir(path: str) -> None:
    """Best-effort durable barrier for a directory entry change.

    ``fsync`` of the containing directory is required for a rename to
    survive a crash; platforms without directory fsync are skipped.
    """
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    handle = os.open(path, flags)
    try:
        os.fsync(handle)
    finally:
        os.close(handle)


def _atomic_write(path: str, payload: bytes) -> None:
    """Write ``payload`` to ``path`` via a sibling temp file and rename."""
    directory = os.path.dirname(os.path.abspath(path)) or "."
    tmp_path = path + _TMP_SUFFIX
    # A stale temporary file left by an interrupted update is overwritten;
    # it is never read as evidence.
    with open(tmp_path, "wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp_path, path)
    _fsync_dir(directory)


def _canonical_state_hash(conn: sqlite3.Connection) -> str:
    """Hash the complete audited database content in a canonical order.

    Every request row (including its anchored per-request head) and every
    event row participates, ordered deterministically by primary key and
    serialised as compact JSON with sorted keys. Deleting, modifying,
    inserting, reordering or substituting rows -- across requests or
    tenants -- or recomputing the SQLite content wholesale therefore
    changes the digest. Column order is fixed explicitly.
    """
    request_rows = conn.execute(
        "SELECT request_id, tenant_id, idempotency_key, subject_id, "
        "scopes_json, status, created_at, chain_hash "
        "FROM requests "
        "ORDER BY tenant_id, request_id"
    ).fetchall()
    event_rows = conn.execute(
        "SELECT tenant_id, request_id, seq, status, occurred_at, chain_hash "
        "FROM status_events "
        "ORDER BY tenant_id, request_id, seq"
    ).fetchall()
    payload = json.dumps(
        {"requests": request_rows, "events": event_rows},
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _link_digest(key: bytes, seq: int, predecessor: str, state_hash: str) -> str:
    return hmac.new(
        key,
        f"{seq}:{predecessor}:{state_hash}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


class _AnchorState:
    """Parsed contents of the external anchor sidecar."""

    __slots__ = ("key", "seq", "pred", "head")

    def __init__(self, key: bytes, seq: int, pred: str, head: str):
        self.key = key
        self.seq = seq
        self.pred = pred
        self.head = head


def _load_anchor(path: str) -> _AnchorState:
    try:
        with open(path, "rb") as handle:
            blob = handle.read()
        document = json.loads(blob.decode("utf-8"))
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        raise _AnchorCorrupt("anchor sidecar is missing or unreadable") from exc
    if not isinstance(document, dict):
        raise _AnchorCorrupt("anchor sidecar is malformed")
    if document.get("version") != _ANCHOR_VERSION:
        raise _AnchorCorrupt("anchor sidecar version is unsupported")
    key_b64 = document.get("key")
    seq = document.get("seq")
    pred = document.get("pred")
    head = document.get("head")
    if not isinstance(key_b64, str):
        raise _AnchorCorrupt("anchor sidecar key is malformed")
    try:
        key = base64.b64decode(key_b64, validate=True)
    except (ValueError, TypeError) as exc:
        raise _AnchorCorrupt("anchor sidecar key is malformed") from exc
    if len(key) < 32:
        raise _AnchorCorrupt("anchor sidecar key is malformed")
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 1:
        raise _AnchorCorrupt("anchor sidecar sequence is malformed")
    if not _is_hex64(pred) or not _is_hex64(head):
        raise _AnchorCorrupt("anchor sidecar links are malformed")
    return _AnchorState(key, seq, pred, head)


def _intent_mac(
    key: bytes, seq: int, predecessor: str, state_hash: str
) -> str:
    return hmac.new(
        key,
        f"intent:{seq}:{predecessor}:{state_hash}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _load_intent(path: str, key: bytes) -> tuple[int, str, str] | None:
    """Return ``(seq, predecessor, state_hash)`` from a staged intent.

    Returns ``None`` when no intent is staged. Malformed content or a
    failed HMAC raise :class:`_AnchorCorrupt`, indistinguishable from
    other interrupted-commit evidence for classification purposes. The
    MAC means an intent cannot be forged to authenticate an arbitrary
    database state without the key held only in the anchor sidecar.
    """
    if not os.path.exists(path):
        return None
    try:
        with open(path, "rb") as handle:
            document = json.loads(handle.read().decode("utf-8"))
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        raise _AnchorCorrupt("anchor intent is unreadable") from exc
    if not isinstance(document, dict) or document.get("version") != _ANCHOR_VERSION:
        raise _AnchorCorrupt("anchor intent is malformed")
    seq = document.get("seq")
    pred = document.get("pred")
    state_hash = document.get("state")
    mac = document.get("mac")
    if (
        not isinstance(seq, int)
        or isinstance(seq, bool)
        or seq < 1
        or not _is_hex64(pred)
        or not _is_hex64(state_hash)
        or not _is_hex64(mac)
    ):
        raise _AnchorCorrupt("anchor intent is malformed")
    if not hmac.compare_digest(
        _intent_mac(key, seq, pred, state_hash), mac
    ):
        raise _AnchorCorrupt("anchor intent signature is invalid")
    return seq, pred, state_hash


class RequestStore:
    """Persist and retrieve accepted deletion requests."""

    def __init__(
        self,
        db_path: str | os.PathLike[str],
        anchor_path: str | os.PathLike[str] | None = None,
        integrity_key: bytes | str | None = None,
    ):
        self._db_path = os.fspath(db_path)
        # Reentrant in-process serialization: recover/verify helpers may
        # be invoked while a write already holds the lock. The unique
        # index additionally guards other processes sharing the database.
        self._write_lock = threading.RLock()
        self._in_memory = self._db_path == ":memory:"
        if integrity_key is not None:
            if isinstance(integrity_key, str):
                integrity_key = integrity_key.encode("utf-8")
            if not isinstance(integrity_key, (bytes, bytearray)) or not integrity_key:
                raise ValueError("integrity_key must be a non-empty bytes-like value")
            integrity_key = bytes(integrity_key)
        self._integrity_key_arg: bytes | None = integrity_key

        if self._in_memory:
            self._mem_conn: sqlite3.Connection | None = self._open_connection()
            self._anchor_path: str | None = None
            self._intent_path: str | None = None
            self._lock_fd: int | None = None
            # Ephemeral anchor: enforces the invariant in-process but,
            # like the :memory: database itself, cannot outlive it.
            self._anchor = _AnchorState(integrity_key or os.urandom(32), 0,
                                        _GENESIS_PREDECESSOR, _GENESIS_PREDECESSOR)
            self._anchor_key_mismatch = False
        else:
            self._mem_conn = None
            db_parent = os.path.dirname(os.path.abspath(self._db_path))
            os.makedirs(db_parent, exist_ok=True)
            if anchor_path is None:
                anchor_path = self._db_path + _ANCHOR_SUFFIX
            self._anchor_path = os.fspath(anchor_path)
            self._intent_path = self._anchor_path + _INTENT_SUFFIX
            lock_path = self._anchor_path + _LOCK_SUFFIX
            # The anchor must live outside SQLite: pointing it at the
            # database file would void the out-of-band guarantee.
            if os.path.abspath(self._anchor_path) == os.path.abspath(self._db_path):
                raise ValueError("anchor_path must not be the SQLite database file")
            os.makedirs(
                os.path.dirname(os.path.abspath(self._anchor_path)) or ".",
                exist_ok=True,
            )
            # A process-scoped lock serialises the SQLite commit and the
            # sidecar replacement across processes: nobody can observe or
            # reconcile another writer's in-flight commit.
            self._lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
            self._anchor = None  # type: ignore[assignment]
            self._anchor_key_mismatch = False

        db_existed = not self._in_memory and os.path.exists(self._db_path)

        conn = self._connect()
        try:
            # RLock first, then the cross-process flock, matching the
            # nesting order used by every write/read path.
            with self._write_lock, self._cross_lock(True):
                conn.execute(_SCHEMA)
                conn.execute(_UNIQUE_TENANT_KEY)
                conn.execute(_EVENT_TABLE)
                self._migrate_schema_locked(conn)
                if not self._in_memory:
                    self._init_anchor(conn, db_existed)
        finally:
            self._release(conn)

    # -- schema / anchor initialisation ---------------------------------

    def _migrate_schema_locked(self, conn: sqlite3.Connection) -> None:
        """Add chain columns to a database written by an older version.

        The caller holds the in-process and cross-process commit locks.
        The upgrade is additive and runs at most once: the columns start
        nullable, existing events are backfilled in sequence order, and
        each request head is anchored at its final event. Existing chain
        values are never recomputed or overwritten, and audit rows are
        never modified by an upgrade.
        """
        if conn.execute(_REQUEST_CHAIN_COLUMN).fetchone() and conn.execute(
            _EVENT_CHAIN_COLUMN
        ).fetchone():
            return
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

    def _database_is_empty(self, conn: sqlite3.Connection) -> bool:
        requests_count = conn.execute("SELECT count(*) FROM requests").fetchone()[0]
        events_count = conn.execute("SELECT count(*) FROM status_events").fetchone()[0]
        return requests_count == 0 and events_count == 0

    def _init_anchor(self, conn: sqlite3.Connection, db_existed: bool) -> None:
        """Establish the external anchor at construction time.

        Trust boundary:

        * existing sidecar: load it; a wrong ``integrity_key`` or corrupt
          content leaves the store untrusted but never overwrites the
          file;
        * no sidecar for a database we just created (or an empty one):
          take the empty state as the genesis snapshot -- there is no
          pre-existing evidence to vouch for;
        * no sidecar for a non-empty, pre-existing database: an
          unanchored legacy database is never silently trusted. Supplying
          an explicit ``integrity_key`` is the operator's deliberate
          adoption gesture and anchors the migrated state; otherwise the
          store opens as ``incomplete`` and writes are refused.
        """
        assert self._anchor_path is not None
        if os.path.exists(self._anchor_path):
            try:
                anchor = _load_anchor(self._anchor_path)
            except _AnchorCorrupt:
                # Keep the damaged evidence untouched so recover() can
                # report it; writes stay blocked.
                self._anchor = None
                return
            if self._integrity_key_arg is not None and not hmac.compare_digest(
                anchor.key, self._integrity_key_arg
            ):
                # Re-keyed sidecar: remember the mismatch and never trust
                # or overwrite it.
                self._anchor = anchor
                self._anchor_key_mismatch = True
                return
            self._anchor = anchor
            return

        empty_database = self._database_is_empty(conn)
        if db_existed and not empty_database and self._integrity_key_arg is None:
            # Legacy data with no external evidence: do not create an
            # anchor and do not treat the database as trusted.
            self._anchor = None
            return

        key = self._integrity_key_arg or os.urandom(32)
        anchor = _AnchorState(key, 0, _GENESIS_PREDECESSOR, _GENESIS_PREDECESSOR)
        # Stage the genesis document in a sibling temporary file, then
        # claim the sidecar name with an exclusive hard link: the name
        # appears atomically with complete content, so no process can
        # ever read a half-written bootstrap anchor.
        assert self._anchor_path is not None
        state_hash = _canonical_state_hash(conn)
        seq = 1
        pred = _GENESIS_PREDECESSOR
        head = _link_digest(key, seq, pred, state_hash)
        document = json.dumps(
            {
                "version": _ANCHOR_VERSION,
                "key": base64.b64encode(key).decode("ascii"),
                "seq": seq,
                "pred": pred,
                "head": head,
            },
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        directory = os.path.dirname(os.path.abspath(self._anchor_path)) or "."
        tmp_path = self._anchor_path + _TMP_SUFFIX
        try:
            with open(tmp_path, "wb") as handle:
                handle.write(document)
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.link(tmp_path, self._anchor_path)
            except FileExistsError:
                # A concurrent constructor bootstrapped first; adopt its
                # sidecar rather than replacing it.
                bootstrap = _load_anchor(self._anchor_path)
                if self._integrity_key_arg is not None and not hmac.compare_digest(
                    bootstrap.key, self._integrity_key_arg
                ):
                    self._anchor = bootstrap
                    self._anchor_key_mismatch = True
                    return
                self._anchor = bootstrap
                return
            _fsync_dir(directory)
        finally:
            try:
                os.remove(tmp_path)
            except FileNotFoundError:
                pass
        anchor.seq = seq
        anchor.pred = pred
        anchor.head = head
        self._anchor = anchor

    # -- connections ----------------------------------------------------

    @contextmanager
    def _cross_lock(self, exclusive: bool):
        """Serialise SQLite/sidecar commit interleaving across processes.

        Writers hold the exclusive lock from before the SQLite write
        transaction until the staged intent is cleared; readers take a
        shared lock, so neither can observe a half-completed commit of
        another process. An OS-level lock is released automatically when
        a process dies mid-commit, which is exactly what makes the
        staged intent recoverable by the next writer.
        """
        if self._in_memory or self._lock_fd is None:
            yield
            return
        flag = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
        fcntl.flock(self._lock_fd, flag)
        try:
            yield
        finally:
            fcntl.flock(self._lock_fd, fcntl.LOCK_UN)

    def _open_connection(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self._db_path,
            timeout=_BUSY_TIMEOUT_MS / 1000,
            check_same_thread=False,
        )
        connection.isolation_level = None  # explicit transaction control
        connection.execute(f"PRAGMA busy_timeout = {_BUSY_TIMEOUT_MS}")
        if not self._in_memory:
            # WAL + synchronous FULL make COMMIT a durability barrier
            # (the WAL is fsync-ed), so the anchor can only name state
            # SQLite has already made crash-durable.
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
        return connection

    def _connect(self) -> sqlite3.Connection:
        if self._mem_conn is not None:
            return self._mem_conn
        return self._open_connection()

    def _release(self, conn: sqlite3.Connection) -> None:
        if conn is not self._mem_conn:
            conn.close()

    # -- recoverable commit ---------------------------------------------

    def _prepare_commit(
        self, conn: sqlite3.Connection
    ) -> tuple[int, str, str]:
        """Phase 1: publish the prepared anchor link for pending state.

        Executed inside the open write transaction, so the canonical
        hash sees exactly the rows the transaction is about to commit.
        """
        anchor = self._anchor
        assert anchor is not None
        state_hash = _canonical_state_hash(conn)
        seq = anchor.seq + 1
        pred = anchor.head
        if self._in_memory:
            return seq, pred, state_hash
        assert self._intent_path is not None
        document = {
            "version": _ANCHOR_VERSION,
            "seq": seq,
            "pred": pred,
            "state": state_hash,
            "mac": _intent_mac(anchor.key, seq, pred, state_hash),
        }
        _atomic_write(
            self._intent_path,
            json.dumps(
                document, ensure_ascii=False, separators=(",", ":"), sort_keys=True
            ).encode("utf-8"),
        )
        return seq, pred, state_hash

    def _finalize_commit(
        self,
        conn: sqlite3.Connection,
        prepared: tuple[int, str, str],
    ) -> None:
        """Phases 2-3: durably commit SQLite, then advance the anchor."""
        seq, pred, state_hash = prepared
        anchor = self._anchor
        assert anchor is not None
        try:
            conn.execute("COMMIT")
        except sqlite3.Error:
            raise RuntimeError("failed to persist request state") from None
        if self._in_memory:
            anchor.seq = seq
            anchor.pred = pred
            anchor.head = _link_digest(anchor.key, seq, pred, state_hash)
            return
        assert self._anchor_path is not None
        next_head = _link_digest(anchor.key, seq, pred, state_hash)
        document = {
            "version": _ANCHOR_VERSION,
            "key": base64.b64encode(anchor.key).decode("ascii"),
            "seq": seq,
            "pred": pred,
            "head": next_head,
        }
        try:
            _atomic_write(
                self._anchor_path,
                json.dumps(
                    document,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("utf-8"),
            )
        except OSError:
            # SQLite is durably committed but the anchor replacement did
            # not happen: the commit is interrupted and stays recoverable
            # from the staged intent. Never report success.
            raise RuntimeError("failed to persist integrity anchor") from None
        anchor.seq = seq
        anchor.pred = pred
        anchor.head = next_head
        self._clear_intent()

    def _clear_intent(self) -> None:
        if self._in_memory or self._intent_path is None:
            return
        try:
            os.remove(self._intent_path)
            _fsync_dir(os.path.dirname(os.path.abspath(self._intent_path)) or ".")
        except FileNotFoundError:
            pass
        except OSError:
            # A stale intent only denies future writes until it is removed
            # or superseded; never mask a successful anchor advance.
            pass

    def _resume_interrupted_commit(
        self, conn: sqlite3.Connection, anchor: _AnchorState
    ) -> None:
        """Roll a prepared, interrupted commit forward or back.

        Invoked only from the write path (never :meth:`recover`, which is
        strictly read-only). The staged intent and the current state
        identify exactly one crash window, mirroring
        :meth:`_assess_state`:

        * anchor updated, intent not cleared -- just clear the intent;
        * SQLite committed but anchor not updated -- publish the
          prepared link (roll-forward);
        * SQLite not committed -- discard the intent (rollback);
        * any other combination is genuine disagreement and is refused.
        """
        if self._in_memory or self._intent_path is None:
            return
        try:
            intent = _load_intent(self._intent_path, anchor.key)
        except _AnchorCorrupt:
            # The intent is internal staging state, not evidence. If the
            # database still matches the anchor exactly, no prepared
            # transaction can have committed, so the unreadable residue is
            # safe to discard from the write path. Any divergence is
            # refused; recover() itself never performs this cleanup.
            current_hash = _canonical_state_hash(conn)
            if hmac.compare_digest(
                _link_digest(
                    anchor.key, anchor.seq, anchor.pred, current_hash
                ),
                anchor.head,
            ):
                self._clear_intent()
                return
            raise RuntimeError("integrity anchor is incomplete") from None
        if intent is None:
            return
        seq, pred, prepared_state = intent
        current_hash = _canonical_state_hash(conn)
        prepared_committed = hmac.compare_digest(current_hash, prepared_state)
        anchor_matches = hmac.compare_digest(
            _link_digest(anchor.key, anchor.seq, anchor.pred, current_hash),
            anchor.head,
        )
        intent_extends_anchor = anchor.seq + 1 == seq and hmac.compare_digest(
            anchor.head, pred
        )

        if anchor_matches and not intent_extends_anchor and prepared_committed:
            # Crash after the anchor was replaced but before the intent
            # was unlinked; the committed state is already anchored.
            self._clear_intent()
            return
        if not anchor_matches and intent_extends_anchor and prepared_committed:
            # SQLite committed the prepared state but the anchor was not
            # replaced: finish the anchor phase (roll-forward).
            prepared_head = _link_digest(anchor.key, seq, pred, prepared_state)
            document = {
                "version": _ANCHOR_VERSION,
                "key": base64.b64encode(anchor.key).decode("ascii"),
                "seq": seq,
                "pred": pred,
                "head": prepared_head,
            }
            _atomic_write(
                self._anchor_path,  # type: ignore[arg-type]
                json.dumps(
                    document,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("utf-8"),
            )
            anchor.seq = seq
            anchor.pred = pred
            anchor.head = prepared_head
            self._clear_intent()
            return
        if anchor_matches and intent_extends_anchor and not prepared_committed:
            # The prepared transaction never committed; discard the
            # intent (rollback).
            self._clear_intent()
            return
        raise RuntimeError("integrity anchor is invalid")

    def _prepare_for_write(self, conn: sqlite3.Connection) -> None:
        """Cheap pre-transaction gate: the anchor must be available."""
        if self._anchor is None:
            raise RuntimeError("integrity anchor is incomplete")
        if self._anchor_key_mismatch:
            raise RuntimeError("integrity anchor is invalid")

    def _begin_write_tx(self, conn: sqlite3.Connection) -> None:
        """Acquire the SQLite write lock, then reconcile the anchor.

        BEGIN IMMEDIATE serialises all writers through SQLite, so the
        intent/sidecar reconciliation here cannot observe another
        process's commit mid-flight: that process clears its intent
        before releasing the lock. The anchor is re-read from disk so a
        long-lived instance observes links another process appended. An
        interrupted commit left by a dead predecessor is rolled forward
        (SQLite committed) or back (it did not) before any new write
        begins.
        """
        try:
            conn.execute("BEGIN IMMEDIATE")
        except sqlite3.Error:
            raise RuntimeError("failed to persist request state") from None
        try:
            disk_anchor = self._load_disk_anchor()
            if disk_anchor is None:
                raise RuntimeError("integrity anchor is incomplete")
            self._resume_interrupted_commit(conn, disk_anchor)
            state = self._assess_state(conn, disk_anchor)
            if state != "valid":
                raise RuntimeError(f"integrity anchor is {state}")
            # Adopt the freshest on-disk chain for subsequent staging.
            self._anchor = disk_anchor
        except RuntimeError:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise

    def _load_disk_anchor(self) -> _AnchorState | None:
        """Re-read the sidecar; ``None`` when missing or unreadable."""
        if self._in_memory:
            return self._anchor
        assert self._anchor_path is not None
        if not os.path.exists(self._anchor_path):
            return None
        try:
            return _load_anchor(self._anchor_path)
        except _AnchorCorrupt:
            return None

    # -- public API -----------------------------------------------------

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
            conn = self._connect()
            try:
                with self._cross_lock(True):
                    self._prepare_for_write(conn)
                    return self._insert_or_reuse(
                        conn, tenant_id, subject_id, scope_list,
                        idempotency_key, scopes_json,
                    )
            finally:
                self._release(conn)

    def _insert_or_reuse(
        self,
        conn: sqlite3.Connection,
        tenant_id: str,
        subject_id: str,
        scope_list: list[str],
        idempotency_key: str,
        scopes_json: str,
    ) -> dict[str, str]:
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
            self._begin_write_tx(conn)
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
            except sqlite3.Error:
                conn.execute("ROLLBACK")
                raise RuntimeError("failed to persist accepted request") from None
            try:
                prepared = self._prepare_commit(conn)
            except OSError:
                # The anchor intent could not be staged while SQLite is
                # still uncommitted: roll the transaction back so the two
                # stores can never diverge.
                conn.execute("ROLLBACK")
                raise RuntimeError("failed to persist integrity anchor") from None
            self._finalize_commit(conn, prepared)
            return {
                "request_id": request_id,
                "status": "accepted",
                "created_at": created_at,
            }
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
        tenant_id = _require_nonempty_str(tenant_id, "tenant_id")
        request_id = _require_nonempty_str(request_id, "request_id")
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
                with self._cross_lock(True):
                    self._prepare_for_write(conn)
                    result = self._transition_locked(
                        conn, tenant_id, request_id, target_status
                    )
            finally:
                self._release(conn)
        _log.info(
            "status transition persisted request_id=%s status=%s",
            request_id,
            target_status,
        )
        return result

    def _transition_locked(
        self,
        conn: sqlite3.Connection,
        tenant_id: str,
        request_id: str,
        target_status: str,
    ) -> dict[str, str]:
        try:
            self._begin_write_tx(conn)
        except RuntimeError:
            raise RuntimeError("failed to persist status transition") from None
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
                raise RuntimeError("failed to persist status transition")
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
            try:
                prepared = self._prepare_commit(conn)
            except OSError:
                # Anchor staging failed before SQLite committed: roll the
                # whole transition back rather than diverging the stores.
                try:
                    conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise RuntimeError("failed to persist integrity anchor") from None
            self._finalize_commit(conn, prepared)
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
            raise RuntimeError("failed to persist status transition") from None
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
        """Verify the persisted audit chain and its external anchor.

        Every link is checked against the stored rows only; verification
        never recomputes-and-overwrites persisted evidence. Deleting,
        altering, inserting or reordering events, tampering with the
        request head, or substituting events from another request or
        tenant all yield ``False``, as does a wholesale recomputation of
        the SQLite content: the complete database state must additionally
        authenticate against the sidecar anchor (``recover() ==
        "valid"``). A missing, corrupt, stale or interrupted anchor
        yields ``False``. Unknown ids and cross-tenant lookups raise
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
        with self._write_lock:
            return self._verify_evidence_locked(tenant_id, request_id)

    def _verify_evidence_locked(
        self, tenant_id: str, request_id: str
    ) -> bool:
        # The shared cross-process lock guarantees the SQLite snapshot
        # and the sidecar describe the same commit: a writer in another
        # process holds the exclusive lock from its SQLite transaction
        # through the anchor replacement.
        conn = self._connect()
        anchor_state = "invalid"
        rows: list[tuple[object, ...]] = []
        current_status = ""
        anchored_head = ""
        try:
            with self._cross_lock(False):
                try:
                    conn.execute("BEGIN")
                    owner = conn.execute(
                        "SELECT status, chain_hash FROM requests "
                        "WHERE tenant_id = ? AND request_id = ?",
                        (tenant_id, request_id),
                    ).fetchone()
                    if owner is None:
                        conn.execute("COMMIT")
                        raise RequestNotFound("request not found")
                    current_status, anchored_head = owner
                    anchor_state = self._assess_state(conn)
                    if anchor_state == "valid" and _is_chain_hash(anchored_head):
                        rows = conn.execute(
                            "SELECT seq, status, occurred_at, chain_hash "
                            "FROM status_events "
                            "WHERE tenant_id = ? AND request_id = ? ORDER BY seq",
                            (tenant_id, request_id),
                        ).fetchall()
                    conn.execute("COMMIT")
                except RequestNotFound:
                    raise
                except sqlite3.Error:
                    try:
                        conn.execute("ROLLBACK")
                    except sqlite3.Error:
                        pass
                    raise RuntimeError(
                        "failed to verify request evidence"
                    ) from None
        finally:
            self._release(conn)

        if anchor_state != "valid":
            return False
        if not _is_chain_hash(anchored_head):
            return False

        predecessor = _GENESIS_PREDECESSOR
        for expected_seq, row in enumerate(rows):
            seq, status, occurred_at, stored_hash = row
            # Gap-free sequences from zero: a deleted, inserted or
            # renumbered event cannot reach here unnoticed. Strict type
            # checks keep malformed (e.g. NULL) tampered rows from
            # reaching the hash preimage as anything but a failure.
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
                tenant_id,
                request_id,
                seq,
                status,
                occurred_at,
                predecessor,
            )
            # Constant-time comparison; either mismatch breaks the chain.
            if not hmac.compare_digest(recomputed, stored_hash):
                return False
            predecessor = stored_hash

        # At least the genesis event must exist, the final link must be
        # the head anchored on the request row, and its status must match
        # the authoritative current status.
        if not rows:
            return False
        if not hmac.compare_digest(predecessor, anchored_head):
            return False
        return rows[-1][1] == current_status

    def recover(self) -> str:
        """Assess database/anchor consistency without modifying anything.

        Returns one of:

        * ``"valid"`` -- the sidecar is present and intact and its anchor
          link authenticates the exact current database state;
        * ``"invalid"`` -- the anchor and the database disagree (the
          database or sidecar was altered, recomputed, replaced or
          re-keyed);
        * ``"incomplete"`` -- the sidecar is missing or unreadable, an
          anchor key is unavailable, or a commit was interrupted between
          SQLite and the sidecar.

        The call is strictly read-only: it never repairs or backfills.
        An interrupted commit is resumed only by a later successful
        :meth:`submit` or :meth:`transition`.
        """
        if self._in_memory:
            return "valid"
        with self._write_lock:
            conn = self._connect()
            try:
                with self._cross_lock(False):
                    try:
                        conn.execute("BEGIN")
                        state = self._assess_state(conn)
                        conn.execute("COMMIT")
                    except sqlite3.Error:
                        try:
                            conn.execute("ROLLBACK")
                        except sqlite3.Error:
                            pass
                        raise
                return state
            finally:
                self._release(conn)

    def _assess_state(
        self,
        conn: sqlite3.Connection,
        anchor: _AnchorState | None = None,
    ) -> str:
        """Classify the on-disk database/sidecar relationship.

        Read-only. The sidecar and intent are re-read from disk on every
        call (or the caller passes a freshly loaded ``anchor``) so
        out-of-band tampering is detected rather than served from cache.
        """
        if self._in_memory:
            return "valid"
        anchor_path = self._anchor_path
        intent_path = self._intent_path
        assert anchor_path is not None and intent_path is not None

        if anchor is None:
            if self._anchor is None or not os.path.exists(anchor_path):
                # Missing sidecar (including a legacy, never-anchored
                # database) or an unreadable sidecar recorded at open.
                return "incomplete"
            try:
                anchor = _load_anchor(anchor_path)
            except _AnchorCorrupt:
                return "incomplete"
        if self._integrity_key_arg is not None and not hmac.compare_digest(
            anchor.key, self._integrity_key_arg
        ):
            return "invalid"
        # Continuity with the key this instance booted with catches a
        # sidecar swapped for another database's anchor file.
        if self._anchor is not None and not hmac.compare_digest(
            anchor.key, self._anchor.key
        ):
            return "invalid"

        try:
            intent = _load_intent(intent_path, anchor.key)
        except _AnchorCorrupt:
            return "incomplete"

        state_hash = _canonical_state_hash(conn)
        anchor_matches = hmac.compare_digest(
            _link_digest(anchor.key, anchor.seq, anchor.pred, state_hash),
            anchor.head,
        )

        if intent is None:
            return "valid" if anchor_matches else "invalid"

        seq, pred, prepared_state = intent
        prepared_committed = hmac.compare_digest(state_hash, prepared_state)
        intent_extends_anchor = anchor.seq + 1 == seq and hmac.compare_digest(
            anchor.head, pred
        )

        if anchor_matches and not intent_extends_anchor and prepared_committed:
            # Crash after the anchor landed but before intent cleanup:
            # the anchor already covers the committed state.
            return "valid"
        if anchor_matches and intent_extends_anchor and not prepared_committed:
            # The prepared transaction never committed; SQLite still
            # holds the last anchored state but the commit is unfinished.
            return "incomplete"
        if not anchor_matches and intent_extends_anchor and prepared_committed:
            # SQLite committed the prepared state but the anchor was not
            # replaced: an interrupted, recoverable commit.
            return "incomplete"
        # Anything else (database diverged, intent unexplained) is a
        # genuine disagreement rather than a known crash window.
        return "invalid"

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
