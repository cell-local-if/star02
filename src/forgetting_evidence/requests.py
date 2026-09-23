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

Workers do not mutate request state directly. They atomically claim the
tenant's oldest runnable request through :meth:`RequestStore.claim_next`,
which persists an execution lease (an opaque, unpredictable claim token
plus an expiry instant) in the database, so leases survive process and
store-instance restarts and are mutually exclusive across concurrent
workers. A first claim moves an ``accepted`` request to ``processing``
in the same transaction and appends the matching audit event; reclaiming
a request whose lease expired only refreshes the lease, never the
timeline. :meth:`RequestStore.finish_claim` resolves a held lease to a
terminal status. Neither the token, the worker identifier nor any lease
detail is ever written to logs or surfaced in exception text.
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
from datetime import datetime, timedelta, timezone

__all__ = [
    "RequestStore",
    "IdempotencyConflict",
    "RequestNotFound",
    "InvalidStatusTransition",
    "ClaimConflict",
]

_log = logging.getLogger(__name__)


class IdempotencyConflict(Exception):
    """Raised when an idempotency key is reused with a different payload."""


class RequestNotFound(Exception):
    """Raised when no request visible to the tenant matches the id."""


class InvalidStatusTransition(Exception):
    """Raised when a requested status change is unknown or not permitted."""


class ClaimConflict(Exception):
    """Raised when a claim token is unknown, spent or expired for the tenant."""


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

# One row per request that has ever been claimed. The single live lease is
# identified by lease_epoch (incremented on each reclaim): finish_claim only
# honours the token/epoch currently stored, so an expired or superseded
# token can never complete a request another worker now holds. The token is
# stored only as a SHA-256 digest, so a database disclosure never yields a
# usable bearer credential. A non-null finished_at marks a spent lease and
# keeps the completed/failed decision auditable without exposing payload.
_CLAIM_TABLE = """
CREATE TABLE IF NOT EXISTS request_claims (
    tenant_id       TEXT NOT NULL,
    request_id      TEXT NOT NULL,
    lease_epoch     INTEGER NOT NULL,
    claim_token_hash TEXT NOT NULL,
    worker_id       TEXT NOT NULL,
    leased_at       TEXT NOT NULL,
    lease_expires_at TEXT NOT NULL,
    finished_at     TEXT,
    PRIMARY KEY (tenant_id, request_id, lease_epoch),
    FOREIGN KEY (tenant_id, request_id) REFERENCES requests(tenant_id, request_id)
);
"""

# A token always identifies exactly one lease, across every tenant: the
# finish lookup relies on this to tell "no such token" apart from "token
# belongs to another tenant", and the digest itself is the credential.
_CLAIM_TOKEN_INDEX = """
CREATE UNIQUE INDEX IF NOT EXISTS idx_claims_token
    ON request_claims(claim_token_hash);
"""

# Database-level guarantee that a request never carries two live leases at
# once: only the current lease keeps finished_at NULL, so the partial index
# holds at most one row per request. Expired-but-unreclaimed leases still
# count as the single live lease until a reclaim closes them.
_CLAIM_ACTIVE_INDEX = """
CREATE UNIQUE INDEX IF NOT EXISTS idx_claims_active
    ON request_claims(tenant_id, request_id)
    WHERE finished_at IS NULL;
"""

# Drives the ordered worker queue: only the live lease per request keeps
# finished_at NULL, so the expired-lease walk stays an index scan and never
# grows with the number of reclaims.
_CLAIMABLE_ACCEPTED_INDEX = """
CREATE INDEX IF NOT EXISTS idx_claims_accepted_order
    ON requests(tenant_id, created_at, request_id)
    WHERE status = 'accepted';
"""

_CLAIMABLE_EXPIRED_INDEX = """
CREATE INDEX IF NOT EXISTS idx_claims_expired_order
    ON request_claims(tenant_id, lease_expires_at, request_id)
    WHERE finished_at IS NULL;
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

# Lease lifetimes are caller-chosen but bounded: a zero or negative lease
# is meaningless and an unbounded one would let a dead worker hold a
# request forever. Booleans are rejected even though they are ints.
_MIN_LEASE_SECONDS = 1
_MAX_LEASE_SECONDS = 3600

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


def _validate_lease_seconds(value: object) -> int:
    # bool is an int subclass; an explicit, non-boolean integer is required.
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("lease_seconds must be an integer between 1 and 3600")
    if not _MIN_LEASE_SECONDS <= value <= _MAX_LEASE_SECONDS:
        raise ValueError("lease_seconds must be an integer between 1 and 3600")
    return value


def _new_claim_token() -> str:
    """Return an unpredictable, URL-safe bearer token for one lease."""
    return uuid.uuid4().hex + uuid.uuid4().hex


def _hash_claim_token(claim_token: str) -> str:
    """Digest a bearer token so the credential itself is never at rest."""
    return hashlib.sha256(claim_token.encode("utf-8")).hexdigest()


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
    # Always emit six fractional digits: timestamps then sort lexicographically
    # even across a whole-second boundary (a bare ``...00Z`` would sort after
    # ``...00.000001Z`` and invert the true order).
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def _lease_expiry_rfc3339(leased_at: str, lease_seconds: int) -> str:
    """Derive the lease deadline from its start, both UTC RFC3339 strings."""
    start = datetime.fromisoformat(leased_at.replace("Z", "+00:00"))
    deadline = start + timedelta(seconds=lease_seconds)
    return (
        deadline.astimezone(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


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


class RequestStore:
    """Persist and retrieve accepted deletion requests."""

    def __init__(self, db_path: str | os.PathLike[str]):
        self._db_path = os.fspath(db_path)
        # In-process serialization; the unique index additionally guards
        # other processes sharing the same database file.
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
            conn.execute(_CLAIM_TABLE)
            conn.execute(_CLAIM_TOKEN_INDEX)
            conn.execute(_CLAIM_ACTIVE_INDEX)
            conn.execute(_CLAIMABLE_ACCEPTED_INDEX)
            conn.execute(_CLAIMABLE_EXPIRED_INDEX)
            self._migrate_schema(conn)
        finally:
            self._release(conn)

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
                except sqlite3.Error:
                    conn.execute("ROLLBACK")
                    raise RuntimeError("failed to persist accepted request") from None
                conn.execute("COMMIT")
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
                try:
                    conn.execute("BEGIN IMMEDIATE")
                except sqlite3.Error:
                    # Never surface the database engine's own error text.
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
                    conn.execute("COMMIT")
                except InvalidStatusTransition:
                    raise
                except RequestNotFound:
                    raise
                except sqlite3.Error:
                    # Best-effort cleanup; the rollback failure must not mask
                    # the original problem or leak engine text.
                    try:
                        conn.execute("ROLLBACK")
                    except sqlite3.Error:
                        pass
                    raise RuntimeError("failed to persist status transition") from None
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

    def _persist_status_event(
        self,
        conn: sqlite3.Connection,
        tenant_id: str,
        request_id: str,
        expected_current: str,
        target_status: str,
    ) -> str:
        """Append a chained status event and move the request, in-txn.

        Mirrors the write half of :meth:`transition`: the predecessor link
        is read from the persisted timeline, the new link binds it, the
        request head is updated only while the status still matches
        ``expected_current``, and the event insert shares the transaction.
        Returns the request's original acceptance timestamp.
        """
        created_row = conn.execute(
            "SELECT created_at FROM requests "
            "WHERE tenant_id = ? AND request_id = ?",
            (tenant_id, request_id),
        ).fetchone()
        if created_row is None:
            # Ownership was resolved by the caller; losing the row here can
            # only mean out-of-band damage. Never fabricate a receipt.
            raise RequestNotFound("request not found")
        (created_at,) = created_row
        latest = conn.execute(
            "SELECT seq, occurred_at, chain_hash FROM status_events "
            "WHERE tenant_id = ? AND request_id = ? ORDER BY seq DESC LIMIT 1",
            (tenant_id, request_id),
        ).fetchone()
        if latest is None or not _is_chain_hash(latest[2]):
            # Defensive only: every accepted request owns its seq-0 link.
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
                expected_current,
            ),
        )
        if cursor.rowcount != 1:
            # Another writer changed the status between selection and the
            # guarded update; the caller retries selection.
            raise _PrimaryKeyConflict
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
        return created_at

    def claim_next(
        self,
        tenant_id: str,
        worker_id: str,
        lease_seconds: int,
    ) -> dict[str, str] | None:
        """Atomically lease the tenant's oldest runnable deletion request.

        Candidates are the tenant's ``accepted`` requests and ``processing``
        requests whose current lease has expired, considered together and
        ordered by acceptance time and then request id. Returns ``None``
        when no request is runnable. Otherwise the lease is persisted and
        the result contains exactly ``request_id``, an unpredictable
        ``claim_token`` and a UTC RFC3339 ``lease_expires_at``.

        A first claim moves an ``accepted`` request to ``processing`` and
        appends the matching audit event in the same transaction; claiming
        an expired lease only rotates the lease (and its token), leaving
        the status timeline untouched. Identifiers must be non-empty
        strings and ``lease_seconds`` an integer from 1 to 3600 (booleans
        rejected); otherwise :class:`ValueError` is raised before any
        write.
        """
        tenant_id = _require_nonempty_str(tenant_id, "tenant_id")
        worker_id = _require_nonempty_str(worker_id, "worker_id")
        lease_seconds = _validate_lease_seconds(lease_seconds)

        with self._write_lock:
            conn = self._connect()
            try:
                claimed = None
                for attempt in range(_MAX_INSERT_ATTEMPTS):
                    try:
                        # BEGIN IMMEDIATE serializes claiming workers, including
                        # workers in other processes sharing the file: the
                        # winner's committed lease is what every loser then sees.
                        conn.execute("BEGIN IMMEDIATE")
                    except sqlite3.Error:
                        raise RuntimeError(
                            "failed to persist request claim"
                        ) from None
                    try:
                        claimed = self._claim_locked(
                            conn, tenant_id, worker_id, lease_seconds
                        )
                        break
                    except _PrimaryKeyConflict:
                        # Lost a guarded update (defensive; IMMEDIATE already
                        # serializes writers): discard and re-select.
                        try:
                            conn.execute("ROLLBACK")
                        except sqlite3.Error:
                            pass
                        continue
                    except RequestNotFound:
                        raise
                    except sqlite3.Error:
                        try:
                            conn.execute("ROLLBACK")
                        except sqlite3.Error:
                            pass
                        raise RuntimeError(
                            "failed to persist request claim"
                        ) from None
            finally:
                self._release(conn)
        if claimed is not None:
            _log.info(
                "request claim persisted request_id=%s lease_expires_at=%s",
                claimed["request_id"],
                claimed["lease_expires_at"],
            )
        return claimed

    def _claim_locked(
        self,
        conn: sqlite3.Connection,
        tenant_id: str,
        worker_id: str,
        lease_seconds: int,
    ) -> dict[str, str] | None:
        now = _utc_now_rfc3339()
        # One FIFO queue across both candidate classes, ordered strictly by
        # acceptance time then request id as the specification requires.
        candidate = conn.execute(
            "SELECT request_id FROM ("
            " SELECT request_id, created_at AS sort_key FROM requests"
            "  WHERE tenant_id = ? AND status = 'accepted'"
            " UNION ALL"
            " SELECT r.request_id, r.created_at"
            "  FROM request_claims c"
            "  JOIN requests r"
            "    ON r.tenant_id = c.tenant_id AND r.request_id = c.request_id"
            "  WHERE c.tenant_id = ? AND c.finished_at IS NULL"
            "    AND r.status = 'processing' AND c.lease_expires_at <= ?"
            ") ORDER BY sort_key, request_id LIMIT 1",
            (tenant_id, tenant_id, now),
        ).fetchone()
        if candidate is None:
            conn.execute("ROLLBACK")
            return None
        (request_id,) = candidate

        state = conn.execute(
            "SELECT r.status, c.lease_epoch FROM requests r"
            " LEFT JOIN request_claims c"
            "   ON c.tenant_id = r.tenant_id"
            "  AND c.request_id = r.request_id"
            "  AND c.finished_at IS NULL"
            " WHERE r.tenant_id = ? AND r.request_id = ?",
            (tenant_id, request_id),
        ).fetchone()
        if state is None:
            # Vanished between selection and read; impossible under the
            # write lock, but refuse rather than inventing a lease.
            raise _PrimaryKeyConflict
        current_status, live_epoch = state

        leased_at = now
        lease_expires_at = _lease_expiry_rfc3339(leased_at, lease_seconds)

        if current_status == _STATUS_ACCEPTED:
            if live_epoch is not None:
                # An accepted request cannot hold a live lease; the
                # invariant was broken out of band.
                raise _PrimaryKeyConflict
            lease_epoch = 0
            # The accepted->processing move, its audit event and the lease
            # row are one unit of commit: a claimed request is always
            # already processing with a usable token.
            created_at = self._persist_status_event(
                conn,
                tenant_id,
                request_id,
                _STATUS_ACCEPTED,
                _STATUS_PROCESSING,
            )
        elif current_status == _STATUS_PROCESSING:
            if live_epoch is None:
                # Processing without any live lease cannot be reclaimed via
                # the candidate set; skip it.
                raise _PrimaryKeyConflict
            # Expired reclaim: rotate the lease only. The prior lease is
            # closed at the handover instant and no status event is added,
            # so repeated reclaim-after-expiry leaves a single processing
            # entry in the audit timeline.
            lease_epoch = live_epoch + 1
            close_cursor = conn.execute(
                "UPDATE request_claims SET finished_at = ?"
                " WHERE tenant_id = ? AND request_id = ?"
                "   AND lease_epoch = ? AND finished_at IS NULL",
                (leased_at, tenant_id, request_id, live_epoch),
            )
            if close_cursor.rowcount != 1:
                raise _PrimaryKeyConflict
            created_at = conn.execute(
                "SELECT created_at FROM requests "
                "WHERE tenant_id = ? AND request_id = ?",
                (tenant_id, request_id),
            ).fetchone()[0]
        else:
            # Terminal or otherwise not claimable.
            raise _PrimaryKeyConflict

        claim_token = _new_claim_token()
        claim_token_hash = _hash_claim_token(claim_token)
        try:
            conn.execute(
                "INSERT INTO request_claims ("
                "tenant_id, request_id, lease_epoch, claim_token_hash, "
                "worker_id, leased_at, lease_expires_at, finished_at"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, NULL)",
                (
                    tenant_id,
                    request_id,
                    lease_epoch,
                    claim_token_hash,
                    worker_id,
                    leased_at,
                    lease_expires_at,
                ),
            )
        except sqlite3.IntegrityError:
            # A digest collision on a fresh 256-bit token is astronomically
            # unlikely; treat it like an allocation failure and retry.
            raise _PrimaryKeyConflict
        conn.execute("COMMIT")
        return {
            "request_id": request_id,
            "claim_token": claim_token,
            "lease_expires_at": lease_expires_at,
        }

    def finish_claim(
        self,
        tenant_id: str,
        claim_token: str,
        target_status: str,
    ) -> dict[str, str]:
        """Atomically complete a request held under a live claim token.

        ``target_status`` must be ``completed`` or ``failed``. Only the
        token of the request's current, unexpired lease succeeds; the
        request moves to the terminal status with its chained audit event
        in the same transaction and the lease is marked finished. Returns
        the same receipt shape as :meth:`get` and :meth:`transition`.

        Unknown tokens and tokens owned by another tenant raise
        :class:`RequestNotFound`, indistinguishable from a missing request.
        Expired, superseded or already-spent tokens, and tokens whose
        request is no longer awaiting completion, raise
        :class:`ClaimConflict` without writing. Invalid arguments raise
        :class:`ValueError` before any write.
        """
        tenant_id = _require_nonempty_str(tenant_id, "tenant_id")
        claim_token = _require_nonempty_str(claim_token, "claim_token")
        target_status = _require_nonempty_str(target_status, "target_status")
        if target_status not in (_STATUS_COMPLETED, _STATUS_FAILED):
            raise InvalidStatusTransition("unknown target status")

        with self._write_lock:
            conn = self._connect()
            try:
                try:
                    conn.execute("BEGIN IMMEDIATE")
                except sqlite3.Error:
                    raise RuntimeError("failed to persist claim completion") from None
                try:
                    receipt = self._finish_claim_locked(
                        conn, tenant_id, claim_token, target_status
                    )
                    conn.execute("COMMIT")
                except (RequestNotFound, ClaimConflict):
                    conn.execute("ROLLBACK")
                    raise
                except sqlite3.Error:
                    try:
                        conn.execute("ROLLBACK")
                    except sqlite3.Error:
                        pass
                    raise RuntimeError("failed to persist claim completion") from None
            finally:
                self._release(conn)
        _log.info(
            "claim completion persisted request_id=%s status=%s",
            receipt["request_id"],
            target_status,
        )
        return receipt

    def _finish_claim_locked(
        self,
        conn: sqlite3.Connection,
        tenant_id: str,
        claim_token: str,
        target_status: str,
    ) -> dict[str, str]:
        now = _utc_now_rfc3339()
        claim_token_hash = _hash_claim_token(claim_token)
        row = conn.execute(
            "SELECT tenant_id, request_id, lease_epoch, finished_at, lease_expires_at "
            "FROM request_claims WHERE claim_token_hash = ?",
            (claim_token_hash,),
        ).fetchone()
        if row is None:
            # Unknown bearer token: report exactly like an unknown request.
            raise RequestNotFound("request not found")
        owner_tenant, request_id, lease_epoch, finished_at, lease_expires_at = row
        if owner_tenant != tenant_id:
            # Cross-tenant presentation is indistinguishable from missing,
            # mirroring get()/audit(): never confirm another tenant's lease.
            raise RequestNotFound("request not found")
        if finished_at is not None or lease_expires_at <= now:
            # Same-tenant token that is spent, superseded by a newer lease
            # or past its deadline: a conflict rather than a missing record.
            raise ClaimConflict("claim is not active")

        request_row = conn.execute(
            "SELECT status FROM requests WHERE tenant_id = ? AND request_id = ?",
            (tenant_id, request_id),
        ).fetchone()
        if request_row is None or request_row[0] != _STATUS_PROCESSING:
            # The request vanished or was moved out of processing by another
            # path; the live token can no longer complete it.
            raise ClaimConflict("claim is not active")

        try:
            created_at = self._persist_status_event(
                conn,
                tenant_id,
                request_id,
                _STATUS_PROCESSING,
                target_status,
            )
        except _PrimaryKeyConflict:
            # The guarded move saw the status change after the read above;
            # the token no longer owns a processing request.
            raise ClaimConflict("claim is not active") from None
        finish_cursor = conn.execute(
            "UPDATE request_claims SET finished_at = ?"
            " WHERE tenant_id = ? AND request_id = ? AND lease_epoch = ?"
            "   AND finished_at IS NULL AND lease_expires_at > ?",
            (now, tenant_id, request_id, lease_epoch, now),
        )
        if finish_cursor.rowcount != 1:
            # Lost the lease between validation and the guarded write.
            raise ClaimConflict("claim is not active")
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
        """Verify the persisted audit chain for a request.

        Every link is checked against the stored rows only; verification
        never recomputes-and-overwrites persisted evidence. Deleting,
        altering, inserting or reordering events, tampering with the
        request head, or substituting events from another request or
        tenant all yield ``False``. Returns ``True`` only when every link
        recomputes to its stored hash from the genesis predecessor, the
        sequences are gap-free from zero, and the final link matches the
        request's anchored head and current status. Unknown ids and
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
                if not _is_chain_hash(anchored_head):
                    return False
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
