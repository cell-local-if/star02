"""SQLite-backed acceptance store for deletion requests.

The store records deletion requests without retaining any identifying
payload in logs, return values beyond the fixed receipt fields, or
exception messages. SQLite integrity conflicts are translated into the
module's own idempotency semantics and never surface to callers.

Two read shapes are offered deliberately:

* :meth:`RequestStore.get` is the *acceptance* query and returns the
  frozen ``accepted`` receipt exactly as it was at submission time, no
  matter how the request's status subsequently advances. This is the
  record served by the HTTP lookup and idempotent submission replay.
* :meth:`RequestStore.get_status` is the *status* query and returns the
  same fixed record shape (``request_id``, ``status``, ``created_at``)
  but with the request's current status. The ``created_at`` field always
  stays the original acceptance time.

Status advances through :meth:`RequestStore.transition` along the fixed
lifecycle ``accepted -> processing -> {completed, failed}`` and
``accepted -> failed``. ``completed`` and ``failed`` are terminal.
Re-issuing the status a request already holds is an idempotent no-op.

Execution orchestration lives on the same store, storage-layer only:

* :meth:`RequestStore.claim_next` atomically leases the oldest claimable
  request (accepted, or processing with an expired lease) to a worker,
  moving a first-time claim to ``processing`` and recording an append-only
  attempt row. It returns the request id, an unpredictable single-use
  claim token and the UTC lease expiry; the worker identity is validated
  but never persisted, and only a hash of the token is stored.
* :meth:`RequestStore.finish_claim` commits a terminal result for the
  live lease: the status change, its audit-chain event, the attempt
  result and the token release land in one transaction. Unknown, expired,
  released or foreign tokens raise :class:`ClaimConflict` unchanged.
* :meth:`RequestStore.get_execution_log` returns the attempt history
  (sequence, claim and expiry times, terminal result and completion
  time) with only strings, integers and nulls -- never a worker or token.
* :meth:`RequestStore.reconcile_execution` reports the existing status
  record and, within a single atomic transaction, converges a request
  whose lease can no longer be valid: unfinished attempts are compensated
  to ``failed`` (their UTC RFC3339 completion time written exactly once)
  and a non-terminal request is brought to ``failed``. Requests that are
  accepted, hold a live lease or have already reached a terminal state
  are returned unchanged, and reconcile itself never inserts a request,
  an attempt or a receipt.
* :meth:`RequestStore.reconcile_batch` applies the same convergence to a
  bounded, resumable batch for one tenant: it scans the tenant's pending
  requests in a stable keyset order (skipping ``accepted`` requests with
  no attempt, receipt or extra event), reconciles up to an optional
  caller cap per call, and returns the batch id, an opaque continuation
  cursor (``None`` once finished) and per-item ``request_id``/``status``
  records. Each item's state, attempt, lease and the cursor advance land
  in one transaction; retried cursors keep the same batch id and resume
  from the persisted position. No HTTP route is added.

The lease boundary enforced by :meth:`claim_next` is deliberately
narrower than "every processing request whose latest timestamp is old":
a processing request is reclaimable after expiry only when its attempts
explain a genuine expired lease (at least one attempt whose latest lease
has expired and no open attempt still inside its lease). A processing
request that carries no attempt, or whose attempts are open without any
expired lease, is never claimed; only :meth:`reconcile_execution`
converges such records.

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

Caller errors are always :class:`ValueError` (invalid parameters) or the
module's own domain exceptions; every database failure -- an unwritable
path, an uncreatable or corrupt file, an I/O or read/write error -- is
reported as a fixed-text :class:`OSError` that never embeds SQL, engine
text or a filesystem path.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import secrets
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
    """Raised when a claim cannot be acquired or finished as requested.

    Covers a finish/release presented with a token that is unknown, expired,
    already released or owned by another tenant, as well as a finish
    attempted against a request that no longer holds a live claim. The
    fixed message never identifies which condition applied, so the outcome
    can never be used to probe for requests, workers or claim tokens.
    """


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

# Append-only execution attempts. One row per lease acquisition: the first
# claim of an accepted request starts attempt 1, and every reclaim after a
# lease expires starts the next sequential attempt. Rows are never updated
# and never deleted, so a worker that lost its lease can never rewrite
# history. ``claimed_at``/``lease_expires_at`` are set at acquisition;
# ``result``/``completed_at`` stay NULL until finish_claim records the
# terminal outcome. No worker identity and no claim token is ever stored.
_CLAIM_TABLE = """
CREATE TABLE IF NOT EXISTS claim_attempts (
    tenant_id       TEXT NOT NULL,
    request_id      TEXT NOT NULL,
    attempt_number  INTEGER NOT NULL,
    claimed_at      TEXT NOT NULL,
    lease_expires_at TEXT NOT NULL,
    result          TEXT,
    completed_at    TEXT,
    PRIMARY KEY (tenant_id, request_id, attempt_number)
);
"""

# Drives the "pick the oldest live candidate" query without a table scan:
# only requests that may still be claimed (accepted, or processing whose
# latest lease has expired) are indexed, ordered by acceptance time then id.
_CLAIM_CANDIDATE_INDEX = """
CREATE INDEX IF NOT EXISTS idx_claim_candidates
    ON requests(tenant_id, created_at, request_id);
"""

# Live claim tokens. At most one row per request: claiming releases every
# prior token and finishing deletes the winning one. Only a salt-free SHA-256
# of the token is stored, so the database at rest never contains the secret
# the worker presents; a leaked file cannot be replayed as a live claim.
_CLAIM_TOKEN_TABLE = """
CREATE TABLE IF NOT EXISTS claim_tokens (
    tenant_id      TEXT NOT NULL,
    request_id     TEXT NOT NULL,
    attempt_number INTEGER NOT NULL,
    token_hash     TEXT NOT NULL,
    PRIMARY KEY (tenant_id, request_id)
);
"""

# Resumable reconciliation batches. One row per (tenant, batch): the
# opaque cursor that resumes the batch, the keyset position already
# committed as inspected ("续跑 from the persisted position"), the
# declared limit and the sealed/finished flags plus the continuation
# cursor handed to the following batch. A row exists once per batch;
# retrying the same cursor reuses the same batch_id instead of minting
# another.
_BATCH_TABLE = """
CREATE TABLE IF NOT EXISTS reconcile_batches (
    tenant_id       TEXT NOT NULL,
    batch_id        TEXT NOT NULL,
    cursor_token    TEXT NOT NULL,
    next_cursor_token TEXT NOT NULL,
    max_items       INTEGER NOT NULL,
    inspected       INTEGER NOT NULL,
    last_created_at TEXT,
    last_request_id TEXT,
    sealed          INTEGER NOT NULL,
    finished        INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, batch_id)
);
"""

# The incoming cursor resolves a retry to its batch, so it must be
# unique within a tenant.
_BATCH_CURSOR_INDEX = """
CREATE UNIQUE INDEX IF NOT EXISTS idx_reconcile_batches_cursor
    ON reconcile_batches(tenant_id, cursor_token);
"""

# The requests a batch has already inspected and reported. Persisting
# the window makes a retried cursor replay the identical batch (same
# batch id, same items, same statuses and order) and lets a batch
# interrupted mid-window resume and then return the complete window.
_BATCH_ITEM_TABLE = """
CREATE TABLE IF NOT EXISTS reconcile_batch_items (
    tenant_id  TEXT NOT NULL,
    batch_id   TEXT NOT NULL,
    item_seq   INTEGER NOT NULL,
    request_id TEXT NOT NULL,
    status     TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, batch_id, item_seq)
);
"""

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

# Fixed, detail-free text for every storage-layer failure. It must never
# embed a SQL statement, the engine's own error text or a filesystem path.
_STORAGE_MESSAGE = "request store is unavailable"


def _storage_failure() -> OSError:
    """Build the single storage error callers are ever allowed to see."""
    return OSError(_STORAGE_MESSAGE)

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

# Execution leasing. A claim is held for at most 3600 seconds; a lease that
# has expired makes the request claimable again, starting a fresh attempt.
_MIN_LEASE_SECONDS = 1
_MAX_LEASE_SECONDS = 3600
# Terminal outcomes finish_claim is allowed to record.
_TERMINAL_RESULTS = frozenset({_STATUS_COMPLETED, _STATUS_FAILED})
# Claim tokens are presented as a fixed-width, URL-safe opaque secret. They
# are generated with the CSPRNG, returned exactly once at acquisition, and
# never persisted, logged or echoed back.
_TOKEN_BYTES = 32
# Fixed, detail-free text for every claim failure.
_CLAIM_CONFLICT_MESSAGE = "claim conflict"

# Batch reconciliation. A batch inspects at most this many pending
# requests per call; a smaller or default bound is used when the caller
# does not pin one.
_DEFAULT_BATCH_LIMIT = 100
_MIN_BATCH_LIMIT = 1
_MAX_BATCH_LIMIT = 1000
# Version tag carried inside every opaque cursor so an unknown format is
# rejected as an illegal cursor rather than misread as a position.
_CURSOR_VERSION = "v1"
# Cursor tokens are fixed-width, URL-safe opaque strings; the same CSPRNG
# as claim tokens backs them and the raw value is never persisted.
_CURSOR_BYTES = 32
# Distinguish the entry cursor of a batch from the continuation cursor
# handed back for the following batch.
_CURSOR_KIND_START = "s"
_CURSOR_KIND_NEXT = "n"


def _require_lease_seconds(value: object) -> int:
    """Validate a lease duration: a non-boolean int in 1..3600."""
    # bool is a subclass of int; a boolean lease is caller error, not a
    # 0/1 second lease.
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError("lease_seconds must be an integer between 1 and 3600")
    if not _MIN_LEASE_SECONDS <= value <= _MAX_LEASE_SECONDS:
        raise ValueError("lease_seconds must be an integer between 1 and 3600")
    return value


def _require_result(value: object) -> str:
    """Validate the terminal result handed to finish_claim."""
    if not isinstance(value, str) or value not in _TERMINAL_RESULTS:
        raise ValueError("result must be 'completed' or 'failed'")
    return value


def _new_claim_token() -> str:
    """Return an unpredictable, single-use claim token."""
    return secrets.token_urlsafe(_TOKEN_BYTES)


def _claim_conflict() -> ClaimConflict:
    """Build the single, detail-free claim error callers ever see."""
    return ClaimConflict(_CLAIM_CONFLICT_MESSAGE)


def _new_cursor(kind: str) -> str:
    """Return an unpredictable, opaque resumable-batch cursor."""
    return (
        f"{_CURSOR_VERSION}.{kind}."
        f"{secrets.token_urlsafe(_CURSOR_BYTES)}"
    )


# A cursor is an opaque handle: a version tag, a kind tag and a random
# token. The scan position it stands for lives only in the database, so
# the string reveals nothing about tenant data. Any shape not matching
# this grammar -- including a fabricated or unrecognised token -- is an
# illegal caller cursor, indistinguishable in error type.
_CURSOR_RE = re.compile(r"^v1[.][sn][.][A-Za-z0-9_-]{22,64}$")
_CURSOR_INVALID_MESSAGE = "cursor is not valid"


def _decode_cursor(value: object) -> str:
    """Validate an opaque cursor; return its kind tag (``s``/``n``)."""
    if not isinstance(value, str):
        raise ValueError(_CURSOR_INVALID_MESSAGE)
    match = _CURSOR_RE.match(value)
    if match is None:
        raise ValueError(_CURSOR_INVALID_MESSAGE)
    return value[3]


def _require_batch_limit(value: object) -> int:
    """Validate the optional batch cap: a non-boolean int in 1..1000."""
    if value is None:
        return _DEFAULT_BATCH_LIMIT
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError("max_items must be an integer between 1 and 1000")
    if not _MIN_BATCH_LIMIT <= value <= _MAX_BATCH_LIMIT:
        raise ValueError("max_items must be an integer between 1 and 1000")
    return value


def _require_nonempty_str(value: object, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _require_identifier(value: object) -> str:
    """Validate a request id, mapping every malformed value to not-found.

    Unlike the other arguments a bad request id must raise
    :class:`RequestNotFound` rather than :class:`ValueError`, so the
    validation layer can never be used as an oracle for which ids exist.
    """
    if not isinstance(value, str) or not value:
        raise RequestNotFound("request not found")
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


def _format_rfc3339(moment: datetime) -> str:
    """Format an aware UTC datetime as RFC3339 with a fixed ``Z`` suffix.

    Microseconds are always emitted (six digits) so that two timestamps
    sort lexicographically in chronological order even when one lands on
    a whole second. ``isoformat`` drops the fractional part on a zero
    microsecond value, which would otherwise make ``...:00Z`` sort after
    ``...:00.000001Z`` textually.
    """
    return moment.astimezone(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _utc_now_rfc3339() -> str:
    return _format_rfc3339(datetime.now(timezone.utc))


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
        # Validate the path before touching the filesystem: an empty or
        # non-string path is caller error (ValueError), never a storage
        # fault, and must not create directories.
        if isinstance(db_path, os.PathLike):
            db_path = os.fspath(db_path)
        if not isinstance(db_path, str) or not db_path:
            raise ValueError("storage path must be a non-empty string")
        self._db_path = db_path
        # In-process serialization; the unique index additionally guards
        # other processes sharing the same database file.
        self._write_lock = threading.Lock()
        try:
            if self._db_path == ":memory:":
                self._mem_conn: sqlite3.Connection | None = self._open_connection()
            else:
                self._mem_conn = None
                parent = os.path.dirname(os.path.abspath(self._db_path))
                os.makedirs(parent, exist_ok=True)
        except sqlite3.Error:
            raise _storage_failure() from None
        except OSError:
            # makedirs/connect errors embed the offending path; replace
            # them with the fixed-text storage error.
            raise _storage_failure() from None
        conn = self._connect()
        try:
            try:
                conn.execute(_SCHEMA)
                conn.execute(_UNIQUE_TENANT_KEY)
                conn.execute(_EVENT_TABLE)
                conn.execute(_CLAIM_TABLE)
                conn.execute(_CLAIM_TOKEN_TABLE)
                conn.execute(_CLAIM_CANDIDATE_INDEX)
                conn.execute(_BATCH_TABLE)
                conn.execute(_BATCH_CURSOR_INDEX)
                conn.execute(_BATCH_ITEM_TABLE)
                self._migrate_schema(conn)
            except sqlite3.Error:
                raise _storage_failure() from None
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
                raise _storage_failure() from None

    def _open_connection(self) -> sqlite3.Connection:
        try:
            conn = sqlite3.connect(
                self._db_path,
                timeout=_BUSY_TIMEOUT_MS / 1000,
                check_same_thread=False,
            )
        except sqlite3.Error:
            raise _storage_failure() from None
        conn.isolation_level = None  # explicit transaction control
        try:
            conn.execute(f"PRAGMA busy_timeout = {_BUSY_TIMEOUT_MS}")
        except sqlite3.Error:
            conn.close()
            raise _storage_failure() from None
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
                try:
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
                        # _PrimaryKeyConflict means retry with a new UUID;
                        # IdempotencyConflict propagates to the caller.
                        return self._load_idempotent(
                            conn, tenant_id, idempotency_key, subject_id, scope_list
                        )
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
                    conn.execute("COMMIT")
                except _PrimaryKeyConflict:
                    # Collision was on request_id; retry with a fresh UUID.
                    continue
                except sqlite3.Error:
                    try:
                        conn.execute("ROLLBACK")
                    except sqlite3.Error:
                        pass
                    raise _storage_failure() from None
                return self._acceptance_receipt(request_id, created_at)
        finally:
            self._release(conn)
        raise _storage_failure()

    @staticmethod
    def _acceptance_receipt(request_id: str, created_at: str) -> dict[str, str]:
        # The acceptance record is frozen: it always reports "accepted",
        # regardless of how the request later advances.
        return {
            "request_id": request_id,
            "status": _STATUS_ACCEPTED,
            "created_at": created_at,
        }

    def _load_idempotent(
        self,
        conn: sqlite3.Connection,
        tenant_id: str,
        idempotency_key: str,
        subject_id: str,
        scope_list: list[str],
    ) -> dict[str, str]:
        row = conn.execute(
            "SELECT request_id, created_at, subject_id, scopes_json "
            "FROM requests WHERE tenant_id = ? AND idempotency_key = ?",
            (tenant_id, idempotency_key),
        ).fetchone()
        if row is None:
            # The conflict came from the primary key rather than the
            # idempotency index; signal a fresh-UUID retry.
            raise _PrimaryKeyConflict
        existing_request_id, created_at, existing_subject, existing_scopes_json = row
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
        # The first acceptance receipt is immutable: always "accepted",
        # with the first request id and first acceptance time.
        return self._acceptance_receipt(existing_request_id, created_at)

    def get(self, tenant_id: str, request_id: str) -> dict[str, str]:
        """Return the *frozen acceptance receipt* for a request.

        The receipt always reports ``accepted`` with the first request id
        and first acceptance time, even after the request has advanced to
        processing/completed/failed. This is the record served by the
        HTTP lookup and idempotent submission replay. Invalid, unknown or
        cross-tenant ids are indistinguishable and raise
        :class:`RequestNotFound`; non-string or empty *tenant_id* raises
        :class:`ValueError`.
        """
        tenant_id = _require_nonempty_str(tenant_id, "tenant_id")
        # An invalid request id is treated exactly like an unknown one so
        # validation can never be used to tell which ids exist.
        request_id = _require_identifier(request_id)
        if self._mem_conn is not None:
            with self._write_lock:
                return self._get(tenant_id, request_id)
        return self._get(tenant_id, request_id)

    def _get(self, tenant_id: str, request_id: str) -> dict[str, str]:
        conn = self._connect()
        try:
            try:
                row = conn.execute(
                    "SELECT request_id, created_at FROM requests "
                    "WHERE tenant_id = ? AND request_id = ?",
                    (tenant_id, request_id),
                ).fetchone()
            except sqlite3.Error:
                raise _storage_failure() from None
        finally:
            self._release(conn)
        if row is None:
            # Identical outcome for unknown ids and cross-tenant lookups:
            # the response must not reveal that another tenant owns a record.
            raise RequestNotFound("request not found")
        return self._acceptance_receipt(row[0], row[1])

    def get_status(self, tenant_id: str, request_id: str) -> dict[str, str]:
        """Return the *current status record* for a request.

        The record has the same fixed shape and field order
        (``request_id``, ``status``, ``created_at``) as the acceptance
        receipt, but ``status`` reflects the latest persisted transition
        while ``created_at`` remains the original acceptance time. The
        result survives store rebuilds. Invalid, unknown or cross-tenant
        ids raise :class:`RequestNotFound`; a non-string or empty
        *tenant_id* raises :class:`ValueError`.
        """
        tenant_id = _require_nonempty_str(tenant_id, "tenant_id")
        request_id = _require_identifier(request_id)
        if self._mem_conn is not None:
            with self._write_lock:
                return self._get_status(tenant_id, request_id)
        return self._get_status(tenant_id, request_id)

    def _get_status(self, tenant_id: str, request_id: str) -> dict[str, str]:
        conn = self._connect()
        try:
            try:
                row = conn.execute(
                    "SELECT request_id, status, created_at FROM requests "
                    "WHERE tenant_id = ? AND request_id = ?",
                    (tenant_id, request_id),
                ).fetchone()
            except sqlite3.Error:
                raise _storage_failure() from None
        finally:
            self._release(conn)
        if row is None:
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
        returns the current status record without appending an event.
        An unknown/empty/non-string ``target_status`` is out of range and
        raises :class:`ValueError`; a move between two defined statuses
        that the lifecycle forbids (including any move out of a terminal
        state) raises :class:`InvalidStatusTransition` without writing.
        Invalid, unknown or cross-tenant request ids raise
        :class:`RequestNotFound`. No storage fault ever surfaces as
        anything other than :class:`OSError`.
        """
        # Validate before touching the database, mirroring submit(): no
        # rejected call may perform a write.
        tenant_id = _require_nonempty_str(tenant_id, "tenant_id")
        request_id = _require_identifier(request_id)
        target_status = _require_nonempty_str(target_status, "target_status")
        if target_status not in _ALLOWED_TRANSITIONS:
            # Out-of-range target (an undefined status) is caller error.
            raise ValueError("target_status is out of range")

        with self._write_lock:
            conn = self._connect()
            try:
                try:
                    conn.execute("BEGIN IMMEDIATE")
                except sqlite3.Error:
                    # Never surface the database engine's own error text.
                    raise _storage_failure() from None
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
                    self._persist_status_change(
                        conn, tenant_id, request_id, current_status, target_status
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
                    raise _storage_failure() from None
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

    def _persist_status_change(
        self,
        conn: sqlite3.Connection,
        tenant_id: str,
        request_id: str,
        current_status: str,
        target_status: str,
    ) -> str:
        """Append the chain event and advance the status within an open txn.

        Shared by :meth:`transition` and :meth:`finish_claim` so a terminal
        result lands in the same transaction as the attempt record. The
        caller owns ``BEGIN``/``COMMIT``; on a domain rejection or a broken
        invariant this helper rolls back before raising, so a shared
        in-memory connection is never left inside an aborted transaction.
        Returns the (monotonic) occurrence time written on the new event so
        the caller can stamp the attempt completion with the same instant.
        """
        allowed = _ALLOWED_TRANSITIONS.get(current_status, frozenset())
        if target_status not in allowed:
            conn.execute("ROLLBACK")
            raise InvalidStatusTransition("illegal status transition")
        # Read the predecessor link before writing so the new link binds
        # the exact persisted predecessor. BEGIN IMMEDIATE serializes
        # writers, so two changes can neither claim the same seq nor read a
        # stale predecessor.
        latest = conn.execute(
            "SELECT seq, occurred_at, chain_hash FROM status_events "
            "WHERE tenant_id = ? AND request_id = ? ORDER BY seq DESC LIMIT 1",
            (tenant_id, request_id),
        ).fetchone()
        if latest is None or not _is_chain_hash(latest[2]):
            # Defensive only: every accepted request owns its seq-0 event
            # with a valid link, so reaching here means the timeline
            # invariant was broken out of band. Never fabricate a link.
            conn.execute("ROLLBACK")
            raise _storage_failure()
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
            # The row vanished or changed under us; refuse rather than
            # persisting a state that breaks the graph observed at read.
            conn.execute("ROLLBACK")
            raise InvalidStatusTransition("illegal status transition")
        # The event is appended in the same transaction as the status
        # update and the attempt row; its link is anchored on the request
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
        return occurred_at

    # -- execution orchestration ---------------------------------------

    def claim_next(
        self,
        tenant_id: str,
        worker_id: str,
        lease_seconds: int,
    ) -> dict[str, object] | None:
        """Atomically claim the next request the tenant may execute.

        Candidates are ``accepted`` requests and ``processing`` requests
        whose latest lease has expired, ordered by acceptance time then
        request id; the oldest wins. The first claim moves an accepted
        request to ``processing`` and starts attempt 1; reclaiming after
        expiry starts the next attempt without changing the acceptance
        time, request id or current status. Only one worker ever holds a
        live lease for a given request.

        Returns ``None`` when no request is currently claimable. On
        success returns exactly ``request_id``, an unpredictable
        ``claim_token`` and the UTC RFC3339 ``lease_expires_at``. The
        worker identity is validated but never stored, logged or returned,
        and the raw token is returned once and never persisted. Invalid
        arguments raise :class:`ValueError` without writing; every storage
        fault is a fixed-text :class:`OSError`.
        """
        # Validate everything before touching the database. worker_id is
        # deliberately not persisted: it is authorised here only.
        tenant_id = _require_nonempty_str(tenant_id, "tenant_id")
        worker_id = _require_nonempty_str(worker_id, "worker_id")
        lease_seconds = _require_lease_seconds(lease_seconds)

        with self._write_lock:
            conn = self._connect()
            try:
                try:
                    conn.execute("BEGIN IMMEDIATE")
                except sqlite3.Error:
                    raise _storage_failure() from None
                claim: dict[str, object] | None = None
                try:
                    claim = self._claim_next_locked(conn, tenant_id, lease_seconds)
                    conn.execute("COMMIT")
                except OSError:
                    # A fixed-text storage failure raised after the helper
                    # rolled back; the second rollback is a harmless no-op
                    # that guarantees the (possibly shared) connection is
                    # never left inside an aborted transaction.
                    try:
                        conn.execute("ROLLBACK")
                    except sqlite3.Error:
                        pass
                    raise
                except sqlite3.Error:
                    try:
                        conn.execute("ROLLBACK")
                    except sqlite3.Error:
                        pass
                    raise _storage_failure() from None
            finally:
                self._release(conn)
        if claim is None:
            _log.info("claim found no candidate")
            return None
        _log.info(
            "claim acquired request_id=%s attempt=%s",
            claim["request_id"],
            claim["_attempt_number"],
        )
        # Strip internal bookkeeping; the caller sees only the contract.
        return {
            "request_id": claim["request_id"],
            "claim_token": claim["claim_token"],
            "lease_expires_at": claim["lease_expires_at"],
        }

    def _claim_next_locked(
        self,
        conn: sqlite3.Connection,
        tenant_id: str,
        lease_seconds: int,
    ) -> dict[str, object] | None:
        now_dt = datetime.now(timezone.utc)
        claimed_at = _format_rfc3339(now_dt)
        lease_expires_at = _format_rfc3339(
            now_dt + timedelta(seconds=lease_seconds)
        )
        # Oldest accepted, or oldest processing whose lease history proves
        # a genuine expired lease: at least one attempt exists, the most
        # recent attempt is still unfinished and its lease has expired,
        # and no attempt is still open inside a live lease. A processing
        # request that carries no attempt, whose latest attempt is already
        # finished (a status/result inconsistency), or that only has open
        # attempts that never lapsed, cannot be explained as an expired
        # lease and is never claimed; such records are left for
        # reconcile_execution to converge. The correlated subqueries read
        # the most recent attempt's expiry/result and whether any open
        # attempt is still inside its lease. BEGIN IMMEDIATE plus the write
        # lock make the read-then-claim atomic, so two workers can never
        # both win.
        row = conn.execute(
            "SELECT r.request_id, r.status "
            "FROM requests r "
            "WHERE r.tenant_id = ? "
            "  AND ( "
            "    r.status = ? "
            "    OR ( "
            "      r.status = ? "
            "      AND EXISTS ( "
            "        SELECT 1 FROM claim_attempts c "
            "        WHERE c.tenant_id = r.tenant_id "
            "          AND c.request_id = r.request_id "
            "      ) "
            "      AND ? > ( "
            "        SELECT c.lease_expires_at FROM claim_attempts c "
            "        WHERE c.tenant_id = r.tenant_id "
            "          AND c.request_id = r.request_id "
            "        ORDER BY c.attempt_number DESC LIMIT 1 "
            "      ) "
            "      AND ( "
            "        SELECT c.result FROM claim_attempts c "
            "        WHERE c.tenant_id = r.tenant_id "
            "          AND c.request_id = r.request_id "
            "        ORDER BY c.attempt_number DESC LIMIT 1 "
            "      ) IS NULL "
            "      AND NOT EXISTS ( "
            "        SELECT 1 FROM claim_attempts c "
            "        WHERE c.tenant_id = r.tenant_id "
            "          AND c.request_id = r.request_id "
            "          AND c.result IS NULL AND c.completed_at IS NULL "
            "          AND ? <= c.lease_expires_at "
            "      ) "
            "    ) "
            "  ) "
            "ORDER BY r.created_at ASC, r.request_id ASC LIMIT 1",
            (
                tenant_id,
                _STATUS_ACCEPTED,
                _STATUS_PROCESSING,
                claimed_at,
                claimed_at,
            ),
        ).fetchone()
        if row is None:
            return None
        request_id, current_status = row

        attempt_row = conn.execute(
            "SELECT COALESCE(MAX(attempt_number), 0) + 1 "
            "FROM claim_attempts WHERE tenant_id = ? AND request_id = ?",
            (tenant_id, request_id),
        ).fetchone()
        attempt_number = attempt_row[0]
        if not isinstance(attempt_number, int) or isinstance(attempt_number, bool):
            # Corrupt attempt sequence: never fabricate a number.
            raise _storage_failure()

        conn.execute(
            "INSERT INTO claim_attempts ("
            "tenant_id, request_id, attempt_number, claimed_at, "
            "lease_expires_at, result, completed_at"
            ") VALUES (?, ?, ?, ?, ?, NULL, NULL)",
            (
                tenant_id,
                request_id,
                attempt_number,
                claimed_at,
                lease_expires_at,
            ),
        )
        # Any token from a previous (now superseded) lease is released the
        # instant a new lease begins, so an expired worker can never finish
        # a request a successor now owns.
        conn.execute(
            "DELETE FROM claim_tokens WHERE tenant_id = ? AND request_id = ?",
            (tenant_id, request_id),
        )
        token = _new_claim_token()
        conn.execute(
            "INSERT INTO claim_tokens ("
            "tenant_id, request_id, attempt_number, token_hash"
            ") VALUES (?, ?, ?, ?)",
            (
                tenant_id,
                request_id,
                attempt_number,
                hashlib.sha256(token.encode("utf-8")).hexdigest(),
            ),
        )
        if current_status == _STATUS_ACCEPTED:
            # The first acquisition enters processing exactly once, in the
            # same transaction as the attempt row. A reclaim after expiry
            # finds the request already processing and writes no state.
            self._persist_status_change(
                conn, tenant_id, request_id, _STATUS_ACCEPTED, _STATUS_PROCESSING
            )
        return {
            "request_id": request_id,
            "claim_token": token,
            "lease_expires_at": lease_expires_at,
            "_attempt_number": attempt_number,
        }

    def finish_claim(
        self,
        tenant_id: str,
        request_id: str,
        claim_token: str,
        result: str,
    ) -> dict[str, str]:
        """Finish the live claim with a terminal ``result``.

        ``result`` must be ``completed`` or ``failed``. The token must
        identify the request's current, unexpired, unreleased lease for
        the same tenant. Precedence is fixed: when the request id is
        unknown, malformed or not visible to the tenant (a cross-tenant
        id) and the presented credential is not the live lease for those
        exact coordinates, :class:`RequestNotFound` is raised first, no
        matter how the credential reads, so credential validity can never
        be used to probe ids. For a request the tenant can see, an
        unknown, expired, already-released or cross-tenant credential --
        as well as finishing a request that has no open claim -- raises
        :class:`ClaimConflict` and changes nothing. The terminal status
        and its chain event are committed in the same transaction that
        records the attempt result and releases the token. Returns the
        status record (``request_id``, ``status``, ``created_at``).
        """
        tenant_id = _require_nonempty_str(tenant_id, "tenant_id")
        request_id = _require_identifier(request_id)
        result = _require_result(result)
        # A token outside the non-empty-string domain is caller error
        # (ValueError), exactly like the other execution parameters. A
        # well-formed string that simply matches no live lease is resolved
        # below and surfaces as ClaimConflict ("no such credential").
        claim_token = _require_nonempty_str(claim_token, "claim_token")

        with self._write_lock:
            conn = self._connect()
            try:
                try:
                    conn.execute("BEGIN IMMEDIATE")
                except sqlite3.Error:
                    raise _storage_failure() from None
                try:
                    receipt = self._finish_claim_locked(
                        conn, tenant_id, request_id, claim_token, result
                    )
                    conn.execute("COMMIT")
                except (InvalidStatusTransition, ClaimConflict, RequestNotFound):
                    # Domain rejections carry no engine text; ensure the
                    # shared in-memory connection leaves the transaction.
                    try:
                        conn.execute("ROLLBACK")
                    except sqlite3.Error:
                        pass
                    raise
                except sqlite3.Error:
                    try:
                        conn.execute("ROLLBACK")
                    except sqlite3.Error:
                        pass
                    raise _storage_failure() from None
            finally:
                self._release(conn)
        _log.info(
            "claim finished request_id=%s status=%s",
            request_id,
            result,
        )
        return receipt

    def _finish_claim_locked(
        self,
        conn: sqlite3.Connection,
        tenant_id: str,
        request_id: str,
        claim_token: str,
        result: str,
    ) -> dict[str, str]:
        # Resolve both the presented token and the target's visibility.
        # Precedence is fixed: a request id that is unknown or not visible
        # to this tenant (a missing or cross-tenant id) paired with a
        # absence of a live lease for these exact coordinates raises
        # RequestNotFound first, regardless of how the credential reads,
        # so credential validity can never be used to probe ids. Only a
        # target the tenant can see with a credential that fails to match
        # its current lease answers ClaimConflict.
        presented = hashlib.sha256(claim_token.encode("utf-8")).hexdigest()
        owner = conn.execute(
            "SELECT tenant_id, request_id, attempt_number FROM claim_tokens "
            "WHERE token_hash = ? LIMIT 1",
            (presented,),
        ).fetchone()
        token_matches = owner is not None and (
            owner[0],
            owner[1],
        ) == (tenant_id, request_id)

        row = conn.execute(
            "SELECT status, created_at FROM requests "
            "WHERE tenant_id = ? AND request_id = ?",
            (tenant_id, request_id),
        ).fetchone()
        if not token_matches:
            if row is None:
                # Unknown id and cross-tenant lookup share one outcome,
                # even when a real (but foreign or misrouted) credential
                # was presented.
                raise RequestNotFound("request not found")
            # The target is visible but the credential is unknown,
            # already released (a successor or finish deleted it),
            # expired, or presented against a different live lease.
            raise _claim_conflict()
        attempt_number = owner[2]

        if row is None:
            # Defensive: a live token always names an existing request.
            raise RequestNotFound("request not found")
        current_status, created_at = row

        # The token names the current lease; its attempt must still be open
        # and the lease must not have lapsed.
        latest = conn.execute(
            "SELECT result, lease_expires_at FROM claim_attempts "
            "WHERE tenant_id = ? AND request_id = ? AND attempt_number = ?",
            (tenant_id, request_id, attempt_number),
        ).fetchone()
        if latest is None or latest[0] is not None:
            raise _claim_conflict()
        if _utc_now_rfc3339() > latest[1]:
            # The lease has expired; the holder no longer owns the request.
            raise _claim_conflict()

        if current_status != _STATUS_PROCESSING:
            # An open attempt must accompany processing; anything else is
            # an out-of-band inconsistency that must not be overwritten.
            raise _claim_conflict()

        # Advance to the terminal state with its chain event and reuse the
        # exact monotonic occurrence time for the attempt completion, all in
        # this one transaction: the attempt result and request status can
        # never disagree and neither can be left half-written.
        completed_at = self._persist_status_change(
            conn, tenant_id, request_id, _STATUS_PROCESSING, result
        )
        cursor = conn.execute(
            "UPDATE claim_attempts SET result = ?, completed_at = ? "
            "WHERE tenant_id = ? AND request_id = ? AND attempt_number = ? "
            "AND result IS NULL",
            (result, completed_at, tenant_id, request_id, attempt_number),
        )
        if cursor.rowcount != 1:
            raise _claim_conflict()
        # Release the single-use token before returning success.
        conn.execute(
            "DELETE FROM claim_tokens "
            "WHERE tenant_id = ? AND request_id = ? AND attempt_number = ?",
            (tenant_id, request_id, attempt_number),
        )
        return {
            "request_id": request_id,
            "status": result,
            "created_at": created_at,
        }

    def get_execution_log(
        self,
        tenant_id: str,
        request_id: str,
    ) -> list[dict[str, object]]:
        """Return the request's execution attempts in attempt order.

        Each entry contains exactly ``attempt_number`` (a positive int
        starting at 1), ``claimed_at`` and ``lease_expires_at`` (UTC
        RFC3339 strings), and ``result``/``completed_at`` which are the
        terminal status and completion time once finished, and ``None``
        while the attempt is still open (or was abandoned on expiry). No
        worker identity and no claim token is ever included. Invalid,
        unknown and cross-tenant ids raise :class:`RequestNotFound`; a
        non-string or empty tenant raises :class:`ValueError`; corrupt
        rows raise the fixed-text :class:`OSError`.
        """
        tenant_id = _require_nonempty_str(tenant_id, "tenant_id")
        request_id = _require_identifier(request_id)
        if self._mem_conn is not None:
            with self._write_lock:
                return self._get_execution_log(tenant_id, request_id)
        return self._get_execution_log(tenant_id, request_id)

    def _get_execution_log(
        self, tenant_id: str, request_id: str
    ) -> list[dict[str, object]]:
        conn = self._connect()
        try:
            try:
                # Resolve ownership first, exactly like audit(): an empty
                # log must not distinguish "missing" from "foreign record".
                owner = conn.execute(
                    "SELECT 1 FROM requests WHERE tenant_id = ? AND request_id = ?",
                    (tenant_id, request_id),
                ).fetchone()
                if owner is None:
                    raise RequestNotFound("request not found")
                rows = conn.execute(
                    "SELECT attempt_number, claimed_at, lease_expires_at, "
                    "result, completed_at FROM claim_attempts "
                    "WHERE tenant_id = ? AND request_id = ? "
                    "ORDER BY attempt_number",
                    (tenant_id, request_id),
                ).fetchall()
            except RequestNotFound:
                raise
            except sqlite3.Error:
                raise _storage_failure() from None
        finally:
            self._release(conn)

        attempts: list[dict[str, object]] = []
        for index, row in enumerate(rows, start=1):
            attempt_number, claimed_at, lease_expires_at, result, completed_at = row
            # Strict shape validation: a tampered row is storage
            # corruption, never a partially-formed record. Only str, int
            # and None ever reach the caller -- never float or bool.
            if (
                not isinstance(attempt_number, int)
                or isinstance(attempt_number, bool)
                or attempt_number != index
                or not isinstance(claimed_at, str)
                or not claimed_at
                or not isinstance(lease_expires_at, str)
                or not lease_expires_at
            ):
                raise _storage_failure()
            if result is not None and (
                not isinstance(result, str) or result not in _TERMINAL_RESULTS
            ):
                raise _storage_failure()
            if completed_at is not None and (
                not isinstance(completed_at, str) or not completed_at
            ):
                raise _storage_failure()
            # result and completed_at are set together at finish time.
            if (result is None) != (completed_at is None):
                raise _storage_failure()
            attempts.append(
                {
                    "attempt_number": attempt_number,
                    "claimed_at": claimed_at,
                    "lease_expires_at": lease_expires_at,
                    "result": result,
                    "completed_at": completed_at,
                }
            )
        return attempts

    def reconcile_execution(
        self,
        tenant_id: str,
        request_id: str,
    ) -> dict[str, str]:
        """Reconcile a request's execution record and converge it.

        Returns the existing status record (``request_id``, ``status``,
        ``created_at``) and never creates a request, an attempt or a
        receipt:

        * an ``accepted`` request (with or without attempts) is returned
          exactly as it stands -- no record, attempt or receipt changes;
        * a ``processing`` request whose lease is still live keeps its
          in-progress attempt: no terminal result is written early and no
          new attempt is generated;
        * a ``completed``/``failed`` request is an idempotent no-op with
          respect to the status record; the first terminal result is
          retained, as is the same status record.

        Convergence runs only for a ``processing`` request whose latest
        lease has expired and that holds no other valid lease (including a
        processing request with no result and no lease at all, or with no
        explainable attempts). Every unfinished attempt is compensated to
        ``failed`` in one atomic transaction with the status convergence
        and the lease release; the compensation completion time is a UTC
        RFC3339 string shared with the convergence event and is written
        exactly once, never over an existing completion time. When the
        execution record already carries terminal attempts the earliest
        completion wins and sets the converged status; later duplicate
        terminal rows are recorded as ``failed`` without altering that
        status on subsequent reconciles.

        A non-string or empty *tenant_id* raises :class:`ValueError`
        without changing any state; a missing, empty, non-string,
        malformed, unknown or cross-tenant *request_id* raises
        :class:`RequestNotFound` identically. Corrupt execution records
        or a failed compensation commit raise the fixed-text
        :class:`OSError`; a half-converged result is never returned.
        """
        # Validate before touching the database: tenant errors are
        # ValueErrors, while every request-id problem (missing, empty,
        # non-string, malformed or foreign) collapses to RequestNotFound.
        tenant_id = _require_nonempty_str(tenant_id, "tenant_id")
        request_id = _require_identifier(request_id)

        with self._write_lock:
            conn = self._connect()
            try:
                try:
                    conn.execute("BEGIN IMMEDIATE")
                except sqlite3.Error:
                    raise _storage_failure() from None
                try:
                    record = self._reconcile_locked(conn, tenant_id, request_id)
                    conn.execute("COMMIT")
                except RequestNotFound:
                    try:
                        conn.execute("ROLLBACK")
                    except sqlite3.Error:
                        pass
                    raise
                except InvalidStatusTransition:
                    # Defensive only: the status was read as processing in
                    # this same write transaction and cannot have changed.
                    # Reconcile has no illegal-transition outcome, so never
                    # let that exception escape its declared error set.
                    try:
                        conn.execute("ROLLBACK")
                    except sqlite3.Error:
                        pass
                    raise _storage_failure() from None
                except OSError:
                    # _persist_status_change and the corruption probes
                    # roll back before raising the fixed-text error; the
                    # second rollback only guarantees the shared
                    # connection has left its transaction.
                    try:
                        conn.execute("ROLLBACK")
                    except sqlite3.Error:
                        pass
                    raise
                except sqlite3.Error:
                    try:
                        conn.execute("ROLLBACK")
                    except sqlite3.Error:
                        pass
                    raise _storage_failure() from None
            finally:
                self._release(conn)
        _log.info(
            "execution reconciled request_id=%s status=%s",
            request_id,
            record["status"],
        )
        return record

    def _reconcile_locked(
        self,
        conn: sqlite3.Connection,
        tenant_id: str,
        request_id: str,
    ) -> dict[str, str]:
        """Converge one request inside an already-open write txn."""
        row = conn.execute(
            "SELECT status, created_at FROM requests "
            "WHERE tenant_id = ? AND request_id = ?",
            (tenant_id, request_id),
        ).fetchone()
        if row is None:
            # Unknown id and cross-tenant lookup share one outcome.
            raise RequestNotFound("request not found")
        current_status, created_at = row
        if current_status not in _ALLOWED_TRANSITIONS or not isinstance(
            created_at, str
        ):
            # A status outside the lifecycle or a broken acceptance time
            # is out-of-band corruption: never converge from a bad read.
            raise _storage_failure()

        attempts = self._load_attempts_for_reconcile(conn, tenant_id, request_id)

        if current_status == _STATUS_ACCEPTED:
            # Accepted means "never executed": only report the current
            # state. No record, attempt or receipt is created or changed.
            return {
                "request_id": request_id,
                "status": current_status,
                "created_at": created_at,
            }

        if current_status in _TERMINAL_RESULTS:
            # Idempotent at the request: the first terminal result and the
            # same status record are retained. A corrupted execution record
            # carrying several terminal attempts is still normalised, but
            # that repair never touches the request row or its timeline.
            self._normalise_duplicate_terminals(
                conn, tenant_id, request_id, attempts
            )
            return {
                "request_id": request_id,
                "status": current_status,
                "created_at": created_at,
            }

        # current_status == processing. A lease is live while any
        # unfinished attempt is still inside its lease window; RFC3339
        # timestamps from _utc_now_rfc3339 compare chronologically as
        # text. Equality with the expiry still counts as held, matching
        # finish_claim's expiry boundary.
        now = _utc_now_rfc3339()
        has_live_lease = any(
            result is None and now <= lease_expires_at
            for _number, result, _completed_at, lease_expires_at in attempts
        )
        if has_live_lease:
            # The current holder still owns the request: keep its open
            # attempt, write no terminal result early and start no
            # successor attempt.
            return {
                "request_id": request_id,
                "status": current_status,
                "created_at": created_at,
            }

        return self._compensate_locked(
            conn, tenant_id, request_id, created_at, attempts
        )

    def _load_attempts_for_reconcile(
        self,
        conn: sqlite3.Connection,
        tenant_id: str,
        request_id: str,
    ) -> list[tuple[int, str | None, str | None, str]]:
        """Read and strictly validate every attempt row for reconcile.

        Returns ``(attempt_number, result, completed_at,
        lease_expires_at)`` tuples in attempt order. A malformed sequence,
        timestamp or result/completion pairing is storage corruption and
        raises the fixed-text OSError before any state is touched.
        """
        rows = conn.execute(
            "SELECT attempt_number, result, completed_at, lease_expires_at "
            "FROM claim_attempts WHERE tenant_id = ? AND request_id = ? "
            "ORDER BY attempt_number",
            (tenant_id, request_id),
        ).fetchall()
        attempts: list[tuple[int, str | None, str | None, str]] = []
        for index, attempt_row in enumerate(rows, start=1):
            attempt_number, result, completed_at, lease_expires_at = attempt_row
            if (
                not isinstance(attempt_number, int)
                or isinstance(attempt_number, bool)
                or attempt_number != index
                or not isinstance(lease_expires_at, str)
                or not lease_expires_at
            ):
                raise _storage_failure()
            if result is not None and (
                not isinstance(result, str) or result not in _TERMINAL_RESULTS
            ):
                raise _storage_failure()
            if completed_at is not None and (
                not isinstance(completed_at, str) or not completed_at
            ):
                raise _storage_failure()
            # Result and completion time are set together and never
            # separately; a split row is a broken invariant.
            if (result is None) != (completed_at is None):
                raise _storage_failure()
            attempts.append(
                (attempt_number, result, completed_at, lease_expires_at)
            )
        return attempts

    def _earliest_terminal(
        self,
        attempts: list[tuple[int, str | None, str | None, str]],
    ) -> tuple[int, str] | None:
        """Return ``(attempt_number, result)`` of the first completion.

        Earliest is the terminal attempt with the smallest completion
        time, sequence breaking a tie. A terminal row validated upstream
        always carries a completion time.
        """
        terminals = [
            (completed_at, attempt_number, result)
            for attempt_number, result, completed_at, _expiry in attempts
            if result is not None
        ]
        if not terminals:
            return None
        completed_at, attempt_number, result = min(
            terminals, key=lambda item: (item[0], item[1])
        )
        return attempt_number, result

    def _normalise_duplicate_terminals(
        self,
        conn: sqlite3.Connection,
        tenant_id: str,
        request_id: str,
        attempts: list[tuple[int, str | None, str | None, str]],
    ) -> None:
        """Force every terminal attempt after the earliest to ``failed``.

        Only rows other than the earliest completion that still claim
        ``completed`` are rewritten; the winning row (earliest completion,
        sequence breaking a tie) and a row already marked ``failed`` are
        left alone, and existing completion times are never overwritten.
        The request row, its status and its timeline are untouched.
        """
        earliest = self._earliest_terminal(attempts)
        if earliest is None:
            return
        earliest_number, _earliest_result = earliest
        conn.execute(
            "UPDATE claim_attempts SET result = 'failed' "
            "WHERE tenant_id = ? AND request_id = ? AND attempt_number != ? "
            "AND result = 'completed'",
            (tenant_id, request_id, earliest_number),
        )

    def _compensate_locked(
        self,
        conn: sqlite3.Connection,
        tenant_id: str,
        request_id: str,
        created_at: str,
        attempts: list[tuple[int, str | None, str | None, str]],
    ) -> dict[str, str]:
        """Compensate open attempts and converge processing in one txn.

        With no valid lease every unfinished attempt is abandoned work;
        it is compensated to ``failed`` once. If terminal attempts
        already exist the earliest completion determines the converged
        status (its row is retained) and later duplicate terminals are
        recorded as ``failed``; otherwise the request itself converges
        to ``failed``. The dead lease credential is released in the same
        transaction as the status, its chain event and every attempt.
        """
        earliest = self._earliest_terminal(attempts)
        target_status = earliest[1] if earliest is not None else _STATUS_FAILED

        # The convergence event and request status land first, exactly
        # like finish_claim; its monotonic occurrence time is reused as
        # the single compensation completion time.
        completed_at = self._persist_status_change(
            conn, tenant_id, request_id, _STATUS_PROCESSING, target_status
        )

        # Abandoned, unfinished attempts become failed. The NULL guards
        # guarantee the completion time is written once and an existing
        # result or completion time can never be overwritten.
        conn.execute(
            "UPDATE claim_attempts SET result = 'failed', completed_at = ? "
            "WHERE tenant_id = ? AND request_id = ? "
            "AND result IS NULL AND completed_at IS NULL",
            (completed_at, tenant_id, request_id),
        )

        if earliest is not None:
            # Keep the earliest completion result; every other duplicate
            # terminal row is downgraded to failed without touching its
            # already-written completion time or the request status. The
            # winner is selected by completion time (sequence breaking a
            # tie), not by attempt number.
            earliest_number, _earliest_result = earliest
            conn.execute(
                "UPDATE claim_attempts SET result = 'failed' "
                "WHERE tenant_id = ? AND request_id = ? "
                "AND attempt_number != ? AND result = 'completed'",
                (tenant_id, request_id, earliest_number),
            )

        # The lease is dead: release whatever credential it left behind
        # atomically with the convergence, so it can never finish a
        # request that no longer belongs to its holder.
        conn.execute(
            "DELETE FROM claim_tokens WHERE tenant_id = ? AND request_id = ?",
            (tenant_id, request_id),
        )
        return {
            "request_id": request_id,
            "status": target_status,
            "created_at": created_at,
        }

    # -- batch reconciliation ------------------------------------------

    def reconcile_batch(
        self,
        tenant_id: str,
        cursor: str | None = None,
        max_items: int | None = None,
    ) -> dict[str, object]:
        """Reconcile a bounded, resumable batch of pending requests.

        Storage-layer only; no HTTP route is added. A call scans the
        tenant's requests in a stable keyset order (acceptance time, then
        request id), skips ``accepted`` requests outright, and reconciles
        up to *max_items* of the remaining records, continuing after an
        optional opaque *cursor* returned by a previous batch.

        Returns exactly ``batch_id``, ``next_cursor`` (a string while more
        requests may remain, ``None`` once the scan is finished),
        ``finished`` and ``items``; each item carries only ``request_id``
        and the reconciled ``status``, in stable scan order. Times and
        cursors are strings, counts are integers (a boolean for
        ``finished``) and absent values stay ``None``; no float, negative
        zero or non-finite number is ever produced.

        Per scanned request the rules match :meth:`reconcile_execution`:
        an ``accepted`` request is skipped without an attempt, receipt or
        extra status event; a ``processing`` request holding a live lease
        stays processing (no early terminal, no new attempt); expired,
        result-less or unexplainable leases are compensated to ``failed``;
        terminals are idempotent no-ops. Each item's status, attempt and
        lease changes settle in the same transaction as the batch cursor
        advance and the persisted window row. A batch interrupted
        mid-window resumes from the persisted position and then returns
        the whole window; retried and restarted calls are idempotent, the
        same cursor always binding to the same ``batch_id``. Every
        database failure is the fixed-text :class:`OSError`; an invalid
        tenant, cursor (including an unknown cursor format or token) or
        limit raises :class:`ValueError` without writing.
        """
        # Validate all caller input before touching the database. An
        # unknown cursor *shape* is an illegal cursor; a well-formed token
        # that names no batch is rejected in the registration txn below.
        tenant_id = _require_nonempty_str(tenant_id, "tenant_id")
        if cursor is not None:
            _decode_cursor(cursor)
        max_items = _require_batch_limit(max_items)

        with self._write_lock:
            conn = self._connect()
            try:
                # The batch is registered (or a retried one resolved) and
                # committed before items are processed: a crash leaves a
                # cursor the caller can resume from, and a repeated cursor
                # always binds to the same batch.
                try:
                    conn.execute("BEGIN IMMEDIATE")
                    state = self._resolve_or_register_batch(
                        conn, tenant_id, cursor, max_items
                    )
                    conn.execute("COMMIT")
                except ValueError:
                    self._rollback_quietly(conn)
                    raise
                except sqlite3.Error:
                    self._rollback_quietly(conn)
                    raise _storage_failure() from None

                # Reconcile one item per transaction until the window is
                # sealed. A retried, already-sealed batch skips the loop
                # and replays the persisted window instead.
                if not state["sealed"]:
                    while True:
                        try:
                            conn.execute("BEGIN IMMEDIATE")
                        except sqlite3.Error:
                            raise _storage_failure() from None
                        try:
                            item = self._reconcile_next_batch_item(conn, state)
                            conn.execute("COMMIT")
                        except RequestNotFound:
                            # The candidate was selected inside this same
                            # write transaction; its vanishing is
                            # corruption, never a caller-visible not-found.
                            self._rollback_quietly(conn)
                            raise _storage_failure() from None
                        except InvalidStatusTransition:
                            # Mirrors reconcile_execution: the batch has
                            # no illegal-transition outcome outside a
                            # broken invariant.
                            self._rollback_quietly(conn)
                            raise _storage_failure() from None
                        except OSError:
                            self._rollback_quietly(conn)
                            raise
                        except sqlite3.Error:
                            self._rollback_quietly(conn)
                            raise _storage_failure() from None
                        if item is None:
                            break

                # The returned window is always the persisted one, so a
                # mid-window resume and a sealed retry are identical to
                # the batch's first successful response.
                finished, next_cursor, items = self._load_sealed_batch(
                    conn, tenant_id, state["batch_id"]
                )
            finally:
                self._release(conn)

        for item in items:
            _log.info(
                "batch item reconciled request_id=%s status=%s",
                item["request_id"],
                item["status"],
            )
        return {
            "batch_id": state["batch_id"],
            "next_cursor": None if finished else next_cursor,
            "finished": finished,
            "items": items,
        }

    @staticmethod
    def _rollback_quietly(conn: sqlite3.Connection) -> None:
        """Best-effort rollback that never masks the original failure."""
        try:
            conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass

    def _resolve_or_register_batch(
        self,
        conn: sqlite3.Connection,
        tenant_id: str,
        cursor: str | None,
        max_items: int,
    ) -> dict[str, object]:
        """Resolve a retried batch or register a new one, in the open txn."""
        if cursor is None:
            return self._insert_batch(
                conn,
                tenant_id=tenant_id,
                batch_id=str(uuid.uuid4()),
                cursor_token=_new_cursor(_CURSOR_KIND_START),
                max_items=max_items,
                last_created_at=None,
                last_request_id=None,
            )

        existing = conn.execute(
            "SELECT batch_id, max_items, inspected, last_created_at, "
            "last_request_id, sealed, finished, next_cursor_token "
            "FROM reconcile_batches WHERE tenant_id = ? AND cursor_token = ?",
            (tenant_id, cursor),
        ).fetchone()
        if existing is not None:
            # Retry of an in-flight or already-sealed batch: same id.
            return self._batch_state_from_row(existing, tenant_id)

        # Otherwise the token is only legitimate as the continuation
        # cursor of a sealed predecessor. A fabricated token -- or a
        # continuation whose predecessor never sealed -- is an illegal
        # caller cursor and writes nothing.
        predecessor = conn.execute(
            "SELECT last_created_at, last_request_id, sealed "
            "FROM reconcile_batches "
            "WHERE tenant_id = ? AND next_cursor_token = ?",
            (tenant_id, cursor),
        ).fetchone()
        if predecessor is None or predecessor[2] != 1:
            raise ValueError(_CURSOR_INVALID_MESSAGE)
        last_created_at, last_request_id, _sealed = predecessor
        if (last_created_at is None) != (last_request_id is None):
            raise _storage_failure()
        return self._insert_batch(
            conn,
            tenant_id=tenant_id,
            batch_id=str(uuid.uuid4()),
            cursor_token=cursor,
            max_items=max_items,
            last_created_at=last_created_at,
            last_request_id=last_request_id,
        )

    def _insert_batch(
        self,
        conn: sqlite3.Connection,
        *,
        tenant_id: str,
        batch_id: str,
        cursor_token: str,
        max_items: int,
        last_created_at: str | None,
        last_request_id: str | None,
    ) -> dict[str, object]:
        """Insert a fresh batch row, regenerating random ids on collision."""
        for _ in range(_MAX_INSERT_ATTEMPTS):
            next_cursor_token = _new_cursor(_CURSOR_KIND_NEXT)
            try:
                conn.execute(
                    "INSERT INTO reconcile_batches ("
                    "tenant_id, batch_id, cursor_token, next_cursor_token, "
                    "max_items, inspected, last_created_at, last_request_id, "
                    "sealed, finished"
                    ") VALUES (?, ?, ?, ?, ?, 0, ?, ?, 0, 0)",
                    (
                        tenant_id,
                        batch_id,
                        cursor_token,
                        next_cursor_token,
                        max_items,
                        last_created_at,
                        last_request_id,
                    ),
                )
            except sqlite3.IntegrityError:
                # A concurrent process sharing the file may have
                # registered this continuation cursor first; that is a
                # retry, not a collision -- resume its batch. Any other
                # unique conflict can only be the random batch id or
                # continuation token: regenerate and retry.
                row = conn.execute(
                    "SELECT batch_id, max_items, inspected, last_created_at, "
                    "last_request_id, sealed, finished, next_cursor_token "
                    "FROM reconcile_batches "
                    "WHERE tenant_id = ? AND cursor_token = ?",
                    (tenant_id, cursor_token),
                ).fetchone()
                if row is not None:
                    return self._batch_state_from_row(row, tenant_id)
                batch_id = str(uuid.uuid4())
                continue
            return {
                "tenant_id": tenant_id,
                "batch_id": batch_id,
                "max_items": max_items,
                "sealed": False,
            }
        raise _storage_failure()

    @staticmethod
    def _batch_state_from_row(row: tuple, tenant_id: str) -> dict[str, object]:
        """Strictly validate a persisted batch header into mutable state."""
        (
            batch_id,
            max_items,
            inspected,
            last_created_at,
            last_request_id,
            sealed,
            finished,
            _next_cursor_token,
        ) = row
        if (
            not isinstance(batch_id, str)
            or not batch_id
            or not isinstance(max_items, int)
            or isinstance(max_items, bool)
            or not _MIN_BATCH_LIMIT <= max_items <= _MAX_BATCH_LIMIT
            or not isinstance(inspected, int)
            or isinstance(inspected, bool)
            or not 0 <= inspected <= max_items
            or sealed not in (0, 1)
            or finished not in (0, 1)
            or (last_created_at is None) != (last_request_id is None)
        ):
            raise _storage_failure()
        if last_created_at is not None and (
            not isinstance(last_created_at, str)
            or not last_created_at
            or not isinstance(last_request_id, str)
            or not last_request_id
        ):
            raise _storage_failure()
        if finished == 1 and sealed != 1:
            raise _storage_failure()
        return {
            "tenant_id": tenant_id,
            "batch_id": batch_id,
            "max_items": max_items,
            "sealed": sealed == 1,
        }

    def _reconcile_next_batch_item(
        self,
        conn: sqlite3.Connection,
        state: dict[str, object],
    ) -> dict[str, object] | None:
        """Reconcile one batch item and advance the cursor, in one txn.

        Returns the item bookkeeping, or ``None`` once the window is
        sealed. ``accepted`` requests are skipped in the scan itself.
        """
        tenant_id = state["tenant_id"]
        batch_id = state["batch_id"]
        max_items = state["max_items"]
        # Re-read the header inside the transaction: a concurrent process
        # sharing the file may have advanced the same cursor, and every
        # decision must be made from persisted state.
        row = conn.execute(
            "SELECT inspected, last_created_at, last_request_id, sealed "
            "FROM reconcile_batches WHERE tenant_id = ? AND batch_id = ?",
            (tenant_id, batch_id),
        ).fetchone()
        if row is None:
            raise _storage_failure()
        inspected, last_created_at, last_request_id, sealed = row
        if (
            not isinstance(inspected, int)
            or isinstance(inspected, bool)
            or not 0 <= inspected <= max_items
            or sealed not in (0, 1)
            or (last_created_at is None) != (last_request_id is None)
        ):
            raise _storage_failure()
        if last_created_at is not None and (
            not isinstance(last_created_at, str)
            or not last_created_at
            or not isinstance(last_request_id, str)
            or not last_request_id
        ):
            raise _storage_failure()
        if sealed == 1:
            # The previous item sealed the window (limit reached or scan
            # exhausted); this call has nothing more to do.
            state["sealed"] = True
            return None
        # The header counter must agree with the persisted window.
        window_count = conn.execute(
            "SELECT count(*) FROM reconcile_batch_items "
            "WHERE tenant_id = ? AND batch_id = ?",
            (tenant_id, batch_id),
        ).fetchone()[0]
        if window_count != inspected:
            raise _storage_failure()

        candidate = self._select_batch_candidate(
            conn, tenant_id, last_created_at, last_request_id
        )
        if candidate is None:
            # Nothing left to reconcile: seal and finish the batch.
            cursor = conn.execute(
                "UPDATE reconcile_batches SET sealed = 1, finished = 1 "
                "WHERE tenant_id = ? AND batch_id = ? AND sealed = 0",
                (tenant_id, batch_id),
            )
            if cursor.rowcount != 1:
                raise _storage_failure()
            state["sealed"] = True
            return None

        request_id, _status, created_at = candidate
        # Reuse the single-request reconciliation exactly: terminals are
        # read-only, live leases stay processing, and dead or
        # unexplainable processing rows converge inside this txn.
        # Accepted requests never reach here.
        record = self._reconcile_locked(conn, tenant_id, request_id)
        reconciled_status = record["status"]

        successor = self._select_batch_candidate(
            conn, tenant_id, created_at, request_id
        )
        new_inspected = inspected + 1
        will_finish = successor is None
        will_seal = new_inspected >= max_items or will_finish
        # Persist the window row in the same transaction as the
        # reconciliation and the cursor advance.
        conn.execute(
            "INSERT INTO reconcile_batch_items ("
            "tenant_id, batch_id, item_seq, request_id, status, created_at"
            ") VALUES (?, ?, ?, ?, ?, ?)",
            (
                tenant_id,
                batch_id,
                inspected,
                request_id,
                reconciled_status,
                created_at,
            ),
        )
        cursor = conn.execute(
            "UPDATE reconcile_batches "
            "SET inspected = ?, last_created_at = ?, last_request_id = ?, "
            "sealed = ?, finished = ? "
            "WHERE tenant_id = ? AND batch_id = ? AND sealed = 0",
            (
                new_inspected,
                created_at,
                request_id,
                1 if will_seal else 0,
                1 if will_finish else 0,
                tenant_id,
                batch_id,
            ),
        )
        if cursor.rowcount != 1:
            raise _storage_failure()
        state["sealed"] = will_seal
        return {
            "request_id": request_id,
            "status": reconciled_status,
        }

    @staticmethod
    def _select_batch_candidate(
        conn: sqlite3.Connection,
        tenant_id: str,
        after_created_at: str | None,
        after_request_id: str | None,
    ) -> tuple[str, str, str] | None:
        """Return the next non-accepted request after the keyset.

        ``accepted`` requests are skipped in the scan itself, so the
        first scan never creates an attempt, receipt or extra event for
        one. The keyset order (acceptance time, then request id) is
        stable.
        """
        if after_created_at is None:
            row = conn.execute(
                "SELECT request_id, status, created_at FROM requests "
                "WHERE tenant_id = ? AND status != ? "
                "ORDER BY created_at ASC, request_id ASC LIMIT 1",
                (tenant_id, _STATUS_ACCEPTED),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT request_id, status, created_at FROM requests "
                "WHERE tenant_id = ? AND status != ? "
                "AND (created_at > ? OR (created_at = ? AND request_id > ?)) "
                "ORDER BY created_at ASC, request_id ASC LIMIT 1",
                (
                    tenant_id,
                    _STATUS_ACCEPTED,
                    after_created_at,
                    after_created_at,
                    after_request_id,
                ),
            ).fetchone()
        if row is None:
            return None
        request_id, status, created_at = row
        if (
            not isinstance(request_id, str)
            or not request_id
            or not isinstance(status, str)
            or status not in _ALLOWED_TRANSITIONS
            or status == _STATUS_ACCEPTED
            or not isinstance(created_at, str)
            or not created_at
        ):
            # An out-of-lifecycle status or broken keyset column is
            # corruption; never scan or report from a bad read.
            raise _storage_failure()
        return request_id, status, created_at

    def _load_sealed_batch(
        self,
        conn: sqlite3.Connection,
        tenant_id: str,
        batch_id: str,
    ) -> tuple[bool, str, list[dict[str, str]]]:
        """Load a sealed batch's outcome and persisted window.

        Returns ``(finished, next_cursor_token, items)``. The items come
        straight from the persisted window so a retry reproduces the
        identical statuses and order; an unsealed batch is treated as
        corruption because the caller is handed a window only once it
        has fully sealed.
        """
        try:
            header = conn.execute(
                "SELECT sealed, finished, next_cursor_token, inspected "
                "FROM reconcile_batches WHERE tenant_id = ? AND batch_id = ?",
                (tenant_id, batch_id),
            ).fetchone()
        except sqlite3.Error:
            raise _storage_failure() from None
        if header is None:
            raise _storage_failure()
        sealed, finished, next_cursor_token, inspected = header
        if (
            sealed != 1
            or finished not in (0, 1)
            or not isinstance(next_cursor_token, str)
            or not next_cursor_token
            or not isinstance(inspected, int)
            or isinstance(inspected, bool)
        ):
            raise _storage_failure()
        try:
            rows = conn.execute(
                "SELECT item_seq, request_id, status FROM reconcile_batch_items "
                "WHERE tenant_id = ? AND batch_id = ? ORDER BY item_seq",
                (tenant_id, batch_id),
            ).fetchall()
        except sqlite3.Error:
            raise _storage_failure() from None
        items: list[dict[str, str]] = []
        for expected_seq, item_row in enumerate(rows):
            item_seq, request_id, status = item_row
            if (
                not isinstance(item_seq, int)
                or isinstance(item_seq, bool)
                or item_seq != expected_seq
                or not isinstance(request_id, str)
                or not request_id
                or not isinstance(status, str)
                or status not in _ALLOWED_TRANSITIONS
                or status == _STATUS_ACCEPTED
            ):
                raise _storage_failure()
            items.append({"request_id": request_id, "status": status})
        if len(items) != inspected:
            raise _storage_failure()
        return finished == 1, next_cursor_token, items

    def audit(
        self,
        tenant_id: str,
        request_id: str,
    ) -> list[dict[str, str]]:
        """Return the request's status timeline in occurrence order.

        Each entry contains only ``status`` and ``occurred_at`` (a UTC
        RFC3339 string). The final entry's status always equals the result
        of :meth:`get_status`. Invalid, unknown and cross-tenant ids raise
        :class:`RequestNotFound` with identical behaviour, so the call
        cannot reveal another tenant's records or which ids exist.
        """
        tenant_id = _require_nonempty_str(tenant_id, "tenant_id")
        request_id = _require_identifier(request_id)
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
            # like get_status().
            try:
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
            except RequestNotFound:
                raise
            except sqlite3.Error:
                raise _storage_failure() from None
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
        to :meth:`get_status`), ``event_count`` (identical to the length
        of :meth:`audit`) and ``chain_hash`` (the SHA-256 head of the
        audit chain as persisted, never recomputed). Invalid, unknown and
        cross-tenant ids raise :class:`RequestNotFound`; a non-string or
        empty *tenant_id* raises :class:`ValueError`.
        """
        tenant_id = _require_nonempty_str(tenant_id, "tenant_id")
        request_id = _require_identifier(request_id)
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
        request's anchored head and current status. Invalid, unknown and
        cross-tenant ids raise :class:`RequestNotFound`; a non-string or
        empty *tenant_id* raises :class:`ValueError`.
        """
        tenant_id = _require_nonempty_str(tenant_id, "tenant_id")
        request_id = _require_identifier(request_id)
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
                raise _storage_failure() from None
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
                raise _storage_failure() from None
        finally:
            self._release(conn)
        if row is None:
            # Identical outcome for unknown ids and cross-tenant lookups.
            raise RequestNotFound("request not found")
        return row[0], row[1], row[2]
