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
* :meth:`RequestStore.reconcile_batch` applies the same convergence in
  tenant-scoped, resumable batches. The first call (no cursor) creates a
  persistent batch whose cursor position survives restarts; the same
  cursor resumes that batch from its committed position and keeps its
  batch identifier. ``accepted`` requests are skipped on the first scan
  without creating an attempt, receipt or status event, and each item's
  state, attempts, lease, batch row and cursor commit in one transaction.

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

import base64
import binascii
import hashlib
import hmac
import json
import logging
import os
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

# Persistent reconcile batches. A batch is created by the first batch call
# for a tenant (cursor omitted) and survives restarts, so a caller that
# presents the same cursor again resumes from the durably committed
# position instead of restarting the sweep. ``position_created_at`` /
# ``position_request_id`` hold the keyset position (the last scanned row);
# both NULL means "before the first row". ``finished`` is 1 once the sweep
# has seen every row that existed when it ran out of candidates.
_BATCH_TABLE = """
CREATE TABLE IF NOT EXISTS reconcile_batches (
    batch_id            TEXT PRIMARY KEY,
    tenant_id           TEXT NOT NULL,
    position_created_at TEXT,
    position_request_id TEXT,
    finished            INTEGER NOT NULL DEFAULT 0
);
"""

# Per-item outcomes of a batch, one row per scanned request. Items are
# written in the same transaction as the status/attempt/lease effects of
# reconciling that request and the batch position update, so a crash can
# never leave a reconciled request without its batch bookkeeping (or vice
# versa) and a retry of the same cursor never rewrites a settled row.
_BATCH_ITEM_TABLE = """
CREATE TABLE IF NOT EXISTS reconcile_batch_items (
    batch_id    TEXT NOT NULL,
    seq         INTEGER NOT NULL,
    request_id  TEXT NOT NULL,
    status      TEXT NOT NULL,
    PRIMARY KEY (batch_id, seq)
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

# Batch reconciliation. A batch sweeps the tenant's requests in stable
# (created_at, request_id) order; each call processes at most ``limit``
# reconcilable items. The default and the upper bound keep a single call
# bounded without letting a caller ask for an unbounded sweep.
_DEFAULT_BATCH_LIMIT = 100
_MAX_BATCH_LIMIT = 1000
# Opaque cursor format: a fixed version prefix plus base64url(JSON) carrying
# only the batch id and the item count it was issued at. The authoritative
# position always lives in reconcile_batches; the cursor only identifies
# which persisted batch to resume. Anything outside this exact shape --
# wrong prefix, bad padding, foreign JSON, unknown or cross-tenant batch --
# is an invalid cursor and raises ValueError without touching storage.
_CURSOR_PREFIX = "rc1."
_B64URL_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)


def _require_batch_limit(value: object) -> int:
    """Validate a batch limit: a non-boolean int in 1..1000."""
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError("limit must be an integer between 1 and 1000")
    if not 1 <= value <= _MAX_BATCH_LIMIT:
        raise ValueError("limit must be an integer between 1 and 1000")
    return value


def _encode_cursor(batch_id: str, position: int) -> str:
    """Render the opaque cursor for a batch at a given item count."""
    payload = json.dumps(
        {"v": 1, "b": batch_id, "n": position},
        separators=(",", ":"),
    ).encode("utf-8")
    return _CURSOR_PREFIX + base64.urlsafe_b64encode(payload).decode("ascii")


def _decode_cursor(value: object) -> tuple[str, int]:
    """Parse and strictly validate an opaque cursor.

    Every malformed value -- non-string, empty, wrong prefix, bad
    base64url, foreign JSON shape, wrong types -- raises :class:`ValueError`
    identically, so the cursor format can never be probed through
    distinguishable failures.
    """
    if not isinstance(value, str) or not value.startswith(_CURSOR_PREFIX):
        raise ValueError("cursor is not valid")
    body = value[len(_CURSOR_PREFIX) :]
    if (
        not body
        or len(body) % 4 != 0
        or any(char not in _B64URL_CHARS and char != "=" for char in body)
    ):
        raise ValueError("cursor is not valid")
    try:
        payload = json.loads(base64.urlsafe_b64decode(body.encode("ascii")))
    except (ValueError, binascii.Error):
        raise ValueError("cursor is not valid") from None
    if not isinstance(payload, dict) or set(payload) != {"v", "b", "n"}:
        raise ValueError("cursor is not valid")
    batch_id = payload["b"]
    position = payload["n"]
    if (
        payload["v"] != 1
        or not isinstance(batch_id, str)
        or not batch_id
        or not isinstance(position, int)
        or isinstance(position, bool)
        or position < 0
    ):
        raise ValueError("cursor is not valid")
    return batch_id, position


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
        the same tenant; an unknown, expired, already-released or
        cross-tenant token -- as well as finishing a request that has no
        open claim -- raises :class:`ClaimConflict` and changes nothing.
        The terminal status and its chain event are committed in the same
        transaction that records the attempt result and releases the
        token. Returns the status record (``request_id``, ``status``,
        ``created_at``).
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
        # Resolve the presented token without scoping by tenant first: a
        # token issued to another tenant (or for another request) must look
        # exactly like an unknown or released one and raise ClaimConflict,
        # never reveal that the coordinates name a record elsewhere.
        presented = hashlib.sha256(claim_token.encode("utf-8")).hexdigest()
        owner = conn.execute(
            "SELECT tenant_id, request_id, attempt_number FROM claim_tokens "
            "WHERE token_hash = ? LIMIT 1",
            (presented,),
        ).fetchone()
        if owner is None:
            # The credential itself is invalid (unknown or released). The
            # request id then decides the error with stable precedence:
            # an unknown or cross-tenant id raises RequestNotFound even
            # though the credential is also invalid, while an existing
            # request presented with a bad credential is a ClaimConflict.
            exists = conn.execute(
                "SELECT 1 FROM requests WHERE tenant_id = ? AND request_id = ?",
                (tenant_id, request_id),
            ).fetchone()
            if exists is None:
                raise RequestNotFound("request not found")
            raise _claim_conflict()
        if (owner[0], owner[1]) != (tenant_id, request_id):
            # A live credential presented against a different tenant or
            # request: already released/foreign for these coordinates.
            raise _claim_conflict()
        attempt_number = owner[2]

        row = conn.execute(
            "SELECT status, created_at FROM requests "
            "WHERE tenant_id = ? AND request_id = ?",
            (tenant_id, request_id),
        ).fetchone()
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
        limit: int | None = None,
    ) -> dict[str, object]:
        """Reconcile a tenant's pending requests in resumable batches.

        Storage-layer only; never routed over HTTP. With ``cursor``
        omitted a new persistent batch sweeps the tenant's requests in
        stable acceptance order (``created_at`` then ``request_id``);
        with a cursor the batch it names is resumed from its durably
        committed position, so a retry after an interruption continues
        instead of restarting, and the same cursor always keeps the same
        batch identifier. Each call reconciles at most ``limit`` items
        (default 100, at most 1000) and returns exactly ``batch_id``,
        ``next_cursor`` (``None`` once the sweep is finished),
        ``finished`` and ``items`` -- one ``{"request_id", "status"}``
        entry per reconciled request, in scan order.

        Reconciliation of each request follows
        :meth:`reconcile_execution`: ``accepted`` rows are skipped
        without creating an attempt, receipt or extra status event;
        a ``processing`` request with a live lease stays processing; a
        ``processing`` request whose lease expired (or that has no
        explainable lease) is compensated to ``failed``. Every item's
        status change, attempt rows, lease release, batch bookkeeping
        and cursor position commit in one transaction, so a failed call
        leaves no half-settled item and a committed item is never
        rewritten by a retry.

        A non-string/empty *tenant_id*, a limit outside 1..1000 (or a
        non-integer), and any malformed, unknown or cross-tenant
        *cursor* raise :class:`ValueError` without writing. Corrupt
        persisted batch state and every storage fault raise the
        fixed-text :class:`OSError`.
        """
        # Validate everything before touching the database: no rejected
        # call may perform a write.
        tenant_id = _require_nonempty_str(tenant_id, "tenant_id")
        if limit is None:
            limit = _DEFAULT_BATCH_LIMIT
        limit = _require_batch_limit(limit)
        cursor_batch: tuple[str, int] | None = None
        if cursor is not None:
            cursor_batch = _decode_cursor(cursor)

        with self._write_lock:
            conn = self._connect()
            try:
                # First transaction resolves the batch: a fresh batch row
                # is inserted when no cursor was given; a cursor names the
                # persisted batch to resume. An unknown/cross-tenant cursor
                # is rejected here before anything is written.
                batch_id, _pos, _rid, finished, start_count = (
                    self._batch_transaction(
                        conn,
                        lambda: self._load_or_init_batch_locked(
                            conn, tenant_id, cursor_batch
                        ),
                    )
                )
                items: list[dict[str, str]] = []
                # Each scanned request is settled in its OWN transaction:
                # its status change, attempts, lease release, the item row
                # and the cursor position all commit together. The next
                # iteration re-reads the persisted position, so an item
                # already settled by an earlier commit or a concurrent call
                # is never rewritten.
                while not finished and len(items) < limit:
                    kind, payload = self._batch_transaction(
                        conn,
                        lambda: self._process_one_batch_item_locked(
                            conn, tenant_id, batch_id
                        ),
                    )
                    if kind == "finished":
                        finished = True
                        break
                    if kind == "item":
                        items.append(payload)
                    # "accepted" only advanced the position and is skipped.
                if not finished:
                    # The limit stopped the loop: finish the batch only if
                    # nothing reconcilable remains beyond the committed
                    # position, otherwise leave it resumable.
                    finished = self._batch_transaction(
                        conn,
                        lambda: self._finalize_batch_if_end_locked(
                            conn, tenant_id, batch_id
                        ),
                    )
            finally:
                self._release(conn)
        # The write lock serializes batch writers, so the batch's item
        # count grows only via the items this call committed.
        next_cursor = (
            None if finished else _encode_cursor(batch_id, start_count + len(items))
        )
        # Log only counts and the stable outcome: no tenant, subject,
        # worker, credential or SQL text ever reaches the log.
        _log.info(
            "reconcile batch settled items=%s finished=%s",
            len(items),
            finished,
        )
        return {
            "batch_id": batch_id,
            "next_cursor": next_cursor,
            "finished": finished,
            "items": items,
        }

    def _batch_transaction(self, conn: sqlite3.Connection, action):
        """Run ``action`` inside one short-lived write transaction.

        Every batch operation (batch resolution, one item, the end
        finalization) commits independently, so a fault while settling a
        later item can never undo an already committed earlier item or
        leave the shared connection inside an aborted transaction. Domain
        and storage exceptions propagate after a rollback; any engine
        error -- including lock conflicts -- becomes the fixed-text
        :class:`OSError`.
        """
        try:
            conn.execute("BEGIN IMMEDIATE")
        except sqlite3.Error:
            raise _storage_failure() from None
        try:
            result = action()
            conn.execute("COMMIT")
            return result
        except ValueError:
            self._rollback_quietly(conn)
            raise
        except (RequestNotFound, InvalidStatusTransition):
            # Defensive only: rows are read inside this write transaction
            # and cannot vanish or move illegally underneath it.
            self._rollback_quietly(conn)
            raise _storage_failure() from None
        except OSError:
            self._rollback_quietly(conn)
            raise
        except sqlite3.Error:
            self._rollback_quietly(conn)
            raise _storage_failure() from None

    @staticmethod
    def _rollback_quietly(conn: sqlite3.Connection) -> None:
        try:
            conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass

    def _process_one_batch_item_locked(
        self,
        conn: sqlite3.Connection,
        tenant_id: str,
        batch_id: str,
    ) -> tuple[str, object]:
        """Settle the next scan position inside an open write txn.

        Re-reads the batch's persisted position every call, so the result
        is independent of any in-memory position. Returns
        ``("finished", None)`` once the sweep end is reached,
        ``("accepted", None)`` after advancing past a skipped accepted
        row, or ``("item", {"request_id", "status"})`` after reconciling
        a processing request and recording its item.
        """
        pos_created, pos_rid, finished, item_count = self._read_batch_state_locked(
            conn, batch_id
        )
        if finished:
            return "finished", None
        row = self._next_batch_candidate(conn, tenant_id, pos_created, pos_rid)
        if row is None:
            self._finish_batch_locked(conn, batch_id)
            return "finished", None
        request_id, created_at, status = row
        if status == _STATUS_ACCEPTED:
            # First-scan rule: accepted rows are skipped -- no attempt,
            # receipt or extra status event -- but the position advances
            # past them so they are never rescanned.
            self._advance_batch_locked(conn, batch_id, created_at, request_id)
            return "accepted", None
        record = self._reconcile_locked(conn, tenant_id, request_id)
        # The item row, the reconcile effects and the cursor position land
        # in this one transaction; the sequence derives from the persisted
        # count so a resumed batch never reuses a number.
        conn.execute(
            "INSERT INTO reconcile_batch_items ("
            "batch_id, seq, request_id, status"
            ") VALUES (?, ?, ?, ?)",
            (batch_id, item_count + 1, request_id, record["status"]),
        )
        self._advance_batch_locked(conn, batch_id, created_at, request_id)
        return "item", {"request_id": request_id, "status": record["status"]}

    def _finalize_batch_if_end_locked(
        self,
        conn: sqlite3.Connection,
        tenant_id: str,
        batch_id: str,
    ) -> bool:
        """Mark a limit-stopped batch finished iff no candidate remains."""
        pos_created, pos_rid, finished, _count = self._read_batch_state_locked(
            conn, batch_id
        )
        if finished:
            return True
        if self._next_batch_candidate(conn, tenant_id, pos_created, pos_rid) is None:
            self._finish_batch_locked(conn, batch_id)
            return True
        return False

    def _read_batch_state_locked(
        self, conn: sqlite3.Connection, batch_id: str
    ) -> tuple[str | None, str | None, bool, int]:
        """Read and strictly validate a batch's persisted position."""
        row = conn.execute(
            "SELECT position_created_at, position_request_id, finished, "
            "(SELECT count(*) FROM reconcile_batch_items i "
            " WHERE i.batch_id = b.batch_id) "
            "FROM reconcile_batches b WHERE b.batch_id = ?",
            (batch_id,),
        ).fetchone()
        if row is None:
            # The batch this transaction is driving vanished out of band.
            raise _storage_failure()
        pos_created, pos_rid, finished, item_count = row
        if (
            finished not in (0, 1)
            or not isinstance(item_count, int)
            or isinstance(item_count, bool)
        ):
            raise _storage_failure()
        if (pos_created is None) != (pos_rid is None):
            # The keyset position is written atomically; a split pair is
            # out-of-band corruption, never a resumable state.
            raise _storage_failure()
        if pos_created is not None and (
            not isinstance(pos_created, str)
            or not pos_created
            or not isinstance(pos_rid, str)
            or not pos_rid
        ):
            raise _storage_failure()
        return pos_created, pos_rid, bool(finished), item_count

    def _load_or_init_batch_locked(
        self,
        conn: sqlite3.Connection,
        tenant_id: str,
        cursor_batch: tuple[str, int] | None,
    ) -> tuple[str, str | None, str | None, bool, int]:
        """Resolve the batch for this call inside an open write txn.

        Returns ``(batch_id, position_created_at, position_request_id,
        finished, item_count)``. Without a cursor a fresh batch row is
        inserted; with a cursor the persisted batch is resumed from its
        committed position -- the cursor's own position field is only a
        format detail, the database is authoritative. An unknown or
        cross-tenant batch id is an invalid cursor and raises
        :class:`ValueError`; corrupt persisted state raises the
        fixed-text :class:`OSError`.
        """
        if cursor_batch is None:
            batch_id = str(uuid.uuid4())
            conn.execute(
                "INSERT INTO reconcile_batches ("
                "batch_id, tenant_id, position_created_at, "
                "position_request_id, finished"
                ") VALUES (?, ?, NULL, NULL, 0)",
                (batch_id, tenant_id),
            )
            return batch_id, None, None, False, 0
        batch_id, _issued_position = cursor_batch
        # Confirm ownership before reading state: an unknown or
        # cross-tenant batch id is an invalid cursor, indistinguishable
        # from one that never existed.
        owner = conn.execute(
            "SELECT 1 FROM reconcile_batches WHERE batch_id = ? AND tenant_id = ?",
            (batch_id, tenant_id),
        ).fetchone()
        if owner is None:
            raise ValueError("cursor is not valid")
        pos_created, pos_rid, finished, item_count = self._read_batch_state_locked(
            conn, batch_id
        )
        return batch_id, pos_created, pos_rid, finished, item_count

    @staticmethod
    def _next_batch_candidate(
        conn: sqlite3.Connection,
        tenant_id: str,
        pos_created: str | None,
        pos_rid: str | None,
    ) -> tuple[str, str, str] | None:
        """Oldest non-terminal request strictly after the keyset position.

        Only ``accepted`` and ``processing`` rows are swept; terminal
        requests are already converged and never need a batch item. The
        (created_at, request_id) ordering matches the claim candidate
        index, so the scan is stable across calls, restarts and
        concurrent submissions.
        """
        if pos_created is None:
            return conn.execute(
                "SELECT request_id, created_at, status FROM requests "
                "WHERE tenant_id = ? AND status IN (?, ?) "
                "ORDER BY created_at ASC, request_id ASC LIMIT 1",
                (tenant_id, _STATUS_ACCEPTED, _STATUS_PROCESSING),
            ).fetchone()
        return conn.execute(
            "SELECT request_id, created_at, status FROM requests "
            "WHERE tenant_id = ? AND status IN (?, ?) "
            "AND (created_at, request_id) > (?, ?) "
            "ORDER BY created_at ASC, request_id ASC LIMIT 1",
            (tenant_id, _STATUS_ACCEPTED, _STATUS_PROCESSING, pos_created, pos_rid),
        ).fetchone()

    @staticmethod
    def _advance_batch_locked(
        conn: sqlite3.Connection,
        batch_id: str,
        pos_created: str,
        pos_rid: str,
    ) -> None:
        """Move the batch's durable keyset position forward."""
        cursor = conn.execute(
            "UPDATE reconcile_batches "
            "SET position_created_at = ?, position_request_id = ? "
            "WHERE batch_id = ?",
            (pos_created, pos_rid, batch_id),
        )
        if cursor.rowcount != 1:
            # The batch row this transaction itself resolved vanished;
            # that is storage corruption, never a caller error.
            raise _storage_failure()

    @staticmethod
    def _finish_batch_locked(conn: sqlite3.Connection, batch_id: str) -> None:
        """Mark the batch durably finished inside the open transaction."""
        cursor = conn.execute(
            "UPDATE reconcile_batches SET finished = 1 WHERE batch_id = ?",
            (batch_id,),
        )
        if cursor.rowcount != 1:
            raise _storage_failure()

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
