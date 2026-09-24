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
        # Oldest accepted, or oldest processing whose latest lease has
        # expired. The correlated subquery reads the most recent attempt's
        # expiry; a request with no attempts has none and only qualifies
        # while accepted. BEGIN IMMEDIATE plus the write lock make the
        # read-then-claim atomic, so two workers can never both win.
        row = conn.execute(
            "SELECT r.request_id, r.status "
            "FROM requests r "
            "WHERE r.tenant_id = ? "
            "  AND ( "
            "    r.status = ? "
            "    OR ( "
            "      r.status = ? "
            "      AND ? > COALESCE( "
            "        (SELECT c.lease_expires_at FROM claim_attempts c "
            "         WHERE c.tenant_id = r.tenant_id "
            "           AND c.request_id = r.request_id "
            "         ORDER BY c.attempt_number DESC LIMIT 1), "
            "        '') "
            "    ) "
            "  ) "
            "ORDER BY r.created_at ASC, r.request_id ASC LIMIT 1",
            (
                tenant_id,
                _STATUS_ACCEPTED,
                _STATUS_PROCESSING,
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
        if owner is None or (owner[0], owner[1]) != (tenant_id, request_id):
            # Unknown, already released (a successor or finish deleted it),
            # or presented against a different tenant/request.
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
