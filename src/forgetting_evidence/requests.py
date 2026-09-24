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

Execution orchestration lives on the same store but is never exposed
over HTTP:

* :meth:`RequestStore.claim_next` atomically hands the oldest claimable
  request of a tenant to one worker for a bounded lease, moving
  ``accepted`` requests to ``processing`` and issuing an unpredictable
  claim token. A request with an expired lease may be re-claimed; each
  (re-)claim opens a new execution attempt.
* :meth:`RequestStore.finish_claim` ends the attempt owning a valid
  token and drives the request to a ``completed`` or ``failed``
  terminal state.
* :meth:`RequestStore.get_execution_log` returns the tenant's attempt
  records -- attempt number, claim/lease-expiry times, terminal result
  and completion time -- without ever revealing a worker id or a claim
  token.

The worker id and claim token are operational secrets, not evidence:
they are persisted only as a keyed SHA-256 digest used to authenticate
:meth:`finish_claim`, and never appear in a return value, log record or
exception message.
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
    """Raised when a claim token is unknown, expired, released or foreign."""


class _PrimaryKeyConflict(Exception):
    """Internal signal: retry insertion with a freshly generated id."""


_SCHEMA = """
CREATE TABLE IF NOT EXISTS requests (
    request_id       TEXT PRIMARY KEY,
    tenant_id        TEXT NOT NULL,
    idempotency_key  TEXT NOT NULL,
    subject_id       TEXT NOT NULL,
    scopes_json      TEXT NOT NULL,
    status           TEXT NOT NULL,
    created_at       TEXT NOT NULL,
    chain_hash       TEXT NOT NULL,
    lease_expires_at TEXT,
    lease_key        TEXT
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

# One row per execution attempt: the first claim of a request opens
# attempt 1 and every claim after an expired lease opens the next one.
# Only the terminal result and completion time of the final attempt are
# ever reported back; worker_id and claim_token are stored solely as
# keyed digests for finish authentication and are never returned.
_ATTEMPT_TABLE = """
CREATE TABLE IF NOT EXISTS execution_attempts (
    tenant_id        TEXT NOT NULL,
    request_id       TEXT NOT NULL,
    attempt_no       INTEGER NOT NULL,
    claimed_at       TEXT NOT NULL,
    lease_expires_at TEXT NOT NULL,
    result           TEXT,
    finished_at      TEXT,
    claim_digest     TEXT NOT NULL,
    PRIMARY KEY (tenant_id, request_id, attempt_no)
);
"""

# The composite primary key already covers the ordered attempt read and
# the lookup of a request's latest attempt.

# Column probes used to add lease/key columns to database files created
# before execution orchestration existed. The upgrade is purely additive
# (nullable columns on the existing table); accepted rows simply carry
# NULL leases until they are first claimed.
_REQUEST_LEASE_COLUMNS = (
    "SELECT 1 FROM pragma_table_info('requests') WHERE name = 'lease_expires_at'"
)
_REQUEST_KEY_COLUMN = (
    "SELECT 1 FROM pragma_table_info('requests') WHERE name = 'lease_key'"
)

# Holds the persistent key used to digest claim tokens. Keeping the key
# in the database itself (rather than generating it per process) means
# unexpired leases and their tokens survive service restarts.
_META_TABLE = """
CREATE TABLE IF NOT EXISTS store_meta (
    meta_key   TEXT PRIMARY KEY,
    meta_value TEXT NOT NULL
);
"""
_LEASE_KEY_NAME = "claim_token_key"

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

# Lease duration domain, in seconds.
_MIN_LEASE_SECONDS = 1
_MAX_LEASE_SECONDS = 3600

# Terminal results a claimed attempt may report.
_RESULT_COMPLETED = "completed"
_RESULT_FAILED = "failed"
_FINISH_RESULTS = frozenset({_RESULT_COMPLETED, _RESULT_FAILED})


def _require_lease_seconds(lease_seconds: object) -> int:
    # bool is an int subclass; a boolean lease is out of range.
    if (
        not isinstance(lease_seconds, int)
        or isinstance(lease_seconds, bool)
        or not _MIN_LEASE_SECONDS <= lease_seconds <= _MAX_LEASE_SECONDS
    ):
        raise ValueError(
            "lease_seconds must be an integer between "
            f"{_MIN_LEASE_SECONDS} and {_MAX_LEASE_SECONDS}"
        )
    return lease_seconds


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
                conn.execute(_ATTEMPT_TABLE)
                conn.execute(_META_TABLE)
                self._migrate_schema(conn)
                self._lease_key = self._load_or_create_lease_key(conn)
            except sqlite3.Error:
                raise _storage_failure() from None
        finally:
            self._release(conn)

    def _load_or_create_lease_key(self, conn: sqlite3.Connection) -> bytes:
        """Return the persistent claim-token key, creating it once.

        The key lives in the database so a token handed out before a
        restart stays verifiable afterwards. A freshly generated key uses
        the operating-system CSPRNG and is never returned or logged.
        """
        row = conn.execute(
            "SELECT meta_value FROM store_meta WHERE meta_key = ?",
            (_LEASE_KEY_NAME,),
        ).fetchone()
        if row is not None:
            key = row[0]
            if isinstance(key, str) and len(key) == 64 and all(
                char in _HEX for char in key
            ):
                return bytes.fromhex(key)
            # A key row altered out of band is corruption: never fall back
            # to a process-local key that would silently invalidate every
            # live lease.
            raise _storage_failure()
        raw_key = secrets.token_bytes(32)
        try:
            conn.execute(
                "INSERT INTO store_meta (meta_key, meta_value) VALUES (?, ?)",
                (_LEASE_KEY_NAME, raw_key.hex()),
            )
        except sqlite3.IntegrityError:
            # Another process creating its store concurrently won the
            # single key row; adopt that key rather than invalidating the
            # leases it authenticates.
            row = conn.execute(
                "SELECT meta_value FROM store_meta WHERE meta_key = ?",
                (_LEASE_KEY_NAME,),
            ).fetchone()
            if row is None:
                raise
            key = row[0]
            if not (isinstance(key, str) and len(key) == 64 and all(
                char in _HEX for char in key
            )):
                raise _storage_failure()
            return bytes.fromhex(key)
        return raw_key

    def _migrate_schema(self, conn: sqlite3.Connection) -> None:
        """Add columns introduced by newer versions.

        Two additive upgrades are handled, each running at most once and
        re-probed inside the migration transaction:

        * lease/claim columns on ``requests`` for execution orchestration;
          accepted rows simply carry NULL leases until first claimed.
        * chain-hash columns on both tables for databases written before
          tamper evidence existed. Existing events are backfilled in
          sequence order and each request head is anchored at its final
          event. Existing chain values are never recomputed or
          overwritten.
        """
        needs_lease_columns = not (
            conn.execute(_REQUEST_LEASE_COLUMNS).fetchone()
            and conn.execute(_REQUEST_KEY_COLUMN).fetchone()
        )
        needs_chain_columns = not (
            conn.execute(_REQUEST_CHAIN_COLUMN).fetchone()
            and conn.execute(_EVENT_CHAIN_COLUMN).fetchone()
        )
        if not needs_lease_columns and not needs_chain_columns:
            return
        with self._write_lock:
            try:
                conn.execute("BEGIN IMMEDIATE")
                # Re-probe inside the transaction: another process may
                # have completed the upgrade while we waited on the lock.
                if not conn.execute(_REQUEST_LEASE_COLUMNS).fetchone():
                    conn.execute(
                        "ALTER TABLE requests ADD COLUMN lease_expires_at TEXT"
                    )
                if not conn.execute(_REQUEST_KEY_COLUMN).fetchone():
                    conn.execute("ALTER TABLE requests ADD COLUMN lease_key TEXT")
                if needs_chain_columns and not conn.execute(
                    _REQUEST_CHAIN_COLUMN
                ).fetchone():
                    conn.execute("ALTER TABLE requests ADD COLUMN chain_hash TEXT")
                if needs_chain_columns and not conn.execute(
                    _EVENT_CHAIN_COLUMN
                ).fetchone():
                    conn.execute(
                        "ALTER TABLE status_events ADD COLUMN chain_hash TEXT"
                    )
                if needs_chain_columns:
                    self._backfill_chain(conn)
                conn.execute("COMMIT")
            except sqlite3.Error:
                try:
                    conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise _storage_failure() from None

    def _backfill_chain(self, conn: sqlite3.Connection) -> None:
        """Backfill chain links on a database written before hashing."""
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
        # Anchor each request head at its final event. A request with no
        # events keeps NULL and fails verification rather than receiving
        # a fabricated anchor.
        conn.execute(
            "UPDATE requests SET chain_hash = ( "
            "SELECT e.chain_hash FROM status_events e "
            "WHERE e.tenant_id = requests.tenant_id "
            "  AND e.request_id = requests.request_id "
            "ORDER BY e.seq DESC LIMIT 1 "
            ") WHERE chain_hash IS NULL"
        )

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

    # -- execution orchestration -------------------------------------

    def _digest_claim_token(self, token: str) -> str:
        """Keyed digest of a claim token, bound to this store's key.

        Only the digest is persisted; the unpredictable token itself
        exists solely in the claim return value and the finish caller's
        hands.
        """
        return hmac.new(
            self._lease_key, token.encode("utf-8"), hashlib.sha256
        ).hexdigest()

    def claim_next(
        self,
        tenant_id: str,
        worker: str,
        lease_seconds: int,
    ) -> dict[str, str] | None:
        """Atomically claim the tenant's oldest claimable request.

        ``accepted`` requests and ``processing`` requests whose lease has
        expired compete by original acceptance time and request id; the
        single oldest row wins. A request under an unexpired lease can
        only be held by one worker. Claiming an ``accepted`` request
        moves it to ``processing``; re-claiming an expired
        ``processing`` request changes neither its first acceptance time,
        request id nor current status. Every (re-)claim opens the next
        execution attempt and returns a fresh unpredictable token.

        Returns ``None`` when the tenant has no claimable request.
        Invalid arguments raise :class:`ValueError` without writing; a
        storage fault raises fixed-text :class:`OSError`.
        """
        tenant_id = _require_nonempty_str(tenant_id, "tenant_id")
        worker = _require_nonempty_str(worker, "worker")
        lease_seconds = _require_lease_seconds(lease_seconds)

        with self._write_lock:
            conn = self._connect()
            try:
                token = secrets.token_urlsafe(32)
                token_digest = self._digest_claim_token(token)
                try:
                    conn.execute("BEGIN IMMEDIATE")
                    # Stamp after acquiring the write transaction so a
                    # contender blocked on the lock never inherits a
                    # stale claim time or lease window.
                    claimed_at = _utc_now_rfc3339()
                    lease_expires_at = (
                        datetime.now(timezone.utc) + timedelta(seconds=lease_seconds)
                    ).isoformat().replace("+00:00", "Z")
                    # BEGIN IMMEDIATE serializes contenders against the
                    # same database file; the in-process lock covers
                    # threads sharing this instance. Exactly one
                    # contender can observe a row as claimable.
                    row = conn.execute(
                        "SELECT request_id, status, created_at "
                        "FROM requests "
                        "WHERE tenant_id = ? "
                        "AND (status = 'accepted' "
                        "     OR (status = 'processing' AND "
                        "         (lease_expires_at IS NULL OR lease_expires_at <= ?))) "
                        "ORDER BY created_at, request_id LIMIT 1",
                        (tenant_id, claimed_at),
                    ).fetchone()
                    if row is None:
                        conn.execute("ROLLBACK")
                        return None
                    request_id, prior_status, created_at = row
                    attempt_no = self._next_attempt_no(conn, tenant_id, request_id)
                    if prior_status == _STATUS_ACCEPTED:
                        # The claim performs the accepted->processing
                        # edge, so append the processing link to the
                        # audit chain in the same transaction.
                        chain_target = _STATUS_PROCESSING
                        predecessor_seq, predecessor_at, predecessor_hash = (
                            self._latest_event(
                                conn, tenant_id, request_id
                            )
                        )
                        if not self._event_head_is_intact(
                            predecessor_seq, predecessor_at, predecessor_hash
                        ):
                            conn.execute("ROLLBACK")
                            raise _storage_failure()
                        occurred_at = _occurred_at_not_before(predecessor_at)
                        next_link = _chain_hash(
                            tenant_id,
                            request_id,
                            predecessor_seq + 1,
                            chain_target,
                            occurred_at,
                            predecessor_hash,
                        )
                        cursor = conn.execute(
                            "UPDATE requests "
                            "SET status = 'processing', lease_expires_at = ?, "
                            "lease_key = ?, chain_hash = ? "
                            "WHERE tenant_id = ? AND request_id = ? AND status = 'accepted'",
                            (
                                lease_expires_at,
                                token_digest,
                                next_link,
                                tenant_id,
                                request_id,
                            ),
                        )
                        if cursor.rowcount != 1:
                            # Another writer advanced the row between
                            # SELECT and UPDATE; the race outcome stays
                            # legal: claim nothing this round.
                            conn.execute("ROLLBACK")
                            return None
                        conn.execute(
                            "INSERT INTO status_events ("
                            "tenant_id, request_id, seq, status, occurred_at, chain_hash"
                            ") VALUES (?, ?, ?, 'processing', ?, ?)",
                            (
                                tenant_id,
                                request_id,
                                predecessor_seq + 1,
                                occurred_at,
                                next_link,
                            ),
                        )
                    else:
                        # Expired-lease re-claim: no state transition and
                        # therefore no status event; only the lease, its
                        # digest and a fresh attempt row change.
                        cursor = conn.execute(
                            "UPDATE requests "
                            "SET lease_expires_at = ?, lease_key = ? "
                            "WHERE tenant_id = ? AND request_id = ? "
                            "AND status = 'processing' "
                            "AND (lease_expires_at IS NULL OR lease_expires_at <= ?)",
                            (
                                lease_expires_at,
                                token_digest,
                                tenant_id,
                                request_id,
                                claimed_at,
                            ),
                        )
                        if cursor.rowcount != 1:
                            # The lease was renewed or the request
                            # finished while we waited; claim nothing.
                            conn.execute("ROLLBACK")
                            return None
                    conn.execute(
                        "INSERT INTO execution_attempts ("
                        "tenant_id, request_id, attempt_no, claimed_at, "
                        "lease_expires_at, result, finished_at, claim_digest"
                        ") VALUES (?, ?, ?, ?, ?, NULL, NULL, ?)",
                        (
                            tenant_id,
                            request_id,
                            attempt_no,
                            claimed_at,
                            lease_expires_at,
                            token_digest,
                        ),
                    )
                    conn.execute("COMMIT")
                except sqlite3.Error:
                    try:
                        conn.execute("ROLLBACK")
                    except sqlite3.Error:
                        pass
                    raise _storage_failure() from None
            finally:
                self._release(conn)
            _log.info(
                "request claimed request_id=%s attempt=%s",
                request_id,
                attempt_no,
            )
            return {
                "request_id": request_id,
                "claim_token": token,
                "lease_expires_at": lease_expires_at,
            }

    @staticmethod
    def _latest_event(
        conn: sqlite3.Connection, tenant_id: str, request_id: str
    ) -> tuple[int | None, str | None, str | None]:
        row = conn.execute(
            "SELECT seq, occurred_at, chain_hash FROM status_events "
            "WHERE tenant_id = ? AND request_id = ? ORDER BY seq DESC LIMIT 1",
            (tenant_id, request_id),
        ).fetchone()
        if row is None:
            return None, None, None
        return row[0], row[1], row[2]

    @staticmethod
    def _event_head_is_intact(
        seq: object, occurred_at: object, chain_hash_value: object
    ) -> bool:
        """Validate the shape of the chain head before extending it.

        SQLite's dynamic typing lets out-of-band writes store unexpected
        Python types; comparing such values would raise ``TypeError`` and
        leak past the fixed-text storage contract.
        """
        return (
            isinstance(seq, int)
            and not isinstance(seq, bool)
            and isinstance(occurred_at, str)
            and _is_chain_hash(chain_hash_value)
        )

    @staticmethod
    def _next_attempt_no(
        conn: sqlite3.Connection, tenant_id: str, request_id: str
    ) -> int:
        row = conn.execute(
            "SELECT max(attempt_no) FROM execution_attempts "
            "WHERE tenant_id = ? AND request_id = ?",
            (tenant_id, request_id),
        ).fetchone()
        latest = row[0]
        return 1 if latest is None else latest + 1

    def finish_claim(
        self,
        tenant_id: str,
        request_id: str,
        claim_token: str,
        result: str,
    ) -> dict[str, str]:
        """Complete the attempt authenticated by ``claim_token``.

        ``result`` must be ``completed`` or ``failed``; the request
        reaches that terminal state and the attempt records its result
        and completion time. An unknown, expired, already-released
        (superseded by a re-claim) or cross-tenant token raises
        :class:`ClaimConflict` and leaves every state untouched.
        Invalid, unknown or cross-tenant request ids raise
        :class:`RequestNotFound`; other invalid arguments raise
        :class:`ValueError`.
        """
        tenant_id = _require_nonempty_str(tenant_id, "tenant_id")
        request_id = _require_identifier(request_id)
        claim_token = _require_nonempty_str(claim_token, "claim_token")
        result = _require_nonempty_str(result, "result")
        if result not in _FINISH_RESULTS:
            raise ValueError("result must be completed or failed")
        token_digest = self._digest_claim_token(claim_token)

        with self._write_lock:
            conn = self._connect()
            try:
                try:
                    conn.execute("BEGIN IMMEDIATE")
                    # Look the id up globally: a token minted for another
                    # tenant's claim must answer ClaimConflict ("the
                    # token is not valid for this caller"), even though
                    # the request itself is foreign. A genuinely unknown
                    # id still answers RequestNotFound.
                    row = conn.execute(
                        "SELECT tenant_id, status, created_at, "
                        "lease_expires_at, lease_key "
                        "FROM requests WHERE request_id = ?",
                        (request_id,),
                    ).fetchone()
                    if row is None:
                        conn.execute("ROLLBACK")
                        raise RequestNotFound("request not found")
                    (
                        owner_tenant,
                        current_status,
                        created_at,
                        lease_expires_at,
                        active_digest,
                    ) = row
                    if owner_tenant != tenant_id:
                        # A foreign claim token is invalid for this
                        # caller; never reveal whose claim it was.
                        conn.execute("ROLLBACK")
                        raise ClaimConflict("claim is not active")
                    # The token must match the *current* lease: after an
                    # expiry-driven re-claim the previous token was
                    # released, and a terminal request holds no lease.
                    if (
                        current_status != _STATUS_PROCESSING
                        or not isinstance(active_digest, str)
                        or not hmac.compare_digest(active_digest, token_digest)
                    ):
                        conn.execute("ROLLBACK")
                        raise ClaimConflict("claim is not active")
                    now = _utc_now_rfc3339()
                    if not isinstance(lease_expires_at, str) or lease_expires_at <= now:
                        # Expired tokens are released: the lease may
                        # already have been handed to another worker.
                        conn.execute("ROLLBACK")
                        raise ClaimConflict("claim is not active")
                    attempt = conn.execute(
                        "SELECT attempt_no FROM execution_attempts "
                        "WHERE tenant_id = ? AND request_id = ? AND claim_digest = ? "
                        "AND result IS NULL ORDER BY attempt_no DESC LIMIT 1",
                        (tenant_id, request_id, token_digest),
                    ).fetchone()
                    if attempt is None:
                        conn.execute("ROLLBACK")
                        raise ClaimConflict("claim is not active")
                    attempt_no = attempt[0]
                    pred_seq, pred_at, pred_hash = self._latest_event(
                        conn, tenant_id, request_id
                    )
                    if not self._event_head_is_intact(
                        pred_seq, pred_at, pred_hash
                    ):
                        conn.execute("ROLLBACK")
                        raise _storage_failure()
                    occurred_at = _occurred_at_not_before(pred_at)
                    next_link = _chain_hash(
                        tenant_id,
                        request_id,
                        pred_seq + 1,
                        result,
                        occurred_at,
                        pred_hash,
                    )
                    cursor = conn.execute(
                        "UPDATE requests "
                        "SET status = ?, chain_hash = ?, "
                        "lease_expires_at = NULL, lease_key = NULL "
                        "WHERE tenant_id = ? AND request_id = ? "
                        "AND status = 'processing' AND lease_key = ?",
                        (result, next_link, tenant_id, request_id, token_digest),
                    )
                    if cursor.rowcount != 1:
                        conn.execute("ROLLBACK")
                        raise ClaimConflict("claim is not active")
                    conn.execute(
                        "UPDATE execution_attempts SET result = ?, finished_at = ? "
                        "WHERE tenant_id = ? AND request_id = ? AND attempt_no = ?",
                        (result, now, tenant_id, request_id, attempt_no),
                    )
                    conn.execute(
                        "INSERT INTO status_events ("
                        "tenant_id, request_id, seq, status, occurred_at, chain_hash"
                        ") VALUES (?, ?, ?, ?, ?, ?)",
                        (
                            tenant_id,
                            request_id,
                            pred_seq + 1,
                            result,
                            occurred_at,
                            next_link,
                        ),
                    )
                    conn.execute("COMMIT")
                except ClaimConflict:
                    raise
                except RequestNotFound:
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
            "claim finished request_id=%s result=%s",
            request_id,
            result,
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

        Each entry contains exactly ``attempt_no`` (integer, starting at
        1), ``claimed_at`` and ``lease_expires_at`` (UTC RFC3339), plus
        ``result`` and ``finished_at`` which are ``None`` while the
        attempt is in progress and afterwards carry only the terminal
        result (``completed``/``failed``) and its completion time.
        Neither a worker id nor a claim token is ever present. Invalid,
        unknown and cross-tenant ids raise :class:`RequestNotFound`; a
        bad tenant raises :class:`ValueError`.
        """
        tenant_id = _require_nonempty_str(tenant_id, "tenant_id")
        request_id = _require_identifier(request_id)
        if self._mem_conn is not None:
            with self._write_lock:
                return self._execution_log(tenant_id, request_id)
        return self._execution_log(tenant_id, request_id)

    def _execution_log(
        self, tenant_id: str, request_id: str
    ) -> list[dict[str, object]]:
        conn = self._connect()
        try:
            try:
                # Gate on ownership exactly like audit(): an empty log
                # must not distinguish "missing" from "foreign".
                owner = conn.execute(
                    "SELECT 1 FROM requests WHERE tenant_id = ? AND request_id = ?",
                    (tenant_id, request_id),
                ).fetchone()
                if owner is None:
                    raise RequestNotFound("request not found")
                rows = conn.execute(
                    "SELECT attempt_no, claimed_at, lease_expires_at, "
                    "result, finished_at FROM execution_attempts "
                    "WHERE tenant_id = ? AND request_id = ? ORDER BY attempt_no",
                    (tenant_id, request_id),
                ).fetchall()
            except RequestNotFound:
                raise
            except sqlite3.Error:
                raise _storage_failure() from None
        finally:
            self._release(conn)
        entries: list[dict[str, object]] = []
        for attempt_no, claimed_at, lease_expires_at, result, finished_at in rows:
            # Strict shape checks: corrupted rows must surface as a
            # storage fault, never as half-formed evidence.
            if (
                not isinstance(attempt_no, int)
                or isinstance(attempt_no, bool)
                or not isinstance(claimed_at, str)
                or not isinstance(lease_expires_at, str)
                or not (result is None or isinstance(result, str))
                or not (finished_at is None or isinstance(finished_at, str))
            ):
                raise _storage_failure()
            entries.append(
                {
                    "attempt_no": attempt_no,
                    "claimed_at": claimed_at,
                    "lease_expires_at": lease_expires_at,
                    "result": result,
                    "finished_at": finished_at,
                }
            )
        return entries

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
