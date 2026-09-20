"""SQLite-backed acceptance store for deletion requests.

The store records deletion requests without retaining any identifying
payload in logs, return values beyond the fixed receipt fields, or
exception messages. SQLite integrity conflicts are translated into the
module's own idempotency semantics and never surface to callers.

Every accepted request carries a persistent, append-only status timeline
in ``status_events``. Events are written in the same transaction as the
request row or status change they describe, so the final timeline entry
always matches the request's current status.

Tamper evidence is keyed, not merely hash-chained:

* Each event carries an HMAC-SHA256 ``chain_hash`` over the tenant,
  request, per-request sequence number, status, occurrence time and the
  predecessor link. The MAC key is derived from a protected integrity
  secret that is never stored in the SQLite database.
* The request row carries an ``anchor_token``: a verifiable anchor
  produced by an :class:`IntegrityAnchor` implementation, binding the
  chain head together with the tenant, request, current status and event
  count. The default anchor uses a second key derived from the same
  protected secret; deployments may inject an external anchor (KMS,
  signing service, timestamp authority, ...).

Because neither the keys nor any forgeable anchor state live in the
database, an attacker who can rewrite the database cannot recompute a
verifiable timeline: recomputing the links and re-anchoring the head
requires the protected key or the external anchor. Rebuilding a
:class:`RequestStore` against the same database keeps verifying as long
as the same key material is available (by default a ``0600`` key file
kept next to the database).

Databases written by older, unkeyed versions are never silently trusted:
their rows carry no anchor, :meth:`evidence` and
:meth:`verify_evidence` report them explicitly as unprotected, and the
schema upgrade never overwrites or backfills existing audit records.
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
from typing import Protocol, runtime_checkable

__all__ = [
    "RequestStore",
    "IdempotencyConflict",
    "RequestNotFound",
    "InvalidStatusTransition",
    "UnprotectedEvidenceError",
    "IntegrityAnchor",
]

_log = logging.getLogger(__name__)

# Environment overrides for key material. Explicit constructor arguments
# take precedence over these.
_ENV_KEY_FILE = "FORGETTING_EVIDENCE_INTEGRITY_KEY_FILE"
_ENV_KEY = "FORGETTING_EVIDENCE_INTEGRITY_KEY"

# Suffix of the default, protected sidecar key file placed next to the
# database file. The file is created owner-only (0600) and never written
# into the SQLite database, receipts, exceptions or logs.
_DEFAULT_KEY_SUFFIX = ".integrity.key"

# Domain-separation labels for the two keys derived from the master
# secret. They never meet the same message construction, so an event link
# can never be mistaken for (or reused as) an anchor token.
_KDF_DOMAIN = b"forgetting-evidence/v1"
_EVENT_KEY_LABEL = b"event-mac"
_ANCHOR_KEY_LABEL = b"anchor-mac"
_ANCHOR_MESSAGE_LABEL = b"request-anchor"

# Cap for anchor tokens produced by external implementations. Protects
# storage and verification from unbounded opaque values.
_MAX_ANCHOR_TOKEN_LEN = 1024


class IdempotencyConflict(Exception):
    """Raised when an idempotency key is reused with a different payload."""


class RequestNotFound(Exception):
    """Raised when no request visible to the tenant matches the id."""


class InvalidStatusTransition(Exception):
    """Raised when a requested status change is unknown or not permitted."""


class UnprotectedEvidenceError(Exception):
    """Raised for legacy records that carry no keyed integrity evidence.

    This is distinct from a verification failure (``verify_evidence``
    returning ``False``), which means protected evidence was altered. A
    record raising this error was never keyed, so no claim about its
    authenticity can be made; the error text deliberately carries no
    record data.
    """


@runtime_checkable
class IntegrityAnchor(Protocol):
    """External integrity anchor for request chain heads.

    Implementations bind a chain head to an authoritative context
    (current status, event count, tenant and request) and verify that
    binding later. Implementations must be safe to call concurrently and
    must never include secret key material in the returned token.
    """

    def anchor(
        self,
        *,
        tenant_id: str,
        request_id: str,
        status: str,
        event_count: int,
        head_hash: str,
    ) -> str:
        """Return an opaque, verifiable token for the described head."""
        ...

    def verify(
        self,
        *,
        tenant_id: str,
        request_id: str,
        status: str,
        event_count: int,
        head_hash: str,
        token: str,
    ) -> bool:
        """Return whether ``token`` authenticates the described head."""
        ...


_SCHEMA = """
CREATE TABLE IF NOT EXISTS requests (
    request_id      TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    subject_id      TEXT NOT NULL,
    scopes_json     TEXT NOT NULL,
    status          TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    chain_hash      TEXT NOT NULL,
    anchor_token    TEXT NOT NULL
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

# Column probes used to recognise database files created by older
# versions. The upgrade is purely additive (nullable columns) and never
# backfills or overwrites evidence: legacy rows keep NULL evidence and
# are reported as unprotected rather than silently trusted.
_REQUEST_CHAIN_COLUMN = (
    "SELECT 1 FROM pragma_table_info('requests') WHERE name = 'chain_hash'"
)
_REQUEST_ANCHOR_COLUMN = (
    "SELECT 1 FROM pragma_table_info('requests') WHERE name = 'anchor_token'"
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


def _derive_key(master_secret: bytes, label: bytes) -> bytes:
    """Derive a domain-specific HMAC key from the protected master secret."""
    return hmac.new(
        master_secret, _KDF_DOMAIN + b"/" + label, hashlib.sha256
    ).digest()


def _feed_length_prefixed(mac: "hmac.HMAC", fields: tuple[str, ...]) -> None:
    # Every field is length-prefixed so no concatenation can be re-parsed
    # two ways, and UTF-8 encoding is fixed so stored text round-trips
    # byte-for-byte. The preimage itself is never persisted or returned.
    for field in fields:
        encoded = field.encode("utf-8")
        mac.update(struct.pack(">Q", len(encoded)))
        mac.update(encoded)


def _event_digest(
    event_key: bytes,
    tenant_id: str,
    request_id: str,
    seq: int,
    status: str,
    occurred_at: str,
    predecessor: str,
) -> str:
    """MAC one audit-chain link with the protected event key.

    The digest binds the tenant, request, per-request event sequence,
    status and occurrence time together with the preceding link's hash.
    It cannot be recomputed from database contents alone because the key
    lives outside the database.
    """
    mac = hmac.new(event_key, digestmod=hashlib.sha256)
    _feed_length_prefixed(
        mac,
        (tenant_id, request_id, str(seq), status, occurred_at, predecessor),
    )
    return mac.hexdigest()


def _is_chain_hash(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in _HEX for char in value)
    )


def _is_anchor_token(value: object) -> bool:
    # Tokens are opaque strings; bound the size so a tampered row cannot
    # smuggle an unbored value into the anchor verification call.
    return isinstance(value, str) and 0 < len(value) <= _MAX_ANCHOR_TOKEN_LEN


class _KeyedAnchor:
    """Default anchor: a keyed HMAC binding the head to request context."""

    def __init__(self, anchor_key: bytes) -> None:
        self._key = anchor_key

    def _token(
        self,
        tenant_id: str,
        request_id: str,
        status: str,
        event_count: int,
        head_hash: str,
    ) -> str:
        mac = hmac.new(self._key, digestmod=hashlib.sha256)
        mac.update(struct.pack(">Q", len(_ANCHOR_MESSAGE_LABEL)))
        mac.update(_ANCHOR_MESSAGE_LABEL)
        _feed_length_prefixed(
            mac,
            (tenant_id, request_id, status, str(event_count), head_hash),
        )
        return mac.hexdigest()

    def anchor(
        self,
        *,
        tenant_id: str,
        request_id: str,
        status: str,
        event_count: int,
        head_hash: str,
    ) -> str:
        return self._token(
            tenant_id, request_id, status, event_count, head_hash
        )

    def verify(
        self,
        *,
        tenant_id: str,
        request_id: str,
        status: str,
        event_count: int,
        head_hash: str,
        token: str,
    ) -> bool:
        expected = self._token(
            tenant_id, request_id, status, event_count, head_hash
        )
        return hmac.compare_digest(expected, token)


class RequestStore:
    """Persist and retrieve accepted deletion requests.

    Integrity key resolution, in order of precedence:

    1. ``integrity_key`` (raw key bytes/text) or ``integrity_key_file``
       (path to a file containing the raw key);
    2. the ``FORGETTING_EVIDENCE_INTEGRITY_KEY_FILE`` /
       ``FORGETTING_EVIDENCE_INTEGRITY_KEY`` environment variables;
    3. a default owner-only sidecar file (``<database>.integrity.key``)
       created next to a file-backed database, so a rebuilt store keeps
       verifying the same database without any operator configuration.

    An explicit ``anchor`` may replace the built-in keyed anchor with an
    external anchoring implementation. Key material is held only in
    process memory (and, by default, the protected sidecar file): it is
    never written into the SQLite database, receipts, exceptions or
    logs.
    """

    def __init__(
        self,
        db_path: str | os.PathLike[str],
        *,
        integrity_key: str | bytes | None = None,
        integrity_key_file: str | os.PathLike[str] | None = None,
        anchor: IntegrityAnchor | None = None,
    ):
        self._db_path = os.fspath(db_path)
        # In-process serialization; the unique index additionally guards
        # other processes sharing the same database file.
        self._write_lock = threading.Lock()
        if self._db_path == ":memory:":
            self._mem_conn: sqlite3.Connection | None = self._open_connection()
            self._master_secret = self._resolve_master_secret(
                integrity_key, integrity_key_file, key_file_path=None
            )
        else:
            self._mem_conn = None
            parent = os.path.dirname(os.path.abspath(self._db_path))
            os.makedirs(parent, exist_ok=True)
            self._master_secret = self._resolve_master_secret(
                integrity_key,
                integrity_key_file,
                key_file_path=self._db_path + _DEFAULT_KEY_SUFFIX,
            )
        # Independent derived keys: event links and head anchors must not
        # be interchangeable.
        self._event_key = _derive_key(self._master_secret, _EVENT_KEY_LABEL)
        self._anchor: IntegrityAnchor = (
            anchor
            if anchor is not None
            else _KeyedAnchor(_derive_key(self._master_secret, _ANCHOR_KEY_LABEL))
        )
        # Drop the master secret reference; only the derived keys remain.
        self._master_secret = b""
        conn = self._connect()
        try:
            conn.execute(_SCHEMA)
            conn.execute(_UNIQUE_TENANT_KEY)
            conn.execute(_EVENT_TABLE)
            self._migrate_schema(conn)
        finally:
            self._release(conn)

    @staticmethod
    def _read_key_file(path: str) -> bytes:
        try:
            with open(path, "rb") as handle:
                raw = handle.read()
        except OSError:
            raise RuntimeError("failed to initialize request store") from None
        # Tolerate the trailing newline added by common editors/shells,
        # but never mutate other key bytes.
        raw = raw.rstrip(b"\r\n")
        if not raw:
            raise RuntimeError("failed to initialize request store")
        return raw

    @staticmethod
    def _create_default_key_file(path: str) -> bytes:
        """Create an owner-only key sidecar, or read an existing one.

        Creation is exclusive so two processes opening a fresh database
        cannot end up with different keys; whichever process loses the
        race reads the winner's key.
        """
        secret = os.urandom(32)
        try:
            descriptor = os.open(
                path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
        except FileExistsError:
            return RequestStore._read_key_file(path)
        except OSError:
            raise RuntimeError("failed to initialize request store") from None
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(secret)
                handle.flush()
                try:
                    os.fsync(handle.fileno())
                except OSError:
                    pass
        except OSError:
            raise RuntimeError("failed to initialize request store") from None
        # Best-effort enforcement of owner-only access.
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return secret

    def _resolve_master_secret(
        self,
        integrity_key: str | bytes | None,
        integrity_key_file: str | os.PathLike[str] | None,
        key_file_path: str | None,
    ) -> bytes:
        if integrity_key is not None:
            if isinstance(integrity_key, str):
                raw = integrity_key.encode("utf-8")
            elif isinstance(integrity_key, bytes):
                raw = integrity_key
            else:
                raise ValueError("integrity_key must be str or bytes")
            if not raw:
                raise ValueError("integrity_key must not be empty")
            return raw
        if integrity_key_file is not None:
            return self._read_key_file(os.fspath(integrity_key_file))
        env_file = os.environ.get(_ENV_KEY_FILE)
        if env_file:
            return self._read_key_file(env_file)
        env_key = os.environ.get(_ENV_KEY)
        if env_key:
            raw = env_key.encode("utf-8")
            if not raw:
                raise RuntimeError("failed to initialize request store")
            return raw
        if key_file_path is not None:
            return self._create_default_key_file(key_file_path)
        # In-memory databases have no durable location for a sidecar; use
        # an ephemeral secret so evidence remains keyed within the
        # process, without ever persisting key material.
        return os.urandom(32)

    def _migrate_schema(self, conn: sqlite3.Connection) -> None:
        """Add evidence columns to a database written by an older version.

        The upgrade is additive only: missing columns are added as
        nullable and every existing row keeps NULL evidence. Nothing is
        backfilled, recomputed or overwritten, so legacy audit records
        remain byte-for-byte intact and are reported as unprotected
        instead of being silently trusted.
        """
        if (
            conn.execute(_REQUEST_CHAIN_COLUMN).fetchone()
            and conn.execute(_REQUEST_ANCHOR_COLUMN).fetchone()
            and conn.execute(_EVENT_CHAIN_COLUMN).fetchone()
        ):
            return
        with self._write_lock:
            try:
                conn.execute("BEGIN IMMEDIATE")
                # Re-probe inside the transaction: another process may
                # have completed the upgrade while we waited on the lock.
                if not conn.execute(_REQUEST_CHAIN_COLUMN).fetchone():
                    conn.execute("ALTER TABLE requests ADD COLUMN chain_hash TEXT")
                if not conn.execute(_REQUEST_ANCHOR_COLUMN).fetchone():
                    conn.execute("ALTER TABLE requests ADD COLUMN anchor_token TEXT")
                if not conn.execute(_EVENT_CHAIN_COLUMN).fetchone():
                    conn.execute(
                        "ALTER TABLE status_events ADD COLUMN chain_hash TEXT"
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

    def _anchor_head(
        self,
        tenant_id: str,
        request_id: str,
        status: str,
        event_count: int,
        head_hash: str,
    ) -> str:
        try:
            token = self._anchor.anchor(
                tenant_id=tenant_id,
                request_id=request_id,
                status=status,
                event_count=event_count,
                head_hash=head_hash,
            )
        except Exception:
            # Never surface an external anchor's error text.
            raise RuntimeError("failed to persist request evidence") from None
        if not _is_anchor_token(token):
            raise RuntimeError("failed to persist request evidence")
        return token

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
                conn.execute("BEGIN IMMEDIATE")
                try:
                    # Resolve idempotency inside the write transaction:
                    # BEGIN IMMEDIATE serializes writers, so a replay sees
                    # the winner's committed row and returns its receipt
                    # without ever touching the anchor, while a genuine
                    # insert is the only path that mints an anchor.
                    existing = conn.execute(
                        "SELECT request_id, status, created_at, subject_id, "
                        "scopes_json FROM requests "
                        "WHERE tenant_id = ? AND idempotency_key = ?",
                        (tenant_id, idempotency_key),
                    ).fetchone()
                    if existing is not None:
                        conn.execute("ROLLBACK")
                        return self._idempotent_receipt(
                            existing, subject_id, scope_list
                        )
                    request_id = str(uuid.uuid4())
                    created_at = _utc_now_rfc3339()
                    genesis_hash = _event_digest(
                        self._event_key,
                        tenant_id,
                        request_id,
                        0,
                        _STATUS_ACCEPTED,
                        created_at,
                        _GENESIS_PREDECESSOR,
                    )
                    # Only a genuinely new request reaches the anchor: a
                    # replay or a rejected payload returns above, so no
                    # external anchor state is ever produced for them.
                    anchor_token = self._anchor_head(
                        tenant_id,
                        request_id,
                        _STATUS_ACCEPTED,
                        1,
                        genesis_hash,
                    )
                    try:
                        conn.execute(
                            "INSERT INTO requests ("
                            "request_id, tenant_id, idempotency_key, subject_id, "
                            "scopes_json, status, created_at, chain_hash, "
                            "anchor_token"
                            ") VALUES (?, ?, ?, ?, ?, 'accepted', ?, ?, ?)",
                            (
                                request_id,
                                tenant_id,
                                idempotency_key,
                                subject_id,
                                scopes_json,
                                created_at,
                                genesis_hash,
                                anchor_token,
                            ),
                        )
                    except sqlite3.IntegrityError:
                        # Astronomically unlikely UUIDv4 primary-key
                        # collision (the idempotency index was probed
                        # above): retry with a freshly generated id.
                        conn.execute("ROLLBACK")
                        continue
                    # The first timeline entry shares the acceptance
                    # transaction: a request can never exist without its
                    # accepted event, nor an event without its request, and
                    # the genesis link plus its head anchor are committed
                    # atomically with both.
                    conn.execute(
                        "INSERT INTO status_events ("
                        "tenant_id, request_id, seq, status, occurred_at, chain_hash"
                        ") VALUES (?, ?, 0, 'accepted', ?, ?)",
                        (tenant_id, request_id, created_at, genesis_hash),
                    )
                except RuntimeError:
                    # The external anchor refused/failed; close the open
                    # transaction and surface the already-generic error.
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

    @staticmethod
    def _idempotent_receipt(
        existing: tuple[str, str, str, str, str],
        subject_id: str,
        scope_list: list[str],
    ) -> dict[str, str]:
        existing_request_id, status, created_at, existing_subject, existing_scopes_json = existing
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
        cross-tenant ids raise :class:`RequestNotFound`. Extending a
        legacy, unprotected record raises
        :class:`UnprotectedEvidenceError` without writing: unkeyed
        timelines can never gain protection retroactively.
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
                        "SELECT status, created_at, chain_hash, anchor_token "
                        "FROM requests "
                        "WHERE tenant_id = ? AND request_id = ?",
                        (tenant_id, request_id),
                    ).fetchone()
                    if row is None:
                        # Same outcome for unknown ids and cross-tenant lookups.
                        conn.execute("ROLLBACK")
                        raise RequestNotFound("request not found")
                    current_status, created_at, head_hash, anchor_token = row
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
                    # A legacy (or stripped) row cannot be extended into a
                    # verifiable chain; refuse rather than appending a
                    # keyed link onto an unprotected predecessor.
                    if not _is_chain_hash(head_hash) or not _is_anchor_token(
                        anchor_token
                    ):
                        conn.execute("ROLLBACK")
                        raise UnprotectedEvidenceError(
                            "request evidence is not protected"
                        )
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
                        # Defensive only: every protected request owns its
                        # seq-0 event with a valid link, so reaching here
                        # means the timeline invariant was broken out of
                        # band. Never fabricate a replacement link.
                        conn.execute("ROLLBACK")
                        raise RuntimeError("failed to persist status transition")
                    next_seq, latest_occurred_at, predecessor_hash = latest
                    occurred_at = _occurred_at_not_before(latest_occurred_at)
                    next_link_hash = _event_digest(
                        self._event_key,
                        tenant_id,
                        request_id,
                        next_seq + 1,
                        target_status,
                        occurred_at,
                        predecessor_hash,
                    )
                    next_anchor = self._anchor_head(
                        tenant_id,
                        request_id,
                        target_status,
                        next_seq + 2,
                        next_link_hash,
                    )
                    cursor = conn.execute(
                        "UPDATE requests SET status = ?, chain_hash = ?, "
                        "anchor_token = ? "
                        "WHERE tenant_id = ? AND request_id = ? AND status = ?",
                        (
                            target_status,
                            next_link_hash,
                            next_anchor,
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
                except UnprotectedEvidenceError:
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
        :meth:`audit`) and ``chain_hash`` (the keyed head of the audit
        chain as persisted, never recomputed). The persisted anchor that
        binds the head is verified by :meth:`verify_evidence` but is not
        part of the receipt. Unknown ids and cross-tenant lookups raise
        :class:`RequestNotFound`; non-string or empty arguments raise
        :class:`ValueError`; legacy records that were never keyed raise
        :class:`UnprotectedEvidenceError`.
        """
        tenant_id = _require_nonempty_str(tenant_id, "tenant_id")
        request_id = _require_nonempty_str(request_id, "request_id")
        if self._mem_conn is not None:
            with self._write_lock:
                return self._evidence(tenant_id, request_id)
        return self._evidence(tenant_id, request_id)

    def _evidence(self, tenant_id: str, request_id: str) -> dict[str, object]:
        status, head_hash, anchor_token, event_count = self._load_chain_head(
            tenant_id, request_id
        )
        # A NULL head/anchor is a legacy record that was never keyed; it
        # must not be presented as evidence at all.
        if head_hash is None or anchor_token is None:
            raise UnprotectedEvidenceError("request evidence is not protected")
        # A malformed head means the row was altered out of band and must
        # not be reported as evidence (mirrors the unkeyed behaviour).
        if not _is_chain_hash(head_hash):
            raise RequestNotFound("request not found")
        return {
            "request_id": request_id,
            "status": status,
            "event_count": event_count,
            "chain_hash": head_hash,
        }

    def verify_evidence(self, tenant_id: str, request_id: str) -> bool:
        """Verify the persisted, keyed audit chain for a request.

        Every link is checked against the stored rows using the protected
        event key; the head is then checked against the persisted anchor.
        Verification only reads persisted evidence: it never repairs,
        backfills or rewrites anything. Deleting, altering, inserting or
        reordering events, tampering with the request head or status,
        substituting events from another request or tenant, or fully
        recomputing the events/head/anchor from the database contents all
        yield ``False`` -- forging a valid result requires the protected
        key (or the external anchor's secret), which is not in the
        database.

        Returns ``True`` only when every link recomputes under the key
        from the genesis predecessor, the sequences are gap-free from
        zero, the final link matches the anchored head and current status,
        and the anchor token validates the head, status and event count.
        Unknown ids and cross-tenant lookups raise
        :class:`RequestNotFound`; non-string or empty arguments raise
        :class:`ValueError`; legacy records that predate keying raise
        :class:`UnprotectedEvidenceError`.
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
                    "SELECT status, chain_hash, anchor_token FROM requests "
                    "WHERE tenant_id = ? AND request_id = ?",
                    (tenant_id, request_id),
                ).fetchone()
                if owner is None:
                    raise RequestNotFound("request not found")
                current_status, anchored_head, anchored_token = owner
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

        # Legacy rows carry no keyed evidence. This is not a tamper
        # verdict (False) but an explicit "never protected" result, and
        # it is checked before any link processing.
        if anchored_head is None or anchored_token is None:
            raise UnprotectedEvidenceError("request evidence is not protected")
        if not _is_chain_hash(anchored_head) or not _is_anchor_token(anchored_token):
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
            recomputed = _event_digest(
                self._event_key,
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
        if rows[-1][1] != current_status:
            return False

        # Finally, the external/keyed anchor must authenticate the head
        # together with the exact persisted context. A database-only
        # attacker can recompute links only without the key, and cannot
        # mint this token. Any failure (including a misbehaving external
        # anchor) is a negative verdict, never an exception leak.
        try:
            return bool(
                self._anchor.verify(
                    tenant_id=tenant_id,
                    request_id=request_id,
                    status=current_status,
                    event_count=len(rows),
                    head_hash=anchored_head,
                    token=anchored_token,
                )
            )
        except Exception:
            return False

    def _load_chain_head(
        self, tenant_id: str, request_id: str
    ) -> tuple[str, str | None, str | None, int]:
        conn = self._connect()
        try:
            try:
                row = conn.execute(
                    "SELECT r.status, r.chain_hash, r.anchor_token, "
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
        return row[0], row[1], row[2], row[3]
