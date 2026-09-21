"""SQLite-backed acceptance store for deletion requests.

The store records deletion requests without retaining any identifying
payload in logs, return values beyond the fixed receipt fields, or
exception messages. SQLite integrity conflicts are translated into the
module's own idempotency semantics and never surface to callers.

Every accepted request carries a persistent, append-only status timeline
in ``status_events``. Events are written in the same transaction as the
request row or status change they describe, so the final timeline entry
always matches the request's current status.

Two independent integrity layers protect the timeline:

1. An internal, append-only hash chain. Each event carries a
   ``chain_hash``: a SHA-256 value binding the tenant, request, sequence
   number, status, occurrence time and the previous event's hash. The
   hash of the final event is also stored on the request row. This layer
   alone is only tamper-*evident*: an attacker who can rewrite the whole
   SQLite database can recompute every link and head.

2. A protected anchor kept **outside** SQLite (see
   :mod:`forgetting_evidence.anchors`). For every new request and every
   actual status transition, an HMAC of
   ``(tenant_id, request_id, final chain head)`` under a master secret
   that never touches the database is persisted atomically with the
   request/event write. Verification recomputes the whole chain from the
   stored rows and then checks the head against the protected anchor.
   Rewriting, recomputing, reordering or cross-substituting the SQLite
   contents cannot produce a verifying database without the protected
   key.

The hash preimage, the master key and all key-derivation material are
never exposed in return values, exceptions or logs, and are never stored
in SQLite. No anchor state is kept inside SQLite: anything an attacker
can rewrite inside the database file is irrelevant to the final trust
decision.
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
import time
import uuid
from collections.abc import Mapping
from datetime import datetime, timezone

from .anchors import (
    AnchorConfig,
    AnchorError,
    LegacyDataError,
    _AnchorBackend,
)

__all__ = [
    "RequestStore",
    "IdempotencyConflict",
    "RequestNotFound",
    "InvalidStatusTransition",
    "EvidenceNotAnchored",
    "AnchorConfig",
    "AnchorError",
    "LegacyDataError",
]

_log = logging.getLogger(__name__)


class IdempotencyConflict(Exception):
    """Raised when an idempotency key is reused with a different payload."""


class RequestNotFound(Exception):
    """Raised when no request visible to the tenant matches the id."""


class InvalidStatusTransition(Exception):
    """Raised when a requested status change is unknown or not permitted."""


class EvidenceNotAnchored(LegacyDataError):
    """Evidence exists but cannot be tied to protected anchor material.

    Raised (never silently trusted) for rows written by a version that
    did not produce protected anchors, and when the outside-database
    anchor material is missing or unavailable. The message is a fixed
    string: it carries no tenant, request, head or key content.
    """

    def __init__(self) -> None:
        super().__init__("request evidence is not protected by anchored material")


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

# Column probes recognizing database files created before chain hashes
# (and therefore before protected anchoring) existed. Such files are
# never upgraded, backfilled or trusted: their rows predate protected
# anchoring and are reported explicitly. Nothing is recorded in the
# database to remember the result, because any such marker would itself
# be attacker-rewritable.
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


class _AnchorBackendAdapter:
    """Mediate between request transactions and the protected backend.

    The write methods are invoked while the caller holds a database
    ``BEGIN IMMEDIATE`` transaction. The protected journal is replaced
    within that window; verification always re-reads the durable journal,
    so it can never observe a database commit without its anchor (another
    process blocks on the database write lock until both are in place).
    """

    __slots__ = ("_backend", "_rollback_coordinate", "_rollback_mac")

    def __init__(self, db_path: str, cfg: AnchorConfig | None) -> None:
        self._backend = _AnchorBackend(db_path, cfg)
        # Never creates files: a read-only open tolerates an
        # unprovisioned database; protected access fails explicitly
        # later if no material exists.
        self._backend.prepare_for_read()
        self._rollback_coordinate: tuple[str, str] | None = None
        self._rollback_mac: str | None = None

    def create(
        self,
        tenant_id: str,
        request_id: str,
        head: str,
    ) -> None:
        """Anchor a brand-new request's genesis head.

        The durable coordinate must not already be anchored; the unique
        request primary key plus this check prevent anchor reuse.
        """
        existing = self._backend.disk_anchor(tenant_id, request_id)
        if existing is not None:
            raise AnchorError("protected anchor already exists")
        self._backend.commit_anchor(tenant_id, request_id, head, None)
        self._rollback_coordinate = (tenant_id, request_id)
        self._rollback_mac = None

    def advance(
        self,
        tenant_id: str,
        request_id: str,
        previous_head: str,
        new_head: str,
    ) -> None:
        """Advance the protected anchor from ``previous_head``.

        The durable anchor must currently authenticate exactly the head
        the transaction chained from. Otherwise the request was never
        protected, belongs to different protected material, or the
        database was rewritten out of band; in every such case the write
        aborts before the database transaction commits.
        """
        mac = self._backend.disk_anchor(tenant_id, request_id)
        if mac is None:
            raise EvidenceNotAnchored()
        try:
            authenticates = self._backend.verify_mac(
                tenant_id, request_id, previous_head, mac
            )
        except AnchorError:
            raise EvidenceNotAnchored() from None
        if not authenticates:
            raise EvidenceNotAnchored()
        self._backend.commit_anchor(tenant_id, request_id, new_head, mac)
        self._rollback_coordinate = (tenant_id, request_id)
        self._rollback_mac = mac

    def committed(self) -> None:
        """Forget the rollback state after a successful DB commit."""
        self._rollback_coordinate = None
        self._rollback_mac = None

    def restore(self) -> None:
        """Undo this transaction's journal replacement.

        Best effort: used only when the database commit fails *after*
        the anchor journal was replaced, so an ordinary (non-crash)
        failure never leaves the two stores diverged. Only this
        transaction's own coordinate is rewound (re-reading durable
        state first, so other processes' anchors survive). A failed
        restore is deliberately swallowed: an anchor one version ahead
        still fails closed on verification.
        """
        coordinate = self._rollback_coordinate
        if coordinate is not None:
            try:
                self._backend.restore_anchor(
                    coordinate[0], coordinate[1], self._rollback_mac
                )
            except AnchorError:
                pass
        self._rollback_coordinate = None
        self._rollback_mac = None

    def require_anchor(self, tenant_id: str, request_id: str, head: str) -> None:
        """Read-only assertion that the protected anchor vouches for ``head``.

        Raises :class:`EvidenceNotAnchored` when no usable protected
        material exists (missing key/journal, unreadable or malformed
        journal); raises :class:`_AnchorMismatch` when material exists
        but does not authenticate the presented head (the caller turns
        that into a ``False`` verification result).
        """
        try:
            mac = self._backend.disk_anchor(tenant_id, request_id)
        except AnchorError:
            raise EvidenceNotAnchored() from None
        if mac is None:
            raise EvidenceNotAnchored()
        try:
            matches = self._backend.verify_mac(tenant_id, request_id, head, mac)
        except AnchorError:
            # No usable master key (deleted/rotated key file, etc.).
            raise EvidenceNotAnchored() from None
        if not matches:
            raise _AnchorMismatch


class _AnchorMismatch(Exception):
    """Internal: the protected anchor does not authenticate the head."""


class _TransientAnchorWindow(Exception):
    """Internal: journal/DB may momentarily disagree during a commit."""


class RequestStore:
    """Persist and retrieve accepted deletion requests.

    ``RequestStore(db_path)`` works unchanged and transparently
    provisions protected anchor material next to the database file
    (``<db_path>.anchor.key`` and ``<db_path>.anchor``, both mode 0600).
    Copying the database together with those files lets another instance
    continue verifying; copying the database alone never can. Named
    optional configuration is accepted through ``anchor_config`` with an
    :class:`AnchorConfig`.
    """

    def __init__(
        self,
        db_path: str | os.PathLike[str],
        *,
        anchor_config: AnchorConfig | None = None,
    ):
        self._db_path = os.fspath(db_path)
        # In-process serialization; the unique index additionally guards
        # other processes sharing the same database file.
        self._write_lock = threading.Lock()
        self._anchors = _AnchorBackendAdapter(self._db_path, anchor_config)
        if self._db_path == ":memory:":
            self._mem_conn: sqlite3.Connection | None = self._open_connection()
        else:
            self._mem_conn = None
            parent = os.path.dirname(os.path.abspath(self._db_path))
            os.makedirs(parent, exist_ok=True)
        conn = self._connect()
        try:
            # CREATE TABLE IF NOT EXISTS never mutates a database written
            # by an older, unprotected version: existing tables are left
            # exactly as found and the missing chain columns are detected
            # structurally afterwards.
            conn.execute(_SCHEMA)
            conn.execute(_UNIQUE_TENANT_KEY)
            conn.execute(_EVENT_TABLE)
            # A pre-existing file from the unprotected era lacks the
            # chain columns on both tables (CREATE TABLE IF NOT EXISTS
            # above was a no-op for them). A freshly created database
            # has the columns, so the probe is False for new files.
            self._legacy = not (
                bool(conn.execute(_REQUEST_CHAIN_COLUMN).fetchone())
                and bool(conn.execute(_EVENT_CHAIN_COLUMN).fetchone())
            )
        finally:
            self._release(conn)

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

    # ---------------------------------------------------------- submit
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
        # A file from the unprotected era can never accept new protected
        # rows: mixing the two would let legacy rows inherit trust they
        # never earned. No write is attempted; the old audit records are
        # left byte-for-byte intact.
        if self._legacy:
            raise EvidenceNotAnchored()
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
                        # The genesis chain link is written in the same
                        # transaction and its hash anchors the request row.
                        conn.execute(
                            "INSERT INTO status_events ("
                            "tenant_id, request_id, seq, status, occurred_at, chain_hash"
                            ") VALUES (?, ?, 0, 'accepted', ?, ?)",
                            (tenant_id, request_id, created_at, genesis_hash),
                        )
                        # Protected anchor, outside SQLite, bound to the
                        # tenant, request and genesis head, replaced
                        # while the DB write lock is held.
                        self._anchors.create(tenant_id, request_id, genesis_hash)
                    except AnchorError:
                        try:
                            conn.execute("ROLLBACK")
                        except sqlite3.Error:
                            pass
                        self._anchors.restore()
                        raise RuntimeError(
                            "failed to persist protected request evidence"
                        ) from None
                    try:
                        conn.execute("COMMIT")
                    except sqlite3.Error:
                        self._anchors.restore()
                        raise
                    self._anchors.committed()
                except sqlite3.Error:
                    try:
                        conn.execute("ROLLBACK")
                    except sqlite3.Error:
                        pass
                    raise RuntimeError("failed to persist accepted request") from None
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

    # ------------------------------------------------------------- get
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

    # ------------------------------------------------------ transition
    def transition(
        self,
        tenant_id: str,
        request_id: str,
        target_status: str,
    ) -> dict[str, str]:
        """Move a request to ``target_status`` according to the lifecycle.

        Moving a request to the status it already holds is idempotent and
        returns the current receipt without writing. Unknown statuses and
        illegal moves raise :class:`InvalidStatusTransition` without
        writing; unknown or cross-tenant ids raise
        :class:`RequestNotFound`. Every actual move appends an event and
        advances the protected anchor in the same database transaction.
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
                        # Idempotent replay: nothing to persist; in
                        # particular no anchor material may change.
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
                    if self._legacy:
                        # Do not extend an unprotected chain: the record
                        # predates anchoring and must stay untouched.
                        conn.execute("ROLLBACK")
                        raise EvidenceNotAnchored()
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
                    # status update; the protected anchor over the new head
                    # is advanced in the same window. Either all three
                    # commit or none do.
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
                        self._anchors.advance(
                            tenant_id,
                            request_id,
                            predecessor_hash,
                            next_link_hash,
                        )
                    except EvidenceNotAnchored:
                        # Raised before any journal replacement: nothing
                        # to restore.
                        conn.execute("ROLLBACK")
                        raise
                    except AnchorError:
                        conn.execute("ROLLBACK")
                        self._anchors.restore()
                        raise RuntimeError(
                            "failed to persist protected status evidence"
                        ) from None
                    try:
                        conn.execute("COMMIT")
                    except sqlite3.Error:
                        self._anchors.restore()
                        raise
                    self._anchors.committed()
                except InvalidStatusTransition:
                    raise
                except RequestNotFound:
                    raise
                except EvidenceNotAnchored:
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

    # ----------------------------------------------------------- audit
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

    # -------------------------------------------------------- evidence
    def evidence(
        self,
        tenant_id: str,
        request_id: str,
    ) -> dict[str, object]:
        """Return the persisted integrity evidence for a request.

        The result contains exactly ``request_id``, ``status`` (identical
        to :meth:`get`), ``event_count`` (identical to the length of
        :meth:`audit`) and ``chain_hash`` (the SHA-256 head of the audit
        chain as persisted, never recomputed). No protected key material
        or anchor value is ever included.

        Rows from the unprotected era raise
        :class:`EvidenceNotAnchored`. Unknown ids and cross-tenant
        lookups raise :class:`RequestNotFound`; non-string or empty
        arguments raise :class:`ValueError`.
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
        if self._legacy and not _is_chain_hash(head_hash):
            raise EvidenceNotAnchored()
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

    # ------------------------------------------------- verify_evidence
    def verify_evidence(self, tenant_id: str, request_id: str) -> bool:
        """Verify a request's audit chain against its protected anchor.

        Verification is strictly read-only: it never repairs, backfills
        or rewrites anything. Every link is recomputed from the stored
        rows, sequences must be gap-free from zero, the final link must
        equal the head stored on the request row and match the current
        status, and that head must match the HMAC held in the protected,
        outside-database material for exactly this
        ``(tenant, request)``.

        Deleting, altering, inserting, reordering or cross-request /
        cross-tenant substituting events, tampering with the request
        head, or recomputing and replacing *all* SQLite contents —
        including any anchor-like columns an attacker might add inside
        the database — all return ``False``.

        Records from the unprotected era, or requests whose protected
        material is missing, raise :class:`EvidenceNotAnchored`: an
        explicit, fixed-message result instead of silent trust. Unknown
        ids and cross-tenant lookups raise :class:`RequestNotFound`;
        non-string or empty arguments raise :class:`ValueError`.
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
        # A committing writer first replaces the protected journal and
        # then commits SQLite while still holding the database write
        # lock. A concurrent reader can therefore briefly observe the
        # *new* anchor against the *old* database view. A few bounded
        # re-reads bridge exactly that window (including back-to-back
        # commits by other writers); genuinely tampered data mismatches
        # on every read and returns False. Clean, quiescent verification
        # pays no retry cost.
        transient = 0
        while True:
            try:
                return self._verify_evidence_once(tenant_id, request_id)
            except _TransientAnchorWindow:
                transient += 1
                if transient > 2:
                    return False
                time.sleep(0.025 if transient == 1 else 0.075)

    def _verify_evidence_once(
        self, tenant_id: str, request_id: str
    ) -> bool:
        conn = self._connect()
        try:
            # Gate on the request row exactly like audit(): an empty
            # timeline must not distinguish "missing" from "foreign".
            try:
                if self._legacy:
                    # Even confirming the row's existence uses only the
                    # old columns; the chain columns do not exist here.
                    owner = conn.execute(
                        "SELECT 1 FROM requests "
                        "WHERE tenant_id = ? AND request_id = ?",
                        (tenant_id, request_id),
                    ).fetchone()
                    if owner is None:
                        raise RequestNotFound("request not found")
                    raise EvidenceNotAnchored()
                owner = conn.execute(
                    "SELECT status, chain_hash FROM requests "
                    "WHERE tenant_id = ? AND request_id = ?",
                    (tenant_id, request_id),
                ).fetchone()
                if owner is None:
                    raise RequestNotFound("request not found")
                current_status, anchored_head = owner
                if not _is_chain_hash(anchored_head):
                    # A non-null, malformed head on a protected-era table
                    # is out-of-band tampering, not a legacy record.
                    return False
                rows = conn.execute(
                    "SELECT seq, status, occurred_at, chain_hash "
                    "FROM status_events "
                    "WHERE tenant_id = ? AND request_id = ? ORDER BY seq",
                    (tenant_id, request_id),
                ).fetchall()
            except RequestNotFound:
                raise
            except EvidenceNotAnchored:
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
        if rows[-1][1] != current_status:
            return False

        # Decisive check: the head must be vouched for by protected
        # material OUTSIDE the database, bound to exactly this tenant and
        # request. An attacker who rewrites and rehashes every SQLite row
        # cannot forge this HMAC without the master key. A mismatch is
        # retried once by the caller because it is also, for a few
        # milliseconds, the observable signature of a concurrent writer
        # between its journal replacement and its database commit.
        try:
            self._anchors.require_anchor(tenant_id, request_id, anchored_head)
        except EvidenceNotAnchored:
            raise
        except _AnchorMismatch:
            raise _TransientAnchorWindow
        return True

    # ---------------------------------------------------- shared reads
    def _load_chain_head(
        self, tenant_id: str, request_id: str
    ) -> tuple[str, str, int]:
        conn = self._connect()
        try:
            try:
                if self._legacy:
                    row = conn.execute(
                        "SELECT r.status, "
                        "(SELECT count(*) FROM status_events e "
                        " WHERE e.tenant_id = r.tenant_id "
                        "   AND e.request_id = r.request_id) "
                        "FROM requests r WHERE r.tenant_id = ? AND r.request_id = ?",
                        (tenant_id, request_id),
                    ).fetchone()
                    if row is None:
                        raise RequestNotFound("request not found")
                    return row[0], None, row[1]
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
