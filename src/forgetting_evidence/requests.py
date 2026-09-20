"""SQLite-backed acceptance store for deletion requests.

The store records deletion requests without retaining any identifying
payload in logs, return values beyond the fixed receipt fields, or
exception messages. SQLite integrity conflicts are translated into the
module's own idempotency semantics and never surface to callers.

Every accepted request carries a persistent, append-only status timeline
in ``status_events``. Events are written in the same transaction as the
request row or status change they describe, so the final timeline entry
always matches the request's current status.

Each event additionally seals a persistent hash chain in ``event_chain``
in that same transaction. A link binds the tenant, request id, event
sequence, resulting status and occurrence time together with the
previous link's digest, so the persisted timeline cannot be modified,
reordered, inserted into or transplanted from another request or tenant
without :meth:`RequestStore.verify_evidence` noticing. Verification
recomputes expected digests read-only and never overwrites stored
evidence; the digests, not the chained preimage, are the only chain data
that surfaces.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
import threading
import uuid
from collections.abc import Mapping
from datetime import datetime, timezone
from hmac import compare_digest

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
    created_at      TEXT NOT NULL
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
    PRIMARY KEY (tenant_id, request_id, seq)
);
"""

# One sealed link per status event, written in the same transaction as the
# event it authenticates. Stored digests are the only chain material that
# ever leaves the database: the chained preimage is never persisted as a
# column and never appears in return values, exceptions or logs.
_CHAIN_TABLE = """
CREATE TABLE IF NOT EXISTS event_chain (
    tenant_id  TEXT NOT NULL,
    request_id TEXT NOT NULL,
    seq        INTEGER NOT NULL,
    chain_hash TEXT NOT NULL,
    PRIMARY KEY (tenant_id, request_id, seq)
);
"""

# The composite primary key already indexes (tenant_id, request_id, seq),
# which serves both the ordered timeline read and the latest-event lookup.

_BUSY_TIMEOUT_MS = 30_000
# A UUIDv4 primary-key collision is astronomically unlikely; the bound
# only keeps that conflict distinct from idempotency conflicts.
_MAX_INSERT_ATTEMPTS = 3

# Prefix mixed into every chain preimage so a digest computed here cannot
# be confused with an unrelated SHA-256 of the same fields.
_CHAIN_DOMAIN = "forgetting-evidence/status-chain/v1"

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


def _chain_digest(
    tenant_id: str,
    request_id: str,
    seq: int,
    status: str,
    occurred_at: str,
    prev_hash: str,
) -> str:
    """Return the 64-char lowercase hex SHA-256 link for one event.

    The preimage is a single JSON object with fixed key order. JSON
    string escaping makes the encoding unambiguous without inventing a
    field separator that a tenant- or request-id could collide with.
    The digest binds the tenant, request, sequence, status, occurrence
    time and previous link, so deleting, altering, inserting or swapping
    any event breaks every subsequent link.
    """
    preimage = json.dumps(
        {
            "domain": _CHAIN_DOMAIN,
            "tenant_id": tenant_id,
            "request_id": request_id,
            "seq": seq,
            "status": status,
            "occurred_at": occurred_at,
            "prev_hash": prev_hash,
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(preimage).hexdigest()


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
            conn.execute(_CHAIN_TABLE)
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
                conn.execute("BEGIN IMMEDIATE")
                try:
                    conn.execute(
                        "INSERT INTO requests ("
                        "request_id, tenant_id, idempotency_key, subject_id, "
                        "scopes_json, status, created_at"
                        ") VALUES (?, ?, ?, ?, ?, 'accepted', ?)",
                        (
                            request_id,
                            tenant_id,
                            idempotency_key,
                            subject_id,
                            scopes_json,
                            created_at,
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
                        "tenant_id, request_id, seq, status, occurred_at"
                        ") VALUES (?, ?, 0, 'accepted', ?)",
                        (tenant_id, request_id, created_at),
                    )
                    # Seal the genesis link in that same transaction. The
                    # empty predecessor anchors every per-request chain.
                    genesis_hash = _chain_digest(
                        tenant_id, request_id, 0, "accepted", created_at, ""
                    )
                    conn.execute(
                        "INSERT INTO event_chain ("
                        "tenant_id, request_id, seq, chain_hash"
                        ") VALUES (?, ?, 0, ?)",
                        (tenant_id, request_id, genesis_hash),
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
                    cursor = conn.execute(
                        "UPDATE requests SET status = ? "
                        "WHERE tenant_id = ? AND request_id = ? AND status = ?",
                        (target_status, tenant_id, request_id, current_status),
                    )
                    if cursor.rowcount != 1:
                        # The row vanished or changed under us; refuse rather
                        # than persisting a state that breaks the transition
                        # graph observed at read time.
                        conn.execute("ROLLBACK")
                        raise InvalidStatusTransition("illegal status transition")
                    # The event is appended in the same transaction as the
                    # status update, keyed by the next per-request sequence
                    # number. BEGIN IMMEDIATE serializes writers, so two
                    # transitions can never claim the same seq or read a
                    # stale predecessor.
                    latest = conn.execute(
                        "SELECT seq, occurred_at FROM status_events "
                        "WHERE tenant_id = ? AND request_id = ? "
                        "ORDER BY seq DESC LIMIT 1",
                        (tenant_id, request_id),
                    ).fetchone()
                    if latest is None:
                        # Defensive only: every accepted request owns its
                        # seq-0 event, so reaching here means the timeline
                        # invariant was broken out of band.
                        conn.execute("ROLLBACK")
                        raise RuntimeError("failed to persist status transition")
                    next_seq, latest_occurred_at = latest
                    occurred_at = _occurred_at_not_before(latest_occurred_at)
                    conn.execute(
                        "INSERT INTO status_events ("
                        "tenant_id, request_id, seq, status, occurred_at"
                        ") VALUES (?, ?, ?, ?, ?)",
                        (
                            tenant_id,
                            request_id,
                            next_seq + 1,
                            target_status,
                            occurred_at,
                        ),
                    )
                    # Seal the successor link against the previous one in
                    # the same transaction as the status update. BEGIN
                    # IMMEDIATE serializes writers, so the predecessor read
                    # and the link insert can never interleave with another
                    # transition on the same request.
                    prev_row = conn.execute(
                        "SELECT chain_hash FROM event_chain "
                        "WHERE tenant_id = ? AND request_id = ? AND seq = ?",
                        (tenant_id, request_id, next_seq),
                    ).fetchone()
                    if prev_row is None:
                        # Defensive only: every event owns a link, so this
                        # means the chain invariant was broken out of band.
                        conn.execute("ROLLBACK")
                        raise RuntimeError("failed to persist status transition")
                    link_hash = _chain_digest(
                        tenant_id,
                        request_id,
                        next_seq + 1,
                        target_status,
                        occurred_at,
                        prev_row[0],
                    )
                    conn.execute(
                        "INSERT INTO event_chain ("
                        "tenant_id, request_id, seq, chain_hash"
                        ") VALUES (?, ?, ?, ?)",
                        (tenant_id, request_id, next_seq + 1, link_hash),
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

    def evidence(self, tenant_id: str, request_id: str) -> dict[str, object]:
        """Return the persisted integrity evidence for one request.

        The result contains only ``request_id``, ``status`` (equal to
        :meth:`get`), ``event_count`` (equal to the :meth:`audit`
        timeline length) and ``chain_hash`` (the 64-character lowercase
        hex SHA-256 tip of the persisted audit chain). Unknown ids and
        cross-tenant lookups raise :class:`RequestNotFound` identically.
        """
        tenant_id = _require_nonempty_str(tenant_id, "tenant_id")
        request_id = _require_nonempty_str(request_id, "request_id")
        if self._mem_conn is not None:
            with self._write_lock:
                return self._evidence(tenant_id, request_id)
        return self._evidence(tenant_id, request_id)

    def _evidence(self, tenant_id: str, request_id: str) -> dict[str, object]:
        conn = self._connect()
        try:
            # Gate on ownership exactly like get()/audit() so a missing
            # record and a foreign one are indistinguishable.
            row = conn.execute(
                "SELECT status FROM requests "
                "WHERE tenant_id = ? AND request_id = ?",
                (tenant_id, request_id),
            ).fetchone()
            if row is None:
                raise RequestNotFound("request not found")
            status = row[0]
            event_count = conn.execute(
                "SELECT count(*) FROM status_events "
                "WHERE tenant_id = ? AND request_id = ?",
                (tenant_id, request_id),
            ).fetchone()[0]
            tip = conn.execute(
                "SELECT chain_hash FROM event_chain "
                "WHERE tenant_id = ? AND request_id = ? ORDER BY seq DESC LIMIT 1",
                (tenant_id, request_id),
            ).fetchone()
        finally:
            self._release(conn)
        if tip is None:
            # Every request seals a genesis link in its acceptance
            # transaction, so a missing tip means the store was damaged
            # out of band; surface a generic failure rather than a guess.
            raise RuntimeError("request evidence unavailable")
        return {
            "request_id": request_id,
            "status": status,
            "event_count": event_count,
            "chain_hash": tip[0],
        }

    def verify_evidence(self, tenant_id: str, request_id: str) -> bool:
        """Verify the persisted audit chain for one request, read-only.

        Recomputes every link from the stored ``status_events`` timeline
        and compares it against the persisted ``event_chain`` digests
        without ever recomputing-and-overwriting stored evidence. Returns
        ``True`` only when the sequences are gap-free from zero, every
        stored link matches the link derived from tenant, request, seq,
        status, occurrence time and predecessor, the tip timeline status
        equals the request's current status, and no chain or timeline
        row is missing, duplicated or extra. Deleting, altering,
        inserting or swapping events, or transplanting events or links
        from another request or tenant, yields ``False``. Unknown ids
        and cross-tenant lookups raise :class:`RequestNotFound`.
        """
        tenant_id = _require_nonempty_str(tenant_id, "tenant_id")
        request_id = _require_nonempty_str(request_id, "request_id")
        if self._mem_conn is not None:
            with self._write_lock:
                return self._verify_evidence(tenant_id, request_id)
        return self._verify_evidence(tenant_id, request_id)

    def _verify_evidence(self, tenant_id: str, request_id: str) -> bool:
        conn = self._connect()
        try:
            owner = conn.execute(
                "SELECT status FROM requests "
                "WHERE tenant_id = ? AND request_id = ?",
                (tenant_id, request_id),
            ).fetchone()
            if owner is None:
                raise RequestNotFound("request not found")
            current_status = owner[0]
            events = conn.execute(
                "SELECT seq, status, occurred_at FROM status_events "
                "WHERE tenant_id = ? AND request_id = ? ORDER BY seq",
                (tenant_id, request_id),
            ).fetchall()
            links = conn.execute(
                "SELECT seq, chain_hash FROM event_chain "
                "WHERE tenant_id = ? AND request_id = ? ORDER BY seq",
                (tenant_id, request_id),
            ).fetchall()
        finally:
            self._release(conn)
        return self._chain_intact(
            tenant_id, request_id, current_status, events, links
        )

    @staticmethod
    def _chain_intact(
        tenant_id: str,
        request_id: str,
        current_status: str,
        events: list[tuple[object, object, object]],
        links: list[tuple[object, object]],
    ) -> bool:
        # Pure recomputation: this path never writes, so damaged evidence
        # can never be silently "repaired" into a passing result.
        if not events:
            return False
        event_seqs = [event[0] for event in events]
        if event_seqs != list(range(len(events))):
            # Gap, duplicate or non-zero start: an event was inserted,
            # deleted or reordered.
            return False
        if [link[0] for link in links] != event_seqs:
            # A missing, extra or duplicated link breaks the 1:1 binding.
            return False
        if events[0][1] != _STATUS_ACCEPTED:
            return False
        previous_hash = ""
        for (seq, status, occurred_at), (_, stored_hash) in zip(events, links):
            # Only values with the shapes the writers produce can be
            # authentic; anything else (a corrupted/forged row) simply
            # fails, and compare_digest must not receive non-ASCII text.
            if (
                not isinstance(seq, int)
                or isinstance(seq, bool)
                or not isinstance(status, str)
                or not isinstance(occurred_at, str)
                or not isinstance(stored_hash, str)
                or len(stored_hash) != 64
            ):
                return False
            expected_hash = _chain_digest(
                tenant_id,
                request_id,
                seq,
                status,
                occurred_at,
                previous_hash,
            )
            try:
                # compare_digest avoids short-circuiting on the first
                # unequal character.
                if not compare_digest(expected_hash, stored_hash):
                    return False
            except TypeError:
                # Non-ASCII stored text: cannot be a lowercase hex digest.
                return False
            previous_hash = stored_hash
        # The sealed timeline must end at the authoritative row status;
        # otherwise the request row or the final event was altered.
        return events[-1][1] == current_status
