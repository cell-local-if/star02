"""SQLite-backed acceptance store for deletion requests.

The store records deletion requests without retaining any identifying
payload in logs, return values beyond the fixed receipt fields, or
exception messages. SQLite integrity conflicts are translated into the
module's own idempotency semantics and never surface to callers.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import uuid
from collections.abc import Mapping
from datetime import datetime, timezone

__all__ = ["RequestStore", "IdempotencyConflict", "RequestNotFound"]


class IdempotencyConflict(Exception):
    """Raised when an idempotency key is reused with a different payload."""


class RequestNotFound(Exception):
    """Raised when no request visible to the tenant matches the id."""


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

_BUSY_TIMEOUT_MS = 30_000
# A UUIDv4 primary-key collision is astronomically unlikely; the bound
# only keeps that conflict distinct from idempotency conflicts.
_MAX_INSERT_ATTEMPTS = 3


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
