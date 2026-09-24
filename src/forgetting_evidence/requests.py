"""SQLite-backed acceptance store for deletion requests.

The store records deletion requests without retaining any identifying
payload in logs, return values beyond the fixed receipt fields, or
exception messages. SQLite integrity conflicts are translated into the
module's own idempotency semantics and never surface to callers; neither
do SQLite lock errors or raw engine text, file paths, tenants, subjects
or idempotency keys. Only request ids, statuses and acceptance times may
appear in receipts, exceptions or logs.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import uuid
from collections.abc import Mapping
from datetime import datetime, timezone

__all__ = ["RequestStore", "IdempotencyConflict", "RequestNotFound"]

_log = logging.getLogger(__name__)


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

# Fixed, payload-free messages. They deliberately never embed caller
# input, database engine text or filesystem paths.
_DB_INIT_ERROR = "failed to initialize request store"
_DB_WRITE_ERROR = "failed to persist accepted request"
_DB_READ_ERROR = "failed to read accepted request"
_NOT_FOUND_MESSAGE = "request not found"
_CONFLICT_MESSAGE = "idempotency key was already submitted with a different payload"
_SCOPES_MESSAGE = "scopes must be a non-empty sequence of distinct non-empty strings"


def _require_nonempty_str(value: object, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _normalize_scopes(scopes: object) -> list[str]:
    # Strings, bytes and mappings are iterable but are not scope sequences.
    if isinstance(scopes, (str, bytes)) or isinstance(scopes, Mapping):
        raise ValueError(_SCOPES_MESSAGE)
    try:
        items = list(scopes)  # type: ignore[arg-type]
    except TypeError as exc:
        raise ValueError(_SCOPES_MESSAGE) from exc
    # Every element must be a non-empty string, and the elements must be
    # pairwise distinct.
    if (
        not items
        or not all(isinstance(item, str) and item for item in items)
        or len(set(items)) != len(items)
    ):
        raise ValueError(_SCOPES_MESSAGE)
    # Canonical order so scope ordering never affects comparison.
    return sorted(items)


def _utc_now_rfc3339() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _is_valid_db_path(db_path: object) -> bool:
    if not isinstance(db_path, str):
        return False
    if not db_path:
        return False
    return True


class RequestStore:
    """Persist and retrieve accepted deletion requests."""

    def __init__(self, db_path: str):
        # The path participates in no error message, receipt or log: it is
        # internal and must never reach callers.
        if not _is_valid_db_path(db_path):
            raise ValueError("db_path must be a non-empty string")
        self._db_path = db_path
        # In-process serialization; the unique index additionally guards
        # other processes sharing the same database file.
        self._write_lock = threading.Lock()
        if self._db_path == ":memory:":
            self._mem_conn: sqlite3.Connection | None = self._open_connection()
        else:
            self._mem_conn = None
            parent = os.path.dirname(os.path.abspath(self._db_path))
            try:
                os.makedirs(parent, exist_ok=True)
            except OSError:
                raise OSError(_DB_INIT_ERROR) from None
        conn = self._connect()
        try:
            try:
                conn.execute(_SCHEMA)
                conn.execute(_UNIQUE_TENANT_KEY)
            except sqlite3.Error:
                # Covers an unwritable location or a corrupt/incompatible
                # database file; engine text must never leak.
                raise OSError(_DB_INIT_ERROR) from None
        finally:
            self._release(conn)

    def _open_connection(self) -> sqlite3.Connection:
        try:
            conn = sqlite3.connect(
                self._db_path,
                timeout=_BUSY_TIMEOUT_MS / 1000,
                check_same_thread=False,
            )
        except sqlite3.Error:
            raise OSError(_DB_INIT_ERROR) from None
        conn.isolation_level = None  # explicit transaction control
        try:
            conn.execute(f"PRAGMA busy_timeout = {_BUSY_TIMEOUT_MS}")
        except sqlite3.Error:
            conn.close()
            raise OSError(_DB_INIT_ERROR) from None
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
                try:
                    conn.execute("BEGIN IMMEDIATE")
                except sqlite3.Error:
                    # Lock contention or engine failure: never surface the
                    # database's own error, and never after a write attempt.
                    raise OSError(_DB_WRITE_ERROR) from None
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
                    self._rollback(conn)
                    try:
                        return self._load_idempotent(
                            conn, tenant_id, idempotency_key, subject_id, scope_list
                        )
                    except _PrimaryKeyConflict:
                        # Collision was on request_id; retry with a new UUID.
                        continue
                except sqlite3.Error:
                    self._rollback(conn)
                    raise OSError(_DB_WRITE_ERROR) from None
                try:
                    conn.execute("COMMIT")
                except sqlite3.Error:
                    self._rollback(conn)
                    raise OSError(_DB_WRITE_ERROR) from None
                _log.info(
                    "request accepted request_id=%s status=accepted", request_id
                )
                return {
                    "request_id": request_id,
                    "status": "accepted",
                    "created_at": created_at,
                }
        finally:
            self._release(conn)
        raise OSError(_DB_WRITE_ERROR)

    @staticmethod
    def _rollback(conn: sqlite3.Connection) -> None:
        try:
            conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass

    def _load_idempotent(
        self,
        conn: sqlite3.Connection,
        tenant_id: str,
        idempotency_key: str,
        subject_id: str,
        scope_list: list[str],
    ) -> dict[str, str]:
        try:
            row = conn.execute(
                "SELECT request_id, status, created_at, subject_id, scopes_json "
                "FROM requests WHERE tenant_id = ? AND idempotency_key = ?",
                (tenant_id, idempotency_key),
            ).fetchone()
        except sqlite3.Error:
            raise OSError(_DB_READ_ERROR) from None
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
            and all(isinstance(item, str) and item for item in existing_scopes)
            and set(existing_scopes) == set(scope_list)
        )
        if not same_payload:
            raise IdempotencyConflict(_CONFLICT_MESSAGE)
        return {
            "request_id": existing_request_id,
            "status": status,
            "created_at": created_at,
        }

    def get(self, tenant_id: str, request_id: str) -> dict[str, str]:
        # Validate before touching the database; invalid arguments perform
        # no I/O and never reveal whether an id exists.
        tenant_id = _require_nonempty_str(tenant_id, "tenant_id")
        request_id = _require_nonempty_str(request_id, "request_id")
        # The in-memory connection is shared across threads; serialize it
        # against writes. File-backed stores use a fresh connection per call
        # and rely on SQLite's own concurrency.
        if self._mem_conn is not None:
            with self._write_lock:
                return self._get(tenant_id, request_id)
        return self._get(tenant_id, request_id)

    def _get(self, tenant_id: str, request_id: str) -> dict[str, str]:
        conn = self._connect()
        try:
            try:
                row = conn.execute(
                    "SELECT request_id, status, created_at FROM requests "
                    "WHERE tenant_id = ? AND request_id = ?",
                    (tenant_id, request_id),
                ).fetchone()
            except sqlite3.Error:
                # Never surface the database engine's own error text.
                raise OSError(_DB_READ_ERROR) from None
        finally:
            self._release(conn)
        if row is None:
            # Identical outcome for unknown ids and cross-tenant lookups:
            # the response must not reveal that another tenant owns a record.
            raise RequestNotFound(_NOT_FOUND_MESSAGE)
        return {
            "request_id": row[0],
            "status": row[1],
            "created_at": row[2],
        }
