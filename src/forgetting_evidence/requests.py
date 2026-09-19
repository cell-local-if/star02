"""SQLite-backed intake and lookup for machine-forgetting requests."""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from typing import Sequence

__all__ = ["RequestStore", "IdempotencyConflict", "RequestNotFound"]


class IdempotencyConflict(Exception):
    """An idempotency key was reused with a different payload."""


class RequestNotFound(Exception):
    """No request with the given identifier exists for the tenant."""


_SCHEMA = """
CREATE TABLE IF NOT EXISTS requests (
    request_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    scopes TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (tenant_id, idempotency_key)
);
"""

_STATUS_ACCEPTED = "accepted"


def _utcnow() -> str:
    now = datetime.now(timezone.utc).isoformat(timespec="microseconds")
    return now.replace("+00:00", "Z")


def _require_non_empty_str(value: object, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _validate_scopes(scopes: object) -> list[str]:
    if isinstance(scopes, (str, bytes)) or not isinstance(scopes, Sequence):
        raise ValueError("scopes must be a non-empty sequence of distinct strings")
    items = list(scopes)
    if not items:
        raise ValueError("scopes must be a non-empty sequence of distinct strings")
    for item in items:
        if not isinstance(item, str) or not item:
            raise ValueError("scopes must be a non-empty sequence of distinct strings")
    if len(set(items)) != len(items):
        raise ValueError("scopes must be a non-empty sequence of distinct strings")
    return items


class RequestStore:
    """Persistent store for forgetting requests backed by SQLite."""

    def __init__(self, db_path: "str | os.PathLike[str]") -> None:
        self._db_path = os.fspath(db_path)
        if self._db_path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(self._db_path)), exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
        self._conn.execute("PRAGMA busy_timeout = 5000")
        self._conn.execute("PRAGMA foreign_keys = ON")
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self) -> "RequestStore":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def submit(
        self,
        tenant_id: str,
        subject_id: str,
        scopes: Sequence[str],
        idempotency_key: str,
    ) -> dict:
        """Accept a forgetting request, deduplicating on the idempotency key."""
        tenant_id = _require_non_empty_str(tenant_id, "tenant_id")
        subject_id = _require_non_empty_str(subject_id, "subject_id")
        idempotency_key = _require_non_empty_str(idempotency_key, "idempotency_key")
        scope_list = _validate_scopes(scopes)
        canonical_scopes = json.dumps(sorted(scope_list))

        with self._lock:
            # INSERT OR IGNORE makes the (tenant_id, idempotency_key) race
            # atomic: exactly one concurrent submitter creates the row.
            for _ in range(8):
                request_id = str(uuid.uuid4())
                created_at = _utcnow()
                cursor = self._conn.execute(
                    "INSERT OR IGNORE INTO requests "
                    "(request_id, tenant_id, subject_id, scopes, "
                    " idempotency_key, status, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        request_id,
                        tenant_id,
                        subject_id,
                        canonical_scopes,
                        idempotency_key,
                        _STATUS_ACCEPTED,
                        created_at,
                    ),
                )
                self._conn.commit()
                if cursor.rowcount:
                    return {
                        "request_id": request_id,
                        "status": _STATUS_ACCEPTED,
                        "created_at": created_at,
                    }
                row = self._conn.execute(
                    "SELECT request_id, subject_id, scopes, status, created_at "
                    "FROM requests WHERE tenant_id = ? AND idempotency_key = ?",
                    (tenant_id, idempotency_key),
                ).fetchone()
                if row is None:
                    # Ignored due to a request_id collision, not the
                    # idempotency key; retry with a fresh UUID.
                    continue
                if row[1] == subject_id and set(json.loads(row[2])) == set(scope_list):
                    return {
                        "request_id": row[0],
                        "status": row[3],
                        "created_at": row[4],
                    }
                raise IdempotencyConflict(
                    "idempotency key was already used with a different payload"
                )
        raise RuntimeError("unable to allocate a request id")

    def get(self, tenant_id: str, request_id: str) -> dict:
        """Look up a request; cross-tenant misses are indistinguishable."""
        with self._lock:
            row = self._conn.execute(
                "SELECT request_id, status, created_at FROM requests "
                "WHERE tenant_id = ? AND request_id = ?",
                (tenant_id, request_id),
            ).fetchone()
        if row is None:
            raise RequestNotFound("request not found")
        return {"request_id": row[0], "status": row[1], "created_at": row[2]}
