"""HTTP boundary for deletion-request acceptance and lookup.

The layer exposes exactly two business endpoints:

* ``POST /requests``         -- accept a deletion request
* ``GET  /requests/<uuid>``  -- retrieve the receipt within one tenant

Every response is a single-line UTF-8 JSON document. Error responses
contain only a stable ``error`` code; request payloads, idempotency
keys, filesystem paths and database engine text are never placed in
responses, logs or raised exception messages.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import uuid
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit

from .requests import IdempotencyConflict, RequestNotFound, RequestStore

__all__ = ["build_handler", "create_server", "serve"]

_log = logging.getLogger(__name__)

_COLLECTION_PATH = "/requests"
_ITEM_PREFIX = "/requests/"
_TENANT_HEADER = "X-Tenant-ID"

# Keep request bodies bounded; the accepted payload is a tiny fixed
# shape, so anything larger is malformed input rather than a request.
_MAX_BODY_BYTES = 1 << 20  # 1 MiB

# Stable error codes. Only these strings ever reach clients.
_ERR_INVALID_REQUEST = "invalid_request"
_ERR_NOT_FOUND = "not_found"
_ERR_METHOD_NOT_ALLOWED = "method_not_allowed"
_ERR_IDEMPOTENCY_CONFLICT = "idempotency_conflict"
_ERR_STORAGE_UNAVAILABLE = "storage_unavailable"


def _is_nonempty_str(value: object) -> bool:
    return isinstance(value, str) and not isinstance(value, bool) and bool(value)


def _validate_scopes(value: object) -> list[str] | None:
    """Validate the deletion scope set.

    Scopes must be a non-empty JSON array of distinct, non-empty
    strings. Returning ``None`` signals invalid input.
    """
    if not isinstance(value, list):
        return None
    if not value or not all(_is_nonempty_str(item) for item in value):
        return None
    if len(set(value)) != len(value):
        return None
    return value  # type: ignore[return-value]


def _parse_submission(raw_body: bytes) -> dict[str, Any] | None:
    """Parse and validate a submission body.

    Returns the validated object or ``None`` when the body is not a
    single JSON object carrying exactly the required fields with the
    required types. No validation error text is produced: the HTTP
    layer answers all of these with one stable code.
    """
    try:
        text = raw_body.decode("utf-8")
    except UnicodeDecodeError:
        return None
    text_stripped = text.strip()
    if not text_stripped:
        return None
    try:
        payload, end = json.JSONDecoder().raw_decode(text_stripped)
    except ValueError:
        return None
    # Reject trailing data after the single JSON document.
    if text_stripped[end:].strip():
        return None
    if not isinstance(payload, dict):
        return None
    tenant_id = payload.get("tenant_id")
    subject_id = payload.get("subject_id")
    idempotency_key = payload.get("idempotency_key")
    scopes = payload.get("scopes")
    if not (
        _is_nonempty_str(tenant_id)
        and _is_nonempty_str(subject_id)
        and _is_nonempty_str(idempotency_key)
    ):
        return None
    scopes = _validate_scopes(scopes)
    if scopes is None:
        return None
    return {
        "tenant_id": tenant_id,
        "subject_id": subject_id,
        "idempotency_key": idempotency_key,
        "scopes": scopes,
    }


def build_handler(store: RequestStore) -> type[BaseHTTPRequestHandler]:
    """Build a request handler class bound to ``store``."""

    class _DeletionRequestHandler(BaseHTTPRequestHandler):
        server_version = "ForgettingEvidence/0.1"
        # The store serializes writers itself; let worker threads exit
        # with the process instead of holding the server shutdown open.
        protocol_version = "HTTP/1.1"

        # -- response helpers ----------------------------------------

        def _send_json(
            self, status: HTTPStatus, payload: dict[str, Any], *, allow: str | None = None
        ) -> None:
            # Field insertion order is preserved; success receipts are
            # built in the contract order, and error bodies carry only
            # the error code. A trailing newline terminates the line.
            body = (json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            if allow is not None:
                self.send_header("Allow", allow)
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                # The client stopped reading; nothing more to do and no
                # engine text may escape.
                pass

        def _send_error(self, status: HTTPStatus, code: str) -> None:
            self._send_json(status, {"error": code})

        # -- routing --------------------------------------------------

        def _route_path(self) -> tuple[str, str | None]:
            """Split the request target into a route kind and an id.

            Returns one of:
            ``("collection", None)``     for ``/requests``
            ``("item", <token>)``        for ``/requests/<token>``
            ``("unknown", None)``        for anything else
            """
            path = urlsplit(self.path).path
            if path == _COLLECTION_PATH:
                return "collection", None
            if path.startswith(_ITEM_PREFIX):
                token = path[len(_ITEM_PREFIX):]
                if token and "/" not in token:
                    return "item", token
            return "unknown", None

        def _tenant(self) -> str | None:
            """Resolve the caller's tenant for the request.

            Acceptance carries the tenant in the JSON body; lookups
            scope by the ``X-Tenant-ID`` header or a ``tenant_id``
            query parameter. Empty/whitespace values are invalid. When
            both scoping forms are present they must agree.
            """
            header = self.headers.get(_TENANT_HEADER)
            fields = parse_qs(
                urlsplit(self.path).query, keep_blank_values=True
            )
            query_values = fields.get("tenant_id")
            query_tenant = query_values[0] if query_values else None
            if header is not None and query_tenant is not None:
                if header != query_tenant:
                    return None
                value = header
            else:
                value = header if header is not None else query_tenant
            return value if _is_nonempty_str(value) else None

        def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            self._dispatch("POST")

        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            self._dispatch("GET")

        def __getattr__(self, name: str) -> Any:
            # BaseHTTPRequestHandler looks up ``do_<METHOD>``; any verb
            # we do not implement is routed so known paths answer 405
            # and unknown paths answer 404 instead of the default 501.
            if name.startswith("do_"):
                return self._handle_unsupported_method
            raise AttributeError(name)

        def _handle_unsupported_method(self) -> None:
            self._dispatch(self.command)

        def _dispatch(self, method: str) -> None:
            try:
                kind, item_id = self._route_path()
                if kind == "unknown":
                    self._send_error(HTTPStatus.NOT_FOUND, _ERR_NOT_FOUND)
                    return
                if method == "POST" and kind == "collection":
                    self._accept_request()
                elif method == "GET" and kind == "item":
                    assert item_id is not None
                    self._lookup_request(item_id)
                else:
                    allowed = "POST" if kind == "collection" else "GET"
                    self._send_json(
                        HTTPStatus.METHOD_NOT_ALLOWED,
                        {"error": _ERR_METHOD_NOT_ALLOWED},
                        allow=allowed,
                    )
            except (BrokenPipeError, ConnectionResetError):
                return
            except Exception:  # noqa: BLE001 - stable code, no text may leak
                # Last-resort guard: collapse every unexpected failure
                # (storage errors, corruption, threading issues) into the
                # single storage code and log only that code.
                _log.warning("request failed with error=%s", _ERR_STORAGE_UNAVAILABLE)
                try:
                    self._send_error(
                        HTTPStatus.SERVICE_UNAVAILABLE, _ERR_STORAGE_UNAVAILABLE
                    )
                except (BrokenPipeError, ConnectionResetError):
                    return

        # -- endpoints ------------------------------------------------

        def _accept_request(self) -> None:
            # Tenant arrives in the JSON body for acceptance. If the
            # caller also supplies a scoping header/parameter it must
            # agree with the body.
            scoped_tenant = self._tenant()
            try:
                length = int(self.headers.get("Content-Length", ""))
            except (TypeError, ValueError):
                self._send_error(HTTPStatus.BAD_REQUEST, _ERR_INVALID_REQUEST)
                return
            if length < 0 or length > _MAX_BODY_BYTES:
                self._send_error(HTTPStatus.BAD_REQUEST, _ERR_INVALID_REQUEST)
                return
            raw_body = self.rfile.read(length)
            if len(raw_body) != length:
                # Client declared more bytes than it sent.
                self._send_error(HTTPStatus.BAD_REQUEST, _ERR_INVALID_REQUEST)
                return
            parsed = _parse_submission(raw_body)
            if parsed is None:
                self._send_error(HTTPStatus.BAD_REQUEST, _ERR_INVALID_REQUEST)
                return
            if scoped_tenant is not None and scoped_tenant != parsed["tenant_id"]:
                self._send_error(HTTPStatus.BAD_REQUEST, _ERR_INVALID_REQUEST)
                return
            try:
                receipt = store.submit(
                    parsed["tenant_id"],
                    parsed["subject_id"],
                    parsed["scopes"],
                    parsed["idempotency_key"],
                )
            except IdempotencyConflict:
                self._send_error(
                    HTTPStatus.CONFLICT, _ERR_IDEMPOTENCY_CONFLICT
                )
                return
            except ValueError:
                self._send_error(HTTPStatus.BAD_REQUEST, _ERR_INVALID_REQUEST)
                return
            except (RuntimeError, sqlite3.Error):
                self._send_error(
                    HTTPStatus.SERVICE_UNAVAILABLE, _ERR_STORAGE_UNAVAILABLE
                )
                return
            self._send_json(
                HTTPStatus.OK,
                {
                    "request_id": receipt["request_id"],
                    "status": receipt["status"],
                    "created_at": receipt["created_at"],
                },
            )

        def _lookup_request(self, item_id: str) -> None:
            tenant_id = self._tenant()
            if tenant_id is None:
                self._send_error(HTTPStatus.BAD_REQUEST, _ERR_INVALID_REQUEST)
                return
            try:
                # Validates the shape of the request number; storage
                # only ever hands out canonical UUIDs.
                uuid.UUID(item_id)
            except (TypeError, ValueError, AttributeError):
                self._send_error(HTTPStatus.NOT_FOUND, _ERR_NOT_FOUND)
                return
            try:
                receipt = store.get(tenant_id, item_id)
            except RequestNotFound:
                # Missing, malformed-from-the-store's-view and
                # cross-tenant lookups share one identical answer.
                self._send_error(HTTPStatus.NOT_FOUND, _ERR_NOT_FOUND)
                return
            except ValueError:
                self._send_error(HTTPStatus.BAD_REQUEST, _ERR_INVALID_REQUEST)
                return
            except (RuntimeError, sqlite3.Error):
                self._send_error(
                    HTTPStatus.SERVICE_UNAVAILABLE, _ERR_STORAGE_UNAVAILABLE
                )
                return
            self._send_json(
                HTTPStatus.OK,
                {
                    "request_id": receipt["request_id"],
                    "status": receipt["status"],
                    "created_at": receipt["created_at"],
                },
            )

        # -- logging --------------------------------------------------

        def log_message(self, format: str, *args: Any) -> None:
            # The default access log renders the request line (and thus
            # the path); keep stderr free of request-derived content.
            return

    return _DeletionRequestHandler


def create_server(
    host: str,
    port: int,
    store: RequestStore,
) -> ThreadingHTTPServer:
    """Create (but do not start) the HTTP server bound to ``host:``port``."""
    server = ThreadingHTTPServer((host, port), build_handler(store))
    server.daemon_threads = True
    return server


def serve(db_path: str, host: str = "127.0.0.1", port: int = 8080) -> None:
    """Open the store and serve until interrupted.

    Storage failures while opening the database are translated to
    :class:`StorageUnavailable`; bind failures propagate as OSError.
    Neither path includes the database path or engine text.
    """
    try:
        store = RequestStore(db_path)
    except (OSError, RuntimeError, sqlite3.Error):
        raise StorageUnavailable("storage_unavailable") from None
    server = create_server(host, port, store)
    try:
        server.serve_forever()
    finally:
        server.server_close()


class StorageUnavailable(RuntimeError):
    """Raised when the backing database cannot be opened at startup."""
