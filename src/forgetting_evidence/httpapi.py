"""HTTP layer for deletion-request acceptance, lookup and observation.

The service exposes four read/accept endpoints:

* ``POST /requests`` -- accept a deletion request for a tenant. The JSON
  body must carry non-empty ``tenant_id``, ``subject_id`` and
  ``idempotency_key`` strings plus a non-empty ``scopes`` array of
  distinct non-empty strings.
* ``GET /requests/{request_id}`` -- return the accepted request's
  receipt, scoped to the tenant identified by the ``X-Tenant-Id`` header
  (or a ``tenant_id`` query parameter). The receipt is the record frozen
  at acceptance time and always reports ``accepted``; it never changes
  when the request's status subsequently advances.
* ``GET /requests/{request_id}/status`` -- return the request's current
  status as a single line of JSON with exactly ``request_id``, ``status``
  and ``created_at`` (in that order); ``status`` reflects the latest
  persisted transition while ``created_at`` stays the original
  acceptance time.
* ``GET /requests/{request_id}/execution-log`` -- return the request id
  and its execution ``attempts`` in attempt order. Each attempt carries
  exactly ``attempt_number`` (from 1), ``claimed_at``,
  ``lease_expires_at``, ``result`` and ``completed_at``; the last two are
  ``null`` for an attempt that has not finished and hold the persisted
  ``completed``/``failed`` result and completion time once it has. No
  lease credential, worker identity, subject, scope or other request
  field is ever returned.

The two observation endpoints are strictly read-only: they never advance
status, create an attempt or write any bookkeeping, and their output is
rebuilt from persisted rows so it is identical after a restart.

Status advancement (:meth:`RequestStore.transition`), the execution
orchestration (:meth:`RequestStore.claim_next`,
:meth:`RequestStore.finish_claim`, :meth:`RequestStore.renew_lease`,
:meth:`RequestStore.reconcile_execution`,
:meth:`RequestStore.reconcile_batch`,
:meth:`RequestStore.migrate_execution_leases`) and the deletion receipts
(:meth:`RequestStore.generate_receipt`,
:meth:`RequestStore.verify_receipt`,
:meth:`RequestStore.rotate_receipt_key`) and the anchor capability
(:meth:`RequestStore.verify_chain`,
:meth:`RequestStore.diagnose_chain`,
:meth:`RequestStore.rotate_anchor_key`) and the read-only batched
audit inspection (:meth:`RequestStore.audit_inspection` and
:meth:`RequestStore.audit_inspection_summary`) exist only on
the storage layer and stay deliberately unexposed; the two read-only
storage lookups that the observation endpoints present --
:meth:`RequestStore.get_status` and
:meth:`RequestStore.get_execution_log` -- are the only state-machine or
execution methods reachable over HTTP. Request acceptance, the
acceptance-receipt lookup and those two observation views are all the
service opens.

Success responses for acceptance, receipt lookup and the current-status
view are a single line of JSON with exactly ``request_id``, ``status``
and ``created_at`` (in that order) followed by a trailing newline; the
same idempotent request and every receipt lookup return byte-identical
bodies. The execution-log view is a single JSON line with exactly
``request_id`` and ``attempts`` (in that order) plus a trailing newline.
Error responses are single-line JSON objects with exactly one key,
``error``, holding a stable error code:

``invalid_request`` (400), ``unauthorized`` (401), ``forbidden``
(403), ``idempotency_conflict`` (409), ``not_found`` (404),
``method_not_allowed`` (405) and ``storage_unavailable`` (503).

Optional token authentication and role-based access control can be
enabled by passing an auth configuration (see :func:`load_auth_config`)
to :func:`build_server` / :func:`make_handler`. Without it the service
keeps the unauthenticated contract described above. When enabled every
matched business request must present ``Authorization: Bearer <token>``
for a configured principal: a missing/malformed/unknown token answers
``401 unauthorized`` and a principal lacking the role required by the
endpoint, or acting on a tenant other than its own ``tenant_id``,
answers ``403 forbidden``. ``POST /requests`` requires
``request:submit`` and the target tenant is the body's ``tenant_id``;
``GET /requests/{request_id}`` and both read-only observation views
(``/status`` and ``/execution-log``) require ``request:read`` and the
target tenant follows the existing ``X-Tenant-Id``/query rule.
Authentication runs after path/method routing (unknown paths stay 404,
unsupported methods stay 405) but before payload validation and any
storage access.
Tokens, roles and the configuration never enter a response, a raised
exception message, a log record, the database or any stored artifact.

No subject, scope, idempotency key, database error text, SQL statement
or filesystem path is ever placed in a response, a log record or a
raised exception message.
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from .requests import IdempotencyConflict, RequestNotFound, RequestStore

__all__ = [
    "build_server",
    "make_handler",
    "DeferredRequestStore",
    "AuthConfig",
    "AuthConfigError",
    "load_auth_config",
]

_log = logging.getLogger(__name__)

_COLLECTION_PATH = "/requests"
_ITEM_PATH_PREFIX = "/requests/"
_STATUS_RESOURCE = "status"
_EXECUTION_LOG_RESOURCE = "execution-log"
_TENANT_HEADER = "X-Tenant-Id"
_AUTHORIZATION_HEADER = "Authorization"
_BEARER_PREFIX = "Bearer "

# Reject oversized request bodies before they reach the database layer.
_MAX_BODY_BYTES = 1 << 20  # 1 MiB

_ROLE_SUBMIT = "request:submit"
_ROLE_READ = "request:read"
_ALLOWED_ROLES = frozenset({_ROLE_SUBMIT, _ROLE_READ})

_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

_INVALID_REQUEST = "invalid_request"
_UNAUTHORIZED = "unauthorized"
_FORBIDDEN = "forbidden"
_NOT_FOUND = "not_found"
_METHOD_NOT_ALLOWED = "method_not_allowed"
_IDEMPOTENCY_CONFLICT = "idempotency_conflict"
_STORAGE_UNAVAILABLE = "storage_unavailable"


class _BadRequest(Exception):
    """Internal signal for malformed or rejected client input."""


class _StorageUnavailable(Exception):
    """Internal signal: the backing database cannot be opened or used."""


# Sentinel returned by a storage read once the matching error reply has
# already been sent; an empty execution log is a legitimate result, so
# ``None`` cannot mark failure.
_READ_FAILED = object()


class AuthConfigError(Exception):
    """The auth configuration file is missing, unreadable or invalid.

    The message is a fixed marker; it never quotes the offending token,
    path or configuration content.
    """


class AuthConfig:
    """Parsed, immutable bearer-token principals for RBAC.

    Principals map a non-empty bearer token to their tenant id and a set
    of roles. Tokens and roles are kept in process memory only and are
    never logged or persisted by this module.
    """

    def __init__(self, principals: list[dict]):
        # ``principals`` has already passed :func:`load_auth_config`; copy
        # into an immutable token -> (tenant_id, frozenset(roles)) map.
        by_token: dict[str, tuple[str, frozenset[str]]] = {}
        for principal in principals:
            by_token[principal["token"]] = (
                principal["tenant_id"],
                frozenset(principal["roles"]),
            )
        self._by_token = by_token

    def authenticate(self, token: str) -> tuple[str, frozenset[str]] | None:
        """Return ``(tenant_id, roles)`` for *token*, or ``None`` if unknown."""
        return self._by_token.get(token)


def load_auth_config(path: str) -> AuthConfig:
    """Read and validate the auth configuration file once, at startup.

    The file must be a UTF-8 JSON object with a ``principals`` array;
    each principal is an object carrying non-empty ``token`` and
    ``tenant_id`` strings plus a non-empty ``roles`` array of distinct
    values drawn from ``request:submit`` and ``request:read``. Tokens
    must be unique across principals. Any deviation -- including an
    unreadable or non-UTF-8 file, malformed JSON, a missing ``principals``
    key or a principal missing/typing-wrong one of the required keys --
    raises :class:`AuthConfigError` so the caller can refuse to bind.
    """
    # Suppress exception chaining ("from None"): the underlying OSError
    # carries the filesystem path and a decode/JSON error may quote file
    # content, neither of which may reach a raised exception message.
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except OSError:
        raise AuthConfigError("auth_config_invalid") from None
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise AuthConfigError("auth_config_invalid") from None

    principals = _validate_auth_config(parsed)
    return AuthConfig(principals)


def _validate_auth_config(parsed: object) -> list[dict]:
    if not isinstance(parsed, dict) or "principals" not in parsed:
        raise AuthConfigError("auth_config_invalid")
    raw_principals = parsed["principals"]
    if not isinstance(raw_principals, list):
        raise AuthConfigError("auth_config_invalid")

    principals: list[dict] = []
    seen_tokens: set[str] = set()
    for entry in raw_principals:
        # Only the three specified keys are validated; their presence,
        # types and value domains are mandatory.
        if not isinstance(entry, dict) or not {
            "token",
            "tenant_id",
            "roles",
        } <= set(entry):
            raise AuthConfigError("auth_config_invalid")
        token = entry["token"]
        tenant_id = entry["tenant_id"]
        roles = entry["roles"]
        if not isinstance(token, str) or not token:
            raise AuthConfigError("auth_config_invalid")
        if not isinstance(tenant_id, str) or not tenant_id:
            raise AuthConfigError("auth_config_invalid")
        if not isinstance(roles, list) or not roles:
            raise AuthConfigError("auth_config_invalid")
        if not all(isinstance(role, str) for role in roles):
            raise AuthConfigError("auth_config_invalid")
        if len(set(roles)) != len(roles) or not set(roles) <= _ALLOWED_ROLES:
            raise AuthConfigError("auth_config_invalid")
        if token in seen_tokens:
            raise AuthConfigError("auth_config_invalid")
        seen_tokens.add(token)
        principals.append(
            {"token": token, "tenant_id": tenant_id, "roles": roles}
        )
    return principals


class DeferredRequestStore:
    """Lazily (re)initialising :class:`RequestStore` wrapper.

    Opening the store and creating the required tables is attempted once
    at construction (service startup); if the database cannot be created
    -- an unwritable path, a corrupt file, an I/O error -- startup still
    succeeds and every business call retries initialization, failing the
    single request with the stable ``storage_unavailable`` outcome. This
    keeps "database cannot be created" indistinguishable from "database
    became unusable": both answer HTTP 503 instead of taking the whole
    service down, and a storage path repaired at runtime heals on the
    next request without a restart.
    """

    def __init__(self, db_path: str):
        self._db_path = db_path
        self._lock = threading.Lock()
        self._store: RequestStore | None = None
        try:
            self._store = RequestStore(db_path)
        except (OSError, sqlite3.Error, RuntimeError):
            _log.warning("storage unavailable at startup")

    def _ready(self) -> RequestStore:
        if self._store is not None:
            return self._store
        with self._lock:
            if self._store is None:
                try:
                    self._store = RequestStore(self._db_path)
                except (OSError, sqlite3.Error, RuntimeError):
                    raise _StorageUnavailable
            return self._store

    def submit(self, tenant_id, subject_id, scopes, idempotency_key):
        return self._ready().submit(tenant_id, subject_id, scopes, idempotency_key)

    def get(self, tenant_id, request_id):
        return self._ready().get(tenant_id, request_id)

    def get_status(self, tenant_id, request_id):
        # Storage-layer only; not routed over HTTP, but proxied so this
        # wrapper stays a faithful RequestStore substitute.
        return self._ready().get_status(tenant_id, request_id)

    def transition(self, tenant_id, request_id, target_status):
        # Storage-layer only; not routed over HTTP, but proxied so this
        # wrapper stays a faithful RequestStore substitute.
        return self._ready().transition(
            tenant_id, request_id, target_status
        )

    def claim_next(self, tenant_id, worker_id, lease_seconds):
        # Execution orchestration is storage-layer only; like the status
        # machine it is never routed over HTTP.
        return self._ready().claim_next(tenant_id, worker_id, lease_seconds)

    def finish_claim(self, tenant_id, request_id, claim_token, result):
        return self._ready().finish_claim(
            tenant_id, request_id, claim_token, result
        )

    def renew_lease(self, tenant_id, request_id, claim_token, lease_seconds):
        # Lease renewal is storage-layer only; like the rest of the
        # execution orchestration it is never routed over HTTP.
        return self._ready().renew_lease(
            tenant_id, request_id, claim_token, lease_seconds
        )

    def get_execution_log(self, tenant_id, request_id):
        return self._ready().get_execution_log(tenant_id, request_id)

    def reconcile_execution(self, tenant_id, request_id):
        # Execution reconciliation is storage-layer only; like the rest of
        # the execution orchestration it is never routed over HTTP.
        return self._ready().reconcile_execution(tenant_id, request_id)

    def reconcile_batch(self, tenant_id, cursor=None, limit=None):
        # Batched, resumable reconciliation is storage-layer only; like the
        # rest of the execution orchestration it is never routed over HTTP.
        return self._ready().reconcile_batch(tenant_id, cursor, limit)

    def migrate_execution_leases(self, tenant_id, cursor=None, limit=None):
        # The recoverable legacy-lease migration is storage-layer only;
        # like the rest of the execution orchestration it is never routed
        # over HTTP and exposes no new endpoint.
        return self._ready().migrate_execution_leases(
            tenant_id, cursor, limit
        )

    def verify_chain(self, tenant_id=None, request_id=None):
        # Full-chain anchor verification is storage-layer only; never
        # routed over HTTP.
        return self._ready().verify_chain(tenant_id, request_id)

    def diagnose_chain(self, tenant_id=None, request_id=None):
        # Read-only recovery diagnosis is storage-layer only; never
        # routed over HTTP and never repairs anything.
        return self._ready().diagnose_chain(tenant_id, request_id)

    def audit_inspection(self, tenant_id, cursor=None, limit=None):
        # Read-only batched audit inspection is storage-layer only;
        # never routed over HTTP and never modifies audit evidence.
        return self._ready().audit_inspection(tenant_id, cursor, limit)

    def audit_inspection_summary(self, tenant_id, batch_id):
        # The read-only inspection summary is storage-layer only; never
        # routed over HTTP and never writes anything.
        return self._ready().audit_inspection_summary(tenant_id, batch_id)


def _normalize_request_id(value: str) -> str:
    """Validate a request id as a UUID and return its canonical text."""
    if not _UUID_RE.match(value):
        raise _BadRequest("invalid request id")
    # Accept upper-case spellings but look the store up under the same
    # canonical form uuid4() rows were written with.
    return value.lower()


def build_server(
    store,
    host: str = "127.0.0.1",
    port: int = 8080,
    auth: AuthConfig | None = None,
) -> ThreadingHTTPServer:
    """Build (but do not start) the threaded HTTP server bound to *host*:*port*.

    With *auth* ``None`` (the default) the server keeps its
    unauthenticated contract; pass a loaded :class:`AuthConfig` to
    require bearer-token authentication and RBAC on the business
    endpoints.
    """
    handler = make_handler(store, auth)
    server = ThreadingHTTPServer((host, port), handler)
    # Worker threads must not keep the process alive on shutdown.
    server.daemon_threads = True
    return server


def make_handler(
    store: RequestStore,
    auth: AuthConfig | None = None,
) -> type[BaseHTTPRequestHandler]:
    """Build a handler class closed over *store* and optional *auth*."""

    class _DeletionRequestHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        # Do not advertise the runtime version.
        server_version = "forgetting-evidence/0.1"
        sys_version = ""

        def version_string(self) -> str:  # type: ignore[override]
            # BaseHTTPRequestHandler joins server/sys versions with a
            # space; with an empty sys version that leaves a trailing
            # space, so render the fixed token verbatim.
            return self.server_version

        # -- routing ---------------------------------------------------

        def _route(self) -> tuple[str | None, str | None]:
            path = urlsplit(self.path).path
            if path == _COLLECTION_PATH:
                return "collection", None
            if path.startswith(_ITEM_PATH_PREFIX):
                remainder = path[len(_ITEM_PATH_PREFIX) :]
                if not remainder:
                    return None, None
                head, separator, tail = remainder.partition("/")
                # An empty leading segment never names a request.
                if not head:
                    return None, None
                if not separator:
                    return "item", head
                # Exactly one trailing segment naming a known read-only
                # sub-resource is routable; anything deeper stays unknown.
                if tail and "/" not in tail:
                    if tail == _STATUS_RESOURCE:
                        return "status", head
                    if tail == _EXECUTION_LOG_RESOURCE:
                        return "execution_log", head
            return None, None

        # -- method entry points --------------------------------------

        def do_POST(self) -> None:  # noqa: N802 - http.server naming
            self._guard(self._handle_post)

        def do_GET(self) -> None:  # noqa: N802 - http.server naming
            self._guard(self._handle_get)

        def do_HEAD(self) -> None:  # noqa: N802 - http.server naming
            # HEAD receives the same 405/404 routing as other unsupported
            # verbs, with headers but no body.
            self._guard(lambda: self._handle_unsupported_method(headless=True))

        def do_PUT(self) -> None:  # noqa: N802 - http.server naming
            self._guard(self._handle_unsupported_method)

        def do_DELETE(self) -> None:  # noqa: N802 - http.server naming
            self._guard(self._handle_unsupported_method)

        def do_PATCH(self) -> None:  # noqa: N802 - http.server naming
            self._guard(self._handle_unsupported_method)

        def do_OPTIONS(self) -> None:  # noqa: N802 - http.server naming
            self._guard(self._handle_unsupported_method)

        def handle_expect_100(self) -> bool:  # type: ignore[override]
            # Honour "Expect: 100-continue" so clients (e.g. curl with a
            # large body) send the payload instead of waiting for a
            # 100-continue that never arrives.
            return True

        def _guard(self, handler) -> None:
            try:
                handler()
            except _BadRequest:
                self._safe_error(400, _INVALID_REQUEST)
            except Exception:
                # A defect in request handling must surface as the
                # stable storage code only; never let http.server print a
                # traceback (which could quote SQL or paths) to stderr.
                _log.warning("request failed: %s", _STORAGE_UNAVAILABLE)
                self._safe_error(503, _STORAGE_UNAVAILABLE)

        def _handle_unsupported_method(self, headless: bool = False) -> None:
            kind, _ = self._route()
            if kind is None:
                self._reply_error(404, _NOT_FOUND, headless=headless)
            else:
                allowed = "POST" if kind == "collection" else "GET"
                self._reply_error(
                    405, _METHOD_NOT_ALLOWED, allowed=allowed, headless=headless
                )

        # -- authentication / authorization ----------------------------

        def _authorize(self, required_role: str) -> tuple[str, frozenset[str]] | None:
            """Authenticate the bearer token and check *required_role*.

            Returns the principal's ``(tenant_id, roles)`` on success.
            Replies ``401 unauthorized`` for a missing, malformed or
            unknown credential and ``403 forbidden`` when the role is
            absent; returns ``None`` in either case. No token material is
            ever logged or quoted in the response.
            """
            if auth is None:
                # Unauthenticated deployment: no principal and no gate.
                return ("", frozenset())
            header = self.headers.get(_AUTHORIZATION_HEADER)
            if header is None or not header.startswith(_BEARER_PREFIX):
                self._auth_rejected(401, _UNAUTHORIZED)
                return None
            token = header[len(_BEARER_PREFIX) :]
            if not token:
                self._auth_rejected(401, _UNAUTHORIZED)
                return None
            principal = auth.authenticate(token)
            if principal is None:
                self._auth_rejected(401, _UNAUTHORIZED)
                return None
            tenant_id, roles = principal
            if required_role not in roles:
                self._auth_rejected(403, _FORBIDDEN)
                return None
            return tenant_id, roles

        def _auth_rejected(self, status: int, code: str) -> None:
            # A rejected POST has not consumed its request body, so the
            # connection cannot serve another pipelined request; close it
            # after the error to keep keep-alive framing intact.
            if self.command == "POST":
                self.close_connection = True
            self._reply_error(status, code)

        def _tenant_allowed(
            self, principal_tenant: str, target_tenant: str
        ) -> bool:
            if auth is None:
                return True
            if target_tenant != principal_tenant:
                self._reply_error(403, _FORBIDDEN)
                return False
            return True

        def _handle_post(self) -> None:
            kind, _ = self._route()
            if kind is None:
                self._reply_error(404, _NOT_FOUND)
                return
            if kind != "collection":
                self._reply_error(405, _METHOD_NOT_ALLOWED, allowed="GET")
                return
            # Authentication precedes payload validation and storage.
            principal = self._authorize(_ROLE_SUBMIT)
            if principal is None:
                return
            payload = self._read_json_object()
            tenant_id = _require_string(payload, "tenant_id")
            # The body's tenant is the authorization target; a principal
            # may only submit for its own tenant.
            if not self._tenant_allowed(principal[0], tenant_id):
                return
            subject_id = _require_string(payload, "subject_id")
            idempotency_key = _require_string(payload, "idempotency_key")
            scopes = _require_scopes(payload)
            try:
                receipt = store.submit(
                    tenant_id, subject_id, scopes, idempotency_key
                )
            except ValueError:
                # Defence in depth: the HTTP validation above is
                # authoritative, but a rejected store call writes nothing
                # and maps to the same client error.
                self._reply_error(400, _INVALID_REQUEST)
                return
            except IdempotencyConflict:
                self._reply_error(409, _IDEMPOTENCY_CONFLICT)
                return
            except _StorageUnavailable:
                _log.warning("request rejected: %s", _STORAGE_UNAVAILABLE)
                self._reply_error(503, _STORAGE_UNAVAILABLE)
                return
            except (sqlite3.Error, RuntimeError, OSError):
                # The store deliberately raises fixed-text RuntimeErrors;
                # sqlite/OSError text (locks, malformed images, paths)
                # must never reach the client.
                _log.warning("request rejected: %s", _STORAGE_UNAVAILABLE)
                self._reply_error(503, _STORAGE_UNAVAILABLE)
                return
            self._reply_receipt(200, receipt)

        def _handle_get(self) -> None:
            kind, segment = self._route()
            if kind is None:
                self._reply_error(404, _NOT_FOUND)
                return
            if kind == "collection":
                self._reply_error(405, _METHOD_NOT_ALLOWED, allowed="POST")
                return
            assert segment is not None
            if kind == "item":
                self._handle_record_read(segment, store.get, self._reply_receipt)
            elif kind == "status":
                self._handle_record_read(
                    segment, store.get_status, self._reply_receipt
                )
            elif kind == "execution_log":
                self._handle_execution_log(segment)
            else:  # pragma: no cover - routing never yields another kind
                self._reply_error(404, _NOT_FOUND)

        def _handle_record_read(self, segment, read, reply) -> None:
            resolved = self._resolve_read_scope(segment)
            if resolved is None:
                return
            tenant_id, request_id = resolved
            record = self._perform_read(read, tenant_id, request_id)
            if record is _READ_FAILED:
                return
            reply(200, record)

        def _handle_execution_log(self, segment: str) -> None:
            resolved = self._resolve_read_scope(segment)
            if resolved is None:
                return
            tenant_id, request_id = resolved
            attempts = self._perform_read(
                store.get_execution_log, tenant_id, request_id
            )
            if attempts is _READ_FAILED:
                return
            self._reply_execution_log(request_id, attempts)

        def _resolve_read_scope(self, segment: str) -> tuple[str, str] | None:
            """Authorize and resolve ``(tenant_id, request_id)`` for a read.

            Returns ``None`` after sending the appropriate error reply.
            """
            # Authentication precedes request-id validation and storage.
            principal = self._authorize(_ROLE_READ)
            if principal is None:
                return None
            if auth is not None:
                # With auth enabled the full authorization -- including
                # resolving the target tenant and matching it -- completes
                # before request-id syntax is even inspected, so a foreign
                # principal cannot reach id validation or storage.
                try:
                    tenant_id = self._tenant_id()
                except _BadRequest:
                    self._reply_error(400, _INVALID_REQUEST)
                    return None
                if not self._tenant_allowed(principal[0], tenant_id):
                    return None
                try:
                    request_id = _normalize_request_id(segment)
                except _BadRequest:
                    # Unknown and malformed ids share one outcome.
                    self._reply_error(404, _NOT_FOUND)
                    return None
            else:
                # Unauthenticated contract keeps its historical order:
                # request-id shape is checked before the tenant header.
                try:
                    request_id = _normalize_request_id(segment)
                except _BadRequest:
                    self._reply_error(404, _NOT_FOUND)
                    return None
                try:
                    tenant_id = self._tenant_id()
                except _BadRequest:
                    self._reply_error(400, _INVALID_REQUEST)
                    return None
            return tenant_id, request_id

        def _perform_read(self, read, tenant_id: str, request_id: str):
            """Run a read-only store call, mapping every fault to a reply.

            Returns :data:`_READ_FAILED` once the error response has been
            sent; a legitimate empty result is never confused with it.
            """
            try:
                return read(tenant_id, request_id)
            except RequestNotFound:
                # Missing ids and cross-tenant lookups are indistinguishable.
                self._reply_error(404, _NOT_FOUND)
            except ValueError:
                self._reply_error(400, _INVALID_REQUEST)
            except _StorageUnavailable:
                _log.warning("request rejected: %s", _STORAGE_UNAVAILABLE)
                self._reply_error(503, _STORAGE_UNAVAILABLE)
            except (sqlite3.Error, RuntimeError, OSError):
                _log.warning("request rejected: %s", _STORAGE_UNAVAILABLE)
                self._reply_error(503, _STORAGE_UNAVAILABLE)
            return _READ_FAILED

        # -- input parsing ---------------------------------------------

        def _tenant_id(self) -> str:
            header = self.headers.get(_TENANT_HEADER)
            if header is not None:
                tenant = header.strip()
                if tenant:
                    return tenant
            query = parse_qs(urlsplit(self.path).query).get("tenant_id")
            if query:
                tenant = query[-1].strip()
                if tenant:
                    return tenant
            raise _BadRequest("missing tenant")

        def _read_json_object(self) -> dict:
            body = self._read_body()
            try:
                parsed = json.loads(body.decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                raise _BadRequest("invalid json body")
            if not isinstance(parsed, dict):
                raise _BadRequest("body must be a JSON object")
            return parsed

        def _read_body(self) -> bytes:
            raw_length = self.headers.get("Content-Length")
            if raw_length is None:
                raise _BadRequest("missing content length")
            try:
                length = int(raw_length)
            except (TypeError, ValueError):
                raise _BadRequest("invalid content length")
            if length < 0 or length > _MAX_BODY_BYTES:
                # Leave the oversized tail unread and close the
                # connection so keep-alive cannot desync the next request.
                self.close_connection = True
                raise _BadRequest("body too large")
            try:
                return self.rfile.read(length)
            except OSError:
                raise _BadRequest("unreadable body")

        # -- responses --------------------------------------------------

        def _reply_receipt(self, status: int, receipt: dict[str, str]) -> None:
            if set(receipt) != {"request_id", "status", "created_at"}:
                # Corrupt persisted rows must never be presented as a
                # receipt.
                raise RuntimeError("malformed receipt from store")
            body = (
                json.dumps(
                    {
                        "request_id": receipt["request_id"],
                        "status": receipt["status"],
                        "created_at": receipt["created_at"],
                    },
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8")
            self._write_body(status, body)

        def _reply_execution_log(
            self, request_id: str, attempts: list
        ) -> None:
            # Defence in depth on top of the store's own strict validation:
            # a malformed or credential-bearing record must never be
            # serialised, so any shape deviation is treated as storage
            # corruption (503 via the guard), never as a partial response.
            if not isinstance(attempts, list):
                raise RuntimeError("malformed execution log from store")
            clean_attempts: list[dict] = []
            for index, attempt in enumerate(attempts, start=1):
                if not isinstance(attempt, dict):
                    raise RuntimeError("malformed execution log from store")
                if set(attempt) != {
                    "attempt_number",
                    "claimed_at",
                    "lease_expires_at",
                    "result",
                    "completed_at",
                }:
                    raise RuntimeError("malformed execution log from store")
                if attempt["attempt_number"] != index:
                    raise RuntimeError("malformed execution log from store")
                clean_attempts.append(
                    {
                        "attempt_number": attempt["attempt_number"],
                        "claimed_at": attempt["claimed_at"],
                        "lease_expires_at": attempt["lease_expires_at"],
                        "result": attempt["result"],
                        "completed_at": attempt["completed_at"],
                    }
                )
            body = (
                json.dumps(
                    {
                        "request_id": request_id,
                        "attempts": clean_attempts,
                    },
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8")
            self._write_body(200, body)

        def _reply_error(
            self,
            status: int,
            code: str,
            allowed: str | None = None,
            headless: bool = False,
        ) -> None:
            body = (
                json.dumps({"error": code}, ensure_ascii=False, separators=(",", ":"))
                + "\n"
            ).encode("utf-8")
            self._write_body(status, body, allowed=allowed, headless=headless)

        def _write_body(
            self,
            status: int,
            body: bytes,
            allowed: str | None = None,
            headless: bool = False,
        ) -> None:
            try:
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                if allowed is not None:
                    self.send_header("Allow", allowed)
                self.send_header("Content-Length", str(len(body)))
                if self.close_connection:
                    # Tell the client explicitly when a request left an
                    # unread body (e.g. an auth rejection before parsing)
                    # so it does not pipeline another request.
                    self.send_header("Connection", "close")
                self.end_headers()
                if not headless:
                    self.wfile.write(body)
            except OSError:
                # The client went away mid-response; nothing to report.
                self.close_connection = True

        def _safe_error(self, status: int, code: str) -> None:
            try:
                self._reply_error(status, code)
            except Exception:
                self.close_connection = True

        # Protocol-level errors (bad request line, unrecognised verbs
        # that never resolve to a do_* method) must use the same JSON
        # error shape and stable codes instead of http.server's HTML
        # 400/501 responses.
        def send_error(self, code, message=None, explain=None):  # type: ignore[override]
            if code == 501:
                # Even an unrecognised verb must honour the
                # unknown-path (404) vs known-path (405) distinction.
                self._handle_unsupported_method()
            elif code == 404:
                self._safe_error(404, _NOT_FOUND)
            elif 400 <= code < 500:
                self._safe_error(400, _INVALID_REQUEST)
            else:
                self._safe_error(503, _STORAGE_UNAVAILABLE)

        # Never emit request lines (paths carry request ids) or default
        # stack traces as access logs; failures are logged by code only.
        def log_message(self, format: str, *args) -> None:  # noqa: A002
            return

    return _DeletionRequestHandler


def _require_string(payload: dict, key: str) -> str:
    if key not in payload:
        raise _BadRequest(f"missing {key}")
    value = payload[key]
    if not isinstance(value, str) or not value:
        raise _BadRequest(f"invalid {key}")
    return value


def _require_scopes(payload: dict) -> list[str]:
    if "scopes" not in payload:
        raise _BadRequest("missing scopes")
    scopes = payload["scopes"]
    if not isinstance(scopes, list):
        raise _BadRequest("invalid scopes")
    if not scopes or not all(isinstance(item, str) and item for item in scopes):
        raise _BadRequest("invalid scopes")
    if len(set(scopes)) != len(scopes):
        raise _BadRequest("duplicate scopes")
    return scopes
