"""HTTP layer for deletion-request acceptance, lookup, observation and
single-request reconciliation.

The service exposes six business endpoints:

* ``POST /requests`` -- accept a deletion request for a tenant. The JSON
  body must carry non-empty ``tenant_id``, ``subject_id`` and
  ``idempotency_key`` strings plus a non-empty ``scopes`` array of
  distinct non-empty strings.
* ``GET /requests`` -- the tenant-scoped, paginated listing of accepted
  requests. The tenant follows the existing ``X-Tenant-Id``/query rule;
  the optional ``status`` (comma-separated distinct lifecycle statuses),
  ``created_from`` (inclusive) and ``created_to`` (exclusive) RFC3339 UTC
  bounds, ``cursor`` and ``limit`` (1..1000, default 100) query
  parameters filter and page the result. The single-line JSON body
  carries exactly ``items`` and ``next_cursor``; each item carries
  exactly ``request_id``, ``status`` and ``created_at`` in ascending
  acceptance order, and ``next_cursor`` is the opaque continuation value
  or ``null`` at the end of the listing. Any other query parameter, a
  duplicated ``status`` value or a malformed filter answers 400.
* ``GET /requests/{request_id}`` -- return the accepted request's
  receipt, scoped to the tenant identified by the ``X-Tenant-Id`` header
  (or a ``tenant_id`` query parameter). The receipt is the record frozen
  at acceptance time and always reports ``accepted``; it never changes
  when the request's status subsequently advances.
* ``GET /requests/{request_id}/status`` -- read-only observation of the
  request's current state. The single-line JSON body carries exactly
  ``request_id``, ``status`` and ``created_at`` in that order; ``status``
  is the latest persisted state while ``created_at`` stays the original
  acceptance time.
* ``GET /requests/{request_id}/execution-log`` -- read-only observation
  of the request's execution attempts. The single-line JSON body carries
  exactly ``request_id`` and ``attempts``; attempts are ordered by
  ``attempt_number`` starting at 1 and each entry carries exactly
  ``attempt_number``, ``claimed_at``, ``lease_expires_at``, ``result``
  and ``completed_at``. An unfinished attempt has ``null`` ``result`` and
  ``completed_at``; a finished attempt carries its stored ``completed``
  or ``failed`` result and completion time.
* ``POST /requests/{request_id}/reconcile`` -- reconcile exactly one
  request's execution record against its persisted state by calling the
  storage layer's :meth:`RequestStore.reconcile_execution`. The endpoint
  takes no business parameters: a missing ``Content-Length`` or a length
  of zero means there is no body; any other body answers 400. On success
  it answers 200 with the same single-line JSON shape as the status
  read -- exactly ``request_id``, ``status`` and ``created_at`` --
  rendering the current record after reconciliation. Repeating the call
  never changes a stable terminal state, historical attempts or existing
  timestamps; concurrent calls leave the unique outcome to the store's
  atomic commit. No subject, scope, idempotency key, worker, lease
  credential or attempt detail is ever exposed.

The observation endpoints never advance state, create an attempt or
write any bookkeeping; they only read persisted rows, so their answers
match the persisted records after a restart. They never expose a lease
credential, worker identity, subject, scope or any other request field.
Only the single-request reconcile endpoint may converge execution state,
through the storage layer's existing atomic semantics; no batch
reconciliation is exposed over HTTP.

Status advancement (:meth:`RequestStore.transition`), the execution
orchestration (:meth:`RequestStore.claim_next`,
:meth:`RequestStore.finish_claim`, :meth:`RequestStore.renew_lease`,
:meth:`RequestStore.transfer_claim`,
:meth:`RequestStore.reconcile_batch`,
:meth:`RequestStore.migrate_execution_leases`) and the deletion receipts
(:meth:`RequestStore.generate_receipt`,
:meth:`RequestStore.get_receipt`,
:meth:`RequestStore.verify_receipt`,
:meth:`RequestStore.rotate_receipt_key`) and the anchor capability
(:meth:`RequestStore.verify_chain`,
:meth:`RequestStore.diagnose_chain`,
:meth:`RequestStore.rotate_anchor_key`) and the read-only batched
audit inspection (:meth:`RequestStore.audit_inspection` and
:meth:`RequestStore.audit_inspection_summary`) exist only on
the storage layer and are deliberately not exposed over HTTP: over HTTP
the service opens request acceptance, the acceptance-receipt lookup, the
read-only tenant-scoped listing, the two read-only observation reads and
the single-request execution reconciliation described above. The
current-status lookup (:meth:`RequestStore.get_status`), the
tenant-scoped listing (:meth:`RequestStore.list_requests`), the
execution log (:meth:`RequestStore.get_execution_log`) and the
single-request reconciliation
(:meth:`RequestStore.reconcile_execution`) back their HTTP endpoints but
remain storage-layer methods as well.

Success responses are a single line of JSON followed by a trailing
newline. Acceptance, receipt lookup, the status read and a successful
reconcile render exactly ``request_id``, ``status`` and ``created_at``
(in that order); the same idempotent request and every lookup return
byte-identical bodies. The execution-log read renders exactly
``request_id`` and ``attempts``. The
listing read renders exactly ``items`` and ``next_cursor``, each item
rendering exactly ``request_id``, ``status`` and ``created_at``.
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
each of the four GET endpoints requires ``request:read`` and the target
tenant follows the existing ``X-Tenant-Id``/query rule; the
single-request reconciliation ``POST /requests/{request_id}/reconcile``
requires ``request:reconcile`` and its target tenant follows the same
existing ``X-Tenant-Id``/query rule. Authentication runs after
path/method routing (unknown paths stay 404, unsupported methods stay
405) but before payload validation and any storage access.
Tokens, roles and the configuration never enter a response, a raised
exception message, a log record, the database or any stored artifact.

No subject, scope, idempotency key, lease credential, worker identity,
database error text, SQL statement or filesystem path is ever placed in
a response, a log record or a raised exception message.
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
_RECONCILE_RESOURCE = "reconcile"
_TENANT_HEADER = "X-Tenant-Id"
_AUTHORIZATION_HEADER = "Authorization"
_BEARER_PREFIX = "Bearer "

# Reject oversized request bodies before they reach the database layer.
_MAX_BODY_BYTES = 1 << 20  # 1 MiB

_ROLE_SUBMIT = "request:submit"
_ROLE_READ = "request:read"
_ROLE_RECONCILE = "request:reconcile"
_ALLOWED_ROLES = frozenset({_ROLE_SUBMIT, _ROLE_READ, _ROLE_RECONCILE})

# Terminal attempt results, mirrored from the execution state machine so a
# corrupt or substituted store can never serialise another value.
_TERMINAL_RESULTS = frozenset({"completed", "failed"})

# The request lifecycle statuses the tenant-scoped listing accepts in its
# ``status`` filter and may serialise in an item.
_REQUEST_STATUSES = frozenset({"accepted", "processing", "completed", "failed"})

# The query parameters the GET /requests listing understands; anything
# else is an invalid request.
_LIST_QUERY_PARAMS = frozenset(
    {"tenant_id", "status", "created_from", "created_to", "cursor", "limit"}
)
_LIST_LIMIT_RE = re.compile(r"^[0-9]+$")

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
    values drawn from ``request:submit``, ``request:read`` and
    ``request:reconcile``. Tokens must be unique across principals. Any
    deviation -- including an unreadable or non-UTF-8 file, malformed
    JSON, a missing ``principals`` key or a principal missing/typing-wrong
    one of the required keys -- raises :class:`AuthConfigError` so the
    caller can refuse to bind.
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
        # Serves the read-only GET /requests/{request_id}/status endpoint.
        return self._ready().get_status(tenant_id, request_id)

    def list_requests(
        self,
        tenant_id,
        statuses=None,
        created_from=None,
        created_to=None,
        cursor=None,
        limit=None,
    ):
        # Serves the read-only GET /requests tenant-scoped listing.
        return self._ready().list_requests(
            tenant_id, statuses, created_from, created_to, cursor, limit
        )

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

    def transfer_claim(self, tenant_id, request_id, claim_token, lease_seconds):
        # The secure lease handover is storage-layer only; like the rest
        # of the execution orchestration it is never routed over HTTP.
        return self._ready().transfer_claim(
            tenant_id, request_id, claim_token, lease_seconds
        )

    def get_execution_log(self, tenant_id, request_id):
        # Serves the read-only GET /requests/{request_id}/execution-log
        # endpoint; strictly read-only, like get_status.
        return self._ready().get_execution_log(tenant_id, request_id)

    def reconcile_execution(self, tenant_id, request_id):
        # Backs the POST /requests/{request_id}/reconcile endpoint; the
        # store's atomic commit decides the unique reconciliation outcome.
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
                segment = path[len(_ITEM_PATH_PREFIX) :]
                # Empty or nested segments do not name a request.
                if segment and "/" not in segment:
                    return "item", segment
                # The two read-only observability sub-resources live under
                # a request id: /requests/{id}/status and
                # /requests/{id}/execution-log, alongside the single
                # reconciliation action /requests/{id}/reconcile. Deeper
                # nesting or any other suffix stays an unknown path (404).
                if "/" in segment:
                    item_id, suffix = segment.split("/", 1)
                    if item_id and "/" not in suffix:
                        if suffix == _STATUS_RESOURCE:
                            return "status", item_id
                        if suffix == _EXECUTION_LOG_RESOURCE:
                            return "execution_log", item_id
                        if suffix == _RECONCILE_RESOURCE:
                            return "reconcile", item_id
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
                # The collection accepts POST (acceptance) and GET (the
                # tenant-scoped listing); the item and both read-only
                # sub-resources are GET-only; the reconcile action is
                # POST-only.
                if kind == "collection":
                    allowed = "GET, POST"
                elif kind == "reconcile":
                    allowed = "POST"
                else:
                    allowed = "GET"
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
            kind, segment = self._route()
            if kind is None:
                self._reply_error(404, _NOT_FOUND)
                return
            if kind == "reconcile":
                assert segment is not None
                self._serve_reconcile(segment)
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
                # The tenant-scoped, paginated listing of accepted
                # requests; read-only like the item observations.
                self._serve_list()
                return
            if kind == "reconcile":
                # The reconciliation action is POST-only.
                self._reply_error(
                    405, _METHOD_NOT_ALLOWED, allowed="POST"
                )
                return
            # item (acceptance receipt), status and execution_log are the
            # three GET-only reads; authorization/tenant/id resolution and
            # the resulting error ordering are shared by all of them.
            assert segment is not None
            resolved = self._resolve_read(segment)
            if resolved is None:
                return
            tenant_id, request_id = resolved
            if kind == "item":
                self._serve_receipt(tenant_id, request_id)
            elif kind == "status":
                self._serve_status(tenant_id, request_id)
            else:
                self._serve_execution_log(tenant_id, request_id)

        def _resolve_read(self, segment: str) -> tuple[str, str] | None:
            """Authorize and resolve ``(tenant_id, request_id)`` for a GET.

            Thin wrapper over :meth:`_resolve_tenant_request` for the
            ``request:read`` role.
            """
            return self._resolve_tenant_request(segment, _ROLE_READ)

        def _resolve_tenant_request(
            self, segment: str, required_role: str
        ) -> tuple[str, str] | None:
            """Authorize and resolve ``(tenant_id, request_id)``.

            Returns ``None`` after already replying. Authentication runs
            before request-id validation and storage; with auth enabled the
            full tenant authorization completes before the id shape is even
            inspected, while the unauthenticated contract keeps its
            historical id-shape-before-tenant order.
            """
            principal = self._authorize(required_role)
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

        def _serve_receipt(self, tenant_id: str, request_id: str) -> None:
            try:
                record = store.get(tenant_id, request_id)
            except RequestNotFound:
                # Missing ids and cross-tenant lookups are indistinguishable.
                self._reply_error(404, _NOT_FOUND)
                return
            except ValueError:
                self._reply_error(400, _INVALID_REQUEST)
                return
            except _StorageUnavailable:
                _log.warning("request rejected: %s", _STORAGE_UNAVAILABLE)
                self._reply_error(503, _STORAGE_UNAVAILABLE)
                return
            except (sqlite3.Error, RuntimeError, OSError):
                _log.warning("request rejected: %s", _STORAGE_UNAVAILABLE)
                self._reply_error(503, _STORAGE_UNAVAILABLE)
                return
            self._reply_receipt(200, record)

        def _serve_status(self, tenant_id: str, request_id: str) -> None:
            try:
                record = store.get_status(tenant_id, request_id)
            except RequestNotFound:
                self._reply_error(404, _NOT_FOUND)
                return
            except ValueError:
                self._reply_error(400, _INVALID_REQUEST)
                return
            except _StorageUnavailable:
                _log.warning("request rejected: %s", _STORAGE_UNAVAILABLE)
                self._reply_error(503, _STORAGE_UNAVAILABLE)
                return
            except (sqlite3.Error, RuntimeError, OSError):
                # Corrupt persisted rows surface as fixed-text RuntimeErrors.
                _log.warning("request rejected: %s", _STORAGE_UNAVAILABLE)
                self._reply_error(503, _STORAGE_UNAVAILABLE)
                return
            self._reply_status(record)

        def _serve_execution_log(self, tenant_id: str, request_id: str) -> None:
            try:
                attempts = store.get_execution_log(tenant_id, request_id)
            except RequestNotFound:
                self._reply_error(404, _NOT_FOUND)
                return
            except ValueError:
                self._reply_error(400, _INVALID_REQUEST)
                return
            except _StorageUnavailable:
                _log.warning("request rejected: %s", _STORAGE_UNAVAILABLE)
                self._reply_error(503, _STORAGE_UNAVAILABLE)
                return
            except (sqlite3.Error, RuntimeError, OSError):
                # Corrupt attempt rows surface as fixed-text OSErrors.
                _log.warning("request rejected: %s", _STORAGE_UNAVAILABLE)
                self._reply_error(503, _STORAGE_UNAVAILABLE)
                return
            self._reply_execution_log(request_id, attempts)

        def _serve_reconcile(self, segment: str) -> None:
            # The single-request reconcile shares the read endpoints'
            # authorization and tenant/id resolution: authentication first,
            # then the tenant (header or query) and its match against the
            # principal, then request-id syntax. The reconcile-specific
            # empty-body gate runs only afterwards, so a wrong credential
            # never gets to probe ids or payload shape.
            resolved = self._resolve_tenant_request(segment, _ROLE_RECONCILE)
            if resolved is None:
                return
            tenant_id, request_id = resolved
            try:
                self._read_empty_body()
            except _BadRequest:
                # A rejected body has been consumed (or the connection is
                # marked for close when it cannot be) before the error.
                self._reply_error(400, _INVALID_REQUEST)
                return
            try:
                record = store.reconcile_execution(tenant_id, request_id)
            except RequestNotFound:
                # Missing ids and cross-tenant lookups are indistinguishable.
                self._reply_error(404, _NOT_FOUND)
                return
            except ValueError:
                # Defence in depth: the HTTP resolution above is
                # authoritative, but a rejected store call converges
                # nothing and maps to the same client error.
                self._reply_error(400, _INVALID_REQUEST)
                return
            except _StorageUnavailable:
                _log.warning("request rejected: %s", _STORAGE_UNAVAILABLE)
                self._reply_error(503, _STORAGE_UNAVAILABLE)
                return
            except (sqlite3.Error, RuntimeError, OSError):
                # A failed atomic commit or a corrupt execution record
                # surfaces as fixed-text RuntimeError/OSError; sqlite text
                # (locks, malformed images, paths) must never reach the
                # client, and the store guarantees no half-converged row.
                _log.warning("request rejected: %s", _STORAGE_UNAVAILABLE)
                self._reply_error(503, _STORAGE_UNAVAILABLE)
                return
            # The reconciled record has the identical fixed shape and
            # field order as the status read: request_id, status,
            # created_at, nothing else.
            self._reply_status(record)

        def _serve_list(self) -> None:
            # The tenant-scoped listing shares the read endpoints'
            # authorization and tenant resolution: authentication first,
            # then the tenant (header or query) and its match against the
            # principal, then query-parameter validation, then storage.
            principal = self._authorize(_ROLE_READ)
            if principal is None:
                return
            try:
                tenant_id = self._tenant_id()
            except _BadRequest:
                self._reply_error(400, _INVALID_REQUEST)
                return
            if not self._tenant_allowed(principal[0], tenant_id):
                return
            try:
                filters = self._list_filters()
            except _BadRequest:
                self._reply_error(400, _INVALID_REQUEST)
                return
            try:
                page = store.list_requests(tenant_id, **filters)
            except ValueError:
                # The store's fixed-text listing ValueError covers every
                # invalid filter, limit or cursor shape.
                self._reply_error(400, _INVALID_REQUEST)
                return
            except _StorageUnavailable:
                _log.warning("request rejected: %s", _STORAGE_UNAVAILABLE)
                self._reply_error(503, _STORAGE_UNAVAILABLE)
                return
            except (sqlite3.Error, RuntimeError, OSError):
                # Corrupt persisted rows surface as fixed-text OSErrors.
                _log.warning("request rejected: %s", _STORAGE_UNAVAILABLE)
                self._reply_error(503, _STORAGE_UNAVAILABLE)
                return
            self._reply_listing(page)

        def _list_filters(self) -> dict[str, object]:
            """Validate the listing query string into store arguments.

            Only ``tenant_id``, ``status``, ``created_from``,
            ``created_to``, ``cursor`` and ``limit`` may appear, each at
            most once (``tenant_id`` keeps its historical
            header-or-query resolution in ``_tenant_id``). ``status`` is
            a comma-separated list of distinct lifecycle statuses. Every
            other shape is a bad request; the store re-validates the
            values themselves as defence in depth.
            """
            params = parse_qs(urlsplit(self.path).query, keep_blank_values=True)
            if not set(params) <= _LIST_QUERY_PARAMS:
                raise _BadRequest("unknown query parameter")
            filters: dict[str, object] = {}
            for name in ("status", "created_from", "created_to", "cursor", "limit"):
                values = params.get(name)
                if values is None:
                    continue
                if len(values) != 1:
                    raise _BadRequest(f"duplicate {name}")
                value = values[0]
                if name == "status":
                    filters["statuses"] = self._parse_status_filter(value)
                elif name == "limit":
                    # Far more digits than the 1..1000 domain can ever
                    # hold is a bad request, not a storage fault (and an
                    # unbounded digit string must never reach int()).
                    if not _LIST_LIMIT_RE.match(value) or len(value) > 10:
                        raise _BadRequest("invalid limit")
                    filters["limit"] = int(value)
                elif not value:
                    raise _BadRequest(f"invalid {name}")
                else:
                    filters[name] = value
            return filters

        def _parse_status_filter(self, value: str) -> list[str]:
            if not value:
                raise _BadRequest("invalid status")
            statuses = value.split(",")
            if any(status not in _REQUEST_STATUSES for status in statuses):
                raise _BadRequest("invalid status")
            if len(set(statuses)) != len(statuses):
                raise _BadRequest("duplicate status")
            return statuses

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

        def _read_empty_body(self) -> None:
            """Require an absent or empty body on a parameterless POST.

            A missing ``Content-Length`` (and no transfer coding) or a
            declared length of zero means there is no body; anything else
            is a client error. A bounded non-empty body is drained first so
            the connection can still serve the next request; an unbounded,
            malformed or unreadable framing closes the connection instead
            of risking a desync.
            """
            # A coded body (chunked or any other transfer coding) is never
            # an empty body and cannot be drained safely here; reject it
            # regardless of any accompanying Content-Length.
            if self.headers.get("Transfer-Encoding") is not None:
                self.close_connection = True
                raise _BadRequest("body must be empty")
            raw_length = self.headers.get("Content-Length")
            if raw_length is None:
                return
            try:
                length = int(raw_length)
            except (TypeError, ValueError):
                self.close_connection = True
                raise _BadRequest("invalid content length")
            if length < 0:
                self.close_connection = True
                raise _BadRequest("invalid content length")
            if length == 0:
                return
            if length > _MAX_BODY_BYTES:
                # Leave the oversized tail unread and close the
                # connection so keep-alive cannot desync the next request.
                self.close_connection = True
                raise _BadRequest("body must be empty")
            try:
                self.rfile.read(length)
            except OSError:
                self.close_connection = True
                raise _BadRequest("unreadable body")
            raise _BadRequest("body must be empty")

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

        def _reply_status(self, record: dict[str, str]) -> None:
            # The current-status record has the identical fixed shape and
            # field order as the acceptance receipt; only the status value
            # differs. Reuse the same strict renderer.
            self._reply_receipt(200, record)

        def _reply_execution_log(
            self, request_id: str, attempts: list[dict[str, object]]
        ) -> None:
            if not isinstance(request_id, str) or not request_id:
                raise RuntimeError("malformed execution log from store")
            if not isinstance(attempts, list):
                raise RuntimeError("malformed execution log from store")
            rendered_attempts: list[dict[str, object]] = []
            for index, attempt in enumerate(attempts, start=1):
                rendered_attempts.append(self._project_attempt(attempt, index))
            body = (
                json.dumps(
                    {"request_id": request_id, "attempts": rendered_attempts},
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8")
            self._write_body(200, body)

        def _project_attempt(
            self, attempt: object, expected_number: int
        ) -> dict[str, object]:
            # Whitelist and re-render every field: even a store substitute
            # that returned extra keys could not leak a claim token, worker
            # identity, subject or scope into the body. Numbering and types
            # are re-checked so a corrupt row never serialises into a
            # partially-formed record.
            allowed = {
                "attempt_number",
                "claimed_at",
                "lease_expires_at",
                "result",
                "completed_at",
            }
            if not isinstance(attempt, dict) or set(attempt) != allowed:
                raise RuntimeError("malformed attempt from store")
            number = attempt["attempt_number"]
            claimed_at = attempt["claimed_at"]
            lease_expires_at = attempt["lease_expires_at"]
            result = attempt["result"]
            completed_at = attempt["completed_at"]
            if (
                not isinstance(number, int)
                or isinstance(number, bool)
                or number != expected_number
                or not isinstance(claimed_at, str)
                or not claimed_at
                or not isinstance(lease_expires_at, str)
                or not lease_expires_at
            ):
                raise RuntimeError("malformed attempt from store")
            if result is not None and (
                not isinstance(result, str) or result not in _TERMINAL_RESULTS
            ):
                raise RuntimeError("malformed attempt from store")
            if completed_at is not None and (
                not isinstance(completed_at, str) or not completed_at
            ):
                raise RuntimeError("malformed attempt from store")
            # result and completed_at are set together at finish time.
            if (result is None) != (completed_at is None):
                raise RuntimeError("malformed attempt from store")
            return {
                "attempt_number": number,
                "claimed_at": claimed_at,
                "lease_expires_at": lease_expires_at,
                "result": result,
                "completed_at": completed_at,
            }

        def _reply_listing(self, page: object) -> None:
            # Whitelist and re-render every field: even a store substitute
            # that returned extra keys could not leak a subject, a scope,
            # an idempotency key or any other request field into the body.
            # Shapes and types are re-checked so a corrupt page never
            # serialises into a partially-formed record.
            if not isinstance(page, dict) or set(page) != {"items", "next_cursor"}:
                raise RuntimeError("malformed listing from store")
            items = page["items"]
            next_cursor = page["next_cursor"]
            if not isinstance(items, list):
                raise RuntimeError("malformed listing from store")
            if next_cursor is not None and (
                not isinstance(next_cursor, str) or not next_cursor
            ):
                raise RuntimeError("malformed listing from store")
            rendered_items: list[dict[str, str]] = []
            for item in items:
                if not isinstance(item, dict) or set(item) != {
                    "request_id",
                    "status",
                    "created_at",
                }:
                    raise RuntimeError("malformed listing from store")
                request_id = item["request_id"]
                status = item["status"]
                created_at = item["created_at"]
                if (
                    not isinstance(request_id, str)
                    or not request_id
                    or not isinstance(status, str)
                    or status not in _REQUEST_STATUSES
                    or not isinstance(created_at, str)
                    or not created_at
                ):
                    raise RuntimeError("malformed listing from store")
                rendered_items.append(
                    {
                        "request_id": request_id,
                        "status": status,
                        "created_at": created_at,
                    }
                )
            body = (
                json.dumps(
                    {"items": rendered_items, "next_cursor": next_cursor},
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
