"""Optional bearer-token authentication and RBAC for the HTTP service.

An auth configuration is a UTF-8 JSON object read exactly once at
startup::

    {"principals": [
        {"token": "...", "tenant_id": "tenant-a",
         "roles": ["request:submit", "request:read"]}
    ]}

``token`` and ``tenant_id`` are non-empty strings and ``roles`` is a
non-empty array of distinct role names drawn from
``request:submit`` and ``request:read``. Duplicate tokens and any
shape or value deviation reject the configuration as a whole.

The parsed configuration lives only in process memory: token material
is never written to the database, a response, an exception message or a
log record.
"""

from __future__ import annotations

import json

__all__ = [
    "AuthConfig",
    "AuthConfigError",
    "load_auth_config",
    "ROLE_SUBMIT",
    "ROLE_READ",
]

ROLE_SUBMIT = "request:submit"
ROLE_READ = "request:read"

_ALLOWED_ROLES = frozenset({ROLE_SUBMIT, ROLE_READ})
_BEARER_PREFIX = "Bearer "
_INVALID = "auth_config_invalid"


class AuthConfigError(ValueError):
    """The auth configuration file is missing or non-compliant.

    The message is the fixed startup code only; it never carries the
    path, JSON text or token material.
    """


class Principal:
    """An authenticated caller: one tenant boundary and a set of roles."""

    __slots__ = ("tenant_id", "roles")

    def __init__(self, tenant_id: str, roles: frozenset[str]):
        self.tenant_id = tenant_id
        self.roles = roles


class AuthConfig:
    """Immutable in-memory token-to-principal map for one startup."""

    def __init__(self, principals: dict[str, tuple[str, frozenset[str]]]):
        self._principals = dict(principals)

    def principal(self, authorization_header: str | None) -> Principal | None:
        """Resolve an ``Authorization`` header to a principal.

        Returns ``None`` for a missing header, a malformed ``Bearer``
        credential or an unconfigured token; callers answer 401.
        """
        if not isinstance(authorization_header, str):
            return None
        if not authorization_header.startswith(_BEARER_PREFIX):
            return None
        token = authorization_header[len(_BEARER_PREFIX) :]
        if not token:
            return None
        match = self._principals.get(token)
        if match is None:
            return None
        tenant_id, roles = match
        return Principal(tenant_id, roles)


def load_auth_config(path: str) -> AuthConfig:
    """Read and validate *path* exactly once.

    Raises :class:`AuthConfigError` (fixed text ``auth_config_invalid``)
    for any missing/unreadable file, non-UTF-8 content, malformed JSON
    or non-compliant configuration.
    """
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except OSError:
        raise AuthConfigError(_INVALID) from None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise AuthConfigError(_INVALID) from None
    try:
        config = json.loads(text)
    except ValueError:
        raise AuthConfigError(_INVALID) from None
    return _build_config(config)


def _build_config(config: object) -> AuthConfig:
    # Fail closed: the configuration must be exactly the documented
    # object shape so an unknown key (a typo such as "role") cannot
    # silently weaken a principal.
    if not isinstance(config, dict) or set(config) != {"principals"}:
        raise AuthConfigError(_INVALID)
    entries = config["principals"]
    if not isinstance(entries, list):
        raise AuthConfigError(_INVALID)
    by_token: dict[str, tuple[str, frozenset[str]]] = {}
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {
            "token",
            "tenant_id",
            "roles",
        }:
            raise AuthConfigError(_INVALID)
        token = entry["token"]
        tenant_id = entry["tenant_id"]
        roles = entry["roles"]
        if not isinstance(token, str) or not token:
            raise AuthConfigError(_INVALID)
        if not isinstance(tenant_id, str) or not tenant_id:
            raise AuthConfigError(_INVALID)
        if not isinstance(roles, list) or not roles:
            raise AuthConfigError(_INVALID)
        if not all(isinstance(role, str) for role in roles):
            raise AuthConfigError(_INVALID)
        if any(role not in _ALLOWED_ROLES for role in roles):
            raise AuthConfigError(_INVALID)
        if len(set(roles)) != len(roles):
            raise AuthConfigError(_INVALID)
        if token in by_token:
            raise AuthConfigError(_INVALID)
        by_token[token] = (tenant_id, frozenset(roles))
    return AuthConfig(by_token)
