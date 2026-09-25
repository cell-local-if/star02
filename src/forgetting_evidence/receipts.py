"""Verifiable deletion receipts: format, commitments and authentication.

A deletion receipt is a compact, single-line JSON document (with a
trailing newline) that attests, after the fact, that a deletion request
reached its settled ``completed`` terminal state. It is deliberately
narrower than the store's own records:

* only business fields are ever carried -- never a subject, the original
  scope strings, an idempotency key, a worker, a credential, SQL or a
  filesystem path;
* the covered scope set is exposed only as a *scope commitment*: a
  64-character lowercase hex SHA-256 digest of the canonical scope list,
  so a verifier that already knows a scope set can confirm coverage
  without the receipt enumerating it;
* the settled execution is summarised as a *completion commitment* over
  the attempt that first reached completion (attempt number, stable
  terminal result category and UTC completion time);
* authenticity is an HMAC-SHA-256 tag produced with a key the caller
  keeps outside the database. The key material is used only to compute
  (and, during verification, compare) the tag: it is never stored, never
  written into a receipt, an exception or a log record.

The document uses a fixed field order and the same compact separators on
every render, so the first receipt issued for a request is byte-for-byte
identical to every later reissue. Timestamps are UTC RFC3339 strings,
digests are 64 lowercase hexadecimal characters, and the document ends
with exactly one ``\\n``.

Verification (:func:`parse_receipt`) is strict by construction: any value
that is not exactly the documented shape -- wrong type, wrong field set
or order, a non-canonical JSON encoding, a malformed timestamp, request
id or digest, trailing data -- is rejected with :class:`ValueError`
*before* the key or the tag is touched. Cryptographic mismatch is
reported separately as ``False`` by the store, never as an exception, so
a well-formed but unauthentic document can never be distinguished into
"exists" versus "forged" through an error channel.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime

__all__ = [
    "ReceiptUnavailable",
    "RECEIPT_VERSION",
    "validate_key",
    "is_rfc3339_utc",
    "scope_commitment",
    "completion_commitment",
    "build_receipt",
    "parse_receipt",
    "expected_tag",
]

# Receipt document version. Bumped only for an incompatible shape; the
# field is carried in the receipt so an old verifier never accepts a
# document whose semantics it does not understand.
RECEIPT_VERSION = 1

# Fixed document layout. Order is part of the contract: JSON objects are
# rendered (and accepted) in exactly this order, so rendering is
# deterministic and a reordered document fails parsing rather than being
# silently canonicalised.
_RECEIPT_FIELDS = (
    "receipt_version",
    "receipt_type",
    "tenant_id",
    "request_id",
    "accepted_at",
    "completed_at",
    "scope_commitment",
    "completion_commitment",
    "auth_tag",
)
_RECEIPT_TYPE = "deletion_confirmation"
_TAG_FIELD = "auth_tag"

# Every digest and tag in the document renders as 64 lowercase hex chars.
_HEX = "0123456789abcdef"
# Timestamps use the same fixed-width UTC RFC3339 shape as the rest of
# the store: six fractional digits and a trailing Z, e.g.
# 2026-01-01T00:00:00.000000Z (exactly 27 characters).
_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
_TIMESTAMP_LENGTH = 27


class ReceiptUnavailable(Exception):
    """Raised when no settled deletion receipt can yet be issued.

    Only a request that has reached ``completed`` with its winning
    execution attempt durably recorded is receipt-eligible; a request
    that is still accepted/processing or that finished ``failed`` raises
    this. Reissuing an already-persisted receipt never raises: the first
    document is returned idempotently.
    """


def _is_hex64(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in _HEX for char in value)
    )


def validate_key(key: object) -> bytes:
    """Validate and normalise the caller-held receipt key.

    The key must be a non-empty byte string (``bytes`` or
    ``bytearray``, but never ``bool`` or ``str``) that the caller stores
    outside this service. A missing, empty or wrong-typed value is
    caller error and raises :class:`ValueError`. The returned bytes are
    only ever fed to the HMAC; no copy is retained.
    """
    if isinstance(key, bool) or not isinstance(key, (bytes, bytearray)):
        raise ValueError("receipt key must be non-empty bytes")
    if not key:
        raise ValueError("receipt key must be non-empty bytes")
    return bytes(key)


def is_rfc3339_utc(value: object) -> bool:
    """Return whether *value* is the store's fixed UTC RFC3339 shape."""
    if not isinstance(value, str) or len(value) != _TIMESTAMP_LENGTH:
        return False
    # Fixed length plus a strict pattern parse both enforces the shape
    # and rejects impossible calendar/clock values (e.g. month 13).
    try:
        datetime.strptime(value, _TIMESTAMP_FORMAT)
    except ValueError:
        return False
    return True


def _is_request_id(value: object) -> bool:
    # The store assigns uuid4 request ids, but the receipt contract only
    # binds a non-empty identifier: the HMAC and the persisted-row
    # cross-check carry the authenticity, so the parser never hard-codes
    # an id format a future store version could change.
    return isinstance(value, str) and bool(value)


def scope_commitment(scopes_json: str) -> str:
    """Return the scope commitment for a canonical JSON scope list.

    The digest binds the canonical (sorted, compact-JSON) scope sequence
    exactly as persisted at acceptance, so scope ordering can never
    change the commitment.
    """
    return hashlib.sha256(scopes_json.encode("utf-8")).hexdigest()


def completion_commitment(
    attempt_number: int,
    result: str,
    completed_at: str,
) -> str:
    """Return the completion commitment for the winning attempt.

    The digest binds the stable terminal result category (never a worker,
    token or SQL text), the attempt that first completed and the UTC
    completion time, each length-prefixed so the preimage parses exactly
    one way.
    """
    digest = hashlib.sha256()
    for field in (str(attempt_number), result, completed_at):
        encoded = field.encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def _json_canonical(fields: dict[str, object]) -> bytes:
    # Insertion order is preserved; fixed separators and literal UTF-8
    # keep rendering byte-stable across machines and Python versions.
    return json.dumps(
        fields, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")


def _authenticated_preimage(fields: dict[str, object]) -> bytes:
    """Render the exact bytes the auth tag signs.

    Every authenticated field is serialised in fixed order without the
    tag itself and without the trailing newline; the tag therefore
    commits to the document content but not to itself.
    """
    ordered = {name: fields[name] for name in _RECEIPT_FIELDS if name != _TAG_FIELD}
    return _json_canonical(ordered)


def _hmac_hex(key: bytes, message: bytes) -> str:
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def build_receipt(
    tenant_id: str,
    request_id: str,
    accepted_at: str,
    completed_at: str,
    scope_digest: str,
    attempt_number: int,
    result: str,
    key: bytes,
) -> bytes:
    """Render the signed receipt document for one settled completion.

    The store validates every business argument before calling; the
    fields are defensively re-checked here so a malformed component is a
    :class:`ValueError` rather than a malformed document. The key is used
    only inside the HMAC and never appears in the result.
    """
    if (
        not isinstance(tenant_id, str)
        or not tenant_id
        or not _is_request_id(request_id)
        or not is_rfc3339_utc(accepted_at)
        or not is_rfc3339_utc(completed_at)
        or completed_at < accepted_at
        or not _is_hex64(scope_digest)
        or not isinstance(attempt_number, int)
        or isinstance(attempt_number, bool)
        or attempt_number < 1
        or result not in ("completed", "failed")
    ):
        raise ValueError("receipt is not valid")
    fields: dict[str, object] = {
        "receipt_version": RECEIPT_VERSION,
        "receipt_type": _RECEIPT_TYPE,
        "tenant_id": tenant_id,
        "request_id": request_id,
        "accepted_at": accepted_at,
        "completed_at": completed_at,
        "scope_commitment": scope_digest,
        "completion_commitment": completion_commitment(
            attempt_number, result, completed_at
        ),
    }
    fields[_TAG_FIELD] = _hmac_hex(key, _authenticated_preimage(fields))
    return _json_canonical(fields) + b"\n"


def parse_receipt(text: object) -> dict[str, object]:
    """Strictly parse a receipt document into its typed fields.

    Accepts only the exact compact, fixed-order rendering produced by
    :func:`build_receipt`, ending in exactly one newline. Returns the
    field dict with values already range-checked (version int, fixed
    type token, non-empty tenant, canonical request id, RFC3339 UTC
    times with completion no earlier than acceptance, two 64-hex
    commitments and a 64-hex tag). The tag is returned among the fields
    but *not* checked here. Every malformed document raises
    :class:`ValueError`; the function never writes and never consults
    the database.
    """
    if isinstance(text, bytes):
        try:
            raw = text.decode("utf-8")
        except UnicodeDecodeError:
            raise ValueError("receipt is not valid") from None
    elif isinstance(text, str):
        raw = text
    else:
        raise ValueError("receipt is not valid")
    if len(raw) < 2 or not raw.endswith("\n") or raw.count("\n") != 1:
        raise ValueError("receipt is not valid")
    body = raw[:-1]
    try:
        parsed = json.loads(body)
    except ValueError:
        raise ValueError("receipt is not valid") from None
    if not isinstance(parsed, dict):
        raise ValueError("receipt is not valid")
    if set(parsed) != set(_RECEIPT_FIELDS) or list(parsed) != list(_RECEIPT_FIELDS):
        raise ValueError("receipt is not valid")
    version = parsed["receipt_version"]
    if not isinstance(version, int) or isinstance(version, bool):
        raise ValueError("receipt is not valid")
    if version != RECEIPT_VERSION or parsed["receipt_type"] != _RECEIPT_TYPE:
        raise ValueError("receipt is not valid")
    tenant_id = parsed["tenant_id"]
    if not isinstance(tenant_id, str) or not tenant_id:
        raise ValueError("receipt is not valid")
    request_id = parsed["request_id"]
    if not _is_request_id(request_id):
        raise ValueError("receipt is not valid")
    accepted_at = parsed["accepted_at"]
    completed_at = parsed["completed_at"]
    if not is_rfc3339_utc(accepted_at) or not is_rfc3339_utc(completed_at):
        raise ValueError("receipt is not valid")
    if completed_at < accepted_at:
        raise ValueError("receipt is not valid")
    if not _is_hex64(parsed["scope_commitment"]):
        raise ValueError("receipt is not valid")
    if not _is_hex64(parsed["completion_commitment"]):
        raise ValueError("receipt is not valid")
    if not _is_hex64(parsed[_TAG_FIELD]):
        raise ValueError("receipt is not valid")
    # The bytes must be exactly the canonical rendering: any whitespace,
    # escaping, duplicate-key or ordering difference is a different,
    # invalid document (duplicate keys survive here because the raw body
    # still contains both occurrences).
    if body.encode("utf-8") != _json_canonical(parsed):
        raise ValueError("receipt is not valid")
    return parsed


def expected_tag(parsed: dict[str, object], key: bytes) -> str:
    """Recompute the tag a parsed receipt must carry under *key*."""
    return _hmac_hex(key, _authenticated_preimage(parsed))
