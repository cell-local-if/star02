"""SQLite-backed acceptance store for deletion requests.

The store records deletion requests without retaining any identifying
payload in logs, return values beyond the fixed receipt fields, or
exception messages. SQLite integrity conflicts are translated into the
module's own idempotency semantics and never surface to callers.

Two read shapes are offered deliberately:

* :meth:`RequestStore.get` is the *acceptance* query and returns the
  frozen ``accepted`` receipt exactly as it was at submission time, no
  matter how the request's status subsequently advances. This is the
  record served by the HTTP lookup and idempotent submission replay.
* :meth:`RequestStore.get_status` is the *status* query and returns the
  same fixed record shape (``request_id``, ``status``, ``created_at``)
  but with the request's current status. The ``created_at`` field always
  stays the original acceptance time.

Status advances through :meth:`RequestStore.transition` along the fixed
lifecycle ``accepted -> processing -> {completed, failed}`` and
``accepted -> failed``. ``completed`` and ``failed`` are terminal.
Re-issuing the status a request already holds is an idempotent no-op.

Execution orchestration lives on the same store, storage-layer only:

* :meth:`RequestStore.claim_next` atomically leases the oldest claimable
  request (accepted, or processing with an expired lease) to a worker,
  moving a first-time claim to ``processing`` and recording an append-only
  attempt row. It returns the request id, an unpredictable single-use
  claim token and the UTC lease expiry; the worker identity is validated
  but never persisted, and only a hash of the token is stored.
* :meth:`RequestStore.finish_claim` commits a terminal result for the
  live lease: the status change, its audit-chain event, the attempt
  result and the token release land in one transaction. Unknown, expired,
  released or foreign tokens raise :class:`ClaimConflict` unchanged.
* :meth:`RequestStore.get_execution_log` returns the attempt history
  (sequence, claim and expiry times, terminal result and completion
  time) with only strings, integers and nulls -- never a worker or token.
* :meth:`RequestStore.reconcile_execution` reports the existing status
  record and, within a single atomic transaction, converges a request
  whose lease can no longer be valid: unfinished attempts are compensated
  to ``failed`` (their UTC RFC3339 completion time written exactly once)
  and a non-terminal request is brought to ``failed``. Requests that are
  accepted, hold a live lease or have already reached a terminal state
  are returned unchanged, and reconcile itself never inserts a request,
  an attempt or a receipt.
* :meth:`RequestStore.reconcile_batch` applies the same convergence in
  tenant-scoped, resumable batches. The first call (no cursor) creates a
  persistent batch whose cursor position survives restarts; the same
  cursor resumes that batch from its committed position and keeps its
  batch identifier. ``accepted`` requests are skipped on the first scan
  without creating an attempt, receipt or status event, and each item's
  state, attempts, lease, batch row and cursor commit in one transaction.

Deletion receipts close the lifecycle with an externally verifiable
record, storage-layer only like the rest of the orchestration:

* :meth:`RequestStore.generate_receipt` issues the deletion receipt for
  a request whose deletion completed and whose execution record has
  settled (a terminal attempt recorded ``completed``; the earliest
  completion wins when several terminal attempts exist). The receipt is
  a single compact JSON line binding the tenant, request id, first
  acceptance time, final completion time, a scope commitment digest and
  a completing-attempt digest, plus an authentication tag keyed with a
  caller-held secret that never enters the database, the receipt, an
  exception or a log. The first receipt is persisted atomically;
  regenerating returns the stored bytes unchanged, whatever key is
  presented, and a corrupt stored record raises the fixed-text
  :class:`OSError` instead of being repaired or recomputed.
* :meth:`RequestStore.verify_receipt` authenticates a presented receipt
  text against the persisted record and the caller's key, returning
  ``True`` only on a complete match. A well-formed receipt whose fields,
  tag, times or tenant/request association were replaced returns
  ``False`` -- the request merely existing never substitutes for the
  authentication -- and verification never writes or repairs anything.
* :meth:`RequestStore.rotate_receipt_key` performs recoverable receipt
  key rotation, storage-layer only like the rest of the receipt
  capability. The first receipt generation registers the presented key
  as generation 1; when no generation exists yet the first rotation
  registers the retired key and the new key as generations 1 and 2 in
  one atomic commit. Every later rotation names the currently active
  key and its successor and promotes just that successor, returning the
  new generation number and its UTC effective time. Repeating the
  rotation that produced the active generation is idempotent and
  returns the first generation and time; a retired key, or the replay
  of an already superseded rotation pair, raises
  :class:`ReceiptKeyConflict` without changing any generation. Only
  irreversible key fingerprints, generations and times are persisted;
  old receipts keep verifying under the key generation that signed
  them, while a new receipt is only ever signed by the active key.

The lease boundary enforced by :meth:`claim_next` is deliberately
narrower than "every processing request whose latest timestamp is old":
a processing request is reclaimable after expiry only when its attempts
explain a genuine expired lease (at least one attempt whose latest lease
has expired and no open attempt still inside its lease). A processing
request that carries no attempt, or whose attempts are open without any
expired lease, is never claimed; only :meth:`reconcile_execution`
converges such records.

Every accepted request carries a persistent, append-only status timeline
in ``status_events``. Events are written in the same transaction as the
request row or status change they describe, so the final timeline entry
always matches the request's current status.

Each event additionally carries a tamper-evident ``chain_hash``: a
SHA-256 value binding the tenant, request, sequence number, status,
occurrence time and the previous event's hash. The hash of the final
event is also stored on the request row, so deleting, modifying,
inserting or reordering persisted events breaks verification. The hash
preimage is never exposed in return values, exceptions or logs.

A hash chain whose every value lives in the same database still trusts
the database: an attacker who can rewrite the rows can recompute every
link and the head from the stored, public event content and present a
self-consistent forgery. Each event therefore also carries an
``anchor_hash`` -- an independent, append-only cross-restart trust
anchor computed under an anchor key that never enters the database, a
receipt, a return value, an exception or a log. The anchor binds the
anchor sequence (a per-store gap-free total order), the event's own
chain link and the preceding anchor, so the anchors form a second
chain an in-database rewrite cannot regenerate. The anchor key is
supplied to the constructor as raw bytes/string or read from a
sidecar key file next to the database (generated on first open with
owner-only permissions); it lives outside the database file by
construction, and a database copied without that key can verify its
ordinary event links but never its anchors. Anchors are written in the
very same transaction as the request row (acceptance) or the status
change, attempt row and lease they accompany: a commit never lands
ordered events, the request head and the external anchor separately,
and a failed commit raises :class:`OSError` without leaving a record
that could be judged complete.

Full-chain verification (:meth:`RequestStore.verify_evidence`) is read
only and checks, together, the ordered event timeline (gap-free from
zero), the request association, the request-row head and current
status, every event anchor against the externally held anchor key and
the unbroken anchor sequence -- including after a rebuild on a fresh
process. Deleting, altering, inserting, reordering or substituting
events across requests or tenants fails, and so does a chain an
attacker recomputed together with replaced heads and anchors: without
the external anchor key the replacement anchors cannot authenticate.
A database written before anchors existed, a damaged anchor or head, a
head that disagrees with the anchored event, or an interrupted commit
all verify ``False``. :meth:`RequestStore.diagnose_chain` reports only
the fixed, detail-free reason such a chain is untrusted; it never
repairs, backfills, recomputes or overwrites any evidence.

Caller errors are always :class:`ValueError` (invalid parameters) or the
module's own domain exceptions; every database failure -- an unwritable
path, an uncreatable or corrupt file, an I/O or read/write error -- is
reported as a fixed-text :class:`OSError` that never embeds SQL, engine
text or a filesystem path.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import sqlite3
import struct
import threading
import time
import uuid
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone

__all__ = [
    "RequestStore",
    "IdempotencyConflict",
    "RequestNotFound",
    "InvalidStatusTransition",
    "ClaimConflict",
    "ReceiptUnavailable",
    "ReceiptKeyConflict",
]

_log = logging.getLogger(__name__)


class IdempotencyConflict(Exception):
    """Raised when an idempotency key is reused with a different payload."""


class RequestNotFound(Exception):
    """Raised when no request visible to the tenant matches the id."""


class InvalidStatusTransition(Exception):
    """Raised when a requested status change is unknown or not permitted."""


class ClaimConflict(Exception):
    """Raised when a claim cannot be acquired or finished as requested.

    Covers a finish/release presented with a token that is unknown, expired,
    already released or owned by another tenant, as well as a finish
    attempted against a request that no longer holds a live claim. The
    fixed message never identifies which condition applied, so the outcome
    can never be used to probe for requests, workers or claim tokens.
    """


class ReceiptUnavailable(Exception):
    """Raised when no deletion receipt can be issued for the request.

    The request exists and is visible to the tenant, but its deletion
    has not completed with a settled execution record: it is still
    accepted or processing, it failed, or no terminal attempt recorded
    the completed deletion. The fixed message never identifies which
    condition applied.
    """


class ReceiptKeyConflict(Exception):
    """Raised when a receipt key rotation cannot take effect as asked.

    The presented retired key is not the tenant's current active key,
    the presented rotation pair was already superseded by a later
    rotation, or a concurrent rotation committed a different successor
    first. The fixed message never identifies which condition applied
    and no generation is ever changed.
    """


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

# The composite primary key already indexes (tenant_id, request_id, seq),
# which serves both the ordered timeline read and the latest-event lookup.

# Append-only execution attempts. One row per lease acquisition: the first
# claim of an accepted request starts attempt 1, and every reclaim after a
# lease expires starts the next sequential attempt. Rows are never updated
# and never deleted, so a worker that lost its lease can never rewrite
# history. ``claimed_at``/``lease_expires_at`` are set at acquisition;
# ``result``/``completed_at`` stay NULL until finish_claim records the
# terminal outcome. No worker identity and no claim token is ever stored.
_CLAIM_TABLE = """
CREATE TABLE IF NOT EXISTS claim_attempts (
    tenant_id       TEXT NOT NULL,
    request_id      TEXT NOT NULL,
    attempt_number  INTEGER NOT NULL,
    claimed_at      TEXT NOT NULL,
    lease_expires_at TEXT NOT NULL,
    result          TEXT,
    completed_at    TEXT,
    PRIMARY KEY (tenant_id, request_id, attempt_number)
);
"""

# Drives the "pick the oldest live candidate" query without a table scan:
# only requests that may still be claimed (accepted, or processing whose
# latest lease has expired) are indexed, ordered by acceptance time then id.
_CLAIM_CANDIDATE_INDEX = """
CREATE INDEX IF NOT EXISTS idx_claim_candidates
    ON requests(tenant_id, created_at, request_id);
"""

# Live claim tokens. At most one row per request: claiming releases every
# prior token and finishing deletes the winning one. Only a salt-free SHA-256
# of the token is stored, so the database at rest never contains the secret
# the worker presents; a leaked file cannot be replayed as a live claim.
_CLAIM_TOKEN_TABLE = """
CREATE TABLE IF NOT EXISTS claim_tokens (
    tenant_id      TEXT NOT NULL,
    request_id     TEXT NOT NULL,
    attempt_number INTEGER NOT NULL,
    token_hash     TEXT NOT NULL,
    PRIMARY KEY (tenant_id, request_id)
);
"""

# Persistent reconcile batches. A batch is created by the first batch call
# for a tenant (cursor omitted) and survives restarts, so a caller that
# presents the same cursor again resumes from the durably committed
# position instead of restarting the sweep. ``position_created_at`` /
# ``position_request_id`` hold the keyset position (the last scanned row);
# both NULL means "before the first row". ``finished`` is 1 once the sweep
# has seen every row that existed when it ran out of candidates.
_BATCH_TABLE = """
CREATE TABLE IF NOT EXISTS reconcile_batches (
    batch_id            TEXT PRIMARY KEY,
    tenant_id           TEXT NOT NULL,
    position_created_at TEXT,
    position_request_id TEXT,
    finished            INTEGER NOT NULL DEFAULT 0
);
"""

# Per-item outcomes of a batch, one row per scanned request. Items are
# written in the same transaction as the status/attempt/lease effects of
# reconciling that request and the batch position update, so a crash can
# never leave a reconciled request without its batch bookkeeping (or vice
# versa) and a retry of the same cursor never rewrites a settled row.
_BATCH_ITEM_TABLE = """
CREATE TABLE IF NOT EXISTS reconcile_batch_items (
    batch_id    TEXT NOT NULL,
    seq         INTEGER NOT NULL,
    request_id  TEXT NOT NULL,
    status      TEXT NOT NULL,
    PRIMARY KEY (batch_id, seq)
);
"""

# Issued deletion receipts, at most one per request. ``receipt_json``
# holds the exact canonical text returned to the first caller (compact
# JSON plus the trailing newline), so a regeneration, a rebuilt instance
# or a restarted service always serves byte-identical content without
# ever recomputing it. Rows are inserted once and never updated or
# deleted by the store; the caller's authentication key is never stored.
_RECEIPT_TABLE = """
CREATE TABLE IF NOT EXISTS deletion_receipts (
    tenant_id    TEXT NOT NULL,
    request_id   TEXT NOT NULL,
    receipt_json TEXT NOT NULL,
    PRIMARY KEY (tenant_id, request_id)
);
"""

# Receipt authentication key generations, one row per key a tenant has
# ever registered, in registration order. Only an irreversible
# salt-free SHA-256 fingerprint is stored -- the key material itself
# never enters this table (or any other table, a return value, an
# exception or a log) -- so a database at rest cannot mint or verify
# receipts even if it leaks. The highest generation is the active key:
# new receipts are minted with it alone, while every older generation
# stays on record solely so receipts signed before a rotation can
# still be verified. ``effective_at`` is the UTC time the generation
# became effective (the first receipt-generation time for generation 1
# of a bootstrapped tenant, otherwise the rotation commit time). Rows
# are inserted once and never updated or deleted.
_RECEIPT_KEY_TABLE = """
CREATE TABLE IF NOT EXISTS receipt_keys (
    tenant_id    TEXT NOT NULL,
    generation   INTEGER NOT NULL,
    key_fingerprint TEXT NOT NULL,
    effective_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, generation)
);
"""

# Each fingerprint can belong to exactly one generation of a tenant:
# registering a key that is already on record, or rotating back to a
# retired key, must be rejected as a key conflict rather than silently
# aliasing two generations. The same key text under different tenants
# is independent and therefore allowed.
_RECEIPT_KEY_FINGERPRINT_INDEX = """
CREATE UNIQUE INDEX IF NOT EXISTS idx_receipt_keys_tenant_fingerprint
    ON receipt_keys(tenant_id, key_fingerprint);
"""

# Cross-restart trust anchors, one row per anchored event. ``anchor_seq``
# is a per-store, gap-free total order assigned from the anchor head row
# inside the same transaction that lands the event, so the anchors form
# their own append-only chain across requests and tenants. The event's
# own chain link is carried redundantly as ``event_hash`` so an anchor
# row is self-describing. ``anchor_hash`` is an HMAC-SHA256 over the
# anchor sequence, the event's chain link and the previous anchor hash,
# keyed with the externally held anchor key -- never with anything
# stored in this database -- so an attacker who can rewrite every public
# row still cannot mint a replacement anchor that verifies. Rows are
# inserted once and never updated or deleted by the store; the key
# material itself is never persisted here.
_ANCHOR_TABLE = """
CREATE TABLE IF NOT EXISTS chain_anchors (
    anchor_seq   INTEGER NOT NULL PRIMARY KEY,
    tenant_id    TEXT NOT NULL,
    request_id   TEXT NOT NULL,
    event_seq    INTEGER NOT NULL,
    event_hash   TEXT NOT NULL,
    anchor_hash  TEXT NOT NULL
);
"""

# Lookup of every anchor for one request timeline, in event order.
_ANCHOR_EVENT_INDEX = """
CREATE INDEX IF NOT EXISTS idx_chain_anchors_event
    ON chain_anchors(tenant_id, request_id, event_seq);
"""

# The anchor head: a single row holding the sequence number and hash of
# the latest anchor. It is created lazily (create-if-absent) inside the
# first anchored write's transaction -- the store never writes at open
# time -- and read and advanced inside the same transaction as every
# later event and anchor row, so a crash can never leave an anchor
# written without its head (or vice versa). A database written before
# anchors existed has no head row and no anchor rows; historical events
# are never re-anchored (that would be a backfill over evidence), so a
# pre-anchor database honestly verifies untrusted instead of being
# silently re-anchored.
_ANCHOR_HEAD_TABLE = """
CREATE TABLE IF NOT EXISTS chain_anchor_head (
    id           INTEGER NOT NULL PRIMARY KEY CHECK (id = 1),
    anchor_seq   INTEGER NOT NULL,
    anchor_hash  TEXT NOT NULL
);
"""

# Column probes used to upgrade database files created before chain
# hashes existed. The upgrade is purely additive (nullable columns plus a
# one-time backfill derived from the already-persisted timeline); it never
# overwrites existing chain evidence.
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

# Fixed, detail-free text for every storage-layer failure. It must never
# embed a SQL statement, the engine's own error text or a filesystem path.
_STORAGE_MESSAGE = "request store is unavailable"


def _storage_failure() -> OSError:
    """Build the single storage error callers are ever allowed to see."""
    return OSError(_STORAGE_MESSAGE)

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

# Execution leasing. A claim is held for at most 3600 seconds; a lease that
# has expired makes the request claimable again, starting a fresh attempt.
_MIN_LEASE_SECONDS = 1
_MAX_LEASE_SECONDS = 3600
# Terminal outcomes finish_claim is allowed to record.
_TERMINAL_RESULTS = frozenset({_STATUS_COMPLETED, _STATUS_FAILED})
# Claim tokens are presented as a fixed-width, URL-safe opaque secret. They
# are generated with the CSPRNG, returned exactly once at acquisition, and
# never persisted, logged or echoed back.
_TOKEN_BYTES = 32
# Fixed, detail-free text for every claim failure.
_CLAIM_CONFLICT_MESSAGE = "claim conflict"

# Batch reconciliation. A batch sweeps the tenant's requests in stable
# (created_at, request_id) order; each call processes at most ``limit``
# reconcilable items. The default and the upper bound keep a single call
# bounded without letting a caller ask for an unbounded sweep.
_DEFAULT_BATCH_LIMIT = 100
_MAX_BATCH_LIMIT = 1000
# Opaque cursor format: a fixed version prefix plus base64url(JSON) carrying
# only the batch id and the item count it was issued at. The authoritative
# position always lives in reconcile_batches; the cursor only identifies
# which persisted batch to resume. Anything outside this exact shape --
# wrong prefix, bad padding, foreign JSON, unknown or cross-tenant batch --
# is an invalid cursor and raises ValueError without touching storage.
_CURSOR_PREFIX = "rc1."
_B64URL_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)


def _require_batch_limit(value: object) -> int:
    """Validate a batch limit: a non-boolean int in 1..1000."""
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError("limit must be an integer between 1 and 1000")
    if not 1 <= value <= _MAX_BATCH_LIMIT:
        raise ValueError("limit must be an integer between 1 and 1000")
    return value


def _encode_cursor(batch_id: str, position: int) -> str:
    """Render the opaque cursor for a batch at a given item count."""
    payload = json.dumps(
        {"v": 1, "b": batch_id, "n": position},
        separators=(",", ":"),
    ).encode("utf-8")
    return _CURSOR_PREFIX + base64.urlsafe_b64encode(payload).decode("ascii")


def _decode_cursor(value: object) -> tuple[str, int]:
    """Parse and strictly validate an opaque cursor.

    Every malformed value -- non-string, empty, wrong prefix, bad
    base64url, foreign JSON shape, wrong types -- raises :class:`ValueError`
    identically, so the cursor format can never be probed through
    distinguishable failures.
    """
    if not isinstance(value, str) or not value.startswith(_CURSOR_PREFIX):
        raise ValueError("cursor is not valid")
    body = value[len(_CURSOR_PREFIX) :]
    if (
        not body
        or len(body) % 4 != 0
        or any(char not in _B64URL_CHARS and char != "=" for char in body)
    ):
        raise ValueError("cursor is not valid")
    try:
        payload = json.loads(base64.urlsafe_b64decode(body.encode("ascii")))
    except (ValueError, binascii.Error):
        raise ValueError("cursor is not valid") from None
    if not isinstance(payload, dict) or set(payload) != {"v", "b", "n"}:
        raise ValueError("cursor is not valid")
    version = payload["v"]
    batch_id = payload["b"]
    position = payload["n"]
    if (
        # bool is a subclass of int and 1.0 == 1: only the exact integer
        # version 1 names the known cursor format.
        not isinstance(version, int)
        or isinstance(version, bool)
        or version != 1
        or not isinstance(batch_id, str)
        or not batch_id
        or not isinstance(position, int)
        or isinstance(position, bool)
        or position < 0
    ):
        raise ValueError("cursor is not valid")
    return batch_id, position


def _require_lease_seconds(value: object) -> int:
    """Validate a lease duration: a non-boolean int in 1..3600."""
    # bool is a subclass of int; a boolean lease is caller error, not a
    # 0/1 second lease.
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError("lease_seconds must be an integer between 1 and 3600")
    if not _MIN_LEASE_SECONDS <= value <= _MAX_LEASE_SECONDS:
        raise ValueError("lease_seconds must be an integer between 1 and 3600")
    return value


def _require_result(value: object) -> str:
    """Validate the terminal result handed to finish_claim."""
    if not isinstance(value, str) or value not in _TERMINAL_RESULTS:
        raise ValueError("result must be 'completed' or 'failed'")
    return value


def _new_claim_token() -> str:
    """Return an unpredictable, single-use claim token."""
    return secrets.token_urlsafe(_TOKEN_BYTES)


def _claim_conflict() -> ClaimConflict:
    """Build the single, detail-free claim error callers ever see."""
    return ClaimConflict(_CLAIM_CONFLICT_MESSAGE)


def _require_nonempty_str(value: object, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _require_identifier(value: object) -> str:
    """Validate a request id, mapping every malformed value to not-found.

    Unlike the other arguments a bad request id must raise
    :class:`RequestNotFound` rather than :class:`ValueError`, so the
    validation layer can never be used as an oracle for which ids exist.
    """
    if not isinstance(value, str) or not value:
        raise RequestNotFound("request not found")
    return value


def _normalize_scopes(scopes: object) -> list[str]:
    # Strings, bytes and mappings are iterable but are not scope sequences.
    if isinstance(scopes, (str, bytes)) or isinstance(scopes, Mapping):
        raise ValueError("scopes must be a non-empty sequence of distinct strings")
    try:
        items = list(scopes)  # type: ignore[arg-type]
    except TypeError as exc:
        raise ValueError("scopes must be a non-empty sequence of distinct strings") from exc
    # Every element must be a non-empty string: an empty element is as
    # invalid as a non-string one, and both are rejected before storage.
    if not items or not all(isinstance(item, str) and item for item in items):
        raise ValueError("scopes must be a non-empty sequence of distinct strings")
    if len(set(items)) != len(items):
        raise ValueError("scopes must be a non-empty sequence of distinct strings")
    # Canonical order so scope ordering never affects comparison.
    return sorted(items)


def _format_rfc3339(moment: datetime) -> str:
    """Format an aware UTC datetime as RFC3339 with a fixed ``Z`` suffix.

    Microseconds are always emitted (six digits) so that two timestamps
    sort lexicographically in chronological order even when one lands on
    a whole second. ``isoformat`` drops the fractional part on a zero
    microsecond value, which would otherwise make ``...:00Z`` sort after
    ``...:00.000001Z`` textually.
    """
    return moment.astimezone(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _utc_now_rfc3339() -> str:
    return _format_rfc3339(datetime.now(timezone.utc))


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


# -- cross-restart trust anchors ---------------------------------------

# Fixed, domain-separated predecessor of the first anchor. It is derived
# from a constant rather than from anything in the database, so a forged
# genesis anchor cannot be made to chain onto a conveniently chosen
# predecessor the database itself contains.
_ANCHOR_GENESIS_HASH = hashlib.sha256(
    b"forgetting-evidence/trust-anchor/genesis/v1"
).hexdigest()

# The externally held anchor key lives in a sidecar file next to the
# database, never inside the database. Random material generated by the
# store is always this many bytes; a caller-supplied key may be any
# non-empty string/byte string.
_ANCHOR_KEY_BYTES = 32
_ANCHOR_KEY_SUFFIX = ".anchor-key"

# Fixed, detail-free reason codes reported by diagnose_chain(). They name
# only *which structural check* failed -- never a value, a key, a tenant,
# a SQL statement or a path -- so the report cannot aid a forgery.
_DIAG_EVENT_CHAIN = "event_chain_invalid"
_DIAG_HEAD = "request_head_mismatch"
_DIAG_MISSING_ANCHORS = "anchors_missing"
_DIAG_ANCHOR_COUNT = "anchor_event_mismatch"
_DIAG_ANCHOR_SEQUENCE = "anchor_sequence_broken"
_DIAG_ANCHOR_HEAD = "anchor_head_mismatch"
_DIAG_ANCHOR_MAC = "anchor_authentication_failed"


def _anchor_mac(
    key: bytes,
    anchor_seq: int,
    tenant_id: str,
    request_id: str,
    event_seq: int,
    event_hash: str,
    predecessor: str,
) -> str:
    """Authenticate one trust anchor under the external anchor key.

    HMAC-SHA256 over length-prefixed fields: the store-wide anchor
    sequence, the owning tenant and request, the per-request event
    sequence, the event's own chain link and the preceding anchor hash.
    The key is held outside the database and never persisted with the
    data it authenticates, so the anchors cannot be regenerated from
    anything an in-database attacker can read or rewrite.
    """
    mac = hmac.new(key, digestmod=hashlib.sha256)
    for field in (
        str(anchor_seq),
        tenant_id,
        request_id,
        str(event_seq),
        event_hash,
        predecessor,
    ):
        encoded = field.encode("utf-8")
        mac.update(struct.pack(">Q", len(encoded)))
        mac.update(encoded)
    return mac.hexdigest()


def _anchor_sidecar_path(db_path: str) -> str:
    """Return the external anchor-key path for a file database path."""
    return os.path.join(
        os.path.dirname(os.path.abspath(db_path)),
        "." + os.path.basename(db_path) + _ANCHOR_KEY_SUFFIX,
    )


def _write_anchor_key_file(path: str, material: bytes) -> None:
    """Create the anchor-key sidecar exclusively, with owner-only mode.

    A single ``O_CREAT|O_EXCL`` open is the atomic create-if-absent: it
    fails with :class:`FileExistsError` when another creator won, and it
    never truncates an existing key. The brief window in which the file
    exists but is not yet fully written is covered by the bounded
    re-read in :func:`_adopt_existing_anchor_key`; a crash inside the
    window leaves an empty sidecar that is treated as damaged trust
    material (fixed-text :class:`OSError`), never silently replaced.
    Every filesystem failure becomes the fixed-text storage error; the
    key bytes themselves are never placed in that error or a log.
    """
    try:
        fd = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
    except FileExistsError:
        raise
    except OSError:
        raise _storage_failure() from None
    try:
        written = 0
        while written < len(material):
            written += os.write(fd, material[written:])
        os.fsync(fd)
    except OSError:
        raise _storage_failure() from None
    finally:
        try:
            os.close(fd)
        except OSError:
            raise _storage_failure() from None


# Bounded wait for a concurrent first-opener to finish publishing the
# sidecar: after losing the atomic create race the winner's link exists
# while its data may not yet be observable on every shared filesystem.
# The retry window is short and never masks a persistently empty/damaged
# sidecar (which keeps raising the fixed-text storage error afterwards).
_ANCHOR_KEY_READ_ATTEMPTS = 50
_ANCHOR_KEY_READ_DELAY_S = 0.01


def _adopt_existing_anchor_key(
    path: str, caller_material: bytes | None
) -> bytes:
    """Read a sidecar another opener just won the race to publish.

    Retries briefly while the winner's linked file is still appearing,
    then enforces a caller-supplied key match. A file that stays empty
    or unreadable past the bounded window is damaged trust material and
    raises the fixed-text :class:`OSError` like any other storage fault.
    """
    last_error: OSError | None = None
    for _ in range(_ANCHOR_KEY_READ_ATTEMPTS):
        try:
            with open(path, "rb") as handle:
                existing = handle.read()
        except FileNotFoundError:
            # The winner publishes with an exclusive create, so this is
            # only the tiny pre-create window; wait for it.
            existing = b""
        except OSError as exc:
            last_error = exc
            existing = b""
        if existing:
            if caller_material is not None and not hmac.compare_digest(
                existing, caller_material
            ):
                raise _storage_failure()
            return existing
        time.sleep(_ANCHOR_KEY_READ_DELAY_S)
    raise _storage_failure() from last_error



def _resolve_anchor_key(
    db_path: str, anchor_key: str | bytes | None
) -> bytes:
    """Resolve the external trust-anchor key for this store.

    A non-empty ``str``/``bytes`` *anchor_key* is the caller-held key:
    it is used directly and, for a file database, matched against (or
    first written to) the owner-only sidecar so the key survives
    restarts outside the database. ``None`` loads the existing sidecar
    or generates fresh random material on first open. ``:memory:``
    stores keep an instance-private key (their data never leaves the
    process). A mismatched explicit key, an unreadable/empty sidecar or
    a sidecar that cannot be created is the fixed-text
    :class:`OSError`; an empty or wrong-typed argument is
    :class:`ValueError`. The material never enters the database, a
    return value beyond this method, an exception or a log.
    """
    if anchor_key is None:
        material: bytes | None = None
    elif isinstance(anchor_key, str):
        if not anchor_key:
            raise ValueError("anchor_key must be a non-empty string")
        material = anchor_key.encode("utf-8")
    elif isinstance(anchor_key, bytes):
        if not anchor_key:
            raise ValueError("anchor_key must be a non-empty byte string")
        material = anchor_key
    else:
        raise ValueError("anchor_key must be a string or bytes")

    if db_path == ":memory:":
        # An in-memory database is process-private; there is no file to
        # anchor across restarts, so an ephemeral random key is used when
        # the caller supplied none.
        return material if material is not None else secrets.token_bytes(
            _ANCHOR_KEY_BYTES
        )

    sidecar = _anchor_sidecar_path(db_path)
    if os.path.exists(sidecar):
        # The adoption helper also enforces an explicit-key match and
        # tolerates the tiny window in which another opener's freshly
        # created sidecar is present but not yet fully written.
        return _adopt_existing_anchor_key(sidecar, material)
    caller_supplied = material is not None
    if material is None:
        material = secrets.token_bytes(_ANCHOR_KEY_BYTES)
    try:
        _write_anchor_key_file(sidecar, material)
    except FileExistsError:
        # Another opener sharing the database generated the sidecar
        # first; its key is the database's key. A caller-supplied key
        # that differs is a genuine mismatch; a generated one simply
        # loses the race and the persisted key is adopted.
        return _adopt_existing_anchor_key(
            sidecar, material if caller_supplied else None
        )
    return material


# -- deletion receipts -------------------------------------------------

# Fixed, detail-free text for every receipt-availability rejection.
_RECEIPT_UNAVAILABLE_MESSAGE = "receipt is not available"

# Fixed, detail-free text for every rejected key rotation. It never
# says which key or which generation was involved, so the outcome can
# never be used to probe which keys a tenant has registered.
_RECEIPT_KEY_CONFLICT_MESSAGE = "receipt key conflict"

# The receipt is a single compact JSON object with exactly these fields
# in exactly this order, followed by a trailing newline. Every value is
# a string; the digests and the tag are 64 lowercase hex characters and
# the timestamps are UTC RFC3339. The object carries only business
# fields -- never a subject, raw scope, idempotency key, worker,
# credential, SQL text or path.
_RECEIPT_FIELDS = (
    "tenant_id",
    "request_id",
    "created_at",
    "completed_at",
    "scope_digest",
    "attempt_digest",
    "tag",
)
# The fields the authentication tag binds (everything but the tag).
_RECEIPT_TAG_FIELDS = _RECEIPT_FIELDS[:-1]

# Shape of the UTC RFC3339 timestamps the store emits (and accepts back
# when parsing a presented receipt): seconds precision with an optional
# fraction and a ``Z`` or numeric offset suffix.
_RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$"
)


def _scope_digest(tenant_id: str, request_id: str, scopes: list[str]) -> str:
    """Commit to the request's scope set without revealing it.

    The digest binds the tenant, the request and each canonical
    (sorted) scope with the same length-prefixed encoding as the audit
    chain, so no concatenation can be re-parsed two ways. The preimage
    is never persisted on the receipt or returned.
    """
    digest = hashlib.sha256()
    for field in [tenant_id, request_id, *scopes]:
        encoded = field.encode("utf-8")
        digest.update(struct.pack(">Q", len(encoded)))
        digest.update(encoded)
    return digest.hexdigest()


def _attempt_digest(
    tenant_id: str,
    request_id: str,
    attempt: dict[str, object],
) -> str:
    """Commit to the completing execution attempt.

    Binds the tenant, request, attempt number, claim and lease-expiry
    times, terminal result and completion time. No worker identity or
    claim token is ever part of the preimage (neither is persisted).
    """
    digest = hashlib.sha256()
    fields = (
        tenant_id,
        request_id,
        str(attempt["attempt_number"]),
        attempt["claimed_at"],
        attempt["lease_expires_at"],
        attempt["result"],
        attempt["completed_at"],
    )
    for field in fields:
        encoded = str(field).encode("utf-8")
        digest.update(struct.pack(">Q", len(encoded)))
        digest.update(encoded)
    return digest.hexdigest()


def _receipt_tag(key: str, fields: dict[str, str]) -> str:
    """Compute the receipt's authentication tag under the caller's key.

    HMAC-SHA256 over the length-prefixed business fields, keyed with a
    secret the caller keeps outside the database. The key is used here
    only: it is never persisted, returned, logged or placed in an
    exception message.
    """
    mac = hmac.new(key.encode("utf-8"), digestmod=hashlib.sha256)
    for name in _RECEIPT_TAG_FIELDS:
        encoded = fields[name].encode("utf-8")
        mac.update(struct.pack(">Q", len(encoded)))
        mac.update(encoded)
    return mac.hexdigest()


def _key_fingerprint(key: str) -> str:
    """Return the irreversible, salt-free fingerprint of a receipt key.

    Only this SHA-256 digest is ever persisted; the key material stays
    with the caller. The same fingerprint construction is used at
    generation, rotation and lookup, so a presented key matches the
    generation it registered byte-for-byte without the key being
    stored.
    """
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def _render_receipt(fields: dict[str, str]) -> str:
    """Render the canonical receipt text: compact JSON, fixed field
    order, exactly one trailing newline."""
    ordered = {name: fields[name] for name in _RECEIPT_FIELDS}
    return json.dumps(ordered, ensure_ascii=False, separators=(",", ":")) + "\n"


def _parse_receipt_text(text: object) -> dict[str, str]:
    """Parse and strictly validate a presented receipt text.

    Every malformed value -- non-string, unparsable JSON, a missing or
    extra field, a non-string value, a malformed timestamp or a digest
    or tag that is not 64 lowercase hex characters -- raises
    :class:`ValueError` identically, so the format can never be probed
    through distinguishable failures.
    """
    if not isinstance(text, str) or not text:
        raise ValueError("receipt must be a non-empty string")
    try:
        parsed = json.loads(text)
    except (ValueError, RecursionError):
        raise ValueError("receipt is not valid") from None
    if not isinstance(parsed, dict) or set(parsed) != set(_RECEIPT_FIELDS):
        raise ValueError("receipt is not valid")
    fields: dict[str, str] = {}
    for name in _RECEIPT_FIELDS:
        value = parsed[name]
        if not isinstance(value, str) or not value:
            raise ValueError("receipt is not valid")
        fields[name] = value
    for name in ("created_at", "completed_at"):
        if not _RFC3339_RE.match(fields[name]):
            raise ValueError("receipt is not valid")
    for name in ("scope_digest", "attempt_digest", "tag"):
        if not _is_chain_hash(fields[name]):
            raise ValueError("receipt is not valid")
    return fields


class RequestStore:
    """Persist and retrieve accepted deletion requests."""

    def __init__(
        self,
        db_path: str | os.PathLike[str],
        anchor_key: str | bytes | None = None,
    ):
        # Validate the path before touching the filesystem: an empty or
        # non-string path is caller error (ValueError), never a storage
        # fault, and must not create directories.
        if isinstance(db_path, os.PathLike):
            db_path = os.fspath(db_path)
        if not isinstance(db_path, str) or not db_path:
            raise ValueError("storage path must be a non-empty string")
        self._db_path = db_path
        # In-process serialization; the unique index additionally guards
        # other processes sharing the same database file.
        self._write_lock = threading.Lock()
        try:
            if self._db_path == ":memory:":
                self._mem_conn: sqlite3.Connection | None = self._open_connection()
            else:
                self._mem_conn = None
                parent = os.path.dirname(os.path.abspath(self._db_path))
                os.makedirs(parent, exist_ok=True)
            # The external anchor key is resolved after the parent
            # directory exists and before any table is created: it is the
            # one piece of trust material that deliberately lives outside
            # the database (a caller-held key or an owner-only sidecar),
            # so anchors written below cannot be regenerated from the
            # database alone.
            self._anchor_key = _resolve_anchor_key(self._db_path, anchor_key)
        except sqlite3.Error:
            raise _storage_failure() from None
        except OSError:
            # makedirs/connect errors embed the offending path; replace
            # them with the fixed-text storage error. (The anchor-key
            # resolver already raises the same fixed-text error.)
            raise _storage_failure() from None
        conn = self._connect()
        try:
            try:
                conn.execute(_SCHEMA)
                conn.execute(_UNIQUE_TENANT_KEY)
                conn.execute(_EVENT_TABLE)
                conn.execute(_CLAIM_TABLE)
                conn.execute(_CLAIM_TOKEN_TABLE)
                conn.execute(_CLAIM_CANDIDATE_INDEX)
                conn.execute(_BATCH_TABLE)
                conn.execute(_BATCH_ITEM_TABLE)
                conn.execute(_RECEIPT_TABLE)
                conn.execute(_RECEIPT_KEY_TABLE)
                conn.execute(_RECEIPT_KEY_FINGERPRINT_INDEX)
                conn.execute(_ANCHOR_TABLE)
                conn.execute(_ANCHOR_EVENT_INDEX)
                conn.execute(_ANCHOR_HEAD_TABLE)
                self._migrate_schema(conn)
            except sqlite3.Error:
                raise _storage_failure() from None
        finally:
            self._release(conn)

    def _migrate_schema(self, conn: sqlite3.Connection) -> None:
        """Add chain columns to a database written by an older version.

        The upgrade is additive and runs at most once: the columns start
        nullable, existing events are backfilled in sequence order, and
        each request head is anchored at its final event. Existing chain
        values are never recomputed or overwritten.
        """
        if conn.execute(_REQUEST_CHAIN_COLUMN).fetchone() and conn.execute(
            _EVENT_CHAIN_COLUMN
        ).fetchone():
            return
        with self._write_lock:
            try:
                conn.execute("BEGIN IMMEDIATE")
                # Re-probe inside the transaction: another process may
                # have completed the upgrade while we waited on the lock.
                if not conn.execute(_REQUEST_CHAIN_COLUMN).fetchone():
                    conn.execute("ALTER TABLE requests ADD COLUMN chain_hash TEXT")
                if not conn.execute(_EVENT_CHAIN_COLUMN).fetchone():
                    conn.execute(
                        "ALTER TABLE status_events ADD COLUMN chain_hash TEXT"
                    )
                current_request: tuple[str, str] | None = None
                predecessor = _GENESIS_PREDECESSOR
                event_rows = conn.execute(
                    "SELECT tenant_id, request_id, seq, status, occurred_at "
                    "FROM status_events ORDER BY tenant_id, request_id, seq"
                ).fetchall()
                for tenant_id, request_id, seq, status, occurred_at in event_rows:
                    key = (tenant_id, request_id)
                    if key != current_request:
                        current_request = key
                        predecessor = _GENESIS_PREDECESSOR
                    link = _chain_hash(
                        tenant_id, request_id, seq, status, occurred_at, predecessor
                    )
                    conn.execute(
                        "UPDATE status_events SET chain_hash = ? "
                        "WHERE tenant_id = ? AND request_id = ? AND seq = ?",
                        (link, tenant_id, request_id, seq),
                    )
                    predecessor = link
                # Anchor each request head at its final event. A request
                # with no events keeps NULL and fails verification rather
                # than receiving a fabricated anchor.
                conn.execute(
                    "UPDATE requests SET chain_hash = ( "
                    "SELECT e.chain_hash FROM status_events e "
                    "WHERE e.tenant_id = requests.tenant_id "
                    "  AND e.request_id = requests.request_id "
                    "ORDER BY e.seq DESC LIMIT 1 "
                    ") WHERE chain_hash IS NULL"
                )
                conn.execute("COMMIT")
            except sqlite3.Error:
                try:
                    conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise _storage_failure() from None

    def _open_connection(self) -> sqlite3.Connection:
        try:
            conn = sqlite3.connect(
                self._db_path,
                timeout=_BUSY_TIMEOUT_MS / 1000,
                check_same_thread=False,
            )
        except sqlite3.Error:
            raise _storage_failure() from None
        conn.isolation_level = None  # explicit transaction control
        try:
            conn.execute(f"PRAGMA busy_timeout = {_BUSY_TIMEOUT_MS}")
        except sqlite3.Error:
            conn.close()
            raise _storage_failure() from None
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
                genesis_hash = _chain_hash(
                    tenant_id,
                    request_id,
                    0,
                    _STATUS_ACCEPTED,
                    created_at,
                    _GENESIS_PREDECESSOR,
                )
                try:
                    conn.execute("BEGIN IMMEDIATE")
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
                        # _PrimaryKeyConflict means retry with a new UUID;
                        # IdempotencyConflict propagates to the caller.
                        return self._load_idempotent(
                            conn, tenant_id, idempotency_key, subject_id, scope_list
                        )
                    # The first timeline entry shares the acceptance
                    # transaction: a request can never exist without its
                    # accepted event, nor an event without its request. The
                    # genesis chain link is written in the same transaction
                    # and its hash anchors the request row.
                    conn.execute(
                        "INSERT INTO status_events ("
                        "tenant_id, request_id, seq, status, occurred_at, chain_hash"
                        ") VALUES (?, ?, 0, 'accepted', ?, ?)",
                        (tenant_id, request_id, created_at, genesis_hash),
                    )
                    # The external trust anchor lands in the same
                    # transaction: request row, genesis event, request head
                    # and anchor either commit together or never land at
                    # all, so no accepted request can ever look complete
                    # without its anchor.
                    self._anchor_event_locked(
                        conn, tenant_id, request_id, 0, genesis_hash
                    )
                    conn.execute("COMMIT")
                except _PrimaryKeyConflict:
                    # Collision was on request_id; retry with a fresh UUID.
                    continue
                except sqlite3.Error:
                    try:
                        conn.execute("ROLLBACK")
                    except sqlite3.Error:
                        pass
                    raise _storage_failure() from None
                return self._acceptance_receipt(request_id, created_at)
        finally:
            self._release(conn)
        raise _storage_failure()

    @staticmethod
    def _acceptance_receipt(request_id: str, created_at: str) -> dict[str, str]:
        # The acceptance record is frozen: it always reports "accepted",
        # regardless of how the request later advances.
        return {
            "request_id": request_id,
            "status": _STATUS_ACCEPTED,
            "created_at": created_at,
        }

    def _load_idempotent(
        self,
        conn: sqlite3.Connection,
        tenant_id: str,
        idempotency_key: str,
        subject_id: str,
        scope_list: list[str],
    ) -> dict[str, str]:
        row = conn.execute(
            "SELECT request_id, created_at, subject_id, scopes_json "
            "FROM requests WHERE tenant_id = ? AND idempotency_key = ?",
            (tenant_id, idempotency_key),
        ).fetchone()
        if row is None:
            # The conflict came from the primary key rather than the
            # idempotency index; signal a fresh-UUID retry.
            raise _PrimaryKeyConflict
        existing_request_id, created_at, existing_subject, existing_scopes_json = row
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
        # The first acceptance receipt is immutable: always "accepted",
        # with the first request id and first acceptance time.
        return self._acceptance_receipt(existing_request_id, created_at)

    def get(self, tenant_id: str, request_id: str) -> dict[str, str]:
        """Return the *frozen acceptance receipt* for a request.

        The receipt always reports ``accepted`` with the first request id
        and first acceptance time, even after the request has advanced to
        processing/completed/failed. This is the record served by the
        HTTP lookup and idempotent submission replay. Invalid, unknown or
        cross-tenant ids are indistinguishable and raise
        :class:`RequestNotFound`; non-string or empty *tenant_id* raises
        :class:`ValueError`.
        """
        tenant_id = _require_nonempty_str(tenant_id, "tenant_id")
        # An invalid request id is treated exactly like an unknown one so
        # validation can never be used to tell which ids exist.
        request_id = _require_identifier(request_id)
        if self._mem_conn is not None:
            with self._write_lock:
                return self._get(tenant_id, request_id)
        return self._get(tenant_id, request_id)

    def _get(self, tenant_id: str, request_id: str) -> dict[str, str]:
        conn = self._connect()
        try:
            try:
                row = conn.execute(
                    "SELECT request_id, created_at FROM requests "
                    "WHERE tenant_id = ? AND request_id = ?",
                    (tenant_id, request_id),
                ).fetchone()
            except sqlite3.Error:
                raise _storage_failure() from None
        finally:
            self._release(conn)
        if row is None:
            # Identical outcome for unknown ids and cross-tenant lookups:
            # the response must not reveal that another tenant owns a record.
            raise RequestNotFound("request not found")
        return self._acceptance_receipt(row[0], row[1])

    def get_status(self, tenant_id: str, request_id: str) -> dict[str, str]:
        """Return the *current status record* for a request.

        The record has the same fixed shape and field order
        (``request_id``, ``status``, ``created_at``) as the acceptance
        receipt, but ``status`` reflects the latest persisted transition
        while ``created_at`` remains the original acceptance time. The
        result survives store rebuilds. Invalid, unknown or cross-tenant
        ids raise :class:`RequestNotFound`; a non-string or empty
        *tenant_id* raises :class:`ValueError`.
        """
        tenant_id = _require_nonempty_str(tenant_id, "tenant_id")
        request_id = _require_identifier(request_id)
        if self._mem_conn is not None:
            with self._write_lock:
                return self._get_status(tenant_id, request_id)
        return self._get_status(tenant_id, request_id)

    def _get_status(self, tenant_id: str, request_id: str) -> dict[str, str]:
        conn = self._connect()
        try:
            try:
                row = conn.execute(
                    "SELECT request_id, status, created_at FROM requests "
                    "WHERE tenant_id = ? AND request_id = ?",
                    (tenant_id, request_id),
                ).fetchone()
            except sqlite3.Error:
                raise _storage_failure() from None
        finally:
            self._release(conn)
        if row is None:
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
        returns the current status record without appending an event.
        An unknown/empty/non-string ``target_status`` is out of range and
        raises :class:`ValueError`; a move between two defined statuses
        that the lifecycle forbids (including any move out of a terminal
        state) raises :class:`InvalidStatusTransition` without writing.
        Invalid, unknown or cross-tenant request ids raise
        :class:`RequestNotFound`. No storage fault ever surfaces as
        anything other than :class:`OSError`.
        """
        # Validate before touching the database, mirroring submit(): no
        # rejected call may perform a write.
        tenant_id = _require_nonempty_str(tenant_id, "tenant_id")
        request_id = _require_identifier(request_id)
        target_status = _require_nonempty_str(target_status, "target_status")
        if target_status not in _ALLOWED_TRANSITIONS:
            # Out-of-range target (an undefined status) is caller error.
            raise ValueError("target_status is out of range")

        with self._write_lock:
            conn = self._connect()
            try:
                try:
                    conn.execute("BEGIN IMMEDIATE")
                except sqlite3.Error:
                    # Never surface the database engine's own error text.
                    raise _storage_failure() from None
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
                    self._persist_status_change(
                        conn, tenant_id, request_id, current_status, target_status
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
                    raise _storage_failure() from None
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

    def _persist_status_change(
        self,
        conn: sqlite3.Connection,
        tenant_id: str,
        request_id: str,
        current_status: str,
        target_status: str,
    ) -> str:
        """Append the chain event and advance the status within an open txn.

        Shared by :meth:`transition` and :meth:`finish_claim` so a terminal
        result lands in the same transaction as the attempt record. The
        caller owns ``BEGIN``/``COMMIT``; on a domain rejection or a broken
        invariant this helper rolls back before raising, so a shared
        in-memory connection is never left inside an aborted transaction.
        Returns the (monotonic) occurrence time written on the new event so
        the caller can stamp the attempt completion with the same instant.
        """
        allowed = _ALLOWED_TRANSITIONS.get(current_status, frozenset())
        if target_status not in allowed:
            conn.execute("ROLLBACK")
            raise InvalidStatusTransition("illegal status transition")
        # Read the predecessor link before writing so the new link binds
        # the exact persisted predecessor. BEGIN IMMEDIATE serializes
        # writers, so two changes can neither claim the same seq nor read a
        # stale predecessor.
        latest = conn.execute(
            "SELECT seq, occurred_at, chain_hash FROM status_events "
            "WHERE tenant_id = ? AND request_id = ? ORDER BY seq DESC LIMIT 1",
            (tenant_id, request_id),
        ).fetchone()
        if latest is None or not _is_chain_hash(latest[2]):
            # Defensive only: every accepted request owns its seq-0 event
            # with a valid link, so reaching here means the timeline
            # invariant was broken out of band. Never fabricate a link.
            conn.execute("ROLLBACK")
            raise _storage_failure()
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
            # The row vanished or changed under us; refuse rather than
            # persisting a state that breaks the graph observed at read.
            conn.execute("ROLLBACK")
            raise InvalidStatusTransition("illegal status transition")
        # The event is appended in the same transaction as the status
        # update and the attempt row; its link is anchored on the request
        # row by the UPDATE above. The external trust anchor lands in
        # that same transaction, so an actual status change can never
        # commit an event and head without its cross-restart anchor.
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
        self._anchor_event_locked(
            conn, tenant_id, request_id, next_seq + 1, next_link_hash
        )
        return occurred_at

    def _anchor_event_locked(
        self,
        conn: sqlite3.Connection,
        tenant_id: str,
        request_id: str,
        event_seq: int,
        event_hash: str,
    ) -> None:
        """Append the external trust anchor for one event in an open txn.

        Reads and advances the single anchor head, inserts the anchor row
        and updates the head inside the caller's transaction, so the
        ordered event, the request head and the external anchor land
        atomically. The genesis head row is created lazily here (the
        store never writes at open time) with an idempotent
        create-if-absent; ``BEGIN IMMEDIATE`` serializes first writers
        across store instances and processes. A damaged or missing head
        that fails validation is storage corruption and never silently
        resets. Every failure rolls the caller's transaction back and
        raises the fixed-text :class:`OSError`.
        """
        conn.execute(
            "INSERT OR IGNORE INTO chain_anchor_head (id, anchor_seq, anchor_hash) "
            "VALUES (1, 0, ?)",
            (_ANCHOR_GENESIS_HASH,),
        )
        head = conn.execute(
            "SELECT anchor_seq, anchor_hash FROM chain_anchor_head WHERE id = 1"
        ).fetchone()
        if (
            head is None
            or not isinstance(head[0], int)
            or isinstance(head[0], bool)
            or head[0] < 0
            or not _is_chain_hash(head[1])
        ):
            conn.execute("ROLLBACK")
            raise _storage_failure()
        prev_seq, prev_anchor = head
        next_seq = prev_seq + 1
        anchor = _anchor_mac(
            self._anchor_key,
            next_seq,
            tenant_id,
            request_id,
            event_seq,
            event_hash,
            prev_anchor,
        )
        conn.execute(
            "INSERT INTO chain_anchors ("
            "anchor_seq, tenant_id, request_id, event_seq, event_hash, anchor_hash"
            ") VALUES (?, ?, ?, ?, ?, ?)",
            (next_seq, tenant_id, request_id, event_seq, event_hash, anchor),
        )
        cursor = conn.execute(
            "UPDATE chain_anchor_head SET anchor_seq = ?, anchor_hash = ? "
            "WHERE id = 1 AND anchor_seq = ? AND anchor_hash = ?",
            (next_seq, anchor, prev_seq, prev_anchor),
        )
        if cursor.rowcount != 1:
            # Another writer advanced the head despite the write lock /
            # BEGIN IMMEDIATE contract; refuse rather than forking the
            # anchor chain.
            conn.execute("ROLLBACK")
            raise _storage_failure()


    # -- execution orchestration ---------------------------------------

    def claim_next(
        self,
        tenant_id: str,
        worker_id: str,
        lease_seconds: int,
    ) -> dict[str, object] | None:
        """Atomically claim the next request the tenant may execute.

        Candidates are ``accepted`` requests and ``processing`` requests
        whose latest lease has expired, ordered by acceptance time then
        request id; the oldest wins. The first claim moves an accepted
        request to ``processing`` and starts attempt 1; reclaiming after
        expiry starts the next attempt without changing the acceptance
        time, request id or current status. Only one worker ever holds a
        live lease for a given request.

        Returns ``None`` when no request is currently claimable. On
        success returns exactly ``request_id``, an unpredictable
        ``claim_token`` and the UTC RFC3339 ``lease_expires_at``. The
        worker identity is validated but never stored, logged or returned,
        and the raw token is returned once and never persisted. Invalid
        arguments raise :class:`ValueError` without writing; every storage
        fault is a fixed-text :class:`OSError`.
        """
        # Validate everything before touching the database. worker_id is
        # deliberately not persisted: it is authorised here only.
        tenant_id = _require_nonempty_str(tenant_id, "tenant_id")
        worker_id = _require_nonempty_str(worker_id, "worker_id")
        lease_seconds = _require_lease_seconds(lease_seconds)

        with self._write_lock:
            conn = self._connect()
            try:
                try:
                    conn.execute("BEGIN IMMEDIATE")
                except sqlite3.Error:
                    raise _storage_failure() from None
                claim: dict[str, object] | None = None
                try:
                    claim = self._claim_next_locked(conn, tenant_id, lease_seconds)
                    conn.execute("COMMIT")
                except OSError:
                    # A fixed-text storage failure raised after the helper
                    # rolled back; the second rollback is a harmless no-op
                    # that guarantees the (possibly shared) connection is
                    # never left inside an aborted transaction.
                    try:
                        conn.execute("ROLLBACK")
                    except sqlite3.Error:
                        pass
                    raise
                except sqlite3.Error:
                    try:
                        conn.execute("ROLLBACK")
                    except sqlite3.Error:
                        pass
                    raise _storage_failure() from None
            finally:
                self._release(conn)
        if claim is None:
            _log.info("claim found no candidate")
            return None
        _log.info(
            "claim acquired request_id=%s attempt=%s",
            claim["request_id"],
            claim["_attempt_number"],
        )
        # Strip internal bookkeeping; the caller sees only the contract.
        return {
            "request_id": claim["request_id"],
            "claim_token": claim["claim_token"],
            "lease_expires_at": claim["lease_expires_at"],
        }

    def _claim_next_locked(
        self,
        conn: sqlite3.Connection,
        tenant_id: str,
        lease_seconds: int,
    ) -> dict[str, object] | None:
        now_dt = datetime.now(timezone.utc)
        claimed_at = _format_rfc3339(now_dt)
        lease_expires_at = _format_rfc3339(
            now_dt + timedelta(seconds=lease_seconds)
        )
        # Oldest accepted, or oldest processing whose lease history proves
        # a genuine expired lease: at least one attempt exists, the most
        # recent attempt is still unfinished and its lease has expired,
        # and no attempt is still open inside a live lease. A processing
        # request that carries no attempt, whose latest attempt is already
        # finished (a status/result inconsistency), or that only has open
        # attempts that never lapsed, cannot be explained as an expired
        # lease and is never claimed; such records are left for
        # reconcile_execution to converge. The correlated subqueries read
        # the most recent attempt's expiry/result and whether any open
        # attempt is still inside its lease. BEGIN IMMEDIATE plus the write
        # lock make the read-then-claim atomic, so two workers can never
        # both win.
        row = conn.execute(
            "SELECT r.request_id, r.status "
            "FROM requests r "
            "WHERE r.tenant_id = ? "
            "  AND ( "
            "    r.status = ? "
            "    OR ( "
            "      r.status = ? "
            "      AND EXISTS ( "
            "        SELECT 1 FROM claim_attempts c "
            "        WHERE c.tenant_id = r.tenant_id "
            "          AND c.request_id = r.request_id "
            "      ) "
            "      AND ? > ( "
            "        SELECT c.lease_expires_at FROM claim_attempts c "
            "        WHERE c.tenant_id = r.tenant_id "
            "          AND c.request_id = r.request_id "
            "        ORDER BY c.attempt_number DESC LIMIT 1 "
            "      ) "
            "      AND ( "
            "        SELECT c.result FROM claim_attempts c "
            "        WHERE c.tenant_id = r.tenant_id "
            "          AND c.request_id = r.request_id "
            "        ORDER BY c.attempt_number DESC LIMIT 1 "
            "      ) IS NULL "
            "      AND NOT EXISTS ( "
            "        SELECT 1 FROM claim_attempts c "
            "        WHERE c.tenant_id = r.tenant_id "
            "          AND c.request_id = r.request_id "
            "          AND c.result IS NULL AND c.completed_at IS NULL "
            "          AND ? <= c.lease_expires_at "
            "      ) "
            "    ) "
            "  ) "
            "ORDER BY r.created_at ASC, r.request_id ASC LIMIT 1",
            (
                tenant_id,
                _STATUS_ACCEPTED,
                _STATUS_PROCESSING,
                claimed_at,
                claimed_at,
            ),
        ).fetchone()
        if row is None:
            return None
        request_id, current_status = row

        attempt_row = conn.execute(
            "SELECT COALESCE(MAX(attempt_number), 0) + 1 "
            "FROM claim_attempts WHERE tenant_id = ? AND request_id = ?",
            (tenant_id, request_id),
        ).fetchone()
        attempt_number = attempt_row[0]
        if not isinstance(attempt_number, int) or isinstance(attempt_number, bool):
            # Corrupt attempt sequence: never fabricate a number.
            raise _storage_failure()

        conn.execute(
            "INSERT INTO claim_attempts ("
            "tenant_id, request_id, attempt_number, claimed_at, "
            "lease_expires_at, result, completed_at"
            ") VALUES (?, ?, ?, ?, ?, NULL, NULL)",
            (
                tenant_id,
                request_id,
                attempt_number,
                claimed_at,
                lease_expires_at,
            ),
        )
        # Any token from a previous (now superseded) lease is released the
        # instant a new lease begins, so an expired worker can never finish
        # a request a successor now owns.
        conn.execute(
            "DELETE FROM claim_tokens WHERE tenant_id = ? AND request_id = ?",
            (tenant_id, request_id),
        )
        token = _new_claim_token()
        conn.execute(
            "INSERT INTO claim_tokens ("
            "tenant_id, request_id, attempt_number, token_hash"
            ") VALUES (?, ?, ?, ?)",
            (
                tenant_id,
                request_id,
                attempt_number,
                hashlib.sha256(token.encode("utf-8")).hexdigest(),
            ),
        )
        if current_status == _STATUS_ACCEPTED:
            # The first acquisition enters processing exactly once, in the
            # same transaction as the attempt row. A reclaim after expiry
            # finds the request already processing and writes no state.
            self._persist_status_change(
                conn, tenant_id, request_id, _STATUS_ACCEPTED, _STATUS_PROCESSING
            )
        return {
            "request_id": request_id,
            "claim_token": token,
            "lease_expires_at": lease_expires_at,
            "_attempt_number": attempt_number,
        }

    def finish_claim(
        self,
        tenant_id: str,
        request_id: str,
        claim_token: str,
        result: str,
    ) -> dict[str, str]:
        """Finish the live claim with a terminal ``result``.

        ``result`` must be ``completed`` or ``failed``. The token must
        identify the request's current, unexpired, unreleased lease for
        the same tenant; an unknown, expired, already-released or
        cross-tenant token -- as well as finishing a request that has no
        open claim -- raises :class:`ClaimConflict` and changes nothing.
        The terminal status and its chain event are committed in the same
        transaction that records the attempt result and releases the
        token. Returns the status record (``request_id``, ``status``,
        ``created_at``).
        """
        tenant_id = _require_nonempty_str(tenant_id, "tenant_id")
        request_id = _require_identifier(request_id)
        result = _require_result(result)
        # A token outside the non-empty-string domain is caller error
        # (ValueError), exactly like the other execution parameters. A
        # well-formed string that simply matches no live lease is resolved
        # below and surfaces as ClaimConflict ("no such credential").
        claim_token = _require_nonempty_str(claim_token, "claim_token")

        with self._write_lock:
            conn = self._connect()
            try:
                try:
                    conn.execute("BEGIN IMMEDIATE")
                except sqlite3.Error:
                    raise _storage_failure() from None
                try:
                    receipt = self._finish_claim_locked(
                        conn, tenant_id, request_id, claim_token, result
                    )
                    conn.execute("COMMIT")
                except (InvalidStatusTransition, ClaimConflict, RequestNotFound):
                    # Domain rejections carry no engine text; ensure the
                    # shared in-memory connection leaves the transaction.
                    try:
                        conn.execute("ROLLBACK")
                    except sqlite3.Error:
                        pass
                    raise
                except sqlite3.Error:
                    try:
                        conn.execute("ROLLBACK")
                    except sqlite3.Error:
                        pass
                    raise _storage_failure() from None
            finally:
                self._release(conn)
        _log.info(
            "claim finished request_id=%s status=%s",
            request_id,
            result,
        )
        return receipt

    def _finish_claim_locked(
        self,
        conn: sqlite3.Connection,
        tenant_id: str,
        request_id: str,
        claim_token: str,
        result: str,
    ) -> dict[str, str]:
        # Resolve the presented token without scoping by tenant first: a
        # token issued to another tenant (or for another request) must look
        # exactly like an unknown or released one and raise ClaimConflict,
        # never reveal that the coordinates name a record elsewhere.
        presented = hashlib.sha256(claim_token.encode("utf-8")).hexdigest()
        owner = conn.execute(
            "SELECT tenant_id, request_id, attempt_number FROM claim_tokens "
            "WHERE token_hash = ? LIMIT 1",
            (presented,),
        ).fetchone()
        if owner is None:
            # The credential itself is invalid (unknown or released). The
            # request id then decides the error with stable precedence:
            # an unknown or cross-tenant id raises RequestNotFound even
            # though the credential is also invalid, while an existing
            # request presented with a bad credential is a ClaimConflict.
            exists = conn.execute(
                "SELECT 1 FROM requests WHERE tenant_id = ? AND request_id = ?",
                (tenant_id, request_id),
            ).fetchone()
            if exists is None:
                raise RequestNotFound("request not found")
            raise _claim_conflict()
        if (owner[0], owner[1]) != (tenant_id, request_id):
            # A live credential presented against a different tenant or
            # request: already released/foreign for these coordinates.
            raise _claim_conflict()
        attempt_number = owner[2]

        row = conn.execute(
            "SELECT status, created_at FROM requests "
            "WHERE tenant_id = ? AND request_id = ?",
            (tenant_id, request_id),
        ).fetchone()
        if row is None:
            # Defensive: a live token always names an existing request.
            raise RequestNotFound("request not found")
        current_status, created_at = row

        # The token names the current lease; its attempt must still be open
        # and the lease must not have lapsed.
        latest = conn.execute(
            "SELECT result, lease_expires_at FROM claim_attempts "
            "WHERE tenant_id = ? AND request_id = ? AND attempt_number = ?",
            (tenant_id, request_id, attempt_number),
        ).fetchone()
        if latest is None or latest[0] is not None:
            raise _claim_conflict()
        if _utc_now_rfc3339() > latest[1]:
            # The lease has expired; the holder no longer owns the request.
            raise _claim_conflict()

        if current_status != _STATUS_PROCESSING:
            # An open attempt must accompany processing; anything else is
            # an out-of-band inconsistency that must not be overwritten.
            raise _claim_conflict()

        # Advance to the terminal state with its chain event and reuse the
        # exact monotonic occurrence time for the attempt completion, all in
        # this one transaction: the attempt result and request status can
        # never disagree and neither can be left half-written.
        completed_at = self._persist_status_change(
            conn, tenant_id, request_id, _STATUS_PROCESSING, result
        )
        cursor = conn.execute(
            "UPDATE claim_attempts SET result = ?, completed_at = ? "
            "WHERE tenant_id = ? AND request_id = ? AND attempt_number = ? "
            "AND result IS NULL",
            (result, completed_at, tenant_id, request_id, attempt_number),
        )
        if cursor.rowcount != 1:
            raise _claim_conflict()
        # Release the single-use token before returning success.
        conn.execute(
            "DELETE FROM claim_tokens "
            "WHERE tenant_id = ? AND request_id = ? AND attempt_number = ?",
            (tenant_id, request_id, attempt_number),
        )
        return {
            "request_id": request_id,
            "status": result,
            "created_at": created_at,
        }

    def get_execution_log(
        self,
        tenant_id: str,
        request_id: str,
    ) -> list[dict[str, object]]:
        """Return the request's execution attempts in attempt order.

        Each entry contains exactly ``attempt_number`` (a positive int
        starting at 1), ``claimed_at`` and ``lease_expires_at`` (UTC
        RFC3339 strings), and ``result``/``completed_at`` which are the
        terminal status and completion time once finished, and ``None``
        while the attempt is still open (or was abandoned on expiry). No
        worker identity and no claim token is ever included. Invalid,
        unknown and cross-tenant ids raise :class:`RequestNotFound`; a
        non-string or empty tenant raises :class:`ValueError`; corrupt
        rows raise the fixed-text :class:`OSError`.
        """
        tenant_id = _require_nonempty_str(tenant_id, "tenant_id")
        request_id = _require_identifier(request_id)
        if self._mem_conn is not None:
            with self._write_lock:
                return self._get_execution_log(tenant_id, request_id)
        return self._get_execution_log(tenant_id, request_id)

    def _get_execution_log(
        self, tenant_id: str, request_id: str
    ) -> list[dict[str, object]]:
        conn = self._connect()
        try:
            try:
                # Resolve ownership first, exactly like audit(): an empty
                # log must not distinguish "missing" from "foreign record".
                owner = conn.execute(
                    "SELECT 1 FROM requests WHERE tenant_id = ? AND request_id = ?",
                    (tenant_id, request_id),
                ).fetchone()
                if owner is None:
                    raise RequestNotFound("request not found")
                rows = conn.execute(
                    "SELECT attempt_number, claimed_at, lease_expires_at, "
                    "result, completed_at FROM claim_attempts "
                    "WHERE tenant_id = ? AND request_id = ? "
                    "ORDER BY attempt_number",
                    (tenant_id, request_id),
                ).fetchall()
            except RequestNotFound:
                raise
            except sqlite3.Error:
                raise _storage_failure() from None
        finally:
            self._release(conn)

        attempts: list[dict[str, object]] = []
        for index, row in enumerate(rows, start=1):
            attempt_number, claimed_at, lease_expires_at, result, completed_at = row
            # Strict shape validation: a tampered row is storage
            # corruption, never a partially-formed record. Only str, int
            # and None ever reach the caller -- never float or bool.
            if (
                not isinstance(attempt_number, int)
                or isinstance(attempt_number, bool)
                or attempt_number != index
                or not isinstance(claimed_at, str)
                or not claimed_at
                or not isinstance(lease_expires_at, str)
                or not lease_expires_at
            ):
                raise _storage_failure()
            if result is not None and (
                not isinstance(result, str) or result not in _TERMINAL_RESULTS
            ):
                raise _storage_failure()
            if completed_at is not None and (
                not isinstance(completed_at, str) or not completed_at
            ):
                raise _storage_failure()
            # result and completed_at are set together at finish time.
            if (result is None) != (completed_at is None):
                raise _storage_failure()
            attempts.append(
                {
                    "attempt_number": attempt_number,
                    "claimed_at": claimed_at,
                    "lease_expires_at": lease_expires_at,
                    "result": result,
                    "completed_at": completed_at,
                }
            )
        return attempts

    def reconcile_execution(
        self,
        tenant_id: str,
        request_id: str,
    ) -> dict[str, str]:
        """Reconcile a request's execution record and converge it.

        Returns the existing status record (``request_id``, ``status``,
        ``created_at``) and never creates a request, an attempt or a
        receipt:

        * an ``accepted`` request (with or without attempts) is returned
          exactly as it stands -- no record, attempt or receipt changes;
        * a ``processing`` request whose lease is still live keeps its
          in-progress attempt: no terminal result is written early and no
          new attempt is generated;
        * a ``completed``/``failed`` request is an idempotent no-op with
          respect to the status record; the first terminal result is
          retained, as is the same status record.

        Convergence runs only for a ``processing`` request whose latest
        lease has expired and that holds no other valid lease (including a
        processing request with no result and no lease at all, or with no
        explainable attempts). Every unfinished attempt is compensated to
        ``failed`` in one atomic transaction with the status convergence
        and the lease release; the compensation completion time is a UTC
        RFC3339 string shared with the convergence event and is written
        exactly once, never over an existing completion time. When the
        execution record already carries terminal attempts the earliest
        completion wins and sets the converged status; later duplicate
        terminal rows are recorded as ``failed`` without altering that
        status on subsequent reconciles.

        A non-string or empty *tenant_id* raises :class:`ValueError`
        without changing any state; a missing, empty, non-string,
        malformed, unknown or cross-tenant *request_id* raises
        :class:`RequestNotFound` identically. Corrupt execution records
        or a failed compensation commit raise the fixed-text
        :class:`OSError`; a half-converged result is never returned.
        """
        # Validate before touching the database: tenant errors are
        # ValueErrors, while every request-id problem (missing, empty,
        # non-string, malformed or foreign) collapses to RequestNotFound.
        tenant_id = _require_nonempty_str(tenant_id, "tenant_id")
        request_id = _require_identifier(request_id)

        with self._write_lock:
            conn = self._connect()
            try:
                try:
                    conn.execute("BEGIN IMMEDIATE")
                except sqlite3.Error:
                    raise _storage_failure() from None
                try:
                    record = self._reconcile_locked(conn, tenant_id, request_id)
                    conn.execute("COMMIT")
                except RequestNotFound:
                    try:
                        conn.execute("ROLLBACK")
                    except sqlite3.Error:
                        pass
                    raise
                except InvalidStatusTransition:
                    # Defensive only: the status was read as processing in
                    # this same write transaction and cannot have changed.
                    # Reconcile has no illegal-transition outcome, so never
                    # let that exception escape its declared error set.
                    try:
                        conn.execute("ROLLBACK")
                    except sqlite3.Error:
                        pass
                    raise _storage_failure() from None
                except OSError:
                    # _persist_status_change and the corruption probes
                    # roll back before raising the fixed-text error; the
                    # second rollback only guarantees the shared
                    # connection has left its transaction.
                    try:
                        conn.execute("ROLLBACK")
                    except sqlite3.Error:
                        pass
                    raise
                except sqlite3.Error:
                    try:
                        conn.execute("ROLLBACK")
                    except sqlite3.Error:
                        pass
                    raise _storage_failure() from None
            finally:
                self._release(conn)
        _log.info(
            "execution reconciled request_id=%s status=%s",
            request_id,
            record["status"],
        )
        return record

    def _reconcile_locked(
        self,
        conn: sqlite3.Connection,
        tenant_id: str,
        request_id: str,
    ) -> dict[str, str]:
        """Converge one request inside an already-open write txn."""
        row = conn.execute(
            "SELECT status, created_at FROM requests "
            "WHERE tenant_id = ? AND request_id = ?",
            (tenant_id, request_id),
        ).fetchone()
        if row is None:
            # Unknown id and cross-tenant lookup share one outcome.
            raise RequestNotFound("request not found")
        current_status, created_at = row
        if current_status not in _ALLOWED_TRANSITIONS or not isinstance(
            created_at, str
        ):
            # A status outside the lifecycle or a broken acceptance time
            # is out-of-band corruption: never converge from a bad read.
            raise _storage_failure()

        attempts = self._load_attempts_for_reconcile(conn, tenant_id, request_id)

        if current_status == _STATUS_ACCEPTED:
            # Accepted means "never executed": only report the current
            # state. No record, attempt or receipt is created or changed.
            return {
                "request_id": request_id,
                "status": current_status,
                "created_at": created_at,
            }

        if current_status in _TERMINAL_RESULTS:
            # Idempotent at the request: the first terminal result and the
            # same status record are retained. A corrupted execution record
            # carrying several terminal attempts is still normalised, but
            # that repair never touches the request row or its timeline.
            self._normalise_duplicate_terminals(
                conn, tenant_id, request_id, attempts
            )
            return {
                "request_id": request_id,
                "status": current_status,
                "created_at": created_at,
            }

        # current_status == processing. A lease is live while any
        # unfinished attempt is still inside its lease window; RFC3339
        # timestamps from _utc_now_rfc3339 compare chronologically as
        # text. Equality with the expiry still counts as held, matching
        # finish_claim's expiry boundary.
        now = _utc_now_rfc3339()
        has_live_lease = any(
            result is None and now <= lease_expires_at
            for _number, result, _completed_at, lease_expires_at in attempts
        )
        if has_live_lease:
            # The current holder still owns the request: keep its open
            # attempt, write no terminal result early and start no
            # successor attempt.
            return {
                "request_id": request_id,
                "status": current_status,
                "created_at": created_at,
            }

        return self._compensate_locked(
            conn, tenant_id, request_id, created_at, attempts
        )

    def _load_attempts_for_reconcile(
        self,
        conn: sqlite3.Connection,
        tenant_id: str,
        request_id: str,
    ) -> list[tuple[int, str | None, str | None, str]]:
        """Read and strictly validate every attempt row for reconcile.

        Returns ``(attempt_number, result, completed_at,
        lease_expires_at)`` tuples in attempt order. A malformed sequence,
        timestamp or result/completion pairing is storage corruption and
        raises the fixed-text OSError before any state is touched.
        """
        rows = conn.execute(
            "SELECT attempt_number, result, completed_at, lease_expires_at "
            "FROM claim_attempts WHERE tenant_id = ? AND request_id = ? "
            "ORDER BY attempt_number",
            (tenant_id, request_id),
        ).fetchall()
        attempts: list[tuple[int, str | None, str | None, str]] = []
        for index, attempt_row in enumerate(rows, start=1):
            attempt_number, result, completed_at, lease_expires_at = attempt_row
            if (
                not isinstance(attempt_number, int)
                or isinstance(attempt_number, bool)
                or attempt_number != index
                or not isinstance(lease_expires_at, str)
                or not lease_expires_at
            ):
                raise _storage_failure()
            if result is not None and (
                not isinstance(result, str) or result not in _TERMINAL_RESULTS
            ):
                raise _storage_failure()
            if completed_at is not None and (
                not isinstance(completed_at, str) or not completed_at
            ):
                raise _storage_failure()
            # Result and completion time are set together and never
            # separately; a split row is a broken invariant.
            if (result is None) != (completed_at is None):
                raise _storage_failure()
            attempts.append(
                (attempt_number, result, completed_at, lease_expires_at)
            )
        return attempts

    def _earliest_terminal(
        self,
        attempts: list[tuple[int, str | None, str | None, str]],
    ) -> tuple[int, str] | None:
        """Return ``(attempt_number, result)`` of the first completion.

        Earliest is the terminal attempt with the smallest completion
        time, sequence breaking a tie. A terminal row validated upstream
        always carries a completion time.
        """
        terminals = [
            (completed_at, attempt_number, result)
            for attempt_number, result, completed_at, _expiry in attempts
            if result is not None
        ]
        if not terminals:
            return None
        completed_at, attempt_number, result = min(
            terminals, key=lambda item: (item[0], item[1])
        )
        return attempt_number, result

    def _normalise_duplicate_terminals(
        self,
        conn: sqlite3.Connection,
        tenant_id: str,
        request_id: str,
        attempts: list[tuple[int, str | None, str | None, str]],
    ) -> None:
        """Force every terminal attempt after the earliest to ``failed``.

        Only rows other than the earliest completion that still claim
        ``completed`` are rewritten; the winning row (earliest completion,
        sequence breaking a tie) and a row already marked ``failed`` are
        left alone, and existing completion times are never overwritten.
        The request row, its status and its timeline are untouched.
        """
        earliest = self._earliest_terminal(attempts)
        if earliest is None:
            return
        earliest_number, _earliest_result = earliest
        conn.execute(
            "UPDATE claim_attempts SET result = 'failed' "
            "WHERE tenant_id = ? AND request_id = ? AND attempt_number != ? "
            "AND result = 'completed'",
            (tenant_id, request_id, earliest_number),
        )

    def _compensate_locked(
        self,
        conn: sqlite3.Connection,
        tenant_id: str,
        request_id: str,
        created_at: str,
        attempts: list[tuple[int, str | None, str | None, str]],
    ) -> dict[str, str]:
        """Compensate open attempts and converge processing in one txn.

        With no valid lease every unfinished attempt is abandoned work;
        it is compensated to ``failed`` once. If terminal attempts
        already exist the earliest completion determines the converged
        status (its row is retained) and later duplicate terminals are
        recorded as ``failed``; otherwise the request itself converges
        to ``failed``. The dead lease credential is released in the same
        transaction as the status, its chain event and every attempt.
        """
        earliest = self._earliest_terminal(attempts)
        target_status = earliest[1] if earliest is not None else _STATUS_FAILED

        # The convergence event and request status land first, exactly
        # like finish_claim; its monotonic occurrence time is reused as
        # the single compensation completion time.
        completed_at = self._persist_status_change(
            conn, tenant_id, request_id, _STATUS_PROCESSING, target_status
        )

        # Abandoned, unfinished attempts become failed. The NULL guards
        # guarantee the completion time is written once and an existing
        # result or completion time can never be overwritten.
        conn.execute(
            "UPDATE claim_attempts SET result = 'failed', completed_at = ? "
            "WHERE tenant_id = ? AND request_id = ? "
            "AND result IS NULL AND completed_at IS NULL",
            (completed_at, tenant_id, request_id),
        )

        if earliest is not None:
            # Keep the earliest completion result; every other duplicate
            # terminal row is downgraded to failed without touching its
            # already-written completion time or the request status. The
            # winner is selected by completion time (sequence breaking a
            # tie), not by attempt number.
            earliest_number, _earliest_result = earliest
            conn.execute(
                "UPDATE claim_attempts SET result = 'failed' "
                "WHERE tenant_id = ? AND request_id = ? "
                "AND attempt_number != ? AND result = 'completed'",
                (tenant_id, request_id, earliest_number),
            )

        # The lease is dead: release whatever credential it left behind
        # atomically with the convergence, so it can never finish a
        # request that no longer belongs to its holder.
        conn.execute(
            "DELETE FROM claim_tokens WHERE tenant_id = ? AND request_id = ?",
            (tenant_id, request_id),
        )
        return {
            "request_id": request_id,
            "status": target_status,
            "created_at": created_at,
        }

    # -- batch reconciliation ------------------------------------------

    def reconcile_batch(
        self,
        tenant_id: str,
        cursor: str | None = None,
        limit: int | None = None,
    ) -> dict[str, object]:
        """Reconcile a tenant's pending requests in resumable batches.

        Storage-layer only; never routed over HTTP. With ``cursor``
        omitted a new persistent batch sweeps the tenant's requests in
        stable acceptance order (``created_at`` then ``request_id``);
        with a cursor the batch it names is resumed from its durably
        committed position, so a retry after an interruption continues
        instead of restarting, and the same cursor always keeps the same
        batch identifier. Each call reconciles at most ``limit`` items
        (default 100, at most 1000) and returns exactly ``batch_id``,
        ``next_cursor`` (``None`` once the sweep is finished),
        ``finished`` and ``items`` -- one ``{"request_id", "status"}``
        entry per reconciled request, in scan order.

        Reconciliation of each request follows
        :meth:`reconcile_execution`: ``accepted`` rows are skipped
        without creating an attempt, receipt or extra status event;
        a ``processing`` request with a live lease stays processing; a
        ``processing`` request whose lease expired (or that has no
        explainable lease) is compensated to ``failed``. Every item's
        status change, attempt rows, lease release, batch bookkeeping
        and cursor position commit in one transaction, so a failed call
        leaves no half-settled item and a committed item is never
        rewritten by a retry.

        A non-string/empty *tenant_id*, a limit outside 1..1000 (or a
        non-integer), and any malformed, unknown or cross-tenant
        *cursor* raise :class:`ValueError` without writing. Corrupt
        persisted batch state and every storage fault raise the
        fixed-text :class:`OSError`.
        """
        # Validate everything before touching the database: no rejected
        # call may perform a write.
        tenant_id = _require_nonempty_str(tenant_id, "tenant_id")
        if limit is None:
            limit = _DEFAULT_BATCH_LIMIT
        limit = _require_batch_limit(limit)
        cursor_batch: tuple[str, int] | None = None
        if cursor is not None:
            cursor_batch = _decode_cursor(cursor)

        with self._write_lock:
            conn = self._connect()
            try:
                # First transaction resolves the batch: a fresh batch row
                # is inserted when no cursor was given; a cursor names the
                # persisted batch to resume. An unknown/cross-tenant cursor
                # is rejected here before anything is written.
                batch_id, _pos, _rid, finished, _start_count = (
                    self._batch_transaction(
                        conn,
                        lambda: self._load_or_init_batch_locked(
                            conn, tenant_id, cursor_batch
                        ),
                    )
                )
                items: list[dict[str, str]] = []
                # Each scanned request is settled in its OWN transaction:
                # its status change, attempts, lease release, the item row
                # and the cursor position all commit together. The next
                # iteration re-reads the persisted position, so an item
                # already settled by an earlier commit or a concurrent call
                # is never rewritten.
                while not finished and len(items) < limit:
                    kind, payload = self._batch_transaction(
                        conn,
                        lambda: self._process_one_batch_item_locked(
                            conn, tenant_id, batch_id
                        ),
                    )
                    if kind == "finished":
                        finished = True
                        break
                    if kind == "item":
                        items.append(payload)
                    # "accepted" only advanced the position and is skipped.
                # Resolve the authoritative outcome in one final short
                # transaction: whether the sweep is finished AND the durable
                # settled-item count are both read from the database rather
                # than from this call's in-memory tally. A file database may
                # be shared by other RequestStore instances/processes whose
                # per-item transactions commit disjoint items for the same
                # resumable batch; the cursor's position must name that
                # durable count, never a stale "start + this call's items"
                # snapshot that lags behind what is already settled.
                finished, durable_count = self._batch_transaction(
                    conn,
                    lambda: self._finalize_batch_if_end_locked(
                        conn, tenant_id, batch_id
                    ),
                )
            finally:
                self._release(conn)
        # The cursor only identifies the persisted batch; its item count is
        # the database-authoritative settled count read in the final
        # transaction, so a cursor returned to any concurrent caller reports
        # a position that matches what is durably committed.
        next_cursor = (
            None if finished else _encode_cursor(batch_id, durable_count)
        )
        # Log only counts and the stable outcome: no tenant, subject,
        # worker, credential or SQL text ever reaches the log.
        _log.info(
            "reconcile batch settled items=%s finished=%s",
            len(items),
            finished,
        )
        return {
            "batch_id": batch_id,
            "next_cursor": next_cursor,
            "finished": finished,
            "items": items,
        }

    def _batch_transaction(self, conn: sqlite3.Connection, action):
        """Run ``action`` inside one short-lived write transaction.

        Every batch operation (batch resolution, one item, the end
        finalization) commits independently, so a fault while settling a
        later item can never undo an already committed earlier item or
        leave the shared connection inside an aborted transaction. Domain
        and storage exceptions propagate after a rollback; any engine
        error -- including lock conflicts -- becomes the fixed-text
        :class:`OSError`.
        """
        try:
            conn.execute("BEGIN IMMEDIATE")
        except sqlite3.Error:
            raise _storage_failure() from None
        try:
            result = action()
            conn.execute("COMMIT")
            return result
        except ValueError:
            self._rollback_quietly(conn)
            raise
        except (RequestNotFound, InvalidStatusTransition):
            # Defensive only: rows are read inside this write transaction
            # and cannot vanish or move illegally underneath it.
            self._rollback_quietly(conn)
            raise _storage_failure() from None
        except OSError:
            self._rollback_quietly(conn)
            raise
        except sqlite3.Error:
            self._rollback_quietly(conn)
            raise _storage_failure() from None

    @staticmethod
    def _rollback_quietly(conn: sqlite3.Connection) -> None:
        try:
            conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass

    def _process_one_batch_item_locked(
        self,
        conn: sqlite3.Connection,
        tenant_id: str,
        batch_id: str,
    ) -> tuple[str, object]:
        """Settle the next scan position inside an open write txn.

        Re-reads the batch's persisted position every call, so the result
        is independent of any in-memory position. Returns
        ``("finished", None)`` once the sweep end is reached,
        ``("accepted", None)`` after advancing past a skipped accepted
        row, or ``("item", {"request_id", "status"})`` after reconciling
        a processing request and recording its item.
        """
        pos_created, pos_rid, finished, item_count = self._read_batch_state_locked(
            conn, batch_id
        )
        if finished:
            return "finished", None
        row = self._next_batch_candidate(conn, tenant_id, pos_created, pos_rid)
        if row is None:
            self._finish_batch_locked(conn, batch_id)
            return "finished", None
        request_id, created_at, status = row
        if status == _STATUS_ACCEPTED:
            # First-scan rule: accepted rows are skipped -- no attempt,
            # receipt or extra status event -- but the position advances
            # past them so they are never rescanned.
            self._advance_batch_locked(conn, batch_id, created_at, request_id)
            return "accepted", None
        record = self._reconcile_locked(conn, tenant_id, request_id)
        # The item row, the reconcile effects and the cursor position land
        # in this one transaction; the sequence derives from the persisted
        # count so a resumed batch never reuses a number.
        conn.execute(
            "INSERT INTO reconcile_batch_items ("
            "batch_id, seq, request_id, status"
            ") VALUES (?, ?, ?, ?)",
            (batch_id, item_count + 1, request_id, record["status"]),
        )
        self._advance_batch_locked(conn, batch_id, created_at, request_id)
        return "item", {"request_id": request_id, "status": record["status"]}

    def _finalize_batch_if_end_locked(
        self,
        conn: sqlite3.Connection,
        tenant_id: str,
        batch_id: str,
    ) -> tuple[bool, int]:
        """Finish a limit-stopped batch iff no candidate remains.

        Always returns the authoritative ``(finished, item_count)`` read
        from the persisted batch inside this write transaction. The count
        reflects every settled item -- including items committed for the
        same batch by another store instance/process -- so the caller can
        issue a cursor whose position matches the durable tally rather
        than its own per-call snapshot.
        """
        pos_created, pos_rid, finished, item_count = (
            self._read_batch_state_locked(conn, batch_id)
        )
        if finished:
            return True, item_count
        if self._next_batch_candidate(conn, tenant_id, pos_created, pos_rid) is None:
            self._finish_batch_locked(conn, batch_id)
            return True, item_count
        return False, item_count

    def _read_batch_state_locked(
        self, conn: sqlite3.Connection, batch_id: str
    ) -> tuple[str | None, str | None, bool, int]:
        """Read and strictly validate a batch's persisted position."""
        row = conn.execute(
            "SELECT position_created_at, position_request_id, finished, "
            "(SELECT count(*) FROM reconcile_batch_items i "
            " WHERE i.batch_id = b.batch_id) "
            "FROM reconcile_batches b WHERE b.batch_id = ?",
            (batch_id,),
        ).fetchone()
        if row is None:
            # The batch this transaction is driving vanished out of band.
            raise _storage_failure()
        pos_created, pos_rid, finished, item_count = row
        if (
            finished not in (0, 1)
            or not isinstance(item_count, int)
            or isinstance(item_count, bool)
        ):
            raise _storage_failure()
        if (pos_created is None) != (pos_rid is None):
            # The keyset position is written atomically; a split pair is
            # out-of-band corruption, never a resumable state.
            raise _storage_failure()
        if pos_created is not None and (
            not isinstance(pos_created, str)
            or not pos_created
            or not isinstance(pos_rid, str)
            or not pos_rid
        ):
            raise _storage_failure()
        return pos_created, pos_rid, bool(finished), item_count

    def _load_or_init_batch_locked(
        self,
        conn: sqlite3.Connection,
        tenant_id: str,
        cursor_batch: tuple[str, int] | None,
    ) -> tuple[str, str | None, str | None, bool, int]:
        """Resolve the batch for this call inside an open write txn.

        Returns ``(batch_id, position_created_at, position_request_id,
        finished, item_count)``. Without a cursor a fresh batch row is
        inserted; with a cursor the persisted batch is resumed from its
        committed position -- the cursor's own position field is only a
        format detail, the database is authoritative. An unknown or
        cross-tenant batch id is an invalid cursor and raises
        :class:`ValueError`; corrupt persisted state raises the
        fixed-text :class:`OSError`.
        """
        if cursor_batch is None:
            batch_id = str(uuid.uuid4())
            conn.execute(
                "INSERT INTO reconcile_batches ("
                "batch_id, tenant_id, position_created_at, "
                "position_request_id, finished"
                ") VALUES (?, ?, NULL, NULL, 0)",
                (batch_id, tenant_id),
            )
            return batch_id, None, None, False, 0
        batch_id, _issued_position = cursor_batch
        # Confirm ownership before reading state: an unknown or
        # cross-tenant batch id is an invalid cursor, indistinguishable
        # from one that never existed.
        owner = conn.execute(
            "SELECT 1 FROM reconcile_batches WHERE batch_id = ? AND tenant_id = ?",
            (batch_id, tenant_id),
        ).fetchone()
        if owner is None:
            raise ValueError("cursor is not valid")
        pos_created, pos_rid, finished, item_count = self._read_batch_state_locked(
            conn, batch_id
        )
        return batch_id, pos_created, pos_rid, finished, item_count

    @staticmethod
    def _next_batch_candidate(
        conn: sqlite3.Connection,
        tenant_id: str,
        pos_created: str | None,
        pos_rid: str | None,
    ) -> tuple[str, str, str] | None:
        """Oldest non-terminal request strictly after the keyset position.

        Only ``accepted`` and ``processing`` rows are swept; terminal
        requests are already converged and never need a batch item. The
        (created_at, request_id) ordering matches the claim candidate
        index, so the scan is stable across calls, restarts and
        concurrent submissions.
        """
        if pos_created is None:
            return conn.execute(
                "SELECT request_id, created_at, status FROM requests "
                "WHERE tenant_id = ? AND status IN (?, ?) "
                "ORDER BY created_at ASC, request_id ASC LIMIT 1",
                (tenant_id, _STATUS_ACCEPTED, _STATUS_PROCESSING),
            ).fetchone()
        return conn.execute(
            "SELECT request_id, created_at, status FROM requests "
            "WHERE tenant_id = ? AND status IN (?, ?) "
            "AND (created_at, request_id) > (?, ?) "
            "ORDER BY created_at ASC, request_id ASC LIMIT 1",
            (tenant_id, _STATUS_ACCEPTED, _STATUS_PROCESSING, pos_created, pos_rid),
        ).fetchone()

    @staticmethod
    def _advance_batch_locked(
        conn: sqlite3.Connection,
        batch_id: str,
        pos_created: str,
        pos_rid: str,
    ) -> None:
        """Move the batch's durable keyset position forward."""
        cursor = conn.execute(
            "UPDATE reconcile_batches "
            "SET position_created_at = ?, position_request_id = ? "
            "WHERE batch_id = ?",
            (pos_created, pos_rid, batch_id),
        )
        if cursor.rowcount != 1:
            # The batch row this transaction itself resolved vanished;
            # that is storage corruption, never a caller error.
            raise _storage_failure()

    @staticmethod
    def _finish_batch_locked(conn: sqlite3.Connection, batch_id: str) -> None:
        """Mark the batch durably finished inside the open transaction."""
        cursor = conn.execute(
            "UPDATE reconcile_batches SET finished = 1 WHERE batch_id = ?",
            (batch_id,),
        )
        if cursor.rowcount != 1:
            raise _storage_failure()

    def audit(
        self,
        tenant_id: str,
        request_id: str,
    ) -> list[dict[str, str]]:
        """Return the request's status timeline in occurrence order.

        Each entry contains only ``status`` and ``occurred_at`` (a UTC
        RFC3339 string). The final entry's status always equals the result
        of :meth:`get_status`. Invalid, unknown and cross-tenant ids raise
        :class:`RequestNotFound` with identical behaviour, so the call
        cannot reveal another tenant's records or which ids exist.
        """
        tenant_id = _require_nonempty_str(tenant_id, "tenant_id")
        request_id = _require_identifier(request_id)
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
            # like get_status().
            try:
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
            except RequestNotFound:
                raise
            except sqlite3.Error:
                raise _storage_failure() from None
        finally:
            self._release(conn)
        return [
            {"status": status, "occurred_at": occurred_at}
            for status, occurred_at in rows
        ]

    def evidence(
        self,
        tenant_id: str,
        request_id: str,
    ) -> dict[str, object]:
        """Return the persisted integrity evidence for a request.

        The result contains exactly ``request_id``, ``status`` (identical
        to :meth:`get_status`), ``event_count`` (identical to the length
        of :meth:`audit`) and ``chain_hash`` (the SHA-256 head of the
        audit chain as persisted, never recomputed). Invalid, unknown and
        cross-tenant ids raise :class:`RequestNotFound`; a non-string or
        empty *tenant_id* raises :class:`ValueError`.
        """
        tenant_id = _require_nonempty_str(tenant_id, "tenant_id")
        request_id = _require_identifier(request_id)
        if self._mem_conn is not None:
            with self._write_lock:
                return self._evidence(tenant_id, request_id)
        return self._evidence(tenant_id, request_id)

    def _evidence(self, tenant_id: str, request_id: str) -> dict[str, object]:
        status, head_hash, event_count = self._load_chain_head(
            tenant_id, request_id
        )
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

    def verify_evidence(self, tenant_id: str, request_id: str) -> bool:
        """Verify the full persisted evidence chain for a request.

        The check is read only and evaluates, together:

        * the ordered event timeline -- gap-free sequences from zero,
          every link recomputed from the genesis predecessor;
        * the request association -- every event belongs to this tenant
          and request, and the final link matches the request-row head
          and current status;
        * the external trust anchors -- one per event, each authentic
          under the anchor key held outside the database, chained in
          store-wide anchor order onto the persisted anchor head;
        * the cross-restart result -- the anchor sequence is intact
          globally and the persisted head equals the final anchor.

        Deleting, altering, inserting, reordering or substituting
        events across requests or tenants, a missing/damaged anchor or
        head, a database written before anchors existed, or an
        interrupted commit all yield ``False`` -- and so does a chain
        whose events, request head and stored anchors were all
        recomputed by an attacker: without the external anchor key no
        replacement anchor authenticates. Verification never writes,
        repairs, backfills, recomputes-for-storage or overwrites
        anything, and repeated calls change no record. Invalid,
        unknown and cross-tenant ids raise :class:`RequestNotFound`; a
        non-string or empty *tenant_id* raises :class:`ValueError`.
        """
        return self.verify_chain(tenant_id, request_id)

    def verify_chain(self, tenant_id: str, request_id: str) -> bool:
        """Full-chain verification: events, head, anchors and head anchor.

        Same read-only check as :meth:`verify_evidence`, offered under
        its explicit name. Returns ``True`` only when every layer is
        intact; every tampering, substitution or interrupted commit
        returns ``False`` and never raises a forgery into place.
        """
        tenant_id = _require_nonempty_str(tenant_id, "tenant_id")
        request_id = _require_identifier(request_id)
        if self._mem_conn is not None:
            with self._write_lock:
                reason = self._full_chain_check(tenant_id, request_id)
        else:
            reason = self._full_chain_check(tenant_id, request_id)
        return reason is None

    def diagnose_chain(
        self, tenant_id: str, request_id: str
    ) -> dict[str, object]:
        """Read-only recovery diagnosis for a request's evidence chain.

        Returns exactly ``trusted`` (a bool) and ``reason`` (``None``
        when trusted, otherwise a fixed, detail-free code naming only
        the structural check that failed): ``event_chain_invalid``,
        ``request_head_mismatch``, ``anchors_missing``,
        ``anchor_event_mismatch``, ``anchor_sequence_broken``,
        ``anchor_head_mismatch`` or ``anchor_authentication_failed``.
        The report contains no tenant, request id, hash, key, SQL or
        path and never repairs, backfills, recomputes or overwrites any
        evidence. Invalid, unknown and cross-tenant ids raise
        :class:`RequestNotFound`; a non-string or empty *tenant_id*
        raises :class:`ValueError`; a storage fault raises the
        fixed-text :class:`OSError`.
        """
        tenant_id = _require_nonempty_str(tenant_id, "tenant_id")
        request_id = _require_identifier(request_id)
        if self._mem_conn is not None:
            with self._write_lock:
                reason = self._full_chain_check(tenant_id, request_id)
        else:
            reason = self._full_chain_check(tenant_id, request_id)
        return {"trusted": reason is None, "reason": reason}

    def _full_chain_check(
        self, tenant_id: str, request_id: str
    ) -> str | None:
        """Return ``None`` for a fully trusted chain, else a reason code.

        Raises :class:`RequestNotFound` for an unknown/cross-tenant id
        and the fixed-text :class:`OSError` for an unreadable store;
        every structural or cryptographic failure is one fixed reason
        code, never an engine text or a piece of evidence.
        """
        conn = self._connect()
        try:
            try:
                # Gate on the request row exactly like audit(): an empty
                # timeline must not distinguish "missing" from "foreign".
                owner = conn.execute(
                    "SELECT status, chain_hash FROM requests "
                    "WHERE tenant_id = ? AND request_id = ?",
                    (tenant_id, request_id),
                ).fetchone()
                if owner is None:
                    raise RequestNotFound("request not found")
                current_status, anchored_head = owner
                event_rows = conn.execute(
                    "SELECT seq, status, occurred_at, chain_hash "
                    "FROM status_events "
                    "WHERE tenant_id = ? AND request_id = ? ORDER BY seq",
                    (tenant_id, request_id),
                ).fetchall()
                # The whole store's anchor chain is the single source: a
                # forgery appended anywhere in the global sequence must be
                # caught even if this request's own anchors are untouched.
                global_anchor_rows = conn.execute(
                    "SELECT anchor_seq, tenant_id, request_id, event_seq, "
                    "event_hash, anchor_hash FROM chain_anchors "
                    "ORDER BY anchor_seq"
                ).fetchall()
                global_head = conn.execute(
                    "SELECT anchor_seq, anchor_hash FROM chain_anchor_head "
                    "WHERE id = 1"
                ).fetchone()
            except RequestNotFound:
                raise
            except sqlite3.Error:
                # Never surface the database engine's own error text.
                raise _storage_failure() from None
        finally:
            self._release(conn)

        # Layer 1: the ordered event chain itself.
        if (
            not isinstance(current_status, str)
            or current_status not in _ALLOWED_TRANSITIONS
            or not _is_chain_hash(anchored_head)
            or not event_rows
        ):
            return _DIAG_EVENT_CHAIN
        predecessor = _GENESIS_PREDECESSOR
        for expected_seq, row in enumerate(event_rows):
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
                or status not in _ALLOWED_TRANSITIONS
                or not isinstance(occurred_at, str)
                or not occurred_at
                or not _is_chain_hash(stored_hash)
            ):
                return _DIAG_EVENT_CHAIN
            recomputed = _chain_hash(
                tenant_id,
                request_id,
                seq,
                status,
                occurred_at,
                predecessor,
            )
            if not hmac.compare_digest(recomputed, stored_hash):
                return _DIAG_EVENT_CHAIN
            predecessor = stored_hash

        # Layer 2: the final link is the head anchored on the request row
        # and its status is the authoritative current status.
        if not hmac.compare_digest(predecessor, anchored_head):
            return _DIAG_HEAD
        if event_rows[-1][1] != current_status:
            return _DIAG_HEAD

        # Layer 3: the global anchor table must be structurally sound
        # (gap-free from one, well-formed rows, one anchor per event
        # anywhere in the store). A forgery inserted anywhere in the
        # global sequence -- even on another tenant's request -- must
        # fail the verification of every chain.
        if not global_anchor_rows:
            # A database written before anchors existed (or one stripped
            # of its anchors) must never be treated as fully verified.
            return _DIAG_MISSING_ANCHORS
        anchors_by_event: dict[tuple[str, str, int], tuple[int, str, str]] = {}
        for expected_global, row in enumerate(global_anchor_rows, start=1):
            anchor_seq, a_tenant, a_request, event_seq, event_hash, anchor_hash = (
                row
            )
            if (
                not isinstance(anchor_seq, int)
                or isinstance(anchor_seq, bool)
                or anchor_seq != expected_global
                or not isinstance(a_tenant, str)
                or not a_tenant
                or not isinstance(a_request, str)
                or not a_request
                or not isinstance(event_seq, int)
                or isinstance(event_seq, bool)
                or event_seq < 0
                or not _is_chain_hash(event_hash)
                or not _is_chain_hash(anchor_hash)
            ):
                return _DIAG_ANCHOR_SEQUENCE
            key = (a_tenant, a_request, event_seq)
            if key in anchors_by_event:
                # Two anchors for one event: the table is not a faithful
                # one-anchor-per-event ledger.
                return _DIAG_ANCHOR_COUNT
            anchors_by_event[key] = (anchor_seq, event_hash, anchor_hash)

        # Layer 4: exactly one external anchor for each event of THIS
        # request, covering the same gap-free event sequences and naming
        # the event's own link.
        own_by_event: dict[int, tuple[int, str, str]] = {}
        for (a_tenant, a_request, event_seq), value in anchors_by_event.items():
            if a_tenant == tenant_id and a_request == request_id:
                own_by_event[event_seq] = value
        if len(own_by_event) != len(event_rows):
            return _DIAG_ANCHOR_COUNT
        for expected_event in range(len(event_rows)):
            if expected_event not in own_by_event:
                return _DIAG_ANCHOR_COUNT
            _anchor_seq, event_hash, _anchor_hash = own_by_event[expected_event]
            # The anchor must name this exact event link: a substituted
            # event from another request or tenant cannot match.
            if not hmac.compare_digest(
                event_hash, event_rows[expected_event][3]
            ):
                return _DIAG_ANCHOR_COUNT

        # Layer 5: the persisted anchor head equals the final global
        # anchor, and EVERY global anchor -- from the genesis sentinel
        # through the head -- authenticates under the key held outside
        # the database, chaining onto the real global predecessor (which
        # may belong to another request). An attacker who recomputed the
        # events, the request head and every stored anchor, or appended a
        # forged anchor and advanced the head, still fails here without
        # the external anchor key: the MAC is the one value such a
        # rewrite cannot regenerate.
        if global_head is None:
            return _DIAG_ANCHOR_HEAD
        head_seq, head_hash = global_head
        if (
            not isinstance(head_seq, int)
            or isinstance(head_seq, bool)
            or head_seq != len(global_anchor_rows)
            or not _is_chain_hash(head_hash)
            or not hmac.compare_digest(head_hash, global_anchor_rows[-1][5])
        ):
            return _DIAG_ANCHOR_HEAD
        predecessor = _ANCHOR_GENESIS_HASH
        for row in global_anchor_rows:
            anchor_seq, a_tenant, a_request, event_seq, event_hash, anchor_hash = (
                row
            )
            expected = _anchor_mac(
                self._anchor_key,
                anchor_seq,
                a_tenant,
                a_request,
                event_seq,
                event_hash,
                predecessor,
            )
            if not hmac.compare_digest(expected, anchor_hash):
                return _DIAG_ANCHOR_MAC
            predecessor = anchor_hash
        return None

    def _verify_evidence(
        self, tenant_id: str, request_id: str
    ) -> bool:
        # Retained as the private hook used by the read paths; the full
        # check (events, head, external anchors, anchor head) is the
        # single implementation.
        return self._full_chain_check(tenant_id, request_id) is None

    def _load_chain_head(
        self, tenant_id: str, request_id: str
    ) -> tuple[str, str, int]:
        conn = self._connect()
        try:
            try:
                row = conn.execute(
                    "SELECT r.status, r.chain_hash, "
                    "(SELECT count(*) FROM status_events e "
                    " WHERE e.tenant_id = r.tenant_id "
                    "   AND e.request_id = r.request_id) "
                    "FROM requests r WHERE r.tenant_id = ? AND r.request_id = ?",
                    (tenant_id, request_id),
                ).fetchone()
            except sqlite3.Error:
                raise _storage_failure() from None
        finally:
            self._release(conn)
        if row is None:
            # Identical outcome for unknown ids and cross-tenant lookups.
            raise RequestNotFound("request not found")
        return row[0], row[1], row[2]

    # -- deletion receipts ---------------------------------------------

    def generate_receipt(
        self,
        tenant_id: str,
        request_id: str,
        key: str,
    ) -> str:
        """Issue the externally verifiable deletion receipt for a request.

        Storage-layer only; never routed over HTTP. The receipt is a
        single compact JSON line (fixed field order, exactly one
        trailing newline) binding the tenant, the request id, the first
        acceptance time, the final completion time, a scope commitment
        digest and a completing-attempt digest, plus an authentication
        tag computed under the caller-held *key*. Only a request whose
        deletion completed with a settled execution record -- the
        earliest terminal attempt recorded ``completed`` -- can be
        issued a receipt; an accepted, processing or failed request (or
        a completed status without a completed terminal attempt) raises
        :class:`ReceiptUnavailable`.

        The first receipt commits atomically with nothing else changing:
        no status, attempt, lease or audit record is created or altered.
        Regenerating returns the stored first receipt byte-for-byte,
        whichever key is presented, and concurrent generations persist
        exactly one record. A corrupt stored receipt raises the
        fixed-text :class:`OSError`; it is never repaired, recomputed or
        overwritten. The key is never persisted, returned or logged.

        A non-string or empty *tenant_id* or *key* raises
        :class:`ValueError` without writing; a missing, empty,
        non-string, malformed, unknown, cross-tenant or
        never-accepted *request_id* raises :class:`RequestNotFound`
        identically, so the request-id validation can never reveal
        which ids exist.

        The receipt is always tagged with the tenant's current active
        receipt key: the first generation registers the presented key
        as generation 1, and after a rotation a retired key is rejected
        with :class:`ReceiptKeyConflict` -- an old key can never mint a
        new receipt. Existing receipts are unaffected: regeneration
        still replays the stored first bytes, and an old receipt still
        verifies under the key generation that signed it.
        """
        # Validate everything before touching the database: no rejected
        # call may perform a write. The request id follows the same
        # boundary as every other request entry -- malformed values
        # collapse to RequestNotFound rather than ValueError, so the
        # validation itself can never be an existence oracle.
        tenant_id = _require_nonempty_str(tenant_id, "tenant_id")
        request_id = _require_identifier(request_id)
        key = _require_nonempty_str(key, "key")

        with self._write_lock:
            conn = self._connect()
            try:
                try:
                    conn.execute("BEGIN IMMEDIATE")
                except sqlite3.Error:
                    raise _storage_failure() from None
                try:
                    text = self._generate_receipt_locked(
                        conn, tenant_id, request_id, key
                    )
                    conn.execute("COMMIT")
                except (RequestNotFound, ReceiptUnavailable, ReceiptKeyConflict):
                    self._rollback_quietly(conn)
                    raise
                except OSError:
                    self._rollback_quietly(conn)
                    raise
                except sqlite3.IntegrityError:
                    # BEGIN IMMEDIATE plus the write lock serialise
                    # creators in this process; the unique keys can
                    # only fire if another process sharing the file
                    # committed first. Resolve which race this was:
                    # the same receipt was generated first (replay its
                    # stored bytes, whichever key we presented), or the
                    # tenant's generation 1 was registered by another
                    # first mint with a different active key (a key
                    # conflict; never mint under a non-active key).
                    self._rollback_quietly(conn)
                    text = self._resolve_lost_mint_race(
                        conn, tenant_id, request_id, key
                    )
                except sqlite3.Error:
                    self._rollback_quietly(conn)
                    raise _storage_failure() from None
            finally:
                self._release(conn)
        _log.info("deletion receipt generated request_id=%s", request_id)
        return text

    def _resolve_lost_mint_race(
        self,
        conn: sqlite3.Connection,
        tenant_id: str,
        request_id: str,
        key: str,
    ) -> str:
        """Re-evaluate a mint after another process won a unique-key race.

        A fresh write transaction re-runs the whole decision: the
        receipt may now exist (its stored first bytes are replayed no
        matter which key is presented), the tenant's generation 1 may
        now be registered with a matching active key (the mint
        proceeds under it), or the active key may be a different one
        (the detail-free :class:`ReceiptKeyConflict` stands; a retired
        or foreign key never mints).
        """
        try:
            conn.execute("BEGIN IMMEDIATE")
            text = self._generate_receipt_locked(conn, tenant_id, request_id, key)
            conn.execute("COMMIT")
            return text
        except (RequestNotFound, ReceiptUnavailable, ReceiptKeyConflict):
            self._rollback_quietly(conn)
            raise
        except OSError:
            self._rollback_quietly(conn)
            raise
        except sqlite3.Error:
            self._rollback_quietly(conn)
            raise _storage_failure() from None

    def _generate_receipt_locked(
        self,
        conn: sqlite3.Connection,
        tenant_id: str,
        request_id: str,
        key: str,
    ) -> str:
        """Issue or replay the receipt inside an open write txn."""
        row = conn.execute(
            "SELECT status, created_at, scopes_json FROM requests "
            "WHERE tenant_id = ? AND request_id = ?",
            (tenant_id, request_id),
        ).fetchone()
        if row is None:
            # Unknown, cross-tenant and never-accepted ids share one
            # outcome, so the call cannot reveal which records exist.
            raise RequestNotFound("request not found")
        status, created_at, scopes_json = row

        stored = self._load_receipt_row_locked(conn, tenant_id, request_id)
        if stored is not None:
            # Idempotent replay: the first receipt is returned exactly
            # as stored, whichever key is presented now. It is never
            # recomputed, backfilled or overwritten.
            return stored[1]

        if (
            status not in _ALLOWED_TRANSITIONS
            or not isinstance(created_at, str)
            or not created_at
        ):
            # A status outside the lifecycle or a broken acceptance time
            # is out-of-band corruption, never a receiptable state.
            raise _storage_failure()
        if status != _STATUS_COMPLETED:
            # Accepted, processing and failed requests cannot obtain a
            # deletion receipt; the fixed message does not say which.
            raise ReceiptUnavailable(_RECEIPT_UNAVAILABLE_MESSAGE)

        try:
            scopes = json.loads(scopes_json)
        except (TypeError, ValueError):
            raise _storage_failure() from None
        if (
            not isinstance(scopes, list)
            or not scopes
            or not all(isinstance(item, str) and item for item in scopes)
        ):
            raise _storage_failure()

        attempts = self._load_attempts_for_receipt(conn, tenant_id, request_id)
        terminals = [
            attempt for attempt in attempts if attempt["result"] is not None
        ]
        if not terminals:
            # A completed status without any settled execution record
            # (e.g. a bare status-machine transition) has no completed
            # deletion to attest.
            raise ReceiptUnavailable(_RECEIPT_UNAVAILABLE_MESSAGE)
        # The earliest completion wins; later duplicate terminal rows
        # never alter the receipt's content.
        earliest = min(
            terminals,
            key=lambda attempt: (
                attempt["completed_at"],  # type: ignore[index]
                attempt["attempt_number"],
            ),
        )
        if earliest["result"] != _STATUS_COMPLETED:
            # The settled execution record does not show a completed
            # deletion, so no deletion receipt may be issued.
            raise ReceiptUnavailable(_RECEIPT_UNAVAILABLE_MESSAGE)

        fields: dict[str, str] = {
            "tenant_id": tenant_id,
            "request_id": request_id,
            "created_at": created_at,
            "completed_at": earliest["completed_at"],  # type: ignore[assignment]
            "scope_digest": _scope_digest(tenant_id, request_id, scopes),
            "attempt_digest": _attempt_digest(tenant_id, request_id, earliest),
        }
        # Mint only under the tenant's current active key. The first
        # receipt a tenant ever issues registers its presented key as
        # generation 1 in the same transaction as the receipt row, so
        # the two can never disagree (and a rollback never leaves a
        # key generation without the receipt that introduced it).
        # After a rotation the active key is the only key allowed to
        # sign a new receipt: a retired key reaching this mint path
        # without a stored receipt is rejected without writing.
        self._require_active_or_bootstrap_key_locked(conn, tenant_id, key)
        fields["tag"] = _receipt_tag(key, fields)
        text = _render_receipt(fields)
        # The receipt row is the only write of this transaction; it
        # commits atomically and never half-exists.
        conn.execute(
            "INSERT INTO deletion_receipts (tenant_id, request_id, receipt_json) "
            "VALUES (?, ?, ?)",
            (tenant_id, request_id, text),
        )
        return text

    @staticmethod
    def _load_receipt_row_locked(
        conn: sqlite3.Connection, tenant_id: str, request_id: str
    ) -> tuple[dict[str, str], str] | None:
        """Return ``(fields, text)`` of the persisted receipt, or None.

        The stored text must parse as a well-formed receipt and be
        exactly the canonical rendering of its fields. Anything else is
        out-of-band corruption and raises the fixed-text
        :class:`OSError`; the record is never repaired, recomputed or
        overwritten on the way out.
        """
        row = conn.execute(
            "SELECT receipt_json FROM deletion_receipts "
            "WHERE tenant_id = ? AND request_id = ?",
            (tenant_id, request_id),
        ).fetchone()
        if row is None:
            return None
        text = row[0]
        if not isinstance(text, str):
            raise _storage_failure()
        try:
            fields = _parse_receipt_text(text)
        except ValueError:
            raise _storage_failure() from None
        if _render_receipt(fields) != text:
            # Only the canonical rendering is ever written; a
            # re-serialised or reordered record was altered out of band.
            raise _storage_failure()
        return fields, text

    @staticmethod
    def _load_attempts_for_receipt(
        conn: sqlite3.Connection, tenant_id: str, request_id: str
    ) -> list[dict[str, object]]:
        """Read and strictly validate every attempt row for a receipt.

        A malformed sequence, timestamp or result/completion pairing is
        storage corruption and raises the fixed-text :class:`OSError`
        before any receipt is built from the rows.
        """
        rows = conn.execute(
            "SELECT attempt_number, claimed_at, lease_expires_at, "
            "result, completed_at FROM claim_attempts "
            "WHERE tenant_id = ? AND request_id = ? ORDER BY attempt_number",
            (tenant_id, request_id),
        ).fetchall()
        attempts: list[dict[str, object]] = []
        for index, row in enumerate(rows, start=1):
            attempt_number, claimed_at, lease_expires_at, result, completed_at = row
            if (
                not isinstance(attempt_number, int)
                or isinstance(attempt_number, bool)
                or attempt_number != index
                or not isinstance(claimed_at, str)
                or not claimed_at
                or not isinstance(lease_expires_at, str)
                or not lease_expires_at
            ):
                raise _storage_failure()
            if result is not None and (
                not isinstance(result, str) or result not in _TERMINAL_RESULTS
            ):
                raise _storage_failure()
            if completed_at is not None and (
                not isinstance(completed_at, str) or not completed_at
            ):
                raise _storage_failure()
            # Result and completion time are set together and never
            # separately; a split row is a broken invariant.
            if (result is None) != (completed_at is None):
                raise _storage_failure()
            attempts.append(
                {
                    "attempt_number": attempt_number,
                    "claimed_at": claimed_at,
                    "lease_expires_at": lease_expires_at,
                    "result": result,
                    "completed_at": completed_at,
                }
            )
        return attempts

    # -- receipt key rotation -------------------------------------------

    @staticmethod
    def _load_key_generations_locked(
        conn: sqlite3.Connection, tenant_id: str
    ) -> list[tuple[int, str, str]]:
        """Return a tenant's registered key generations as strict rows.

        Rows are ``(generation, fingerprint, effective_at)`` in
        generation order. Generations start at 1 and are gap-free, each
        fingerprint is 64 lowercase hex characters and each effective
        time a UTC RFC3339 string; anything else is out-of-band
        corruption and raises the fixed-text :class:`OSError`, never a
        half-read generation set.
        """
        rows = conn.execute(
            "SELECT generation, key_fingerprint, effective_at "
            "FROM receipt_keys WHERE tenant_id = ? ORDER BY generation",
            (tenant_id,),
        ).fetchall()
        generations: list[tuple[int, str, str]] = []
        for index, row in enumerate(rows, start=1):
            generation, fingerprint, effective_at = row
            if (
                not isinstance(generation, int)
                or isinstance(generation, bool)
                or generation != index
                or not _is_chain_hash(fingerprint)
                or not isinstance(effective_at, str)
                or not _RFC3339_RE.match(effective_at)
            ):
                raise _storage_failure()
            generations.append((generation, fingerprint, effective_at))
        return generations

    def _require_active_or_bootstrap_key_locked(
        self,
        conn: sqlite3.Connection,
        tenant_id: str,
        key: str,
    ) -> None:
        """Admit *key* as the minting key inside an open write txn.

        A tenant's first ever receipt bootstraps generation 1 with the
        presented key, inserted in the same transaction as the receipt
        row. Afterwards only the current active generation may sign a
        new receipt: a retired or never-registered key reaches the mint
        path without a stored receipt and gets the single, detail-free
        :class:`ReceiptKeyConflict`, so which fingerprints exist can
        never be probed through distinct failures.

        The full generation set is validated (gap-free generations with
        well-formed fingerprints and times) before the active row is
        trusted: a tampered key history is storage corruption and
        raises the fixed-text :class:`OSError` rather than minting off
        a forged active row.
        """
        generations = self._load_key_generations_locked(conn, tenant_id)
        fingerprint = _key_fingerprint(key)
        if not generations:
            conn.execute(
                "INSERT INTO receipt_keys ("
                "tenant_id, generation, key_fingerprint, effective_at"
                ") VALUES (?, 1, ?, ?)",
                (tenant_id, fingerprint, _utc_now_rfc3339()),
            )
            return
        active_fingerprint = generations[-1][1]
        if not hmac.compare_digest(active_fingerprint, fingerprint):
            raise ReceiptKeyConflict(_RECEIPT_KEY_CONFLICT_MESSAGE)

    def rotate_receipt_key(
        self,
        tenant_id: str,
        retired_key: str,
        new_key: str,
    ) -> dict[str, object]:
        """Rotate the tenant's receipt authentication key.

        Storage-layer only; never routed over HTTP. *retired_key* is
        the tenant's currently active key and *new_key* its successor.
        On success exactly one new generation becomes active and the
        result carries ``generation`` (a positive int) and
        ``effective_at`` (the UTC RFC3339 rotation time); old
        generations remain registered solely so receipts signed under
        them keep verifying, and only fingerprints, generations and
        times are persisted -- key material never enters the database,
        a return value, an exception or a log.

        * With no generation registered yet (no receipt was ever
          generated) the first rotation establishes generations 1 and
          2 atomically and returns generation 2.
        * Repeating the rotation that produced the active generation is
          idempotent and returns that first generation and its first
          effective time.
        * A retired key that is registered but no longer active, the
          replay of an already superseded rotation pair, or a successor
          key already registered raises :class:`ReceiptKeyConflict`
          with generations unchanged; a concurrent rotation with a
          different successor loses identically, so only the first
          transaction ever produces the active generation.
        * When generations already exist but *retired_key* names no
          registered generation, :class:`ValueError` is raised; empty
          or non-string arguments and identical keys are
          :class:`ValueError` as well, and no rejected call commits.

        Generations, times and historical receipts survive restarts;
        an unfinished rotation is rolled back as a whole and can never
        appear effective. Every storage fault is the fixed-text
        :class:`OSError`.
        """
        tenant_id = _require_nonempty_str(tenant_id, "tenant_id")
        retired_key = _require_nonempty_str(retired_key, "retired_key")
        new_key = _require_nonempty_str(new_key, "new_key")
        if retired_key == new_key:
            raise ValueError("retired_key and new_key must differ")

        with self._write_lock:
            conn = self._connect()
            try:
                try:
                    conn.execute("BEGIN IMMEDIATE")
                except sqlite3.Error:
                    raise _storage_failure() from None
                try:
                    result = self._rotate_receipt_key_locked(
                        conn, tenant_id, retired_key, new_key
                    )
                    conn.execute("COMMIT")
                except (ValueError, ReceiptKeyConflict):
                    self._rollback_quietly(conn)
                    raise
                except sqlite3.IntegrityError:
                    # Another process sharing the file won the same
                    # generation slot: an identical rotation replays
                    # idempotently, any other lost race is a conflict.
                    self._rollback_quietly(conn)
                    result = self._resolve_lost_rotation_race(
                        conn, tenant_id, retired_key, new_key
                    )
                except sqlite3.Error:
                    self._rollback_quietly(conn)
                    raise _storage_failure() from None
            finally:
                self._release(conn)
        # Only the generation number is logged -- never a fingerprint
        # or any key material.
        _log.info("receipt key rotated generation=%s", result["generation"])
        return result

    def _rotate_receipt_key_locked(
        self,
        conn: sqlite3.Connection,
        tenant_id: str,
        retired_key: str,
        new_key: str,
    ) -> dict[str, object]:
        """Apply one rotation inside an already-open write transaction."""
        generations = self._load_key_generations_locked(conn, tenant_id)
        retired_fp = _key_fingerprint(retired_key)
        new_fp = _key_fingerprint(new_key)

        if not generations:
            # No active generation yet: the first rotation establishes
            # both generation 1 (the retired key) and generation 2 (the
            # new key) in this one atomic commit. Receipts generated
            # afterwards are signed by generation 2; receipts that were
            # minted before any rotation cannot exist for this tenant.
            effective_at = _utc_now_rfc3339()
            conn.execute(
                "INSERT INTO receipt_keys ("
                "tenant_id, generation, key_fingerprint, effective_at"
                ") VALUES (?, 1, ?, ?), (?, 2, ?, ?)",
                (
                    tenant_id,
                    retired_fp,
                    effective_at,
                    tenant_id,
                    new_fp,
                    effective_at,
                ),
            )
            return {"generation": 2, "effective_at": effective_at}

        active_generation, active_fp, active_effective_at = generations[-1]

        # Idempotent replay first: the exact pair that produced the
        # active generation returns the first generation and time, even
        # though the retired key is no longer current.
        if len(generations) >= 2:
            predecessor_fp = generations[-2][1]
            if hmac.compare_digest(
                predecessor_fp, retired_fp
            ) and hmac.compare_digest(active_fp, new_fp):
                return {
                    "generation": active_generation,
                    "effective_at": active_effective_at,
                }

        if hmac.compare_digest(retired_fp, active_fp):
            for _gen, fingerprint, _at in generations:
                if hmac.compare_digest(fingerprint, new_fp):
                    # The successor already has a generation (a retired
                    # key, or the active key itself); reusing it would
                    # alias generations and is rejected unchanged.
                    raise ReceiptKeyConflict(_RECEIPT_KEY_CONFLICT_MESSAGE)
            effective_at = _utc_now_rfc3339()
            conn.execute(
                "INSERT INTO receipt_keys ("
                "tenant_id, generation, key_fingerprint, effective_at"
                ") VALUES (?, ?, ?, ?)",
                (tenant_id, active_generation + 1, new_fp, effective_at),
            )
            return {
                "generation": active_generation + 1,
                "effective_at": effective_at,
            }

        # The retired key is not the active generation. A consecutive
        # historical pair presented again after it was superseded is
        # the explicit "superseded rotation combination" conflict; any
        # other registered-but-old key simply does not match the
        # current generation. Both share one detail-free outcome.
        for index in range(len(generations) - 1):
            if hmac.compare_digest(
                generations[index][1], retired_fp
            ) and hmac.compare_digest(generations[index + 1][1], new_fp):
                raise ReceiptKeyConflict(_RECEIPT_KEY_CONFLICT_MESSAGE)
        if any(
            hmac.compare_digest(fingerprint, retired_fp)
            for _gen, fingerprint, _at in generations
        ):
            raise ReceiptKeyConflict(_RECEIPT_KEY_CONFLICT_MESSAGE)
        # Generations exist, but the presented retired key names none
        # of them: the rotation is missing the generation it claims to
        # retire. Caller error, not a conflict -- and nothing commits.
        raise ValueError("retired_key does not name a registered generation")

    def _resolve_lost_rotation_race(
        self,
        conn: sqlite3.Connection,
        tenant_id: str,
        retired_key: str,
        new_key: str,
    ) -> dict[str, object]:
        """Resolve the outcome after another process won the insert race."""
        try:
            conn.execute("BEGIN IMMEDIATE")
            generations = self._load_key_generations_locked(conn, tenant_id)
            conn.execute("COMMIT")
        except sqlite3.Error:
            self._rollback_quietly(conn)
            raise _storage_failure() from None
        if len(generations) < 2:
            # The winning transaction registered no successor; nothing
            # can be safely returned as a rotation result.
            raise _storage_failure()
        retired_fp = _key_fingerprint(retired_key)
        new_fp = _key_fingerprint(new_key)
        active_generation, active_fp, active_effective_at = generations[-1]
        predecessor_fp = generations[-2][1]
        if hmac.compare_digest(predecessor_fp, retired_fp) and hmac.compare_digest(
            active_fp, new_fp
        ):
            # The winner committed the identical rotation: replay its
            # first generation and time.
            return {
                "generation": active_generation,
                "effective_at": active_effective_at,
            }
        # A different successor won; the loser observes the same
        # detail-free conflict an in-process loser would, with the
        # winner's generation untouched.
        raise ReceiptKeyConflict(_RECEIPT_KEY_CONFLICT_MESSAGE)

    def verify_receipt(self, receipt_text: str, key: str) -> bool:
        """Authenticate a presented deletion receipt text.

        Returns ``True`` only on a complete match: the text is a
        well-formed receipt, it names a persisted receipt record whose
        fields it equals exactly, the presented key names one of the
        tenant's registered receipt key generations, and its
        authentication tag recomputes under that key. An old key
        presented for a newer receipt, a new key presented for an older
        receipt, a foreign tenant's key, any replaced field, tag,
        timestamp or tenant/request association -- and any well-formed
        text whose tag does not authenticate -- all return ``False``;
        the named request merely existing never substitutes for the
        authentication, and a request or receipt that does not exist
        is simply ``False`` as well.

        A malformed *receipt_text* or a non-string or empty *key* raises
        :class:`ValueError`; a corrupt persisted receipt or key record
        and every storage fault raise the fixed-text :class:`OSError`.
        Verification never writes, repairs or recomputes persisted data.
        """
        # Validate both parameters before touching the database.
        fields = _parse_receipt_text(receipt_text)
        key = _require_nonempty_str(key, "key")
        if self._mem_conn is not None:
            with self._write_lock:
                return self._verify_receipt(receipt_text, fields, key)
        return self._verify_receipt(receipt_text, fields, key)

    def _verify_receipt(
        self, text: str, fields: dict[str, str], key: str
    ) -> bool:
        conn = self._connect()
        try:
            try:
                stored = self._load_receipt_row_locked(
                    conn, fields["tenant_id"], fields["request_id"]
                )
                fingerprints = [
                    fingerprint
                    for _generation, fingerprint, _effective_at
                    in self._load_key_generations_locked(
                        conn, fields["tenant_id"]
                    )
                ]
            except sqlite3.Error:
                raise _storage_failure() from None
        finally:
            self._release(conn)
        if stored is None:
            return False
        _stored_fields, stored_text = stored
        # A complete match: the presented text is byte-for-byte the
        # persisted first receipt, and its tag authenticates under the
        # presented key. A re-serialised, reordered or re-spaced copy,
        # or a copy named after another tenant/request, is False.
        if not hmac.compare_digest(stored_text, text):
            return False
        if not fingerprints:
            # A database written before key generations existed has
            # receipts but no fingerprint rows; such a historical
            # receipt verifies exactly as it always did -- the tag
            # alone decides -- so existing evidence stays readable
            # after an upgrade. Every receipt minted by this version
            # registers its key generation atomically, so a fingerprint
            # set can only be empty for genuinely historical rows.
            expected = _receipt_tag(key, fields)
            return hmac.compare_digest(expected, fields["tag"])
        presented_fingerprint = _key_fingerprint(key)
        if not any(
            hmac.compare_digest(presented_fingerprint, fingerprint)
            for fingerprint in fingerprints
        ):
            # The presented key was never registered for the receipt's
            # tenant: an old key on a newer receipt, a newer key on an
            # older receipt, or a foreign key all share one outcome, so
            # verification can never be used to tell which generations
            # exist.
            return False
        # The key names one of the tenant's generations; the HMAC then
        # decides whether it is the generation that actually signed
        # this receipt.
        expected = _receipt_tag(key, fields)
        return hmac.compare_digest(expected, fields["tag"])
