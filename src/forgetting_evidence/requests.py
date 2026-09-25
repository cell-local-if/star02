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

A database-only chain cannot, however, tell a genuine timeline from
one an attacker rewrote in full: with the file in hand every event,
every request head and every commitment stored *in that file* can be
recomputed so the internal hashes verify again. The store therefore
optionally anchors every acceptance and every actual status change to
an external trust anchor: when constructed with an ``anchor_secret``
the caller keeps outside the database, each event also receives an
HMAC-SHA256 anchor keyed with that secret, binding the tenant, request,
sequence, status, occurrence time, the event's own ``chain_hash`` and
the preceding anchor. Anchors form their own per-request chain from a
fixed genesis predecessor, are stored one-to-one with the events they
anchor, and the current global anchor head is held exactly once in a
single-row meta table. The event, its request head, its anchor and the
new global head always commit in one transaction, so a failure at any
stage rolls the whole write back as the fixed-text :class:`OSError`
and never leaves a record that could be judged complete.

The anchor secret exists only in the constructing process's memory: it
is never persisted (only irreversible HMAC outputs are), never placed
in a receipt, return value, exception or log, and anchors cannot be
rebuilt from the stored events, heads or other public contents. A
store opened without a secret keeps the historical, un-anchored
behaviour; an already anchored database rejects writes from a store
that cannot settle the next anchor rather than appending an
un-anchored event. :meth:`RequestStore.verify_chain` performs the
read-only full-chain check -- event order, request association,
database link hashes, per-request anchor authentication, the
events-to-anchors binding and the global head, across restarts and
across every tenant in the file -- and :meth:`RequestStore.diagnose_chain`
reports only the fixed reason codes that make a timeline untrusted,
never repairing, backfilling, recomputing or overwriting anything.
Old (un-anchored) databases, corrupt anchors, split heads and
interrupted commits verify as ``False``.

The anchor secret itself supports recoverable generation rotation,
storage-layer only via :meth:`RequestStore.rotate_anchor_key`: a
retired-secret/enabled-secret pair atomically promotes one new
generation, and a rebuilt store is handed the current secret plus the
historical secrets keyed by generation through the optional
``anchor_history_secrets`` constructor mapping. Every anchor keeps
using the secret generation active when its event was committed --
past anchors are never rewritten -- so an event anchored under an old
generation verifies only while that generation's secret is presented,
and a rebuilt instance missing a needed historical secret reports the
fixed ``anchor_key_missing`` diagnosis rather than trusting the chain.
Only generation numbers, effective times and irreversible fingerprints
are persisted; the historical secrets always stay with the caller.

Read-only batch inspection closes the audit capability, storage-layer
only like the rest of the orchestration and never routed over HTTP:
:meth:`RequestStore.audit_inspection` sweeps a tenant's requests in
stable acceptance order (first acceptance time, then request id) in
resumable, persistent batches. The first call creates a durable batch
whose keyset position survives restarts; presenting the issued cursor
resumes that batch from its committed position without re-reporting
settled items. Each item carries only the request id, a boolean
verified flag and a stable reason code (empty when verified): the
request's own event chain, chain head, status, event/anchor binding
and anchor authentication are assessed together with the file-wide
seal (meta head, secret generations, commit order and the replayed
global head). The sweep is strictly read-only for every audit, anchor
and key record -- it never repairs, backfills, recomputes or
overwrites them; only the inspection bookkeeping tables are written,
and the whole page -- batch resolution or creation, every item, the
cursor position and the possible finish marker -- commits in one
transaction. Concurrent continuations naming the same tenant, batch
and cursor are therefore atomic: the winning call advances exactly
one page and reports its items with the post-commit progress, while
the competing call writes nothing, returns the same shape with an
empty item list and the winner's committed position, and a finished
cursor stays null for every caller.

:meth:`RequestStore.audit_inspection_summary` is the read-only
companion entry point, storage-layer only like the sweep itself. It
takes just a tenant and a batch identifier and returns one compact
JSON line (exactly one trailing newline) holding, in order,
``batch_id``, ``scanned``, ``verified``, ``unverified``,
``next_cursor`` and ``finished`` -- counts only (``scanned`` is the
sum of the other two), no per-item results, and never a float, a
negative zero or a non-finite value. It never advances a cursor,
creates a batch, repairs evidence or writes any business or audit
record; a missing or cross-tenant batch raises
:class:`AuditInspectionNotFound`, invalid arguments raise
:class:`ValueError`, and corrupt bookkeeping or any storage fault is
the fixed-text :class:`OSError`, never a fabricated summary.

:meth:`RequestStore.audit_inspection_metrics` is the read-only
reason-aggregating companion, storage-layer only like the sweep and
the summary. It takes just a tenant and a batch identifier and
returns one compact JSON line (exactly one trailing newline)
holding, in order, ``batch_id``, ``scanned``, ``reasons``,
``next_cursor`` and ``finished``: the batch's aggregate progress
plus the per-reason breakdown of its unverified items. ``reasons``
is a list of ``{"reason", "count"}`` entries -- the stable reason
code and a positive integer count -- sorted by reason code in
Unicode code point order, with duplicate reasons merged, every
unverified item contributing exactly one to its reason and verified
items (empty reason) never appearing; an empty list renders as
``[]``. The whole snapshot is read inside a single read-only
transaction: it never advances a cursor, creates a batch, repairs
evidence or writes any record, and the text never contains a float,
a negative zero or a non-finite value. A missing or cross-tenant
batch raises :class:`AuditInspectionNotFound`, invalid arguments
raise :class:`ValueError`, and corrupt bookkeeping or any storage
fault is the fixed-text :class:`OSError`, never fabricated metrics.

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
    "AnchorKeyConflict",
    "AuditInspectionNotFound",
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


class AnchorKeyConflict(Exception):
    """Raised when an anchor key rotation cannot land as asked.

    A concurrent rotation committed a different enabled secret first:
    only the first transaction promotes the new generation, and the
    loser observes this single, detail-free outcome so the active
    generation can never be probed through distinguishable failures.
    """


class AuditInspectionNotFound(Exception):
    """Raised when no inspection batch visible to the tenant matches.

    A summary is requested for a batch id that is missing or owned by
    another tenant; both share one detail-free outcome, so the
    read-only summary can never reveal another tenant's batches.
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

# Persistent audit-inspection batches. Same resumable keyset shape as
# the reconcile batches, but for the read-only integrity sweep: the
# batch row and its committed position survive restarts, so presenting
# the same cursor again resumes the sweep from its durable position
# instead of restarting it. The inspection never writes to any audit,
# anchor or key table -- only to these two bookkeeping tables.
_INSPECTION_BATCH_TABLE = """
CREATE TABLE IF NOT EXISTS inspection_batches (
    batch_id            TEXT PRIMARY KEY,
    tenant_id           TEXT NOT NULL,
    position_created_at TEXT,
    position_request_id TEXT,
    finished            INTEGER NOT NULL DEFAULT 0
);
"""

# Per-item inspection outcomes, one row per scanned request. Each row is
# written in the same transaction as the batch position advance, so a
# crash can never leave a scanned request without its bookkeeping (or
# vice versa) and a cursor retry never re-reports a settled item.
# ``verified`` is 1/0 and ``reason`` the stable reason code reported for
# the item (empty when the request's chain verified).
_INSPECTION_BATCH_ITEM_TABLE = """
CREATE TABLE IF NOT EXISTS inspection_batch_items (
    batch_id    TEXT NOT NULL,
    seq         INTEGER NOT NULL,
    request_id  TEXT NOT NULL,
    verified    INTEGER NOT NULL,
    reason      TEXT NOT NULL,
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

# External cross-restart trust anchors, one row per anchored status
# event. ``commit_seq`` is the file-wide sealing order (1, 2, 3, ...) so
# the global head can be replayed deterministically; ``anchor_hmac`` is
# the HMAC-SHA256 of the event's business fields, its database chain
# hash and the preceding anchor, keyed with the caller-held anchor
# secret. Neither value can be derived from anything stored in the file
# without that secret. Rows are inserted in the same transaction as the
# events they anchor and never updated or deleted by the store, so an
# event can never exist without its anchor or vice versa.
_ANCHOR_TABLE = """
CREATE TABLE IF NOT EXISTS audit_anchors (
    commit_seq  INTEGER NOT NULL,
    tenant_id   TEXT NOT NULL,
    request_id  TEXT NOT NULL,
    seq         INTEGER NOT NULL,
    event_hash  TEXT NOT NULL,
    anchor_hmac TEXT NOT NULL,
    key_generation INTEGER,
    PRIMARY KEY (tenant_id, request_id, seq)
);
"""

# The file-wide sealing order is also unique on its own: a renumbered,
# duplicated or deleted anchor leaves a gap or a collision that the
# global-head replay cannot accept.
_ANCHOR_COMMIT_SEQ_INDEX = """
CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_anchors_commit_seq
    ON audit_anchors(commit_seq);
"""

# Exactly one row (id = 1) holding the current global anchor head. The
# head chains every anchor in file-wide commit order, so it cannot be
# recomputed from a single request's rows: a substitution, deletion or
# reordering anywhere in the file changes it. It is upserted in the
# same transaction as the anchor it seals; an interrupted commit leaves
# the old head (or none), never a split one. Only an HMAC is stored --
# the keying material never enters this table.
_ANCHOR_META_TABLE = """
CREATE TABLE IF NOT EXISTS audit_anchor_meta (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    head_hmac  TEXT NOT NULL
);
"""

# Anchor secret generations, one row per secret that has ever sealed
# anchors. Generation 1 is the constructor secret in force when the
# database was first anchored; each :meth:`RequestStore.rotate_anchor_key`
# appends exactly one successor row. Like receipt keys, only an
# irreversible salt-free SHA-256 fingerprint is ever stored -- the
# secret material stays with the caller and is supplied to a rebuilt
# instance out of band -- together with the generation and its UTC
# effective time. Rows are inserted once and never updated or deleted,
# so an anchor sealed under an old generation can always be attributed
# to the exact secret generation active when it was committed.
_ANCHOR_KEY_TABLE = """
CREATE TABLE IF NOT EXISTS anchor_key_generations (
    generation     INTEGER PRIMARY KEY,
    key_fingerprint TEXT NOT NULL,
    effective_at   TEXT NOT NULL
);
"""

# Each secret may own exactly one generation: rotating back to a
# retired secret would let two generations authenticate the same
# material and is rejected as caller error before any write.
_ANCHOR_KEY_FINGERPRINT_INDEX = """
CREATE UNIQUE INDEX IF NOT EXISTS idx_anchor_key_fingerprint
    ON anchor_key_generations(key_fingerprint);
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
# Additive upgrade probe for the per-anchor secret generation column.
# Existing anchored databases gain a NULL-able column that is never
# backfilled: legacy anchors keep verifying under generation 1, while
# every anchor sealed after the upgrade carries its active generation.
_ANCHOR_GENERATION_COLUMN = (
    "SELECT 1 FROM pragma_table_info('audit_anchors') "
    "WHERE name = 'key_generation'"
)
_ANCHOR_GENERATIONS_TABLE_PROBE = (
    "SELECT 1 FROM sqlite_master WHERE type = 'table' "
    "AND name = 'anchor_key_generations'"
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
# Audit-inspection cursors share the reconcile cursor envelope but carry
# their own version prefix, so a reconcile cursor presented to the
# inspection entry point (or vice versa) is an unknown format and is
# rejected as caller error before storage is touched.
_INSPECTION_CURSOR_PREFIX = "ai1."
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


def _encode_cursor(batch_id: str, position: int, prefix: str = _CURSOR_PREFIX) -> str:
    """Render the opaque cursor for a batch at a given item count."""
    payload = json.dumps(
        {"v": 1, "b": batch_id, "n": position},
        separators=(",", ":"),
    ).encode("utf-8")
    return prefix + base64.urlsafe_b64encode(payload).decode("ascii")


def _decode_cursor(value: object, prefix: str = _CURSOR_PREFIX) -> tuple[str, int]:
    """Parse and strictly validate an opaque cursor.

    Every malformed value -- non-string, empty, wrong prefix, bad
    base64url, foreign JSON shape, wrong types -- raises :class:`ValueError`
    identically, so the cursor format can never be probed through
    distinguishable failures.
    """
    if not isinstance(value, str) or not value.startswith(prefix):
        raise ValueError("cursor is not valid")
    body = value[len(prefix) :]
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


# -- external trust anchors -------------------------------------------

# Fixed genesis predecessors for the two anchor chains. They are
# domain-separated from the database chain's genesis and from each
# other, so the first anchor of a request can never be confused with a
# link chained onto a forged 64-character predecessor.
_ANCHOR_GENESIS_PREDECESSOR = hashlib.sha256(
    b"forgetting-evidence:anchor:request-genesis"
).hexdigest()
_ANCHOR_GLOBAL_GENESIS = hashlib.sha256(
    b"forgetting-evidence:anchor:global-genesis"
).hexdigest()

# Stable, detail-free reason codes reported by diagnose_chain. They name
# only *why* the persisted evidence cannot be trusted -- never a tenant,
# request, credential, SQL text or path -- and diagnosis never repairs,
# backfills, recomputes or overwrites anything.
_ANCHOR_REASON_SECRET_MISSING = "anchor_secret_missing"
_ANCHOR_REASON_UNANCHORED = "unanchored_database"
_ANCHOR_REASON_STATE_SPLIT = "anchor_state_split"
_ANCHOR_REASON_META_CORRUPT = "anchor_meta_corrupt"
_ANCHOR_REASON_EVENT_UNANCHORED = "event_unanchored"
_ANCHOR_REASON_ANCHOR_ORPHAN = "anchor_orphan"
_ANCHOR_REASON_EVENT_ORDER = "event_order_invalid"
_ANCHOR_REASON_CHAIN_MISMATCH = "chain_hash_mismatch"
_ANCHOR_REASON_HEAD_MISMATCH = "chain_head_mismatch"
_ANCHOR_REASON_STATUS_MISMATCH = "request_status_mismatch"
_ANCHOR_REASON_ASSOCIATION = "request_association_mismatch"
_ANCHOR_REASON_AUTH_FAILED = "anchor_auth_failed"
_ANCHOR_REASON_SEQUENCE_GAP = "anchor_sequence_gap"
_ANCHOR_REASON_GLOBAL_HEAD = "anchor_head_mismatch"
_ANCHOR_REASON_CORRUPT_ROW = "anchor_row_corrupt"
# An anchor needs a secret generation the assessing store was not
# handed (neither the current secret nor ``anchor_history_secrets``
# provides it). Distinct from ``anchor_auth_failed``: the material is
# absent, not wrong.
_ANCHOR_REASON_KEY_MISSING = "anchor_key_missing"

# Fixed, detail-free text for every lost anchor rotation race. It never
# says which secret or generation was involved.
_ANCHOR_KEY_CONFLICT_MESSAGE = "anchor key conflict"


def _anchor_mac(
    secret: str,
    tenant_id: str,
    request_id: str,
    seq: int,
    status: str,
    occurred_at: str,
    event_hash: str,
    predecessor: str,
) -> str:
    """Compute one per-request external anchor under the caller secret.

    The anchor binds the event's business fields, its database chain
    hash and the preceding anchor, length-prefixed exactly like the
    database chain so no concatenation can be re-parsed two ways. The
    secret is used only here and in the global-head MAC; it is never
    persisted, returned, logged or placed in an exception, and the
    preimage is never stored either.
    """
    mac = hmac.new(secret.encode("utf-8"), digestmod=hashlib.sha256)
    for field in (
        tenant_id,
        request_id,
        str(seq),
        status,
        occurred_at,
        event_hash,
        predecessor,
    ):
        encoded = field.encode("utf-8")
        mac.update(struct.pack(">Q", len(encoded)))
        mac.update(encoded)
    return mac.hexdigest()


def _anchor_head_mac(
    secret: str,
    predecessor: str,
    anchor_hmac: str,
    tenant_id: str,
    request_id: str,
    seq: int,
) -> str:
    """Seal one anchor into the file-wide global anchor head.

    The head chains anchors in their global commit order, binding each
    anchor value to its tenant/request/sequence association. Because the
    head covers the whole file, deleting, inserting, reordering or
    substituting an anchor anywhere -- including across requests or
    tenants -- changes the recomputed head even though every individual
    anchor value is syntactically valid.
    """
    mac = hmac.new(secret.encode("utf-8"), digestmod=hashlib.sha256)
    for field in (
        predecessor,
        anchor_hmac,
        tenant_id,
        request_id,
        str(seq),
    ):
        encoded = field.encode("utf-8")
        mac.update(struct.pack(">Q", len(encoded)))
        mac.update(encoded)
    return mac.hexdigest()


def _anchor_key_fingerprint(secret: str) -> str:
    """Return the irreversible, salt-free fingerprint of an anchor secret.

    Only this SHA-256 digest is ever persisted in
    ``anchor_key_generations``; the secret material stays with the
    caller and is supplied to a rebuilt instance out of band.
    """
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


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

    Every malformed value -- non-string, a missing or duplicated
    trailing newline, unparsable JSON, a missing or extra field, a
    non-string value, a malformed timestamp or a digest or tag that is
    not 64 lowercase hex characters -- raises :class:`ValueError`
    identically, so the format can never be probed through
    distinguishable failures. A well-formed body whose fields or bytes
    simply do not match the persisted receipt is *not* a parse failure:
    the caller gets ``False`` from verification instead.
    """
    if not isinstance(text, str) or not text:
        raise ValueError("receipt must be a non-empty string")
    # Exactly one trailing newline is part of the receipt format: a
    # missing newline or an extra (duplicated) newline is a malformed
    # presentation rather than an authentication mismatch.
    if not text.endswith("\n") or text.endswith("\n\n"):
        raise ValueError("receipt is not valid")
    try:
        parsed = json.loads(text[:-1])
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
        anchor_secret: str | None = None,
        anchor_history_secrets: Mapping[int, str] | None = None,
    ):
        # Validate the path before touching the filesystem: an empty or
        # non-string path is caller error (ValueError), never a storage
        # fault, and must not create directories.
        if isinstance(db_path, os.PathLike):
            db_path = os.fspath(db_path)
        if not isinstance(db_path, str) or not db_path:
            raise ValueError("storage path must be a non-empty string")
        self._db_path = db_path
        # The external anchor secret is optional and lives only in this
        # process's memory. It is validated as a non-empty string; a
        # non-string or empty value is caller error, never silently
        # downgraded to an un-anchored store. None deliberately opts a
        # store out of anchoring (historical callers). The secret is
        # never written anywhere.
        if anchor_secret is not None:
            if not isinstance(anchor_secret, str) or not anchor_secret:
                raise ValueError("anchor_secret must be a non-empty string")
        self._anchor_secret: str | None = anchor_secret
        # Historical anchor secrets are supplied out of band, keyed by
        # the generation they were active for, so a rebuilt instance can
        # still authenticate anchors sealed before the latest rotation.
        # Only their shape is validated here; the secrets themselves are
        # never written. A mapping without a current secret is meaningless
        # (the store could not seal or authenticate the active
        # generation) and is rejected before storage is touched.
        self._anchor_history_secrets: dict[int, str] = (
            self._validate_history_secrets(anchor_secret, anchor_history_secrets)
        )
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
        except sqlite3.Error:
            raise _storage_failure() from None
        except OSError:
            # makedirs/connect errors embed the offending path; replace
            # them with the fixed-text storage error.
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
                conn.execute(_INSPECTION_BATCH_TABLE)
                conn.execute(_INSPECTION_BATCH_ITEM_TABLE)
                conn.execute(_RECEIPT_TABLE)
                conn.execute(_RECEIPT_KEY_TABLE)
                conn.execute(_RECEIPT_KEY_FINGERPRINT_INDEX)
                conn.execute(_ANCHOR_TABLE)
                conn.execute(_ANCHOR_COMMIT_SEQ_INDEX)
                conn.execute(_ANCHOR_META_TABLE)
                conn.execute(_ANCHOR_KEY_TABLE)
                conn.execute(_ANCHOR_KEY_FINGERPRINT_INDEX)
                self._migrate_schema(conn)
                self._migrate_anchor_generation_column(conn)
            except sqlite3.Error:
                raise _storage_failure() from None
        finally:
            self._release(conn)

    @staticmethod
    def _validate_history_secrets(
        anchor_secret: str | None,
        history: object,
    ) -> dict[int, str]:
        """Validate the optional generation-to-historical-secret mapping.

        The container must be a mapping; every generation key must be a
        non-boolean positive integer and every secret a non-empty
        string. Historical secrets only make sense alongside the
        current secret. Nothing is ever persisted: the validated map
        lives solely in process memory.
        """
        if history is None:
            return {}
        if anchor_secret is None or not isinstance(history, Mapping):
            raise ValueError(
                "anchor_history_secrets must be a mapping of positive "
                "integer generations to non-empty secret strings"
            )
        validated: dict[int, str] = {}
        for generation, secret in history.items():
            if (
                not isinstance(generation, int)
                or isinstance(generation, bool)
                or generation < 1
                or not isinstance(secret, str)
                or not secret
            ):
                raise ValueError(
                    "anchor_history_secrets must be a mapping of positive "
                    "integer generations to non-empty secret strings"
                )
            validated[generation] = secret
        return validated

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

    def _migrate_anchor_generation_column(self, conn: sqlite3.Connection) -> None:
        """Add the per-anchor ``key_generation`` column to an old file.

        Purely additive and idempotent: a database created before anchor
        key rotation existed gains a NULL-able column that is never
        backfilled. Legacy anchors therefore stay attributed to
        generation 1 (the constructor secret the file was anchored
        with), and every anchor sealed after the upgrade records the
        generation active at its commit. Existing anchor evidence is
        never rewritten.
        """
        if conn.execute(_ANCHOR_GENERATION_COLUMN).fetchone():
            return
        with self._write_lock:
            try:
                conn.execute("BEGIN IMMEDIATE")
                # Re-probe in the transaction: another process may have
                # run the upgrade while this one waited on the lock.
                if not conn.execute(_ANCHOR_GENERATION_COLUMN).fetchone():
                    conn.execute(
                        "ALTER TABLE audit_anchors ADD COLUMN key_generation INTEGER"
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
                        # Detect an idempotent replay before gating on the
                        # anchor state: replaying the frozen acceptance
                        # record is a read and must still succeed on a
                        # legacy or differently-anchored file without the
                        # secret. The INSERT below remains the atomic
                        # guard against the concurrent first-writer race.
                        probe = conn.execute(
                            "SELECT request_id FROM requests "
                            "WHERE tenant_id = ? AND idempotency_key = ?",
                            (tenant_id, idempotency_key),
                        ).fetchone()
                        if probe is not None:
                            conn.execute("ROLLBACK")
                            return self._load_idempotent(
                                conn,
                                tenant_id,
                                idempotency_key,
                                subject_id,
                                scope_list,
                            )
                        # A genuinely new acceptance first proves the
                        # committed anchor state is whole under the
                        # configured secret: a wrong secret or a
                        # tampered/legacy file must never accept a new
                        # request.
                        self._require_anchors_intact_locked(conn)
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
                    # The external anchor seals the genesis event in the
                    # same transaction; a failure here rolls the request
                    # and event away as the fixed-text storage error.
                    self._settle_anchor_locked(
                        conn,
                        tenant_id,
                        request_id,
                        0,
                        _STATUS_ACCEPTED,
                        created_at,
                        genesis_hash,
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
        # Authenticate the committed evidence under the configured secret
        # before appending anything, so a wrong secret or a tampered,
        # interrupted or legacy-un-anchored file can never extend the
        # chain. Runs inside the caller's write transaction and rolls it
        # back as the fixed-text storage error on any inconsistency.
        self._require_anchors_intact_locked(conn)
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
        # row by the UPDATE above.
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
        # The external anchor for the new event is settled in this same
        # transaction, after the event insert and before the caller adds
        # the attempt/token rows, so the event, request head, anchor and
        # global head either all commit together or none of them do.
        self._settle_anchor_locked(
            conn,
            tenant_id,
            request_id,
            next_seq + 1,
            target_status,
            occurred_at,
            next_link_hash,
        )
        return occurred_at

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

    # -- read-only audit inspection ------------------------------------

    def audit_inspection(
        self,
        tenant_id: str,
        cursor: str | None = None,
        limit: int | None = None,
    ) -> dict[str, object]:
        """Inspect a tenant's settled audit chains in resumable batches.

        Storage-layer only; never routed over HTTP. With ``cursor``
        omitted a new persistent batch sweeps the tenant's requests in
        stable acceptance order (``created_at`` then ``request_id``);
        with a cursor the batch it names is resumed from its durably
        committed position, so a retry after an interruption or a
        service restart continues instead of restarting, and the same
        cursor always keeps the same batch identifier. Each call
        inspects at most ``limit`` requests (default 100, at most 1000)
        and returns exactly ``batch_id``, ``next_cursor`` (``None`` once
        the sweep is finished), ``finished`` and ``items`` -- one
        ``{"request_id", "verified", "reason"}`` entry per scanned
        request, in scan order. ``verified`` is a boolean and
        ``reason`` the stable, detail-free reason code the request's
        chain failed with (the empty string when it verified).

        Each request is assessed against its settled audit evidence
        exactly like the read-only full-chain verification: the event
        order and database link hashes, the request row's chain head
        and current status, the one-to-one event/anchor binding, every
        anchor's authentication under its own sealing generation, and
        the file-wide seal (the singleton meta head, the secret
        generation records, the gap-free global commit order and the
        replayed global anchor head). A healthy request verifies with
        an empty reason; deleted, altered, inserted or reordered
        events, cross-request or cross-tenant substitutions, a tampered
        chain head, anchor or global head, a missing historical secret,
        a broken generation association, a forged chain, an un-anchored
        legacy database and an interrupted commit all report
        ``verified`` false with a stable reason code.

        The sweep is strictly read-only for every audit, anchor and key
        record: it never repairs, backfills, recomputes or overwrites
        them. Only the inspection bookkeeping tables are written -- the
        batch row, one item row per scanned request and the cursor
        position -- and the whole page (batch creation/resolution, every
        item and the position advance or end marker) commits in one
        transaction, so a failed call never returns half-settled results
        and a committed item is never re-reported.

        Concurrent continuations naming the same tenant, batch and
        cursor are atomic: the first transaction to run advances the
        batch by exactly this call's page and returns its items with
        the post-commit progress, while the competing call changes
        nothing and returns the same shape with an empty item list and
        the winner's post-commit progress. Sequential retries of an
        already-continued cursor are identical replays: empty items,
        durable progress, no re-reporting.

        A non-string/empty *tenant_id*, a limit outside 1..1000 (or a
        non-integer or boolean), and any malformed, unknown or
        cross-tenant *cursor* raise :class:`ValueError` without
        writing. Corrupt persisted batch state and every storage fault
        raise the fixed-text :class:`OSError`.
        """
        # Validate everything before touching the database: no rejected
        # call may perform a write.
        tenant_id = _require_nonempty_str(tenant_id, "tenant_id")
        if limit is None:
            limit = _DEFAULT_BATCH_LIMIT
        limit = _require_batch_limit(limit)
        cursor_batch: tuple[str, int] | None = None
        if cursor is not None:
            cursor_batch = _decode_cursor(cursor, _INSPECTION_CURSOR_PREFIX)

        with self._write_lock:
            conn = self._connect()
            try:
                # The whole continuation is one atomic write transaction.
                # BEGIN IMMEDIATE serialises same-batch continuations, in
                # this process through the write lock and across processes
                # sharing the file through the database write lock: the
                # winning transaction advances the entire page (batch row,
                # item rows and cursor position committing together), and
                # a competing transaction only ever reads the winner's
                # committed position.
                batch_id, items, finished, durable_count = (
                    self._batch_transaction(
                        conn,
                        lambda: self._continue_inspection_locked(
                            conn, tenant_id, cursor_batch, limit
                        ),
                    )
                )
            finally:
                self._release(conn)
        # The cursor only identifies the persisted batch; its item count
        # is the database-authoritative settled count read in the same
        # transaction, so the cursor returned to a winner and to a
        # competing loser names the same durable position.
        next_cursor = (
            None
            if finished
            else _encode_cursor(batch_id, durable_count, _INSPECTION_CURSOR_PREFIX)
        )
        # Log only counts and the stable outcome: no tenant, subject,
        # credential or SQL text ever reaches the log.
        _log.info(
            "audit inspection settled items=%s finished=%s",
            len(items),
            finished,
        )
        return {
            "batch_id": batch_id,
            "next_cursor": next_cursor,
            "finished": finished,
            "items": items,
        }

    def _continue_inspection_locked(
        self,
        conn: sqlite3.Connection,
        tenant_id: str,
        cursor_batch: tuple[str, int] | None,
        limit: int,
    ) -> tuple[str, list[dict[str, object]], bool, int]:
        """Advance (or observe) one inspection page in the open write txn.

        Returns ``(batch_id, items, finished, item_count)``. Without a
        cursor a fresh batch row is inserted and the sweep starts before
        the first row; with a cursor the named batch is resumed from its
        durably committed position -- the cursor's own position field is
        only an envelope detail, the database is authoritative.

        When the durable item count is already ahead of the position the
        presented cursor was issued at, a concurrent (or retried)
        continuation committed first: nothing is scanned or written and
        the winner's post-commit progress is returned with an empty item
        list, so a settled item is never re-reported. Otherwise up to
        ``limit`` candidates after the durable position are assessed in
        stable scan order; the item rows, the cursor position and the
        possible end-of-sweep marker all commit with the batch row in
        the caller's single transaction. Only the inspection
        bookkeeping tables are touched -- never a request, status
        event, attempt, lease, receipt, anchor or key record.

        An unknown or cross-tenant batch id is an invalid cursor and
        raises :class:`ValueError`; corrupt persisted state raises the
        fixed-text :class:`OSError`.
        """
        if cursor_batch is None:
            batch_id = str(uuid.uuid4())
            conn.execute(
                "INSERT INTO inspection_batches ("
                "batch_id, tenant_id, position_created_at, "
                "position_request_id, finished"
                ") VALUES (?, ?, NULL, NULL, 0)",
                (batch_id, tenant_id),
            )
            issued_position = 0
        else:
            batch_id, issued_position = cursor_batch
            # Confirm ownership before reading state: an unknown or
            # cross-tenant batch id is an invalid cursor, indistinguishable
            # from one that never existed.
            owner = conn.execute(
                "SELECT 1 FROM inspection_batches WHERE batch_id = ? AND tenant_id = ?",
                (batch_id, tenant_id),
            ).fetchone()
            if owner is None:
                raise ValueError("cursor is not valid")

        pos_created, pos_rid, finished, item_count = (
            self._read_inspection_state_locked(conn, batch_id)
        )
        if item_count > issued_position:
            # A concurrent same-cursor continuation (or a sequential
            # replay) already advanced the batch past this cursor's
            # issued position: observe the committed progress, report
            # nothing twice and write nothing.
            return batch_id, [], finished, item_count

        items: list[dict[str, object]] = []
        # Assess up to ``limit`` rows strictly after the durable
        # position. Each item row, the position advance and the possible
        # finish marker land in this one transaction, so the page either
        # commits whole or rolls back whole.
        while not finished and len(items) < limit:
            row = self._next_inspection_candidate(
                conn, tenant_id, pos_created, pos_rid
            )
            if row is None:
                self._finish_inspection_locked(conn, batch_id)
                finished = True
                break
            request_id, created_at = row
            item = self._inspect_request_locked(conn, tenant_id, request_id)
            # The sequence derives from the durable count plus this
            # page's offset, so a resumed batch never reuses a number.
            conn.execute(
                "INSERT INTO inspection_batch_items ("
                "batch_id, seq, request_id, verified, reason"
                ") VALUES (?, ?, ?, ?, ?)",
                (
                    batch_id,
                    item_count + 1 + len(items),
                    request_id,
                    1 if item["verified"] else 0,
                    item["reason"],
                ),
            )
            pos_created, pos_rid = created_at, request_id
            items.append(item)
        if items:
            self._advance_inspection_locked(
                conn, batch_id, pos_created, pos_rid
            )
        if not finished:
            # A limit-stopped page may also have consumed the last
            # candidate: finish the batch in this same transaction when
            # nothing remains after the new position.
            if (
                self._next_inspection_candidate(
                    conn, tenant_id, pos_created, pos_rid
                )
                is None
            ):
                self._finish_inspection_locked(conn, batch_id)
                finished = True
        # Re-read the authoritative end flag and count inside the same
        # transaction rather than trusting the in-memory tally.
        _pos_created, _pos_rid, finished, final_count = (
            self._read_inspection_state_locked(conn, batch_id)
        )
        return batch_id, items, finished, final_count

    def _read_inspection_state_locked(
        self, conn: sqlite3.Connection, batch_id: str
    ) -> tuple[str | None, str | None, bool, int]:
        """Read and strictly validate an inspection batch's position."""
        row = conn.execute(
            "SELECT position_created_at, position_request_id, finished, "
            "(SELECT count(*) FROM inspection_batch_items i "
            " WHERE i.batch_id = b.batch_id) "
            "FROM inspection_batches b WHERE b.batch_id = ?",
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

    def audit_inspection_summary(
        self,
        tenant_id: str,
        batch_id: str,
    ) -> str:
        """Return a compact, read-only summary of an inspection batch.

        Storage-layer only; never routed over HTTP. The caller supplies
        only the tenant and the batch identifier issued by
        :meth:`audit_inspection` (not a cursor). The summary never
        advances a cursor, never creates a batch, never repairs
        evidence and never writes any business or audit record -- it is
        a pure read of the existing inspection bookkeeping.

        The result is one compact JSON object with exactly one trailing
        newline and exactly these fields in order: ``batch_id``,
        ``scanned``, ``verified``, ``unverified``, ``next_cursor`` and
        ``finished``. The three counts are non-negative integers with
        ``scanned`` equal to ``verified`` plus ``unverified``; the
        batch id and cursor are strings or null and ``finished`` is a
        boolean -- the text never contains a float, a negative zero or
        a non-finite number. ``next_cursor`` is null exactly when the
        batch has finished; otherwise it is the cursor that resumes the
        batch from its committed position. No per-item results are
        included.

        An empty or non-string *tenant_id* or *batch_id* raises
        :class:`ValueError` without touching storage; a batch that is
        missing or owned by another tenant raises
        :class:`AuditInspectionNotFound` with one detail-free outcome,
        so another tenant's batches can never be probed. A storage
        outage, corrupt inspection bookkeeping or a read failure
        raises the fixed-text :class:`OSError` instead of a fabricated
        summary.
        """
        # Validate before touching the database: a rejected call never
        # reads or writes anything.
        tenant_id = _require_nonempty_str(tenant_id, "tenant_id")
        batch_id = _require_nonempty_str(batch_id, "batch_id")
        if self._mem_conn is not None:
            with self._write_lock:
                return self._audit_inspection_summary(tenant_id, batch_id)
        return self._audit_inspection_summary(tenant_id, batch_id)

    def _audit_inspection_summary(self, tenant_id: str, batch_id: str) -> str:
        conn = self._connect()
        try:
            try:
                # Resolve ownership first: a missing batch and another
                # tenant's batch share one indistinguishable outcome.
                owner = conn.execute(
                    "SELECT 1 FROM inspection_batches "
                    "WHERE batch_id = ? AND tenant_id = ?",
                    (batch_id, tenant_id),
                ).fetchone()
                if owner is None:
                    raise AuditInspectionNotFound("audit inspection batch not found")
                _pos_created, _pos_rid, finished, scanned = (
                    self._read_inspection_state_locked(conn, batch_id)
                )
                flags = conn.execute(
                    "SELECT verified FROM inspection_batch_items "
                    "WHERE batch_id = ?",
                    (batch_id,),
                ).fetchall()
            except AuditInspectionNotFound:
                raise
            except sqlite3.Error:
                raise _storage_failure() from None
        finally:
            self._release(conn)

        # Every persisted item flag must be the 0/1 the sweep writes;
        # anything else is bookkeeping corruption, never a count to
        # divide silently.
        verified = 0
        for (flag,) in flags:
            if not isinstance(flag, int) or isinstance(flag, bool) or flag not in (0, 1):
                raise _storage_failure()
            verified += flag
        unverified = len(flags) - verified
        # The item table and the batch row's own position are committed
        # together; a split tally is out-of-band damage.
        if unverified < 0 or scanned != len(flags) or scanned != verified + unverified:
            raise _storage_failure()

        next_cursor = (
            None
            if finished
            else _encode_cursor(batch_id, scanned, _INSPECTION_CURSOR_PREFIX)
        )
        summary = {
            "batch_id": batch_id,
            "scanned": scanned,
            "verified": verified,
            "unverified": unverified,
            "next_cursor": next_cursor,
            "finished": finished,
        }
        text = json.dumps(summary, ensure_ascii=False, separators=(",", ":")) + "\n"
        # Log only counts and the stable outcome: no tenant, batch id,
        # credential or SQL text ever reaches the log.
        _log.info(
            "audit inspection summary read scanned=%s verified=%s finished=%s",
            scanned,
            verified,
            finished,
        )
        return text

    def audit_inspection_metrics(
        self,
        tenant_id: str,
        batch_id: str,
    ) -> str:
        """Return compact, read-only reason metrics of an inspection batch.

        Storage-layer only; never routed over HTTP. The caller supplies
        only the tenant and the batch identifier issued by
        :meth:`audit_inspection` (not a cursor). The metrics never
        advance a cursor, never create a batch, never repair evidence
        and never write any business or audit record -- the whole
        snapshot is read inside a single read-only transaction.

        The result is one compact JSON object with exactly one trailing
        newline and exactly these fields in order: ``batch_id``,
        ``scanned``, ``reasons``, ``next_cursor`` and ``finished``.
        ``scanned`` is the non-negative integer count of items the
        sweep has settled so far. ``reasons`` is the stable per-reason
        breakdown of the unverified items: a list of ``{"reason",
        "count"}`` entries sorted by reason code in Unicode code point
        order, each ``count`` a positive integer, duplicate reasons
        merged and every unverified item contributing exactly one;
        verified items (empty reason) never appear, and an empty
        breakdown renders as ``[]``. The batch id and cursor are
        strings or null (``next_cursor`` is null exactly when the batch
        has finished) and ``finished`` is a boolean -- the text never
        contains a float, a negative zero or a non-finite number. No
        per-item results, subjects, scopes, secrets or SQL text are
        included.

        An empty or non-string *tenant_id* or *batch_id* raises
        :class:`ValueError` without touching storage; a batch that is
        missing or owned by another tenant raises
        :class:`AuditInspectionNotFound` with one detail-free outcome,
        so another tenant's batches can never be probed. A storage
        outage, corrupt inspection bookkeeping or a read failure
        raises the fixed-text :class:`OSError` instead of fabricated
        metrics.
        """
        # Validate before touching the database: a rejected call never
        # reads or writes anything.
        tenant_id = _require_nonempty_str(tenant_id, "tenant_id")
        batch_id = _require_nonempty_str(batch_id, "batch_id")
        if self._mem_conn is not None:
            with self._write_lock:
                return self._audit_inspection_metrics(tenant_id, batch_id)
        return self._audit_inspection_metrics(tenant_id, batch_id)

    def _audit_inspection_metrics(self, tenant_id: str, batch_id: str) -> str:
        conn = self._connect()
        try:
            try:
                # The whole snapshot is one read-only transaction: every
                # row is read against the same committed state, and the
                # transaction is rolled back rather than committed to
                # underline that nothing is ever written.
                conn.execute("BEGIN")
                # Resolve ownership first: a missing batch and another
                # tenant's batch share one indistinguishable outcome.
                owner = conn.execute(
                    "SELECT 1 FROM inspection_batches "
                    "WHERE batch_id = ? AND tenant_id = ?",
                    (batch_id, tenant_id),
                ).fetchone()
                if owner is None:
                    raise AuditInspectionNotFound("audit inspection batch not found")
                _pos_created, _pos_rid, finished, scanned = (
                    self._read_inspection_state_locked(conn, batch_id)
                )
                rows = conn.execute(
                    "SELECT verified, reason FROM inspection_batch_items "
                    "WHERE batch_id = ?",
                    (batch_id,),
                ).fetchall()
            except AuditInspectionNotFound:
                raise
            except sqlite3.Error:
                raise _storage_failure() from None
            finally:
                try:
                    conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
        finally:
            self._release(conn)

        # Every persisted item must be exactly what the sweep writes: a
        # 0/1 flag and a reason that is empty precisely when the item
        # verified. Anything else is bookkeeping corruption, never a
        # tally to report silently.
        counts: dict[str, int] = {}
        for flag, reason in rows:
            if not isinstance(flag, int) or isinstance(flag, bool) or flag not in (0, 1):
                raise _storage_failure()
            if not isinstance(reason, str):
                raise _storage_failure()
            if flag == 1:
                if reason != "":
                    raise _storage_failure()
                continue
            if reason == "":
                raise _storage_failure()
            counts[reason] = counts.get(reason, 0) + 1
        # The item table and the batch row's own position are committed
        # together; a split tally is out-of-band damage.
        if scanned != len(rows):
            raise _storage_failure()

        # Code point order is exactly Python's string ordering.
        reasons = [
            {"reason": reason, "count": counts[reason]}
            for reason in sorted(counts)
        ]
        next_cursor = (
            None
            if finished
            else _encode_cursor(batch_id, scanned, _INSPECTION_CURSOR_PREFIX)
        )
        metrics = {
            "batch_id": batch_id,
            "scanned": scanned,
            "reasons": reasons,
            "next_cursor": next_cursor,
            "finished": finished,
        }
        text = json.dumps(metrics, ensure_ascii=False, separators=(",", ":")) + "\n"
        # Log only counts and the stable outcome: no tenant, batch id,
        # reason text, credential or SQL text ever reaches the log.
        _log.info(
            "audit inspection metrics read scanned=%s reasons=%s finished=%s",
            scanned,
            len(reasons),
            finished,
        )
        return text

    @staticmethod
    def _next_inspection_candidate(
        conn: sqlite3.Connection,
        tenant_id: str,
        pos_created: str | None,
        pos_rid: str | None,
    ) -> tuple[str, str] | None:
        """Oldest request strictly after the keyset position.

        Every request of the tenant is swept, whatever its status: the
        inspection covers the settled audit chain each acceptance
        started. The (created_at, request_id) ordering is the same
        stable order the claim and reconcile scans use, so the sweep is
        stable across calls, restarts and concurrent submissions.
        """
        if pos_created is None:
            return conn.execute(
                "SELECT request_id, created_at FROM requests "
                "WHERE tenant_id = ? "
                "ORDER BY created_at ASC, request_id ASC LIMIT 1",
                (tenant_id,),
            ).fetchone()
        return conn.execute(
            "SELECT request_id, created_at FROM requests "
            "WHERE tenant_id = ? AND (created_at, request_id) > (?, ?) "
            "ORDER BY created_at ASC, request_id ASC LIMIT 1",
            (tenant_id, pos_created, pos_rid),
        ).fetchone()

    @staticmethod
    def _advance_inspection_locked(
        conn: sqlite3.Connection,
        batch_id: str,
        pos_created: str,
        pos_rid: str,
    ) -> None:
        """Move the inspection batch's durable keyset position forward."""
        cursor = conn.execute(
            "UPDATE inspection_batches "
            "SET position_created_at = ?, position_request_id = ? "
            "WHERE batch_id = ?",
            (pos_created, pos_rid, batch_id),
        )
        if cursor.rowcount != 1:
            # The batch row this transaction itself resolved vanished;
            # that is storage corruption, never a caller error.
            raise _storage_failure()

    @staticmethod
    def _finish_inspection_locked(conn: sqlite3.Connection, batch_id: str) -> None:
        """Mark the inspection batch durably finished in the open txn."""
        cursor = conn.execute(
            "UPDATE inspection_batches SET finished = 1 WHERE batch_id = ?",
            (batch_id,),
        )
        if cursor.rowcount != 1:
            raise _storage_failure()

    def _inspect_request_locked(
        self,
        conn: sqlite3.Connection,
        tenant_id: str,
        request_id: str,
    ) -> dict[str, object]:
        """Assess one request's settled chain inside the open transaction.

        Reads the same persisted evidence the full-chain assessment
        uses, then evaluates the request's own chain together with the
        file-wide seal that also binds it. Purely read-only: nothing is
        written, repaired, recomputed-into-place or overwritten.
        """
        meta_rows = conn.execute(
            "SELECT head_hmac FROM audit_anchor_meta"
        ).fetchall()
        event_rows = conn.execute(
            "SELECT tenant_id, request_id, seq, status, occurred_at, "
            "chain_hash FROM status_events ORDER BY tenant_id, request_id, seq"
        ).fetchall()
        anchor_rows = conn.execute(
            "SELECT commit_seq, tenant_id, request_id, seq, event_hash, "
            "anchor_hmac, key_generation FROM audit_anchors ORDER BY commit_seq"
        ).fetchall()
        request_rows = conn.execute(
            "SELECT tenant_id, request_id, status, chain_hash FROM requests"
        ).fetchall()
        generation_rows = conn.execute(
            "SELECT generation, key_fingerprint, effective_at "
            "FROM anchor_key_generations ORDER BY generation"
        ).fetchall()
        reasons = self._evaluate_inspection_rows(
            tuple(meta_rows),
            tuple(event_rows),
            tuple(anchor_rows),
            tuple(request_rows),
            tuple(generation_rows),
            self._anchor_secret,
            self._anchor_history_secrets,
            (tenant_id, request_id),
        )
        return {
            "request_id": request_id,
            "verified": not reasons,
            "reason": reasons[0] if reasons else "",
        }

    @staticmethod
    def _evaluate_inspection_rows(
        meta_rows: tuple,
        event_rows: tuple,
        anchor_rows: tuple,
        request_rows: tuple,
        generation_rows: tuple,
        secret: str | None,
        history_secrets: Mapping[int, str],
        scope: tuple[str, str],
    ) -> list[str]:
        """Pure, read-only per-request evaluation of the persisted chain.

        Kept free of any connection so the logic is deterministic and
        side-effect free: it only compares and recomputes, never writes.
        Returns the sorted stable reason codes that make the scoped
        request's settled audit chain untrusted -- an empty list means
        the request verifies. Two layers are assessed:

        * the request's own evidence: event order and database link
          hashes, the request row's chain head and current status, the
          one-to-one event/anchor binding and every anchor's
          authentication under the secret of the generation recorded on
          its own row;
        * the file-wide seal the request cannot be trusted without: the
          singleton meta head, the secret-generation records, the
          gap-free global commit order, the replayed global anchor head
          and file-wide split or orphaned evidence.
        """
        scope_tenant, scope_request = scope
        global_reasons: set[str] = set()
        scoped_reasons: set[str] = set()

        # -- singleton meta head (file-wide) -------------------------
        stored_head: str | None = None
        if len(meta_rows) > 1:
            global_reasons.add(_ANCHOR_REASON_META_CORRUPT)
        elif meta_rows:
            stored_head = meta_rows[0][0]
            if not _is_chain_hash(stored_head):
                global_reasons.add(_ANCHOR_REASON_META_CORRUPT)
                stored_head = None

        # -- secret generations (file-wide) --------------------------
        # One gap-free row per generation that has ever sealed anchors,
        # starting at 1, each with a well-formed fingerprint and an
        # effective time; legacy anchors carry NULL and are attributed
        # to generation 1.
        generation_fingerprints: dict[int, str] = {}
        generation_corrupt = False
        for index, grow in enumerate(generation_rows, start=1):
            generation, fingerprint, effective_at = grow
            if (
                not isinstance(generation, int)
                or isinstance(generation, bool)
                or generation != index
                or not _is_chain_hash(fingerprint)
                or not isinstance(effective_at, str)
                or not _RFC3339_RE.match(effective_at)
            ):
                generation_corrupt = True
            if isinstance(generation, int) and not isinstance(generation, bool):
                generation_fingerprints[generation] = fingerprint
        if anchor_rows and generation_corrupt:
            global_reasons.add(_ANCHOR_REASON_CORRUPT_ROW)
        if generation_rows and not anchor_rows:
            # Secret generations without a single anchor are only valid
            # as the bootstrap-rotation shape (exactly generations 1 and
            # 2 sharing one effective time).
            bootstrap_shape = (
                not generation_corrupt
                and [g for g, _f, _t in generation_rows] == [1, 2]
                and generation_rows[0][2] == generation_rows[1][2]
            )
            if not bootstrap_shape:
                global_reasons.add(_ANCHOR_REASON_CORRUPT_ROW)

        # -- event/anchor population invariants (file-wide) ----------
        # A database with events but no anchor rows is the historical
        # un-anchored shape: old content is never judged trusted.
        legacy_unanchored = bool(event_rows) and not anchor_rows
        if legacy_unanchored:
            global_reasons.add(_ANCHOR_REASON_UNANCHORED)
        if anchor_rows and not event_rows:
            global_reasons.add(_ANCHOR_REASON_STATE_SPLIT)
        if anchor_rows and stored_head is None:
            # Sealed anchors without a global head: an interrupted
            # commit or out-of-band deletion.
            global_reasons.add(_ANCHOR_REASON_META_CORRUPT)

        # -- index the rows ------------------------------------------
        # A malformed evidence row anywhere corrupts the file every
        # request's seal is replayed against, so it is a file-wide
        # reason rather than a per-request one.
        events: dict[tuple, tuple] = {}
        for row in event_rows:
            tenant_id, request_id, seq, status, occurred_at, chain_hash = row
            key = (tenant_id, request_id, seq)
            if (
                not isinstance(tenant_id, str)
                or not tenant_id
                or not isinstance(request_id, str)
                or not request_id
                or not isinstance(seq, int)
                or isinstance(seq, bool)
                or not isinstance(status, str)
                or not status
                or not isinstance(occurred_at, str)
                or not occurred_at
                or not _is_chain_hash(chain_hash)
            ):
                global_reasons.add(_ANCHOR_REASON_CORRUPT_ROW)
            if key in events:
                global_reasons.add(_ANCHOR_REASON_CORRUPT_ROW)
            events[key] = row

        anchors: dict[tuple, tuple] = {}
        for row in anchor_rows:
            (
                commit_seq,
                tenant_id,
                request_id,
                seq,
                event_hash,
                anchor_hmac,
                key_generation,
            ) = row
            key = (tenant_id, request_id, seq)
            if (
                not isinstance(commit_seq, int)
                or isinstance(commit_seq, bool)
                or commit_seq < 1
                or not isinstance(tenant_id, str)
                or not tenant_id
                or not isinstance(request_id, str)
                or not request_id
                or not isinstance(seq, int)
                or isinstance(seq, bool)
                or not _is_chain_hash(event_hash)
                or not _is_chain_hash(anchor_hmac)
                # NULL is the legacy attribution (generation 1); any
                # present value must be a positive integer.
                or not (
                    key_generation is None
                    or (
                        isinstance(key_generation, int)
                        and not isinstance(key_generation, bool)
                        and key_generation >= 1
                    )
                )
            ):
                global_reasons.add(_ANCHOR_REASON_CORRUPT_ROW)
            if key in anchors:
                global_reasons.add(_ANCHOR_REASON_CORRUPT_ROW)
            anchors[key] = row

        requests_by_key = {
            (tenant_id, request_id): (status, chain_hash)
            for tenant_id, request_id, status, chain_hash in request_rows
        }

        # Evidence naming a request row that no longer exists is
        # file-wide corruption: no scanned item can be trusted to be
        # the whole story while stray rows circulate.
        for tenant_id, request_id, _seq in list(events) + list(anchors):
            if (tenant_id, request_id) not in requests_by_key:
                global_reasons.add(_ANCHOR_REASON_ASSOCIATION)

        # -- the scoped request's own chain --------------------------
        scope_key = (scope_tenant, scope_request)
        scoped_event_keys = {
            key for key in events if (key[0], key[1]) == scope_key
        }
        scoped_anchor_keys = {
            key for key in anchors if (key[0], key[1]) == scope_key
        }
        # One-to-one binding: every event anchored, every anchor an
        # event. A legacy database with no anchors at all is already
        # reported as the single unanchored reason and must not cascade.
        if not legacy_unanchored and scoped_event_keys - scoped_anchor_keys:
            scoped_reasons.add(_ANCHOR_REASON_EVENT_UNANCHORED)
        if scoped_anchor_keys - scoped_event_keys:
            scoped_reasons.add(_ANCHOR_REASON_ANCHOR_ORPHAN)

        rows = [events[key] for key in scoped_event_keys]
        # A tampered seq must not raise out of the sort; such a row is
        # already flagged and sorts deterministically to the front.
        rows.sort(
            key=lambda row: (
                not isinstance(row[2], int) or isinstance(row[2], bool),
                row[2]
                if isinstance(row[2], int) and not isinstance(row[2], bool)
                else -1,
            )
        )
        predecessor = _GENESIS_PREDECESSOR
        anchor_predecessor = _ANCHOR_GENESIS_PREDECESSOR
        if not rows:
            # A request row without a single event can only come from
            # out-of-band deletion: the acceptance event is written in
            # the same transaction as the request.
            scoped_reasons.add(_ANCHOR_REASON_EVENT_ORDER)
        for expected_seq, row in enumerate(rows):
            _t, _r, seq, status, occurred_at, chain_hash = row
            well_typed = (
                isinstance(seq, int)
                and not isinstance(seq, bool)
                and isinstance(status, str)
                and isinstance(occurred_at, str)
            )
            if (
                isinstance(seq, int)
                and not isinstance(seq, bool)
                and seq != expected_seq
            ):
                # Deleted, inserted or renumbered event.
                scoped_reasons.add(_ANCHOR_REASON_EVENT_ORDER)
            if well_typed:
                recomputed = _chain_hash(
                    scope_tenant,
                    scope_request,
                    expected_seq,
                    status,
                    occurred_at,
                    predecessor,
                )
                if not hmac.compare_digest(recomputed, chain_hash):
                    scoped_reasons.add(_ANCHOR_REASON_CHAIN_MISMATCH)
            predecessor = chain_hash if isinstance(chain_hash, str) else ""

            anchor_row = anchors.get((scope_tenant, scope_request, expected_seq))
            if anchor_row is not None:
                (
                    _cs,
                    at,
                    ar,
                    aseq,
                    event_hash,
                    anchor_hmac,
                    anchor_generation,
                ) = anchor_row
                if (at, ar, aseq) != (scope_tenant, scope_request, expected_seq):
                    scoped_reasons.add(_ANCHOR_REASON_ASSOCIATION)
                if event_hash != chain_hash:
                    # The anchor seals a different event than the one
                    # persisted here: a cross-request/cross-tenant
                    # substitution cannot silently rebind.
                    scoped_reasons.add(_ANCHOR_REASON_ASSOCIATION)
                if (
                    secret is not None
                    and well_typed
                    and _is_chain_hash(chain_hash)
                    and _is_chain_hash(anchor_hmac)
                ):
                    sealing_secret, secret_status = (
                        RequestStore._resolve_anchor_generation_secret(
                            anchor_generation,
                            generation_fingerprints,
                            secret,
                            history_secrets,
                        )
                    )
                    if secret_status == "missing":
                        # The store was not handed this anchor's
                        # historical generation: it can neither
                        # authenticate nor forge this anchor.
                        scoped_reasons.add(_ANCHOR_REASON_KEY_MISSING)
                    elif secret_status in ("association", "wrong"):
                        # A forged generation association, or a handed
                        # secret that does not match the generation's
                        # persisted fingerprint, can never authenticate.
                        scoped_reasons.add(_ANCHOR_REASON_AUTH_FAILED)
                    else:
                        expected_anchor = _anchor_mac(
                            sealing_secret,
                            scope_tenant,
                            scope_request,
                            expected_seq,
                            status,
                            occurred_at,
                            chain_hash,
                            anchor_predecessor,
                        )
                        if not hmac.compare_digest(expected_anchor, anchor_hmac):
                            scoped_reasons.add(_ANCHOR_REASON_AUTH_FAILED)
                anchor_predecessor = (
                    anchor_hmac if isinstance(anchor_hmac, str) else ""
                )

        request_row = requests_by_key.get(scope_key)
        if request_row is None:
            # Unreachable through the scan (the row was just read), but
            # an out-of-band delete between transactions is corruption.
            scoped_reasons.add(_ANCHOR_REASON_ASSOCIATION)
        else:
            current_status, anchored_head = request_row
            if not _is_chain_hash(anchored_head):
                scoped_reasons.add(_ANCHOR_REASON_HEAD_MISMATCH)
            elif not hmac.compare_digest(anchored_head, predecessor):
                scoped_reasons.add(_ANCHOR_REASON_HEAD_MISMATCH)
            if rows:
                final_status = rows[-1][3]
                if (
                    not isinstance(current_status, str)
                    or not isinstance(final_status, str)
                    or current_status != final_status
                ):
                    scoped_reasons.add(_ANCHOR_REASON_STATUS_MISMATCH)

        # -- global seal: gap-free commit order and the head ---------
        if anchor_rows:
            ordered = sorted(
                (
                    row
                    for row in anchor_rows
                    if isinstance(row[0], int) and not isinstance(row[0], bool)
                ),
                key=lambda row: row[0],
            )
            if [row[0] for row in ordered] != list(range(1, len(anchor_rows) + 1)):
                global_reasons.add(_ANCHOR_REASON_SEQUENCE_GAP)
            elif secret is not None and stored_head is not None:
                head = _ANCHOR_GLOBAL_GENESIS
                replay_ok = True
                replay_block_reason: str | None = None
                for row in ordered:
                    (
                        _commit_seq,
                        tenant_id,
                        request_id,
                        seq,
                        _event_hash,
                        anchor_hmac,
                        anchor_generation,
                    ) = row
                    if not (
                        isinstance(tenant_id, str)
                        and isinstance(request_id, str)
                        and isinstance(seq, int)
                        and not isinstance(seq, bool)
                        and _is_chain_hash(anchor_hmac)
                    ):
                        # A malformed sealing row is already flagged; the
                        # head cannot authenticate off garbage preimages.
                        replay_ok = False
                        break
                    sealing_secret, secret_status = (
                        RequestStore._resolve_anchor_generation_secret(
                            anchor_generation,
                            generation_fingerprints,
                            secret,
                            history_secrets,
                        )
                    )
                    if secret_status != "ok":
                        # The head replay needs every row's actual
                        # sealing secret; without it the file-wide seal
                        # cannot be checked and no request may be judged
                        # trusted on an unverifiable seal.
                        replay_ok = False
                        replay_block_reason = (
                            _ANCHOR_REASON_KEY_MISSING
                            if secret_status == "missing"
                            else _ANCHOR_REASON_AUTH_FAILED
                        )
                        break
                    head = _anchor_head_mac(
                        sealing_secret,
                        head,
                        anchor_hmac,
                        tenant_id,
                        request_id,
                        seq,
                    )
                if replay_ok:
                    if not hmac.compare_digest(head, stored_head):
                        global_reasons.add(_ANCHOR_REASON_GLOBAL_HEAD)
                elif replay_block_reason is not None:
                    global_reasons.add(replay_block_reason)

        if secret is None and anchor_rows:
            # An anchored file assessed by a store that holds no secret
            # cannot be authenticated: never call an unverifiable chain
            # trusted, however internally consistent it looks.
            global_reasons.add(_ANCHOR_REASON_SECRET_MISSING)

        return sorted(global_reasons | scoped_reasons)

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
        """Verify the persisted audit chain for a request.

        Every link is checked against the stored rows only; verification
        never recomputes-and-overwrites persisted evidence. Deleting,
        altering, inserting or reordering events, tampering with the
        request head, or substituting events from another request or
        tenant all yield ``False``. Returns ``True`` only when every link
        recomputes to its stored hash from the genesis predecessor, the
        sequences are gap-free from zero, and the final link matches the
        request's anchored head and current status. Invalid, unknown and
        cross-tenant ids raise :class:`RequestNotFound`; a non-string or
        empty *tenant_id* raises :class:`ValueError`.
        """
        tenant_id = _require_nonempty_str(tenant_id, "tenant_id")
        request_id = _require_identifier(request_id)
        if self._mem_conn is not None:
            with self._write_lock:
                return self._verify_evidence(tenant_id, request_id)
        return self._verify_evidence(tenant_id, request_id)

    def _verify_evidence(
        self, tenant_id: str, request_id: str
    ) -> bool:
        conn = self._connect()
        try:
            # Gate on the request row exactly like audit(): an empty
            # timeline must not distinguish "missing" from "foreign".
            try:
                owner = conn.execute(
                    "SELECT status, chain_hash FROM requests "
                    "WHERE tenant_id = ? AND request_id = ?",
                    (tenant_id, request_id),
                ).fetchone()
                if owner is None:
                    raise RequestNotFound("request not found")
                current_status, anchored_head = owner
                if not _is_chain_hash(anchored_head):
                    return False
                rows = conn.execute(
                    "SELECT seq, status, occurred_at, chain_hash "
                    "FROM status_events "
                    "WHERE tenant_id = ? AND request_id = ? ORDER BY seq",
                    (tenant_id, request_id),
                ).fetchall()
            except RequestNotFound:
                raise
            except sqlite3.Error:
                # Never surface the database engine's own error text.
                raise _storage_failure() from None
        finally:
            self._release(conn)

        predecessor = _GENESIS_PREDECESSOR
        for expected_seq, row in enumerate(rows):
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
                or not isinstance(occurred_at, str)
                or not _is_chain_hash(stored_hash)
            ):
                return False
            recomputed = _chain_hash(
                tenant_id,
                request_id,
                seq,
                status,
                occurred_at,
                predecessor,
            )
            # Constant-time comparison; either mismatch breaks the chain.
            if not hmac.compare_digest(recomputed, stored_hash):
                return False
            predecessor = stored_hash

        # At least the genesis event must exist, the final link must be
        # the head anchored on the request row, and its status must match
        # the authoritative current status.
        if not rows:
            return False
        if not hmac.compare_digest(predecessor, anchored_head):
            return False
        return rows[-1][1] == current_status

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

    # -- external trust anchors ---------------------------------------

    def _fail_anchor_commit_locked(self, conn: sqlite3.Connection):
        """Abort an anchor write and raise the single storage error.

        Every failure while settling an event's anchor -- an un-anchored
        legacy database, a corrupt or split anchor state, a missing
        secret on an anchored file, a bad commit -- rolls the whole
        surrounding transaction back, so the request row, status event,
        anchor and global head can never land separately. The caller
        never sees engine text, SQL or a path.
        """
        try:
            conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        raise _storage_failure()

    def _require_anchors_intact_locked(self, conn: sqlite3.Connection) -> None:
        """Authenticate the committed anchor state before extending it.

        A write under an external secret is only allowed on a database
        whose committed evidence is already whole under *that* secret
        and every historical secret generation the committed anchors
        need. The read-only full assessment is replayed inside the
        write transaction -- per-request chains, every external
        anchor's authentication under its own sealing generation and
        the file-wide global head -- so a store configured with a
        wrong secret, a rebuilt store missing a historical generation
        secret, or an already tampered, interrupted or
        legacy-un-anchored file, can never append an event or a fresh
        anchor. A genuinely empty file vacuously passes and
        bootstraps. The no-secret historical path is gated later by
        :meth:`_settle_anchor_locked`.
        """
        secret = self._anchor_secret
        if secret is None:
            return
        try:
            meta_rows = conn.execute(
                "SELECT head_hmac FROM audit_anchor_meta"
            ).fetchall()
            event_rows = conn.execute(
                "SELECT tenant_id, request_id, seq, status, occurred_at, "
                "chain_hash FROM status_events ORDER BY tenant_id, request_id, seq"
            ).fetchall()
            anchor_rows = conn.execute(
                "SELECT commit_seq, tenant_id, request_id, seq, event_hash, "
                "anchor_hmac, key_generation FROM audit_anchors ORDER BY commit_seq"
            ).fetchall()
            request_rows = conn.execute(
                "SELECT tenant_id, request_id, status, chain_hash FROM requests"
            ).fetchall()
            generation_rows = conn.execute(
                "SELECT generation, key_fingerprint, effective_at "
                "FROM anchor_key_generations ORDER BY generation"
            ).fetchall()
        except sqlite3.Error:
            self._fail_anchor_commit_locked(conn)
            return
        reasons = self._evaluate_chain_rows(
            tuple(meta_rows),
            tuple(event_rows),
            tuple(anchor_rows),
            tuple(request_rows),
            tuple(generation_rows),
            secret,
            self._anchor_history_secrets,
        )
        if reasons:
            self._fail_anchor_commit_locked(conn)

    def _settle_anchor_locked(
        self,
        conn: sqlite3.Connection,
        tenant_id: str,
        request_id: str,
        seq: int,
        status: str,
        occurred_at: str,
        event_hash: str,
    ) -> None:
        """Settle the external anchor for one event inside an open txn.

        Called after the event's database link has been computed but in
        the same transaction as the request row/event insert. With no
        configured secret the store keeps the historical un-anchored
        behaviour only for a database that has never carried an anchor;
        an already anchored file can never accept an un-anchored append.
        With a secret, a legacy database (events but no anchors) is
        refused rather than having its past retroactively "anchored" by
        recomputation -- anchors can only cover events committed under a
        secret from the genesis on.
        """
        secret = self._anchor_secret
        try:
            anchor_count = conn.execute(
                "SELECT count(*) FROM audit_anchors"
            ).fetchone()[0]
            event_count = conn.execute(
                "SELECT count(*) FROM status_events"
            ).fetchone()[0]
            meta_row = conn.execute(
                "SELECT head_hmac FROM audit_anchor_meta WHERE id = 1"
            ).fetchone()
        except sqlite3.Error:
            self._fail_anchor_commit_locked(conn)
            return  # unreachable; keeps type checkers on the branch

        if secret is None:
            # An un-anchored store may only write to a database that
            # belongs to no secret-holding deployment: no anchors, no
            # sealed head and no anchor-key generations (a bootstrap
            # rotation registers generations 1 and 2 before the first
            # anchor). The pending event is already inserted, so a
            # genuinely un-anchored file shows exactly one event with
            # nothing else.
            try:
                generation_count = conn.execute(
                    "SELECT count(*) FROM anchor_key_generations"
                ).fetchone()[0]
            except sqlite3.Error:
                self._fail_anchor_commit_locked(conn)
                return
            if (
                anchor_count != 0
                or meta_row is not None
                or generation_count != 0
            ):
                self._fail_anchor_commit_locked(conn)
            return

        if anchor_count == 0:
            # The pending event is already in status_events. A fresh
            # database has exactly that one event and no head; anything
            # larger is legacy content that must never receive
            # retroactive anchors by recomputation.
            if event_count != 1 or meta_row is not None:
                self._fail_anchor_commit_locked(conn)
            request_predecessor = _ANCHOR_GENESIS_PREDECESSOR
            head_predecessor = _ANCHOR_GLOBAL_GENESIS
            commit_seq = 1
            # The very first anchor seals the secret generation state.
            # Two shapes are legitimate: the generations table is empty
            # (this anchor registers the configured secret as generation
            # 1 in the same transaction), or a bootstrap rotation has
            # already established generations 1 and 2 before the first
            # event (the anchor is sealed by the active generation 2).
            # Anything else is out-of-band corruption.
            try:
                generation_state = conn.execute(
                    "SELECT generation, key_fingerprint, effective_at "
                    "FROM anchor_key_generations ORDER BY generation"
                ).fetchall()
            except sqlite3.Error:
                self._fail_anchor_commit_locked(conn)
                return
            insert_generation_one = False
            if not generation_state:
                active_generation = 1
                bootstrap_effective_at = _utc_now_rfc3339()
                insert_generation_one = True
            else:
                if (
                    [row[0] for row in generation_state] != [1, 2]
                    or not all(_is_chain_hash(row[1]) for row in generation_state)
                    or not all(
                        isinstance(row[2], str) and _RFC3339_RE.match(row[2])
                        for row in generation_state
                    )
                    or generation_state[0][2] != generation_state[1][2]
                    or not hmac.compare_digest(
                        generation_state[-1][1],
                        _anchor_key_fingerprint(secret),
                    )
                ):
                    self._fail_anchor_commit_locked(conn)
                active_generation = 2
            sealing_secret = secret
        else:
            # An anchored database must be internally whole before it is
            # extended: one valid head and exactly one anchor per
            # previously committed event (the pending event accounts
            # for the +1).
            if (
                meta_row is None
                or not _is_chain_hash(meta_row[0])
                or event_count != anchor_count + 1
            ):
                self._fail_anchor_commit_locked(conn)
            head_predecessor = meta_row[0]
            commit_seq = anchor_count + 1
            insert_generation_one = False
            try:
                previous = conn.execute(
                    "SELECT anchor_hmac FROM audit_anchors "
                    "WHERE tenant_id = ? AND request_id = ? ORDER BY seq DESC LIMIT 1",
                    (tenant_id, request_id),
                ).fetchone()
                # The active generation is the single highest row; its
                # fingerprint must match the configured secret before
                # anything new is sealed.
                active_row = conn.execute(
                    "SELECT generation, key_fingerprint "
                    "FROM anchor_key_generations ORDER BY generation DESC LIMIT 1"
                ).fetchone()
            except sqlite3.Error:
                self._fail_anchor_commit_locked(conn)
                return
            if active_row is None:
                # Legacy anchors exist but predate the generations
                # table: they all carry the NULL (generation-1)
                # attribution. Register the configured secret -- already
                # proven by the write gate's full-chain replay to
                # authenticate every legacy anchor -- as generation 1
                # in this same transaction, then seal the new anchor as
                # generation 1. Any non-NULL attribution alongside no
                # generation rows is out-of-band corruption.
                try:
                    attributed = conn.execute(
                        "SELECT count(*) FROM audit_anchors "
                        "WHERE key_generation IS NOT NULL"
                    ).fetchone()[0]
                except sqlite3.Error:
                    self._fail_anchor_commit_locked(conn)
                    return
                if attributed != 0:
                    self._fail_anchor_commit_locked(conn)
                active_generation = 1
                bootstrap_effective_at = _utc_now_rfc3339()
                insert_generation_one = True
            else:
                active_generation, active_fingerprint = active_row
                if (
                    not isinstance(active_generation, int)
                    or isinstance(active_generation, bool)
                    or active_generation < 1
                    or not _is_chain_hash(active_fingerprint)
                    or not hmac.compare_digest(
                        active_fingerprint, _anchor_key_fingerprint(secret)
                    )
                ):
                    # The configured secret is not the active generation
                    # -- a wrong secret or a stale instance after a
                    # rotation.
                    self._fail_anchor_commit_locked(conn)
            if seq == 0:
                # A genesis event can never extend an existing chain.
                if previous is not None:
                    self._fail_anchor_commit_locked(conn)
                request_predecessor = _ANCHOR_GENESIS_PREDECESSOR
            else:
                if previous is None or not _is_chain_hash(previous[0]):
                    self._fail_anchor_commit_locked(conn)
                request_predecessor = previous[0]
            sealing_secret = secret

        anchor = _anchor_mac(
            sealing_secret,
            tenant_id,
            request_id,
            seq,
            status,
            occurred_at,
            event_hash,
            request_predecessor,
        )
        new_head = _anchor_head_mac(
            sealing_secret, head_predecessor, anchor, tenant_id, request_id, seq
        )
        try:
            if insert_generation_one:
                # The generation-1 row lands together with the very
                # first anchor it seals: a failure rolls both away.
                conn.execute(
                    "INSERT INTO anchor_key_generations ("
                    "generation, key_fingerprint, effective_at"
                    ") VALUES (1, ?, ?)",
                    (
                        _anchor_key_fingerprint(sealing_secret),
                        bootstrap_effective_at,
                    ),
                )
            conn.execute(
                "INSERT INTO audit_anchors ("
                "commit_seq, tenant_id, request_id, seq, event_hash, "
                "anchor_hmac, key_generation"
                ") VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    commit_seq,
                    tenant_id,
                    request_id,
                    seq,
                    event_hash,
                    anchor,
                    active_generation,
                ),
            )
            # Upsert the singleton head in the same transaction.
            conn.execute(
                "INSERT INTO audit_anchor_meta (id, head_hmac) VALUES (1, ?) "
                "ON CONFLICT(id) DO UPDATE SET head_hmac = excluded.head_hmac",
                (new_head,),
            )
        except sqlite3.Error:
            self._fail_anchor_commit_locked(conn)

    def verify_chain(
        self,
        tenant_id: str | None = None,
        request_id: str | None = None,
    ) -> bool:
        """Read-only full-chain verification across restarts.

        With no arguments the whole database is assessed: event order,
        per-request association with the request row, database link
        hashes and anchored heads, every external anchor's
        authentication, the events-to-anchors one-to-one binding and the
        file-wide global anchor head. With *tenant_id* and *request_id*
        the same assessment runs (the global head still seals every
        tenant, so a cross-request or cross-tenant substitution is
        visible), gated on the request belonging to the tenant exactly
        like :meth:`audit`.

        Returns ``True`` only when every check passes; deleting,
        altering, inserting or reordering events, substituting events or
        anchors across requests or tenants, tampering with a head, a
        corrupt anchor, an interrupted commit, an un-anchored legacy
        database and a missing secret on an anchored file all yield
        ``False``. Recomputing the database events and heads alone can
        never forge validity: without the external secret the anchors do
        not authenticate. Verification never writes, repairs,
        backfills, recomputes or overwrites anything.

        Invalid, unknown or cross-tenant ids raise
        :class:`RequestNotFound`; an empty/non-string *tenant_id* or a
        scope supplied as only one of the two coordinates raises
        :class:`ValueError`. A storage fault is the fixed-text
        :class:`OSError`.
        """
        scope = self._validate_chain_scope(tenant_id, request_id)
        if self._mem_conn is not None:
            with self._write_lock:
                return not self._assess_chain(scope)
        return not self._assess_chain(scope)

    def verify_audit_chain(
        self,
        tenant_id: str | None = None,
        request_id: str | None = None,
    ) -> bool:
        """Alias of :meth:`verify_chain` under the audit vocabulary."""
        return self.verify_chain(tenant_id, request_id)

    def diagnose_chain(
        self,
        tenant_id: str | None = None,
        request_id: str | None = None,
    ) -> list[str]:
        """Report the fixed reason codes that make the chain untrusted.

        Read-only recovery diagnosis: returns an empty list for a
        trusted chain, otherwise a sorted list of stable, detail-free
        codes (e.g. ``unanchored_database``, ``anchor_auth_failed``,
        ``anchor_head_mismatch``). It only ever reports why the
        persisted evidence cannot be trusted -- it never repairs,
        backfills, recomputes or overwrites an event, a head or an
        anchor. The same scoping and error semantics as
        :meth:`verify_chain` apply.
        """
        scope = self._validate_chain_scope(tenant_id, request_id)
        if self._mem_conn is not None:
            with self._write_lock:
                return self._assess_chain(scope)
        return self._assess_chain(scope)

    def diagnose_audit_chain(
        self,
        tenant_id: str | None = None,
        request_id: str | None = None,
    ) -> list[str]:
        """Alias of :meth:`diagnose_chain` under the audit vocabulary."""
        return self.diagnose_chain(tenant_id, request_id)

    @staticmethod
    def _validate_chain_scope(
        tenant_id: str | None, request_id: str | None
    ) -> tuple[str, str] | None:
        """Validate an optional (tenant, request) verification scope."""
        if tenant_id is None and request_id is None:
            return None
        if tenant_id is None:
            # A request coordinate without a tenant is caller error,
            # never a read.
            raise ValueError("chain scope requires tenant_id and request_id")
        tenant_id = _require_nonempty_str(tenant_id, "tenant_id")
        # With a tenant supplied, a missing/non-string/malformed request
        # id collapses to not-found exactly like audit()/evidence().
        request_id = _require_identifier(request_id)
        return tenant_id, request_id

    def _assess_chain(self, scope: tuple[str, str] | None) -> list[str]:
        """Run the read-only whole-file assessment and return reasons."""
        conn = self._connect()
        try:
            try:
                if scope is not None:
                    owner = conn.execute(
                        "SELECT 1 FROM requests WHERE tenant_id = ? AND request_id = ?",
                        scope,
                    ).fetchone()
                    if owner is None:
                        raise RequestNotFound("request not found")
                meta_rows = conn.execute(
                    "SELECT head_hmac FROM audit_anchor_meta"
                ).fetchall()
                event_rows = conn.execute(
                    "SELECT tenant_id, request_id, seq, status, occurred_at, "
                    "chain_hash FROM status_events "
                    "ORDER BY tenant_id, request_id, seq"
                ).fetchall()
                anchor_rows = conn.execute(
                    "SELECT commit_seq, tenant_id, request_id, seq, event_hash, "
                    "anchor_hmac, key_generation FROM audit_anchors ORDER BY commit_seq"
                ).fetchall()
                request_rows = conn.execute(
                    "SELECT tenant_id, request_id, status, chain_hash FROM requests"
                ).fetchall()
                generation_rows = conn.execute(
                    "SELECT generation, key_fingerprint, effective_at "
                    "FROM anchor_key_generations ORDER BY generation"
                ).fetchall()
            except RequestNotFound:
                raise
            except sqlite3.Error:
                raise _storage_failure() from None
        finally:
            self._release(conn)
        return self._evaluate_chain_rows(
            tuple(meta_rows),
            tuple(event_rows),
            tuple(anchor_rows),
            tuple(request_rows),
            tuple(generation_rows),
            self._anchor_secret,
            self._anchor_history_secrets,
        )

    @staticmethod
    def _evaluate_chain_rows(
        meta_rows: tuple,
        event_rows: tuple,
        anchor_rows: tuple,
        request_rows: tuple,
        generation_rows: tuple,
        secret: str | None,
        history_secrets: Mapping[int, str],
    ) -> list[str]:
        """Pure, read-only evaluation of the persisted chain state.

        Kept free of any connection so the logic is deterministic and
        side-effect free: it only compares and recomputes, never writes.
        Each anchor authenticates under the secret of the generation
        recorded on its own row; generations not handed to the
        assessing store report ``anchor_key_missing`` instead of being
        guessed against the current secret.
        """
        reasons: set[str] = set()

        # -- singleton meta head -------------------------------------
        stored_head: str | None = None
        if len(meta_rows) > 1:
            reasons.add(_ANCHOR_REASON_META_CORRUPT)
        elif meta_rows:
            stored_head = meta_rows[0][0]
            if not _is_chain_hash(stored_head):
                reasons.add(_ANCHOR_REASON_META_CORRUPT)
                stored_head = None

        # -- the empty database is vacuously trusted -----------------
        if (
            not event_rows
            and not anchor_rows
            and stored_head is None
            and not generation_rows
        ):
            return []

        # -- secret generations --------------------------------------
        # One gap-free row per generation that has ever sealed anchors,
        # starting at 1, each with a well-formed fingerprint and an
        # effective time. Anchors attribute themselves to a generation
        # by number; legacy anchors written before rotation existed
        # carry NULL and are attributed to generation 1. A malformed
        # generation set on an anchored file is anchor-state corruption,
        # never a reason to fall back to the current secret blindly.
        generation_fingerprints: dict[int, str] = {}
        generation_corrupt = False
        for index, grow in enumerate(generation_rows, start=1):
            generation, fingerprint, effective_at = grow
            if (
                not isinstance(generation, int)
                or isinstance(generation, bool)
                or generation != index
                or not _is_chain_hash(fingerprint)
                or not isinstance(effective_at, str)
                or not _RFC3339_RE.match(effective_at)
            ):
                generation_corrupt = True
            if isinstance(generation, int) and not isinstance(generation, bool):
                generation_fingerprints[generation] = fingerprint
        if anchor_rows and (generation_corrupt or not generation_fingerprints):
            # Anchors with a malformed generations table are corrupt; a
            # wholly empty generations table is the pre-rotation legacy
            # shape and authenticates under the configured secret as
            # generation 1 (NULL attributions below), exactly like a
            # historical receipt verifying on its tag alone.
            if generation_corrupt:
                reasons.add(_ANCHOR_REASON_CORRUPT_ROW)
        if generation_rows and not anchor_rows:
            # Secret generations without a single anchor is only valid
            # as the bootstrap-rotation shape (exactly generations 1 and
            # 2, sharing one effective time, written before the first
            # anchor); anything else is an interrupted or out-of-band
            # state, never a silently bootstrappable file.
            bootstrap_shape = (
                not generation_corrupt
                and [g for g, _f, _t in generation_rows] == [1, 2]
                and generation_rows[0][2] == generation_rows[1][2]
            )
            if not bootstrap_shape:
                reasons.add(_ANCHOR_REASON_CORRUPT_ROW)

        # -- event/anchor population invariants ----------------------
        # A database with events but no anchor rows is the historical
        # un-anchored shape: report exactly one reason, rather than a
        # cascade of consequences of the missing anchors.
        legacy_unanchored = bool(event_rows) and not anchor_rows
        if legacy_unanchored:
            reasons.add(_ANCHOR_REASON_UNANCHORED)
        if anchor_rows and not event_rows:
            reasons.add(_ANCHOR_REASON_STATE_SPLIT)
        if event_rows and anchor_rows and len(event_rows) != len(anchor_rows):
            reasons.add(_ANCHOR_REASON_STATE_SPLIT)
        if anchor_rows and stored_head is None:
            # Sealed anchors without a global head: an interrupted
            # commit or out-of-band deletion.
            reasons.add(_ANCHOR_REASON_META_CORRUPT)

        # -- index the rows ------------------------------------------
        events: dict[tuple[str, str, int], tuple] = {}
        for row in event_rows:
            tenant_id, request_id, seq, status, occurred_at, chain_hash = row
            key = (tenant_id, request_id, seq)
            if (
                not isinstance(tenant_id, str)
                or not tenant_id
                or not isinstance(request_id, str)
                or not request_id
                or not isinstance(seq, int)
                or isinstance(seq, bool)
                or not isinstance(status, str)
                or not status
                or not isinstance(occurred_at, str)
                or not occurred_at
                or not _is_chain_hash(chain_hash)
            ):
                reasons.add(_ANCHOR_REASON_CORRUPT_ROW)
            events[key] = row

        anchors: dict[tuple[str, str, int], tuple] = {}
        for row in anchor_rows:
            (
                commit_seq,
                tenant_id,
                request_id,
                seq,
                event_hash,
                anchor_hmac,
                key_generation,
            ) = row
            key = (tenant_id, request_id, seq)
            if (
                not isinstance(commit_seq, int)
                or isinstance(commit_seq, bool)
                or commit_seq < 1
                or not isinstance(tenant_id, str)
                or not tenant_id
                or not isinstance(request_id, str)
                or not request_id
                or not isinstance(seq, int)
                or isinstance(seq, bool)
                or not _is_chain_hash(event_hash)
                or not _is_chain_hash(anchor_hmac)
                # NULL is the legacy attribution (generation 1); any
                # present value must be a positive integer naming a
                # generation on record.
                or not (
                    key_generation is None
                    or (
                        isinstance(key_generation, int)
                        and not isinstance(key_generation, bool)
                        and key_generation >= 1
                    )
                )
            ):
                reasons.add(_ANCHOR_REASON_CORRUPT_ROW)
            if key in anchors:
                reasons.add(_ANCHOR_REASON_CORRUPT_ROW)
            anchors[key] = row

        def resolve_generation_secret(key_generation: object):
            return RequestStore._resolve_anchor_generation_secret(
                key_generation, generation_fingerprints, secret, history_secrets
            )

        # One-to-one keys binding: every event anchored, every anchor an
        # event, same tenant/request/sequence. A legacy database with no
        # anchors at all is already reported as a single unanchored
        # reason and must not cascade into per-event consequences.
        event_keys = set(events)
        anchor_keys = set(anchors)
        if not legacy_unanchored and event_keys - anchor_keys:
            reasons.add(_ANCHOR_REASON_EVENT_UNANCHORED)
        if anchor_keys - event_keys:
            reasons.add(_ANCHOR_REASON_ANCHOR_ORPHAN)

        # -- per-request database chains -----------------------------
        requests_by_key = {
            (tenant_id, request_id): (status, chain_hash)
            for tenant_id, request_id, status, chain_hash in request_rows
        }

        grouped: dict[tuple[object, object], list[tuple]] = {}
        for key in event_keys:
            grouped.setdefault((key[0], key[1]), []).append(events[key])

        for (tenant_id, request_id), rows in grouped.items():
            # A tampered seq must not raise out of the sort; such a row
            # is already flagged and sorts deterministically to the front.
            rows.sort(
                key=lambda row: (
                    not isinstance(row[2], int) or isinstance(row[2], bool),
                    row[2] if isinstance(row[2], int) and not isinstance(row[2], bool) else -1,
                )
            )
            predecessor = _GENESIS_PREDECESSOR
            anchor_predecessor = _ANCHOR_GENESIS_PREDECESSOR
            for expected_seq, row in enumerate(rows):
                _t, _r, seq, status, occurred_at, chain_hash = row
                well_typed = (
                    isinstance(tenant_id, str)
                    and isinstance(request_id, str)
                    and isinstance(seq, int)
                    and not isinstance(seq, bool)
                    and isinstance(status, str)
                    and isinstance(occurred_at, str)
                )
                if not well_typed:
                    reasons.add(_ANCHOR_REASON_CORRUPT_ROW)
                if isinstance(seq, int) and not isinstance(seq, bool) and seq != expected_seq:
                    # Deleted, inserted or renumbered event.
                    reasons.add(_ANCHOR_REASON_EVENT_ORDER)
                if well_typed:
                    recomputed = _chain_hash(
                        tenant_id,
                        request_id,
                        expected_seq,
                        status,
                        occurred_at,
                        predecessor,
                    )
                    if not hmac.compare_digest(recomputed, chain_hash):
                        reasons.add(_ANCHOR_REASON_CHAIN_MISMATCH)
                predecessor = chain_hash if isinstance(chain_hash, str) else ""

                anchor_row = anchors.get((tenant_id, request_id, expected_seq))
                if anchor_row is not None:
                    (
                        _cs,
                        at,
                        ar,
                        aseq,
                        event_hash,
                        anchor_hmac,
                        anchor_generation,
                    ) = anchor_row
                    if (at, ar, aseq) != (tenant_id, request_id, expected_seq):
                        reasons.add(_ANCHOR_REASON_ASSOCIATION)
                    if event_hash != chain_hash:
                        # The anchor seals a different event than the one
                        # persisted here: a cross-request/cross-tenant
                        # substitution cannot silently rebind.
                        reasons.add(_ANCHOR_REASON_ASSOCIATION)
                    if (
                        secret is not None
                        and well_typed
                        and _is_chain_hash(chain_hash)
                        and _is_chain_hash(anchor_hmac)
                    ):
                        sealing_secret, secret_status = resolve_generation_secret(
                            anchor_generation
                        )
                        if secret_status == "missing":
                            # The store was not handed this anchor's
                            # historical generation: it can neither
                            # authenticate nor forge this anchor.
                            reasons.add(_ANCHOR_REASON_KEY_MISSING)
                        elif secret_status == "association":
                            # The anchor claims a secret generation that
                            # does not exist on record -- a forged
                            # generation association that can never
                            # authenticate.
                            reasons.add(_ANCHOR_REASON_AUTH_FAILED)
                        elif secret_status == "wrong":
                            # The secret handed for that generation does
                            # not match its persisted fingerprint: the
                            # anchor can never authenticate under it.
                            reasons.add(_ANCHOR_REASON_AUTH_FAILED)
                        else:
                            expected_anchor = _anchor_mac(
                                sealing_secret,
                                tenant_id,
                                request_id,
                                expected_seq,
                                status,
                                occurred_at,
                                chain_hash,
                                anchor_predecessor,
                            )
                            if not hmac.compare_digest(expected_anchor, anchor_hmac):
                                reasons.add(_ANCHOR_REASON_AUTH_FAILED)
                    anchor_predecessor = (
                        anchor_hmac if isinstance(anchor_hmac, str) else ""
                    )

            request_row = requests_by_key.get((tenant_id, request_id))
            if request_row is None:
                reasons.add(_ANCHOR_REASON_ASSOCIATION)
            else:
                current_status, anchored_head = request_row
                if not _is_chain_hash(anchored_head):
                    reasons.add(_ANCHOR_REASON_HEAD_MISMATCH)
                elif not hmac.compare_digest(anchored_head, predecessor):
                    reasons.add(_ANCHOR_REASON_HEAD_MISMATCH)
                final_status = rows[-1][3]
                if (
                    not isinstance(current_status, str)
                    or not isinstance(final_status, str)
                    or current_status != final_status
                ):
                    reasons.add(_ANCHOR_REASON_STATUS_MISMATCH)

        # An anchor whose request row does not exist at all.
        for tenant_id, request_id, _seq in anchor_keys:
            if (tenant_id, request_id) not in requests_by_key:
                reasons.add(_ANCHOR_REASON_ASSOCIATION)

        # -- global seal: gap-free commit order and the head ---------
        if anchor_rows:
            ordered = sorted(
                (
                    row
                    for row in anchor_rows
                    if isinstance(row[0], int) and not isinstance(row[0], bool)
                ),
                key=lambda row: row[0],
            )
            if [row[0] for row in ordered] != list(range(1, len(anchor_rows) + 1)):
                reasons.add(_ANCHOR_REASON_SEQUENCE_GAP)
            elif secret is not None and stored_head is not None:
                head = _ANCHOR_GLOBAL_GENESIS
                replay_ok = True
                for row in ordered:
                    (
                        _commit_seq,
                        tenant_id,
                        request_id,
                        seq,
                        _event_hash,
                        anchor_hmac,
                        anchor_generation,
                    ) = row
                    if not (
                        isinstance(tenant_id, str)
                        and isinstance(request_id, str)
                        and isinstance(seq, int)
                        and not isinstance(seq, bool)
                        and _is_chain_hash(anchor_hmac)
                    ):
                        # A malformed sealing row is already flagged; the
                        # head cannot authenticate off garbage preimages.
                        replay_ok = False
                        break
                    sealing_secret, secret_status = resolve_generation_secret(
                        anchor_generation
                    )
                    if secret_status in ("missing", "association", "wrong"):
                        # The head replay needs every row's actual
                        # sealing secret. A missing generation records
                        # ``anchor_key_missing`` (per-anchor loop above);
                        # a wrong secret or an unknown generation already
                        # records the authentication/association failure.
                        # Neither can reproduce the sealed head.
                        replay_ok = False
                        break
                    head = _anchor_head_mac(
                        sealing_secret,
                        head,
                        anchor_hmac,
                        tenant_id,
                        request_id,
                        seq,
                    )
                if replay_ok and not hmac.compare_digest(head, stored_head):
                    reasons.add(_ANCHOR_REASON_GLOBAL_HEAD)

        if secret is None and anchor_rows:
            # An anchored file assessed by a store that holds no secret
            # cannot be authenticated: never call an unverifiable chain
            # trusted, however internally consistent it looks.
            reasons.add(_ANCHOR_REASON_SECRET_MISSING)

        return sorted(reasons)

    @staticmethod
    def _resolve_anchor_generation_secret(
        key_generation: object,
        generation_fingerprints: dict[int, str],
        secret: str | None,
        history_secrets: Mapping[int, str],
    ):
        """Resolve the secret an anchor was sealed under.

        Returns ``(secret, status)`` where status is ``"ok"``,
        ``"missing"`` (the generation's secret was not handed to this
        store), ``"wrong"`` (the handed secret does not match the
        generation's persisted fingerprint) or ``"association"`` (the
        anchor names no known generation). A NULL attribution on a file
        whose generations table is empty is the pre-rotation legacy
        shape: its one secret is the configured secret and authenticates
        directly, exactly like a historical receipt verifying on its tag
        alone.
        """
        if key_generation is None and not generation_fingerprints:
            if secret is None:
                return None, "missing"
            return secret, "ok"
        generation = 1 if key_generation is None else key_generation
        if (
            not isinstance(generation, int)
            or isinstance(generation, bool)
            or generation < 1
            or generation not in generation_fingerprints
        ):
            return None, "association"
        candidate: str | None
        if secret is not None and generation == max(
            generation_fingerprints, default=None
        ):
            candidate = secret
        else:
            candidate = history_secrets.get(generation)
        if candidate is None:
            return None, "missing"
        if not hmac.compare_digest(
            _anchor_key_fingerprint(candidate),
            generation_fingerprints[generation],
        ):
            return None, "wrong"
        return candidate, "ok"

    # -- anchor key rotation -------------------------------------------

    def rotate_anchor_key(
        self,
        retired_secret: str,
        new_secret: str,
    ) -> dict[str, object]:
        """Rotate the external anchor secret by one generation.

        Storage-layer only; never routed over HTTP and never a health
        command. *retired_secret* is the currently active anchor secret
        and *new_secret* its successor; the pair atomically promotes
        exactly one new generation. The result carries precisely
        ``generation`` (a positive int, the newly active generation)
        and ``effective_at`` (that generation's UTC RFC3339 effective
        time). After the rotation newly sealed anchors use the new
        generation; every existing anchor keeps the generation it was
        sealed under and is never rewritten. Historical secrets stay
        with the caller and must be handed to a rebuilt instance via
        ``anchor_history_secrets`` keyed by generation.

        * The first rotation on a database that has never anchored an
          event still establishes generations 1 (the retired secret)
          and 2 (the enabled secret) in one atomic commit and returns
          generation 2; the first anchor sealed afterwards is
          generation 2.
        * Repeating the exact retired->enabled pair that produced the
          active generation is idempotent and returns that first
          generation and its first effective time; the same pair called
          concurrently returns one identical result.
        * Concurrent rotations with different enabled secrets: only
          the first transaction takes effect; losers raise
          :class:`AnchorKeyConflict` with the active generation
          untouched.
        * A retired secret that is registered but not active, an
          enabled secret already registered, an empty/non-string
          argument or equal secrets raise :class:`ValueError`, and no
          rejected call writes.
        * Corrupt generation records, an unreadable database or a
          failed atomic commit all raise the fixed-text
          :class:`OSError`; a half-applied generation is never visible.
        Only fingerprints, generations and times are persisted.
        """
        retired_secret = _require_nonempty_str(retired_secret, "retired_secret")
        new_secret = _require_nonempty_str(new_secret, "new_secret")
        if retired_secret == new_secret:
            raise ValueError("retired_secret and new_secret must differ")
        if self._anchor_secret is None:
            # Rotation only exists for a store configured to anchor. A
            # no-secret store can neither retire nor enable a generation.
            raise ValueError("anchor rotation requires an anchor secret")

        with self._write_lock:
            conn = self._connect()
            try:
                try:
                    conn.execute("BEGIN IMMEDIATE")
                except sqlite3.Error:
                    raise _storage_failure() from None
                try:
                    result = self._rotate_anchor_key_locked(
                        conn, retired_secret, new_secret
                    )
                    conn.execute("COMMIT")
                except (ValueError, AnchorKeyConflict):
                    self._rollback_quietly(conn)
                    raise
                except sqlite3.IntegrityError:
                    # Another process sharing the file won the same
                    # generation/fingerprint slot: an identical rotation
                    # replays idempotently, any other lost race is the
                    # single detail-free conflict.
                    self._rollback_quietly(conn)
                    result = self._resolve_lost_anchor_rotation_race(
                        conn, retired_secret, new_secret
                    )
                except sqlite3.Error:
                    self._rollback_quietly(conn)
                    raise _storage_failure() from None
            finally:
                self._release(conn)
        # Only the generation number is logged -- never a fingerprint
        # or any secret material.
        _log.info("anchor key rotated generation=%s", result["generation"])
        # The current secret rotates in process memory as well, so this
        # same instance seals subsequent anchors under the new
        # generation without a rebuild; historical secrets are never
        # written and the retired secret is retained only in memory.
        self._anchor_history_secrets[result["generation"] - 1] = retired_secret
        self._anchor_secret = new_secret
        return result

    def _load_anchor_generations_locked(
        self, conn: sqlite3.Connection
    ) -> list[tuple[int, str, str]]:
        """Return the strictly-validated anchor secret generations.

        Rows are ``(generation, fingerprint, effective_at)`` in
        generation order, gap-free from 1 with well-formed fingerprints
        and UTC RFC3339 times. Any other shape is storage corruption and
        raises the fixed-text :class:`OSError`.
        """
        rows = conn.execute(
            "SELECT generation, key_fingerprint, effective_at "
            "FROM anchor_key_generations ORDER BY generation"
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

    def _rotate_anchor_key_locked(
        self,
        conn: sqlite3.Connection,
        retired_secret: str,
        new_secret: str,
    ) -> dict[str, object]:
        """Apply one anchor-key rotation inside an open write txn."""
        generations = self._load_anchor_generations_locked(conn)
        retired_fp = _anchor_key_fingerprint(retired_secret)
        new_fp = _anchor_key_fingerprint(new_secret)

        if not generations:
            # The file has never registered anchor secret generations.
            # Two shapes may receive the generations 1-and-2 bootstrap:
            # a genuinely empty file, or a database anchored before key
            # rotation existed (every anchor carries the NULL
            # generation-1 attribution). The latter is accepted only
            # after the whole committed chain replays intact under the
            # presented retired secret inside this transaction -- the
            # registration adds fingerprints alone and never rewrites
            # an anchor. An un-anchored legacy database (events without
            # anchors) or an already-tampered file is refused.
            try:
                anchor_count = conn.execute(
                    "SELECT count(*) FROM audit_anchors"
                ).fetchone()[0]
            except sqlite3.Error:
                raise _storage_failure() from None
            if anchor_count > 0:
                meta_rows = conn.execute(
                    "SELECT head_hmac FROM audit_anchor_meta"
                ).fetchall()
                event_rows = conn.execute(
                    "SELECT tenant_id, request_id, seq, status, occurred_at, "
                    "chain_hash FROM status_events "
                    "ORDER BY tenant_id, request_id, seq"
                ).fetchall()
                anchor_rows = conn.execute(
                    "SELECT commit_seq, tenant_id, request_id, seq, event_hash, "
                    "anchor_hmac, key_generation FROM audit_anchors ORDER BY commit_seq"
                ).fetchall()
                request_rows = conn.execute(
                    "SELECT tenant_id, request_id, status, chain_hash FROM requests"
                ).fetchall()
                reasons = self._evaluate_chain_rows(
                    tuple(meta_rows),
                    tuple(event_rows),
                    tuple(anchor_rows),
                    tuple(request_rows),
                    (),
                    retired_secret,
                    {},
                )
                if reasons:
                    raise _storage_failure()
            else:
                # Genuinely empty of anchors: legacy un-anchored content
                # (events but no anchors) must not gain generations by
                # recomputation.
                try:
                    event_count = conn.execute(
                        "SELECT count(*) FROM status_events"
                    ).fetchone()[0]
                except sqlite3.Error:
                    raise _storage_failure() from None
                if event_count != 0:
                    raise _storage_failure()
            effective_at = _utc_now_rfc3339()
            conn.execute(
                "INSERT INTO anchor_key_generations ("
                "generation, key_fingerprint, effective_at"
                ") VALUES (1, ?, ?), (2, ?, ?)",
                (retired_fp, effective_at, new_fp, effective_at),
            )
            return {"generation": 2, "effective_at": effective_at}

        active_generation, active_fp, active_effective_at = generations[-1]

        # Idempotent replay first: the exact pair that produced the
        # active generation returns the first generation and time.
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
                    # The successor was already registered (a retired
                    # secret, or the active secret itself); aliasing it
                    # onto a fresh generation is caller error and commits
                    # nothing.
                    raise ValueError(
                        "new_secret is already registered as a generation"
                    )
            effective_at = _utc_now_rfc3339()
            conn.execute(
                "INSERT INTO anchor_key_generations ("
                "generation, key_fingerprint, effective_at"
                ") VALUES (?, ?, ?)",
                (active_generation + 1, new_fp, effective_at),
            )
            return {
                "generation": active_generation + 1,
                "effective_at": effective_at,
            }

        # The retired secret is not the active generation.
        if len(generations) >= 2 and hmac.compare_digest(
            generations[-2][1], retired_fp
        ):
            # The retired secret is the *immediate predecessor* of the
            # active generation but the enabled secret differs from the
            # successor that won: this caller raced the promotion and
            # lost -- the single detail-free conflict, whether the
            # contention was concurrent or the call simply arrived
            # after the winner committed. The identical pair was the
            # idempotent replay handled above.
            raise AnchorKeyConflict(_ANCHOR_KEY_CONFLICT_MESSAGE)
        if any(
            hmac.compare_digest(fingerprint, retired_fp)
            for _gen, fingerprint, _at in generations
        ):
            # Registered but long superseded (older than the active
            # generation's predecessor): caller error, nothing commits.
            raise ValueError("retired_secret is not the active generation")
        # It names no registered generation at all.
        raise ValueError("retired_secret does not name a registered generation")

    def _resolve_lost_anchor_rotation_race(
        self,
        conn: sqlite3.Connection,
        retired_secret: str,
        new_secret: str,
    ) -> dict[str, object]:
        """Resolve the outcome after another process won the insert race."""
        try:
            conn.execute("BEGIN IMMEDIATE")
            generations = self._load_anchor_generations_locked(conn)
            conn.execute("COMMIT")
        except sqlite3.Error:
            self._rollback_quietly(conn)
            raise _storage_failure() from None
        if len(generations) < 2:
            # The winner registered no successor; no safe result.
            raise _storage_failure()
        retired_fp = _anchor_key_fingerprint(retired_secret)
        new_fp = _anchor_key_fingerprint(new_secret)
        active_generation, active_fp, active_effective_at = generations[-1]
        predecessor_fp = generations[-2][1]
        if hmac.compare_digest(predecessor_fp, retired_fp) and hmac.compare_digest(
            active_fp, new_fp
        ):
            # The winner committed the identical rotation: replay the
            # first generation and time.
            return {
                "generation": active_generation,
                "effective_at": active_effective_at,
            }
        # A different successor won; the loser observes the same
        # detail-free conflict an in-process loser would, and the
        # winner's generation is untouched.
        raise AnchorKeyConflict(_ANCHOR_KEY_CONFLICT_MESSAGE)

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
        as generation 1 (in the same transaction as the receipt row),
        and once a generation exists a retired or foreign key is
        rejected with :class:`ReceiptKeyConflict` for *any*
        receipt-less request -- before the request's own availability
        is assessed -- so an old key can never mint a new receipt, and
        the key state can never be probed through a different
        availability outcome. Existing receipts are unaffected:
        regeneration still replays the stored first bytes, and an old
        receipt still verifies under the key generation that signed
        it. With no generation registered yet the first-receipt
        availability rules still apply and the generation-1 bootstrap
        commits only with the receipt row.
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

        # Admit the minting key BEFORE inspecting the request's state:
        # once a tenant has registered a receipt key, a retired or
        # foreign key on any receipt-less request -- accepted,
        # processing, failed or unknown to the execution ledger -- is
        # the single detail-free ReceiptKeyConflict, whatever the
        # request state, and writes nothing. With no generation yet the
        # presented key is a potential generation-1 bootstrap; the
        # bootstrap row is only inserted below, in the same transaction
        # as the receipt, so an unavailable request never registers a
        # key on a rolled-back mint.
        needs_bootstrap = self._admit_minting_key_locked(conn, tenant_id, key)

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
        # The first receipt a tenant ever issues registers its presented
        # key as generation 1 in the same transaction as the receipt row,
        # so the two can never disagree (and a rollback never leaves a
        # key generation without the receipt that introduced it). After
        # a rotation the active key is the only key allowed to sign a new
        # receipt: a retired or foreign key reaches here only when no
        # generation exists yet.
        if needs_bootstrap:
            self._bootstrap_receipt_key_locked(conn, tenant_id, key)
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

    def _admit_minting_key_locked(
        self,
        conn: sqlite3.Connection,
        tenant_id: str,
        key: str,
    ) -> bool:
        """Decide whether *key* may mint inside an open write txn.

        Read-only: returns ``True`` when the tenant has no registered
        generation yet (the presented key would bootstrap generation
        1, inserted later in the mint's own transaction) and ``False``
        when it matches the current active generation's fingerprint.
        A retired or never-registered key presented while generations
        exist gets the single, detail-free
        :class:`ReceiptKeyConflict`, so which fingerprints exist can
        never be probed through distinct failures, and no rejected
        decision writes anything.

        The full generation set is validated (gap-free generations with
        well-formed fingerprints and times) before the active row is
        trusted: a tampered key history is storage corruption and
        raises the fixed-text :class:`OSError` rather than minting off
        a forged active row.
        """
        generations = self._load_key_generations_locked(conn, tenant_id)
        if not generations:
            return True
        active_fingerprint = generations[-1][1]
        if not hmac.compare_digest(active_fingerprint, _key_fingerprint(key)):
            raise ReceiptKeyConflict(_RECEIPT_KEY_CONFLICT_MESSAGE)
        return False

    @staticmethod
    def _bootstrap_receipt_key_locked(
        conn: sqlite3.Connection,
        tenant_id: str,
        key: str,
    ) -> None:
        """Register generation 1 with *key* inside the mint transaction.

        The bootstrap row is inserted in the same transaction as the
        receipt row, so a mint that rolls back can never leave a key
        generation behind. Only invoked once the request has proved
        receiptable.
        """
        conn.execute(
            "INSERT INTO receipt_keys ("
            "tenant_id, generation, key_fingerprint, effective_at"
            ") VALUES (?, 1, ?, ?)",
            (tenant_id, _key_fingerprint(key), _utc_now_rfc3339()),
        )

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
