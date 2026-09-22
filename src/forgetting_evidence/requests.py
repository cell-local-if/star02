"""SQLite-backed acceptance store for deletion requests.

The store records deletion requests without retaining any identifying
payload in logs, return values beyond the fixed receipt fields, or
exception messages. SQLite integrity conflicts are translated into the
module's own idempotency semantics and never surface to callers.

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

Because the chain itself lives entirely inside SQLite, an attacker who
can rewrite the database could recompute every link. Trusted
verification therefore never relies on SQLite content alone: callers
supply an ``integrity_key`` that is held outside both the database and
the sidecar anchor file. Each accepted request and each committed
status transition is anchored by an HMAC record in the sidecar that
binds the tenant, request, event count, final status and chain head.
The key, any material that could substitute for it, and the plaintext
chain preimages are never written to SQLite, the sidecar, receipts,
exceptions or logs.

Anchoring follows a decidable two-phase commit protocol: the sidecar
record is staged as ``prepared`` before the SQLite transaction commits
and flipped to ``committed`` only afterwards. Any interruption leaves a
state that :meth:`RequestStore.verify_evidence` reports as ``False``
and :meth:`RequestStore.recover` reports as an explicit non-valid
state; neither operation ever repairs, backfills or rewrites evidence.

The journal is append-only: every committed seq keeps its anchor
forever and a journal-wide HMAC digest authenticates the record set.
Deleting, truncating or reordering SQLite events, removing journal
records, or replacing either file with an independently modified copy
therefore fails verification. The boundary is deliberately explicit:
the trust anchor is a symmetric secret the verifier holds outside both
files, so this cannot detect an attacker who restores a *complete,
mutually-consistent historical snapshot* of both files (equivalently,
rolls the world back to a previously valid state) — no file-local
evidence can, since every byte the verifier can see was valid at that
point in time. Detection of that case requires an external monotonic
counter or key epoch held by the caller.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import logging
import os
import sqlite3
import struct
import threading
import uuid
from collections.abc import Mapping
from datetime import datetime, timezone

try:  # cross-process journal locking; POSIX only, inert elsewhere
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX fallback
    fcntl = None

__all__ = [
    "RequestStore",
    "IdempotencyConflict",
    "RequestNotFound",
    "InvalidStatusTransition",
]

_log = logging.getLogger(__name__)


class IdempotencyConflict(Exception):
    """Raised when an idempotency key is reused with a different payload."""


class RequestNotFound(Exception):
    """Raised when no request visible to the tenant matches the id."""


class InvalidStatusTransition(Exception):
    """Raised when a requested status change is unknown or not permitted."""


class _PrimaryKeyConflict(Exception):
    """Internal signal: retry insertion with a freshly generated id."""


class _AnchorCorrupt(Exception):
    """Internal signal: the sidecar anchor journal is missing or corrupt."""


class _AnchorMissing(_AnchorCorrupt):
    """Internal signal: the sidecar anchor journal does not exist yet.

    Distinct from corruption so the write path can bootstrap an empty
    journal while verification still treats absence as failure.
    """


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

# Column probes used to upgrade database files created before chain
# hashes existed. The upgrade is purely additive (nullable columns plus a
# one-time backfill derived from the already-persisted timeline); it never
# overwrites existing chain evidence and never fabricates a trusted
# anchor: rows that predate keyed anchoring remain unanchored forever.
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


# --- sidecar anchor journal ------------------------------------------------
#
# The anchor journal is the only component trusted beyond SQLite. It is a
# JSON document holding one HMAC-SHA256 record per request. Every record
# binds the tenant, request id, event count, final status, chain head and
# the head it extends, so records cannot be moved between requests or
# tenants, replayed at a different chain position, or recomputed without
# the caller-held integrity key. The key itself is never written anywhere.

_ANCHOR_VERSION = 1
_ANCHOR_DOMAIN = "forgetting-evidence.anchor.v1"
_ANCHOR_PREPARED = "prepared"
_ANCHOR_COMMITTED = "committed"
_ANCHOR_STATES = frozenset({_ANCHOR_PREPARED, _ANCHOR_COMMITTED})
_ANCHOR_REQUIRED_FIELDS = frozenset(
    {"tenant_id", "request_id", "seq", "status", "event_count", "head", "prev_head", "state", "mac"}
)

# recover() outcome states. Only "committed" is a valid state; every
# other value is an explicit non-valid verdict and never triggers any
# repair, backfill or rewrite of evidence.
_RECOVER_COMMITTED = "committed"
_RECOVER_PREPARED = "prepared"
_RECOVER_UNANCHORED = "unanchored"
_RECOVER_INCONSISTENT = "inconsistent"
_RECOVER_CORRUPT = "corrupt"


def _anchor_mac(
    key: bytes,
    tenant_id: str,
    request_id: str,
    seq: int,
    status: str,
    event_count: int,
    head: str,
    prev_head: str,
    state: str,
) -> str:
    """Compute the HMAC binding one anchor record.

    The domain label separates anchor MACs from any other HMAC use, and
    every field is length-prefixed exactly like the chain links, so the
    record cannot be re-parsed or transplanted. The MAC preimage is
    computed in memory only; it is never persisted, returned or logged.
    """
    digest = hmac.new(key, digestmod=hashlib.sha256)
    for field in (
        _ANCHOR_DOMAIN,
        tenant_id,
        request_id,
        str(seq),
        status,
        str(event_count),
        head,
        prev_head,
        state,
    ):
        encoded = field.encode("utf-8")
        digest.update(struct.pack(">Q", len(encoded)))
        digest.update(encoded)
    return digest.hexdigest()


def _anchor_record_key(tenant_id: str, request_id: str, seq: int) -> str:
    # NUL cannot appear in a JSON string without escaping, so joining on
    # it keeps (tenant, request, seq) triples unambiguous inside the
    # journal. The journal is append-only: one record per seq, never
    # replaced, so an earlier anchored head stays provably visible after
    # later transitions and SQLite rollback cannot line up with it.
    return tenant_id + "\x00" + request_id + "\x00" + str(seq)


def _anchor_record_prefix(tenant_id: str, request_id: str) -> str:
    return tenant_id + "\x00" + request_id + "\x00"


_ANCHOR_DIGEST_DOMAIN = "forgetting-evidence.anchor-journal.v1"


def _journal_digest(key: bytes, records: Mapping[str, Mapping[str, object]]) -> str:
    """HMAC over the complete, ordered set of anchor records.

    Per-record MACs authenticate each record in isolation; this digest
    authenticates the journal as a whole, so deleting, inserting or
    reordering records (which would leave every individual MAC valid)
    is detected as journal corruption.
    """
    digest = hmac.new(key, digestmod=hashlib.sha256)
    prefix = _ANCHOR_DIGEST_DOMAIN.encode("utf-8")
    digest.update(struct.pack(">Q", len(prefix)))
    digest.update(prefix)
    digest.update(struct.pack(">Q", len(records)))
    for record_key in sorted(records):
        key_raw = record_key.encode("utf-8")
        mac_raw = str(records[record_key]["mac"]).encode("utf-8")
        digest.update(struct.pack(">Q", len(key_raw)))
        digest.update(key_raw)
        digest.update(struct.pack(">Q", len(mac_raw)))
        digest.update(mac_raw)
    return digest.hexdigest()


class _AnchorJournal:
    """Load and atomically replace the sidecar anchor journal.

    Loading is fail-closed: a missing file, malformed JSON, unexpected
    shape, or any record whose MAC does not verify under the configured
    key raises :class:`_AnchorCorrupt`, and callers treat the journal as
    unusable rather than guessing at partial contents. Replacement writes
    a temp file, fsyncs it and renames it over the target so a crash can
    never leave a half-written journal.
    """

    def __init__(
        self,
        key: bytes,
        path: str | None,
        memory_records: dict[str, dict[str, object]] | None = None,
    ) -> None:
        self._key = key
        self._path = path
        self._memory_records = memory_records

    @contextlib.contextmanager
    def locked(self):
        """Hold the cross-process journal lock for a read-modify-write.

        The in-process write lock serializes threads; this flock on a
        sibling lock file serializes other processes replacing the same
        journal, so a full-file rewrite can never silently clobber a
        concurrently staged record.
        """
        if self._memory_records is not None or fcntl is None:
            yield
            return
        assert self._path is not None
        directory = os.path.dirname(os.path.abspath(self._path))
        os.makedirs(directory, exist_ok=True)
        lock_fd = os.open(self._path + ".lock", os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            yield
        finally:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)

    def load(self) -> dict[str, dict[str, object]]:
        if self._memory_records is not None:
            return {key: dict(record) for key, record in self._memory_records.items()}
        assert self._path is not None
        try:
            with open(self._path, "rb") as handle:
                raw = handle.read()
        except FileNotFoundError:
            raise _AnchorMissing from None
        except OSError:
            raise _AnchorCorrupt from None
        try:
            document = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise _AnchorCorrupt from None
        if not isinstance(document, dict) or set(document) != {
            "version",
            "records",
            "digest",
        }:
            raise _AnchorCorrupt
        if document["version"] != _ANCHOR_VERSION:
            raise _AnchorCorrupt
        records = document["records"]
        journal_digest = document["digest"]
        if not isinstance(records, dict) or not _is_chain_hash(journal_digest):
            raise _AnchorCorrupt
        parsed: dict[str, dict[str, object]] = {}
        for record_key, record in records.items():
            if not isinstance(record_key, str) or not isinstance(record, dict):
                raise _AnchorCorrupt
            if set(record) != _ANCHOR_REQUIRED_FIELDS:
                raise _AnchorCorrupt
            tenant_id = record["tenant_id"]
            request_id = record["request_id"]
            seq = record["seq"]
            status = record["status"]
            event_count = record["event_count"]
            head = record["head"]
            prev_head = record["prev_head"]
            state = record["state"]
            mac = record["mac"]
            if (
                not isinstance(tenant_id, str)
                or not isinstance(request_id, str)
                or _anchor_record_key(tenant_id, request_id, seq) != record_key
                or not isinstance(seq, int)
                or isinstance(seq, bool)
                or seq < 0
                or not isinstance(status, str)
                or not isinstance(event_count, int)
                or isinstance(event_count, bool)
                or event_count != seq + 1
                or not _is_chain_hash(head)
                or not _is_chain_hash(prev_head)
                or state not in _ANCHOR_STATES
                or not _is_chain_hash(mac)
            ):
                raise _AnchorCorrupt
            expected = _anchor_mac(
                self._key,
                tenant_id,
                request_id,
                seq,
                status,
                event_count,
                head,
                prev_head,
                state,
            )
            if not hmac.compare_digest(expected, mac):
                raise _AnchorCorrupt
            parsed[record_key] = dict(record)
        # The journal digest is the set-membership MAC checked last:
        # without it, deleting a record would leave every per-record MAC
        # valid and the request would merely look unanchored.
        expected_digest = _journal_digest(self._key, parsed)
        if not hmac.compare_digest(expected_digest, journal_digest):
            raise _AnchorCorrupt
        return parsed

    def replace_all(self, records: dict[str, dict[str, object]]) -> None:
        """Atomically replace the whole journal with ``records``."""
        if self._memory_records is not None:
            self._memory_records.clear()
            self._memory_records.update({key: dict(record) for key, record in records.items()})
            return
        assert self._path is not None
        ordered = {key: records[key] for key in sorted(records)}
        document = {
            "version": _ANCHOR_VERSION,
            "records": ordered,
            "digest": _journal_digest(self._key, ordered),
        }
        raw = json.dumps(document, ensure_ascii=False, sort_keys=True).encode("utf-8")
        directory = os.path.dirname(os.path.abspath(self._path))
        os.makedirs(directory, exist_ok=True)
        tmp_path = self._path + ".tmp-" + uuid.uuid4().hex
        try:
            fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                with os.fdopen(fd, "wb") as handle:
                    handle.write(raw)
                    handle.flush()
                    os.fsync(handle.fileno())
            except BaseException:
                try:
                    os.close(fd)
                except OSError:
                    pass
                raise
            os.replace(tmp_path, self._path)
            # The rename itself must be durable before a subsequent crash
            # could expose the previous journal version. Directory fsync
            # is POSIX-specific and best-effort elsewhere.
            try:
                directory_fd = os.open(directory, os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            except OSError:
                pass
        except BaseException:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise


def _make_anchor_record(
    key: bytes,
    tenant_id: str,
    request_id: str,
    seq: int,
    status: str,
    head: str,
    prev_head: str,
    state: str,
) -> dict[str, object]:
    record: dict[str, object] = {
        "tenant_id": tenant_id,
        "request_id": request_id,
        "seq": seq,
        "status": status,
        "event_count": seq + 1,
        "head": head,
        "prev_head": prev_head,
        "state": state,
    }
    record["mac"] = _anchor_mac(
        key, tenant_id, request_id, seq, status, seq + 1, head, prev_head, state
    )
    return record


class RequestStore:
    """Persist and retrieve accepted deletion requests.

    ``integrity_key`` is the secret trusted verification rests on; it
    must be kept by the caller outside both the database and the sidecar
    anchor file. Without a key the store still accepts and serves
    requests, but their evidence is unanchored and
    :meth:`verify_evidence` always returns ``False``. ``anchor_path``
    overrides the sidecar location (default: ``<db_path>.anchors`` next
    to the database). For ``":memory:"`` databases without an explicit
    ``anchor_path`` the journal lives only in this instance's memory.
    """

    def __init__(
        self,
        db_path: str | os.PathLike[str],
        *,
        anchor_path: str | os.PathLike[str] | None = None,
        integrity_key: str | bytes | None = None,
    ):
        self._db_path = os.fspath(db_path)
        # In-process serialization; the unique index additionally guards
        # other processes sharing the same database file.
        self._write_lock = threading.Lock()
        # The key is held only in memory. Empty or non-string/bytes keys
        # are treated as "no key": unanchored operation rather than a
        # half-configured store that would appear to verify.
        if integrity_key is None:
            self._integrity_key: bytes | None = None
        elif isinstance(integrity_key, str):
            self._integrity_key = integrity_key.encode("utf-8") or None
        elif isinstance(integrity_key, (bytes, bytearray)):
            self._integrity_key = bytes(integrity_key) or None
        else:
            raise TypeError("integrity_key must be str, bytes or None")
        if self._db_path == ":memory:":
            self._mem_conn: sqlite3.Connection | None = self._open_connection()
        else:
            self._mem_conn = None
            parent = os.path.dirname(os.path.abspath(self._db_path))
            os.makedirs(parent, exist_ok=True)
        if anchor_path is not None:
            self._anchor_path: str | None = os.fspath(anchor_path)
        elif self._mem_conn is None:
            self._anchor_path = self._db_path + ".anchors"
        else:
            self._anchor_path = None
        # In-memory journals back ":memory:" stores that have no explicit
        # anchor_path; they vanish with the instance exactly like the
        # in-memory database itself.
        self._mem_anchor_records: dict[str, dict[str, object]] | None = (
            {} if self._anchor_path is None and self._integrity_key is not None else None
        )
        conn = self._connect()
        try:
            conn.execute(_SCHEMA)
            conn.execute(_UNIQUE_TENANT_KEY)
            conn.execute(_EVENT_TABLE)
            self._migrate_schema(conn)
        finally:
            self._release(conn)

    def _migrate_schema(self, conn: sqlite3.Connection) -> None:
        """Add chain columns to a database written by an older version.

        The upgrade is additive and runs at most once: the columns start
        nullable, existing events are backfilled in sequence order, and
        each request head is anchored at its final event. Existing chain
        values are never recomputed or overwritten. The backfilled hashes
        are plain SHA-256 links only — no trusted anchor is fabricated
        for pre-existing rows, so legacy data can never verify.
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
                raise RuntimeError("failed to initialize request store") from None

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

    # --- anchor journal helpers -------------------------------------------

    def _journal(self) -> _AnchorJournal:
        assert self._integrity_key is not None
        return _AnchorJournal(self._integrity_key, self._anchor_path, self._mem_anchor_records)

    def _request_anchors(
        self,
        records: dict[str, dict[str, object]],
        tenant_id: str,
        request_id: str,
    ) -> dict[int, dict[str, object]]:
        prefix = _anchor_record_prefix(tenant_id, request_id)
        return {
            int(record_key.rsplit("\x00", 1)[1]): record
            for record_key, record in records.items()
            if record_key.startswith(prefix)
        }

    def _stage_anchor(
        self,
        tenant_id: str,
        request_id: str,
        seq: int,
        status: str,
        head: str,
        prev_head: str,
    ) -> bool:
        """Phase one of the commit protocol: append a ``prepared`` record.

        Called with the write lock held, inside the SQLite write window.
        The journal is append-only: a fresh record is written for this
        seq only when every earlier seq for the request (0..seq-1) is
        already present and committed and the immediately preceding
        record binds the exact predecessor head. A request whose history
        was never anchored is never backfilled, and the caller then
        skips phase two as well.
        """
        journal = self._journal()
        with journal.locked():
            try:
                records = journal.load()
            except _AnchorMissing:
                # First keyed write to a fresh journal. An attacker deleting
                # the file gets the same empty start, which can only ever
                # invalidate existing anchors — never forge one.
                records = {}
            anchors = self._request_anchors(records, tenant_id, request_id)
            prior = anchors.get(seq - 1) if seq > 0 else None
            if seq == 0:
                if anchors:
                    raise RuntimeError("failed to persist request evidence")
            else:
                if (
                    prior is None
                    or prior["state"] != _ANCHOR_COMMITTED
                    or prior["head"] != prev_head
                    or set(anchors) != set(range(seq))
                    or any(
                        anchors[index]["state"] != _ANCHOR_COMMITTED
                        for index in range(seq)
                    )
                ):
                    # Unanchored or interrupted history: persist the SQLite
                    # change without an anchor. The request stays
                    # unverifiable rather than gaining a retroactive
                    # trusted anchor.
                    return False
            record_key = _anchor_record_key(tenant_id, request_id, seq)
            if record_key in records:
                raise RuntimeError("failed to persist request evidence")
            records[record_key] = _make_anchor_record(
                self._integrity_key, tenant_id, request_id, seq, status, head, prev_head,
                _ANCHOR_PREPARED,
            )
            journal.replace_all(records)
        return True

    def _commit_anchor(
        self,
        tenant_id: str,
        request_id: str,
        seq: int,
        status: str,
        head: str,
        prev_head: str,
    ) -> None:
        """Phase two: flip the staged seq record to ``committed``.

        Called with the write lock held, immediately after the SQLite
        transaction commits. The append-only journal keeps every earlier
        record, so a crash between the phases leaves this record
        ``prepared`` forever: the request can never verify again and
        nothing here ever rewrites or deletes it.
        """
        journal = self._journal()
        with journal.locked():
            try:
                records = journal.load()
            except _AnchorMissing:
                raise RuntimeError("failed to persist request evidence") from None
            record_key = _anchor_record_key(tenant_id, request_id, seq)
            existing = records.get(record_key)
            if (
                existing is None
                or existing["state"] != _ANCHOR_PREPARED
                or existing["seq"] != seq
                or existing["head"] != head
            ):
                # The staged record vanished or was replaced out of band;
                # refuse to guess and leave the journal untouched.
                raise RuntimeError("failed to persist request evidence")
            records[record_key] = _make_anchor_record(
                self._integrity_key, tenant_id, request_id, seq, status, head, prev_head,
                _ANCHOR_COMMITTED,
            )
            journal.replace_all(records)

    def _load_anchor_records(self) -> dict[str, dict[str, object]] | None:
        """Best-effort journal read for verification and recovery.

        Returns ``None`` when there is no key, the journal is absent, or
        any record fails to authenticate; callers must treat ``None`` as
        "no trustworthy anchor information", never as "empty journal".
        """
        if self._integrity_key is None:
            return None
        try:
            return self._journal().load()
        except _AnchorCorrupt:
            return None

    # --- request lifecycle -------------------------------------------------

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
                    # The idempotent-replay path never touches the anchor
                    # journal: replaying a submission must not change
                    # evidence in any way.
                    try:
                        return self._load_idempotent(
                            conn, tenant_id, idempotency_key, subject_id, scope_list
                        )
                    except _PrimaryKeyConflict:
                        # Collision was on request_id; retry with a new UUID.
                        continue
                try:
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
                except sqlite3.Error:
                    conn.execute("ROLLBACK")
                    raise RuntimeError("failed to persist accepted request") from None
                anchor_staged = False
                if self._integrity_key is not None:
                    # Commit protocol, phase one: stage the genesis anchor
                    # inside the SQLite write window, after the rows exist
                    # but before the commit. If the journal is unusable the
                    # transaction is rolled back and the submit fails.
                    try:
                        anchor_staged = self._stage_anchor(
                            tenant_id,
                            request_id,
                            0,
                            _STATUS_ACCEPTED,
                            genesis_hash,
                            _GENESIS_PREDECESSOR,
                        )
                    except (_AnchorCorrupt, RuntimeError):
                        conn.execute("ROLLBACK")
                        raise RuntimeError(
                            "failed to persist accepted request"
                        ) from None
                conn.execute("COMMIT")
                if anchor_staged:
                    # Commit protocol, phase two: mark the anchor committed
                    # only after the SQLite commit is durable.
                    try:
                        self._commit_anchor(
                            tenant_id,
                            request_id,
                            0,
                            _STATUS_ACCEPTED,
                            genesis_hash,
                            _GENESIS_PREDECESSOR,
                        )
                    except (_AnchorCorrupt, RuntimeError):
                        raise RuntimeError(
                            "failed to persist accepted request"
                        ) from None
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

    def transition(
        self,
        tenant_id: str,
        request_id: str,
        target_status: str,
    ) -> dict[str, str]:
        """Move a request to ``target_status`` according to the lifecycle.

        Moving a request to the status it already holds is idempotent and
        returns the current receipt. Unknown statuses and illegal moves
        raise :class:`InvalidStatusTransition` without writing; unknown or
        cross-tenant ids raise :class:`RequestNotFound`.
        """
        # Validate before touching the database, mirroring submit(): no
        # rejected call may perform a write.
        tenant_id = _require_nonempty_str(tenant_id, "tenant_id")
        request_id = _require_nonempty_str(request_id, "request_id")
        target_status = _require_nonempty_str(target_status, "target_status")
        if target_status not in _ALLOWED_TRANSITIONS:
            raise InvalidStatusTransition("unknown target status")

        with self._write_lock:
            conn = self._connect()
            try:
                try:
                    conn.execute("BEGIN IMMEDIATE")
                except sqlite3.Error:
                    # Never surface the database engine's own error text.
                    raise RuntimeError("failed to persist status transition") from None
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
                    allowed = _ALLOWED_TRANSITIONS.get(current_status, frozenset())
                    if target_status not in allowed:
                        conn.execute("ROLLBACK")
                        raise InvalidStatusTransition("illegal status transition")
                    # Read the predecessor link before writing so the new
                    # link binds the exact persisted predecessor. BEGIN
                    # IMMEDIATE serializes writers, so two transitions can
                    # neither claim the same seq nor read a stale predecessor.
                    latest = conn.execute(
                        "SELECT seq, occurred_at, chain_hash FROM status_events "
                        "WHERE tenant_id = ? AND request_id = ? "
                        "ORDER BY seq DESC LIMIT 1",
                        (tenant_id, request_id),
                    ).fetchone()
                    if latest is None or not _is_chain_hash(latest[2]):
                        # Defensive only: every accepted request owns its
                        # seq-0 event with a valid link, so reaching here
                        # means the timeline invariant was broken out of
                        # band. Never fabricate a replacement link.
                        conn.execute("ROLLBACK")
                        raise RuntimeError("failed to persist status transition")
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
                        # The row vanished or changed under us; refuse rather
                        # than persisting a state that breaks the transition
                        # graph observed at read time.
                        conn.execute("ROLLBACK")
                        raise InvalidStatusTransition("illegal status transition")
                    anchor_staged = False
                    if self._integrity_key is not None:
                        # Commit protocol, phase one: stage the anchor for
                        # the new head inside the SQLite write window, after
                        # the row update succeeded but before the commit.
                        # Anchors only extend a journal that already commits
                        # the exact predecessor head.
                        try:
                            anchor_staged = self._stage_anchor(
                                tenant_id,
                                request_id,
                                next_seq + 1,
                                target_status,
                                next_link_hash,
                                predecessor_hash,
                            )
                        except (_AnchorCorrupt, RuntimeError):
                            conn.execute("ROLLBACK")
                            raise RuntimeError(
                                "failed to persist status transition"
                            ) from None
                    # The event is appended in the same transaction as the
                    # status update. The event's chain link binds the
                    # predecessor hash and is itself anchored on the request
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
                    raise RuntimeError("failed to persist status transition") from None
                if anchor_staged:
                    # Commit protocol, phase two: mark the anchor committed
                    # only after the SQLite commit is durable.
                    try:
                        self._commit_anchor(
                            tenant_id,
                            request_id,
                            next_seq + 1,
                            target_status,
                            next_link_hash,
                            predecessor_hash,
                        )
                    except (_AnchorCorrupt, RuntimeError):
                        raise RuntimeError(
                            "failed to persist status transition"
                        ) from None
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

    def audit(
        self,
        tenant_id: str,
        request_id: str,
    ) -> list[dict[str, str]]:
        """Return the request's status timeline in occurrence order.

        Each entry contains only ``status`` and ``occurred_at`` (a UTC
        RFC3339 string). The final entry's status always equals the result
        of :meth:`get`. Unknown ids and cross-tenant lookups raise
        :class:`RequestNotFound` with identical behaviour, so the call
        cannot reveal another tenant's records.
        """
        tenant_id = _require_nonempty_str(tenant_id, "tenant_id")
        request_id = _require_nonempty_str(request_id, "request_id")
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
            # like get().
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
        to :meth:`get`), ``event_count`` (identical to the length of
        :meth:`audit`) and ``chain_hash`` (the SHA-256 head of the audit
        chain as persisted, never recomputed). Unknown ids and cross-
        tenant lookups raise :class:`RequestNotFound`; non-string or
        empty arguments raise :class:`ValueError`.
        """
        tenant_id = _require_nonempty_str(tenant_id, "tenant_id")
        request_id = _require_nonempty_str(request_id, "request_id")
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

        Verification is fail-closed and never writes: it returns ``True``
        only when the request carries a ``committed`` sidecar anchor that
        authenticates under the configured integrity key *and* every
        SQLite chain link recomputes to its stored hash from the genesis
        predecessor, the sequences are gap-free from zero, and the final
        link matches the request's anchored head and current status.

        Without an integrity key, with a missing or corrupt sidecar, for
        requests that predate keyed anchoring, and for any state left by
        an interrupted commit, the result is ``False``. Deleting,
        altering, inserting or reordering events, tampering with the
        request head, substituting events or anchors from another request
        or tenant, or recomputing and replacing every public value in
        SQLite and the sidecar all yield ``False`` as well. Unknown ids
        and cross-tenant lookups raise :class:`RequestNotFound`;
        non-string or empty arguments raise :class:`ValueError`.
        """
        tenant_id = _require_nonempty_str(tenant_id, "tenant_id")
        request_id = _require_nonempty_str(request_id, "request_id")
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
                raise RuntimeError("failed to verify request evidence") from None
        finally:
            self._release(conn)

        # The trusted anchor gate comes first: without an authentic
        # append-only anchor sequence for exactly this request, no SQLite
        # content — however self-consistent — can verify. Every seq from
        # zero must have a committed anchor; the final one must bind the
        # SQLite head. Earlier anchors are retained forever, so rolling
        # SQLite back to a previous state cannot line up with the journal.
        records = self._load_anchor_records()
        if records is None:
            return False
        anchors = self._request_anchors(records, tenant_id, request_id)
        if not anchors or set(anchors) != set(range(len(rows))):
            return False
        if any(record["state"] != _ANCHOR_COMMITTED for record in anchors.values()):
            return False

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
            # The anchor for this seq must bind exactly this link and
            # status, so a forged event can never be hidden inside an
            # otherwise-correct-looking chain.
            anchor = anchors[seq]
            if (
                anchor["head"] != stored_hash
                or anchor["status"] != status
                or anchor["event_count"] != seq + 1
            ):
                return False
            predecessor = stored_hash

        # At least the genesis event must exist, the final link must be
        # the head anchored on the request row, and its status must match
        # the authoritative current status.
        if not rows:
            return False
        if not hmac.compare_digest(predecessor, anchored_head):
            return False
        if rows[-1][1] != current_status:
            return False
        # The final committed anchor must bind the SQLite head, status and
        # event count exactly. Anything else — a rolled-back journal, a
        # swapped record, an interrupted commit — fails here.
        final_anchor = anchors[len(rows) - 1]
        return (
            final_anchor["head"] == anchored_head
            and final_anchor["status"] == current_status
        )

    def recover(self) -> dict[str, object]:
        """Inspect commit-protocol consistency without changing anything.

        Returns a report with ``state`` (the worst per-request state),
        ``key_configured``, ``sidecar`` (``"ok"``, ``"missing"``,
        ``"corrupt"`` or ``"unconfigured"``) and ``requests``: a sorted
        list of ``{"tenant_id", "request_id", "state"}`` entries where
        each state is one of ``"committed"``, ``"prepared"``,
        ``"unanchored"``, ``"inconsistent"`` or ``"corrupt"``. Only
        ``"committed"`` is valid; every other state is an explicit
        non-valid verdict. The method is strictly read-only: it never
        repairs, backfills or rewrites evidence, and it never raises for
        damaged stores.
        """
        requests: list[dict[str, object]] = []
        conn = self._connect()
        try:
            try:
                rows = conn.execute(
                    "SELECT tenant_id, request_id, status, chain_hash FROM requests"
                ).fetchall()
                for tenant_id, request_id, status, chain_hash in rows:
                    events = conn.execute(
                        "SELECT seq, status, occurred_at, chain_hash "
                        "FROM status_events "
                        "WHERE tenant_id = ? AND request_id = ? ORDER BY seq",
                        (tenant_id, request_id),
                    ).fetchall()
                    requests.append(
                        {
                            "tenant_id": tenant_id,
                            "request_id": request_id,
                            "status": status,
                            "chain_hash": chain_hash,
                            "events": events,
                        }
                    )
            except sqlite3.Error:
                return {
                    "state": _RECOVER_CORRUPT,
                    "key_configured": self._integrity_key is not None,
                    "sidecar": (
                        "unconfigured"
                        if self._integrity_key is None
                        else "corrupt"
                    ),
                    "requests": [],
                }
        finally:
            self._release(conn)

        key_configured = self._integrity_key is not None
        records: dict[str, dict[str, object]] | None = None
        if key_configured:
            if self._mem_anchor_records is not None:
                sidecar_state = "ok"
                records = self._load_anchor_records()
            elif self._anchor_path is not None and not os.path.exists(self._anchor_path):
                sidecar_state = "missing"
            else:
                try:
                    records = self._journal().load()
                    sidecar_state = "ok"
                except _AnchorCorrupt:
                    sidecar_state = "corrupt"
        else:
            sidecar_state = "unconfigured"

        # Surface orphan anchors too: a prepared record whose SQLite
        # transaction never committed, or a committed anchor whose row is
        # gone, must not disappear from the report merely because SQLite
        # was rolled back or deleted.
        if records is not None:
            known = {
                (item["tenant_id"], item["request_id"]) for item in requests
            }
            orphaned: set[tuple[str, str]] = set()
            for record in records.values():
                pair = (str(record["tenant_id"]), str(record["request_id"]))
                if pair not in known and pair not in orphaned:
                    orphaned.add(pair)
                    requests.append(
                        {
                            "tenant_id": pair[0],
                            "request_id": pair[1],
                            "status": None,
                            "chain_hash": None,
                            "events": [],
                        }
                    )

        worst_rank = 0
        rank = {
            _RECOVER_COMMITTED: 0,
            _RECOVER_UNANCHORED: 1,
            _RECOVER_PREPARED: 2,
            _RECOVER_INCONSISTENT: 3,
            _RECOVER_CORRUPT: 4,
        }
        report_entries: list[dict[str, str]] = []
        for item in requests:
            state = self._classify_request(item, records)
            worst_rank = max(worst_rank, rank[state])
            report_entries.append(
                {
                    "tenant_id": item["tenant_id"],
                    "request_id": item["request_id"],
                    "state": state,
                }
            )
        if sidecar_state == "corrupt":
            worst_rank = max(worst_rank, rank[_RECOVER_CORRUPT])
        report_entries.sort(key=lambda entry: (entry["tenant_id"], entry["request_id"]))
        overall = _RECOVER_COMMITTED
        for name, value in rank.items():
            if value == worst_rank:
                overall = name
                break
        return {
            "state": overall,
            "key_configured": key_configured,
            "sidecar": sidecar_state,
            "requests": report_entries,
        }

    def _classify_request(
        self,
        item: dict[str, object],
        records: dict[str, dict[str, object]] | None,
    ) -> str:
        """Classify one request's commit-protocol state (read-only)."""
        tenant_id = item["tenant_id"]
        request_id = item["request_id"]
        current_status = item["status"]
        anchored_head = item["chain_hash"]
        events = item["events"]
        assert isinstance(tenant_id, str) and isinstance(request_id, str)
        assert isinstance(events, list)

        chain_ok = False
        head: str | None = None
        if isinstance(current_status, str) and _is_chain_hash(anchored_head):
            predecessor = _GENESIS_PREDECESSOR
            chain_ok = bool(events)
            for expected_seq, event in enumerate(events):
                seq, status, occurred_at, stored_hash = event
                if (
                    not isinstance(seq, int)
                    or isinstance(seq, bool)
                    or seq != expected_seq
                    or not isinstance(status, str)
                    or not isinstance(occurred_at, str)
                    or not _is_chain_hash(stored_hash)
                ):
                    chain_ok = False
                    break
                recomputed = _chain_hash(
                    tenant_id, request_id, seq, status, occurred_at, predecessor
                )
                if not hmac.compare_digest(recomputed, stored_hash):
                    chain_ok = False
                    break
                predecessor = stored_hash
            if chain_ok and (
                not hmac.compare_digest(predecessor, anchored_head)
                or events[-1][1] != current_status
            ):
                chain_ok = False
            if chain_ok:
                head = anchored_head

        if records is None:
            # No trustworthy anchor information: a broken chain is
            # inconsistent, anything else is simply unanchored.
            return _RECOVER_INCONSISTENT if not chain_ok else _RECOVER_UNANCHORED

        anchors = self._request_anchors(records, tenant_id, request_id)
        if not anchors:
            return _RECOVER_INCONSISTENT if not chain_ok else _RECOVER_UNANCHORED
        if any(record["state"] == _ANCHOR_PREPARED for record in anchors.values()):
            # An interrupted commit: never valid, never repaired.
            return _RECOVER_PREPARED
        if not chain_ok:
            return _RECOVER_INCONSISTENT
        expected_seqs = set(range(len(events)))
        if set(anchors) != expected_seqs:
            # Anchor history extends beyond SQLite (rollback/snapshot) or
            # has gaps: inconsistent, never silently trusted or repaired.
            return _RECOVER_INCONSISTENT
        for seq, event in enumerate(events):
            anchor = anchors[seq]
            if anchor["state"] != _ANCHOR_COMMITTED:
                return _RECOVER_INCONSISTENT
            _, status, _, stored_hash = event
            if anchor["head"] != stored_hash or anchor["status"] != status:
                return _RECOVER_INCONSISTENT
        final_anchor = anchors[len(events) - 1]
        return (
            _RECOVER_COMMITTED
            if final_anchor["head"] == head and final_anchor["status"] == current_status
            else _RECOVER_INCONSISTENT
        )

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
                raise RuntimeError("failed to read request evidence") from None
        finally:
            self._release(conn)
        if row is None:
            # Identical outcome for unknown ids and cross-tenant lookups.
            raise RequestNotFound("request not found")
        return row[0], row[1], row[2]
