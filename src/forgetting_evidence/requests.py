"""SQLite-backed acceptance store for deletion requests.

The store records deletion requests without retaining any identifying
payload in logs, return values beyond the fixed receipt fields, or
exception messages. SQLite integrity conflicts are translated into the
module's own idempotency semantics and never surface to callers.

Every accepted request carries a persistent, append-only status timeline
in ``status_events``. Events are written in the same SQLite transaction
as the request row or status change they describe, so the final timeline
entry always matches the request's current status.

Each event additionally carries a tamper-evident ``chain_hash``: a
SHA-256 value binding the tenant, request, sequence number, status,
occurrence time and the previous event's hash. The hash of the final
event is also stored on the request row, so deleting, modifying,
inserting or reordering persisted events breaks verification. The hash
preimage is never exposed in return values, exceptions or logs.

Trust model
-----------

The plain chain is fully public: anyone able to read the database can
recompute every link, so it cannot anchor trust outside SQLite by
itself. Trusted verification additionally requires two things outside
the attacker's reach:

1. An *external anchor*: an append-only sidecar file outside SQLite
   holding, for every acceptance and every actual status migration, a
   prepare/commit pair under the recoverable commit protocol below.
2. A secret ``integrity_key`` kept by the caller outside both SQLite and
   the sidecar. Each sidecar record carries an HMAC-SHA-256 tag keyed by
   that secret. Without the key an attacker cannot author a single
   well-formed record, therefore deleting, altering, inserting,
   reordering, substituting across requests/tenants, or recomputing and
   replacing all public contents of both the database and the sidecar
   can never verify as true.

The key itself, key-equivalent derived material, and the chain
preimage are never written to SQLite, the sidecar, receipts,
exceptions or logs. Sidecar records contain only public fields plus
HMAC tags.

Recoverable commit protocol
---------------------------

For each acceptance or actual migration, with counter ``n`` (strictly
increasing, per sidecar):

1. The SQLite write transaction is opened and all row/event changes are
   staged, so rejected calls (idempotent replay, illegal migration,
   unknown record, bad arguments) never reach the sidecar.
2. *Prepare*: a ``P`` record keyed with HMAC over
   ``version|counter|tenant|request|event_index|chain_head`` is appended
   to the sidecar, flushed and ``fsync``ed (parent directory fsynced on
   file creation). ``anchor_seq = n`` is then staged in the same SQLite
   transaction.
3. *Commit-DB*: the SQLite transaction is committed, a WAL checkpoint
   and an ``fsync`` of the database file and its durable parent pin the
   referenced data.
4. *Commit-anchor*: a ``C`` record whose HMAC tag covers the prepare
   fields *and* the prepare record's own tag (referenced in its ``p``
   field) is appended, flushed and ``fsync``ed. C can therefore only be
   validated against the authenticated P, without a second derived
   secret.

Only after step 4 does the call return a success receipt. A failure at
any step raises; it never returns success. A ``P`` without its ``C`` is
an interrupted commit: on rebuild the log is reported ``incomplete``,
:meth:`RequestStore.verify_evidence` returns ``False`` and further
anchored writes are refused (the instance never repairs the evidence
itself; the uncommitted tail must be resolved by the operator). Records
are never silently skipped.

Rebuild semantics
------------------

On construction the sidecar is replayed and every HMAC tag is checked.
Committed counters must form the contiguous prefix ``1..m``; any
malformed, unauthenticatable, duplicated or out-of-order record makes
the log invalid from that point (``recover() == "invalid"``). A clean
log ending in prepared-but-uncommitted records is ``incomplete``.
Databases written before trusted anchoring have ``anchor_seq IS NULL``
and fail verification (``recover() == "incomplete"``) until extended by
a properly anchored write.
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

try:  # POSIX advisory locks serialize sidecar writers across processes.
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX fallback
    fcntl = None  # type: ignore[assignment]

__all__ = [
    "RequestStore",
    "IdempotencyConflict",
    "RequestNotFound",
    "InvalidStatusTransition",
]

_log = logging.getLogger(__name__)

# --- constants -------------------------------------------------------

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

_HEX = "0123456789abcdef"

# SHA-256 of the empty string: the predecessor of the genesis event.
# A fixed non-derived sentinel keeps the first event distinguishable
# from an event chained onto a forged 64-character predecessor.
_GENESIS_PREDECESSOR = (
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

# Sidecar record format version and record kinds.
_SIDECAR_VERSION = 1
_RECORD_PREPARE = "P"
_RECORD_COMMIT = "C"

# HMAC domain separators keep tags for the same public fields distinct
# in each role, so a prepare tag can never be replayed as a commit tag.
_TAG_PREPARE_DOMAIN = b"forgetting-evidence.sidecar.prepare.v1\n"
_TAG_COMMIT_DOMAIN = b"forgetting-evidence.sidecar.commit.v1\n"
_TAG_LENGTH = hashlib.sha256().digest_size

# Every sidecar record is one JSON object with exactly these keys; all
# values are public (no key, derived secret or chain preimage is stored).
# A commit record references its prepare by the prepare's own HMAC tag,
# so C can only be validated against an authenticated P and no extra
# secret-derived value is introduced.
_PREPARE_FIELDS = frozenset({"v", "k", "n", "t", "tenant", "r", "c", "h"})
_COMMIT_FIELDS = frozenset({"v", "k", "n", "t", "p"})


# --- exceptions ------------------------------------------------------


class IdempotencyConflict(Exception):
    """Raised when an idempotency key is reused with a different payload."""


class RequestNotFound(Exception):
    """Raised when no request visible to the tenant matches the id."""


class InvalidStatusTransition(Exception):
    """Raised when a requested status change is unknown or not permitted."""


class _PrimaryKeyConflict(Exception):
    """Internal signal: retry insertion with a freshly generated id."""


# --- schema ----------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS requests (
    request_id      TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    subject_id      TEXT NOT NULL,
    scopes_json     TEXT NOT NULL,
    status          TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    chain_hash      TEXT NOT NULL,
    anchor_seq      INTEGER
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

# Column probes used to upgrade database files created before integrity
# columns existed. Upgrades are purely additive; trusted anchors are
# never fabricated, so pre-anchor data fails trusted verification.
_REQUEST_CHAIN_COLUMN = (
    "SELECT 1 FROM pragma_table_info('requests') WHERE name = 'chain_hash'"
)
_EVENT_CHAIN_COLUMN = (
    "SELECT 1 FROM pragma_table_info('status_events') WHERE name = 'chain_hash'"
)
_REQUEST_ANCHOR_COLUMN = (
    "SELECT 1 FROM pragma_table_info('requests') WHERE name = 'anchor_seq'"
)


# --- validation / encoding helpers -----------------------------------


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
        raise ValueError(
            "scopes must be a non-empty sequence of distinct strings"
        ) from exc
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


def _is_hex64(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in _HEX for char in value)
    )


# Preserve the descriptive name used at internal call sites.
_is_chain_hash = _is_hex64


def _hmac_digest(key: bytes, domain: bytes, parts: list[bytes]) -> bytes:
    mac = hmac.new(key, domain, digestmod=hashlib.sha256)
    for part in parts:
        mac.update(struct.pack(">Q", len(part)))
        mac.update(part)
    return mac.digest()


def _fsync_directory(directory: str) -> None:
    """Fsync a directory so a freshly created file's dirent is durable."""
    if not directory:
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        fd = os.open(directory, flags)
    except OSError:
        # Some platforms/filesystems disallow opening directories.
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def _fsync_file(path: str) -> None:
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


# --- sidecar anchor log ----------------------------------------------


class _AnchorLog:
    """Append-only, keyed anchor log stored outside SQLite.

    On-disk layout: newline-delimited JSON, one record per line.

    Prepare record::

        {"v":1,"k":"P","n":N,"t":"<hmac hex>","tenant":T,"r":R,"c":C,"h":H}

    Commit record::

        {"v":1,"k":"C","n":N,"t":"<hmac hex>","p":"<prepare tag hex>"}

    ``N`` is the global prepare counter (1-based); ``C`` is the
    per-request event index (0-based); ``H`` is the event chain head at
    that event. Replay enforces strictly increasing prepares
    ``P1, P2, ...`` and commits that complete them in order
    (``C1`` before ``C2``); committed counters always form ``1..m``.
    """

    def __init__(self, path: str, key: bytes, repair_torn: bool = True):
        self._path = path
        self._key = key
        # Counter -> validated public prepare info.
        self._prepared: dict[int, dict[str, object]] = {}
        # Contiguous set {1..m} of counters with a valid C record.
        self._committed: set[int] = set()
        # Valid prepares without a commit (interrupted-commit tail).
        self._pending: set[int] = set()
        # True once a malformed/unauthenticatable/order-breaking record
        # was encountered; everything from that line on is untrusted.
        self._invalid = False
        # Set after a local I/O failure: this instance cannot safely
        # append more; reopening replays the durable truth.
        self._poisoned = False
        if repair_torn:
            self._truncate_torn_tail()
        self._replay()

    def _truncate_torn_tail(self) -> None:
        """Drop a final record whose write never completed.

        Every durable record ends with a newline. If the file ends
        without one, the last line is a torn append (a crash before
        ``fsync`` returned) and was never acknowledged; truncating to
        the last newline restores the last fully durable prefix. This
        cannot fabricate evidence: the discarded bytes never formed a
        valid record, and the database cross-check still fails closed if
        the truncation hides an attack.
        """
        try:
            with open(self._path, "rb") as handle:
                handle.seek(0, os.SEEK_END)
                size = handle.tell()
                if size == 0:
                    return
                handle.seek(max(0, size - 4096))
                tail = handle.read()
        except FileNotFoundError:
            return
        except OSError:
            # Unreadable log: let replay mark it invalid.
            return
        if tail.endswith(b"\n"):
            return
        last_nl = tail.rfind(b"\n")
        clean_size = size - len(tail) + last_nl + 1 if last_nl != -1 else 0
        try:
            with open(self._path, "r+b") as handle:
                handle.truncate(clean_size)
                handle.flush()
                os.fsync(handle.fileno())
        except OSError:
            # Cannot repair the torn tail; leave replay to reject it.
            pass

    # ----- replay -----------------------------------------------------

    def _replay(self) -> None:
        try:
            with open(self._path, "rb") as handle:
                raw = handle.read()
        except FileNotFoundError:
            return
        except OSError:
            # An unreadable anchor log is a hard integrity failure.
            self._invalid = True
            return
        if not raw:
            # An empty file can only result from interrupted creation;
            # it anchors nothing but is not corrupt.
            return

        prepared: dict[int, dict[str, object]] = {}
        committed: set[int] = set()
        invalid = False

        for line in raw.splitlines():
            if not self._replay_line(line, prepared, committed):
                invalid = True
                break

        if invalid:
            self._invalid = True
            # Retain only the clean committed prefix; discard all tail
            # state, including prepares that only appeared in it.
            self._committed = committed
            self._prepared = {n: prepared[n] for n in committed if n in prepared}
            self._pending = set()
            return

        self._prepared = prepared
        self._committed = committed
        self._pending = {n for n in prepared if n not in committed}

    def _replay_line(
        self,
        line: bytes,
        prepared: dict[int, dict[str, object]],
        committed: set[int],
    ) -> bool:
        try:
            record = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return False
        if not isinstance(record, dict):
            return False
        kind = record.get("k")
        if kind == _RECORD_PREPARE:
            if set(record) != _PREPARE_FIELDS:
                return False
        elif kind == _RECORD_COMMIT:
            if set(record) != _COMMIT_FIELDS:
                return False
        else:
            return False
        if record.get("v") != _SIDECAR_VERSION:
            return False
        counter = record.get("n")
        if not isinstance(counter, int) or isinstance(counter, bool) or counter <= 0:
            return False
        tag_hex = record.get("t")
        if not isinstance(tag_hex, str) or len(tag_hex) != _TAG_LENGTH * 2:
            return False
        try:
            tag = bytes.fromhex(tag_hex)
        except ValueError:
            return False

        if kind == _RECORD_PREPARE:
            tenant = record.get("tenant")
            request = record.get("r")
            event_index = record.get("c")
            head = record.get("h")
            if (
                not isinstance(tenant, str)
                or not tenant
                or not isinstance(request, str)
                or not request
                or not isinstance(event_index, int)
                or isinstance(event_index, bool)
                or event_index < 0
                or not _is_hex64(head)
            ):
                return False
            # Prepares must be strictly increasing and must never
            # restate an already committed counter.
            expected = (max(prepared, default=0) + 1) if prepared else 1
            if counter != expected or counter in committed:
                return False
            info = {
                "tenant": tenant,
                "request": request,
                "c": event_index,
                "h": head,
            }
            expected_tag = _hmac_digest(
                self._key, _TAG_PREPARE_DOMAIN, self._prepare_parts(counter, info)
            )
            if not hmac.compare_digest(expected_tag, tag):
                return False
            prepared[counter] = info
            return True

        # Commit record.
        if counter not in prepared or counter in committed:
            return False
        # Commits must complete prepares in strict order, so committed
        # counters always form 1..m with no gaps.
        if counter != len(committed) + 1:
            return False
        prepare_tag_hex = record.get("p")
        if not isinstance(prepare_tag_hex, str) or len(prepare_tag_hex) != _TAG_LENGTH * 2:
            return False
        try:
            prepare_tag = bytes.fromhex(prepare_tag_hex)
        except ValueError:
            return False
        info = prepared[counter]
        # C must reference the exact authenticated P tag, binding the
        # commit to that prepare without any second derived secret.
        expected_prepare_tag = _hmac_digest(
            self._key, _TAG_PREPARE_DOMAIN, self._prepare_parts(counter, info)
        )
        if not hmac.compare_digest(expected_prepare_tag, prepare_tag):
            return False
        expected_tag = _hmac_digest(
            self._key,
            _TAG_COMMIT_DOMAIN,
            [
                str(_SIDECAR_VERSION).encode("utf-8"),
                str(counter).encode("utf-8"),
                *self._prepare_parts(counter, info),
                prepare_tag,
            ],
        )
        if not hmac.compare_digest(expected_tag, tag):
            return False
        committed.add(counter)
        return True

    @staticmethod
    def _prepare_parts(counter: int, info: dict[str, object]) -> list[bytes]:
        return [
            str(_SIDECAR_VERSION).encode("utf-8"),
            str(counter).encode("utf-8"),
            str(info["tenant"]).encode("utf-8"),
            str(info["request"]).encode("utf-8"),
            str(info["c"]).encode("utf-8"),
            str(info["h"]).encode("utf-8"),
        ]

    # ----- introspection ---------------------------------------------

    @property
    def has_invalid_records(self) -> bool:
        return self._invalid

    @property
    def is_incomplete(self) -> bool:
        """A clean log ending in prepared-but-uncommitted records."""
        return not self._invalid and bool(self._pending)

    @property
    def committed_counters(self) -> set[int]:
        return set(self._committed)

    def latest_committed_anchor(
        self, tenant: str, request: str
    ) -> tuple[int, int, str] | None:
        """Return ``(counter, event_index, head)`` for a request.

        The highest committed counter naming ``tenant``/``request``.
        ``None`` when no committed record authenticates the request.
        """
        match: tuple[int, int, str] | None = None
        for counter in sorted(self._committed):
            info = self._prepared.get(counter)
            if info is None:
                continue
            if info["tenant"] == tenant and info["request"] == request:
                match = (counter, int(info["c"]), str(info["h"]))
        return match

    def committed_anchor(self, counter: int) -> dict[str, object] | None:
        if counter not in self._committed:
            return None
        return dict(self._prepared[counter])

    # ----- mutation ---------------------------------------------------

    def _require_writable(self) -> None:
        if self._invalid or self._poisoned or self._pending:
            # An interrupted-commit tail or corrupt log must not be
            # extended; doing so would paper over evidence loss.
            raise RuntimeError("anchor log is not writable")

    def next_counter(self) -> int:
        self._require_writable()
        return (max(self._prepared, default=0) + 1) if self._prepared else 1

    def prepare(
        self,
        counter: int,
        tenant: str,
        request: str,
        event_index: int,
        head: str,
    ) -> bytes:
        """Append and fsync a prepare record; return its HMAC tag.

        The returned tag is the prepare's own HMAC, which the later
        commit record references in its ``p`` field; the raw key never
        leaves this class.
        """
        self._require_writable()
        info = {
            "tenant": tenant,
            "request": request,
            "c": event_index,
            "h": head,
        }
        parts = self._prepare_parts(counter, info)
        tag = _hmac_digest(self._key, _TAG_PREPARE_DOMAIN, parts)
        record = {
            "v": _SIDECAR_VERSION,
            "k": _RECORD_PREPARE,
            "n": counter,
            "t": tag.hex(),
            "tenant": tenant,
            "r": request,
            "c": event_index,
            "h": head,
        }
        self._append_record(record)
        self._prepared[counter] = info
        self._pending.add(counter)
        return tag

    def commit(self, counter: int, prepare_tag: bytes) -> None:
        """Append and fsync the commit record for ``counter``."""
        if self._invalid or self._poisoned:
            raise RuntimeError("anchor log is not writable")
        info = self._prepared.get(counter)
        if info is None or counter not in self._pending:
            raise RuntimeError("anchor log is not writable")
        tag = _hmac_digest(
            self._key,
            _TAG_COMMIT_DOMAIN,
            [
                str(_SIDECAR_VERSION).encode("utf-8"),
                str(counter).encode("utf-8"),
                *self._prepare_parts(counter, info),
                prepare_tag,
            ],
        )
        record = {
            "v": _SIDECAR_VERSION,
            "k": _RECORD_COMMIT,
            "n": counter,
            "t": tag.hex(),
            "p": prepare_tag.hex(),
        }
        self._append_record(record)
        self._committed.add(counter)
        self._pending.discard(counter)

    def _append_record(self, record: dict[str, object]) -> None:
        line = json.dumps(record, separators=(",", ":"), sort_keys=True) + "\n"
        payload = line.encode("utf-8")
        parent = os.path.dirname(os.path.abspath(self._path))
        os.makedirs(parent, exist_ok=True)
        created = not os.path.exists(self._path)
        try:
            fd = os.open(self._path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                written = 0
                while written < len(payload):
                    written += os.write(fd, payload[written:])
                os.fsync(fd)
            finally:
                os.close(fd)
        except OSError:
            self._poisoned = True
            raise
        if created:
            _fsync_directory(parent)


# --- store -----------------------------------------------------------


class RequestStore:
    """Persist and retrieve accepted deletion requests.

    :param db_path: SQLite database path (or ``":memory:"``).
    :param anchor_path: optional path to the trusted append-only anchor
        sidecar. Must be supplied together with ``integrity_key``.
    :param integrity_key: secret bytes/string held only by the caller,
        outside SQLite and the sidecar. Must be supplied together with
        ``anchor_path``. The key is never persisted.
    """

    def __init__(
        self,
        db_path: str | os.PathLike[str],
        anchor_path: str | os.PathLike[str] | None = None,
        integrity_key: bytes | str | None = None,
    ):
        if (anchor_path is None) ^ (integrity_key is None):
            raise ValueError(
                "anchor_path and integrity_key must be provided together"
            )
        key_bytes: bytes | None
        if integrity_key is None:
            key_bytes = None
        elif isinstance(integrity_key, str):
            key_bytes = integrity_key.encode("utf-8")
        elif isinstance(integrity_key, bytes):
            key_bytes = integrity_key
        else:
            raise ValueError("integrity_key must be bytes or string")
        if key_bytes is not None and not key_bytes:
            raise ValueError("integrity_key must be non-empty")

        self._anchor_path: str | None = None
        self._anchor_key: bytes | None = None
        self._anchor_lock_fd: int | None = None
        if anchor_path is not None:
            anchor_fspath = os.fspath(anchor_path)
            if anchor_fspath == ":memory:":
                raise ValueError("anchor_path cannot be ':memory:'")
            self._anchor_path = anchor_fspath
            self._anchor_key = key_bytes
            # A separate lock file serializes prepare->commit across
            # processes so the global counter stays contiguous even with
            # concurrent writers on different connections.
            if fcntl is not None:
                lock_fspath = anchor_fspath + ".lock"
                lock_parent = os.path.dirname(os.path.abspath(lock_fspath))
                os.makedirs(lock_parent, exist_ok=True)
                created = not os.path.exists(lock_fspath)
                self._anchor_lock_fd = os.open(
                    lock_fspath, os.O_RDWR | os.O_CREAT, 0o600
                )
                if created:
                    _fsync_directory(lock_parent)

        self._db_path = os.fspath(db_path)
        # In-process serialization; the unique index additionally guards
        # other processes sharing the same database file.
        self._write_lock = threading.Lock()
        # Serializes sidecar replay/repair/append between threads: POSIX
        # flock on a shared descriptor does not distinguish threads in
        # the same process. Writers already hold _write_lock; read-only
        # anchor sessions take only this lock. Lock order is always
        # _write_lock -> _anchor_lock, never the reverse.
        self._anchor_lock = threading.Lock()
        if self._db_path == ":memory:":
            self._mem_conn: sqlite3.Connection | None = self._open_connection()
        else:
            self._mem_conn = None
            parent = os.path.dirname(os.path.abspath(self._db_path))
            os.makedirs(parent, exist_ok=True)
        conn = self._connect()
        try:
            conn.execute(_SCHEMA)
            conn.execute(_UNIQUE_TENANT_KEY)
            conn.execute(_EVENT_TABLE)
            self._migrate_schema(conn)
        finally:
            self._release(conn)

    # ----- schema / migration ----------------------------------------

    def _migrate_schema(self, conn: sqlite3.Connection) -> None:
        """Add integrity columns to a database from an older version.

        Purely additive: ``chain_hash`` columns are backfilled for files
        from the pre-chain build so the public timeline stays coherent;
        the trusted ``anchor_seq`` column is added NULL and never
        fabricated, so old data fails trusted verification until a
        properly anchored write extends it.
        """
        need_chain_request = not conn.execute(_REQUEST_CHAIN_COLUMN).fetchone()
        need_chain_event = not conn.execute(_EVENT_CHAIN_COLUMN).fetchone()
        need_anchor = not conn.execute(_REQUEST_ANCHOR_COLUMN).fetchone()
        if not (need_chain_request or need_chain_event or need_anchor):
            return
        with self._write_lock:
            try:
                conn.execute("BEGIN IMMEDIATE")
                if not conn.execute(_REQUEST_CHAIN_COLUMN).fetchone():
                    conn.execute("ALTER TABLE requests ADD COLUMN chain_hash TEXT")
                if not conn.execute(_EVENT_CHAIN_COLUMN).fetchone():
                    conn.execute(
                        "ALTER TABLE status_events ADD COLUMN chain_hash TEXT"
                    )
                if not conn.execute(_REQUEST_ANCHOR_COLUMN).fetchone():
                    conn.execute("ALTER TABLE requests ADD COLUMN anchor_seq INTEGER")
                if need_chain_request or need_chain_event:
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
                            tenant_id,
                            request_id,
                            seq,
                            status,
                            occurred_at,
                            predecessor,
                        )
                        conn.execute(
                            "UPDATE status_events SET chain_hash = ? "
                            "WHERE tenant_id = ? AND request_id = ? AND seq = ?",
                            (link, tenant_id, request_id, seq),
                        )
                        predecessor = link
                    # A request with no events keeps NULL and fails
                    # verification rather than receiving a fabricated
                    # anchor.
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

    # ----- connections / durability -----------------------------------

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

    def _fsync_database(self, conn: sqlite3.Connection) -> None:
        """Pin committed SQLite data before the anchor commit marker."""
        if self._mem_conn is not None:
            return
        try:
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except sqlite3.Error:
            pass
        db_file = os.path.abspath(self._db_path)
        _fsync_file(db_file)
        _fsync_directory(os.path.dirname(db_file))

    def _fresh_anchor(self, repair_torn: bool = True) -> _AnchorLog:
        """Re-read the sidecar so cross-process writes are visible."""
        return _AnchorLog(
            self._anchor_path,  # type: ignore[arg-type]
            self._anchor_key,  # type: ignore[arg-type]
            repair_torn=repair_torn,
        )

    @contextlib.contextmanager
    def _anchor_session(self, exclusive: bool):
        """Provide a freshly-replayed anchor log under the cross-process lock.

        The lock is always taken exclusively while the log is re-read:
        recovering a torn (never-acknowledged) tail truncates the file,
        which must be serialized against other processes' readers and
        writers. For a write call the lock stays held through the whole
        prepare->db-commit->anchor-commit sequence; for a read call it
        is released as soon as the authenticated in-memory view has been
        built, since that view is immutable for the duration of the
        read. Yields ``None`` when no anchor is configured.
        """
        if self._anchor_path is None:
            yield None
            return
        with self._anchor_lock:
            lock_fd = self._anchor_lock_fd
            locked = False
            if lock_fd is not None and fcntl is not None:
                fcntl.flock(lock_fd, fcntl.LOCK_EX)
                locked = True
            try:
                # Re-read under the lock and repair any torn tail (bytes
                # past the last newline never formed a durable record).
                anchor = self._fresh_anchor(repair_torn=True)
                if (
                    not exclusive
                    and locked
                    and lock_fd is not None
                    and fcntl is not None
                ):
                    # The authenticated view is now fixed in memory.
                    # Other readers may proceed; writers still block
                    # (they need an exclusive lock for prepare->commit),
                    # so the sidecar snapshot cannot race a database
                    # commit they observe.
                    fcntl.flock(lock_fd, fcntl.LOCK_SH)
                yield anchor
            finally:
                if locked and lock_fd is not None and fcntl is not None:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)

    # ----- submit -----------------------------------------------------

    def submit(
        self,
        tenant_id: str,
        subject_id: str,
        scopes: object,
        idempotency_key: str,
    ) -> dict[str, str]:
        # Validate everything before touching the database or sidecar so
        # rejected input can never create a record.
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
            # The exclusive anchor session takes the cross-process
            # flock and re-reads the sidecar, so the global prepare
            # counter is contiguous and current even with other writers.
            with self._anchor_session(exclusive=True) as anchor:
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
                        try:
                            conn.execute(
                                "INSERT INTO requests ("
                                "request_id, tenant_id, idempotency_key, subject_id, "
                                "scopes_json, status, created_at, chain_hash, anchor_seq"
                                ") VALUES (?, ?, ?, ?, ?, 'accepted', ?, ?, NULL)",
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
                            # No anchor prepare has happened for this
                            # attempt, so idempotent reuse / PK retry
                            # leave the sidecar untouched.
                            try:
                                return self._load_idempotent(
                                    conn,
                                    tenant_id,
                                    idempotency_key,
                                    subject_id,
                                    scope_list,
                                )
                            except _PrimaryKeyConflict:
                                # Collision was on request_id; retry UUID.
                                continue
                        try:
                            # Genesis event shares the acceptance
                            # transaction: no request without its event.
                            conn.execute(
                                "INSERT INTO status_events ("
                                "tenant_id, request_id, seq, status, occurred_at, "
                                "chain_hash) VALUES (?, ?, 0, 'accepted', ?, ?)",
                                (
                                    tenant_id,
                                    request_id,
                                    created_at,
                                    genesis_hash,
                                ),
                            )
                        except sqlite3.Error:
                            conn.execute("ROLLBACK")
                            raise RuntimeError(
                                "failed to persist accepted request"
                            ) from None

                        # Anchor prepare happens only after the row/event
                        # inserts are known to succeed, so a rejected
                        # call never reaches the sidecar. A durable P
                        # left by a later crash is an interrupted commit,
                        # never a reported success.
                        anchor_counter: int | None = None
                        prepare_tag: bytes | None = None
                        if anchor is not None:
                            try:
                                anchor_counter = anchor.next_counter()
                                prepare_tag = anchor.prepare(
                                    anchor_counter,
                                    tenant_id,
                                    request_id,
                                    0,
                                    genesis_hash,
                                )
                                conn.execute(
                                    "UPDATE requests SET anchor_seq = ? "
                                    "WHERE request_id = ?",
                                    (anchor_counter, request_id),
                                )
                            except (sqlite3.Error, OSError, RuntimeError):
                                self._abort_transaction(conn)
                                raise RuntimeError(
                                    "failed to persist accepted request"
                                ) from None

                        self._commit_and_anchor(
                            conn, anchor, anchor_counter, prepare_tag
                        )
                    except RuntimeError:
                        self._abort_transaction(conn)
                        raise
                    return {
                        "request_id": request_id,
                        "status": "accepted",
                        "created_at": created_at,
                    }
        finally:
            self._release(conn)
        raise RuntimeError("unable to allocate a unique request id")

    def _commit_and_anchor(
        self,
        conn: sqlite3.Connection,
        anchor: _AnchorLog | None,
        counter: int | None,
        prepare_tag: bytes | None,
    ) -> None:
        """Commit the DB durably, then publish the anchor commit marker.

        Called inside the staged write transaction while the caller
        holds the anchor session's exclusive lock. Any failure raises
        :class:`RuntimeError`; the transaction is rolled back by the
        caller where possible, and success is never returned.
        """
        try:
            conn.execute("COMMIT")
        except sqlite3.Error:
            raise RuntimeError("failed to persist state") from None
        if anchor is None:
            return
        # Pin the exact database contents the anchor names before
        # publishing C. If this fails the P stays uncommitted, which on
        # reopen reads as an interrupted commit.
        self._fsync_database(conn)
        try:
            anchor.commit(counter, prepare_tag)  # type: ignore[arg-type]
        except (OSError, RuntimeError):
            # The database commit already happened, but the external
            # commit marker was not published: this is an interrupted
            # commit, never a success.
            raise RuntimeError("failed to persist state") from None

    @staticmethod
    def _abort_transaction(conn: sqlite3.Connection) -> None:
        try:
            if conn.in_transaction:
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
        row = conn.execute(
            "SELECT request_id, status, created_at, subject_id, scopes_json "
            "FROM requests WHERE tenant_id = ? AND idempotency_key = ?",
            (tenant_id, idempotency_key),
        ).fetchone()
        if row is None:
            # The conflict came from the primary key rather than the
            # idempotency index; signal a fresh-UUID retry.
            raise _PrimaryKeyConflict
        (
            existing_request_id,
            status,
            created_at,
            existing_subject,
            existing_scopes_json,
        ) = row
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

    # ----- get --------------------------------------------------------

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
            # the response must not reveal that another tenant owns a
            # record.
            raise RequestNotFound("request not found")
        return {
            "request_id": row[0],
            "status": row[1],
            "created_at": row[2],
        }

    # ----- transition -------------------------------------------------

    def transition(
        self,
        tenant_id: str,
        request_id: str,
        target_status: str,
    ) -> dict[str, str]:
        """Move a request to ``target_status`` according to the lifecycle.

        Moving a request to the status it already holds is idempotent and
        returns the current receipt. Unknown statuses and illegal moves
        raise :class:`InvalidStatusTransition` without writing; unknown
        or cross-tenant ids raise :class:`RequestNotFound`. Only an
        actual migration is anchored.
        """
        # Validate before touching the database, mirroring submit().
        tenant_id = _require_nonempty_str(tenant_id, "tenant_id")
        request_id = _require_nonempty_str(request_id, "request_id")
        target_status = _require_nonempty_str(target_status, "target_status")
        if target_status not in _ALLOWED_TRANSITIONS:
            raise InvalidStatusTransition("unknown target status")

        with self._write_lock:
            conn = self._connect()
            try:
                with self._anchor_session(exclusive=True) as anchor:
                    receipt = self._transition_once(
                        conn,
                        anchor,
                        tenant_id,
                        request_id,
                        target_status,
                    )
            finally:
                self._release(conn)
        _log.info(
            "status transition persisted request_id=%s status=%s",
            request_id,
            target_status,
        )
        return receipt

    def _transition_once(
        self,
        conn: sqlite3.Connection,
        anchor: _AnchorLog | None,
        tenant_id: str,
        request_id: str,
        target_status: str,
    ) -> dict[str, str]:
        """Stage and commit exactly one transition under held locks.

        Idempotent replays, illegal moves and missing records perform no
        write (SQLite transaction rolled back, anchor untouched).
        Returns the current receipt.
        """
        try:
            conn.execute("BEGIN IMMEDIATE")
        except sqlite3.Error:
            raise RuntimeError("failed to persist status transition") from None
        try:
            row = conn.execute(
                "SELECT status, created_at FROM requests "
                "WHERE tenant_id = ? AND request_id = ?",
                (tenant_id, request_id),
            ).fetchone()
            if row is None:
                conn.execute("ROLLBACK")
                raise RequestNotFound("request not found")
            current_status, created_at = row
            if current_status == target_status:
                # Idempotent replay: nothing to persist, so no event and
                # no anchor change.
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
            # Read the predecessor link before writing so the new link
            # binds the exact persisted predecessor.
            latest = conn.execute(
                "SELECT seq, occurred_at, chain_hash FROM status_events "
                "WHERE tenant_id = ? AND request_id = ? "
                "ORDER BY seq DESC LIMIT 1",
                (tenant_id, request_id),
            ).fetchone()
            if latest is None or not _is_chain_hash(latest[2]):
                # Defensive only: every accepted request owns its seq-0
                # event. Never fabricate a replacement link.
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

            anchor_counter: int | None = None
            prepare_tag: bytes | None = None
            if anchor is not None:
                try:
                    anchor_counter = anchor.next_counter()
                    prepare_tag = anchor.prepare(
                        anchor_counter,
                        tenant_id,
                        request_id,
                        next_seq + 1,
                        next_link_hash,
                    )
                except (OSError, RuntimeError):
                    conn.execute("ROLLBACK")
                    raise RuntimeError(
                        "failed to persist status transition"
                    ) from None

            try:
                cursor = conn.execute(
                    "UPDATE requests SET status = ?, chain_hash = ?, "
                    "anchor_seq = ? "
                    "WHERE tenant_id = ? AND request_id = ? AND status = ?",
                    (
                        target_status,
                        next_link_hash,
                        anchor_counter,
                        tenant_id,
                        request_id,
                        current_status,
                    ),
                )
                if cursor.rowcount != 1:
                    # The row vanished or changed under us; refuse rather
                    # than persisting a broken graph state.
                    conn.execute("ROLLBACK")
                    raise InvalidStatusTransition("illegal status transition")
                conn.execute(
                    "INSERT INTO status_events ("
                    "tenant_id, request_id, seq, status, occurred_at, "
                    "chain_hash) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        tenant_id,
                        request_id,
                        next_seq + 1,
                        target_status,
                        occurred_at,
                        next_link_hash,
                    ),
                )
                self._commit_and_anchor(
                    conn, anchor, anchor_counter, prepare_tag
                )
            except InvalidStatusTransition:
                self._abort_transaction(conn)
                raise
            except sqlite3.Error:
                self._abort_transaction(conn)
                raise RuntimeError(
                    "failed to persist status transition"
                ) from None
        except InvalidStatusTransition:
            raise
        except RequestNotFound:
            raise
        except RuntimeError:
            self._abort_transaction(conn)
            raise
        return {
            "request_id": request_id,
            "status": target_status,
            "created_at": created_at,
        }

    # ----- audit ------------------------------------------------------

    def audit(
        self,
        tenant_id: str,
        request_id: str,
    ) -> list[dict[str, str]]:
        """Return the request's status timeline in occurrence order.

        Each entry contains only ``status`` and ``occurred_at`` (a UTC
        RFC3339 string). The final entry's status always equals the
        result of :meth:`get`. Unknown ids and cross-tenant lookups raise
        :class:`RequestNotFound` identically, so the call cannot reveal
        another tenant's records.
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
            # Resolve ownership first: filtering the event query by
            # tenant alone would still distinguish "missing" from
            # "foreign record" via an empty timeline.
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

    # ----- evidence ---------------------------------------------------

    def evidence(
        self,
        tenant_id: str,
        request_id: str,
    ) -> dict[str, object]:
        """Return the persisted integrity evidence for a request.

        The result contains exactly ``request_id``, ``status`` (identical
        to :meth:`get`), ``event_count`` (identical to the length of
        :meth:`audit`) and ``chain_hash`` (the SHA-256 head of the audit
        chain as persisted, never recomputed). It never contains the
        integrity key, key-derived material, anchor counters or chain
        preimages. Unknown ids and cross-tenant lookups raise
        :class:`RequestNotFound`; non-string or empty arguments raise
        :class:`ValueError`.
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
        # The stored head must be a well-formed digest; a malformed
        # value means the row was altered out of band and must not be
        # reported as evidence.
        if not _is_chain_hash(head_hash):
            raise RequestNotFound("request not found")
        return {
            "request_id": request_id,
            "status": status,
            "event_count": event_count,
            "chain_hash": head_hash,
        }

    # ----- verification ----------------------------------------------

    def verify_evidence(self, tenant_id: str, request_id: str) -> bool:
        """Verify the persisted, externally anchored audit evidence.

        Trusted verification requires the store to have been opened with
        ``anchor_path`` and the caller's ``integrity_key``. Every chain
        link is recomputed from the genesis predecessor and compared in
        constant time, sequences must be gap-free from zero, the final
        link must equal the request's anchored head and current status,
        and a committed, HMAC-valid sidecar record keyed by the caller's
        secret must name exactly that tenant, request, event index and
        head.

        Returns ``False`` (never raises for tampering) when the sidecar
        is absent, corrupt, carries an invalid record, lacks an anchor
        for the request, disagrees with the database, the database is a
        pre-anchor file, or a prepare has no commit (interrupted
        commit). Unknown ids / cross-tenant lookups raise
        :class:`RequestNotFound`; non-string or empty arguments raise
        :class:`ValueError`.
        """
        tenant_id = _require_nonempty_str(tenant_id, "tenant_id")
        request_id = _require_nonempty_str(request_id, "request_id")
        if self._mem_conn is not None:
            with self._write_lock:
                return self._verify_evidence(tenant_id, request_id)
        return self._verify_evidence(tenant_id, request_id)

    def _read_chain(
        self, conn: sqlite3.Connection, tenant_id: str, request_id: str
    ) -> tuple[str, str, int | None, list] | None:
        """Load request head + event rows; ``None`` when not visible."""
        owner = conn.execute(
            "SELECT status, chain_hash, anchor_seq FROM requests "
            "WHERE tenant_id = ? AND request_id = ?",
            (tenant_id, request_id),
        ).fetchone()
        if owner is None:
            return None  # type: ignore[return-value]
        current_status, anchored_head, anchor_seq = owner
        rows = conn.execute(
            "SELECT seq, status, occurred_at, chain_hash FROM status_events "
            "WHERE tenant_id = ? AND request_id = ? ORDER BY seq",
            (tenant_id, request_id),
        ).fetchall()
        return current_status, anchored_head, anchor_seq, rows

    @staticmethod
    def _chain_is_valid(
        tenant_id: str,
        request_id: str,
        rows: list[tuple[int, str, str, str]],
        anchored_head: str,
        current_status: str,
    ) -> bool:
        predecessor = _GENESIS_PREDECESSOR
        for expected_seq, row in enumerate(rows):
            seq, status, occurred_at, stored_hash = row
            # Gap-free sequences from zero; strict types keep tampered
            # NULL/renumbered rows out of the preimage as anything but a
            # failure.
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
                tenant_id, request_id, seq, status, occurred_at, predecessor
            )
            if not hmac.compare_digest(recomputed, stored_hash):
                return False
            predecessor = stored_hash
        if not rows:
            return False
        if not hmac.compare_digest(predecessor, anchored_head):
            return False
        return rows[-1][1] == current_status

    def _verify_evidence(self, tenant_id: str, request_id: str) -> bool:
        # Resolve ownership and load the chain before deciding trust, so
        # missing ids and cross-tenant lookups keep raising
        # RequestNotFound regardless of whether trusted anchoring is
        # configured.
        conn = self._connect()
        try:
            try:
                loaded = self._read_chain(conn, tenant_id, request_id)
            except sqlite3.Error:
                # Never surface the database engine's own error text.
                raise RuntimeError("failed to verify request evidence") from None
        finally:
            self._release(conn)
        if loaded is None:
            raise RequestNotFound("request not found")
        current_status, anchored_head, anchor_seq, rows = loaded

        # Trusted anchoring is mandatory. A store opened without the
        # external, keyed anchor cannot verify.
        if self._anchor_path is None:
            return False

        with self._anchor_session(exclusive=False) as anchor:
            # A corrupt log, or any interrupted commit, fails all
            # verification rather than being papered over.
            if anchor.has_invalid_records or anchor.is_incomplete:
                return False

            if not _is_chain_hash(anchored_head) or not isinstance(
                anchor_seq, int
            ):
                return False
            if not self._chain_is_valid(
                tenant_id, request_id, rows, anchored_head, current_status
            ):
                return False

            external = anchor.latest_committed_anchor(tenant_id, request_id)
            if external is None:
                # Missing sidecar / no committed anchor for this request.
                return False
            counter, event_index, sidecar_head = external
            if counter != anchor_seq:
                return False
            if event_index != len(rows) - 1:
                return False
            if not hmac.compare_digest(sidecar_head, anchored_head):
                return False
            return True

    # ----- recovery ---------------------------------------------------

    def recover(self) -> str:
        """Read-only aggregate evidence state: valid/invalid/incomplete.

        * ``"valid"``: the sidecar has no invalid or uncommitted
          records, every request chain internally verifies and each
          request's current head is named by its committed keyed anchor;
        * ``"incomplete"``: no forgery is present but coverage is not
          finished — an interrupted prepare/commit, a pre-anchor legacy
          row, or a fresh database with no anchor log yet;
        * ``"invalid"``: the sidecar contains malformed or
          unauthenticatable content, an anchor names a head/event the
          database does not hold, a request chain is broken, or a
          database claims an anchor the sidecar cannot prove.

        This method never repairs, backfills or writes anything.
        """
        if self._mem_conn is not None:
            with self._write_lock:
                return self._recover_state()
        return self._recover_state()

    def _recover_state(self) -> str:
        with self._anchor_session(exclusive=False) as anchor:
            if anchor is not None and anchor.has_invalid_records:
                return "invalid"
            # An interrupted prepare/commit is always incomplete, even
            # when the database has not (or not yet) committed the
            # matching row; it must never be misclassified.
            if anchor is not None and anchor.is_incomplete:
                return "incomplete"

            conn = self._connect()
            try:
                try:
                    request_rows = conn.execute(
                        "SELECT tenant_id, request_id, status, chain_hash, anchor_seq "
                        "FROM requests"
                    ).fetchall()
                    event_rows = conn.execute(
                        "SELECT tenant_id, request_id, seq, status, occurred_at, "
                        "chain_hash FROM status_events "
                        "ORDER BY tenant_id, request_id, seq"
                    ).fetchall()
                except sqlite3.Error:
                    return "incomplete"
            finally:
                self._release(conn)

            # Group events per request without trusting row order.
            events: dict[tuple[str, str], list] = {}
            for (
                tenant_id,
                request_id,
                seq,
                status,
                occurred_at,
                stored_hash,
            ) in event_rows:
                events.setdefault((tenant_id, request_id), []).append(
                    (seq, status, occurred_at, stored_hash)
                )

            legacy_rows = False
            for tenant_id, request_id, status, head, anchor_seq in request_rows:
                chain = events.get((tenant_id, request_id), [])
                if not _is_chain_hash(head) or not self._chain_is_valid(
                    tenant_id, request_id, chain, head, status
                ):
                    return "invalid"
                if anchor is None or anchor_seq is None:
                    # Unanchored store, or pre-anchor data: structurally
                    # fine but not trusted.
                    legacy_rows = True
                    continue
                external = anchor.latest_committed_anchor(tenant_id, request_id)
                if external is None:
                    # The database claims an anchor the sidecar cannot
                    # prove (missing / replaced sidecar): invalid, not
                    # merely old.
                    return "invalid"
                counter, event_index, sidecar_head = external
                if counter != anchor_seq:
                    return "invalid"
                if event_index != len(chain) - 1:
                    return "invalid"
                if not hmac.compare_digest(sidecar_head, head):
                    return "invalid"

            if anchor is None:
                # No external anchor configured: any data is legacy.
                return "incomplete" if request_rows else "valid"

            # Every committed anchor must correspond to an existing event
            # carrying exactly that head; a dangling anchor means a
            # request or event was deleted out of band.
            head_by_key_seq: dict[tuple[str, str, int], str] = {}
            for (tenant_id, request_id), chain in events.items():
                for seq, _status, _occurred_at, stored_hash in chain:
                    head_by_key_seq[(tenant_id, request_id, seq)] = stored_hash
            for counter in anchor.committed_counters:
                info = anchor.committed_anchor(counter)
                if info is None:
                    return "invalid"
                key = (str(info["tenant"]), str(info["request"]), int(info["c"]))
                if head_by_key_seq.get(key) != info["h"]:
                    return "invalid"

            if legacy_rows:
                return "incomplete"
            return "valid"

    # ----- internals --------------------------------------------------

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
