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

Protected anchoring
-------------------

The SHA-256 chain and its request-side head both live inside the same
SQLite database, so an attacker who can rewrite that file could simply
recompute every hash. Integrity therefore additionally depends on
protected material that is *not* stored in SQLite and that can be
reprovisioned on rebuilt instances:

* ``anchor_mac`` columns on both ``status_events`` and ``requests`` hold
  HMAC-SHA-256 tags derived from a key the database never contains; an
  attacker rewriting rows cannot recompute valid tags.
* An external, append-only anchor journal (a separate sidecar file, by
  default next to the database) records, for every genesis and every
  actual transition, an entry binding the tenant, request, per-request
  sequence, final chain head and the event/head MACs. Consecutive
  journal entries are chained under a third derived key, so the journal
  cannot be reordered or partially rewritten either.

The master key is generated on first use and kept outside SQLite in a
``0600`` key file (default: ``<database>.key``), or supplied explicitly
via the :class:`RequestStore` ``anchor_key`` / ``anchor_key_file``
options. A rebuilt instance pointed at the same database and key
material verifies previously written requests. Neither the master key,
the derived keys nor any forgeable anchor state is ever written into
SQLite, receipts, exceptions or logs.

Databases created before protected anchoring are upgraded additively
(the anchor columns are added but left ``NULL``) and are *never* silently
trusted: unanchored records fail :meth:`verify_evidence`. The upgrade
never overwrites or backfills audit records.
"""

from __future__ import annotations

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

try:  # POSIX only; used to serialize cross-process journal appends.
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


class IdempotencyConflict(Exception):
    """Raised when an idempotency key is reused with a different payload."""


class RequestNotFound(Exception):
    """Raised when no request visible to the tenant matches the id."""


class InvalidStatusTransition(Exception):
    """Raised when a requested status change is unknown or not permitted."""


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
    chain_hash      TEXT NOT NULL,
    anchor_mac      TEXT
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
    anchor_mac  TEXT,
    PRIMARY KEY (tenant_id, request_id, seq)
);
"""

# The composite primary key already indexes (tenant_id, request_id, seq),
# which serves both the ordered timeline read and the latest-event lookup.

# Column probes used to upgrade database files written by older versions.
# The upgrade is purely additive: columns are added but never populated,
# because a value derived purely from data already inside the database
# would add no trust. Unanchored legacy rows fail verification.
_REQUEST_CHAIN_COLUMN = (
    "SELECT 1 FROM pragma_table_info('requests') WHERE name = 'chain_hash'"
)
_EVENT_CHAIN_COLUMN = (
    "SELECT 1 FROM pragma_table_info('status_events') WHERE name = 'chain_hash'"
)
_REQUEST_ANCHOR_COLUMN = (
    "SELECT 1 FROM pragma_table_info('requests') WHERE name = 'anchor_mac'"
)
_EVENT_ANCHOR_COLUMN = (
    "SELECT 1 FROM pragma_table_info('status_events') WHERE name = 'anchor_mac'"
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

# --- Protected anchoring constants -----------------------------------------

_KEY_FILE_MODE = 0o600
_JOURNAL_FILE_MODE = 0o600
_KEY_BYTES = 32
# Domain-separation labels for the three derived keys; they never appear
# outside this process.
_DK_EVENT = b"fe-anchor-event-v1"
_DK_HEAD = b"fe-anchor-head-v1"
_DK_JOURNAL = b"fe-anchor-journal-v1"
# Fixed first predecessor of the external append-only journal.
_JOURNAL_GENESIS = (
    "0000000000000000000000000000000000000000000000000000000000000000"
)
_JOURNAL_RECORD_VERSION = "feaj-v1"


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


def _is_hex64(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in _HEX for char in value)
    )


# Backwards-compatible internal alias.
_is_chain_hash = _is_hex64


def _length_prefixed(*fields: str) -> bytes:
    out = bytearray()
    for field in fields:
        encoded = field.encode("utf-8")
        out += struct.pack(">Q", len(encoded))
        out += encoded
    return bytes(out)


def _derive_key(master_key: bytes, label: bytes) -> bytes:
    return hashlib.sha256(label + b"\x00" + master_key).digest()


def _hmac_hex(key: bytes, message: bytes) -> str:
    return hmac.new(key, message, hashlib.sha256).hexdigest()


class _AnchorMaterial:
    """Protected keying material that never enters the SQLite database.

    Three domain-separated HMAC keys are derived from a master key that
    lives in an external ``0600`` file (or is supplied by the caller).
    The master key and its derivatives are held only in memory; they are
    never logged, returned in receipts, or persisted alongside the data
    they authenticate.
    """

    def __init__(self, master_key: bytes) -> None:
        self._event_key = _derive_key(master_key, _DK_EVENT)
        self._head_key = _derive_key(master_key, _DK_HEAD)
        self._journal_key = _derive_key(master_key, _DK_JOURNAL)

    def event_mac(
        self,
        tenant_id: str,
        request_id: str,
        seq: int,
        status: str,
        occurred_at: str,
        predecessor: str,
        chain_hash: str,
    ) -> str:
        message = _length_prefixed(
            tenant_id,
            request_id,
            str(seq),
            status,
            occurred_at,
            predecessor,
            chain_hash,
        )
        return _hmac_hex(self._event_key, message)

    def head_mac(
        self,
        tenant_id: str,
        request_id: str,
        status: str,
        event_count: int,
        head_hash: str,
    ) -> str:
        message = _length_prefixed(
            tenant_id, request_id, status, str(event_count), head_hash
        )
        return _hmac_hex(self._head_key, message)

    def journal_mac(
        self,
        predecessor: str,
        tenant_id: str,
        request_id: str,
        seq: int,
        status: str,
        occurred_at: str,
        head_hash: str,
        event_mac: str,
        head_mac: str,
    ) -> str:
        message = _length_prefixed(
            predecessor,
            _JOURNAL_RECORD_VERSION,
            tenant_id,
            request_id,
            str(seq),
            status,
            occurred_at,
            head_hash,
            event_mac,
            head_mac,
        )
        return _hmac_hex(self._journal_key, message)


class _AnchorJournal:
    """External append-only journal protected by the anchor key.

    The journal is a separate file from the SQLite database. Each line is
    one JSON record plus an HMAC that chains over the previous record's
    HMAC (a fixed genesis sentinel for the first record), so entries
    cannot be inserted, deleted, reordered or altered without the key.
    Appends take a cross-process file lock, re-read the authenticated
    tail and ``fsync`` before the corresponding SQLite transaction is
    allowed to commit. The journal never contains key material.

    A journal may also be in-memory only (``path is None``), which still
    binds every write for the lifetime of a single process -- used by
    ``:memory:`` databases where no cross-instance file exists.
    """

    def __init__(self, path: str | None, material: _AnchorMaterial) -> None:
        self._path = path
        self._material = material
        self._lock = threading.Lock()
        self._last_mac: str | None = None
        self._memory_lines: list[bytes] = []
        # A present-but-unauthenticatable journal is fail-closed: it is
        # never truncated or "repaired", appends are refused, and
        # verification reports False.
        self._broken = False

    # -- parsing -------------------------------------------------------

    @staticmethod
    def _parse_line(line: bytes) -> dict[str, object] | None:
        try:
            record = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return None
        return record if isinstance(record, dict) else None

    def _record_fields(
        self, record: dict[str, object]
    ) -> tuple[str, str, int, str, str, str, str, str] | None:
        seq = record.get("seq")
        if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
            return None
        fields = [
            record.get("tenant_id"),
            record.get("request_id"),
            record.get("status"),
            record.get("occurred_at"),
            record.get("head"),
            record.get("event_mac"),
            record.get("head_mac"),
        ]
        if not all(isinstance(value, str) for value in fields):
            return None
        tenant_id, request_id, status, occurred_at, head, event_mac, head_mac = fields
        return (
            tenant_id,
            request_id,
            seq,
            status,
            occurred_at,
            head,
            event_mac,
            head_mac,
        )

    def _mac_for(
        self,
        predecessor: str,
        fields: tuple[str, str, int, str, str, str, str, str],
    ) -> str:
        tenant_id, request_id, seq, status, occurred_at, head, event_mac, head_mac = (
            fields
        )
        return self._material.journal_mac(
            predecessor,
            tenant_id,
            request_id,
            seq,
            status,
            occurred_at,
            head,
            event_mac,
            head_mac,
        )

    def _read_all(self) -> bytes:
        if self._path is None:
            return b"\n".join(self._memory_lines) + (
                b"\n" if self._memory_lines else b""
            )
        with open(self._path, "rb") as handle:
            return handle.read()

    def _validate_bytes(
        self, raw: bytes
    ) -> tuple[list[tuple[str, str, int, str, str, str, str, str]], str] | None:
        """Validate every record end to end; return (fields, final_mac)."""
        predecessor = _JOURNAL_GENESIS
        entries: list[tuple[str, str, int, str, str, str, str, str]] = []
        saw_any = False
        for line in raw.splitlines():
            if not line:
                return None
            record = self._parse_line(line)
            if record is None:
                return None
            fields = self._record_fields(record)
            if fields is None:
                return None
            stored_mac = record.get("mac")
            if not _is_hex64(stored_mac):
                return None
            expected = self._mac_for(predecessor, fields)
            if not hmac.compare_digest(expected, stored_mac):
                return None
            predecessor = stored_mac
            entries.append(fields)
            saw_any = True
        if not saw_any:
            return None
        return entries, predecessor

    # -- lifecycle -----------------------------------------------------

    def load(self) -> None:
        """Validate any existing journal and remember the final MAC.

        A missing file-backed journal is treated as empty; a present but
        unauthenticating journal marks the journal fail-closed rather than
        raising, so opening a database never itself crashes callers --
        verification then reports ``False`` and writes are refused.
        Never logs record contents.
        """
        with self._lock:
            if self._path is not None:
                try:
                    raw = self._read_all_locked()
                except FileNotFoundError:
                    # Nothing anchored yet: an empty journal is normal.
                    self._broken = False
                    self._last_mac = None
                    return
                except OSError:
                    self._broken = True
                    self._last_mac = None
                    return
            else:
                raw = self._read_all()
            if not raw:
                self._last_mac = None
                return
            validated = self._validate_bytes(raw)
            if validated is None:
                self._broken = True
                self._last_mac = None
                return
            self._last_mac = validated[1]

    @property
    def broken(self) -> bool:
        return self._broken

    def append(
        self,
        tenant_id: str,
        request_id: str,
        seq: int,
        status: str,
        occurred_at: str,
        head_hash: str,
        event_tag: str,
        head_tag: str,
    ) -> str:
        """Append and persist one record; return its MAC."""
        fields = (
            tenant_id,
            request_id,
            seq,
            status,
            occurred_at,
            head_hash,
            event_tag,
            head_tag,
        )
        line_out: bytes | None = None
        mac = ""
        with self._lock:
            if self._broken:
                # Fail closed: never append onto a journal whose existing
                # contents cannot be authenticated.
                raise ValueError("anchor journal is corrupted")
            if self._path is None:
                predecessor = (
                    self._last_mac
                    if self._last_mac is not None
                    else _JOURNAL_GENESIS
                )
                mac = self._mac_for(predecessor, fields)
                record = self._record_dict(fields, mac)
                line_out = (
                    json.dumps(
                        record, ensure_ascii=False, separators=(",", ":")
                    ).encode("utf-8")
                    + b"\n"
                )
                self._memory_lines.append(line_out[:-1])
                self._last_mac = mac
                return mac

            # Cross-process serialization plus tail re-read so two
            # processes sharing the journal never fork the MAC chain.
            lock_fd = os.open(self._path, os.O_RDWR | os.O_CREAT, _JOURNAL_FILE_MODE)
            try:
                if fcntl is not None:
                    fcntl.flock(lock_fd, fcntl.LOCK_EX)
                try:
                    os.lseek(lock_fd, 0, os.SEEK_SET)
                    raw = b""
                    while True:
                        chunk = os.read(lock_fd, 1 << 20)
                        if not chunk:
                            break
                        raw += chunk
                    predecessor = _JOURNAL_GENESIS
                    if raw.strip():
                        validated = self._validate_bytes(raw)
                        if validated is None:
                            self._broken = True
                            raise ValueError("anchor journal is corrupted")
                        predecessor = validated[1]
                    mac = self._mac_for(predecessor, fields)
                    record = self._record_dict(fields, mac)
                    line_out = (
                        json.dumps(
                            record, ensure_ascii=False, separators=(",", ":")
                        ).encode("utf-8")
                        + b"\n"
                    )
                    os.lseek(lock_fd, 0, os.SEEK_END)
                    os.write(lock_fd, line_out)
                    os.fsync(lock_fd)
                finally:
                    if fcntl is not None:
                        fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)
            try:
                os.chmod(self._path, _JOURNAL_FILE_MODE)
            except OSError:
                pass
            self._last_mac = mac
            return mac

    @staticmethod
    def _record_dict(
        fields: tuple[str, str, int, str, str, str, str, str], mac: str
    ) -> dict[str, object]:
        tenant_id, request_id, seq, status, occurred_at, head, event_mac, head_mac = (
            fields
        )
        return {
            "v": _JOURNAL_RECORD_VERSION,
            "tenant_id": tenant_id,
            "request_id": request_id,
            "seq": seq,
            "status": status,
            "occurred_at": occurred_at,
            "head": head,
            "event_mac": event_mac,
            "head_mac": head_mac,
            "mac": mac,
        }

    def _read_all_locked(self) -> bytes:
        """Read the journal under a shared flock so a concurrent append
        can never expose a partially written final line."""
        if self._path is None:
            return self._read_all()
        fd = os.open(self._path, os.O_RDONLY)
        try:
            if fcntl is not None:
                fcntl.flock(fd, fcntl.LOCK_SH)
            try:
                raw = b""
                while True:
                    chunk = os.read(fd, 1 << 20)
                    if not chunk:
                        break
                    raw += chunk
            finally:
                if fcntl is not None:
                    fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)
        return raw

    def verify(
        self,
        expected: list[tuple[str, str, int, str, str, str, str, str]],
    ) -> bool:
        """Authenticate the whole journal and match one request's records.

        The journal must validate end to end and contain the ``expected``
        records consecutively and exactly (same tenant/request, sequence,
        status, timestamp, head and both MACs). Other tenants'/requests'
        records may surround them, but deletion, duplication, insertion or
        substitution within the matched run -- or anywhere in the file --
        fails.
        """
        if not expected:
            return False
        with self._lock:
            if self._broken:
                return False
            try:
                raw = self._read_all_locked()
            except OSError:
                return False
        validated = self._validate_bytes(raw)
        if validated is None:
            return False
        entries = validated[0]
        target = (expected[0][0], expected[0][1])
        # The authenticated stream filtered to this tenant/request must be
        # exactly the expected sequence, contiguous in seq from zero.
        own = [entry for entry in entries if (entry[0], entry[1]) == target]
        if len(own) != len(expected):
            return False
        for index, (got, want) in enumerate(zip(own, expected)):
            if got[2] != index or got != want:
                return False
        return True


def _load_or_create_master_key(
    key_file: str | None,
    explicit_key: bytes | None,
    explicit_key_file: str | None,
) -> bytes:
    """Resolve master key material from an explicit value or a key file.

    When an explicit raw key is given it is used verbatim and no key file
    is managed. Otherwise a ``0600`` file is read, or generated on first
    use. A ``None`` path (the ``:memory:`` case) yields an in-process key.
    Key material is never logged or written into SQLite.
    """
    if explicit_key is not None:
        if not isinstance(explicit_key, (bytes, bytearray)) or not explicit_key:
            raise ValueError("anchor key must be non-empty bytes")
        return bytes(explicit_key)
    path = explicit_key_file if explicit_key_file is not None else key_file
    if path is None:
        # In-memory database: protect the in-process journal with an
        # ephemeral key that never touches disk.
        return os.urandom(_KEY_BYTES)
    try:
        with open(path, "rb") as handle:
            data = handle.read()
    except FileNotFoundError:
        parent = os.path.dirname(os.path.abspath(path))
        os.makedirs(parent, exist_ok=True)
        generated = os.urandom(_KEY_BYTES)
        try:
            # O_EXCL refuses to follow or overwrite a pre-created path,
            # closing a symlink/TOCTOU race at creation.
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, _KEY_FILE_MODE)
        except FileExistsError:
            # Another process initialized the key first: use its copy.
            with open(path, "rb") as handle:
                data = handle.read()
        else:
            try:
                os.write(fd, generated)
                os.fsync(fd)
            finally:
                os.close(fd)
            try:
                os.chmod(path, _KEY_FILE_MODE)
            except OSError:
                pass
            return generated
    if not data:
        raise ValueError("anchor key file is empty")
    return data


class RequestStore:
    """Persist and retrieve accepted deletion requests.

    Protected anchoring is configured with optional keyword arguments;
    the default ``RequestStore(db_path)`` call keeps working and gains a
    key file and anchor journal next to the database automatically:

    * ``anchor_key``: raw master key bytes (managed externally; nothing
      is written to disk by the store).
    * ``anchor_key_file``: override the path of the ``0600`` master-key
      file (default: ``<db_path>.key`` for file-backed databases).
    * ``anchor_journal_file``: override the path of the append-only
      anchor journal (default: ``<db_path>.anchorlog``).
    """

    def __init__(
        self,
        db_path: str | os.PathLike[str],
        *,
        anchor_key: bytes | None = None,
        anchor_key_file: str | os.PathLike[str] | None = None,
        anchor_journal_file: str | os.PathLike[str] | None = None,
    ):
        self._db_path = os.fspath(db_path)
        # In-process serialization; the unique index additionally guards
        # other processes sharing the same database file.
        self._write_lock = threading.Lock()
        if self._db_path == ":memory:":
            self._mem_conn: sqlite3.Connection | None = self._open_connection()
            default_key_file = None
            default_journal = None
        else:
            self._mem_conn = None
            db_abs = os.path.abspath(self._db_path)
            parent = os.path.dirname(db_abs)
            os.makedirs(parent, exist_ok=True)
            default_key_file = db_abs + ".key"
            default_journal = db_abs + ".anchorlog"

        key_file_arg = (
            os.fspath(anchor_key_file) if anchor_key_file is not None else None
        )
        journal_arg = (
            os.fspath(anchor_journal_file)
            if anchor_journal_file is not None
            else None
        )
        master_key = _load_or_create_master_key(
            default_key_file, anchor_key, key_file_arg
        )
        self._anchor = _AnchorMaterial(master_key)
        if self._db_path == ":memory:" and journal_arg is None:
            # No cross-instance file exists for an in-memory database;
            # anchor in process memory so writes and verification stay
            # consistent within the store's lifetime.
            self._journal: _AnchorJournal | None = _AnchorJournal(
                None, self._anchor
            )
        else:
            journal_path = (
                journal_arg if journal_arg is not None else default_journal
            )
            if journal_path is not None:
                journal_parent = os.path.dirname(os.path.abspath(journal_path))
                os.makedirs(journal_parent, exist_ok=True)
            self._journal = (
                _AnchorJournal(journal_path, self._anchor)
                if journal_path is not None
                else None
            )
        if self._journal is not None:
            # Existing journal must authenticate end to end before the
            # store will append anything else.
            self._journal.load()

        conn = self._connect()
        try:
            conn.execute(_SCHEMA)
            conn.execute(_UNIQUE_TENANT_KEY)
            conn.execute(_EVENT_TABLE)
            self._migrate_schema(conn)
        finally:
            self._release(conn)

    def _migrate_schema(self, conn: sqlite3.Connection) -> None:
        """Add integrity columns to a database written by an older version.

        The upgrade is additive and never fabricates protected trust:

        * The keyless ``chain_hash`` columns, when missing, are added and
          populated by recomputing the keyless chain from the already
          persisted timeline. This preserves the pre-existing hash-chain
          view (and :meth:`evidence`) but, on its own, proves nothing
          against a writer who controls the database.
        * The keyed ``anchor_mac`` columns are added if missing and
          *always left ``NULL``*. No key-held value could legitimately
          populate them for pre-anchoring data, so legacy audit records
          are never overwritten or silently treated as anchored. They
          fail :meth:`verify_evidence` until the end of time.
        """
        have_req_chain = bool(conn.execute(_REQUEST_CHAIN_COLUMN).fetchone())
        have_evt_chain = bool(conn.execute(_EVENT_CHAIN_COLUMN).fetchone())
        have_req_anchor = bool(conn.execute(_REQUEST_ANCHOR_COLUMN).fetchone())
        have_evt_anchor = bool(conn.execute(_EVENT_ANCHOR_COLUMN).fetchone())
        if have_req_chain and have_evt_chain and have_req_anchor and have_evt_anchor:
            return
        with self._write_lock:
            try:
                conn.execute("BEGIN IMMEDIATE")
                added_req_chain = False
                added_evt_chain = False
                if not conn.execute(_REQUEST_CHAIN_COLUMN).fetchone():
                    conn.execute("ALTER TABLE requests ADD COLUMN chain_hash TEXT")
                    added_req_chain = True
                if not conn.execute(_EVENT_CHAIN_COLUMN).fetchone():
                    conn.execute(
                        "ALTER TABLE status_events ADD COLUMN chain_hash TEXT"
                    )
                    added_evt_chain = True
                if not conn.execute(_REQUEST_ANCHOR_COLUMN).fetchone():
                    conn.execute("ALTER TABLE requests ADD COLUMN anchor_mac TEXT")
                if not conn.execute(_EVENT_ANCHOR_COLUMN).fetchone():
                    conn.execute(
                        "ALTER TABLE status_events ADD COLUMN anchor_mac TEXT"
                    )
                # Backfill only the keyless chain, and only when the
                # columns were just added; the keyed anchor columns are
                # deliberately never populated.
                if added_req_chain or added_evt_chain:
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
                            tenant_id, request_id, seq, status, occurred_at,
                            predecessor,
                        )
                        conn.execute(
                            "UPDATE status_events SET chain_hash = ? "
                            "WHERE tenant_id = ? AND request_id = ? AND seq = ?",
                            (link, tenant_id, request_id, seq),
                        )
                        predecessor = link
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

    def _compute_link_evidence(
        self,
        tenant_id: str,
        request_id: str,
        seq: int,
        status: str,
        occurred_at: str,
        predecessor: str,
        link_hash: str,
        event_count: int,
    ) -> tuple[str, str]:
        """Compute the keyed tags for one link (pure; no persistence).

        Returns ``(event_mac, head_mac)``. The tags bind the tenant,
        request, sequence, status, timestamp, predecessor, keyless chain
        head, and -- for the head tag -- the final status, event count
        and final head.
        """
        event_tag = self._anchor.event_mac(
            tenant_id,
            request_id,
            seq,
            status,
            occurred_at,
            predecessor,
            link_hash,
        )
        head_tag = self._anchor.head_mac(
            tenant_id, request_id, status, event_count, link_hash
        )
        return event_tag, head_tag

    def _journal_link(
        self,
        tenant_id: str,
        request_id: str,
        seq: int,
        status: str,
        occurred_at: str,
        link_hash: str,
        event_tag: str,
        head_tag: str,
    ) -> None:
        """Append one link's record to the protected journal."""
        if self._journal is not None:
            self._journal.append(
                tenant_id,
                request_id,
                seq,
                status,
                occurred_at,
                link_hash,
                event_tag,
                head_tag,
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
                        "scopes_json, status, created_at, chain_hash, anchor_mac"
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
                    try:
                        return self._load_idempotent(
                            conn, tenant_id, idempotency_key, subject_id, scope_list
                        )
                    except _PrimaryKeyConflict:
                        # Collision was on request_id; retry with a new UUID.
                        continue
                try:
                    # The first timeline entry shares the acceptance
                    # transaction. Stage the genesis event row (keyless
                    # link first), compute the protected tags, fsync the
                    # external journal, and only then commit: a committed
                    # request is atomically anchored with its row and
                    # event.
                    event_tag, head_tag = self._compute_link_evidence(
                        tenant_id,
                        request_id,
                        0,
                        _STATUS_ACCEPTED,
                        created_at,
                        _GENESIS_PREDECESSOR,
                        genesis_hash,
                        1,
                    )
                    conn.execute(
                        "INSERT INTO status_events ("
                        "tenant_id, request_id, seq, status, occurred_at, "
                        "chain_hash, anchor_mac"
                        ") VALUES (?, ?, 0, 'accepted', ?, ?, ?)",
                        (
                            tenant_id,
                            request_id,
                            created_at,
                            genesis_hash,
                            event_tag,
                        ),
                    )
                    conn.execute(
                        "UPDATE requests SET anchor_mac = ? "
                        "WHERE tenant_id = ? AND request_id = ?",
                        (head_tag, tenant_id, request_id),
                    )
                    self._journal_link(
                        tenant_id,
                        request_id,
                        0,
                        _STATUS_ACCEPTED,
                        created_at,
                        genesis_hash,
                        event_tag,
                        head_tag,
                    )
                except (sqlite3.Error, OSError, ValueError):
                    conn.execute("ROLLBACK")
                    raise RuntimeError("failed to persist accepted request") from None
                conn.execute("COMMIT")
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
                        # Idempotent replay: nothing to persist, and in
                        # particular no new anchor evidence is produced.
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
                        "SELECT seq, occurred_at, chain_hash, anchor_mac "
                        "FROM status_events "
                        "WHERE tenant_id = ? AND request_id = ? "
                        "ORDER BY seq DESC LIMIT 1",
                        (tenant_id, request_id),
                    ).fetchone()
                    if latest is None or not _is_chain_hash(latest[2]):
                        # Defensive: every accepted request owns its
                        # seq-0 event with a valid link; reaching here
                        # means the timeline invariant broke out of band.
                        conn.execute("ROLLBACK")
                        raise RuntimeError("failed to persist status transition")
                    predecessor_mac = latest[3]
                    if predecessor_mac is not None and not _is_hex64(
                        predecessor_mac
                    ):
                        # A present-but-malformed keyed tag is out-of-band
                        # corruption; never extend a forged chain. A NULL
                        # tag marks a legacy, never-anchored record: the
                        # state machine stays usable, but such a request
                        # can never verify because its genesis is unanchored.
                        conn.execute("ROLLBACK")
                        raise RuntimeError("failed to persist status transition")
                    next_seq, latest_occurred_at, predecessor_hash, _ = latest
                    occurred_at = _occurred_at_not_before(latest_occurred_at)
                    next_link_hash = _chain_hash(
                        tenant_id,
                        request_id,
                        next_seq + 1,
                        target_status,
                        occurred_at,
                        predecessor_hash,
                    )
                    next_count = next_seq + 2
                    event_tag, head_tag = self._compute_link_evidence(
                        tenant_id,
                        request_id,
                        next_seq + 1,
                        target_status,
                        occurred_at,
                        predecessor_hash,
                        next_link_hash,
                        next_count,
                    )
                    cursor = conn.execute(
                        "UPDATE requests SET status = ?, chain_hash = ?, "
                        "anchor_mac = ? "
                        "WHERE tenant_id = ? AND request_id = ? AND status = ?",
                        (
                            target_status,
                            next_link_hash,
                            head_tag,
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
                    # The event is appended in the same transaction as the
                    # status update. The event's chain link binds the
                    # predecessor hash and its keyed tag, and the head tag
                    # is anchored on the request row by the UPDATE above.
                    conn.execute(
                        "INSERT INTO status_events ("
                        "tenant_id, request_id, seq, status, occurred_at, "
                        "chain_hash, anchor_mac"
                        ") VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (
                            tenant_id,
                            request_id,
                            next_seq + 1,
                            target_status,
                            occurred_at,
                            next_link_hash,
                            event_tag,
                        ),
                    )
                    # Stage everything in SQLite first, then fsync the
                    # external journal while the transaction is still
                    # open, and commit only after the journal is durable:
                    # an actual transition is anchored atomically with
                    # its status and event write.
                    self._journal_link(
                        tenant_id,
                        request_id,
                        next_seq + 1,
                        target_status,
                        occurred_at,
                        next_link_hash,
                        event_tag,
                        head_tag,
                    )
                    conn.execute("COMMIT")
                except InvalidStatusTransition:
                    raise
                except RequestNotFound:
                    raise
                except (sqlite3.Error, OSError, ValueError):
                    # Best-effort cleanup; the rollback failure must not mask
                    # the original problem or leak engine text.
                    try:
                        conn.execute("ROLLBACK")
                    except sqlite3.Error:
                        pass
                    raise RuntimeError("failed to persist status transition") from None
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
        chain as persisted, never recomputed). The keyed anchor material
        is never included. Unknown ids and cross-tenant lookups raise
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
        status, head_hash, head_mac, event_count = self._load_chain_head(
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
        """Verify the persisted audit chain and its protected anchors.

        Verification is strictly read-only: it never repairs, backfills
        or rewrites anything. A request verifies only when *all* of the
        following hold:

        1. Every event link recomputes to its stored keyless
           ``chain_hash`` from the genesis predecessor, with gap-free
           sequences starting at zero.
        2. Every event's keyed ``anchor_mac`` recomputes under the
           external anchor key (so rewritten rows cannot be rehashed into
           validity).
        3. The final link equals the request's anchored head, the
           request's keyed head MAC validates and binds the tenant,
           request, current status, event count and final head, and the
           final event status equals the authoritative current status.
        4. The same records appear, in order, in the external append-only
           anchor journal, which itself authenticates end to end.

        Deleting, altering, inserting, reordering, cross-request or
        cross-tenant substituting events, tampering with either head
        field, or recomputing and replacing every SQLite value (events,
        chain heads and in-database anchor columns) all yield ``False``,
        because the external key and journal cannot be reproduced from
        the database. Legacy unanchored databases fail rather than being
        silently trusted. Unknown ids and cross-tenant lookups raise
        :class:`RequestNotFound`; non-string or empty arguments raise
        :class:`ValueError`.
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
                    "SELECT status, chain_hash, anchor_mac FROM requests "
                    "WHERE tenant_id = ? AND request_id = ?",
                    (tenant_id, request_id),
                ).fetchone()
                if owner is None:
                    raise RequestNotFound("request not found")
                current_status, anchored_head, anchored_head_mac = owner
                if not _is_chain_hash(anchored_head) or not _is_hex64(
                    anchored_head_mac
                ):
                    return False
                rows = conn.execute(
                    "SELECT seq, status, occurred_at, chain_hash, anchor_mac "
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

        predecessor = _GENESIS_PREDECESSOR
        for expected_seq, row in enumerate(rows):
            seq, status, occurred_at, stored_hash, stored_mac = row
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
                or not _is_hex64(stored_mac)
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
            # Keyed check: cannot be reproduced from the database alone.
            expected_mac = self._anchor.event_mac(
                tenant_id,
                request_id,
                seq,
                status,
                occurred_at,
                predecessor,
                stored_hash,
            )
            if not hmac.compare_digest(expected_mac, stored_mac):
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
        # The request-row keyed tag binds tenant, request, final status,
        # event count and final chain head.
        expected_head_mac = self._anchor.head_mac(
            tenant_id, request_id, current_status, len(rows), anchored_head
        )
        if not hmac.compare_digest(expected_head_mac, anchored_head_mac):
            return False
        # Reconstruct the exact external-journal records a clean chain
        # implies (including each historical head tag) and cross-check
        # them against the protected, append-only journal.
        rebuilt_journal = self._rebuild_journal_records(
            tenant_id, request_id, rows
        )
        if rebuilt_journal is None:
            return False
        if rebuilt_journal[-1][7] != anchored_head_mac:
            return False

        # External, off-database cross-check. A file-backed store always
        # has a journal; an in-memory database uses an in-process journal.
        if self._journal is None or self._journal.broken:
            return False
        if not self._journal.verify(rebuilt_journal):
            return False
        return True

    def _rebuild_journal_records(
        self,
        tenant_id: str,
        request_id: str,
        rows: list[tuple[object, ...]],
    ) -> list[tuple[str, str, int, str, str, str, str, str]] | None:
        """Reconstruct the exact journal tuples a clean chain implies.

        Each historical head tag authenticates the head *as of that
        sequence* (status, seq+1 count, that link's hash). The values
        come only from rows already validated above.
        """
        records: list[tuple[str, str, int, str, str, str, str, str]] = []
        for index, row in enumerate(rows):
            seq, status, occurred_at, stored_hash, stored_mac = row
            if not isinstance(seq, int) or isinstance(seq, bool):
                return None
            head_tag = self._anchor.head_mac(
                tenant_id,
                request_id,
                status,
                index + 1,
                stored_hash,
            )
            records.append(
                (
                    tenant_id,
                    request_id,
                    seq,
                    status,
                    occurred_at,
                    stored_hash,
                    stored_mac,
                    head_tag,
                )
            )
        return records

    def _load_chain_head(
        self, tenant_id: str, request_id: str
    ) -> tuple[str, str, str, int]:
        conn = self._connect()
        try:
            try:
                row = conn.execute(
                    "SELECT r.status, r.chain_hash, r.anchor_mac, "
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
        return row[0], row[1], row[2], row[3]
