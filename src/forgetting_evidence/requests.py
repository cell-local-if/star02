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

External anchoring
------------------

Per-request chain hashes live inside the database they attest to, so an
attacker with file-level write access could recompute every hash after a
forgery. To close that hole the store maintains a *sidecar anchor*
outside SQLite:

* the sidecar holds a random HMAC key that never lives in the database;
* it records a global root covering the byte-stable content of every
  audited row, the SQLite file's geometry/change-counter header, and a
  random nonce, all sealed with the key;
* every accepted request or actual status transition is a recoverable
  commit spanning SQLite and the sidecar -- SQLite commits first, the
  anchor is staged through a temporary file, atomically renamed to a
  pending name and then atomically renamed over the committed anchor;
* a crash in between leaves either an older anchor that no longer
  matches the database or a pending file marking the unfinished commit;
* :meth:`recover` reports the state but never repairs or backfills it.
  ``"invalid"`` and ``"incomplete"`` both make :meth:`verify_evidence`
  return ``False`` and make writes fail.

A database written by an older version *without chain columns* is
upgraded once (purely additive backfill; existing evidence is never
recomputed or overwritten) and then sealed. A database that already
contains chain evidence but has no sidecar is never silently trusted:
it stays unsealed, :meth:`recover` reports ``"incomplete"``, writes are
refused, and verification returns ``False``.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import hmac
import json
import logging
import os
import secrets
import sqlite3
import struct
import threading
import uuid
from collections.abc import Iterator, Mapping
from datetime import datetime, timezone
from urllib.request import pathname2url

__all__ = [
    "RequestStore",
    "IdempotencyConflict",
    "RequestNotFound",
    "InvalidStatusTransition",
    "AnchorUnavailable",
]

_log = logging.getLogger(__name__)


class IdempotencyConflict(Exception):
    """Raised when an idempotency key is reused with a different payload."""


class RequestNotFound(Exception):
    """Raised when no request visible to the tenant matches the id."""


class InvalidStatusTransition(Exception):
    """Raised when a requested status change is unknown or not permitted."""


class AnchorUnavailable(RuntimeError):
    """Raised when a write cannot be anchored (missing/broken sidecar)."""


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

# ---------------------------------------------------------------------------
# External sidecar anchor
# ---------------------------------------------------------------------------

_ANCHOR_VERSION = 1
_KEY_BYTES = 32
_NONCE_BYTES = 16
_ANCHOR_SUFFIX = ".anchor.json"
_PENDING_SUFFIX = ".anchor.json.pending"
_LOCK_SUFFIX = ".anchor.lock"

# Recoverability states returned by RequestStore.recover().
_VALID = "valid"
_INVALID = "invalid"
_INCOMPLETE = "incomplete"


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


def _default_sidecar_paths(db_path: str) -> tuple[str, str, str]:
    """Resolve default sidecar paths next to a file-backed database."""
    directory = os.path.dirname(os.path.abspath(db_path))
    base = os.path.basename(db_path)
    anchor = os.path.join(directory, "." + base + _ANCHOR_SUFFIX)
    pending = os.path.join(directory, "." + base + _PENDING_SUFFIX)
    lock = os.path.join(directory, "." + base + _LOCK_SUFFIX)
    return anchor, pending, lock


def _fsync_directory(path: str) -> None:
    """fsync a directory so a rename within it is durable."""
    handle = os.open(path, os.O_RDONLY)
    try:
        os.fsync(handle)
    finally:
        os.close(handle)


def _feed(digest: "hashlib._Hash", value: object) -> None:
    """Length-prefixed canonical encoding of one tagged value.

    Integers use their canonical decimal text; text uses UTF-8. A tag
    byte prevents type confusion between the encodings.
    """
    if value is None:
        digest.update(b"N")
    elif isinstance(value, bool):
        encoded = ("bool:" + str(value)).encode("utf-8")
        digest.update(b"S")
        digest.update(struct.pack(">Q", len(encoded)))
        digest.update(encoded)
    elif isinstance(value, int):
        encoded = str(value).encode("ascii")
        digest.update(b"I")
        digest.update(struct.pack(">Q", len(encoded)))
        digest.update(encoded)
    elif isinstance(value, bytes):
        digest.update(b"B")
        digest.update(struct.pack(">Q", len(value)))
        digest.update(value)
    else:
        encoded = str(value).encode("utf-8")
        digest.update(b"S")
        digest.update(struct.pack(">Q", len(encoded)))
        digest.update(encoded)


def _database_file_path(conn: sqlite3.Connection) -> str | None:
    row = conn.execute("PRAGMA database_list").fetchone()
    if not row or len(row) < 3:
        return None
    path = row[2]
    return path if path else None


def _read_sqlite_identity(conn: sqlite3.Connection) -> tuple[int, int, int, int]:
    """Read geometry and file-header counters of the main database.

    The database file header begins with ``SQLite format 3\\0``; offset
    24 holds the file change counter and offset 92 the
    version-valid-for counter, which SQLite keeps equal and bumps on
    every committed transaction while the database is in rollback
    journal mode. Including both -- together with page size and page
    count -- binds the seal to the exact physical file revision, so a
    database rebuilt or substituted out of band cannot be made to match.
    """
    page_size = int(conn.execute("PRAGMA page_size").fetchone()[0])
    page_count = int(conn.execute("PRAGMA page_count").fetchone()[0])
    change_counter = 0
    version_valid = 0
    path = _database_file_path(conn)
    if path:
        try:
            with open(path, "rb") as handle:
                header = handle.read(100)
        except OSError:
            header = b""
        if len(header) >= 100 and header[:16] == b"SQLite format 3\x00":
            change_counter = struct.unpack(">I", header[24:28])[0]
            version_valid = struct.unpack(">I", header[92:96])[0]
    return page_size, page_count, change_counter, version_valid


def _compute_db_root(
    conn: sqlite3.Connection,
) -> tuple[str, tuple[int, int, int, int]]:
    """Recompute the global database root from stored rows and header.

    The digest covers, in a fixed order:

    * the ``sqlite_master`` rows of the audited tables and their index,
      so a silently rebuilt/recreated schema differs;
    * every row of ``requests`` and ``status_events`` in fully ordered
      form, including every column;
    * the SQLite file identity (page size, page count, change counter,
      version-valid counter).

    A whole-database recomputation after a forgery cannot match a seal
    produced over a different file revision, and substitution of events
    from another request or tenant changes the ordered row stream.
    """
    digest = hashlib.sha256()
    master_rows = conn.execute(
        "SELECT type, name, tbl_name, sql FROM sqlite_master "
        "WHERE name IN ('requests', 'status_events', "
        "'idx_requests_tenant_idempotency') "
        "ORDER BY name"
    ).fetchall()
    _feed(digest, len(master_rows))
    for row in master_rows:
        for value in row:
            _feed(digest, value)
    request_rows = conn.execute(
        "SELECT request_id, tenant_id, idempotency_key, subject_id, "
        "scopes_json, status, created_at, chain_hash "
        "FROM requests ORDER BY tenant_id, request_id"
    ).fetchall()
    _feed(digest, len(request_rows))
    for row in request_rows:
        for value in row:
            _feed(digest, value)
    event_rows = conn.execute(
        "SELECT tenant_id, request_id, seq, status, occurred_at, chain_hash "
        "FROM status_events ORDER BY tenant_id, request_id, seq"
    ).fetchall()
    _feed(digest, len(event_rows))
    for row in event_rows:
        for value in row:
            _feed(digest, value)
    identity = _read_sqlite_identity(conn)
    for value in identity:
        _feed(digest, value)
    return digest.hexdigest(), identity


def _seal(key: bytes, root: str, identity: tuple[int, ...], nonce: bytes) -> str:
    """HMAC the integrity-relevant fields of an anchor payload."""
    message = b"fe-anchor-v1|" + root.encode("ascii")
    message += b"|" + b",".join(str(part).encode("ascii") for part in identity)
    message += b"|" + nonce.hex().encode("ascii")
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def _atomic_write(path: str, payload: dict[str, object]) -> None:
    """Write JSON via a private temporary file and atomic replacement."""
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    tmp_path = os.path.join(
        directory, ".anchor-tmp-" + secrets.token_hex(12)
    )
    fd = os.open(
        tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
    )
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(
                json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(
                    "utf-8"
                )
            )
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
        _fsync_directory(directory)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp_path)
        raise


def _load_json(path: str) -> dict[str, object] | None:
    """Load a JSON object, or signals:

    ``None``  -- file does not exist;
    ``{}``    -- file exists but is unreadable or malformed (damaged).
    """
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except FileNotFoundError:
        return None
    except OSError:
        return {}
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _extract_key(payload: dict[str, object]) -> bytes | None:
    value = payload.get("key")
    if not isinstance(value, str):
        return None
    try:
        key = bytes.fromhex(value)
    except ValueError:
        return None
    return key if len(key) == _KEY_BYTES else None


class _Sidecar:
    """External anchor files living outside the SQLite database.

    Mutation and verification are serialized across processes by an
    exclusive flock on a dedicated lock file. Each lock acquisition uses
    its own file descriptor so concurrent threads never share one.
    """

    def __init__(
        self,
        anchor_path: str,
        pending_path: str,
        lock_path: str,
        configured_key: bytes | None,
    ) -> None:
        self._anchor_path = anchor_path
        self._pending_path = pending_path
        self._lock_path = lock_path
        self._configured_key = configured_key
        # The effective key is adopted from an existing sidecar when no
        # explicit key was supplied; otherwise the configured key is the
        # only one trusted.
        self._key = configured_key
        # An explicitly supplied key is operator-held and never written
        # to disk. Only the auto-generated first key lives in the
        # sidecar, as required for unattended rebuild verification.
        self._persist_key = configured_key is None

    @property
    def key(self) -> bytes | None:
        return self._key

    @property
    def anchor_path(self) -> str:
        return self._anchor_path

    @property
    def pending_path(self) -> str:
        return self._pending_path

    @contextlib.contextmanager
    def exclusive(self) -> Iterator[None]:
        parent = os.path.dirname(os.path.abspath(self._lock_path))
        os.makedirs(parent, exist_ok=True)
        handle = os.open(self._lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(handle, fcntl.LOCK_EX)
            yield
        except OSError as exc:
            raise RuntimeError("failed to initialize request store") from exc
        finally:
            with contextlib.suppress(OSError):
                fcntl.flock(handle, fcntl.LOCK_UN)
            os.close(handle)

    # -- payload parsing ------------------------------------------------

    def _parse(self, path: str) -> dict[str, object] | None:
        return _load_json(path)

    def _valid_payload(self, payload: dict[str, object] | None) -> bool:
        if not payload or payload.get("version") != _ANCHOR_VERSION:
            return False
        if self._key is None:
            return False
        # Auto-managed keys must be embedded and match. With an
        # operator-supplied key the sidecar carries no key field; an
        # embedded key, if present at all, must still match it (so a
        # sidecar sealed under another key can never authenticate).
        embedded = _extract_key(payload)
        if self._persist_key:
            if embedded != self._key:
                return False
        elif embedded is not None and embedded != self._key:
            return False
        if not isinstance(payload.get("root"), str):
            return False
        identity = payload.get("db_identity")
        if (
            not isinstance(identity, list)
            or len(identity) != 4
            or not all(
                isinstance(part, int) and not isinstance(part, bool)
                for part in identity
            )
        ):
            return False
        nonce_text = payload.get("nonce")
        if not isinstance(nonce_text, str) or len(nonce_text) != _NONCE_BYTES * 2:
            return False
        try:
            nonce = bytes.fromhex(nonce_text)
        except ValueError:
            return False
        expected = _seal(
            self._key,
            str(payload["root"]),
            tuple(identity),  # type: ignore[arg-type]
            nonce,
        )
        provided = payload.get("hmac")
        return isinstance(provided, str) and hmac.compare_digest(expected, provided)

    def _payload_matches(
        self,
        payload: dict[str, object],
        root: str,
        identity: tuple[int, ...],
    ) -> bool:
        if payload.get("root") != root:
            return False
        stored_identity = payload.get("db_identity")
        if not isinstance(stored_identity, list) or tuple(stored_identity) != tuple(
            identity
        ):
            return False
        nonce = bytes.fromhex(str(payload["nonce"]))
        return hmac.compare_digest(
            _seal(self._key, root, identity, nonce), str(payload["hmac"])
        )

    # -- key resolution at construction ---------------------------------

    def resolve_key(self) -> None:
        """Adopt key material from the sidecar when none was configured.

        A configured key always wins; a mismatch is not raised here but
        leaves every seal unverifiable (``invalid``). When no key was
        configured, the key is taken from the committed anchor or, if
        the first seal was interrupted before promotion, from the
        pending file.
        """
        committed = self._parse(self._anchor_path)
        if committed:
            existing = _extract_key(committed)
            if existing is not None and self._configured_key is None:
                self._key = existing
            return
        if self._key is not None:
            return
        pending = self._parse(self._pending_path)
        if pending:
            staged = _extract_key(pending)
            if staged is not None:
                self._key = staged
                return
        self._key = secrets.token_bytes(_KEY_BYTES)

    # -- evaluation ------------------------------------------------------

    def evaluate(
        self, root: str, identity: tuple[int, ...]
    ) -> tuple[str, dict[str, object] | None]:
        """Classify the anchor relative to the current database.

        Never mutates anything. Returns the state and the parsed
        committed payload (when usable).
        """
        committed = self._parse(self._anchor_path)
        pending_present = os.path.exists(self._pending_path)

        # No committed sidecar at all: missing or an interrupted first
        # seal -- incomplete, never auto-repaired.
        if committed is None:
            return _INCOMPLETE, None
        # A present-but-unreadable or unauthenticatable anchor is a
        # damaged sidecar: incomplete rather than invalid, since the
        # operator must supply a replacement out of band.
        if not committed or not self._valid_payload(committed):
            return _INCOMPLETE, None
        # A staged file means the last commit was not observed to finish
        # (promotion is the final step). Fail closed as incomplete even
        # when the committed anchor alone would still parse.
        if pending_present:
            return _INCOMPLETE, committed
        if not self._payload_matches(committed, root, identity):
            return _INVALID, committed
        return _VALID, committed

    # -- staging / promotion --------------------------------------------

    def stage(
        self, root: str, identity: tuple[int, ...], nonce: bytes
    ) -> None:
        assert self._key is not None
        payload: dict[str, object] = {
            "version": _ANCHOR_VERSION,
            "root": root,
            "db_identity": list(identity),
            "nonce": nonce.hex(),
            "hmac": _seal(self._key, root, identity, nonce),
        }
        # The auto-generated key is the only key material that lives on
        # disk; an operator-supplied key never enters the sidecar.
        if self._persist_key:
            payload["key"] = self._key.hex()
        _atomic_write(self._pending_path, payload)

    def promote(self) -> None:
        directory = os.path.dirname(os.path.abspath(self._anchor_path))
        os.replace(self._pending_path, self._anchor_path)
        _fsync_directory(directory)

    def write_initial(
        self, root: str, identity: tuple[int, ...], nonce: bytes
    ) -> None:
        """Seal a brand-new or additively upgraded legacy database."""
        self.stage(root, identity, nonce)
        self.promote()


class RequestStore:
    """Persist and retrieve accepted deletion requests."""

    def __init__(
        self,
        db_path: str | os.PathLike[str],
        anchor_path: str | os.PathLike[str] | None = None,
        integrity_key: bytes | str | None = None,
    ):
        self._db_path = os.fspath(db_path)
        # In-process serialization; the unique index additionally guards
        # other processes sharing the same database file.
        self._write_lock = threading.Lock()
        if self._db_path == ":memory:":
            if anchor_path is not None:
                raise ValueError("anchor_path is not supported for :memory: stores")
            if integrity_key is not None:
                raise ValueError("integrity_key is not supported for :memory: stores")
            self._sidecar: _Sidecar | None = None
            self._mem_conn: sqlite3.Connection | None = self._open_connection()
        else:
            self._mem_conn = None
            parent = os.path.dirname(os.path.abspath(self._db_path))
            os.makedirs(parent, exist_ok=True)
            key = self._coerce_key(integrity_key)
            if anchor_path is None:
                anchor_file, pending_file, lock_file = _default_sidecar_paths(
                    self._db_path
                )
            else:
                anchor_file = os.path.abspath(os.fspath(anchor_path))
                pending_file = anchor_file + ".pending"
                lock_file = anchor_file + ".lock"
                if anchor_file == os.path.abspath(self._db_path):
                    raise ValueError("anchor_path must reside outside the SQLite file")
                os.makedirs(os.path.dirname(anchor_file), exist_ok=True)
            self._sidecar = _Sidecar(anchor_file, pending_file, lock_file, key)

        conn = self._connect()
        try:
            self._initialize_store(conn)
        finally:
            self._release(conn)

    @staticmethod
    def _coerce_key(integrity_key: bytes | str | None) -> bytes | None:
        if integrity_key is None:
            return None
        if isinstance(integrity_key, str):
            try:
                key = bytes.fromhex(integrity_key)
            except ValueError as exc:
                raise ValueError(
                    "integrity_key must be 32 raw bytes or 64 hex characters"
                ) from exc
        elif isinstance(integrity_key, (bytes, bytearray)):
            key = bytes(integrity_key)
        else:
            raise ValueError("integrity_key must be 32 raw bytes or 64 hex characters")
        if len(key) != _KEY_BYTES:
            raise ValueError("integrity_key must be 32 raw bytes or 64 hex characters")
        return key

    # -- initialization -------------------------------------------------

    def _initialize_store(self, conn: sqlite3.Connection) -> None:
        """Create/upgrade the schema and reconcile the external anchor."""
        sidecar = self._sidecar
        if sidecar is None:
            conn.execute(_SCHEMA)
            conn.execute(_UNIQUE_TENANT_KEY)
            conn.execute(_EVENT_TABLE)
            return

        with sidecar.exclusive():
            conn.execute(_SCHEMA)
            conn.execute(_UNIQUE_TENANT_KEY)
            conn.execute(_EVENT_TABLE)
            sidecar.resolve_key()

            legacy_layout = not (
                conn.execute(_REQUEST_CHAIN_COLUMN).fetchone()
                and conn.execute(_EVENT_CHAIN_COLUMN).fetchone()
            )

            anchor_exists = os.path.exists(sidecar.anchor_path)
            pending_exists = os.path.exists(sidecar.pending_path)

            if anchor_exists:
                # An existing anchor decides trust. Verify it against the
                # current file; never migrate, reseal or overwrite. A
                # mismatch (or a damaged anchor) leaves the store
                # untrusted: recover() reports it, writes are refused.
                root, identity = _compute_db_root(conn)
                state, _committed = sidecar.evaluate(root, identity)
                if state == _VALID:
                    return
                _log.warning(
                    "audit anchor not consistent on open: state=%s", state
                )
                return

            # No committed anchor.
            if pending_exists:
                # A previous process staged a first seal but never
                # promoted it: the commit is unfinished. Never seal over
                # an interrupted commit; the operator must intervene.
                _log.warning("unfinished anchor commit found on open")
                return

            if legacy_layout:
                # Truly legacy database (written before chain hashes):
                # the upgrade is additive and never overwrites existing
                # audit records; afterwards the upgraded content gets
                # the database's first seal.
                self._migrate_schema(conn)
                self._fsync_database_file(conn)
            else:
                # Modern schema without an anchor. An empty database
                # carries no audit evidence yet and may be sealed. A
                # database that already contains events is *not*
                # silently trusted: upgrading must never bless
                # unanchored evidence with a fresh key.
                event_count = conn.execute(
                    "SELECT count(*) FROM status_events"
                ).fetchone()[0]
                request_count = conn.execute(
                    "SELECT count(*) FROM requests"
                ).fetchone()[0]
                if event_count or request_count:
                    _log.warning(
                        "database contains audit evidence but no anchor; "
                        "left unsealed"
                    )
                    return

            try:
                root, identity = _compute_db_root(conn)
                # Cross-check from an independent read-only connection
                # before the anchor ever exists, then stage and promote.
                readonly = self._open_readonly_connection()
                try:
                    check_root, check_identity = _compute_db_root(readonly)
                finally:
                    readonly.close()
                if check_root != root or check_identity != identity:
                    raise RuntimeError("failed to initialize request store")
                nonce = secrets.token_bytes(_NONCE_BYTES)
                sidecar.write_initial(root, identity, nonce)
            except RuntimeError:
                raise
            except (OSError, sqlite3.Error) as exc:
                raise RuntimeError(
                    "failed to initialize request store"
                ) from exc

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
            with contextlib.suppress(sqlite3.Error):
                conn.execute("ROLLBACK")
            raise RuntimeError("failed to initialize request store") from None

    # -- connection management ------------------------------------------

    def _open_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            self._db_path,
            timeout=_BUSY_TIMEOUT_MS / 1000,
            check_same_thread=False,
        )
        conn.isolation_level = None  # explicit transaction control
        conn.execute(f"PRAGMA busy_timeout = {_BUSY_TIMEOUT_MS}")
        if self._db_path != ":memory:":
            # The external anchor reads the raw file change counter,
            # which SQLite only maintains in rollback-journal mode.
            conn.execute("PRAGMA journal_mode = DELETE")
            conn.execute("PRAGMA synchronous = FULL")
        return conn

    def _open_readonly_connection(self) -> sqlite3.Connection:
        path = os.path.abspath(self._db_path)
        uri = "file:" + pathname2url(path) + "?mode=ro"
        return sqlite3.connect(
            uri,
            uri=True,
            timeout=_BUSY_TIMEOUT_MS / 1000,
            check_same_thread=False,
        )

    def _connect(self) -> sqlite3.Connection:
        if self._mem_conn is not None:
            return self._mem_conn
        return self._open_connection()

    def _release(self, conn: sqlite3.Connection) -> None:
        if conn is not self._mem_conn:
            conn.close()

    def _fsync_database_file(self, conn: sqlite3.Connection) -> None:
        path = _database_file_path(conn)
        if not path:
            return
        handle = os.open(path, os.O_RDONLY)
        try:
            os.fsync(handle)
        finally:
            os.close(handle)
        directory = os.path.dirname(os.path.abspath(path))
        if directory:
            _fsync_directory(directory)

    # -- recoverable commit ---------------------------------------------

    @contextlib.contextmanager
    def _anchor_guard(self) -> Iterator[None]:
        """Serialize an anchored write and refuse untrusted stores.

        The in-process write lock is held by callers; for file-backed
        stores the sidecar flock is taken as well, and the anchor must
        describe the current database before any write begins.
        """
        sidecar = self._sidecar
        if sidecar is None:
            yield
            return
        with sidecar.exclusive():
            conn = self._open_readonly_connection()
            try:
                root, identity = _compute_db_root(conn)
                state, _payload = sidecar.evaluate(root, identity)
            finally:
                conn.close()
            if state != _VALID:
                raise AnchorUnavailable("audit anchor is not consistent")
            yield

    def _verify_anchor_against_committed_state(self) -> None:
        """Re-check the anchor from a connection seeing only committed data.

        Called after ``BEGIN IMMEDIATE`` (which reserves the write lock):
        the pre-transaction database must still match the sealed anchor.
        This closes the check-then-act window so a modification committed
        out of band between the guard check and our write can never be
        laundered by a fresh seal.
        """
        sidecar = self._sidecar
        if sidecar is None:
            return
        readonly = self._open_readonly_connection()
        try:
            root, identity = _compute_db_root(readonly)
        finally:
            readonly.close()
        state, _payload = sidecar.evaluate(root, identity)
        if state != _VALID:
            raise AnchorUnavailable("audit anchor is not consistent")

    def _anchored_commit(self, conn: sqlite3.Connection) -> None:
        """Commit the open SQLite transaction and renew the sidecar.

        Recoverable ordering:

        1. COMMIT SQLite and force the file to disk so the bumped change
           counter is durable;
        2. recompute root and file identity from a fresh read-only
           connection;
        3. stage the new anchor in a temporary file, atomically replaced
           onto the pending name and fsynced;
        4. re-read the file to confirm nothing moved;
        5. atomically replace the committed anchor with the pending one.

        A failure at any point raises (success is never reported) and
        leaves the discrepancy on disk for :meth:`recover` to surface:
        the old anchor no longer matches the database (``invalid``) or a
        staged file remains after an interrupted promotion
        (``incomplete``). Staged evidence is never deleted on failure --
        recover() never repairs either.
        """
        sidecar = self._sidecar
        if sidecar is None:
            conn.execute("COMMIT")
            return
        assert sidecar.key is not None
        try:
            conn.execute("COMMIT")
            self._fsync_database_file(conn)

            readonly = self._open_readonly_connection()
            try:
                root, identity = _compute_db_root(readonly)
            finally:
                readonly.close()

            nonce = secrets.token_bytes(_NONCE_BYTES)
            # If staging fails the old anchor is in place and the
            # database is already newer: the store is observably
            # invalid. Nothing staged is removed on failure.
            sidecar.stage(root, identity, nonce)

            readonly = self._open_readonly_connection()
            try:
                confirm_root, confirm_identity = _compute_db_root(readonly)
            finally:
                readonly.close()
            if confirm_root != root or confirm_identity != identity:
                raise AnchorUnavailable("audit anchor is not consistent")

            # os.replace is atomic. If it does not complete, the pending
            # file remains on disk and marks the unfinished commit
            # (incomplete); it is deliberately not removed.
            sidecar.promote()
        except AnchorUnavailable:
            raise
        except (OSError, sqlite3.Error) as exc:
            # Never surface database engine or filesystem error text.
            raise RuntimeError("failed to persist audit evidence") from exc

    # -- public API: submit ---------------------------------------------

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

        with self._write_lock, self._anchor_guard():
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
                # Hold the SQLite write lock while re-confirming the
                # sealed anchor against committed state: nothing can
                # advance the file between this check and our commit.
                try:
                    self._verify_anchor_against_committed_state()
                except AnchorUnavailable:
                    with contextlib.suppress(sqlite3.Error):
                        conn.execute("ROLLBACK")
                    raise
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
                    with contextlib.suppress(sqlite3.Error):
                        conn.execute("ROLLBACK")
                    raise RuntimeError("failed to persist accepted request") from None
                self._anchored_commit(conn)
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

        with self._write_lock, self._anchor_guard():
            conn = self._connect()
            try:
                try:
                    conn.execute("BEGIN IMMEDIATE")
                except sqlite3.Error:
                    # Never surface the database engine's own error text.
                    raise RuntimeError(
                        "failed to persist status transition"
                    ) from None
                try:
                    # Same sealed-state re-confirmation as in submit(),
                    # performed while holding the SQLite write lock.
                    self._verify_anchor_against_committed_state()
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
                    self._anchored_commit(conn)
                except InvalidStatusTransition:
                    raise
                except RequestNotFound:
                    raise
                except AnchorUnavailable:
                    raise
                except sqlite3.Error:
                    # Best-effort cleanup; the rollback failure must not mask
                    # the original problem or leak engine text.
                    with contextlib.suppress(sqlite3.Error):
                        conn.execute("ROLLBACK")
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

        Every link is checked against the stored rows only; verification
        never recomputes-and-overwrites persisted evidence. Deleting,
        altering, inserting or reordering events, tampering with the
        request head, substituting events from another request or tenant,
        recomputing the database or sidecar content out of band, or
        restarting against an inconsistent/missing anchor all yield
        ``False``. For file-backed stores the external sidecar must
        additionally seal the whole database in its exact current file
        revision. Returns ``True`` only when every link recomputes to its
        stored hash from the genesis predecessor, the sequences are
        gap-free from zero, the final link matches the request's anchored
        head and current status, and the global anchor is ``valid``.
        Unknown ids and cross-tenant lookups raise
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
                    "SELECT status, chain_hash FROM requests "
                    "WHERE tenant_id = ? AND request_id = ?",
                    (tenant_id, request_id),
                ).fetchone()
                if owner is None:
                    raise RequestNotFound("request not found")
                current_status, anchored_head = owner
                rows = conn.execute(
                    "SELECT seq, status, occurred_at, chain_hash "
                    "FROM status_events "
                    "WHERE tenant_id = ? AND request_id = ? ORDER BY seq",
                    (tenant_id, request_id),
                ).fetchall()
                anchor_ok = self._global_anchor_valid(conn)
            except RequestNotFound:
                raise
            except sqlite3.Error:
                # Never surface the database engine's own error text.
                raise RuntimeError("failed to verify request evidence") from None
        finally:
            self._release(conn)

        if not anchor_ok:
            return False
        if not _is_chain_hash(anchored_head):
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
                raise RuntimeError("failed to read request evidence") from None
        finally:
            self._release(conn)
        if row is None:
            # Identical outcome for unknown ids and cross-tenant lookups.
            raise RequestNotFound("request not found")
        return row[0], row[1], row[2]

    # -- recovery --------------------------------------------------------

    def _global_anchor_valid(self, conn: sqlite3.Connection) -> bool:
        sidecar = self._sidecar
        if sidecar is None:
            return True
        with sidecar.exclusive():
            root, identity = _compute_db_root(conn)
            state, _payload = sidecar.evaluate(root, identity)
            return state == _VALID

    def recover(self) -> str:
        """Report the consistency of the external audit anchor.

        Returns one of:

        * ``"valid"`` -- the committed anchor seals the database in its
          exact current file revision and no commit is staged;
        * ``"invalid"`` -- the anchor exists, parses and authenticates,
          but its root or file identity does not match the database;
        * ``"incomplete"`` -- the sidecar is missing, damaged, or a
          commit was staged but not finished.

        The check is strictly read-only: it never creates, repairs,
        re-seals or backfills anything, and never migrates the database.
        ``"invalid"`` and ``"incomplete"`` both make
        :meth:`verify_evidence` return ``False`` and writes raise
        :class:`AnchorUnavailable`. In-memory stores always report
        ``"valid"``.
        """
        sidecar = self._sidecar
        if sidecar is None:
            return _VALID
        with sidecar.exclusive():
            conn = self._open_readonly_connection()
            try:
                root, identity = _compute_db_root(conn)
                state, _payload = sidecar.evaluate(root, identity)
            except (OSError, sqlite3.Error):
                return _INVALID
            finally:
                conn.close()
            return state
