"""SQLite-backed acceptance store for deletion requests.

The store records deletion requests without retaining any identifying
payload in logs, return values beyond the fixed receipt fields, or
exception messages. SQLite integrity conflicts are translated into the
module's own idempotency semantics and never surface to callers.

Every accepted request carries a persistent, append-only status timeline
in ``status_events``. Events are written in the same transaction as the
request row or status change they describe, so the final timeline entry
always matches the request's current status.

Trust root
----------
The audit chain is not verifiable from the SQLite database alone.

* Every event carries a keyed ``chain_hash`` (HMAC-SHA256) binding the
  tenant, request, per-request sequence, status, occurrence time and the
  previous event's link.
* A second, domain-separated anchor tag binds the chain head together
  with the current status and the event count. The anchor label is
  persisted on the request row and in ``evidence_meta`` *and* mirrored in
  an external head ledger that lives outside the database.
* The secret key likewise lives outside the database.

An attacker who rewrites the SQLite file can recompute ordinary hashes
but cannot recompute the keyed links or head anchor, and cannot move the
external ledger entry: replacing the events, the request head and the
in-database anchor fields with a self-consistent set still fails
verification because the external head disagrees and the key is absent.
Key material and key preimages never appear in SQLite, receipts,
exceptions or logs; the ledger stores tag outputs only.

The trust root is resolved, in order of precedence, from an explicit
``integrity_anchor`` object, an explicit ``integrity_key`` argument, the
``FORGETTING_EVIDENCE_INTEGRITY_KEY`` /
``FORGETTING_EVIDENCE_INTEGRITY_KEY_FILE`` environment variables, an
auto-generated 0600 key file (``<db_path>.integrity.key``), or - for
``:memory:`` databases - a process-local random key. Default
construction consequently keeps verifying the same database after the
store is rebuilt, while a database copied without its external files
always fails verification. Custom :class:`IntegrityAnchor`
implementations may forward tag operations to an HSM, signing service or
transparency log.

Databases created before keyed evidence existed are upgraded purely
additively (nullable columns, a meta table); their audit rows are never
backfilled or overwritten. Such unprotected requests never verify,
report a dedicated :class:`LegacyEvidenceUnsupported` result from
:meth:`evidence` and :meth:`transition`, and remain readable through
:meth:`audit` and :meth:`get`.
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
import tempfile
import threading
import uuid
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone

try:  # POSIX only; the deployment target is Linux.
    import fcntl
except ImportError:  # pragma: no cover - exercised only on non-POSIX hosts
    fcntl = None  # type: ignore[assignment]

__all__ = [
    "RequestStore",
    "IdempotencyConflict",
    "RequestNotFound",
    "InvalidStatusTransition",
    "LegacyEvidenceUnsupported",
    "IntegrityConfigurationError",
    "IntegrityKeyMismatch",
    "IntegrityAnchor",
    "KeyedIntegrityAnchor",
]

_log = logging.getLogger(__name__)


class IdempotencyConflict(Exception):
    """Raised when an idempotency key is reused with a different payload."""


class RequestNotFound(Exception):
    """Raised when no request visible to the tenant matches the id."""


class InvalidStatusTransition(Exception):
    """Raised when a requested status change is unknown or not permitted."""


class LegacyEvidenceUnsupported(Exception):
    """Raised when a request predates key-protected audit evidence.

    The request's timeline is still readable, but it carries no keyed
    anchor and can never verify; extending it is refused rather than
    silently treating its unprotected history as trustworthy.
    """


class IntegrityConfigurationError(Exception):
    """Raised when the external integrity key/anchor cannot be resolved."""


class IntegrityKeyMismatch(IntegrityConfigurationError):
    """Raised when the configured key does not match the database's key."""


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
    chain_hash      TEXT,
    anchor_value    TEXT
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
    chain_hash  TEXT,
    PRIMARY KEY (tenant_id, request_id, seq)
);
"""

# External anchor labels for per-request heads and the static key
# verifier. Only tag outputs live here; the secret key never does.
_META_TABLE = """
CREATE TABLE IF NOT EXISTS evidence_meta (
    domain TEXT PRIMARY KEY,
    value  TEXT NOT NULL
);
"""

# The composite primary key already indexes (tenant_id, request_id, seq),
# which serves both the ordered timeline read and the latest-event lookup.

# Column probes used to upgrade database files created before keyed
# evidence existed. The upgrade is purely additive: nullable columns only,
# no backfill, existing audit rows are never rewritten.
_REQUEST_CHAIN_COLUMN = (
    "SELECT 1 FROM pragma_table_info('requests') WHERE name = 'chain_hash'"
)
_REQUEST_ANCHOR_COLUMN = (
    "SELECT 1 FROM pragma_table_info('requests') WHERE name = 'anchor_value'"
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

# HMAC domain separators: a tag valid in one role can never be replayed
# in another.
_PURPOSE_LINK = "forgetting-evidence/status-event/v1"
_PURPOSE_ANCHOR = "forgetting-evidence/chain-anchor/v1"
_PURPOSE_KEY_CHECK = "forgetting-evidence/key-check/v1"
_KEY_CHECK_PART = "forgetting-evidence"
_META_HEAD_PREFIX = "head\x1f"
_META_KEY_CHECK = "key_check"

# A fixed genesis predecessor keeps the first event distinguishable
# from a link chained onto a forged 64-character predecessor; the HMAC
# key supplies the actual secret, so this sentinel need not be one.
_GENESIS_PREDECESSOR = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
_HEX = "0123456789abcdef"

_ENV_KEY = "FORGETTING_EVIDENCE_INTEGRITY_KEY"
_ENV_KEY_FILE = "FORGETTING_EVIDENCE_INTEGRITY_KEY_FILE"
_KEY_FILE_SUFFIX = ".integrity.key"
_LEDGER_SUFFIX = ".integrity.heads"
_LOCK_SUFFIX = ".integrity.lock"
_MIN_KEY_BYTES = 32
_LEDGER_VERSION = 1


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


def _is_tag(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in _HEX for char in value)
    )


def _tag_input(purpose: str, parts: Sequence[str]) -> bytes:
    """Length-prefix every field so no preimage can be re-parsed two ways."""
    out = bytearray()
    for field in (purpose, *parts):
        encoded = field.encode("utf-8")
        out += struct.pack(">Q", len(encoded))
        out += encoded
    return bytes(out)


def _head_domain(tenant_id: str, request_id: str) -> str:
    return f"{_META_HEAD_PREFIX}{tenant_id}\x1f{request_id}"


def _coerce_integrity_key(value: object) -> bytes:
    """Validate a caller-supplied key without echoing it in any error."""
    if isinstance(value, bytes):
        raw = value
    elif isinstance(value, str):
        # Prefer an exact 32-byte hex encoding; otherwise take the raw
        # UTF-8 bytes so passphrases work too.
        if len(value) == 64:
            try:
                raw = bytes.fromhex(value)
            except ValueError:
                raw = value.encode("utf-8")
        else:
            raw = value.encode("utf-8")
    else:
        raise ValueError(
            f"integrity_key must be bytes or a string of at least "
            f"{_MIN_KEY_BYTES} bytes"
        )
    if len(raw) < _MIN_KEY_BYTES:
        raise ValueError(
            f"integrity_key must contain at least {_MIN_KEY_BYTES} bytes"
        )
    return raw


class IntegrityAnchor:
    """External trust root for audit-chain evidence.

    Implementations produce and verify opaque hexadecimal tags. They
    must never expose key material through return values, exceptions or
    logs. The default :class:`KeyedIntegrityAnchor` computes HMAC tags
    locally; alternative implementations may forward the calls to an
    HSM, a signing service or a transparency log.
    """

    def attest(self, purpose: str, parts: Sequence[str]) -> str:
        raise NotImplementedError

    def verify_attestation(
        self, purpose: str, parts: Sequence[str], tag: str
    ) -> bool:
        raise NotImplementedError


class KeyedIntegrityAnchor(IntegrityAnchor):
    """HMAC-SHA256 anchor backed by an externally held symmetric key."""

    def __init__(self, key: bytes):
        if not isinstance(key, bytes) or len(key) < _MIN_KEY_BYTES:
            # Never include the key material in the message.
            raise IntegrityConfigurationError(
                f"integrity key must be at least {_MIN_KEY_BYTES} bytes"
            )
        # Keep a private copy; callers retain no shared mutable buffer.
        self._key = bytes(key)

    def attest(self, purpose: str, parts: Sequence[str]) -> str:
        return hmac.new(
            self._key, _tag_input(purpose, parts), hashlib.sha256
        ).hexdigest()

    def verify_attestation(
        self, purpose: str, parts: Sequence[str], tag: str
    ) -> bool:
        if not _is_tag(tag):
            return False
        expected = self.attest(purpose, parts)
        return hmac.compare_digest(expected, tag)


class _MemoryTrustState:
    """Process-local mirror of the external files for ``:memory:`` DBs."""

    def __init__(self) -> None:
        self.heads: dict[str, str] = {}


@contextlib.contextmanager
def _file_lock(path: str):
    """Cross-process lock guarding read/modify/write of external state.

    The lock is taken before ``BEGIN IMMEDIATE`` and released only after
    the external ledger replacement, so every process observes one
    global order of (database commit, external head update). Verifying
    readers take the same shared lock and therefore never observe a
    half-finished commit.
    """
    if fcntl is None:  # pragma: no cover - non-POSIX fallback
        yield
        return
    handle = open(path, "a+")
    try:
        with contextlib.suppress(OSError):
            os.fchmod(handle.fileno(), 0o600)
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()


def _write_atomic_0600(path: str, payload: bytes) -> None:
    directory = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp_path = tempfile.mkstemp(prefix=".integrity-", dir=directory)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp_path)
        raise


class RequestStore:
    """Persist and retrieve accepted deletion requests."""

    def __init__(
        self,
        db_path: str | os.PathLike[str],
        *,
        integrity_key: bytes | str | None = None,
        integrity_key_file: str | os.PathLike[str] | None = None,
        integrity_anchor: IntegrityAnchor | None = None,
    ):
        self._db_path = os.fspath(db_path)
        # In-process serialization; the unique index additionally guards
        # other processes sharing the same database file.
        self._write_lock = threading.Lock()

        explicit_key_file = (
            os.fspath(integrity_key_file) if integrity_key_file is not None else None
        )
        env_key_file = os.environ.get(_ENV_KEY_FILE)

        if self._db_path == ":memory:":
            self._mem_conn: sqlite3.Connection | None = self._open_connection()
            self._key_path: str | None = None
            self._ledger_path: str | None = None
            self._lock_path: str | None = None
            self._memory_state = _MemoryTrustState()
        else:
            self._mem_conn = None
            self._memory_state = None
            parent = os.path.dirname(os.path.abspath(self._db_path))
            os.makedirs(parent, exist_ok=True)
            self._key_path = explicit_key_file or env_key_file or (
                self._db_path + _KEY_FILE_SUFFIX
            )
            self._ledger_path = self._db_path + _LEDGER_SUFFIX
            self._lock_path = self._db_path + _LOCK_SUFFIX

        self._anchor: IntegrityAnchor | None = None
        conn = self._connect()
        try:
            # Schema upgrade needs no key and is purely additive, so it
            # runs before the trust root is resolved.
            conn.execute(_SCHEMA)
            conn.execute(_UNIQUE_TENANT_KEY)
            conn.execute(_EVENT_TABLE)
            conn.execute(_META_TABLE)
            self._migrate_schema(conn)
            self._anchor = self._resolve_anchor(integrity_key, integrity_anchor, conn)
            self._bind_database_key(conn)
            # Merge any committed anchors missing from the external
            # ledger (crash between commit and ledger update). This is a
            # recovery path, never part of verification.
            self._reconcile_external(conn)
        finally:
            self._release(conn)

    # ------------------------------------------------------------------
    # Trust-root resolution and schema setup
    # ------------------------------------------------------------------

    def _resolve_anchor(
        self,
        integrity_key: bytes | str | None,
        integrity_anchor: IntegrityAnchor | None,
        conn: sqlite3.Connection,
    ) -> IntegrityAnchor:
        """Resolve the external trust root and create/open external files.

        Resolution order: explicit anchor object, explicit/env key,
        stored key file, freshly generated key. External files are
        created 0600 and never stored inside SQLite. An existing
        database that already carries protected anchors but lacks the
        external key is refused rather than silently re-keyed, since
        that is precisely the shape of a copied or replayed database.
        """
        if integrity_anchor is not None and not isinstance(
            integrity_anchor, IntegrityAnchor
        ):
            raise IntegrityConfigurationError(
                "integrity_anchor must implement IntegrityAnchor"
            )

        configured_raw: object = None
        if integrity_key is not None:
            configured_raw = integrity_key
        elif os.environ.get(_ENV_KEY):
            configured_raw = os.environ[_ENV_KEY]
        configured_key = (
            _coerce_integrity_key(configured_raw) if configured_raw is not None else None
        )

        if self._key_path is None:
            # In-memory database: trust state lives only in this process.
            if integrity_anchor is not None:
                return integrity_anchor
            if configured_key is not None:
                return KeyedIntegrityAnchor(configured_key)
            return KeyedIntegrityAnchor(os.urandom(_MIN_KEY_BYTES))

        with _file_lock(self._lock_path):  # type: ignore[arg-type]
            stored_key = self._read_key_file(self._key_path)
            # Has this database ever been protected by a trust root?
            protected = bool(
                conn.execute(
                    "SELECT 1 FROM evidence_meta WHERE domain = ? "
                    "UNION ALL SELECT 1 FROM requests "
                    "WHERE anchor_value IS NOT NULL LIMIT 1",
                    (_META_KEY_CHECK,),
                ).fetchone()
            )

            if integrity_anchor is not None:
                # A custom anchor owns key management. A local key file
                # alongside it is irrelevant but never trusted.
                resolved = integrity_anchor
            elif configured_key is not None:
                if stored_key is not None and not hmac.compare_digest(
                    stored_key, configured_key
                ):
                    raise IntegrityKeyMismatch(
                        "configured integrity key does not match the database"
                    )
                resolved: IntegrityAnchor = KeyedIntegrityAnchor(configured_key)
            elif stored_key is not None:
                if len(stored_key) < _MIN_KEY_BYTES:
                    raise IntegrityConfigurationError(
                        "stored integrity key is unusable"
                    )
                resolved = KeyedIntegrityAnchor(stored_key)
            elif protected:
                # The database contains protected anchors but neither an
                # available key file nor an explicit key exists. This is
                # the signature of a copied/replayed database whose
                # external trust root was withheld: never mint a new key.
                raise IntegrityConfigurationError(
                    "database requires an externally configured integrity key"
                )
            else:
                # Fresh file, or a legacy unprotected database: generate
                # the trust root. Legacy requests keep NULL anchors and
                # remain untrusted; only new writes are protected.
                generated = os.urandom(_MIN_KEY_BYTES)
                _write_atomic_0600(self._key_path, generated)
                resolved = KeyedIntegrityAnchor(generated)

            # Ensure the external head ledger exists. It stores tag
            # outputs only, never key material.
            if not os.path.exists(self._ledger_path):
                _write_atomic_0600(
                    self._ledger_path,
                    json.dumps(
                        {"version": _LEDGER_VERSION, "heads": {}},
                        ensure_ascii=True,
                        separators=(",", ":"),
                    ).encode("utf-8"),
                )
            return resolved

    @staticmethod
    def _read_key_file(path: str) -> bytes | None:
        try:
            with open(path, "rb") as handle:
                data = handle.read()
        except FileNotFoundError:
            return None
        except OSError:
            # Unreadable state must not be silently replaced by a new key.
            raise IntegrityConfigurationError(
                "integrity key is unavailable"
            ) from None
        # The key file holds raw bytes; tolerate a trailing newline from
        # operators who provision it with a text editor.
        return data.rstrip(b"\r\n")

    def _read_ledger_raw(self) -> dict[str, str] | None:
        """Read the external head ledger, or ``None`` if unreadable.

        ``None`` means missing/corrupt external state; callers may
        reconstruct it from key-verified database anchors.
        """
        if self._memory_state is not None:
            return dict(self._memory_state.heads)
        try:
            with open(self._ledger_path, "rb") as handle:  # type: ignore[arg-type]
                data = handle.read()
        except OSError:
            return None
        try:
            parsed = json.loads(data.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None
        if not isinstance(parsed, dict) or not isinstance(parsed.get("heads"), dict):
            return None
        return {
            domain: label
            for domain, label in parsed["heads"].items()
            if isinstance(domain, str) and isinstance(label, str)
        }

    def _write_ledger(self, heads: dict[str, str]) -> None:
        _write_atomic_0600(
            self._ledger_path,  # type: ignore[arg-type]
            json.dumps(
                {"version": _LEDGER_VERSION, "heads": heads},
                ensure_ascii=True,
                separators=(",", ":"),
            ).encode("utf-8"),
        )

    def _read_ledger(self) -> dict[str, str]:
        heads = self._read_ledger_raw()
        return heads if heads is not None else {}

    def _reconcile_external(self, conn: sqlite3.Connection | None = None) -> None:
        """Reconcile the external head ledger with committed DB anchors.

        Construction-time recovery only; never invoked from verification.
        The database can legitimately be one entry ahead of the ledger if
        a process died between the SQLite commit and the ledger write, so
        key-verified anchors are merged in. Keyed tags cannot be forged
        from database contents, therefore copying a re-verified tag into
        the ledger grants an attacker nothing. Existing ledger entries
        are never removed or downgraded.
        """
        if self._lock_path is None:
            return
        own_conn = conn if conn is not None else self._connect()
        try:
            with _file_lock(self._lock_path):
                heads = self._read_ledger_raw()
                existed = heads is not None
                if heads is None:
                    heads = {}
                merged = False
                for domain, label in self._rebuild_heads(own_conn).items():
                    # A tag that re-verifies under the key is
                    # authoritative: it repairs a corrupt or stale
                    # ledger value as well as a missing one.
                    if heads.get(domain) != label:
                        heads[domain] = label
                        merged = True
                if merged or not existed:
                    self._write_ledger(heads)
        finally:
            if conn is None:
                self._release(own_conn)

    def _publish_head(
        self,
        domain: str,
        label: str,
        conn: sqlite3.Connection,
        failure_message: str = "failed to persist accepted request",
    ) -> None:
        """Publish a committed head, masking filesystem error details.

        The SQLite commit has already succeeded durably and the next
        construction reconciles a missing ledger, so a failure here must
        not surface engine or path text; it is reported with the same
        generic message as other persistence failures.
        """
        try:
            self._record_external_head(domain, label, conn)
        except OSError:
            raise RuntimeError(failure_message) from None

    def _record_external_head(
        self, domain: str, label: str, conn: sqlite3.Connection
    ) -> None:
        """Persist the newly attested head outside SQLite.

        Runs inside the cross-process lock, after the SQLite commit.
        Only tag outputs are written; key material is never present.
        Committed anchors missing from a damaged ledger are merged back
        in (their tags re-verify under the trust root).
        """
        if self._memory_state is not None:
            self._memory_state.heads[domain] = label
            return
        heads = self._read_ledger_raw()
        if heads is None:
            heads = {}
        for known_domain, known_label in self._rebuild_heads(conn).items():
            # Key-verified DB anchors are authoritative; this heals a
            # stale or corrupt ledger entry for other requests too.
            heads[known_domain] = known_label
        heads[domain] = label
        self._write_ledger(heads)

    def _rebuild_heads(self, conn: sqlite3.Connection) -> dict[str, str]:
        """Reconstruct the tag-only head map from key-verified DB rows."""
        heads: dict[str, str] = {}
        try:
            rows = conn.execute(
                "SELECT r.tenant_id, r.request_id, r.chain_hash, r.status, "
                "r.anchor_value, (SELECT count(*) FROM status_events e "
                " WHERE e.tenant_id = r.tenant_id AND e.request_id = r.request_id) "
                "FROM requests r WHERE r.anchor_value IS NOT NULL"
            ).fetchall()
        except sqlite3.Error:
            return {}
        for tenant_id, request_id, head, status, stored_label, count in rows:
            if not _is_tag(head) or not _is_tag(stored_label) or not isinstance(
                status, str
            ):
                continue
            if self._anchor.verify_attestation(
                _PURPOSE_ANCHOR,
                (tenant_id, request_id, head, status, str(count)),
                stored_label,
            ):
                heads[_head_domain(tenant_id, request_id)] = stored_label
        return heads

    def _migrate_schema(self, conn: sqlite3.Connection) -> None:
        """Add integrity columns to a database written by an older version.

        Additive only: nullable columns and the meta table are created,
        existing rows keep NULL evidence and are never backfilled or
        recomputed. The transactional upgrade runs at most once per file.
        """
        if conn.execute(_REQUEST_CHAIN_COLUMN).fetchone() and conn.execute(
            _REQUEST_ANCHOR_COLUMN
        ).fetchone() and conn.execute(_EVENT_CHAIN_COLUMN).fetchone():
            return
        with self._write_lock:
            try:
                conn.execute("BEGIN IMMEDIATE")
                # Re-probe inside the transaction: another process may
                # have completed the upgrade while we waited on the lock.
                if not conn.execute(_REQUEST_CHAIN_COLUMN).fetchone():
                    conn.execute("ALTER TABLE requests ADD COLUMN chain_hash TEXT")
                if not conn.execute(_REQUEST_ANCHOR_COLUMN).fetchone():
                    conn.execute("ALTER TABLE requests ADD COLUMN anchor_value TEXT")
                if not conn.execute(_EVENT_CHAIN_COLUMN).fetchone():
                    conn.execute(
                        "ALTER TABLE status_events ADD COLUMN chain_hash TEXT"
                    )
                conn.execute(_META_TABLE)
                conn.execute("COMMIT")
            except sqlite3.Error:
                try:
                    conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise RuntimeError("failed to initialize request store") from None

    def _bind_database_key(self, conn: sqlite3.Connection) -> None:
        """Record/check the static anchor verifier in ``evidence_meta``.

        The stored value is a tag output only, never the key or its
        preimage. A mismatch means the database was initialised under a
        different trust root; refusing further use prevents silently
        forking the chain.
        """
        verifier = self._anchor.attest(_PURPOSE_KEY_CHECK, (_KEY_CHECK_PART,))
        if self._lock_path is not None:
            lock = _file_lock(self._lock_path)
        else:
            lock = contextlib.nullcontext()
        with lock:
            try:
                conn.execute("BEGIN IMMEDIATE")
                row = conn.execute(
                    "SELECT value FROM evidence_meta WHERE domain = ?",
                    (_META_KEY_CHECK,),
                ).fetchone()
                if row is None:
                    conn.execute(
                        "INSERT INTO evidence_meta (domain, value) VALUES (?, ?)",
                        (_META_KEY_CHECK, verifier),
                    )
                elif not self._anchor.verify_attestation(
                    _PURPOSE_KEY_CHECK, (_KEY_CHECK_PART,), row[0]
                ):
                    conn.execute("ROLLBACK")
                    raise IntegrityKeyMismatch(
                        "configured integrity key does not match the database"
                    )
                conn.execute("COMMIT")
            except IntegrityConfigurationError:
                raise
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

    @contextlib.contextmanager
    def _trust_guard(self):
        """Hold the cross-process trust lock for file-backed stores."""
        if self._lock_path is not None:
            with _file_lock(self._lock_path):
                yield
        else:
            yield

    def _link_hash(
        self,
        tenant_id: str,
        request_id: str,
        seq: int,
        status: str,
        occurred_at: str,
        predecessor: str,
    ) -> str:
        return self._anchor.attest(
            _PURPOSE_LINK,
            (
                tenant_id,
                request_id,
                str(seq),
                status,
                occurred_at,
                predecessor,
            ),
        )

    def _head_anchor(
        self,
        tenant_id: str,
        request_id: str,
        head: str,
        status: str,
        event_count: int,
    ) -> str:
        return self._anchor.attest(
            _PURPOSE_ANCHOR,
            (tenant_id, request_id, head, status, str(event_count)),
        )

    # ------------------------------------------------------------------
    # Writes
    # ------------------------------------------------------------------

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
                genesis_hash = self._link_hash(
                    tenant_id,
                    request_id,
                    0,
                    _STATUS_ACCEPTED,
                    created_at,
                    _GENESIS_PREDECESSOR,
                )
                head_label = self._head_anchor(
                    tenant_id, request_id, genesis_hash, _STATUS_ACCEPTED, 1
                )
                with self._trust_guard():
                    conn.execute("BEGIN IMMEDIATE")
                    try:
                        conn.execute(
                            "INSERT INTO requests ("
                            "request_id, tenant_id, idempotency_key, subject_id, "
                            "scopes_json, status, created_at, chain_hash, anchor_value"
                            ") VALUES (?, ?, ?, ?, ?, 'accepted', ?, ?, ?)",
                            (
                                request_id,
                                tenant_id,
                                idempotency_key,
                                subject_id,
                                scopes_json,
                                created_at,
                                genesis_hash,
                                head_label,
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
                        # accepted event, nor an event without its request.
                        conn.execute(
                            "INSERT INTO status_events ("
                            "tenant_id, request_id, seq, status, occurred_at, chain_hash"
                            ") VALUES (?, ?, 0, 'accepted', ?, ?)",
                            (tenant_id, request_id, created_at, genesis_hash),
                        )
                        conn.execute(
                            "INSERT INTO evidence_meta (domain, value) VALUES (?, ?)",
                            (_head_domain(tenant_id, request_id), head_label),
                        )
                    except sqlite3.Error:
                        conn.execute("ROLLBACK")
                        raise RuntimeError(
                            "failed to persist accepted request"
                        ) from None
                    conn.execute("COMMIT")
                    # External attestation follows the atomic SQLite
                    # commit; verification binds the two stores together.
                    self._publish_head(
                        _head_domain(tenant_id, request_id), head_label, conn
                    )
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
        cross-tenant ids raise :class:`RequestNotFound`; requests created
        before keyed evidence existed raise
        :class:`LegacyEvidenceUnsupported` and are never extended.
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
                with self._trust_guard():
                    try:
                        conn.execute("BEGIN IMMEDIATE")
                    except sqlite3.Error:
                        # Never surface the database engine's own error text.
                        raise RuntimeError(
                            "failed to persist status transition"
                        ) from None
                    try:
                        row = conn.execute(
                            "SELECT status, created_at, anchor_value FROM requests "
                            "WHERE tenant_id = ? AND request_id = ?",
                            (tenant_id, request_id),
                        ).fetchone()
                        if row is None:
                            # Same outcome for unknown ids and cross-tenant lookups.
                            conn.execute("ROLLBACK")
                            raise RequestNotFound("request not found")
                        current_status, created_at, current_anchor = row
                        if current_anchor is None:
                            # Unprotected legacy record: refuse to extend
                            # rather than silently treating it as anchored.
                            conn.execute("ROLLBACK")
                            raise LegacyEvidenceUnsupported(
                                "request predates protected audit evidence "
                                "and cannot be extended"
                            )
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
                        if latest is None or not _is_tag(latest[2]):
                            # Defensive only: every accepted request owns its
                            # seq-0 event with a valid link, so reaching here
                            # means the timeline invariant was broken out of
                            # band. Never fabricate a replacement link.
                            conn.execute("ROLLBACK")
                            raise RuntimeError(
                                "failed to persist status transition"
                            )
                        next_seq, latest_occurred_at, predecessor_hash = latest
                        occurred_at = _occurred_at_not_before(latest_occurred_at)
                        next_link_hash = self._link_hash(
                            tenant_id,
                            request_id,
                            next_seq + 1,
                            target_status,
                            occurred_at,
                            predecessor_hash,
                        )
                        next_anchor = self._head_anchor(
                            tenant_id,
                            request_id,
                            next_link_hash,
                            target_status,
                            next_seq + 2,
                        )
                        cursor = conn.execute(
                            "UPDATE requests SET status = ?, chain_hash = ?, "
                            "anchor_value = ? "
                            "WHERE tenant_id = ? AND request_id = ? AND status = ?",
                            (
                                target_status,
                                next_link_hash,
                                next_anchor,
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
                        # status update and head anchor.
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
                        if conn.execute(
                            "UPDATE evidence_meta SET value = ? WHERE domain = ?",
                            (next_anchor, _head_domain(tenant_id, request_id)),
                        ).rowcount != 1:
                            conn.execute("ROLLBACK")
                            raise RuntimeError(
                                "failed to persist status transition"
                            )
                        conn.execute("COMMIT")
                    except (
                        InvalidStatusTransition,
                        LegacyEvidenceUnsupported,
                        RequestNotFound,
                    ):
                        raise
                    except sqlite3.Error:
                        # Best-effort cleanup; the rollback failure must not mask
                        # the original problem or leak engine text.
                        try:
                            conn.execute("ROLLBACK")
                        except sqlite3.Error:
                            pass
                        raise RuntimeError(
                            "failed to persist status transition"
                        ) from None
                    # External attestation only after the durable commit.
                    self._publish_head(
                        _head_domain(tenant_id, request_id),
                        next_anchor,
                        conn,
                        failure_message="failed to persist status transition",
                    )
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

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------

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
        :meth:`audit`) and ``chain_hash`` (the keyed head of the audit
        chain as persisted, never recomputed). Unknown ids and
        cross-tenant lookups raise :class:`RequestNotFound`; requests
        predating keyed evidence raise
        :class:`LegacyEvidenceUnsupported`; non-string or empty arguments
        raise :class:`ValueError`.
        """
        tenant_id = _require_nonempty_str(tenant_id, "tenant_id")
        request_id = _require_nonempty_str(request_id, "request_id")
        if self._mem_conn is not None:
            with self._write_lock:
                return self._evidence(tenant_id, request_id)
        return self._evidence(tenant_id, request_id)

    def _evidence(self, tenant_id: str, request_id: str) -> dict[str, object]:
        status, head_hash, anchor, event_count = self._load_chain_head(
            tenant_id, request_id
        )
        if anchor is None:
            # A readable but unprotected (legacy) record is reported
            # explicitly rather than dressed up as verifiable evidence.
            raise LegacyEvidenceUnsupported(
                "request predates protected audit evidence"
            )
        # The stored head must be a well-formed tag; a malformed value
        # means the row was altered out of band and must not be reported
        # as evidence.
        if not _is_tag(head_hash):
            raise RequestNotFound("request not found")
        return {
            "request_id": request_id,
            "status": status,
            "event_count": event_count,
            "chain_hash": head_hash,
        }

    def verify_evidence(self, tenant_id: str, request_id: str) -> bool:
        """Verify the persisted audit chain for a request.

        Verification is strictly read-only: it recomputes each keyed link
        from the persisted rows and checks the head anchor against the
        request row, ``evidence_meta`` *and* the external head ledger,
        but never repairs, backfills or rewrites anything. Deleting,
        altering, inserting or reordering events, tampering with the
        request head, substituting events or heads across requests or
        tenants, and recomputing the whole database (events, heads and
        anchors) all yield ``False``, because the secret key and the
        attested head state live outside the database. Unprotected
        legacy records also return ``False``. Unknown ids and
        cross-tenant lookups raise :class:`RequestNotFound`; non-string
        or empty arguments raise :class:`ValueError`.
        """
        tenant_id = _require_nonempty_str(tenant_id, "tenant_id")
        request_id = _require_nonempty_str(request_id, "request_id")
        if self._mem_conn is not None:
            with self._write_lock:
                return self._verify_evidence(tenant_id, request_id)
        return self._verify_evidence(tenant_id, request_id)

    def _verify_evidence(self, tenant_id: str, request_id: str) -> bool:
        conn = self._connect()
        try:
            # Gate on the request row exactly like audit(): an empty
            # timeline must not distinguish "missing" from "foreign".
            # All reads and the external ledger check happen under one
            # cross-process lock, so a concurrent writer's database
            # commit and ledger update are observed as one atomic step.
            with self._trust_guard():
                try:
                    owner = conn.execute(
                        "SELECT status, chain_hash, anchor_value FROM requests "
                        "WHERE tenant_id = ? AND request_id = ?",
                        (tenant_id, request_id),
                    ).fetchone()
                    if owner is None:
                        raise RequestNotFound("request not found")
                    current_status, anchored_head, anchored_label = owner
                    # Unprotected legacy evidence is never trustworthy.
                    if anchored_label is None:
                        return False
                    if not _is_tag(anchored_head) or not _is_tag(anchored_label):
                        return False
                    meta_row = conn.execute(
                        "SELECT value FROM evidence_meta WHERE domain = ?",
                        (_head_domain(tenant_id, request_id),),
                    ).fetchone()
                    rows = conn.execute(
                        "SELECT seq, status, occurred_at, chain_hash "
                        "FROM status_events "
                        "WHERE tenant_id = ? AND request_id = ? ORDER BY seq",
                        (tenant_id, request_id),
                    ).fetchall()
                    external_heads = self._read_ledger()
                except RequestNotFound:
                    raise
                except sqlite3.Error:
                    # Never surface the database engine's own error text.
                    raise RuntimeError(
                        "failed to verify request evidence"
                    ) from None
        finally:
            self._release(conn)

        # The in-DB meta copy and the external ledger copy must both
        # agree with the request row before anything is recomputed.
        if meta_row is None or not _is_tag(meta_row[0]):
            return False
        if not hmac.compare_digest(meta_row[0], anchored_label):
            return False
        external_label = external_heads.get(_head_domain(tenant_id, request_id))
        if not _is_tag(external_label) or not hmac.compare_digest(
            external_label, anchored_label
        ):
            return False

        predecessor = _GENESIS_PREDECESSOR
        for expected_seq, row in enumerate(rows):
            seq, status, occurred_at, stored_hash = row
            # Gap-free sequences from zero: a deleted, inserted or
            # renumbered event cannot reach here unnoticed. Strict type
            # checks keep malformed (e.g. NULL) tampered rows from
            # reaching the tag preimage as anything but a failure.
            if (
                not isinstance(seq, int)
                or isinstance(seq, bool)
                or seq != expected_seq
                or not isinstance(status, str)
                or not isinstance(occurred_at, str)
                or not _is_tag(stored_hash)
            ):
                return False
            if not self._anchor.verify_attestation(
                _PURPOSE_LINK,
                (
                    tenant_id,
                    request_id,
                    str(seq),
                    status,
                    occurred_at,
                    predecessor,
                ),
                stored_hash,
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
        # Finally, the anchor must recompute under the external trust
        # root for exactly this head, status and event count.
        return self._anchor.verify_attestation(
            _PURPOSE_ANCHOR,
            (tenant_id, request_id, anchored_head, current_status, str(len(rows))),
            anchored_label,
        )

    def _load_chain_head(
        self, tenant_id: str, request_id: str
    ) -> tuple[str, str, str | None, int]:
        conn = self._connect()
        try:
            try:
                row = conn.execute(
                    "SELECT r.status, r.chain_hash, r.anchor_value, "
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
