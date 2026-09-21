"""Protected anchor material kept outside the audit SQLite database.

The audit chain in ``requests.py`` derives its integrity from material an
attacker who rewrites the SQLite file cannot also reproduce: a symmetric
secret and, derived from it per chain head, HMAC anchors recorded in a
separate file.

Design constraints honoured here:

* The master secret is auto-provisioned with :func:`secrets.token_bytes`
  into ``<db>.anchor.key`` with mode ``0600`` when no explicit key / key
  file is configured, so a database reopened by a fresh
  :class:`~forgetting_evidence.requests.RequestStore` instance verifies
  with no extra caller setup.
* The anchor journal lives at ``<db>.anchor``, mode ``0600``, and is
  rewritten atomically (temp file in the same directory + ``os.replace``
  + ``fsync``) on every chain extension. It never sits inside SQLite.
* Neither the master secret nor any HMAC key-derivation preimage is ever
  written into the database, printed, logged, or returned in a receipt.
  Anchors are keyed only by non-sensitive coordinates
  ``(tenant_id, request_id)``.
* Multi-process writers are serialized by SQLite ``BEGIN IMMEDIATE`` in
  the caller; every flush additionally re-reads and merges the durable
  journal first, so a journal replacement committed by another process
  can never be silently dropped. Verification always re-reads the
  durable journal rather than trusting a process-local cache.

The journal format is a JSON object::

    {"version": 1, "entries": [["<tenant>", "<request>", "<hex64 mac>"], ...]}

Entries are ordered by (tenant_id, request_id) purely for deterministic
on-disk output. The mac binds a domain-separated, length-prefixed
preimage of the coordinates and chain head, so an attacker who fully
controls the database contents but lacks the master secret cannot mint
valid macs.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import tempfile
import threading

__all__ = ["AnchorConfig", "AnchorError", "LegacyDataError"]


class AnchorError(Exception):
    """Protected anchor material is missing, unreadable or inconsistent.

    The message deliberately carries no anchor content: it stays safe to
    surface through the store's generic error paths.
    """


class LegacyDataError(AnchorError):
    """Existing data predates protected anchoring and cannot be trusted.

    Raised when a write or verification encounters rows that were never
    anchored against protected material. The unprotected rows themselves
    are left untouched.
    """


# Separate domains so a mac minted for one purpose can never be valid in
# another context even if preimages happen to collide.
_DOMAIN_HEAD_MAC = b"forgetting-evidence|head-mac|v1"
# 256-bit master secret; token_bytes draws from the OS CSPRNG. The mac
# stored per chain head is a 64-char hex string.
_KEY_BYTES = 32
_MAX_KEY_FILE_BYTES = 4096
_ANCHOR_FILE_MODE = 0o600
_V1 = 1


def _lp(value: str) -> bytes:
    """Length-prefix a text field for MAC preimages."""
    raw = value.encode("utf-8")
    return len(raw).to_bytes(8, "big") + raw


def _head_mac(master_key: bytes, tenant_id: str, request_id: str, head: str) -> str:
    mac = hmac.new(master_key, _DOMAIN_HEAD_MAC, hashlib.sha256)
    mac.update(_lp(tenant_id))
    mac.update(_lp(request_id))
    mac.update(_lp(head))
    return mac.hexdigest()


class AnchorConfig:
    """Optional, named configuration for protected anchoring.

    All parameters are keyword-only; plain ``RequestStore(db_path)``
    keeps working with auto-provisioned, file-backed material::

        AnchorConfig(key=b"...")                 # injected/ephemeral key
        AnchorConfig(key_file="/path/key")       # raw secret in a file
        AnchorConfig(key_hex="...")              # hex-encoded secret
        AnchorConfig(anchor_file="/path/journal")
        AnchorConfig(auto_init=True)             # default: provision files
        AnchorConfig(auto_init=False)            # strictly read existing

    The raw key and its HMAC derivation preimages are never persisted by
    this module outside the dedicated key file, never written into
    SQLite, and never appear in return values, exceptions or logs.
    """

    __slots__ = ("key", "key_file", "anchor_file", "auto_init")

    def __init__(
        self,
        *,
        key: "str | bytes | None" = None,
        key_file: "str | os.PathLike[str] | None" = None,
        key_hex: "str | None" = None,
        anchor_file: "str | os.PathLike[str] | None" = None,
        auto_init: bool = True,
    ) -> None:
        if key is not None and key_hex is not None:
            raise ValueError("anchor config accepts at most one key source")
        if key is not None:
            key = key.encode("utf-8") if isinstance(key, str) else bytes(key)
        elif key_hex is not None:
            if not isinstance(key_hex, str):
                raise ValueError("anchor key_hex must be hexadecimal")
            try:
                key = bytes.fromhex(key_hex)
            except ValueError as exc:
                raise ValueError("anchor key_hex must be hexadecimal") from exc
        if key is not None and not key:
            raise ValueError("anchor key must be non-empty")
        if key is not None and len(key) > 1024:
            raise ValueError("anchor key is too long")
        if key_file is not None:
            if not isinstance(key_file, (str, os.PathLike)):
                raise ValueError("anchor key_file must be a path")
            key_file = os.fspath(key_file)
        if anchor_file is not None:
            if not isinstance(anchor_file, (str, os.PathLike)):
                raise ValueError("anchor file must be a path")
            anchor_file = os.fspath(anchor_file)
        self.key = key
        self.key_file = key_file
        self.anchor_file = anchor_file
        self.auto_init = bool(auto_init)


class _AnchorBackend:
    """Loads the master secret and reads/writes the protected journal."""

    __slots__ = (
        "_cfg",
        "_default_key_path",
        "_default_anchor_path",
        "_master_key",
        "_mem_entries",
        "_lock",
    )

    def __init__(self, db_path: str, cfg: AnchorConfig | None) -> None:
        self._cfg = cfg if cfg is not None else AnchorConfig()
        if db_path == ":memory:":
            # No durable location exists for an in-memory database: keep
            # the protected material process-local (still fully isolated
            # from the SQLite content) unless the caller named files.
            self._default_key_path: str | None = self._cfg.key_file
            self._default_anchor_path: str | None = self._cfg.anchor_file
        else:
            self._default_key_path = (
                self._cfg.key_file if self._cfg.key_file is not None
                else db_path + ".anchor.key"
            )
            self._default_anchor_path = (
                self._cfg.anchor_file if self._cfg.anchor_file is not None
                else db_path + ".anchor"
            )
        self._master_key: bytes | None = None
        self._mem_entries: dict[tuple[str, str], str] = {}
        self._lock = threading.RLock()

    # ------------------------------------------------------------ paths
    @property
    def key_path(self) -> str | None:
        return self._default_key_path

    @property
    def anchor_path(self) -> str | None:
        return self._default_anchor_path

    # ----------------------------------------------------- master key
    def _read_key_file(self, path: str) -> bytes:
        try:
            with open(path, "rb") as handle:
                data = handle.read()
        except OSError:
            raise AnchorError("protected key is unavailable") from None
        if not data or len(data) > _MAX_KEY_FILE_BYTES:
            raise AnchorError("protected key is unavailable")
        return data

    def _create_key_file(self, path: str) -> bytes:
        parent = os.path.dirname(os.path.abspath(path)) or "."
        os.makedirs(parent, exist_ok=True)
        data = secrets.token_bytes(_KEY_BYTES)
        # O_EXCL makes first-writer-wins across processes exact: two
        # stores initializing the same database cannot mint two keys.
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        try:
            fd = os.open(path, flags, _ANCHOR_FILE_MODE)
            try:
                os.fchmod(fd, _ANCHOR_FILE_MODE)
                os.write(fd, data)
                os.fsync(fd)
            finally:
                os.close(fd)
        except FileExistsError:
            return self._read_key_file(path)
        except OSError:
            raise AnchorError("could not initialize protected key") from None
        return data

    def _load_key(self, *, create: bool) -> bytes:
        if self._cfg.key is not None:
            return self._cfg.key
        path = self.key_path
        if path is None:
            # In-memory database with process-local material: a fresh
            # random key per process. (A :memory: database itself cannot
            # outlive the process, so cross-rebuild verification is moot
            # unless the caller configured explicit file paths.)
            if self._master_key is not None:
                return self._master_key
            data = secrets.token_bytes(_KEY_BYTES)
            self._master_key = data
            return data
        if os.path.exists(path):
            return self._read_key_file(path)
        if not create:
            raise AnchorError("protected key is unavailable")
        if not self._cfg.auto_init:
            raise AnchorError("protected key is unavailable")
        return self._create_key_file(path)

    def _key(self, *, create: bool = False) -> bytes:
        key = self._master_key
        if key is not None:
            return key
        with self._lock:
            if self._master_key is None:
                self._master_key = self._load_key(create=create)
            return self._master_key

    def prepare_for_read(self) -> None:
        """Load existing key material for a read-only open.

        Never creates files. A missing key is tolerated here (a
        brand-new or legacy database has none); a present-but-unreadable
        key is also tolerated here so opening a store never fails over
        protected-material state — the first operation that actually
        needs the key reports the explicit, non-leaking failure instead.
        """
        with self._lock:
            if self._cfg.key is not None:
                return
            path = self.key_path
            if path is not None and os.path.exists(path):
                try:
                    self._master_key = self._read_key_file(path)
                except AnchorError:
                    # Leave unset; _key() re-attempts and callers map the
                    # failure to their explicit result.
                    self._master_key = None

    # ------------------------------------------------------ journal IO
    def _read_journal(self) -> dict[tuple[str, str], str]:
        path = self.anchor_path
        if path is None:
            # Process-local journal for a purely in-memory database.
            return dict(self._mem_entries)
        if not os.path.exists(path):
            return {}
        try:
            with open(path, "rb") as handle:
                raw = handle.read()
        except OSError:
            raise AnchorError("protected anchor journal is unavailable") from None
        if not raw:
            return {}
        try:
            doc = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise AnchorError("protected anchor journal is unavailable") from None
        return self._parse_doc(doc)

    @staticmethod
    def _parse_doc(doc: object) -> dict[tuple[str, str], str]:
        if not isinstance(doc, dict) or doc.get("version") != _V1:
            raise AnchorError("protected anchor journal is unavailable")
        raw_entries = doc.get("entries")
        if not isinstance(raw_entries, list):
            raise AnchorError("protected anchor journal is unavailable")
        entries: dict[tuple[str, str], str] = {}
        for item in raw_entries:
            if (
                not isinstance(item, list)
                or len(item) != 3
                or not all(isinstance(part, str) for part in item)
            ):
                raise AnchorError("protected anchor journal is unavailable")
            tenant_id, request_id, mac = item
            if len(mac) != 64:
                raise AnchorError("protected anchor journal is unavailable")
            entries[(tenant_id, request_id)] = mac
        if len(entries) != len(raw_entries):
            raise AnchorError("protected anchor journal is unavailable")
        return entries

    def load_disk_entries(self) -> dict[tuple[str, str], str]:
        """Read and return the durable journal (fresh, never cached)."""
        with self._lock:
            return self._read_journal()

    def disk_anchor(self, tenant_id: str, request_id: str) -> str | None:
        """The durable anchor for one coordinate, re-read from storage."""
        return self.load_disk_entries().get((tenant_id, request_id))

    def verify_mac(self, tenant_id: str, request_id: str, head: str, mac: str) -> bool:
        return hmac.compare_digest(
            _head_mac(self._key(create=False), tenant_id, request_id, head), mac
        )

    def commit_anchor(
        self,
        tenant_id: str,
        request_id: str,
        head: str,
        previous_mac: str | None,
    ) -> dict[tuple[str, str], str]:
        """Persist the anchor for ``(tenant, request)`` at ``head``.

        ``previous_mac`` is the durable anchor observed by the caller
        inside its database write transaction (``None`` for a new
        request). The durable journal is re-read and merged before the
        replacement is written, so concurrent commits on *other*
        coordinates are preserved; a concurrent change to *this*
        coordinate aborts the caller's transaction.

        Returns the journal's contents as they were immediately before
        the replacement, so the caller can restore them if the
        surrounding database commit subsequently fails.

        Must be called while the caller holds the database's write
        transaction: SQLite's ``BEGIN IMMEDIATE`` lock is what makes the
        read-merge-replace sequence multi-process safe.
        """
        with self._lock:
            key = self._key(create=True)
            previous = self._read_journal()
            current = previous.get((tenant_id, request_id))
            if current != previous_mac:
                raise AnchorError("protected anchor changed concurrently")
            entries = dict(previous)
            entries[(tenant_id, request_id)] = _head_mac(
                key, tenant_id, request_id, head
            )
            self._flush(entries)
            return previous

    def restore_anchor(
        self,
        tenant_id: str,
        request_id: str,
        previous_mac: str | None,
    ) -> None:
        """Undo one coordinate's replacement, preserving other entries.

        Used when the surrounding database commit fails after the
        journal was replaced. ``previous_mac`` is the coordinate's
        pre-transaction mac (``None`` when the request was newly
        created). The durable journal is re-read first so anchors
        committed by other processes for other coordinates survive.
        """
        with self._lock:
            entries = self._read_journal()
            if previous_mac is None:
                entries.pop((tenant_id, request_id), None)
            else:
                entries[(tenant_id, request_id)] = previous_mac
            self._flush(entries)

    def _flush(self, entries: dict[tuple[str, str], str]) -> None:
        path = self.anchor_path
        if path is None:
            # Process-local storage for a purely in-memory database.
            self._mem_entries = dict(entries)
            return
        if not self._cfg.auto_init and not os.path.exists(path):
            raise AnchorError("protected anchor journal is unavailable")
        parent = os.path.dirname(os.path.abspath(path)) or "."
        os.makedirs(parent, exist_ok=True)
        doc = {
            "version": _V1,
            "entries": [
                [tenant_id, request_id, mac]
                for (tenant_id, request_id), mac in sorted(entries.items())
            ],
        }
        payload = json.dumps(doc, ensure_ascii=False, separators=(",", ":")).encode(
            "utf-8"
        )
        # Named temp file in the SAME directory so os.replace is atomic
        # on POSIX; 0600 from creation.
        fd, tmp_path = tempfile.mkstemp(prefix=".anchor.", suffix=".tmp", dir=parent)
        closed = False
        try:
            os.fchmod(fd, _ANCHOR_FILE_MODE)
            os.write(fd, payload)
            os.fsync(fd)
            os.close(fd)
            closed = True
            os.replace(tmp_path, path)
            # Best-effort directory fsync so the rename survives a crash.
            try:
                dir_fd = os.open(parent, os.O_RDONLY)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
            except OSError:
                pass
        except OSError:
            raise AnchorError("could not persist protected anchor") from None
        finally:
            if not closed:
                try:
                    os.close(fd)
                except OSError:
                    pass
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
