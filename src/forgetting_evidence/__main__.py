import json
import os
import signal
import sqlite3
import sys
import urllib.parse

from .httpapi import (
    AuthConfigError,
    DeferredRequestStore,
    build_server,
    load_auth_config,
)
from .requests import RestoreConflict, restore_backup

_USAGE = "usage: python -m forgetting_evidence health"
_SERVE_USAGE = (
    "usage: python -m forgetting_evidence serve <database> <address> <port>\n"
    "       python -m forgetting_evidence serve --db <database> "
    "--host <address> --port <port> [--auth-file <auth-config>]"
)
# Restore's markers are fixed, detail-free text: the paths and any
# underlying error are never printed.
_RESTORE_USAGE = "restore_usage"
# Status shares the same discipline: the markers are fixed text and
# never embed the tenant, the request id, SQL, the underlying error or
# any path.
_STATUS_USAGE = "status_usage"

_FLAG_ALIASES = {
    "--db": "db",
    "--database": "db",
    "--host": "host",
    "--address": "host",
    "--bind": "host",
    "--port": "port",
    "--auth-file": "auth_file",
}
_POSITIONAL_FIELDS = ("db", "host", "port")


def _parse_serve_args(args: list[str]) -> dict[str, str] | None:
    values: dict[str, str] = {}
    positionals: list[str] = []
    index = 0
    while index < len(args):
        token = args[index]
        if "=" in token and token.split("=", 1)[0] in _FLAG_ALIASES:
            name, value = token.split("=", 1)
            field = _FLAG_ALIASES[name]
            if field in values or value == "":
                return None
            values[field] = value
        elif token in _FLAG_ALIASES:
            field = _FLAG_ALIASES[token]
            if field in values or index + 1 >= len(args):
                return None
            values[field] = args[index + 1]
            index += 1
        elif token.startswith("--"):
            return None
        else:
            positionals.append(token)
        index += 1
    if positionals and values:
        # Avoid ambiguity when both styles are mixed.
        return None
    if positionals:
        if len(positionals) != 3:
            return None
        values = dict(zip(_POSITIONAL_FIELDS, positionals))
    missing = [field for field in _POSITIONAL_FIELDS if not values.get(field)]
    if missing:
        return None
    return values


def _run_serve(args: list[str]) -> int:
    parsed = _parse_serve_args(args)
    if parsed is None:
        print(_SERVE_USAGE, file=sys.stderr)
        return 2
    try:
        port = int(parsed["port"])
    except ValueError:
        print(_SERVE_USAGE, file=sys.stderr)
        return 2
    if not 1 <= port <= 65535:
        print(_SERVE_USAGE, file=sys.stderr)
        return 2

    # The auth configuration is read and validated exactly once, before
    # the port is bound. A missing/unreadable file or any non-compliant
    # configuration refuses startup: no socket is opened and the process
    # exits with status 2 and the fixed marker only -- the path, tokens
    # and configuration content are never printed.
    auth = None
    if parsed.get("auth_file"):
        try:
            auth = load_auth_config(parsed["auth_file"])
        except AuthConfigError:
            print("auth_config_invalid", file=sys.stderr)
            return 2

    # The store opens (creating the file and required tables) at startup.
    # If the database cannot be created the service still binds: business
    # requests then answer 503 storage_unavailable and the store retries
    # initialization on the next request so a repaired path self-heals.
    store = DeferredRequestStore(parsed["db"])
    try:
        server = build_server(store, parsed["host"], port, auth)
    except OSError:
        print("address_in_use", file=sys.stderr)
        return 1

    def _stop(_signum, _frame):
        raise KeyboardInterrupt

    previous_sigterm = signal.signal(signal.SIGTERM, _stop)
    try:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
    finally:
        signal.signal(signal.SIGTERM, previous_sigterm)
    return 0


def _run_restore(args: list[str]) -> int:
    # Exactly the snapshot and the destination database are accepted;
    # any other arity is the fixed usage marker at exit 2.
    if len(args) != 2:
        print(_RESTORE_USAGE, file=sys.stderr)
        return 2
    snapshot_path, database_path = args
    try:
        restore_backup(snapshot_path, database_path)
    except RestoreConflict:
        print("restore_conflict", file=sys.stderr)
        return 3
    except (OSError, ValueError):
        # Invalid path values share the single failure marker of a
        # missing, unreadable or inconsistent snapshot.
        print("restore_failed", file=sys.stderr)
        return 2
    print(json.dumps({"status": "restored"}, separators=(",", ":")))
    return 0


_STATUS_FLAG_ALIASES = {
    "--db": "db",
    "--tenant-id": "tenant_id",
    "--request-id": "request_id",
}
_STATUS_POSITIONAL_FIELDS = ("db", "tenant_id", "request_id")


def _parse_status_args(args: list[str]) -> dict[str, str] | None:
    values: dict[str, str] = {}
    positionals: list[str] = []
    index = 0
    while index < len(args):
        token = args[index]
        if "=" in token and token.split("=", 1)[0] in _STATUS_FLAG_ALIASES:
            name, value = token.split("=", 1)
            field = _STATUS_FLAG_ALIASES[name]
            if field in values:
                return None
            values[field] = value
        elif token in _STATUS_FLAG_ALIASES:
            field = _STATUS_FLAG_ALIASES[token]
            if field in values or index + 1 >= len(args):
                return None
            values[field] = args[index + 1]
            index += 1
        elif token.startswith("--"):
            return None
        else:
            positionals.append(token)
        index += 1
    if positionals and values:
        # The positional and flag spellings are equivalent but never
        # mixable in a single invocation.
        return None
    if positionals:
        if len(positionals) != len(_STATUS_POSITIONAL_FIELDS):
            return None
        values = dict(zip(_STATUS_POSITIONAL_FIELDS, positionals))
    if any(field not in values for field in _STATUS_POSITIONAL_FIELDS):
        return None
    return values


def _run_status(args: list[str]) -> int:
    parsed = _parse_status_args(args)
    if parsed is None:
        print(_STATUS_USAGE, file=sys.stderr)
        return 2
    tenant_id = parsed["tenant_id"]
    request_id = parsed["request_id"]
    # Validation mirrors get_status: an invalid tenant is caller error
    # (status_failed), while an invalid request id is indistinguishable
    # from an unknown or cross-tenant one (request_not_found).
    if not tenant_id:
        print("status_failed", file=sys.stderr)
        return 2
    if not request_id:
        print("request_not_found", file=sys.stderr)
        return 3
    db_path = parsed["db"]
    # The command is strictly read-only: it never creates the database,
    # never migrates the schema and never writes bookkeeping. A missing
    # or non-file path is the same fixed failure as an unreadable,
    # locked or corrupt database -- the underlying exception type never
    # crosses the command line.
    if not db_path or not os.path.isfile(db_path):
        print("status_failed", file=sys.stderr)
        return 2
    uri = "file:" + urllib.parse.quote(os.path.abspath(db_path)) + "?mode=ro"
    try:
        conn = sqlite3.connect(uri, uri=True)
    except (sqlite3.Error, OSError):
        print("status_failed", file=sys.stderr)
        return 2
    try:
        try:
            row = conn.execute(
                "SELECT request_id, status, created_at FROM requests "
                "WHERE tenant_id = ? AND request_id = ?",
                (tenant_id, request_id),
            ).fetchone()
        except (sqlite3.Error, OSError):
            print("status_failed", file=sys.stderr)
            return 2
    finally:
        conn.close()
    if row is None:
        print("request_not_found", file=sys.stderr)
        return 3
    # The same fixed shape and field order as RequestStore.get_status.
    record = {"request_id": row[0], "status": row[1], "created_at": row[2]}
    print(json.dumps(record, separators=(",", ":")))
    return 0


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args == ["health"]:
        print(json.dumps({"service": "forgetting-evidence", "status": "ok"}, sort_keys=True))
        return 0
    if args and args[0] == "serve":
        return _run_serve(args[1:])
    if args and args[0] == "restore":
        return _run_restore(args[1:])
    if args and args[0] == "status":
        return _run_status(args[1:])
    print(_USAGE, file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
