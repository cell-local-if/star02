import json
import signal
import sys

from .httpapi import (
    AuthConfigError,
    DeferredRequestStore,
    build_server,
    load_auth_config,
)
from .requests import (
    RequestNotFound,
    RestoreConflict,
    BackupConflict,
    backup_database,
    read_audit_health,
    read_request_evidence,
    read_request_status,
    restore_backup,
)

_USAGE = "usage: python -m forgetting_evidence health"
_SERVE_USAGE = (
    "usage: python -m forgetting_evidence serve <database> <address> <port>\n"
    "       python -m forgetting_evidence serve --db <database> "
    "--host <address> --port <port> [--auth-file <auth-config>]"
)
# Restore's markers are fixed, detail-free text: the paths and any
# underlying error are never printed.
_RESTORE_USAGE = "restore_usage"
# Backup shares the same rule: fixed, detail-free markers only.
_BACKUP_USAGE = "backup_usage"
# Status shares the same rule: fixed, detail-free markers only.
_STATUS_USAGE = "status_usage"
# Evidence mirrors status: fixed, detail-free markers only.
_EVIDENCE_USAGE = "evidence_usage"
# Audit-health shares the same rule: fixed, detail-free markers only.
_AUDIT_HEALTH_USAGE = "audit_health_usage"

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

_STATUS_FLAG_ALIASES = {
    "--db": "db",
    "--tenant-id": "tenant_id",
    "--request-id": "request_id",
}
_STATUS_POSITIONAL_FIELDS = ("db", "tenant_id", "request_id")

_AUDIT_HEALTH_FLAG_ALIASES = {
    "--db": "db",
    "--database": "db",
    "--tenant-id": "tenant_id",
}
_AUDIT_HEALTH_POSITIONAL_FIELDS = ("db", "tenant_id")


def _parse_named_args(
    args: list[str],
    flag_aliases: dict[str, str],
    positional_fields: tuple[str, ...],
) -> dict[str, str] | None:
    values: dict[str, str] = {}
    positionals: list[str] = []
    index = 0
    while index < len(args):
        token = args[index]
        if "=" in token and token.split("=", 1)[0] in flag_aliases:
            name, value = token.split("=", 1)
            field = flag_aliases[name]
            if field in values or value == "":
                return None
            values[field] = value
        elif token in flag_aliases:
            field = flag_aliases[token]
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
        if len(positionals) != len(positional_fields):
            return None
        values = dict(zip(positional_fields, positionals))
    missing = [field for field in positional_fields if not values.get(field)]
    if missing:
        return None
    return values


def _parse_status_args(args: list[str]) -> dict[str, str] | None:
    return _parse_named_args(args, _STATUS_FLAG_ALIASES, _STATUS_POSITIONAL_FIELDS)


def _run_status(args: list[str]) -> int:
    parsed = _parse_status_args(args)
    if parsed is None:
        print(_STATUS_USAGE, file=sys.stderr)
        return 2
    # The lookup is strictly read-only: it never creates the database,
    # never migrates the schema and never writes bookkeeping. Every
    # storage problem -- a missing, unreadable, locked or corrupt
    # database -- collapses to the single fixed failure marker, and an
    # invalid, unknown or cross-tenant request id is indistinguishable
    # from a missing one. The path, the tenant, the request id and any
    # underlying error are never printed.
    try:
        record = read_request_status(
            parsed["db"], parsed["tenant_id"], parsed["request_id"]
        )
    except RequestNotFound:
        print("request_not_found", file=sys.stderr)
        return 3
    except (ValueError, OSError):
        print("status_failed", file=sys.stderr)
        return 2
    print(json.dumps(record, separators=(",", ":")))
    return 0


def _run_evidence(args: list[str]) -> int:
    # Evidence accepts the exact same two invocation styles as status --
    # three positionals or the three named flags -- so the two share one
    # parser; mixing styles, duplicates, empty values, unknown flags or a
    # wrong arity never reach storage.
    parsed = _parse_status_args(args)
    if parsed is None:
        print(_EVIDENCE_USAGE, file=sys.stderr)
        return 2
    # Strictly read-only like status: the database is never created,
    # migrated or repaired. A tampered chain is still a successful read
    # with verified=false; only an invalid/unknown/cross-tenant id (or a
    # record that cannot form a legal evidence summary) is not-found, and
    # every storage problem collapses to the fixed failure marker. The
    # path, tenant, request id, SQL and underlying error are never
    # printed, and the JSON line is only emitted once the read succeeds.
    try:
        record = read_request_evidence(
            parsed["db"], parsed["tenant_id"], parsed["request_id"]
        )
    except RequestNotFound:
        print("evidence_not_found", file=sys.stderr)
        return 3
    except (ValueError, OSError):
        print("evidence_failed", file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "request_id": record["request_id"],
                "status": record["status"],
                "event_count": record["event_count"],
                "chain_hash": record["chain_hash"],
                "verified": record["verified"],
            },
            separators=(",", ":"),
        )
    )
    return 0


def _run_audit_health(args: list[str]) -> int:
    # Audit-health accepts exactly two invocation styles -- two
    # positionals (database, tenant-id) or the named flags (--db or
    # --database, plus --tenant-id) -- parsed by the same strict rules
    # as status and evidence: mixing styles, duplicates, empty values,
    # unknown flags or a wrong arity never reach storage.
    parsed = _parse_named_args(
        args, _AUDIT_HEALTH_FLAG_ALIASES, _AUDIT_HEALTH_POSITIONAL_FIELDS
    )
    if parsed is None:
        print(_AUDIT_HEALTH_USAGE, file=sys.stderr)
        return 2
    # Strictly read-only: the database is never created, migrated,
    # repaired or overwritten, and no partial snapshot is ever emitted.
    # Unverified evidence is still a successful read -- its stable
    # reason codes are reported as-is; only a missing, unreadable,
    # locked or corrupt database (or a snapshot that cannot be read
    # consistently) is the fixed failure marker. The path, the tenant,
    # request ids, SQL and any underlying error are never printed, and
    # the JSON line is only emitted once the read succeeds.
    try:
        snapshot = read_audit_health(parsed["db"], parsed["tenant_id"])
    except (ValueError, OSError):
        print("audit_health_failed", file=sys.stderr)
        return 3
    print(
        json.dumps(
            {
                "total": snapshot["total"],
                "statuses": snapshot["statuses"],
                "verified": snapshot["verified"],
                "unverified": snapshot["unverified"],
                "reasons": snapshot["reasons"],
            },
            separators=(",", ":"),
        )
    )
    return 0


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


def _run_backup(args: list[str]) -> int:
    # Exactly the source database and the snapshot target are
    # accepted; any other arity is the fixed usage marker at exit 2.
    if len(args) != 2:
        print(_BACKUP_USAGE, file=sys.stderr)
        return 2
    database_path, snapshot_path = args
    # The export is strictly read-only at the source: it never creates
    # or migrates the database, never writes bookkeeping and never
    # creates the target directory. Every storage problem -- a missing,
    # unreadable, locked or corrupt source, an empty, directory or
    # unusable target, a staging failure or a snapshot that fails its
    # openability, structure or consistency checks -- collapses to the
    # single fixed failure marker; only an already claimed target,
    # including one won by a concurrent backup, is the conflict marker.
    # The paths, SQL and any underlying error are never printed.
    try:
        backup_database(database_path, snapshot_path)
    except BackupConflict:
        print("backup_conflict", file=sys.stderr)
        return 3
    except (ValueError, OSError):
        print("backup_failed", file=sys.stderr)
        return 2
    print(json.dumps({"status": "backed_up"}, separators=(",", ":")))
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
    if args and args[0] == "backup":
        return _run_backup(args[1:])
    if args and args[0] == "status":
        return _run_status(args[1:])
    if args and args[0] == "evidence":
        return _run_evidence(args[1:])
    if args and args[0] == "audit-health":
        return _run_audit_health(args[1:])
    print(_USAGE, file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
