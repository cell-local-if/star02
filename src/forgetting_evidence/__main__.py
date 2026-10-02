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
    AuditBundleUnavailable,
    RequestNotFound,
    RequestStore,
)

_USAGE = "usage: python -m forgetting_evidence health"
_SERVE_USAGE = (
    "usage: python -m forgetting_evidence serve <database> <address> <port>\n"
    "       python -m forgetting_evidence serve --db <database> "
    "--host <address> --port <port> [--auth-file <auth-config>]"
)

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

# Fixed, detail-free error marker shared by the bundle hand-off commands.
# It names only the failure category -- never a tenant, request id,
# secret, subject, raw scope, SQL text, file path or stack trace.
_INVALID_INPUT = '{"error":"invalid_input"}\n'
_NOT_FOUND = '{"error":"not_found"}\n'
_BUNDLE_UNAVAILABLE = '{"error":"bundle_unavailable"}\n'
_STORAGE_UNAVAILABLE = '{"error":"storage_unavailable"}\n'


def _parse_flag_args(args: list[str], flags: dict[str, str]) -> dict[str, str] | None:
    """Parse ``--flag value`` / ``--flag=value`` options, no positionals.

    Returns the field mapping, or ``None`` on a duplicate, an empty
    value, an unknown ``--`` option or a stray positional token.
    """
    values: dict[str, str] = {}
    index = 0
    while index < len(args):
        token = args[index]
        if "=" in token and token.split("=", 1)[0] in flags:
            name, value = token.split("=", 1)
            field = flags[name]
            if field in values or value == "":
                return None
            values[field] = value
        elif token in flags:
            field = flags[token]
            if field in values or index + 1 >= len(args):
                return None
            values[field] = args[index + 1]
            index += 1
        else:
            return None
        index += 1
    return values


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


# -- library-external evidence bundle hand-off -------------------------

# export-bundle reads an existing database strictly read-only and hands
# the settled chain to an off-site party; verify-bundle and
# diagnose-bundle are fully offline and never touch a database. All
# three are read-only: neither creates a database nor writes a database,
# inspection bookkeeping row or evidence file. Every failure is one
# fixed, detail-free single-line JSON marker -- no secret, subject, raw
# scope, SQL text, file path or traceback is ever emitted.


def _run_export_bundle(args: list[str]) -> int:
    parsed = _parse_flag_args(
        args,
        {
            "--db": "db",
            "--database": "db",
            "--tenant-id": "tenant_id",
            "--request-id": "request_id",
        },
    )
    if parsed is None or not all(
        parsed.get(field) for field in ("db", "tenant_id", "request_id")
    ):
        sys.stderr.write(_INVALID_INPUT)
        return 2
    try:
        bundle = RequestStore.export_existing_audit_bundle(
            parsed["db"], parsed["tenant_id"], parsed["request_id"]
        )
    except (ValueError, TypeError):
        sys.stderr.write(_INVALID_INPUT)
        return 2
    except RequestNotFound:
        # Identical outcome for unknown ids and cross-tenant lookups.
        sys.stdout.write(_NOT_FOUND)
        return 2
    except AuditBundleUnavailable:
        sys.stdout.write(_BUNDLE_UNAVAILABLE)
        return 1
    except OSError:
        sys.stdout.write(_STORAGE_UNAVAILABLE)
        return 3
    # The existing single-line JSON text, retaining its trailing newline.
    sys.stdout.write(bundle)
    return 0


def _load_bundle_secrets(path: str) -> dict[int, str]:
    """Read and validate the generation-to-secret JSON mapping.

    A UTF-8 JSON object mapping decimal generation strings to non-empty
    secret strings. Any missing/unreadable file, encoding error, parse
    failure or shape violation raises :class:`ValueError` so the caller
    reports the single ``invalid_input`` marker; the path and the secret
    material are never placed in a message.
    """
    with open(path, "rb") as handle:
        raw = handle.read()
    try:
        decoded = raw.decode("utf-8")
        loaded = json.loads(decoded)
    except (UnicodeDecodeError, ValueError):
        raise ValueError("invalid secrets mapping") from None
    if not isinstance(loaded, dict) or not loaded:
        raise ValueError("invalid secrets mapping")
    secrets: dict[int, str] = {}
    for generation, secret in loaded.items():
        # JSON object keys arrive as strings; only decimal generation
        # numerals are accepted (no sign, no whitespace, no leading
        # zero beyond a single zero, and zero itself is rejected).
        if (
            not isinstance(generation, str)
            or not generation.isascii()
            or not generation.isdigit()
            or (len(generation) > 1 and generation[0] == "0")
            or generation == "0"
            or not isinstance(secret, str)
            or not secret
        ):
            raise ValueError("invalid secrets mapping")
        secrets[int(generation)] = secret
    return secrets


def _read_bundle_stdin() -> str:
    """Read the evidence bundle from standard input as UTF-8 text."""
    try:
        data = sys.stdin.buffer.read()
    except (OSError, ValueError):
        raise ValueError("invalid bundle") from None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("invalid bundle") from None


def _run_verify_bundle(args: list[str]) -> int:
    parsed = _parse_flag_args(args, {"--secrets": "secrets"})
    if parsed is None or not parsed.get("secrets"):
        sys.stderr.write(_INVALID_INPUT)
        return 2
    try:
        secrets = _load_bundle_secrets(parsed["secrets"])
        bundle_text = _read_bundle_stdin()
        trusted = RequestStore.verify_audit_bundle(bundle_text, secrets)
    except (ValueError, TypeError, OSError):
        sys.stderr.write(_INVALID_INPUT)
        return 2
    sys.stdout.write('{"trusted":true}\n' if trusted else '{"trusted":false}\n')
    return 0 if trusted else 1


def _run_diagnose_bundle(args: list[str]) -> int:
    parsed = _parse_flag_args(args, {"--secrets": "secrets"})
    if parsed is None or not parsed.get("secrets"):
        sys.stderr.write(_INVALID_INPUT)
        return 2
    try:
        secrets = _load_bundle_secrets(parsed["secrets"])
        bundle_text = _read_bundle_stdin()
        result = RequestStore.diagnose_audit_bundle(bundle_text, secrets)
    except (ValueError, TypeError, OSError):
        sys.stderr.write(_INVALID_INPUT)
        return 2
    # The existing single-line diagnosis text; trusted/reasons ordering
    # and the stable reason codes come straight from the storage layer.
    sys.stdout.write(result)
    return 0 if result.startswith('{"trusted":true') else 1


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args == ["health"]:
        print(json.dumps({"service": "forgetting-evidence", "status": "ok"}, sort_keys=True))
        return 0
    if args and args[0] == "serve":
        return _run_serve(args[1:])
    if args and args[0] == "export-bundle":
        return _run_export_bundle(args[1:])
    if args and args[0] == "verify-bundle":
        return _run_verify_bundle(args[1:])
    if args and args[0] == "diagnose-bundle":
        return _run_diagnose_bundle(args[1:])
    print(_USAGE, file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
