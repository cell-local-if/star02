import json
import re
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
    export_existing_audit_bundle,
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

# Flags of the three read-only evidence-bundle commands. Each names a
# required, non-empty value that may appear exactly once; both
# ``--flag value`` and ``--flag=value`` are accepted.
_EXPORT_BUNDLE_FLAGS = {
    "--db": "db",
    "--tenant-id": "tenant_id",
    "--request-id": "request_id",
}
_SECRETS_FLAGS = {"--secrets": "secrets"}

# Canonical decimal strings of positive integer generations: no sign,
# no leading zero, digits only.
_GENERATION_DECIMAL_RE = re.compile(r"[1-9][0-9]*")


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


def _parse_named_flags(
    args: list[str], flags: dict[str, str]
) -> dict[str, str] | None:
    """Parse only ``--flag value`` / ``--flag=value`` named arguments.

    Every flag in *flags* must appear exactly once with a non-empty
    value; any positional token, unknown flag, duplicate flag or empty
    value makes the whole invocation caller error.
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
            value = args[index + 1]
            if value == "":
                return None
            values[field] = value
            index += 1
        else:
            return None
        index += 1
    if set(values) != set(flags.values()):
        return None
    return values


def _emit(stream, text: str) -> None:
    """Write *text* as UTF-8, falling back to the text stream in tests.

    Real standard streams carry a binary buffer, so output is encoded
    explicitly and a non-UTF-8 locale can never corrupt a bundle or its
    non-ASCII tenant string; an in-memory text stream (unit-test
    redirection) has no buffer and accepts the text directly.
    """
    buffer = getattr(stream, "buffer", None)
    if buffer is not None:
        buffer.write(text.encode("utf-8"))
        buffer.flush()
    else:
        stream.write(text)
        stream.flush()


def _error_line(code: str) -> str:
    return (
        json.dumps({"error": code}, ensure_ascii=False, separators=(",", ":"))
        + "\n"
    )


def _invalid_input() -> int:
    """The one detail-free caller-error outcome for the bundle commands.

    stdout stays empty and stderr receives exactly the fixed JSON
    marker; the offending argument, file path, secret material or
    parse detail is never printed.
    """
    _emit(sys.stderr, _error_line("invalid_input"))
    return 2


def _read_bundle_stdin() -> str:
    """Read the evidence bundle presented on standard input as UTF-8."""
    buffer = getattr(sys.stdin, "buffer", None)
    if buffer is not None:
        return buffer.read().decode("utf-8")
    return sys.stdin.read()


def _load_bundle_secrets(path: str) -> dict[int, str]:
    """Load the generation-to-secret UTF-8 JSON mapping from *path*.

    The file must be a JSON object whose keys are canonical decimal
    strings of positive integer generations and whose values are
    non-empty secret strings; a repeated member name, any other shape or
    any read/decode/parse failure is the same :class:`ValueError`. An
    empty object is a valid (fail-closed) mapping. Secret material is
    returned only to the in-memory offline check and never logged or
    echoed.
    """
    with open(path, "rb") as handle:
        raw = handle.read()
    text = raw.decode("utf-8")

    def _reject_duplicate_keys(pairs: list[tuple[object, object]]) -> dict:
        seen: set[object] = set()
        for key, _value in pairs:
            if key in seen:
                raise ValueError("duplicate generation key")
            seen.add(key)
        return dict(pairs)

    parsed = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    if not isinstance(parsed, dict):
        raise ValueError("secrets mapping must be a JSON object")
    secrets: dict[int, str] = {}
    for key, secret in parsed.items():
        if not isinstance(key, str) or not _GENERATION_DECIMAL_RE.fullmatch(key):
            raise ValueError("generation key must be a decimal string")
        generation = int(key)
        if not isinstance(secret, str) or not secret:
            raise ValueError("secret must be a non-empty string")
        secrets[generation] = secret
    return secrets


def _run_export_bundle(args: list[str]) -> int:
    parsed = _parse_named_flags(args, _EXPORT_BUNDLE_FLAGS)
    if parsed is None:
        return _invalid_input()
    try:
        # Strictly read-only against an existing database: the entry
        # never constructs a writable store, never creates the file or
        # its directory and never holds anchor secret material.
        text = export_existing_audit_bundle(
            parsed["db"], parsed["tenant_id"], parsed["request_id"]
        )
    except RequestNotFound:
        # Unknown and cross-tenant request ids share one outcome.
        _emit(sys.stdout, _error_line("not_found"))
        return 2
    except AuditBundleUnavailable:
        _emit(sys.stdout, _error_line("bundle_unavailable"))
        return 1
    except ValueError:
        # A bad tenant/request value is caller error; never a traceback.
        return _invalid_input()
    except OSError:
        _emit(sys.stdout, _error_line("storage_unavailable"))
        return 3
    except Exception:
        # Past argument validation every failure originates in the
        # store: answer the fixed storage marker, never a stack trace,
        # SQL text or filesystem path.
        _emit(sys.stdout, _error_line("storage_unavailable"))
        return 3
    _emit(sys.stdout, text)
    return 0


def _run_verify_bundle(args: list[str]) -> int:
    parsed = _parse_named_flags(args, _SECRETS_FLAGS)
    if parsed is None:
        return _invalid_input()
    try:
        secrets = _load_bundle_secrets(parsed["secrets"])
        bundle_text = _read_bundle_stdin()
        trusted = RequestStore.verify_audit_bundle(bundle_text, secrets)
    except Exception:
        # An unreadable/invalid secrets file, an invalid secret mapping
        # or a malformed bundle is caller error; a well-formed bundle
        # that simply does not authenticate returns False below.
        return _invalid_input()
    result = {"trusted": bool(trusted)}
    _emit(
        sys.stdout,
        json.dumps(result, ensure_ascii=False, separators=(",", ":")) + "\n",
    )
    return 0 if trusted else 1


def _run_diagnose_bundle(args: list[str]) -> int:
    parsed = _parse_named_flags(args, _SECRETS_FLAGS)
    if parsed is None:
        return _invalid_input()
    try:
        secrets = _load_bundle_secrets(parsed["secrets"])
        bundle_text = _read_bundle_stdin()
        diagnosis = RequestStore.diagnose_audit_bundle(bundle_text, secrets)
        trusted = bool(json.loads(diagnosis)["trusted"])
    except Exception:
        return _invalid_input()
    # The storage layer's existing single-line JSON, ordering and reason
    # codes are emitted verbatim.
    _emit(sys.stdout, diagnosis)
    return 0 if trusted else 1


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
