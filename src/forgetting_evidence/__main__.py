import argparse
import json
import sys

from .server import StorageUnavailable, serve


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="forgetting_evidence",
        description="Machine-forgetting evidence service",
    )
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("health", help="print the health document")

    serve_parser = subparsers.add_parser(
        "serve", help="run the deletion-request HTTP service"
    )
    serve_parser.add_argument(
        "--db",
        required=True,
        metavar="PATH",
        help="path to the SQLite database file",
    )
    serve_parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="listen address (default: 127.0.0.1)",
    )
    serve_parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="listen port (default: 8080)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    # Keep the historical bare "health" invocation byte-for-byte
    # compatible: no argparse reformatting of its output or exit code.
    if args == ["health"]:
        print(json.dumps({"service": "forgetting-evidence", "status": "ok"}, sort_keys=True))
        return 0
    if not args:
        print("usage: python -m forgetting_evidence health", file=sys.stderr)
        return 2
    if args[0] not in ("health", "serve"):
        # Preserve the baseline usage message and exit code for
        # unknown commands rather than argparse's SystemExit text.
        print("usage: python -m forgetting_evidence health", file=sys.stderr)
        return 2

    parser = _build_parser()
    parsed = parser.parse_args(args)
    if parsed.command == "serve":
        try:
            serve(parsed.db, parsed.host, parsed.port)
        except StorageUnavailable:
            # Only the stable code may surface; never the path or
            # database engine text.
            print(json.dumps({"error": "storage_unavailable"}), file=sys.stderr)
            return 1
        except OSError:
            # Bind failure: no address details may surface.
            print("service failed to start", file=sys.stderr)
            return 1
        return 0

    parser.print_usage(sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
