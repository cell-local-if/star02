import json
import sys


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args == ["health"]:
        print(json.dumps({"service": "forgetting-evidence", "status": "ok"}, sort_keys=True))
        return 0
    print("usage: python -m forgetting_evidence health", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
