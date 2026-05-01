import argparse
import json
import sys
import webbrowser
from pathlib import Path

from redakt import Redactor
from redakt.management import RuleStore


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="redakt", description="PII redaction tools")
    subparsers = parser.add_subparsers(dest="command", required=True)

    redact_parser = subparsers.add_parser("redact", help="Redact text from the terminal")
    redact_parser.add_argument("text", nargs="?", help="Text to redact. Reads stdin when omitted.")
    redact_parser.add_argument("--rules", help="Path to rules.json")
    redact_parser.add_argument("--json", action="store_true", help="Print full JSON result")
    redact_parser.set_defaults(func=_redact_command)

    dashboard_parser = subparsers.add_parser("dashboard", help="Run the local dashboard")
    dashboard_parser.add_argument("--rules", default="rules.json", help="Path to rules.json")
    dashboard_parser.add_argument("--host", default="127.0.0.1", help="Host to bind")
    dashboard_parser.add_argument("--port", type=int, default=8765, help="Port to bind")
    dashboard_parser.add_argument("--open", action="store_true", help="Open the dashboard in a browser")
    dashboard_parser.set_defaults(func=_dashboard_command)

    args = parser.parse_args(argv)
    return args.func(args)


def _redact_command(args: argparse.Namespace) -> int:
    text = args.text if args.text is not None else sys.stdin.read()
    redactor = Redactor(rules=_load_rules(args.rules) if args.rules else None)
    result = redactor.redact(text)

    if args.json:
        print(json.dumps({
            "redacted_text": result.redacted_text,
            "pii_count": result.pii_count,
            "labels_found": result.labels_found,
            "matches": [match.__dict__ for match in result.matches],
            "token_map": result.token_map,
        }, indent=2))
    else:
        print(result.redacted_text)

    return 0


def _dashboard_command(args: argparse.Namespace) -> int:
    try:
        import uvicorn
        from redakt.management.dashboard.server import create_app
    except ImportError as exc:
        print(
            "Dashboard dependencies are not installed. Install with: pip install 'redakt[dashboard]'",
            file=sys.stderr,
        )
        raise SystemExit(1) from exc

    rules_path = Path(args.rules)
    app = create_app(rules_path)
    url = f"http://{args.host}:{args.port}"
    print(f"redakt dashboard running at {url}", flush=True)
    print(f"rules file: {rules_path}", flush=True)

    if args.open:
        webbrowser.open(url)

    uvicorn.run(app, host=args.host, port=args.port)
    return 0


def _load_rules(path: str):
    return RuleStore(path).load_or_create_defaults()


if __name__ == "__main__":
    raise SystemExit(main())
