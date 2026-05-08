import argparse
import json
import re
import sys
import webbrowser
from pathlib import Path
from typing import Any

from redakt import DEFAULT_RULES, RedactionMode, Redactor, Rule
from redakt.management import RuleStore


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="redakt", description="PII redaction tools")
    subparsers = parser.add_subparsers(dest="command", required=True)

    redact_parser = subparsers.add_parser("redact", help="Redact text from the terminal")
    redact_parser.add_argument("text", nargs="?", help="Text to redact. Reads stdin when omitted.")
    redact_parser.add_argument("--rules", help="Path to rules.json")
    redact_parser.add_argument("--mode", choices=[mode.value for mode in RedactionMode], default=RedactionMode.REPLACE.value, help="Redaction mode")
    redact_parser.add_argument("--hash-salt", default="", help="Optional salt for hash mode")
    redact_parser.add_argument("--json", action="store_true", help="Print full JSON result")
    redact_parser.set_defaults(func=_redact_command)

    dashboard_parser = subparsers.add_parser("dashboard", help="Run the local dashboard")
    dashboard_parser.add_argument("--rules", default="rules.json", help="Path to rules.json")
    dashboard_parser.add_argument("--host", default="127.0.0.1", help="Host to bind")
    dashboard_parser.add_argument("--port", type=int, default=8765, help="Port to bind")
    dashboard_parser.add_argument("--open", action="store_true", help="Open the dashboard in a browser")
    dashboard_parser.set_defaults(func=_dashboard_command)

    rules_parser = subparsers.add_parser("rules", help="Manage a rules.json file")
    rules_parser.add_argument("--rules", default="rules.json", help="Path to rules.json")
    rules_subparsers = rules_parser.add_subparsers(dest="rules_command", required=True)

    rules_init_parser = rules_subparsers.add_parser("init", help="Create rules.json with default rules")
    rules_init_parser.add_argument("--force", action="store_true", help="Overwrite an existing rules file")
    rules_init_parser.set_defaults(func=_rules_init_command)

    rules_list_parser = rules_subparsers.add_parser("list", help="List configured rules")
    rules_list_parser.add_argument("--json", action="store_true", help="Print rules as JSON")
    rules_list_parser.set_defaults(func=_rules_list_command)

    rules_add_parser = rules_subparsers.add_parser("add", help="Add a custom regex rule")
    rules_add_parser.add_argument("label", help="Rule label, e.g. EMPLOYEE_ID")
    rules_add_parser.add_argument("pattern", help="Regex pattern")
    rules_add_parser.add_argument("--description", default="", help="Rule description")
    rules_add_parser.add_argument("--priority", type=int, default=0, help="Priority for overlap resolution")
    rules_add_parser.add_argument("--disabled", action="store_true", help="Add the rule disabled")
    rules_add_parser.add_argument("--replace", action="store_true", help="Replace an existing rule with the same label")
    rules_add_parser.set_defaults(func=_rules_add_command)

    rules_enable_parser = rules_subparsers.add_parser("enable", help="Enable a rule")
    rules_enable_parser.add_argument("label", help="Rule label")
    rules_enable_parser.set_defaults(func=_rules_enable_command)

    rules_disable_parser = rules_subparsers.add_parser("disable", help="Disable a rule")
    rules_disable_parser.add_argument("label", help="Rule label")
    rules_disable_parser.set_defaults(func=_rules_disable_command)

    rules_remove_parser = rules_subparsers.add_parser("remove", help="Remove a rule")
    rules_remove_parser.add_argument("label", help="Rule label")
    rules_remove_parser.set_defaults(func=_rules_remove_command)

    rules_reset_parser = rules_subparsers.add_parser("reset", help="Reset rules.json to default rules")
    rules_reset_parser.set_defaults(func=_rules_reset_command)

    args = parser.parse_args(argv)
    return args.func(args)


def _redact_command(args: argparse.Namespace) -> int:
    text = args.text if args.text is not None else sys.stdin.read()
    redactor = Redactor(rules=_load_rules(args.rules) if args.rules else None, mode=args.mode, hash_salt=args.hash_salt)
    result = redactor.redact(text)

    if args.json:
        print(json.dumps({
            "redacted_text": result.redacted_text,
            "mode": result.mode,
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


def _rules_init_command(args: argparse.Namespace) -> int:
    path = Path(args.rules)
    if path.exists() and not args.force:
        print(f"Rules file already exists: {path}. Use --force to overwrite.", file=sys.stderr)
        return 1

    store = RuleStore(path)
    rules = store.reset_to_defaults()
    print(f"Created {path} with {len(rules)} default rules.")
    return 0


def _rules_list_command(args: argparse.Namespace) -> int:
    store = RuleStore(args.rules)
    rules = store.load_or_create_defaults()

    if args.json:
        print(json.dumps([_rule_to_dict(rule) for rule in rules], indent=2))
    else:
        for rule in rules:
            state = "enabled" if rule.enabled else "disabled"
            builtin = "built-in" if _is_builtin(rule) else "custom"
            description = f" - {rule.description}" if rule.description else ""
            print(f"{rule.label}\t{state}\tpriority={rule.priority}\t{builtin}{description}")

    return 0


def _rules_add_command(args: argparse.Namespace) -> int:
    store = RuleStore(args.rules)
    store.load_or_create_defaults()

    try:
        rule = store.add_regex_rule(
            label=args.label,
            pattern=args.pattern,
            description=args.description,
            enabled=not args.disabled,
            priority=args.priority,
            replace=args.replace,
        )
    except (ValueError, re.PatternError) as exc:
        print(str(exc), file=sys.stderr)
        return 1

    action = "Updated" if args.replace else "Added"
    print(f"{action} rule {rule.label} in {store.path}.")
    return 0


def _rules_enable_command(args: argparse.Namespace) -> int:
    return _set_rule_enabled(args.rules, args.label, enabled=True)


def _rules_disable_command(args: argparse.Namespace) -> int:
    return _set_rule_enabled(args.rules, args.label, enabled=False)


def _rules_remove_command(args: argparse.Namespace) -> int:
    store = RuleStore(args.rules)
    store.load_or_create_defaults()

    if not store.remove(args.label):
        print(f"Rule '{args.label}' not found.", file=sys.stderr)
        return 1

    print(f"Removed rule {args.label} from {store.path}.")
    return 0


def _rules_reset_command(args: argparse.Namespace) -> int:
    store = RuleStore(args.rules)
    rules = store.reset_to_defaults()
    print(f"Reset {store.path} to {len(rules)} default rules.")
    return 0


def _load_rules(path: str):
    return RuleStore(path).load_or_create_defaults()


def _set_rule_enabled(path: str, label: str, enabled: bool) -> int:
    store = RuleStore(path)
    store.load_or_create_defaults()

    try:
        if enabled:
            store.enable(label)
        else:
            store.disable(label)
    except KeyError:
        print(f"Rule '{label}' not found.", file=sys.stderr)
        return 1

    state = "enabled" if enabled else "disabled"
    print(f"Rule {label} {state} in {store.path}.")
    return 0


def _rule_to_dict(rule: Rule) -> dict[str, Any]:
    return {
        "label": rule.label,
        "pattern": rule.pattern,
        "method": rule.method.value,
        "description": rule.description,
        "enabled": rule.enabled,
        "priority": rule.priority,
        "builtin": _is_builtin(rule),
    }


def _is_builtin(rule: Rule) -> bool:
    return any(default.label == rule.label for default in DEFAULT_RULES)


if __name__ == "__main__":
    raise SystemExit(main())
