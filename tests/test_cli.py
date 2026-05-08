import json

from redakt.cli import main
from redakt.management import RuleStore


def test_cli_redact_prints_redacted_text(capsys) -> None:
    exit_code = main(["redact", "Email test@example.com"])

    output = capsys.readouterr().out.strip()
    assert exit_code == 0
    assert output == "Email [PII_EMAIL_1]"


def test_cli_redact_can_use_rules_file(tmp_path, capsys) -> None:
    path = tmp_path / "rules.json"
    store = RuleStore(path)
    store.load_or_create_defaults()
    store.disable("EMAIL")

    exit_code = main(["redact", "Email test@example.com", "--rules", str(path)])

    output = capsys.readouterr().out.strip()
    assert exit_code == 0
    assert output == "Email test@example.com"


def test_cli_redact_json_output(capsys) -> None:
    exit_code = main(["redact", "test@example.com", "--json"])

    output = capsys.readouterr().out
    assert exit_code == 0
    assert '"redacted_text": "[PII_EMAIL_1]"' in output
    assert '"mode": "replace"' in output
    assert '"pii_count": 1' in output


def test_cli_redact_mask_mode(capsys) -> None:
    exit_code = main(["redact", "Email test@example.com", "--mode", "mask"])

    output = capsys.readouterr().out.strip()
    assert exit_code == 0
    assert output == "Email t***@example.com"


def test_cli_redact_remove_mode(capsys) -> None:
    exit_code = main(["redact", "Email test@example.com", "--mode", "remove"])

    output = capsys.readouterr().out.strip()
    assert exit_code == 0
    assert output == "Email"


def test_cli_redact_hash_mode_uses_salt(capsys) -> None:
    first_exit = main(["redact", "Email test@example.com", "--mode", "hash", "--hash-salt", "alpha"])
    first_output = capsys.readouterr().out.strip()
    second_exit = main(["redact", "Email test@example.com", "--mode", "hash", "--hash-salt", "alpha"])
    second_output = capsys.readouterr().out.strip()
    third_exit = main(["redact", "Email test@example.com", "--mode", "hash", "--hash-salt", "beta"])
    third_output = capsys.readouterr().out.strip()

    assert first_exit == 0
    assert second_exit == 0
    assert third_exit == 0
    assert first_output == second_output
    assert first_output.startswith("Email sha256:")
    assert first_output != third_output


def test_cli_redact_reads_stdin(monkeypatch, capsys) -> None:
    monkeypatch.setattr("sys.stdin", _Stdin("Email test@example.com"))

    exit_code = main(["redact"])

    output = capsys.readouterr().out.strip()
    assert exit_code == 0
    assert output == "Email [PII_EMAIL_1]"


def test_cli_rules_init_creates_rules_file(tmp_path, capsys) -> None:
    path = tmp_path / "rules.json"

    exit_code = main(["rules", "--rules", str(path), "init"])

    output = capsys.readouterr().out
    assert exit_code == 0
    assert path.exists()
    assert "Created" in output
    assert "default rules" in output


def test_cli_rules_init_refuses_existing_file_without_force(tmp_path, capsys) -> None:
    path = tmp_path / "rules.json"
    path.write_text("[]\n", encoding="utf-8")

    exit_code = main(["rules", "--rules", str(path), "init"])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "already exists" in captured.err
    assert path.read_text(encoding="utf-8") == "[]\n"


def test_cli_rules_init_force_overwrites_existing_file(tmp_path, capsys) -> None:
    path = tmp_path / "rules.json"
    path.write_text("[]\n", encoding="utf-8")

    exit_code = main(["rules", "--rules", str(path), "init", "--force"])

    output = capsys.readouterr().out
    assert exit_code == 0
    assert "Created" in output
    assert any(rule["label"] == "EMAIL" for rule in json.loads(path.read_text(encoding="utf-8")))


def test_cli_rules_list_prints_plain_text(tmp_path, capsys) -> None:
    path = tmp_path / "rules.json"

    exit_code = main(["rules", "--rules", str(path), "list"])

    output = capsys.readouterr().out
    assert exit_code == 0
    assert "EMAIL\tenabled\tpriority=0\tbuilt-in" in output


def test_cli_rules_list_json(tmp_path, capsys) -> None:
    path = tmp_path / "rules.json"

    exit_code = main(["rules", "--rules", str(path), "list", "--json"])

    output = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert any(rule["label"] == "EMAIL" and rule["builtin"] for rule in output)


def test_cli_rules_add_custom_rule_and_redact_with_it(tmp_path, capsys) -> None:
    path = tmp_path / "rules.json"

    add_exit = main([
        "rules",
        "--rules",
        str(path),
        "add",
        "EMPLOYEE_ID",
        r"EMP-\d{5}",
        "--description",
        "Employee IDs",
        "--priority",
        "5",
    ])
    add_output = capsys.readouterr().out
    redact_exit = main(["redact", "Owner EMP-12345", "--rules", str(path)])
    redact_output = capsys.readouterr().out.strip()

    assert add_exit == 0
    assert "Added rule EMPLOYEE_ID" in add_output
    assert redact_exit == 0
    assert redact_output == "Owner [PII_EMPLOYEE_ID_1]"


def test_cli_rules_add_disabled_rule(tmp_path, capsys) -> None:
    path = tmp_path / "rules.json"

    exit_code = main(["rules", "--rules", str(path), "add", "CODE", r"CODE-\d+", "--disabled"])
    capsys.readouterr()
    rules = json.loads(path.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert next(rule for rule in rules if rule["label"] == "CODE")["enabled"] is False


def test_cli_rules_add_duplicate_fails_without_replace(tmp_path, capsys) -> None:
    path = tmp_path / "rules.json"
    main(["rules", "--rules", str(path), "add", "CODE", r"CODE-\d+"])
    capsys.readouterr()

    exit_code = main(["rules", "--rules", str(path), "add", "CODE", r"OTHER-\d+"])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "already exists" in captured.err


def test_cli_rules_add_replace_updates_existing_rule(tmp_path, capsys) -> None:
    path = tmp_path / "rules.json"
    main(["rules", "--rules", str(path), "add", "CODE", r"CODE-\d+"])
    capsys.readouterr()

    exit_code = main(["rules", "--rules", str(path), "add", "CODE", r"OTHER-\d+", "--replace"])
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "Updated rule CODE" in output
    rules = json.loads(path.read_text(encoding="utf-8"))
    assert next(rule for rule in rules if rule["label"] == "CODE")["pattern"] == r"OTHER-\d+"


def test_cli_rules_add_invalid_regex_returns_error(tmp_path, capsys) -> None:
    path = tmp_path / "rules.json"

    exit_code = main(["rules", "--rules", str(path), "add", "BROKEN", "["])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "unterminated character set" in captured.err


def test_cli_rules_disable_and_enable(tmp_path, capsys) -> None:
    path = tmp_path / "rules.json"

    disable_exit = main(["rules", "--rules", str(path), "disable", "EMAIL"])
    disable_output = capsys.readouterr().out
    redact_disabled_exit = main(["redact", "test@example.com", "--rules", str(path)])
    redact_disabled = capsys.readouterr().out.strip()
    enable_exit = main(["rules", "--rules", str(path), "enable", "EMAIL"])
    enable_output = capsys.readouterr().out
    redact_enabled_exit = main(["redact", "test@example.com", "--rules", str(path)])
    redact_enabled = capsys.readouterr().out.strip()

    assert disable_exit == 0
    assert "Rule EMAIL disabled" in disable_output
    assert redact_disabled_exit == 0
    assert redact_disabled == "test@example.com"
    assert enable_exit == 0
    assert "Rule EMAIL enabled" in enable_output
    assert redact_enabled_exit == 0
    assert redact_enabled == "[PII_EMAIL_1]"


def test_cli_rules_enable_missing_rule_returns_error(tmp_path, capsys) -> None:
    path = tmp_path / "rules.json"

    exit_code = main(["rules", "--rules", str(path), "enable", "MISSING"])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "not found" in captured.err


def test_cli_rules_remove_rule(tmp_path, capsys) -> None:
    path = tmp_path / "rules.json"
    main(["rules", "--rules", str(path), "add", "CODE", r"CODE-\d+"])
    capsys.readouterr()

    exit_code = main(["rules", "--rules", str(path), "remove", "CODE"])
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "Removed rule CODE" in output
    assert "CODE" not in path.read_text(encoding="utf-8")


def test_cli_rules_remove_missing_rule_returns_error(tmp_path, capsys) -> None:
    path = tmp_path / "rules.json"

    exit_code = main(["rules", "--rules", str(path), "remove", "MISSING"])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "not found" in captured.err


def test_cli_rules_reset_removes_custom_rules(tmp_path, capsys) -> None:
    path = tmp_path / "rules.json"
    main(["rules", "--rules", str(path), "add", "CODE", r"CODE-\d+"])
    capsys.readouterr()

    exit_code = main(["rules", "--rules", str(path), "reset"])
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "Reset" in output
    assert "CODE" not in path.read_text(encoding="utf-8")


class _Stdin:
    def __init__(self, value: str) -> None:
        self.value = value

    def read(self) -> str:
        return self.value
