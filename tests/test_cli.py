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
    assert '"pii_count": 1' in output
