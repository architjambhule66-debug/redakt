import json

import pytest

from redakt import Redactor
from redakt.management import RuleStore


def test_rule_store_creates_default_rules_file(tmp_path) -> None:
    path = tmp_path / "rules.json"
    store = RuleStore(path)

    rules = store.load_or_create_defaults()

    assert path.exists()
    assert any(rule.label == "EMAIL" for rule in rules)


def test_rule_store_can_disable_rule(tmp_path) -> None:
    store = RuleStore(tmp_path / "rules.json")
    store.load_or_create_defaults()

    store.disable("EMAIL")
    result = Redactor(rules=store.get_rules(), use_ner=False).redact("test@example.com")

    assert result.redacted_text == "test@example.com"
    assert result.pii_count == 0


def test_rule_store_can_add_custom_regex_rule(tmp_path) -> None:
    path = tmp_path / "rules.json"
    store = RuleStore(path)
    store.load_or_create_defaults()

    store.add_regex_rule("EMPLOYEE_ID", r"EMP-\d{5}", "Employee IDs")
    loaded = RuleStore(path)
    rules = loaded.load()
    result = Redactor(rules=rules, use_ner=False).redact("Owner EMP-12345")

    assert result.redacted_text == "Owner [PII_EMPLOYEE_ID_1]"
    assert result.matches[0].label == "EMPLOYEE_ID"


def test_rule_store_remove_rule(tmp_path) -> None:
    store = RuleStore(tmp_path / "rules.json")
    store.load_or_create_defaults()

    assert store.remove("EMAIL") is True
    assert all(rule.label != "EMAIL" for rule in store.get_rules())


def test_rule_store_rejects_invalid_json_shape(tmp_path) -> None:
    path = tmp_path / "rules.json"
    path.write_text(json.dumps({"label": "EMAIL"}), encoding="utf-8")

    with pytest.raises(ValueError, match="list of rules"):
        RuleStore(path).load()


def test_rule_store_rejects_non_regex_rules(tmp_path) -> None:
    path = tmp_path / "rules.json"
    path.write_text(json.dumps([{"label": "PERSON", "method": "ner", "pattern": "x"}]), encoding="utf-8")

    with pytest.raises(ValueError, match="regex rules only"):
        RuleStore(path).load()
