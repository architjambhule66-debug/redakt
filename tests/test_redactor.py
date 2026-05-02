from redakt import Redactor, Rule


def test_redactor_uses_default_rules() -> None:
    result = Redactor(use_ner=False).redact("Contact test@example.com today")

    assert result.redacted_text == "Contact [PII_EMAIL_1] today"
    assert result.pii_count == 1
    assert result.matches[0].label == "EMAIL"


def test_restore_returns_original_text() -> None:
    text = "Email test@example.com and PAN ABCDE1234F"
    result = Redactor(use_ner=False).redact(text)

    assert result.redacted_text != text
    assert result.restore() == text


def test_default_rules_find_indian_identifiers() -> None:
    result = Redactor(use_ner=False).redact("PAN ABCDE1234F Aadhaar 1234 5678 9012")

    labels = {match.label for match in result.matches}

    assert "PAN" in labels
    assert "AADHAAR" in labels


def test_tokens_are_numbered_in_text_order() -> None:
    result = Redactor(use_ner=False).redact("a@example.com b@example.com")

    assert result.matches[0].token == "[PII_EMAIL_1]"
    assert result.matches[1].token == "[PII_EMAIL_2]"
    assert result.redacted_text == "[PII_EMAIL_1] [PII_EMAIL_2]"


def test_higher_priority_rule_wins_overlapping_span() -> None:
    rules = [
        Rule(label="SHORT", pattern=r"ABC", priority=0),
        Rule(label="LONG", pattern=r"ABCDE", priority=10),
    ]

    result = Redactor(rules=rules, use_ner=False).redact("xx ABCDE yy")

    assert result.redacted_text == "xx [PII_LONG_1] yy"
    assert result.matches[0].label == "LONG"


def test_higher_priority_rule_wins_when_nested_inside_lower_priority_match() -> None:
    rules = [
        Rule(label="LOW", pattern=r"ABCDE", priority=0),
        Rule(label="HIGH", pattern=r"BCD", priority=10),
    ]

    result = Redactor(rules=rules, use_ner=False).redact("xx ABCDE yy")

    assert result.redacted_text == "xx A[PII_HIGH_1]E yy"
    assert result.matches[0].label == "HIGH"
