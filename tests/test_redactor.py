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


def test_mask_mode_masks_email_and_pan() -> None:
    result = Redactor(use_ner=False, mode="mask").redact("Email test@example.com and PAN ABCDE1234F")

    assert result.redacted_text == "Email t***@example.com and PAN A****1234F"
    assert result.token_map == {}
    assert result.mode == "mask"


def test_remove_mode_removes_matches() -> None:
    result = Redactor(use_ner=False, mode="remove").redact("Email test@example.com")

    assert result.redacted_text == "Email "
    assert result.token_map == {}


def test_hash_mode_is_deterministic_and_uses_salt() -> None:
    first = Redactor(use_ner=False, mode="hash", hash_salt="alpha").redact("Email test@example.com")
    second = Redactor(use_ner=False, mode="hash", hash_salt="alpha").redact("Email test@example.com")
    different = Redactor(use_ner=False, mode="hash", hash_salt="beta").redact("Email test@example.com")

    assert first.redacted_text == second.redacted_text
    assert first.redacted_text.startswith("Email sha256:")
    assert first.redacted_text != different.redacted_text


def test_restore_raises_for_non_replace_modes() -> None:
    result = Redactor(use_ner=False, mode="mask").redact("Email test@example.com")

    try:
        result.restore()
    except ValueError as exc:
        assert "replace mode" in str(exc)
    else:
        raise AssertionError("restore() should fail outside replace mode")


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
