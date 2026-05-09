from redakt import Redactor, Rule
from redakt import ner as _ner
from redakt.rules import DetectionMethod


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


def test_weak_date_rule_requires_context() -> None:
    rules = [
        Rule(
            label="DATE_OF_BIRTH",
            pattern=r"\b\d{2}/\d{2}/\d{4}\b",
            score=0.2,
            min_score=0.45,
            context=["dob"],
        )
    ]

    no_context = Redactor(rules=rules, use_ner=False).redact("01/01/2000")
    with_context = Redactor(rules=rules, use_ner=False).redact("dob 01/01/2000")

    assert no_context.redacted_text == "01/01/2000"
    assert with_context.redacted_text == "dob [PII_DATE_OF_BIRTH_1]"
    assert "context boost" in (with_context.matches[0].explanation or "")


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


def test_redactor_uses_native_spacy_ner(monkeypatch) -> None:
    monkeypatch.setattr(_ner, "_get_nlp", lambda language: _FakeNlp([_FakeEnt("PERSON", 0, 8)]))

    rules = [Rule(label="PERSON_NAME", method=DetectionMethod.NER, ner_entity="PERSON")]
    result = Redactor(rules=rules).redact("John Doe")

    assert result.redacted_text == "[PII_PERSON_NAME_1]"
    assert result.matches[0].label == "PERSON_NAME"
    assert result.matches[0].source == "spacy"
    assert result.matches[0].score == 0.85


def test_ner_rule_min_score_filters_low_confidence_entity(monkeypatch) -> None:
    monkeypatch.setattr(_ner, "_get_nlp", lambda language: _FakeNlp([_FakeEnt("PERSON", 0, 8)]))

    rules = [Rule(label="PERSON_NAME", method=DetectionMethod.NER, ner_entity="PERSON", min_score=0.9)]
    result = Redactor(rules=rules).redact("John Doe")

    assert result.redacted_text == "John Doe"
    assert result.matches == []


def test_ner_context_boost_can_pass_threshold(monkeypatch) -> None:
    monkeypatch.setattr(_ner, "_get_nlp", lambda language: _FakeNlp([_FakeEnt("PERSON", 5, 13)]))

    rules = [
        Rule(
            label="PERSON_NAME",
            method=DetectionMethod.NER,
            ner_entity="PERSON",
            min_score=0.9,
            context=["name"],
        )
    ]
    result = Redactor(rules=rules).redact("name John Doe")

    assert result.redacted_text == "name [PII_PERSON_NAME_1]"
    assert result.matches[0].score == 1.0
    assert "context boost" in (result.matches[0].explanation or "")


def test_hybrid_resolution_prefers_regex_over_spacy_on_same_span(monkeypatch) -> None:
    monkeypatch.setattr(_ner, "_get_nlp", lambda language: _FakeNlp([_FakeEnt("PERSON", 0, 10)]))

    rules = [
        Rule(label="FULL_NAME", pattern=r"John Smith"),
        Rule(label="PERSON_NAME", method=DetectionMethod.NER, ner_entity="PERSON"),
    ]
    result = Redactor(rules=rules).redact("John Smith")

    assert result.redacted_text == "[PII_FULL_NAME_1]"
    assert result.matches[0].label == "FULL_NAME"


class _FakeNlp:
    def __init__(self, ents):
        self._ents = ents

    def __call__(self, text: str):
        return _FakeDoc(self._ents)


class _FakeDoc:
    def __init__(self, ents):
        self.ents = ents


class _FakeEnt:
    def __init__(self, label_: str, start_char: int, end_char: int) -> None:
        self.label_ = label_
        self.start_char = start_char
        self.end_char = end_char
