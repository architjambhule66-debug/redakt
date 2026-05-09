import copy
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory

from redakt import NER_RULES, Redactor, Rule
from redakt import ner as _ner
from redakt.management import RuleStore


def print_section(title: str) -> None:
    print(f"\n=== {title} ===")


def show_result(label: str, result) -> None:
    print(f"\n{label}")
    print(f"mode: {result.mode}")
    print(f"redacted: {result.redacted_text}")
    print(f"labels: {sorted(result.labels_found)}")
    for match in result.matches:
        print(
            f"- {match.label}: {match.original!r} -> {match.token!r} "
            f"(method={match.method}, source={match.source}, score={match.score}, explanation={match.explanation!r})"
        )
    if result.token_map:
        print(f"token_map: {result.token_map}")


def demo_default_rules() -> None:
    print_section("Default Rules")
    text = "Contact test@example.com, PAN ABCDE1234F, Aadhaar 1234 5678 9012"
    result = Redactor(use_ner=False).redact(text)
    show_result("Default redaction", result)
    print(f"restored: {result.restore()}")


def demo_modes() -> None:
    print_section("Modes")
    text = "Email test@example.com and PAN ABCDE1234F"
    for mode, extra in [
        ("replace", {}),
        ("mask", {}),
        ("remove", {}),
        ("hash", {"hash_salt": "demo-salt"}),
    ]:
        result = Redactor(use_ner=False, mode=mode, **extra).redact(text)
        show_result(f"Mode={mode}", result)


def demo_custom_rules() -> None:
    print_section("Custom rules.json")
    with TemporaryDirectory() as tmp_dir:
        rules_path = Path(tmp_dir) / "rules.json"
        store = RuleStore(rules_path)
        store.load_or_create_defaults()
        store.add_regex_rule(
            label="EMPLOYEE_ID",
            pattern=r"EMP-\d{5}",
            description="Employee IDs",
            priority=5,
        )
        store.disable("EMAIL")

        redactor = Redactor(rules=store.get_rules(), use_ner=False)
        result = redactor.redact("Email test@example.com employee EMP-12345")

        print(f"rules file: {rules_path}")
        show_result("Custom rules redaction", result)


def demo_context_boosting() -> None:
    print_section("Weak regex with context boosting")
    rules = [
        Rule(
            label="DATE_OF_BIRTH",
            pattern=r"\b\d{2}/\d{2}/\d{4}\b",
            description="Weak DOB detector with context",
            score=0.2,
            min_score=0.45,
            context=["dob"],
        )
    ]
    no_context = Redactor(rules=rules, use_ner=False).redact("01/01/2000")
    with_context = Redactor(rules=rules, use_ner=False).redact("dob 01/01/2000")

    show_result("Without context", no_context)
    show_result("With context", with_context)



def demo_ner() -> None:
    print_section("Native spaCy NER")
    text = "John Smith met Acme Corp in Berlin"
    ensure_spacy_model_for_demo()

    ner_rules = copy.deepcopy(NER_RULES)
    for rule in ner_rules:
        rule.enabled = True

    result = Redactor(rules=ner_rules).redact(text)
    if not result.matches:
        print("No local spaCy model found, so falling back to a mocked NER run.")
        demo_mock_ner(text)
        print("\nFor real model-backed NER, install:")
        print('pip install "redakt[ner]"')
        print("python -m spacy download en_core_web_sm")
        return
    show_result("NER redaction", result)


def ensure_spacy_model_for_demo() -> None:
    if _ner._get_nlp("en") is not None:
        return

    try:
        import spacy  # noqa: F401
    except ImportError:
        return

    print("No local spaCy English model found. Attempting one-time download for the test bench...")
    try:
        subprocess.run(
            [sys.executable, "-m", "spacy", "download", "en_core_web_sm"],
            check=True,
        )
        _ner._load_attempted.discard("en")
        _ner._nlp_cache.pop("en", None)
    except Exception as exc:
        print(f"Automatic spaCy model download failed: {exc}")


def demo_mock_ner(text: str) -> None:
    original_get_nlp = _ner._get_nlp
    try:
        _ner._get_nlp = lambda language: _FakeNlp([
            _FakeEnt("PERSON", 0, 10),
            _FakeEnt("ORG", 15, 24),
            _FakeEnt("GPE", 28, 34),
        ])

        ner_rules = copy.deepcopy(NER_RULES)
        for rule in ner_rules:
            rule.enabled = True

        result = Redactor(rules=ner_rules).redact(text)
        show_result("Mocked NER redaction", result)
    finally:
        _ner._get_nlp = original_get_nlp


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


def main() -> None:
    demo_default_rules()
    demo_modes()
    demo_custom_rules()
    demo_context_boosting()
    demo_ner()


if __name__ == "__main__":
    main()
