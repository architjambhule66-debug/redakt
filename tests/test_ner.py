from redakt import Rule
from redakt import ner as _ner
from redakt.rules import DetectionMethod


def test_ner_candidates_maps_spacy_entities(monkeypatch) -> None:
    monkeypatch.setattr(_ner, "_get_nlp", lambda language: _FakeNlp([
        _FakeEnt("PERSON", 0, 8),
        _FakeEnt("GPE", 12, 18),
        _FakeEnt("DATE", 22, 32),
    ]))

    rules = [
        Rule(label="PERSON_NAME", method=DetectionMethod.NER, ner_entity="PERSON"),
        Rule(label="LOCATION", method=DetectionMethod.NER, ner_entity="GPE"),
    ]

    candidates = _ner.ner_candidates("John Doe in Berlin on 01/01/2000", rules)

    assert len(candidates) == 2
    assert candidates[0].label == "PERSON_NAME"
    assert candidates[0].source == "spacy"
    assert candidates[0].score == 0.85
    assert candidates[1].label == "LOCATION"
    assert candidates[1].score == 0.75
    assert candidates[0].min_score == 0.0


def test_ner_candidates_includes_rule_context_and_threshold(monkeypatch) -> None:
    monkeypatch.setattr(_ner, "_get_nlp", lambda language: _FakeNlp([_FakeEnt("PERSON", 0, 8)]))

    rules = [
        Rule(
            label="PERSON_NAME",
            method=DetectionMethod.NER,
            ner_entity="PERSON",
            min_score=0.9,
            context=["name"],
        )
    ]
    candidates = _ner.ner_candidates("John Doe", rules)

    assert candidates[0].min_score == 0.9
    assert candidates[0].context == ("name",)


def test_ner_candidates_returns_empty_without_model(monkeypatch) -> None:
    monkeypatch.setattr(_ner, "_get_nlp", lambda language: None)

    candidates = _ner.ner_candidates("John Doe", [Rule(label="PERSON_NAME", method=DetectionMethod.NER, ner_entity="PERSON")])

    assert candidates == []


def test_ner_spans_keeps_backward_compatible_shape(monkeypatch) -> None:
    monkeypatch.setattr(_ner, "_get_nlp", lambda language: _FakeNlp([_FakeEnt("PERSON", 0, 8)]))

    spans = _ner.ner_spans("John Doe", ["PERSON"])

    assert spans == {"PERSON": [(0, 8)]}


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
