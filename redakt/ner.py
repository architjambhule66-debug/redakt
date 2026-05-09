import logging
from typing import Any, Dict, List, Tuple

from redakt.rules import DetectionCandidate, DetectionMethod, Rule

logger = logging.getLogger(__name__)

_spacy_available = False
_nlp_cache: Dict[str, Any] = {}
_load_attempted: set[str] = set()

_ENTITY_SCORES = {
    "PERSON": 0.85,
    "ORG": 0.8,
    "GPE": 0.75,
    "LOC": 0.75,
}

_MODEL_CANDIDATES = {
    "en": [
        "en_core_web_trf",
        "en_core_web_lg",
        "en_core_web_md",
        "en_core_web_sm",
    ]
}

try:
    import spacy

    _spacy_available = True
except ImportError:
    pass


def is_available() -> bool:
    return _get_nlp("en") is not None


def _get_nlp(language: str):
    if not _spacy_available:
        return None
    if language in _nlp_cache:
        return _nlp_cache[language]
    if language in _load_attempted:
        return None

    _load_attempted.add(language)
    for model_name in _candidate_models(language):
        try:
            nlp = spacy.load(model_name)
            _nlp_cache[language] = nlp
            logger.info("spaCy model initialised for %s using %s", language, model_name)
            return nlp
        except Exception:
            continue

    logger.warning("No spaCy model available for language '%s'", language)
    return None


def _candidate_models(language: str) -> list[str]:
    if language in _MODEL_CANDIDATES:
        return _MODEL_CANDIDATES[language]
    return [
        f"{language}_core_web_lg",
        f"{language}_core_web_md",
        f"{language}_core_web_sm",
    ]


def ner_candidates(text: str, rules: List[Rule], language: str = "en") -> List[DetectionCandidate]:
    nlp = _get_nlp(language)
    if nlp is None:
        return []

    entity_to_rule = {rule.ner_entity: rule for rule in rules if rule.ner_entity}
    if not entity_to_rule:
        return []

    try:
        doc = nlp(text)
    except Exception as exc:
        logger.warning("spaCy analysis failed: %s", exc)
        return []

    candidates: list[DetectionCandidate] = []
    for ent in getattr(doc, "ents", []):
        rule = entity_to_rule.get(ent.label_)
        if rule is None:
            continue
        base_score = _ENTITY_SCORES.get(ent.label_, 0.75)
        if rule.score != 1.0:
            base_score = rule.score
        candidates.append(
            DetectionCandidate(
                start=ent.start_char,
                end=ent.end_char,
                label=rule.label,
                method=DetectionMethod.NER.value,
                source="spacy",
                score=base_score,
                priority=rule.priority,
                min_score=rule.min_score,
                context=tuple(rule.context),
                explanation=f"spaCy entity {ent.label_}",
            )
        )
    return candidates


def ner_spans(text: str, entity_types: List[str], language: str = "en") -> Dict[str, List[Tuple[int, int]]]:
    rules = [Rule(label=entity_type, method=DetectionMethod.NER, ner_entity=entity_type) for entity_type in entity_types]
    spans: Dict[str, List[Tuple[int, int]]] = {}
    for candidate in ner_candidates(text, rules, language):
        spans.setdefault(candidate.label, []).append((candidate.start, candidate.end))
    return spans
