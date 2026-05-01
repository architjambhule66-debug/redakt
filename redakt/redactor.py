import copy
from typing import List, Optional
from redakt.rules import DEFAULT_RULES, DetectionMethod, RedactionMatch, RedactionResult, Rule, _resolve_spans
from redakt import ner as _ner

class Redactor:
    def __init__(self, rules: Optional[List[Rule]] = None, token_format: str = "[PII_{label}_{n}]", use_ner: bool = True, ner_language: str = "en") -> None:
        self._rules: List[Rule] = []
        self.token_format = token_format
        self.use_ner = use_ner and _ner.is_available()
        self.ner_language = ner_language

        for rule in (DEFAULT_RULES if rules is None else rules):
            self.add_rule(rule)

    def add_rule(self, rule: Rule) -> None:
        rule = copy.deepcopy(rule)
        rule.compile()
        for i, existing in enumerate(self._rules):
            if existing.label == rule.label:
                self._rules[i] = rule
                return
        self._rules.append(rule)
        
    def remove_rule(self, label: str) -> bool:
        before = len(self._rules)
        self._rules = [r for r in self._rules if r.label != label]
        return len(self._rules) < before

    def enable_rule(self, label: str) -> None:
        self._get_rule(label).enabled = True

    def disable_rule(self, label: str) -> None:
        self._get_rule(label).enabled = False

    def get_rules(self) -> List[Rule]:
        return list(self._rules)

    def _get_rule(self, label: str) -> Rule:
        for r in self._rules:
            if r.label == label:
                return r
        raise KeyError(f"Rule '{label}' not found.")

    def redact(self, text: str) -> RedactionResult:
        """Main detection function"""
        if not text:
            return RedactionResult(
                redacted_text=text,
                original_text=text,
                matches=[],
                token_map={},
            )

        raw_spans: list[tuple[int, int, str, str, int]] = []

        for rule in self._rules:
            if not rule.enabled or rule.method == DetectionMethod.NER:
                continue
            for start, end in rule.find_spans(text):
                raw_spans.append((start, end, rule.label, rule.method.value, rule.priority))

        if self.use_ner:
            ner_rules = [r for r in self._rules if r.enabled and r.method == DetectionMethod.NER and r.ner_entity]
            if ner_rules:
                entity_types = [r.ner_entity for r in ner_rules]
                ner_map = _ner.ner_spans(text, entity_types, self.ner_language)
                entity_to_label = {r.ner_entity: r.label for r in ner_rules}
                for entity, spans in ner_map.items():
                    label = entity_to_label.get(entity, entity)
                    for start, end in spans:
                        raw_spans.append((start, end, label, "ner", 0))

        resolved = _resolve_spans(raw_spans)

        resolved.sort(key=lambda x: x[0])

        label_counters: dict[str, int] = {}
        token_map: dict[str, str] = {}
        matches: list[RedactionMatch] = []
        result_text = text

        replacements: list[tuple[int, int, str]] = []

        for start, end, label, method, _priority in resolved:
            label_counters[label] = label_counters.get(label, 0) + 1
            n = label_counters[label]
            token = self.token_format.format(label=label, n=n)
            original = text[start:end]
            token_map[token] = original
            replacements.append((start, end, token))
            matches.append(RedactionMatch(
                original=original,
                token=token,
                label=label,
                start=start,
                end=end,
                method=method,
            ))

        for start, end, token in sorted(replacements, key=lambda x: x[0], reverse=True):
            result_text = result_text[:start] + token + result_text[end:]

        return RedactionResult(
            redacted_text=result_text,
            original_text=text,
            matches=matches,
            token_map=token_map,
        )

    def redact_batch(self, texts: List[str]) -> List[RedactionResult]:
        """Redact a list of texts."""
        return [self.redact(t) for t in texts]
