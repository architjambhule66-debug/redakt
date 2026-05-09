import copy
import hashlib
from typing import List, Optional
from redakt.rules import DEFAULT_RULES, DetectionCandidate, DetectionMethod, RedactionMatch, RedactionMode, RedactionResult, Rule, _resolve_candidates
from redakt import ner as _ner


_CONTEXT_WINDOW_CHARS = 40
_CONTEXT_BOOST = 0.35

class Redactor:
    def __init__(self, rules: Optional[List[Rule]] = None, token_format: str = "[PII_{label}_{n}]", use_ner: bool = True, ner_language: str = "en", mode: str = RedactionMode.REPLACE.value, hash_salt: str = "") -> None:
        self._rules: List[Rule] = []
        self.token_format = token_format
        self.use_ner = use_ner and _ner.is_available()
        self.ner_language = ner_language
        self.mode = RedactionMode(mode)
        self.hash_salt = hash_salt

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
                mode=self.mode.value,
            )

        candidates: list[DetectionCandidate] = []

        for rule in self._rules:
            if not rule.enabled or rule.method == DetectionMethod.NER:
                continue
            for start, end in rule.find_spans(text):
                candidates.append(
                    DetectionCandidate(
                        start=start,
                        end=end,
                        label=rule.label,
                        method=rule.method.value,
                        source=rule.method.value,
                        score=rule.score,
                        priority=rule.priority,
                        min_score=rule.min_score,
                        context=tuple(rule.context),
                        explanation=rule.description or None,
                    )
                )

        if self.use_ner:
            ner_rules = [r for r in self._rules if r.enabled and r.method == DetectionMethod.NER and r.ner_entity]
            if ner_rules:
                candidates.extend(_ner.ner_candidates(text, ner_rules, self.ner_language))

        candidates = [self._apply_context_and_thresholds(text, candidate) for candidate in candidates]
        candidates = [candidate for candidate in candidates if candidate.score >= candidate.min_score]

        resolved = _resolve_candidates(candidates)

        label_counters: dict[str, int] = {}
        token_map: dict[str, str] = {}
        matches: list[RedactionMatch] = []
        result_text = text

        replacements: list[tuple[int, int, str]] = []

        for candidate in resolved:
            label_counters[candidate.label] = label_counters.get(candidate.label, 0) + 1
            n = label_counters[candidate.label]
            token = self.token_format.format(label=candidate.label, n=n)
            original = text[candidate.start:candidate.end]
            replacement = self._replacement_text(original, candidate.label, token)
            if self.mode == RedactionMode.REPLACE:
                token_map[token] = original
            replacements.append((candidate.start, candidate.end, replacement))
            matches.append(RedactionMatch(
                original=original,
                token=replacement,
                label=candidate.label,
                start=candidate.start,
                end=candidate.end,
                method=candidate.method,
                source=candidate.source,
                score=candidate.score,
                explanation=candidate.explanation,
            ))

        for start, end, token in sorted(replacements, key=lambda x: x[0], reverse=True):
            result_text = result_text[:start] + token + result_text[end:]

        return RedactionResult(
            redacted_text=result_text,
            original_text=text,
            matches=matches,
            token_map=token_map,
            mode=self.mode.value,
        )

    def redact_batch(self, texts: List[str]) -> List[RedactionResult]:
        """Redact a list of texts."""
        return [self.redact(t) for t in texts]

    def _replacement_text(self, original: str, label: str, token: str) -> str:
        if self.mode == RedactionMode.REPLACE:
            return token
        if self.mode == RedactionMode.REMOVE:
            return ""
        if self.mode == RedactionMode.HASH:
            digest = hashlib.sha256(f"{self.hash_salt}{label}:{original}".encode("utf-8")).hexdigest()
            return f"sha256:{digest[:16]}"
        return _mask_value(original)

    def _apply_context_and_thresholds(self, text: str, candidate: DetectionCandidate) -> DetectionCandidate:
        if not candidate.context:
            return candidate

        window_start = max(0, candidate.start - _CONTEXT_WINDOW_CHARS)
        window_end = min(len(text), candidate.end + _CONTEXT_WINDOW_CHARS)
        context_window = text[window_start:window_end].lower()

        for context_word in candidate.context:
            if context_word.lower() in context_window:
                boosted_score = min(1.0, candidate.score + _CONTEXT_BOOST)
                explanation = candidate.explanation or ""
                if explanation:
                    explanation += "; "
                explanation += f"context boost via '{context_word}'"
                return DetectionCandidate(
                    start=candidate.start,
                    end=candidate.end,
                    label=candidate.label,
                    method=candidate.method,
                    source=candidate.source,
                    score=boosted_score,
                    priority=candidate.priority,
                    min_score=candidate.min_score,
                    context=candidate.context,
                    explanation=explanation,
                )

        return candidate


def _mask_value(value: str) -> str:
    if "@" in value and value.count("@") == 1:
        local, domain = value.split("@", 1)
        if not local:
            return f"***@{domain}"
        return f"{local[0]}{'*' * max(1, len(local) - 1)}@{domain}"

    alnum_positions = [index for index, char in enumerate(value) if char.isalnum()]
    if not alnum_positions:
        return value

    has_letters = any(char.isalpha() for char in value)
    has_digits = any(char.isdigit() for char in value)
    preserve_start = 1 if len(alnum_positions) > 2 else 0
    preserve_end = 5 if has_letters and has_digits and len(alnum_positions) > 6 else 4 if len(alnum_positions) > 4 else 1
    preserve = set(alnum_positions[:preserve_start])
    preserve.update(alnum_positions[-preserve_end:])

    chars: list[str] = []
    for index, char in enumerate(value):
        if not char.isalnum() or index in preserve:
            chars.append(char)
        elif char.isdigit():
            chars.append("X")
        else:
            chars.append("*")
    return "".join(chars)
