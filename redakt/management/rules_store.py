import copy
import json
import re
from pathlib import Path
from typing import Any, Iterable

from redakt.rules import DEFAULT_RULES, DetectionMethod, Rule


class RuleStore:
    """JSON-backed rule management for regex rules."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.rules: list[Rule] = []

    def load(self) -> list[Rule]:
        data = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(data, list):
            raise ValueError("rules.json must contain a list of rules")

        self.rules = [self._rule_from_dict(item) for item in data]
        return self.get_rules()

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        data = [self._rule_to_dict(rule) for rule in self.rules]
        self.path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

    def load_or_create_defaults(self) -> list[Rule]:
        if self.path.exists():
            return self.load()
        return self.reset_to_defaults()

    def reset_to_defaults(self) -> list[Rule]:
        self.rules = copy.deepcopy(DEFAULT_RULES)
        self.save()
        return self.get_rules()

    def get_rules(self) -> list[Rule]:
        return copy.deepcopy(self.rules)

    def add_regex_rule(
        self,
        label: str,
        pattern: str,
        description: str = "",
        enabled: bool = True,
        priority: int = 0,
        replace: bool = True,
    ) -> Rule:
        if not label:
            raise ValueError("label is required")
        if not pattern:
            raise ValueError("pattern is required")

        re.compile(pattern)
        rule = Rule(
            label=label,
            pattern=pattern,
            method=DetectionMethod.REGEX,
            description=description,
            enabled=enabled,
            priority=priority,
        )
        rule.compile()

        existing_index = self._find_index(label)
        if existing_index is not None:
            if not replace:
                raise ValueError(f"Rule '{label}' already exists")
            self.rules[existing_index] = rule
        else:
            self.rules.append(rule)

        self.save()
        return copy.deepcopy(rule)

    def enable(self, label: str) -> None:
        self._get_rule(label).enabled = True
        self.save()

    def disable(self, label: str) -> None:
        self._get_rule(label).enabled = False
        self.save()

    def remove(self, label: str) -> bool:
        before = len(self.rules)
        self.rules = [rule for rule in self.rules if rule.label != label]
        removed = len(self.rules) < before
        if removed:
            self.save()
        return removed

    def replace_all(self, rules: Iterable[Rule]) -> list[Rule]:
        self.rules = copy.deepcopy(list(rules))
        self.save()
        return self.get_rules()

    def _find_index(self, label: str) -> int | None:
        for index, rule in enumerate(self.rules):
            if rule.label == label:
                return index
        return None

    def _get_rule(self, label: str) -> Rule:
        index = self._find_index(label)
        if index is None:
            raise KeyError(f"Rule '{label}' not found")
        return self.rules[index]

    @staticmethod
    def _rule_from_dict(data: Any) -> Rule:
        if not isinstance(data, dict):
            raise ValueError("each rule must be an object")

        method = DetectionMethod(data.get("method", DetectionMethod.REGEX.value))
        if method != DetectionMethod.REGEX:
            raise ValueError("rules.json currently supports regex rules only")

        label = data.get("label")
        pattern = data.get("pattern")
        if not label or not pattern:
            raise ValueError("each regex rule requires label and pattern")

        re.compile(pattern)
        rule = Rule(
            label=label,
            pattern=pattern,
            method=method,
            description=data.get("description", ""),
            enabled=bool(data.get("enabled", True)),
            priority=int(data.get("priority", 0)),
        )
        rule.compile()
        return rule

    @staticmethod
    def _rule_to_dict(rule: Rule) -> dict[str, Any]:
        if rule.method != DetectionMethod.REGEX:
            raise ValueError("rules.json currently supports regex rules only")

        return {
            "label": rule.label,
            "pattern": rule.pattern,
            "method": rule.method.value,
            "description": rule.description,
            "enabled": rule.enabled,
            "priority": rule.priority,
            "builtin": any(default.label == rule.label for default in DEFAULT_RULES),
        }
