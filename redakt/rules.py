import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Callable
from enum import Enum 


class DetectionMethod(str, Enum):
    REGEX = "regex"
    NER = "ner"
    CUSTOM_FUNC = "custom_func"


class RedactionMode(str, Enum):
    REPLACE = "replace"
    MASK = "mask"
    REMOVE = "remove"
    HASH = "hash"

@dataclass
class RedactionMatch:
    original: str
    token: str
    label: str
    start: int
    end: int
    method: str
    source: str = ""
    score: float = 0.0
    explanation: Optional[str] = None


@dataclass
class DetectionCandidate:
    start: int
    end: int
    label: str
    method: str
    source: str
    score: float
    priority: int
    min_score: float = 0.0
    context: Tuple[str, ...] = ()
    explanation: Optional[str] = None

@dataclass
class Rule:
    label : str 
    pattern : Optional[str] = None
    method: DetectionMethod = DetectionMethod.REGEX
    ner_entity: Optional[str] = None 
    detector: Optional[Callable[[str], List[Tuple[int, int]]]] = None
    description: str = ""
    enabled: bool = True
    priority: int = 0
    score: float = 1.0
    min_score: float = 0.0
    context: List[str] = field(default_factory=list)
    _compiled: Optional[re.Pattern] = field(default=None, init=False, repr=False, compare=False)

    def compile(self) -> None:
        if self.method == DetectionMethod.REGEX and self.pattern:
            self._compiled = re.compile(self.pattern)

    def find_spans(self, text: str) -> List[Tuple[int, int]]:
        if not self.enabled:
            return []
        if self.method == DetectionMethod.REGEX:
            if self._compiled is None:
                self.compile()
            return [(m.start(), m.end()) for m in self._compiled.finditer(text)]
        if self.method == DetectionMethod.CUSTOM_FUNC and self.detector:
            return self.detector(text)
        return []

@dataclass
class RedactionResult:
    redacted_text: str
    original_text: str
    matches: List[RedactionMatch]
    token_map: Dict[str, str]
    mode: str = RedactionMode.REPLACE.value

    @property
    def pii_count(self) -> int:
        return len(self.matches)

    @property
    def labels_found(self) -> List[str]:
        return list({m.label for m in self.matches})

    def restore(self, text: Optional[str] = None) -> str:
        if self.mode != RedactionMode.REPLACE.value:
            raise ValueError("restore() is only available in replace mode")
        t = text if text is not None else self.redacted_text
        for token, original in self.token_map.items():
            t = t.replace(token, original)
        return t

# GLOBAL RULES 

GLOBAL_RULES: list[Rule] = [
    Rule(label="EMAIL", pattern=r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", description="Email addresses",),
    Rule(label="PHONE_INTL", pattern=r"(?<!\d)(\+\d{1,3}[\s\-]?)?(\(?\d{2,4}\)?[\s\-]?)(\d{3,4}[\s\-]?\d{3,4})\b", description="International phone numbers",),
    Rule(label="IPV4", pattern=r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b", description="IPv4 addresses",),
    Rule(label="CREDIT_CARD", pattern=r"\b(?:\d[ \-]?){13,16}\b", description="Credit / debit card numbers (13–16 digits)",),
    Rule(label="SSN", pattern=r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b", description="US Social Security Numbers",),
    Rule(
        label="DATE_OF_BIRTH",
        pattern=r"\b\d{1,2}[/\-\.]\d{1,2}[/\-\.]\d{2,4}\b",
        description="Dates when supported by DOB context",
        score=0.2,
        min_score=0.45,
        context=["dob", "date of birth", "birth", "born"],
    ),
    Rule(label="URL", pattern=r"https?://[^\s]+", description="HTTP/HTTPS URLs",),
    Rule(label="MAC_ADDRESS", pattern=r"\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b", description="MAC addresses",),
    Rule(label="PASSPORT", pattern=r"\b[A-Z]{1,2}\d{6,9}\b", description="Passport numbers (generic pattern)",),
    Rule(label="IBAN", pattern=r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b", description="IBAN bank account numbers",),
]

INDIA_RULES: list[Rule] = [
    Rule(label="AADHAAR", pattern=r"\b\d{4}\s?\d{4}\s?\d{4}\b", description="Aadhaar number (12 digits)", priority=10,),
    Rule(label="PAN", pattern=r"\b[A-Z]{5}[0-9]{4}[A-Z]\b", description="Permanent Account Number (PAN)",),
    Rule(label="GSTIN", pattern=r"\b\d{2}[A-Z]{5}\d{4}[A-Z][A-Z\d]Z[A-Z\d]\b", description="GST Identification Number",),
    Rule(label="IFSC", pattern=r"\b[A-Z]{4}0[A-Z0-9]{6}\b", description="IFSC bank branch code",),
    Rule(label="INDIAN_PHONE", pattern=r"(\+91[\s\-]?)?[6-9]\d{4}[\s\-]?\d{5}\b", description="Indian mobile number",),
    Rule(label="VOTER_ID", pattern=r"\b[A-Z]{3}\d{7}\b", description="Voter ID (Election Card)",),
    Rule(label="DRIVING_LICENSE_IN", pattern=r"\b[A-Z]{2}\d{2}\s?\d{4}\s?\d{7}\b", description="Indian driving licence number",),
    Rule(label="UPI_ID", pattern=r"\b[\w.\-]+@(upi|ybl|okhdfcbank|okicici|oksbi|okaxis|paytm|ibl|apl|axl|fbl|kmbl|rbl|icici|sbi|hdfc|kotak)\b", description="UPI payment IDs (known handles)",),
]

NER_RULES: list[Rule] = [
    Rule(label="PERSON_NAME", method=DetectionMethod.NER, ner_entity="PERSON", description="Person names (via spaCy NER)", enabled=True, min_score=0.8),
    Rule(label="LOCATION", method=DetectionMethod.NER, ner_entity="GPE", description="Locations / geopolitical entities (via spaCy NER)", enabled=False, min_score=0.75),
    Rule(label="ORGANIZATION", method=DetectionMethod.NER, ner_entity="ORG", description="Organisation names (via spaCy NER)", enabled=False, min_score=0.8),
]

ALL_REGEX_RULES: list[Rule] = GLOBAL_RULES + INDIA_RULES
DEFAULT_RULES: list[Rule] = [r for r in ALL_REGEX_RULES if r.label in {"EMAIL", "INDIAN_PHONE", "PHONE_INTL", "AADHAAR", "PAN", "CREDIT_CARD", "DATE_OF_BIRTH", "IPV4", "SSN",}]

def _resolve_spans(spans: list[tuple[int, int, str, str, int]],) -> list[tuple[int, int, str, str, int]]:
    spans = sorted(spans, key=lambda x: (-x[4], -(x[1] - x[0]), x[0]))
    resolved: list[tuple[int, int, str, str, int]] = []

    for span in spans:
        start, end, *_ = span
        if all(end <= existing[0] or start >= existing[1] for existing in resolved):
            resolved.append(span)
    return sorted(resolved, key=lambda x: x[0])


def _resolve_candidates(candidates: list[DetectionCandidate]) -> list[DetectionCandidate]:
    candidates = sorted(
        candidates,
        key=lambda candidate: (
            -candidate.priority,
            -candidate.score,
            -(candidate.end - candidate.start),
            candidate.start,
        ),
    )
    resolved: list[DetectionCandidate] = []

    for candidate in candidates:
        if all(candidate.end <= existing.start or candidate.start >= existing.end for existing in resolved):
            resolved.append(candidate)

    return sorted(resolved, key=lambda candidate: candidate.start)
