import logging
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

_presidio_available = False
_analyzer = None

try:
    from presidio_analyzer import AnalyzerEngine
    _presidio_available = True
except ImportError:
    pass


def is_available() -> bool:
    return _presidio_available


def _get_analyzer():
    global _analyzer
    if _analyzer is None and _presidio_available:
        try:
            _analyzer = AnalyzerEngine()
            logger.info("Presidio AnalyzerEngine initialised.")
        except Exception as exc:
            logger.warning("Presidio initialisation failed: %s", exc)
    return _analyzer


def ner_spans(text: str, entity_types: List[str], language: str = "en") -> Dict[str, List[Tuple[int, int]]]:
    analyzer = _get_analyzer()
    if analyzer is None:
        return {}
    try:
        results = analyzer.analyze(text=text, language=language, entities=entity_types)
        spans: Dict[str, List[Tuple[int, int]]] = {}
        for r in results:
            spans.setdefault(r.entity_type, []).append((r.start, r.end))
        return spans
    except Exception as exc:
        logger.warning("Presidio analysis failed: %s", exc)
        return {}
