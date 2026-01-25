from __future__ import annotations

from typing import List

from .models import SignalFinding

# Weights are still useful for ordering within a band, but band thresholds must remain explainable.
from .explain import WEIGHTS

VERDICT_SAFE = "SAFE"
VERDICT_SUSPICIOUS = "SUSPICIOUS"
VERDICT_MALICIOUS = "MALICIOUS"


def _max_severity(signals: List[SignalFinding]) -> str:
    rank = {"low": 1, "medium": 2, "high": 3}
    m = 1
    for s in signals or []:
        m = max(m, rank.get(getattr(s, "severity", "low"), 1))
    if m >= 3:
        return "high"
    if m >= 2:
        return "medium"
    return "low"


def score_from_signals(signals: List[SignalFinding]) -> int:
    """
    Phase-1 locked scoring:
    - Score is explainable and cannot imply a higher band than the signal severities support.
    - We still sum WEIGHTS, but we clamp the score so:
        * if max severity is LOW -> score <= 19
        * if max severity is MEDIUM -> score <= 59
        * if max severity is HIGH -> score can go up to 100
    This prevents 'MEDIUM/HIGH with no reasons' forever.
    """
    signals = list(signals or [])
    raw = sum(WEIGHTS.get(s.id, 0) for s in signals)
    raw = max(0, min(100, raw))

    max_sev = _max_severity(signals)

    if max_sev == "low":
        return min(raw, 19)
    if max_sev == "medium":
        return min(raw, 59)
    return raw


def verdict_from_score(score: int) -> str:
    if score >= 60:
        return VERDICT_MALICIOUS
    if score >= 20:
        return VERDICT_SUSPICIOUS
    return VERDICT_SAFE
