from __future__ import annotations

from typing import Dict, List, Tuple

from .models import SignalFinding
from .explain import WEIGHTS

# -------------------------------
# Signal-based scoring
# -------------------------------

def score_from_signals(signals: List[SignalFinding]) -> int:
    score = sum(WEIGHTS.get(s.id, 0) for s in signals)
    return min(100, score)


# -------------------------------
# Verdict constants (local)
# -------------------------------

VERDICT_SAFE = "SAFE"
VERDICT_SUSPICIOUS = "SUSPICIOUS"
VERDICT_MALICIOUS = "MALICIOUS"


# -------------------------------
# Signal-based scoring
# -------------------------------
def score_from_signals(signals: List[SignalFinding]) -> int:
    score = sum(WEIGHTS.get(s.id, 0) for s in signals)
    return min(100, score)


def verdict_from_score(score: int) -> str:
    """
    Map final numeric score to verdict.
    Keep this aligned with your product semantics.
    """
    if score >= 60:
        return VERDICT_MALICIOUS
    if score >= 20:
        return VERDICT_SUSPICIOUS
    return VERDICT_SAFE


# -------------------------------
# Optional rules layer (reputation, confidence bumps)
# -------------------------------
def apply_scoring_rules(
    base_score: int,
    explanations: List[str],
    indicators: Dict[str, bool],
    have_reputation_data: bool = False,
    gsb_status: str | None = None,
    vt_status: str | None = None,
    **_ignored: object,  # prevents crashes if callers pass extra keywords
) -> Tuple[int, str, List[str]]:
    score = base_score

    # --- Reputation rules ---
    if gsb_status == "malicious":
        score = max(score, 90)
        indicators["gsb_malicious"] = True
        explanations.append("Google Safe Browsing reports this URL as malicious.")
    elif gsb_status == "suspicious":
        score += 40
        indicators["gsb_suspicious"] = True
        explanations.append("Google Safe Browsing reports this URL as suspicious or uncommon.")

    if vt_status == "malicious":
        score = max(score, 90)
        indicators["vt_detections"] = True
        explanations.append("VirusTotal reports one or more detections.")

    # --- No reputation data confidence bump ---
    if not have_reputation_data:
        fired = sum(1 for _, val in indicators.items() if val)
        if score >= 50 and fired >= 3:
            score += 10
            explanations.append("Multiple indicators fired with no reputation data available (confidence bump).")

    # --- Final score cleanup ---
    score = max(0, min(100, score))
    verdict = verdict_from_score(score)

    return score, verdict, explanations
