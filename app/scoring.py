from __future__ import annotations

from typing import List, Dict, Tuple

from .models import (
    VERDICT_SAFE,
    VERDICT_SUSPICIOUS,
    VERDICT_MALICIOUS,
)


# -------------------------------
# Verdict Mapping
# -------------------------------

def verdict_from_score(score: int) -> str:
    """
    Map final numeric score to verdict.
    """
    if score >= 70:
        return VERDICT_MALICIOUS
    elif score >= 40:
        return VERDICT_SUSPICIOUS
    return VERDICT_SAFE


# -------------------------------
# Scoring Engine
# -------------------------------

def apply_scoring_rules(
    base_score: int,
    explanations: List[str],
    indicators: Dict[str, bool],
    have_reputation_data: bool = False,
    gsb_status: str | None = None,
    vt_status: str | None = None,
    **_ignored: object,  # <-- prevents crashes if callers pass extra keywords
) -> Tuple[int, str, List[str]]:
    """
    Apply scoring rules, cap score, produce final verdict and explanation list.

    Inputs:
        base_score: total score from heuristics
        explanations: list of human-readable explanation strings
        indicators: dict of heuristic indicators
        have_reputation_data: whether reputation sources were checked
        gsb_status: "malicious" / "suspicious" / "clean" / None
        vt_status: "malicious" / "clean" / None

    Returns:
        final_score (0–100),
        final_verdict ("safe", "suspicious", "malicious"),
        explanations (possibly augmented)
    """

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
            explanations.append(
                "Multiple indicators fired with no reputation data available (confidence bump)."
            )

    # --- Final score cleanup ---
    score = max(0, min(100, score))
    verdict = verdict_from_score(score)

    return score, verdict, explanations
