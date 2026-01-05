from __future__ import annotations

from typing import Dict, List, Tuple
from .models import SignalFinding

INDICATOR_TO_SIGNAL: Dict[str, Tuple[str, str, str]] = {
    "punycode": (
        "punycode_idn",
        "high",
        "This domain uses punycode (IDN), which can disguise lookalike characters.",
    ),
    "url_shortener": (
        "url_shortener",
        "medium",
        "This link uses a URL shortener, which hides the real destination.",
    ),
    "ip_address_url": (
        "ip_in_url",
        "high",
        "This link uses an IP address instead of a domain, which is common in phishing.",
    ),
    "suspicious_tld": (
        "suspicious_tld",
        "medium",
        "This domain uses a TLD commonly abused in phishing campaigns.",
    ),
    "many_subdomains": (
        "many_subdomains",
        "medium",
        "This domain has many subdomains, which can be used to imitate trusted sites.",
    ),
    "brand_lookalike": (
        "brand_lookalike",
        "high",
        "This domain looks similar to a trusted brand.",
    ),
    "mismatched_brand": (
        "mismatched_brand",
        "high",
        "The link references a brand, but the domain does not match it.",
    ),
    "credential_keywords": (
        "credential_keywords",
        "high",
        "The URL contains login or credential-related keywords.",
    ),
    "urgency_keywords": (
        "urgency_keywords",
        "medium",
        "The URL contains urgency language often used in phishing.",
    ),
    "long_query": (
        "long_query",
        "low",
        "This URL has an unusually long query string.",
    ),
    "sensitive_query_params": (
        "sensitive_params",
        "high",
        "This URL contains parameters resembling sensitive data.",
    ),
}

WEIGHTS: Dict[str, int] = {
    "punycode_idn": 45,
    "url_shortener": 25,
    "multi_redirect": 20,
    "ip_in_url": 50,
    "suspicious_tld": 20,
    "many_subdomains": 15,
    "brand_lookalike": 40,
    "mismatched_brand": 45,
    "credential_keywords": 35,
    "urgency_keywords": 15,
    "long_query": 10,
    "sensitive_params": 40,
}

SEVERITY_ORDER = {"high": 3, "medium": 2, "low": 1}


def indicators_to_signals(indicators: Dict[str, bool]) -> List[SignalFinding]:
    signals: List[SignalFinding] = []
    for key, active in indicators.items():
        if not active:
            continue
        mapping = INDICATOR_TO_SIGNAL.get(key)
        if not mapping:
            continue

        signal_id, severity, explanation = mapping
        signals.append(
            SignalFinding(
                id=signal_id,
                severity=severity,  # type: ignore[arg-type]
                explanation=explanation,
                evidence={"indicator": key},
            )
        )
    return signals


def sort_signals(signals: List[SignalFinding]) -> List[SignalFinding]:
    return sorted(signals, key=lambda s: SEVERITY_ORDER.get(s.severity, 0), reverse=True)


def score_from_signals(signals: List[SignalFinding]) -> int:
    score = sum(WEIGHTS.get(s.id, 0) for s in signals)
    return min(100, score)


def verdict_from_score(score: int) -> str:
    if score >= 60:
        return "MALICIOUS"
    if score >= 20:
        return "SUSPICIOUS"
    return "SAFE"


def summary_from_signals(signals: List[SignalFinding]) -> str:
    ids = {s.id for s in signals}

    if "credential_keywords" in ids or "mismatched_brand" in ids or "brand_lookalike" in ids:
        return "Likely phishing: the link suggests credential capture or brand impersonation."
    if "punycode_idn" in ids and "url_shortener" in ids:
        return "Caution: the link hides its destination and uses a lookalike-style domain."
    if "punycode_idn" in ids:
        return "Caution: the domain uses punycode (IDN), which can disguise lookalike characters."
    if "multi_redirect" in ids and "url_shortener" in ids:
        return "Caution: the link hides its destination behind a shortener and multiple redirects."
    if "multi_redirect" in ids:
        return "Caution: the link uses multiple redirects, which can hide the true destination."
    if "url_shortener" in ids:
        return "Caution: the link uses a URL shortener, hiding the real destination."
    if not signals:
        return "No high-confidence phishing signals detected."

    return sort_signals(signals)[0].explanation
