# app/explain.py (replace INDICATOR_TO_SIGNAL and summary_from_signals)

from __future__ import annotations

from typing import Dict, List, Tuple
from .models import SignalFinding

INDICATOR_TO_SIGNAL: Dict[str, Tuple[str, str, str]] = {
    "punycode": (
        "punycode_idn",
        "high",
        "The domain uses punycode (IDN), which can hide lookalike characters (e.g. ‘paypaI’ vs ‘paypal’).",
    ),
    "url_shortener": (
        "url_shortener",
        "medium",
        "This link uses a URL shortener, which hides the real destination until you open it.",
    ),
    "ip_address_url": (
        "ip_in_url",
        "high",
        "This link uses a raw IP address instead of a normal domain name — common in phishing and malware delivery.",
    ),
        "insecure_http": (
        "insecure_http",
        "medium",
        "This page loads over HTTP (no encryption). Avoid entering passwords or personal data here.",
    ),
    "suspicious_tld": (
        "suspicious_tld",
        "medium",
        "The domain ends in a TLD that is frequently abused in phishing/spam campaigns.",
    ),
    "many_subdomains": (
        "many_subdomains",
        "medium",
        "The domain has many subdomains, which is often used to make a link look more trustworthy than it is.",
    ),
    "brand_lookalike": (
        "brand_lookalike",
        "high",
        "The domain looks similar to a known brand (possible impersonation).",
    ),
    "mismatched_brand": (
        "mismatched_brand",
        "high",
        "The link mentions a brand, but the actual domain doesn’t match that brand’s official domain.",
    ),
    "credential_keywords": (
        "credential_keywords",
        "high",
        "This URL contains login/account keywords (often used on credential-harvesting pages).",
    ),
    "urgency_keywords": (
        "urgency_keywords",
        "medium",
        "This link uses urgency language (e.g. ‘urgent’, ‘verify now’) — a common phishing tactic.",
    ),
    "long_query": (
        "long_query",
        "low",
        "This URL has an unusually long query string, which can be used to hide tracking or payload data.",
    ),
    "sensitive_query_params": (
        "sensitive_params",
        "high",
        "This URL contains parameters that resemble sensitive data (tokens, emails, passwords).",
    ),
}

def summary_from_signals(signals: List[SignalFinding]) -> str:
    ids = {s.id for s in signals}

    if "credential_keywords" in ids:
        return "High risk: this link looks like it may be trying to capture login details."
    if "mismatched_brand" in ids or "brand_lookalike" in ids:
        return "High risk: the domain may be impersonating a trusted brand."
    if "url_shortener" in ids and "multi_redirect" in ids:
        return "Caution: the destination is being hidden behind a shortener and redirects."
    if "multi_redirect" in ids:
        return "Caution: redirects are being used to hide the final destination."
    if "url_shortener" in ids:
        return "Caution: the destination is hidden behind a short link."
    if not signals:
        return "No high-confidence phishing signals detected."

    # fallback: most severe signal’s explanation
    most_severe = sorted(
        signals,
        key=lambda s: {"high": 3, "medium": 2, "low": 1}.get(s.severity, 0),
        reverse=True,
    )[0]
    return most_severe.explanation

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


def summary_from_signals(signals: List[SignalFinding]) -> str:
    if not signals:
        return "No high-confidence phishing signals detected."

    ids = {s.id for s in signals}

    # 1) Credential harvesting (strongest signal)
    if "credential_keywords" in ids:
        return "High risk: this link appears designed to capture login credentials."

    # 2) Brand impersonation
    if "mismatched_brand" in ids or "brand_lookalike" in ids:
        return "High risk: the domain appears to be impersonating a trusted brand."

    # 3) Hidden destination patterns
    if "url_shortener" in ids and "multi_redirect" in ids:
        return "Caution: the destination is hidden behind a short link and multiple redirects."

    if "multi_redirect" in ids:
        return "Caution: multiple redirects are used, which can hide the true destination."

    if "url_shortener" in ids:
        return "Caution: the destination is hidden behind a shortened link."

    # 4) Domain / transport concerns
    if "punycode_idn" in ids:
        return "Caution: the domain uses lookalike characters (IDN/punycode)."

    if "insecure_http" in ids:
        return "Caution: this page loads over HTTP (no encryption). Avoid entering sensitive data."

    # 5) Fallback: explain the most severe signal
    most_severe = sort_signals(signals)[0]
    return most_severe.explanation
