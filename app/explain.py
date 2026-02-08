# app/explain.py (Phase-2 update: treadmill signals)

from __future__ import annotations

from typing import Dict, List, Tuple
from .models import SignalFinding

# indicator_key -> (signal_id, severity, explanation)
INDICATOR_TO_SIGNAL: Dict[str, Tuple[str, str, str]] = {
    # Domain deception / impersonation
    "punycode": (
        "punycode_idn",
        "medium",
        "The domain uses punycode (IDN), which can hide lookalike characters (e.g., 'paypaI' vs 'paypal').",
    ),
    "brand_lookalike": (
        "brand_lookalike",
        "high",
        "The domain looks similar to a known brand (possible impersonation).",
    ),
    "mismatched_brand": (
        "mismatched_brand",
        "high",
        "The link mentions a brand, but the actual domain doesn't match that brand's official domain.",
    ),

    # Destination hiding / obfuscation
    "url_shortener": (
        "url_shortener",
        "medium",
        "This link uses a URL shortener, which hides the real destination until you open it.",
    ),

    # Infrastructure oddities
    "ip_address_url": (
        "ip_in_url",
        "high",
        "This link uses a raw IP address instead of a normal domain name — common in phishing and malware delivery.",
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

    # Content/intent hints
    "credential_keywords": (
        "credential_keywords",
        "high",
        "This URL contains login/account keywords, which are commonly used on credential-harvesting pages.",
    ),
    "urgency_keywords": (
        "urgency_keywords",
        "medium",
        "This link uses urgency language (e.g., 'urgent', 'verify now') — a common phishing tactic.",
    ),

    # Tracking / tokenization (usually not enough alone)
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

    # Transport (Option A: HTTP is LOW by itself)
    "insecure_http": (
        "insecure_http",
        "low",
        "This page loads over HTTP (no encryption). Avoid entering passwords or personal data here.",
    ),
}

# ===========================
# Treadmill Signal Definitions (Phase 2)
# ===========================
TREADMILL_SIGNALS: Dict[str, Dict] = {
    "treadmill_pre_submit_cross_origin_post": {
        "id": "treadmill_pre_submit_cross_origin_post",
        "severity": "low",
        "explanation": "Unexpected cross-origin network activity occurred shortly after you interacted with a credential field.",
        "is_modifier": True,  # Never triggers overlay alone
    },
    "treadmill_submit_window_cross_origin_post": {
        "id": "treadmill_submit_window_cross_origin_post",
        "severity": "medium",
        "explanation": "During credential submission, the page sent data to an unexpected external origin.",
        "is_modifier": False,  # Can trigger overlay
    },
}

# Signals that should never trigger overlay by themselves
MODIFIER_ONLY_SIGNALS = {
    "treadmill_pre_submit_cross_origin_post",
    "long_query",
    "insecure_http",
}

# Score weights are used for ranking *within* severity bands.
# Phase-1 scoring clamps ensure weights cannot promote a band without corresponding severities.
WEIGHTS: Dict[str, int] = {
    "punycode_idn": 25,        # medium
    "url_shortener": 25,       # medium
    "multi_redirect": 20,      # medium (added in main.py)
    "runtime_multi_redirect": 20,  # medium (added in main.py)

    "ip_in_url": 60,           # high
    "brand_lookalike": 60,     # high
    "mismatched_brand": 70,    # high
    "credential_keywords": 70, # high
    "sensitive_params": 60,    # high

    "suspicious_tld": 20,      # medium
    "many_subdomains": 20,     # medium
    "urgency_keywords": 20,    # medium

    "long_query": 10,          # low
    "insecure_http": 5,        # low (Option A)
    "resolution_failed": 0,    # informational low signal added in main.py

    # Treadmill signals (Phase 2)
    "treadmill_pre_submit_cross_origin_post": 5,   # low, modifier only
    "treadmill_submit_window_cross_origin_post": 30,  # medium, can trigger overlay
}

SEVERITY_ORDER = {"high": 3, "medium": 2, "low": 1}


def indicators_to_signals(indicators: Dict[str, bool]) -> List[SignalFinding]:
    signals: List[SignalFinding] = []
    for key, active in (indicators or {}).items():
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
    return sorted(signals or [], key=lambda s: SEVERITY_ORDER.get(s.severity, 0), reverse=True)


def has_non_modifier_signal(signals: List[SignalFinding]) -> bool:
    """
    Check if there's at least one signal that can trigger an overlay by itself.
    Modifier-only signals (low severity, informational) should not cause overlay alone.
    """
    for s in (signals or []):
        if s.id not in MODIFIER_ONLY_SIGNALS:
            if SEVERITY_ORDER.get(s.severity, 0) >= 2:  # medium or high
                return True
    return False


def should_escalate_treadmill(signals: List[SignalFinding]) -> bool:
    """
    Escalation rule: If we have BOTH:
    - treadmill_submit_window_cross_origin_post (medium)
    - credential_form_action_cross_origin OR credential_keywords (high)
    Then the combination strongly suggests AiTM/credential relay.
    
    This is deterministic and explainable.
    """
    signal_ids = {s.id for s in (signals or [])}
    
    has_treadmill_submit = "treadmill_submit_window_cross_origin_post" in signal_ids
    has_credential_signal = (
        "credential_form_action_cross_origin" in signal_ids or
        "credential_keywords" in signal_ids or
        "mismatched_brand" in signal_ids
    )
    
    return has_treadmill_submit and has_credential_signal


def summary_from_signals(signals: List[SignalFinding]) -> str:
    """
    Band-neutral summaries:
    - No "High risk:" / "Medium risk:" language here.
    - The UI pill conveys severity; summary conveys the most important reason in plain terms.
    """
    if not signals:
        return "No notable risk indicators detected."

    ids = {s.id for s in signals}

    # Escalation: Treadmill + credential signal = AiTM pattern
    if should_escalate_treadmill(signals):
        return "Credential submission was followed by unexpected external data transfer, consistent with a credential relay flow."

    # 1) Credential harvesting / impersonation
    if "credential_keywords" in ids:
        return "This link looks like it may be trying to capture login credentials."
    if "mismatched_brand" in ids or "brand_lookalike" in ids:
        return "The destination may be impersonating a trusted brand."

    # 2) Treadmill events (submit-time)
    if "treadmill_submit_window_cross_origin_post" in ids:
        return "During credential submission, the page sent data to an unexpected external origin."

    # 3) Hidden destination patterns
    if "url_shortener" in ids and ("multi_redirect" in ids or "runtime_multi_redirect" in ids):
        return "The destination is being hidden behind a short link and redirects."
    if "multi_redirect" in ids or "runtime_multi_redirect" in ids:
        return "Redirects are being used, which can hide the true destination."
    if "url_shortener" in ids:
        return "The destination is hidden behind a shortened link."

    # 4) Domain / infrastructure anomalies
    if "ip_in_url" in ids:
        return "The destination uses a raw IP address instead of a normal domain."
    if "punycode_idn" in ids:
        return "The domain uses lookalike characters (IDN/punycode)."

    # 5) Transport / tracking
    if "insecure_http" in ids:
        return "This page loads over HTTP (no encryption). Avoid entering sensitive data."
    if "sensitive_params" in ids:
        return "This URL contains parameters that look like sensitive data (tokens/emails/passwords)."
    if "long_query" in ids:
        return "This URL contains a long query string, which can hide tracking or payload data."

    # Fallback: explain the most severe signal
    most_severe = sort_signals(signals)[0]
    return most_severe.explanation


def build_treadmill_signal(
    signal_id: str,
    expected_origin: str,
    trigger: str,
    window_ms: int,
    observed_origins: List[str],
    methods: List[str],
    event_count: int,
    min_timing_ms: int,
    is_new_origin: bool,
) -> SignalFinding:
    """
    Factory function to build a treadmill signal with proper evidence schema.
    """
    signal_def = TREADMILL_SIGNALS.get(signal_id)
    if not signal_def:
        raise ValueError(f"Unknown treadmill signal: {signal_id}")

    return SignalFinding(
        id=signal_def["id"],
        severity=signal_def["severity"],
        explanation=signal_def["explanation"],
        evidence={
            "expected_origin": expected_origin,
            "trigger": trigger,
            "window_ms": window_ms,
            "observed_origins": observed_origins,
            "methods": methods,
            "event_count": event_count,
            "min_timing_ms_since_trigger": min_timing_ms,
            "is_new_origin": is_new_origin,
        },
    )
