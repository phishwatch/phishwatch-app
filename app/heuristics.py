from __future__ import annotations

from typing import Dict, List, Tuple

from .utils import URLInfo, parse_url
from .models import create_empty_indicators


# -------------------------------
# Heuristic configuration
# -------------------------------

# H1: Suspicious TLDs
SUSPICIOUS_TLDS = {
    "xyz",
    "top",
    "click",
    "link",
    "info",
    "club",
    "online",
    "shop",
    "fit",
    "loan",
    "work",
    "gq",
    "cf",
    "tk",
}

# H4: URL shorteners (very common in phishing delivery)
URL_SHORTENER_DOMAINS = {
    "bit.ly",
    "t.co",
    "tinyurl.com",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "rebrand.ly",
    "lnkd.in",
    "trib.al",
    "rb.gy",
    "shorturl.at",
}

# H7: Credential-related keywords in the path
CREDENTIAL_KEYWORDS = [
    "login",
    "signin",
    "sign-in",
    "account",
    "verify",
    "verification",
    "reset",
    "password",
    "passwd",
    "secure",
    "webscr",  # historically used in some phishing paths
]


# -------------------------------
# Individual heuristic checks
# -------------------------------

def h1_suspicious_tld(url_info: URLInfo, indicators: Dict[str, bool], explanations: List[str]) -> int:
    """
    H1 – Suspicious TLD
    Score: +20
    """
    tld = (url_info.tld or "").lower()
    if tld and tld in SUSPICIOUS_TLDS:
        indicators["suspicious_tld"] = True
        explanations.append("TLD is commonly seen in phishing or spam campaigns.")
        return 20
    return 0


def h2_ip_address_url(url_info: URLInfo, indicators: Dict[str, bool], explanations: List[str]) -> int:
    """
    H2 – IP address URL
    Score: +40
    """
    if url_info.is_ip:
        indicators["ip_address_url"] = True
        explanations.append("URL uses a raw IP address instead of a domain name.")
        return 40
    return 0


def h3_many_subdomains(url_info: URLInfo, indicators: Dict[str, bool], explanations: List[str]) -> int:
    """
    H3 – Many subdomains
    Score: +10

    Simple rule:
        - Count labels in the host (split by '.')
        - If there are 4 or more labels, consider it suspicious
          e.g., a.b.c.example.com -> 5 labels
    """
    host = url_info.host or ""
    if not host:
        return 0

    labels = host.split(".")
    if len(labels) >= 4:
        indicators["many_subdomains"] = True
        explanations.append("Domain has many nested subdomains (common obfuscation technique).")
        return 10

    return 0


def h4_url_shortener(url_info: URLInfo, indicators: Dict[str, bool], explanations: List[str]) -> int:
    """
    H4 – URL shortener
    Score: +20
    """
    host = (url_info.host or "").lower()
    if host in URL_SHORTENER_DOMAINS:
        indicators["url_shortener"] = True
        explanations.append("URL uses a shortening service, hiding the final destination.")
        return 20
    return 0


def h5_punycode(url_info: URLInfo, indicators: Dict[str, bool], explanations: List[str]) -> int:
    """
    H5 – Punycode / IDN
    Score: +15

    We mark this because it can be used to hide lookalike characters.
    (Not always malicious, but worth a mild bump.)
    """
    if url_info.is_punycode:
        indicators["punycode"] = True
        explanations.append("Domain uses punycode which can disguise lookalike characters.")
        return 15
    return 0


def h7_credential_keywords(url_info: URLInfo, indicators: Dict[str, bool], explanations: List[str]) -> int:
    """
    H7 – Credential keywords in path
    Score: +20
    """
    path_lower = (url_info.path or "").lower()
    for keyword in CREDENTIAL_KEYWORDS:
        if keyword in path_lower:
            indicators["credential_keywords"] = True
            explanations.append("Path contains login/account-related keywords common in credential harvesting.")
            return 20
    return 0


# -------------------------------
# Main heuristics entry point
# -------------------------------

def apply_basic_heuristics(url_info: URLInfo) -> Tuple[int, List[str], Dict[str, bool]]:
    """
    Apply a subset of heuristics to a parsed URL.

    Returns:
        score_delta: int            -> total score contributed by these heuristics
        explanations: List[str      -> list of explanation strings
        indicators: Dict[str, bool] -> indicator flags for all heuristics
    """
    indicators = create_empty_indicators()
    explanations: List[str] = []
    score = 0

    # Apply each heuristic and accumulate score + explanations
    score += h1_suspicious_tld(url_info, indicators, explanations)
    score += h2_ip_address_url(url_info, indicators, explanations)
    score += h3_many_subdomains(url_info, indicators, explanations)
    score += h4_url_shortener(url_info, indicators, explanations)
    score += h5_punycode(url_info, indicators, explanations)
    score += h7_credential_keywords(url_info, indicators, explanations)

    return score, explanations, indicators


def analyze_url_with_heuristics(raw_url: str) -> Tuple[int, List[str], Dict[str, bool], URLInfo]:
    """
    Convenience function:
    - parse and normalize the raw URL
    - run the basic heuristics
    - return score, explanations, indicators, and URLInfo
    """
    url_info = parse_url(raw_url)
    score, explanations, indicators = apply_basic_heuristics(url_info)

    # Fallback explanation generation (if heuristics didn't add any)
    if not explanations:
        explanations = build_explanations(indicators)

    return score, explanations, indicators, url_info


INDICATOR_EXPLANATIONS = {
    "suspicious_tld": "The domain uses a top-level domain that is frequently abused in phishing attacks.",
    "ip_address_url": "The URL uses a raw IP address instead of a domain name.",
    "many_subdomains": "The URL contains an unusually high number of subdomains.",
    "punycode": "The domain uses punycode, which can disguise lookalike characters.",
    "brand_lookalike": "The domain appears to imitate a known brand.",
    "url_shortener": "The URL uses a shortening service, hiding the final destination.",
    "credential_keywords": "The URL contains keywords commonly used to steal login credentials.",
    "urgency_keywords": "The URL uses urgency language often seen in phishing attacks.",
    "long_query": "The URL contains an unusually long query string.",
    "sensitive_query_params": "The URL includes parameters that may collect sensitive data.",
    "mismatched_brand": "The domain does not match the claimed brand context.",
}


def build_explanations(indicators: dict) -> list[str]:
    explanations: List[str] = []

    for key, triggered in indicators.items():
        if triggered and key in INDICATOR_EXPLANATIONS:
            explanations.append(INDICATOR_EXPLANATIONS[key])

    if not explanations:
        explanations.append("No suspicious URL patterns or known phishing indicators were detected.")

    return explanations
