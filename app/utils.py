from __future__ import annotations

from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse, urlunparse
import ipaddress


@dataclass
class URLInfo:
    """Normalized and parsed information about a URL."""
    original_url: str
    normalized_url: str

    scheme: str
    host: str
    domain: str
    tld: str
    path: str
    query: str

    is_ip: bool
    is_punycode: bool


def _ensure_scheme(url: str) -> str:
    """
    Ensure the URL has a scheme. If missing, default to http://

    Examples:
        "example.com"      -> "http://example.com"
        "https://x.test"   -> unchanged
    """
    url = url.strip()

    # If it already starts with http:// or https://, leave it
    lowered = url.lower()
    if lowered.startswith("http://") or lowered.startswith("https://"):
        return url

    # Otherwise, assume http://
    return f"http://{url}"


def normalize_url(url: str) -> str:
    """
    Perform lightweight normalization on a URL string.

    - Ensure scheme (default http)
    - Lowercase the host portion
    - Strip surrounding whitespace
    """
    url = _ensure_scheme(url)

    parsed = urlparse(url)

    # Lowercase host / netloc
    netloc = parsed.netloc.lower()

    # Rebuild the URL with normalized netloc
    normalized = urlunparse(
        (
            parsed.scheme.lower(),
            netloc,
            parsed.path or "",
            parsed.params or "",
            parsed.query or "",
            parsed.fragment or "",
        )
    )

    return normalized


def _is_ip(host: str) -> bool:
    """Return True if host is a valid IPv4 or IPv6 address."""
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _split_domain_tld(host: str) -> tuple[str, str]:
    """
    Roughly split a hostname into (domain, tld).

    This is a simple heuristic:
        - "example.com"        -> ("example.com", "com")
        - "sub.mail.google.com"-> ("google.com", "com")
        - "localhost"          -> ("localhost", "")
        - IP addresses         -> (host, "")
    """
    if not host:
        return "", ""

    # IP addresses: just return host, no TLD
    if _is_ip(host):
        return host, ""

    parts = host.split(".")
    if len(parts) < 2:
        # e.g. "localhost"
        return host, ""

    tld = parts[-1]
    domain = ".".join(parts[-2:])
    return domain, tld


def parse_url(url: str) -> URLInfo:
    """
    Normalize and parse a URL into a URLInfo object.

    This is the main entry point for downstream heuristics.
    """
    original = url
    normalized = normalize_url(url)
    parsed = urlparse(normalized)

    host = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""

    is_ip = _is_ip(host)
    is_punycode = "xn--" in host

    domain, tld = _split_domain_tld(host)

    return URLInfo(
        original_url=original,
        normalized_url=normalized,
        scheme=parsed.scheme.lower(),
        host=host,
        domain=domain,
        tld=tld,
        path=path,
        query=query,
        is_ip=is_ip,
        is_punycode=is_punycode,
    )
