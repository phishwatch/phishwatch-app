from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Set
from urllib.parse import urlparse
import ipaddress
import socket
import json
import os

import httpx

from .utils import normalize_url, parse_url


# Known URL shorteners (expand later)
URL_SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
}


# Marketing allowlist data structures
MARKETING_SUBDOMAIN_PATTERNS: Set[str] = set()
MARKETING_DOMAINS: Set[str] = set()


def _load_marketing_allowlist():
    """Load marketing allowlist from JSON file."""
    global MARKETING_SUBDOMAIN_PATTERNS, MARKETING_DOMAINS

    try:
        # Find the marketing-allowlist.json file
        current_dir = os.path.dirname(os.path.abspath(__file__))
        allowlist_path = os.path.join(os.path.dirname(current_dir), "marketing-allowlist.json")

        if not os.path.exists(allowlist_path):
            # Fallback: try current directory
            allowlist_path = os.path.join(current_dir, "marketing-allowlist.json")

        if os.path.exists(allowlist_path):
            with open(allowlist_path, 'r') as f:
                data = json.load(f)

            # Load subdomain patterns
            if "subdomain_patterns" in data:
                patterns = data["subdomain_patterns"].get("common_patterns", [])
                MARKETING_SUBDOMAIN_PATTERNS = set(patterns)

            # Load known domains from all provider categories
            domains = set()
            categories = [
                "email_service_providers",
                "marketing_automation_platforms",
                "crm_platforms",
                "ecommerce_platforms",
                "travel_hospitality",
                "financial_services",
                "analytics_tracking",
                "other_legitimate_services"
            ]

            for category in categories:
                if category in data:
                    providers = data[category].get("providers", {})
                    for provider_name, provider_data in providers.items():
                        if isinstance(provider_data, dict) and "domains" in provider_data:
                            domains.update(provider_data["domains"])
                        # Also add common subdomains if they're full domains
                        if isinstance(provider_data, dict) and "common_subdomains" in provider_data:
                            for subdomain in provider_data["common_subdomains"]:
                                # Extract domain if it's in format "*.domain.com"
                                if subdomain.startswith("*."):
                                    domains.add(subdomain[2:])
                                elif subdomain and not subdomain.startswith("*"):
                                    domains.add(subdomain)

            MARKETING_DOMAINS = domains

    except Exception as e:
        # Silently fail - allowlist is optional
        pass


def _is_marketing_domain(host: str) -> bool:
    """
    Check if a host matches known marketing/ESP domain patterns.

    Args:
        host: The hostname to check (e.g., "click.e.company.com")

    Returns:
        True if the host matches marketing domain patterns or known domains
    """
    if not host:
        return False

    host = host.lower().strip()

    # Direct domain match
    if host in MARKETING_DOMAINS:
        return True

    # Check if any known marketing domain is a suffix (handles subdomains)
    for domain in MARKETING_DOMAINS:
        if host == domain or host.endswith(f".{domain}"):
            return True

    # Check subdomain patterns (e.g., "click.", "track.", "email.")
    for pattern in MARKETING_SUBDOMAIN_PATTERNS:
        # Check if subdomain starts with the pattern
        parts = host.split('.')
        if len(parts) >= 2:
            first_subdomain = parts[0]
            # Check if first subdomain matches pattern (e.g., "click" matches "click.")
            if pattern.endswith('.'):
                if first_subdomain == pattern[:-1]:
                    return True
            elif first_subdomain == pattern:
                return True

    return False


# Load marketing allowlist on module import
_load_marketing_allowlist()


@dataclass
class ResolveResult:
    input_url: str
    normalized_input_url: str

    final_url: str
    normalized_final_url: str

    redirect_chain: List[str]
    resolved: bool

    input_is_shortener: bool
    input_is_marketing: bool
    final_is_marketing: bool
    error: Optional[str] = None


def _is_disallowed_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True  # treat unparseable as unsafe

    # Block private, loopback, link-local, multicast, unspecified, etc.
    if (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_unspecified
        or addr.is_reserved
    ):
        return True

    # Block cloud metadata range explicitly (IPv4)
    try:
        if addr.version == 4 and addr in ipaddress.ip_network("169.254.0.0/16"):
            return True
    except Exception:
        pass

    return False


def _host_resolves_to_disallowed_ip(host: str) -> bool:
    # Block obvious local hostnames
    h = (host or "").lower().strip(".")
    if h in {"localhost"}:
        return True

    # If host is already an IP literal, check it directly
    try:
        ipaddress.ip_address(h)
        return _is_disallowed_ip(h)
    except ValueError:
        pass

    # DNS resolve and check all A/AAAA answers
    try:
        infos = socket.getaddrinfo(h, None)
        ips = {info[4][0] for info in infos if info and info[4]}
        for ip in ips:
            if _is_disallowed_ip(ip):
                return True
    except Exception:
        # If we can't resolve, fail safe: don't resolve
        return True

    return False


def resolve_url(
    url: str,
    timeout: float = 2.5,
    max_redirects: int = 8,
    max_head_bytes: int = 0,
    max_body_bytes: int = 64_000,
) -> ResolveResult:
    """
    Resolve redirects safely and ALWAYS return a ResolveResult.
    Hardened against SSRF and large downloads.
    """
    normalized_input = normalize_url(url)
    info = parse_url(normalized_input)

    # Scheme guard
    parsed = urlparse(normalized_input)
    if parsed.scheme not in {"http", "https"}:
        return ResolveResult(
            input_url=url,
            normalized_input_url=normalized_input,
            final_url=normalized_input,
            normalized_final_url=normalized_input,
            redirect_chain=[normalized_input],
            resolved=False,
            input_is_shortener=False,
            input_is_marketing=False,
            final_is_marketing=False,
            error=f"disallowed_scheme:{parsed.scheme}",
        )

    host = (info.host or "").lower()
    input_is_shortener = host in URL_SHORTENER_DOMAINS
    input_is_marketing = _is_marketing_domain(host)

    # SSRF guard
    if not host or _host_resolves_to_disallowed_ip(host):
        return ResolveResult(
            input_url=url,
            normalized_input_url=normalized_input,
            final_url=normalized_input,
            normalized_final_url=normalized_input,
            redirect_chain=[normalized_input],
            resolved=False,
            input_is_shortener=input_is_shortener,
            input_is_marketing=input_is_marketing,
            final_is_marketing=input_is_marketing,
            error="blocked_host_or_private_ip",
        )

    chain: List[str] = [normalized_input]

    headers = {"User-Agent": "Mozilla/5.0 (PhishWatch Resolver)"}
    limits = httpx.Limits(max_connections=5, max_keepalive_connections=2)

    try:
        with httpx.Client(
            follow_redirects=True,
            timeout=timeout,
            headers=headers,
            limits=limits,
            max_redirects=max_redirects,
        ) as client:

            # HEAD first (best-effort): reject obviously huge bodies
            try:
                head = client.head(normalized_input)
                cl = head.headers.get("content-length")
                if cl is not None:
                    try:
                        if int(cl) > max_body_bytes:
                            return ResolveResult(
                                input_url=url,
                                normalized_input_url=normalized_input,
                                final_url=normalized_input,
                                normalized_final_url=normalized_input,
                                redirect_chain=[normalized_input],
                                resolved=False,
                                input_is_shortener=input_is_shortener,
                                input_is_marketing=input_is_marketing,
                                final_is_marketing=input_is_marketing,
                                error="content_too_large",
                            )
                    except ValueError:
                        pass
            except Exception:
                # HEAD can fail on many servers; continue to streamed GET
                pass

            # Streamed GET: don't download large bodies
            with client.stream("GET", normalized_input) as resp:
                resp.raise_for_status()

                # Read only a small chunk (enough to finalize redirects)
                _ = resp.read(max_body_bytes)

                final_url = str(resp.url)
                normalized_final = normalize_url(final_url)

                # Build redirect chain (best-effort)
                try:
                    for h in resp.history:
                        u = normalize_url(str(h.url))
                        if u not in chain:
                            chain.append(u)
                except Exception:
                    pass

                if normalized_final not in chain:
                    chain.append(normalized_final)

                # Also SSRF-guard the final host
                final_host = (urlparse(normalized_final).hostname or "").lower()
                if not final_host or _host_resolves_to_disallowed_ip(final_host):
                    return ResolveResult(
                        input_url=url,
                        normalized_input_url=normalized_input,
                        final_url=normalized_input,
                        normalized_final_url=normalized_input,
                        redirect_chain=[normalized_input],
                        resolved=False,
                        input_is_shortener=input_is_shortener,
                        input_is_marketing=input_is_marketing,
                        final_is_marketing=input_is_marketing,
                        error="blocked_final_host_or_private_ip",
                    )

                # Check if final destination is a marketing domain
                final_is_marketing = _is_marketing_domain(final_host)

                return ResolveResult(
                    input_url=url,
                    normalized_input_url=normalized_input,
                    final_url=final_url,
                    normalized_final_url=normalized_final,
                    redirect_chain=chain,
                    resolved=(normalized_final != normalized_input),
                    input_is_shortener=input_is_shortener,
                    input_is_marketing=input_is_marketing,
                    final_is_marketing=final_is_marketing,
                    error=None,
                )

    except Exception as e:
        return ResolveResult(
            input_url=url,
            normalized_input_url=normalized_input,
            final_url=normalized_input,
            normalized_final_url=normalized_input,
            redirect_chain=[normalized_input],
            resolved=False,
            input_is_shortener=input_is_shortener,
            input_is_marketing=input_is_marketing,
            final_is_marketing=input_is_marketing,
            error=f"{type(e).__name__}: {e}",
        )
