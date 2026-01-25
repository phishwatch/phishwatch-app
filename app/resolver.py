from __future__ import annotations

from dataclasses import dataclass
from typing import List

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


@dataclass
class ResolveResult:
    input_url: str
    normalized_input_url: str

    final_url: str
    normalized_final_url: str

    redirect_chain: List[str]
    resolved: bool

    input_is_shortener: bool
    error: str | None = None


def resolve_url(url: str, timeout: float = 6.0) -> ResolveResult:
    """
    Resolve redirects safely and ALWAYS return a ResolveResult (never None).
    If resolution fails, we fall back to analyzing the original input URL.
    """
    normalized_input = normalize_url(url)
    info = parse_url(normalized_input)
    input_is_shortener = info.host in URL_SHORTENER_DOMAINS

    chain: List[str] = [normalized_input]

    try:
        headers = {"User-Agent": "Mozilla/5.0 (PhishWatch Resolver)"}

        limits = httpx.Limits(
            max_connections=5,
            max_keepalive_connections=2,
        )

        with httpx.Client(
            follow_redirects=True,
            timeout=timeout,
            headers=headers,
            limits=limits,
        ) as client:
            resp = client.get(normalized_input)

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

            return ResolveResult(
                input_url=url,
                normalized_input_url=normalized_input,
                final_url=final_url,
                normalized_final_url=normalized_final,
                redirect_chain=chain,
                resolved=(normalized_final != normalized_input),
                input_is_shortener=input_is_shortener,
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
            error=f"{type(e).__name__}: {e}",
        )
