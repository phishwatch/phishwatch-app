from fastapi import FastAPI, Request, Response
from fastapi.staticfiles import StaticFiles
from pathlib import Path
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from urllib.parse import urlparse
import re
from typing import Optional, List

from .models import (
    ScanResult,
    SignalFinding,
    ExternalReputation,
    ExternalInfo,
)
from .resolver import resolve_url
from .heuristics import analyze_url_with_heuristics
from .explain import indicators_to_signals, sort_signals, summary_from_signals
from .scoring import score_from_signals, verdict_from_score

app = FastAPI(title="PhishWatch API", version="0.1.0")

BASE_DIR = Path("/app").resolve()
STATIC_DIR = (BASE_DIR / "static").resolve()

app.mount("/static", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")

# DEV CORS ONLY
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.options("/api/check")
def options_check():
    return Response(status_code=200)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/")
def root():
    return {"status": "ok", "docs": "/docs"}


class CheckRequest(BaseModel):
    url: str
    redirect_count: int = 0


def neutralize_summary(summary: Optional[str]) -> str:
    if not summary:
        return "No notable risk indicators detected."
    return re.sub(r"^(high|medium|low)\s+risk:\s*", "", summary.strip(), flags=re.I)


def risk_band_from_signals(signals: List[SignalFinding]) -> str:
    rank = {"low": 1, "medium": 2, "high": 3}
    m = 1
    for s in signals or []:
        m = max(m, rank.get(s.severity, 1))
    if m >= 3:
        return "high"
    if m >= 2:
        return "medium"
    return "low"


def enforce_option_a_invariants(final_url: str, signals: List[SignalFinding]) -> List[SignalFinding]:
    out = list(signals or [])

    if final_url.startswith("http://"):
        replaced = False
        for i, s in enumerate(out):
            if s.id == "insecure_http":
                out[i] = SignalFinding(
                    id="insecure_http",
                    severity="low",
                    explanation=(
                        "This page uses an unencrypted HTTP connection, which can be intercepted on insecure networks."
                    ),
                    evidence={"final_url": final_url},
                )
                replaced = True
                break

        if not replaced:
            out.append(
                SignalFinding(
                    id="insecure_http",
                    severity="low",
                    explanation=(
                        "This page uses an unencrypted HTTP connection, which can be intercepted on insecure networks."
                    ),
                    evidence={"final_url": final_url},
                )
            )

    return out


def enforce_band_reason_invariant(
    risk_band: str, signals: List[SignalFinding], summary: str
) -> tuple[str, str]:
    sev = [s.severity for s in (signals or [])]

    if risk_band == "high" and ("high" not in sev):
        return ("medium" if ("medium" in sev) else "low", "No notable risk indicators detected.")

    if risk_band == "medium" and (("medium" not in sev) and ("high" not in sev)):
        return ("low", "No notable risk indicators detected.")

    return (risk_band, summary)


@app.post("/api/check", response_model=ScanResult)
async def check_url(payload: CheckRequest, request: Request) -> ScanResult:
    pw_test = request.query_params.get("pw_test")
    raw_url = payload.url

    # 0) Resolve redirects / shorteners (fail-safe)
    try:
        resolved = resolve_url(raw_url)
        final_url = resolved.final_url
        redirect_chain = resolved.redirect_chain
        input_is_shortener = bool(getattr(resolved, "input_is_shortener", False))
        resolver_error = None
    except Exception as e:
        final_url = raw_url
        redirect_chain = [raw_url]
        input_is_shortener = False
        resolver_error = str(e)

    # 1) Heuristics → indicators
    _, _, indicators, _ = analyze_url_with_heuristics(final_url)

    if input_is_shortener:
        indicators["url_shortener"] = True

    # 2) External checks (disabled)
    external = ExternalReputation(
        gsb=ExternalInfo(checked=False, reason="disabled_in_v1"),
        virustotal=ExternalInfo(checked=False, reason="disabled_in_v1"),
    )

    # 3) Indicators → explainable signals
    signals = indicators_to_signals(indicators)

   
    if resolver_error:
        signals.append(
            SignalFinding(
                id="resolution_failed",
                severity="low",
                explanation="This link could not be fully resolved (it may be expired or unreachable).",
                evidence={"error": resolver_error},
            )
        )

    if payload.redirect_count >= 1:
        signals.append(
            SignalFinding(
                id="runtime_multi_redirect",
                severity="medium",
                explanation=(
                    f"This page performed {payload.redirect_count} redirect(s) before loading, "
                    "which can hide the true destination."
                ),
                evidence={"redirect_count": payload.redirect_count},
            )
        )

    if len(redirect_chain) >= 3:
        signals.append(
            SignalFinding(
                id="multi_redirect",
                severity="medium",
                explanation="This link uses multiple redirects, which can hide the true destination.",
                evidence={"redirect_hops": len(redirect_chain)},
            )
        )

    # 4) Facts
    host = (urlparse(final_url).hostname or "").lower()
    uses_https = final_url.startswith("https://")
    has_punycode = "xn--" in host

    # 5) Option A invariants
    signals = enforce_option_a_invariants(final_url, signals)

    # 6) Score + verdict (internal)
    signals = sort_signals(signals)
    risk_score = score_from_signals(signals)
    verdict = verdict_from_score(risk_score)

    # 7) Summary + band
    summary = neutralize_summary(summary_from_signals(signals))
    risk_band = risk_band_from_signals(signals)

    if pw_test in {"low", "medium", "high"}:
        risk_band = pw_test

    risk_band, summary = enforce_band_reason_invariant(risk_band, signals, summary)

    return ScanResult(
        input_url=raw_url,
        final_url=final_url,
        redirect_chain=redirect_chain,
        domain=host,
        uses_https=uses_https,
        has_punycode=has_punycode,
        uses_url_shortener=input_is_shortener or bool(indicators.get("url_shortener", False)),
        domain_age_days=None,
        registrar_country=None,
        hosting_country=None,
        brand_similarity_match=None,
        external_reputation=external,
        risk_score=risk_score,
        verdict=verdict,
        risk_band=risk_band,
        summary=summary,
        signals=signals,
    )
