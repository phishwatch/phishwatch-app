from fastapi import FastAPI, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from urllib.parse import urlparse

# Local imports (these files live next to main.py inside /app/app/)
from .models import (
    ScanResult,
    SignalFinding,
    ExternalReputation,
    ExternalInfo,
)
from .resolver import resolve_url
from .heuristics import analyze_url_with_heuristics
from .explain import (
    indicators_to_signals,
    sort_signals,
    summary_from_signals,
)
from .scoring import score_from_signals, verdict_from_score

app = FastAPI(title="PhishWatch API", version="0.1.0")

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


def risk_band_from_score(score: int) -> str:
    if score >= 60:
        return "high"
    if score >= 20:
        return "medium"
    return "low"


@app.post("/api/check", response_model=ScanResult)
def check_url(payload: CheckRequest) -> ScanResult:
    raw_url = payload.url

    # 0) Resolve redirects / shorteners
    resolved = resolve_url(raw_url)

    # 1) Heuristics → indicators
    _, _, indicators, _ = analyze_url_with_heuristics(resolved.final_url)

    # Hard guarantee: resolver shortener always counts
    input_is_shortener = bool(getattr(resolved, "input_is_shortener", False))
    if input_is_shortener:
        indicators["url_shortener"] = True

    # 2) External checks (disabled in Phase 1)
    external = ExternalReputation(
        gsb=ExternalInfo(checked=False, status=None, reason="disabled_in_v1"),
        virustotal=ExternalInfo(checked=False, status=None, reason="disabled_in_v1"),
    )

    # 3) Indicators → explainable signals
    signals = indicators_to_signals(indicators)
    # Browser-observed redirects (runtime signal)
    if payload.redirect_count >= 1:
        signals.append(
            SignalFinding(
                id="multi_redirect",
                severity="medium",
                explanation=(
                    f"This page performed {payload.redirect_count} redirect(s) "
                    "before loading, which can hide the true destination."
                ),
                evidence={"redirect_count": payload.redirect_count},
        )
    )


    # 3b) Obfuscation: multiple redirects
    if len(resolved.redirect_chain) >= 3:
        signals.append(
            SignalFinding(
                id="multi_redirect",
                severity="medium",
                explanation="This link uses multiple redirects, which can hide the true destination.",
                evidence={"redirect_hops": len(resolved.redirect_chain)},
            )
        )

    # 4) Score + verdict (initial)
    signals = sort_signals(signals)
    risk_score = score_from_signals(signals)
    verdict = verdict_from_score(risk_score)

    # 5) Domain / transport facts
    host = (urlparse(resolved.final_url).hostname or "").lower()
    uses_https = resolved.final_url.startswith("https://")
    has_punycode = "xn--" in host

    # --- Step 1A: Guaranteed signal for insecure HTTP (no TLS) ---
    if resolved.final_url.startswith("http://"):
        signals.append(
            SignalFinding(
                id="insecure_http",
                severity="medium",
                explanation="This page is served over insecure HTTP (no TLS).",
                evidence={"final_url": resolved.final_url},
            )
        )
        signals = sort_signals(signals)
        risk_score = score_from_signals(signals)
        verdict = verdict_from_score(risk_score)
        if verdict == "SAFE":
            verdict = "SUSPICIOUS"
        risk_score = max(risk_score, 20)

    # Hardening: punycode can never be SAFE
    if has_punycode and verdict == "SAFE":
        verdict = "SUSPICIOUS"
        risk_score = max(risk_score, 20)

    # 6) Risk band + summary
    risk_band = risk_band_from_score(risk_score)
    summary = summary_from_signals(signals)

    # 7) Return canonical ScanResult
    return ScanResult(
        input_url=raw_url,
        final_url=resolved.final_url,
        redirect_chain=resolved.redirect_chain,

        domain=host,
        uses_https=uses_https,
        has_punycode=has_punycode,
        uses_url_shortener=input_is_shortener or indicators.get("url_shortener", False),

        domain_age_days=None,
        registrar_country=None,
        hosting_country=None,
        brand_similarity_match=None,

        external_reputation_hits=external,

        risk_score=risk_score,
        verdict=verdict,
        risk_band=risk_band,

        summary=summary,
        signals=signals,
    )
