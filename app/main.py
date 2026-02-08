# app/main.py (Phase-2 update: treadmill signals + marketing infra handling)
from __future__ import annotations

from fastapi import FastAPI, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pathlib import Path
from urllib.parse import urlparse
from typing import List

from app.models import (
    ScanResult,
    SignalFinding,
    ExternalReputation,
    ExternalInfo,
    CheckRequest,
)
from app.resolver import resolve_url
from app.heuristics import analyze_url_with_heuristics
from app.explain import (
    indicators_to_signals,
    sort_signals,
    summary_from_signals,
    should_escalate_treadmill,
    build_treadmill_signal,
    MODIFIER_ONLY_SIGNALS,
)
from app.scoring import score_from_signals, verdict_from_score

app = FastAPI(title="PhishWatch API", version="0.2.0")

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
    return {"status": "ok", "version": "0.2.0"}


@app.get("/")
def root():
    return {"status": "ok", "docs": "/docs", "version": "0.2.0"}


def risk_band_from_signals(signals: List[SignalFinding]) -> str:
    """
    Derive risk band from signal severities.
    Only non-modifier signals can elevate to medium/high.
    """
    rank = {"low": 1, "medium": 2, "high": 3}
    m = 1
    for s in signals or []:
        # Modifier-only signals don't elevate band by themselves
        if s.id in MODIFIER_ONLY_SIGNALS:
            continue
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
    """
    Ensure risk_band is justified by signal severities.
    Excludes modifier-only signals from the check.
    """
    # Get severities of non-modifier signals only
    sev = [s.severity for s in (signals or []) if s.id not in MODIFIER_ONLY_SIGNALS]

    if risk_band == "high" and ("high" not in sev):
        return ("medium" if ("medium" in sev) else "low", "No notable risk indicators detected.")

    if risk_band == "medium" and (("medium" not in sev) and ("high" not in sev)):
        return ("low", "No notable risk indicators detected.")

    return (risk_band, summary)


def dedup_signals_by_id(signals: List[SignalFinding]) -> List[SignalFinding]:
    seen = set()
    out: List[SignalFinding] = []
    for s in (signals or []):
        if s.id in seen:
            continue
        seen.add(s.id)
        out.append(s)
    return out


def user_action_from_band(band: str) -> str:
    if band == "high":
        return "avoid"
    if band == "medium":
        return "review"
    return "proceed"


def process_treadmill_observation(req: CheckRequest) -> List[SignalFinding]:
    """
    Process treadmill observation from client and generate appropriate signals.
    """
    if not req.treadmill:
        return []
    
    obs = req.treadmill
    
    # No events observed = no signal
    if not obs.observed_events:
        return []
    
    # Determine signal type based on trigger
    if obs.trigger == "form_submit":
        signal_id = "treadmill_submit_window_cross_origin_post"
    else:
        signal_id = "treadmill_pre_submit_cross_origin_post"
    
    # Extract data from events
    origins = list(set(e.origin for e in obs.observed_events))
    methods = [e.method for e in obs.observed_events]
    event_count = len(obs.observed_events)
    min_timing = min(e.elapsed_ms for e in obs.observed_events) if obs.observed_events else 0
    has_new_origin = any(e.is_new_origin for e in obs.observed_events)
    
    signal = build_treadmill_signal(
        signal_id=signal_id,
        expected_origin=obs.expected_origin,
        trigger=obs.trigger,
        window_ms=obs.window_ms,
        observed_origins=origins,
        methods=methods,
        event_count=event_count,
        min_timing_ms=min_timing,
        is_new_origin=has_new_origin,
    )
    
    return [signal]


@app.post("/api/check", response_model=ScanResult)
def api_check(req: CheckRequest):
    raw_url = req.input_url
    client_signals = req.client_signals or []
    redirect_count = req.redirect_count or 0
    is_marketing_infra = req.is_marketing_infra

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

    if redirect_count >= 1:
        signals.append(
            SignalFinding(
                id="runtime_multi_redirect",
                severity="medium",
                explanation=(
                    f"This page performed {redirect_count} redirect(s) before loading, "
                    "which can hide the true destination."
                ),
                evidence={"redirect_count": redirect_count},
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

    # 4) Process treadmill observation (Phase 2)
    treadmill_signals = process_treadmill_observation(req)
    signals.extend(treadmill_signals)

    # 5) Facts
    host = (urlparse(final_url).hostname or "").lower()
    uses_https = final_url.startswith("https://")
    has_punycode = "xn--" in host

    # 6) Option A invariants
    signals = enforce_option_a_invariants(final_url, signals)

    # 7) Merge deterministic client signals, then sort deterministically
    signals = dedup_signals_by_id(list(signals or []) + list(client_signals or []))
    signals = sort_signals(signals)

    # 8) Check for treadmill escalation
    treadmill_escalated = should_escalate_treadmill(signals)

    # 9) Score + verdict (internal)
    risk_score = score_from_signals(signals)
    verdict = verdict_from_score(risk_score)

    # 10) Summary + band + contract helpers (ALWAYS present)
    summary = summary_from_signals(signals)
    risk_band = risk_band_from_signals(signals)
    
    # Escalate band if treadmill + credential signal combination
    if treadmill_escalated and risk_band != "high":
        risk_band = "high"
        # Update summary for escalation
        summary = "Credential submission was followed by unexpected external data transfer, consistent with a credential relay flow."
    
    risk_band, summary = enforce_band_reason_invariant(risk_band, signals, summary)

    # 11) Marketing infra special handling
    # If this is marketing infrastructure, we only want to show overlay for HIGH risk
    # The client handles this, but we can also downgrade here for defense in depth
    if is_marketing_infra and risk_band == "medium":
        # Check if there are any non-modifier medium+ signals
        # If all medium signals are from redirect chains (common in marketing), allow
        medium_high_signals = [s for s in signals if s.severity in ("medium", "high") and s.id not in MODIFIER_ONLY_SIGNALS]
        marketing_benign_signals = {"multi_redirect", "runtime_multi_redirect", "url_shortener"}
        
        if all(s.id in marketing_benign_signals for s in medium_high_signals):
            # All medium signals are expected for marketing links
            risk_band = "low"
            summary = "This link uses marketing/tracking infrastructure with expected redirect behavior."

    top_signals = list((signals or [])[:3])
    user_action = user_action_from_band(risk_band)

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
        top_signals=top_signals,
        user_action=user_action,
        signals=signals,
        treadmill_escalated=treadmill_escalated,
    )
