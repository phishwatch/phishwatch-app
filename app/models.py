# app/models.py (Phase-2 update: treadmill signal support)
from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field, ConfigDict

# Verdict constants (used by scoring.py)
VERDICT_SAFE = "SAFE"
VERDICT_SUSPICIOUS = "SUSPICIOUS"
VERDICT_MALICIOUS = "MALICIOUS"

# -------------------------------
# Types
# -------------------------------
Verdict = Literal["SAFE", "SUSPICIOUS", "MALICIOUS"]
Severity = Literal["low", "medium", "high"]
RiskBand = Literal["low", "medium", "high"]
UserAction = Literal["proceed", "review", "avoid"]
TreadmillTrigger = Literal["credential_focus", "form_submit"]

# -------------------------------
# External Reputation
# -------------------------------
class ExternalInfo(BaseModel):
    checked: bool = False
    status: Optional[str] = None  # e.g. "clean" / "malicious" / "unknown"
    reason: Optional[str] = None  # e.g. "disabled_in_v1", error string, etc.
    details: Optional[Dict[str, Any]] = None  # optional future extensibility


class ExternalReputation(BaseModel):
    gsb: ExternalInfo = Field(default_factory=ExternalInfo)
    virustotal: ExternalInfo = Field(default_factory=ExternalInfo)

# -------------------------------
# Explainable Signals
# -------------------------------
class SignalFinding(BaseModel):
    id: str
    severity: Severity
    explanation: str
    evidence: Dict[str, Any] = Field(default_factory=dict)


# -------------------------------
# Treadmill Event (Phase 2)
# -------------------------------
class TreadmillEvent(BaseModel):
    """
    Represents a cross-origin network event observed during an authentication window.
    Used for client-side treadmill detection.
    """
    origin: str
    method: str  # POST, PUT, PATCH
    elapsed_ms: int
    is_new_origin: bool = False


class TreadmillObservation(BaseModel):
    """
    Complete treadmill observation from client, sent with scan request.
    """
    trigger: TreadmillTrigger
    expected_origin: str
    window_ms: int
    observed_events: List[TreadmillEvent] = Field(default_factory=list)


# -------------------------------
# Response Model
# -------------------------------
class ScanResult(BaseModel):
    """
    Canonical result returned by /api/check.
    Backbone contract for backend, extension, and UI.
    """

    # Human-facing interpretation (always present)
    risk_band: RiskBand
    summary: str

    # Contract-locked helpers for UX and explainability
    top_signals: List[SignalFinding] = Field(default_factory=list)
    user_action: UserAction

    # URL trace
    input_url: str
    final_url: str
    redirect_chain: List[str] = Field(default_factory=list)

    # Core URL/domain features
    domain: str
    uses_https: bool
    has_punycode: bool
    uses_url_shortener: bool

    # Enrichment (optional)
    domain_age_days: Optional[int] = None
    registrar_country: Optional[str] = None
    hosting_country: Optional[str] = None

    # Brand/intent hints (optional)
    brand_similarity_match: Optional[str] = None

    # External reputation (structured, but can be "disabled_in_v1")
    external_reputation: ExternalReputation = Field(default_factory=ExternalReputation)

    # Scoring + decision
    risk_score: int = 0
    verdict: Verdict = VERDICT_SAFE

    # Explainable findings
    signals: List[SignalFinding] = Field(default_factory=list)
    
    # Phase 2: Treadmill escalation flag
    treadmill_escalated: bool = False


class CheckRequest(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,  # allow "input_url" in addition to alias "url"
        extra="ignore",
    )

    # Prefer input_url, but accept legacy "url"
    input_url: str = Field(..., alias="url")

    redirect_count: int = 0
    client_signals: List[SignalFinding] = Field(default_factory=list)
    
    # Phase 2: Prescan context from client
    prescan_reasons: List[str] = Field(default_factory=list)
    is_marketing_infra: bool = False
    
    # Phase 2: Treadmill observation from client (optional)
    treadmill: Optional[TreadmillObservation] = None


# -------------------------------
# Helpers (required by heuristics.py)
# -------------------------------
def create_empty_indicators() -> Dict[str, Any]:
    """
    Heuristics layer writes into this dict. Keep it flexible.
    """
    return {
        "url_shortener": False,
        "punycode": False,
        "https": False,
        "redirect_count": 0,
        "final_domain": "",
    }
