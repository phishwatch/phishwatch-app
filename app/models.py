# app/models.py
from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field

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

# -------------------------------
# External Reputation
# -------------------------------
class ExternalInfo(BaseModel):
    checked: bool = False
    status: Optional[str] = None   # e.g. "clean" / "malicious" / "unknown"
    reason: Optional[str] = None   # e.g. "disabled_in_v1", error string, etc.
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
