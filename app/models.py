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


# -------------------------------
# External Reputation
# -------------------------------

class ExternalInfo(BaseModel):
    checked: bool = False
    status: Optional[str] = None   # e.g. "clean" / "malicious" / "unknown"
    reason: Optional[str] = None   # e.g. "disabled_in_v1", error string, etc.


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
# Request / Response Models
# -------------------------------

class CheckRequest(BaseModel):
    url: str


class ScanResult(BaseModel):
    """
    Canonical result returned by /api/check.
    This is the backbone contract for backend, extension, and UI.
    """
    input_url: str
    final_url: str
    redirect_chain: List[str] = Field(default_factory=list)

    domain: str
    uses_https: bool
    has_punycode: bool
    uses_url_shortener: bool

    domain_age_days: Optional[int] = None
    registrar_country: Optional[str] = None
    hosting_country: Optional[str] = None

    brand_similarity_match: Optional[str] = None

    external_reputation_hits: ExternalReputation = Field(default_factory=ExternalReputation)

    risk_score: int
    verdict: Verdict

    # Human-facing interpretation
    risk_band: Optional[str] = None
    summary: str

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
