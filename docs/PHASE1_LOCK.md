# PhishWatch — Phase-1 Lock

Status: LOCKED  
Date: 2026-01-20  
Scope: Runtime post-click phishing detection (no inbox scanning)
PhishWatch — Phase-1 Lock (Acceptance Criteria)

Scope:
Runtime, post-click phishing risk detection based on deterministic URL and infrastructure signals.
No inbox scanning. No content classification. No ML.

A. Architecture Invariants

Chrome MV3 extension

Message types are fixed:

PHISHWATCH_SCAN

PHISHWATCH_SESSION_RPC

Content script never calls backend APIs directly

Background service worker handles all network calls

onMessage handlers always return true for async responses

System is fail-open:

Navigation must never be blocked permanently

Any error → allow navigation

B. Backend Invariants

/health returns { "status": "ok" } in Docker parity

/api/check always returns a valid ScanResult (or controlled error)

Risk band derivation rules:

Risk band derived from signal severities, not raw score

Score is clamped so it cannot imply a higher band than severities

Hard guard:

Backend must never return medium or high unless at least one signal of that severity is present

C. Explainability Invariants

Every signal:

Is deterministic

Has a one-sentence explanation

Is traceable to a Phase-1 indicator

No probabilistic or “AI thinks” language

Summary text must be band-neutral and non-authoritative

D. Frontend / UX Invariants

UI is risk-gated

Overlay appears only for risk_band ∈ {medium}

Session allowlist implemented via chrome.storage.session

RPC actions: allowlist.has, allowlist.add, allowlist.clear

Allowlist short-circuits scan and UI

“Continue anyway”:

Adds URL to session allowlist

Removes overlay

Navigates immediately

Silent allowlist for trusted Google/Drive flows

No loops on:

SPA routing

BFCache restores

Rapid multi-clicks

E. Phase-1 Risk Policy

Allowed severities:

none

low

medium

Disallowed:

high (reserved for Phase-2+)

Typical Phase-1 medium triggers:

IP-as-host URLs

Excessive redirect chains (thresholded)

F. Test Protocol (must pass)

Fresh Chrome session + extension reload

example.com:

no overlay

band none/low

Redirect chain URLs:

navigation succeeds

overlay only if band = medium

IP-host URLs:

medium band

overlay appears

Backend down:

navigation still proceeds (fail-open)

Phase-1 Lock Declaration

Phase-1 is considered locked when all above criteria pass in:

a fresh browser session

after 20–30 mixed navigation events across multiple tabs
