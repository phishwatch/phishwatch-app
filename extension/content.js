// PhishWatch MV3 — content.js
// Minimal, robust content script that:
// 1) Always shows a visible "Scanning…" overlay on non-trusted pages
// 2) Sends the current URL to the background service worker
// 3) Renders a simple result when a response arrives
// 4) Avoids SPA + Gmail noise (no repeated rescans, hard-skip Gmail)

/* =========================
   Config / guards
   ========================= */

(() => {
  "use strict";

  // --- "Trusted app" / noisy surfaces to SKIP entirely ---
  // Even though Gmail may be part of your wider idea, for this MVP we skip it
  // to avoid constant SPA route updates + DOM churn.
  const SKIP_HOSTS = new Set([
    "mail.google.com",
    "inbox.google.com",
    "calendar.google.com",
    "docs.google.com",
    "drive.google.com",
  ]);

  // Don’t run in iframes (prevents multiple overlays on embedded content).
  if (window.top !== window) return;

  const host = location.hostname;

// Skip Gmail + Google apps
if (SKIP_HOSTS.has(host)) return;

// Skip only the PhishWatch API/docs (keeps other localhost pages testable)
if ((host === "127.0.0.1" || host === "localhost") && (
  location.pathname.startsWith("/docs") ||
  location.pathname.startsWith("/openapi.json") ||
  location.pathname.startsWith("/redoc") ||
  location.pathname.startsWith("/health") ||
  location.pathname.startsWith("/api/")
)) {
  return;
}
console.log("[PhishWatch] content.js loaded on", location.href);
document.documentElement.setAttribute("data-phishwatch-loaded", "1");

  // Some special Chrome pages are not inject-able anyway; this keeps logs clean.
  if (!location.href.startsWith("http://") && !location.href.startsWith("https://")) return;

  /* =========================
     Overlay (UI)
     ========================= */

  const OVERLAY_ID = "phishwatch-overlay";
  let overlayEl = null;

  function ensureOverlay() {
    if (overlayEl && document.contains(overlayEl)) return overlayEl;

    overlayEl = document.createElement("div");
    overlayEl.id = OVERLAY_ID;

    // Keep it simple + highly visible.
    overlayEl.style.position = "fixed";
    overlayEl.style.top = "16px";
    overlayEl.style.right = "16px";
    overlayEl.style.zIndex = "2147483647";
    overlayEl.style.maxWidth = "360px";
    overlayEl.style.padding = "12px 14px";
    overlayEl.style.borderRadius = "12px";
    overlayEl.style.boxShadow = "0 8px 24px rgba(0,0,0,.18)";
    overlayEl.style.fontFamily = "system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif";
    overlayEl.style.fontSize = "13px";
    overlayEl.style.lineHeight = "1.35";
    overlayEl.style.color = "#111";
    overlayEl.style.background = "rgba(255,255,255,.96)";
    overlayEl.style.border = "1px solid rgba(0,0,0,.10)";
    overlayEl.style.backdropFilter = "blur(6px)";
    overlayEl.style.pointerEvents = "auto"; // allow copy/select if you want later

    // Initial state
    overlayEl.innerHTML = `
      <div style="font-weight:700; margin-bottom:4px;">PhishWatch</div>
      <div id="phishwatch-status" style="display:flex; gap:8px; align-items:center;">
        <span aria-hidden="true">⏳</span>
        <span>Scanning…</span>
      </div>
      <div id="phishwatch-detail" style="margin-top:8px; color:#333; opacity:.9;">
        ${escapeHtml(location.href)}
      </div>
    `;

    // Append ASAP (even before DOMContentLoaded if possible).
    // If body isn't available yet, fall back to documentElement.
    const mount = document.body || document.documentElement;
    mount.appendChild(overlayEl);

    return overlayEl;
  }

  function setOverlayScanning(targetUrl) {
    const el = ensureOverlay();
    const status = el.querySelector("#phishwatch-status");
    const detail = el.querySelector("#phishwatch-detail");
    if (status) status.innerHTML = `<span aria-hidden="true">⏳</span><span>Scanning…</span>`;
    if (detail) detail.textContent = url;
  }

  function setOverlayResult(result) {
    const el = ensureOverlay();
    const status = el.querySelector("#phishwatch-status");
    const detail = el.querySelector("#phishwatch-detail");

    // You said your API returns ScanResult; keep this tolerant to different shapes.
    // Prefer these if present: verdict, risk_band, score, summary.
    const verdict = String(result?.risk_band ?? result?.verdict ?? "unknown").toUpperCase();
    const score = typeof result?.score === "number" ? result.score : null;
    const summary = result?.summary ?? null;

    const badge = formatVerdictBadge(verdict);
    const scoreLine = score !== null ? `Score: <b>${score}</b>` : "";
    const summaryLine = summary ? `<div style="margin-top:6px;">${escapeHtml(String(summary))}</div>` : "";

  if (status) {
    const isRisky =
    verdict === "HIGH" ||
    verdict === "MALICIOUS";

  const icon = isRisky ? "⚠️" : "✅";

  status.innerHTML = `
    <span aria-hidden="true">${icon}</span>
    <span>${badge}</span>
  `;
}

    if (detail) {
      detail.innerHTML = `
        <div style="color:#333; opacity:.95;">
          ${scoreLine}
          ${summaryLine}
        </div>
      `;
    }
  }

  function setOverlayError(message) {
    const el = ensureOverlay();
    const status = el.querySelector("#phishwatch-status");
    const detail = el.querySelector("#phishwatch-detail");
    if (status) status.innerHTML = `<span aria-hidden="true">⚠️</span><span><b>Error</b></span>`;
    if (detail) detail.textContent = message;
  }

  function formatVerdictBadge(v) {
    const text = String(v);
    // Tiny, neutral badge. (No CSS files, no refactors.)
    return `<span style="
      display:inline-block;
      padding:2px 8px;
      border-radius:999px;
      border:1px solid rgba(0,0,0,.12);
      background:rgba(0,0,0,.04);
      font-weight:600;
    ">${escapeHtml(text)}</span>`;
  }

  function escapeHtml(str) {
    return String(str).replace(/[&<>"']/g, (m) => {
      switch (m) {
        case "&": return "&amp;";
        case "<": return "&lt;";
        case ">": return "&gt;";
        case '"': return "&quot;";
        case "'": return "&#039;";
        default: return m;
      }
    });
  }

  /* =========================
     Scan control (SPA-safe)
     ========================= */

/* =========================
   Scan control (outbound-only)
   ========================= */

/* =========================
   Scan control (outbound-only) + Continue anyway
   ========================= */

let lastScannedUrl = null;
let scanInFlight = false;
let pendingNavigationUrl = null;

function setOverlayScanning(targetUrl) {
  const el = ensureOverlay();
  const status = el.querySelector("#phishwatch-status");
  const detail = el.querySelector("#phishwatch-detail");
  if (status) status.innerHTML = `<span aria-hidden="true">⏳</span><span>Scanning…</span>`;
  if (detail) detail.textContent = targetUrl;
}

function addContinueButtonIfNeeded() {
  const el = ensureOverlay();
  // remove any previous button (avoid duplicates)
  el.querySelector("#phishwatch-continue")?.remove();

  if (!pendingNavigationUrl) return;

  const btn = document.createElement("button");
  btn.id = "phishwatch-continue";
  btn.type = "button";
  btn.textContent = "Continue anyway →";
  btn.style.marginTop = "10px";
  btn.style.padding = "8px 10px";
  btn.style.borderRadius = "10px";
  btn.style.border = "1px solid rgba(0,0,0,.14)";
  btn.style.background = "rgba(0,0,0,.04)";
  btn.style.fontWeight = "600";
  btn.style.cursor = "pointer";

  btn.addEventListener("click", () => {
    const url = pendingNavigationUrl;
    pendingNavigationUrl = null;
    window.location.assign(url);
  });

  // append under the detail area
  (el.querySelector("#phishwatch-detail")?.parentElement || el).appendChild(btn);
}

function runScan(reason, url) {
  if (!url) return;
  if (url === lastScannedUrl) return;
  if (scanInFlight) return;

  lastScannedUrl = url;
  scanInFlight = true;

  // Step 1: show overlay immediately
  setOverlayScanning(url);

  // Safety timeout (never hang forever)
  let didRespond = false;
  const failTimer = setTimeout(() => {
    if (didRespond) return;
    scanInFlight = false;
    setOverlayError("Scan timed out (no response from background).");
    addContinueButtonIfNeeded();
  }, 5000);

  // Step 2: send to background
  chrome.runtime.sendMessage(
    { type: "PHISHWATCH_SCAN", url },
    (response) => {
      didRespond = true;
      clearTimeout(failTimer);
      scanInFlight = false;

      if (chrome.runtime.lastError) {
        setOverlayError(`Background error: ${chrome.runtime.lastError.message}`);
        addContinueButtonIfNeeded();
        return;
      }

      // Step 3: render result
      if (!response) {
        setOverlayError("No response from background worker.");
        addContinueButtonIfNeeded();
        return;
      }

      if (response.ok && response.data) {
        setOverlayResult(response.data);
      } else if (response.error) {
        setOverlayError(String(response.error));
      } else {
        setOverlayResult(response.data ?? response);
      }

      // always offer user a path forward after intercepting navigation
      addContinueButtonIfNeeded();
    }
  );
}

/* =========================
   Outbound click interception
   ========================= */

document.addEventListener(
  "click",
  (e) => {
    const a = e.target?.closest?.("a[href]");
    if (!a) return;

    if (e.defaultPrevented) return;
    if (e.button !== 0) return;
    if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
    if (a.hasAttribute("download")) return;

    const href = a.getAttribute("href");
    if (!href || href.startsWith("#") || href.startsWith("javascript:")) return;

    let targetUrl;
    try {
      targetUrl = new URL(href, location.href).toString();
    } catch {
      return;
    }

    // Only intercept outbound navigation
    if (new URL(targetUrl).origin === location.origin) return;

    console.log("[PhishWatch] outbound click → scanning", targetUrl);

    e.preventDefault();
    e.stopPropagation();

    pendingNavigationUrl = targetUrl;
    runScan("outbound_click", targetUrl);
  },
  true
);

})();
