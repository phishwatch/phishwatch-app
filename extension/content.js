console.log("[PhishWatch] CONTENT VERSION: RESET-2026-01-12-C");

(() => {
  "use strict";

  const DEBUG = true;
  const pwLog = (...args) => DEBUG && console.log("[PhishWatch]", ...args);

  const OVERLAY_ID = "phishwatch-overlay";
  const ALLOW_ACTION_TYPE = "PHISHWATCH_SESSION_RPC";
  const SCAN_TYPE = "PHISHWATCH_SCAN";

  let overlayEl = null;
  let pendingUrl = null;
  let scanInFlight = false;
  let scanSeq = 0; // token to invalidate old timers/callbacks

  // Fix BFCache “back button weirdness”
  window.addEventListener("pageshow", (event) => {
    if (event.persisted) {
      pwLog("BFCache restore -> reset transient state");
      pendingUrl = null;
      scanInFlight = false;
      cleanupOverlay();
      scanSeq++;
    }
  });

  // ---------- RPC helper ----------
  function pwSessionRpc(action, payload) {
    return new Promise((resolve) => {
      chrome.runtime.sendMessage(
        { type: ALLOW_ACTION_TYPE, action, payload },
        (response) => {
          if (chrome.runtime.lastError) {
            resolve({ ok: false, error: chrome.runtime.lastError.message });
            return;
          }
          resolve(response);
        }
      );
    });
  }

  async function isAllowlisted(url) {
    const resp = await pwSessionRpc("allowlist.has", { url });
    pwLog("allowlist.has ->", resp);
    return !!(resp?.ok && resp.data?.allowed);
  }

  // ---------- Overlay ----------
  function ensureOverlay() {
    if (overlayEl && document.contains(overlayEl)) return overlayEl;

    overlayEl = document.createElement("div");
    overlayEl.id = OVERLAY_ID;

    overlayEl.style.position = "fixed";
    overlayEl.style.top = "16px";
    overlayEl.style.right = "16px";
    overlayEl.style.zIndex = "2147483647";
    overlayEl.style.maxWidth = "380px";
    overlayEl.style.padding = "12px 14px";
    overlayEl.style.borderRadius = "12px";
    overlayEl.style.boxShadow = "0 8px 24px rgba(0,0,0,.18)";
    overlayEl.style.fontFamily =
      "system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif";
    overlayEl.style.fontSize = "13px";
    overlayEl.style.lineHeight = "1.35";
    overlayEl.style.color = "#111";
    overlayEl.style.background = "rgba(255,255,255,.96)";
    overlayEl.style.border = "1px solid rgba(0,0,0,.10)";
    overlayEl.style.backdropFilter = "blur(6px)";
    overlayEl.style.pointerEvents = "auto";

    overlayEl.innerHTML = `
      <div style="display:flex; justify-content:space-between; align-items:center; gap:10px;">
        <div style="font-weight:700;">PhishWatch</div>
        <button id="pw-close" type="button" style="border:0;background:transparent;cursor:pointer;font-size:16px;">✕</button>
      </div>
      <div id="pw-status" style="display:flex; gap:8px; align-items:center; margin-top:6px;">
        <span aria-hidden="true">⏳</span>
        <span>Scanning…</span>
      </div>
      <div id="pw-detail" style="margin-top:8px; color:#333; opacity:.9;"></div>
      <div id="pw-actions" style="margin-top:10px; display:none; gap:8px; justify-content:flex-end;">
        <button id="pw-cancel" type="button" style="padding:8px 10px;border-radius:10px;cursor:pointer;border:1px solid rgba(0,0,0,.14);background:rgba(0,0,0,.03);font-weight:600;">Cancel</button>
        <button id="pw-continue" type="button" style="padding:8px 10px;border-radius:10px;cursor:pointer;border:1px solid rgba(0,0,0,.14);background:rgba(0,0,0,.08);font-weight:700;">Continue anyway</button>
      </div>
    `;

    overlayEl.addEventListener("click", (e) => {
      const t = e.target;
      if (!(t instanceof HTMLElement)) return;

      if (t.id === "pw-close" || t.id === "pw-cancel") {
        cleanupOverlay();
        pendingUrl = null;
        scanInFlight = false;
        scanSeq++; // invalidate any pending timers/callbacks
        return;
      }

      if (t.id === "pw-continue") {
        e.preventDefault();
        e.stopPropagation();
        continueAnyway();
      }
    });

    (document.body || document.documentElement).appendChild(overlayEl);
    return overlayEl;
  }

  function cleanupOverlay() {
    const el = document.getElementById(OVERLAY_ID);
    if (el) el.remove();
    overlayEl = null;
  }

  function setOverlayScanning(url) {
    const el = ensureOverlay();
    el.querySelector("#pw-status").innerHTML =
      `<span aria-hidden="true">⏳</span><span>Scanning…</span>`;
    el.querySelector("#pw-detail").textContent = url;
    el.querySelector("#pw-actions").style.display = "none";
  }

  function setOverlayStillScanning() {
    const el = ensureOverlay();
    el.querySelector("#pw-status").innerHTML =
      `<span aria-hidden="true">⏳</span><span>Still scanning…</span>`;
  }

  function setOverlayError(message) {
    const el = ensureOverlay();
    el.querySelector("#pw-status").innerHTML =
      `<span aria-hidden="true">❌</span><span>Error</span>`;
    el.querySelector("#pw-detail").textContent = String(message || "Unknown error");
    el.querySelector("#pw-actions").style.display = "flex";
  }

  function setOverlayResult(result) {
    const verdict = String(result?.risk_band ?? "unknown").toUpperCase();
    const summary = result?.summary ? String(result.summary) : "";
    const isRisky = verdict === "HIGH" || verdict === "MEDIUM" || verdict === "MALICIOUS";

    const el = ensureOverlay();
    el.querySelector("#pw-status").innerHTML =
      `<span aria-hidden="true">${isRisky ? "⚠️" : "✅"}</span><span>${verdict}</span>`;
    el.querySelector("#pw-detail").textContent =
      summary || (isRisky ? "Risk detected." : "Looks safe.");

    // Not risky -> auto continue
    if (!isRisky && pendingUrl) {
      const go = pendingUrl;
      pendingUrl = null;
      cleanupOverlay();
      scanInFlight = false;
      window.location.assign(go);
      return;
    }

    // Risky -> show actions
    el.querySelector("#pw-actions").style.display = pendingUrl ? "flex" : "none";
  }

  // ---------- Continue anyway ----------
  async function continueAnyway() {
    pwLog("continueAnyway", { pendingUrl, scanInFlight });
    if (!pendingUrl) return;

    const target = pendingUrl;

    const ok = await pwSessionRpc("allowlist.add", { url: target, reason: "user_bypass" });
    pwLog("allowlist.add result", { target, ok });

    pendingUrl = null;
    cleanupOverlay();
    scanInFlight = false;
    window.location.assign(target);
  }

  // ---------- Scan flow ----------
  async function runScan(url) {
    if (!url) return;
    if (scanInFlight) return;

    // Lock immediately to prevent double-click races during allowlist check
    scanInFlight = true;
    pendingUrl = url;
    const mySeq = ++scanSeq;

    // IMPORTANT: allowlist short-circuit BEFORE showing overlay (prevents flash + auto-nav)
    if (await isAllowlisted(url)) {
      pwLog("allowlisted -> navigating (no overlay)", url);
      pendingUrl = null;
      scanInFlight = false;
      cleanupOverlay();
      window.location.assign(url);
      return;
    }

    setOverlayScanning(url);

    // Two-stage timeout: no “error flash”
    const tStill = setTimeout(() => {
      if (scanInFlight && pendingUrl === url && scanSeq === mySeq) {
        setOverlayStillScanning();
      }
    }, 2500);

    const tHard = setTimeout(() => {
      if (scanInFlight && pendingUrl === url && scanSeq === mySeq) {
        setOverlayError("No response from background worker. Reload extension & try again.");
        scanInFlight = false;
      }
    }, 10000);

    chrome.runtime.sendMessage({ type: SCAN_TYPE, url }, (response) => {
      clearTimeout(tStill);
      clearTimeout(tHard);

      // Ignore late responses from a previous scan attempt
      if (scanSeq !== mySeq) return;

      scanInFlight = false;

      if (chrome.runtime.lastError) {
        setOverlayError(`Background error: ${chrome.runtime.lastError.message}`);
        return;
      }
      if (!response) {
        setOverlayError("No response from background worker.");
        return;
      }

      if (response.ok && response.data) setOverlayResult(response.data);
      else if (response.error) setOverlayError(String(response.error));
      else setOverlayResult(response.data ?? response);
    });
  }

  // ---------- Outbound click interception ----------
  function isOutboundNavigation(targetUrl) {
    try {
      const u = new URL(targetUrl, location.href);
      return u.origin !== location.origin;
    } catch {
      return false;
    }
  }

  function findAnchor(t) {
    return t && t.closest ? t.closest("a[href]") : null;
  }

  function shouldIgnoreClick(e, a) {
    if (e.defaultPrevented) return true;
    if (e.button !== 0) return true;
    if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return true;
    if (!a) return true;
    const href = a.getAttribute("href");
    if (!href || href.startsWith("#") || href.startsWith("javascript:")) return true;
    if (a.hasAttribute("download")) return true;
    return false;
  }

  document.addEventListener(
    "click",
    (e) => {
      const a = findAnchor(e.target);
      if (shouldIgnoreClick(e, a)) return;

      const href = a.getAttribute("href");
      let targetUrl;
      try {
        targetUrl = new URL(href, location.href).toString();
      } catch {
        return;
      }

      if (!isOutboundNavigation(targetUrl)) return;

      pwLog("OUTBOUND intercept", { targetUrl });
      e.preventDefault();
      e.stopPropagation();

      runScan(targetUrl);
    },
    true
  );

  console.log("[PhishWatch] content.js loaded on", location.href);
})();
