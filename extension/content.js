/* PhishWatch content.js (baseline + Phase-2 Step-1 Option A submit detector + submit-safe Continue Anyway)
   + Phase-3 Sensor A (net treadmill): CSP-tolerant injection via pw-net-hook.js
*/

(() => {
  // =========================
  // Constants & logging
  // =========================
  const DEBUG = true;
  const pwLog = (msg, obj) => {
    if (!DEBUG) return;
    try {
      console.log(`[PhishWatch] ${msg}`, obj || "");
    } catch {}
  };

  const OVERLAY_ID = "phishwatch-overlay";
  const ALLOW_ACTION_TYPE = "PHISHWATCH_SESSION_RPC";
  const SCAN_TYPE = "PHISHWATCH_SCAN";

  // Phase-2 flag (currently true for testing)
  const PW_ENABLE_PHASE2_CRED_FORM = false;

  // Silent allowlist suffixes
  const SILENT_ALLOW_SUFFIXES = [
    ".google.com",
    ".microsoftonline.com",
    ".live.com",
    ".github.com",
    ".stripe.com",
    ".paypal.com",
    ".apple.com",
    ".amazon.com",
    ".okta.com",
    ".auth0.com",
    ".gitlab.com",
    ".linkedin.com",
    ".x.com",
    ".twitter.com",
    ".facebook.com",
    ".instagram.com",
    ".cloudflare.com",
    ".vercel.app",
    ".netlify.app",
    ".onrender.com",
    ".railway.app",
    ".ngrok-free.app",
    ".ngrok.app",
    ".localhost",
  ];

  // Prescan thresholds
  const PRESCAN_LONG_URL = 220;
  const PRESCAN_LONG_QUERY = 120;

  // =========================
  // State
  // =========================
  let overlayEl = null;
  let pendingUrl = null;
  let scanInFlight = false;
  let scanSeq = 0;
  let interceptionEnabled = true;

  // Submit bypass flag so form.submit() doesn't loop back into our submit capture
  let submitBypass = false;

  // When overlay was triggered by a FORM submit, keep a handle so "Continue anyway" can submit (POST)
  let pendingSubmitForm = null;

  // =========================
  // Phase-3 Sensor A: Network treadmill
  // =========================
  const PW_ENABLE_PHASE3_NET_TREADMILL = true;
  const PW_PHASE3_AUTH_WINDOW_MS = 1500;
  const PW_PHASE3_WATCH_METHODS = new Set(["POST", "PUT", "PATCH"]);

  const PW_NET_RING_MAX = 80;

  let pwLastPasswordFocusTs = 0;
  let pwLastPasswordSubmitTs = 0;

  // Origins we have already seen during *current* auth window
  const pwSeenRequestOrigins = new Set();

  // Ring buffer of events (content-script-side)
  let pwNetTreadmillEvents = [];

  function pwNow() {
    return Date.now();
  }

  function pwInAuthWindow(ts) {
    const t0 = Math.max(pwLastPasswordFocusTs || 0, pwLastPasswordSubmitTs || 0);
    if (!t0) return false;
    return ts >= t0 && ts - t0 <= PW_PHASE3_AUTH_WINDOW_MS;
  }

  function pwNetTreadmillEventsShiftSafe() {
    try {
      pwNetTreadmillEvents.shift();
    } catch {}
  }

  function pwRememberNetEvent(evt) {
    pwNetTreadmillEvents.push(evt);
    if (pwNetTreadmillEvents.length > PW_NET_RING_MAX) pwNetTreadmillEventsShiftSafe();
  }

  function pwPhase3ArmAuthWindow(reason) {
    try {
      if (!PW_ENABLE_PHASE3_NET_TREADMILL) return;

      const ts = pwNow();
      if (reason === "focus") pwLastPasswordFocusTs = ts;
      else if (reason === "submit") pwLastPasswordSubmitTs = ts;

      pwLog("P3 auth window armed", { reason, ts });

      // Reset per-window state
      pwSeenRequestOrigins.clear();
      pwNetTreadmillEvents.length = 0;
    } catch {}
  }

  function pwPhase3OnFocusIn(evt) {
    try {
      if (!PW_ENABLE_PHASE3_NET_TREADMILL) return;
      const el = evt?.target || null;
      if (!el) return;

      if (el.tagName === "INPUT" && String(el.type || "").toLowerCase() === "password") {
        pwPhase3ArmAuthWindow("focus");
      }
    } catch {}
  }

  function phase3NetTreadmillSignal(expectedOrigin) {
    try {
      if (!PW_ENABLE_PHASE3_NET_TREADMILL) return null;
      if (!expectedOrigin) return null;

      const t0 = Math.max(pwLastPasswordFocusTs || 0, pwLastPasswordSubmitTs || 0);
      if (!t0) return null;

      const windowEnd = t0 + PW_PHASE3_AUTH_WINDOW_MS;

      // Only consider:
      // - within auth window
      // - cross-origin vs expectedOrigin
      // - "new origin" events (helps avoid common same-provider noise)
      const relevant = (pwNetTreadmillEvents || []).filter((ev) => {
        if (!ev || !ev.ts || !ev.destination_origin) return false;
        if (ev.ts < t0 || ev.ts > windowEnd) return false;
        if (ev.destination_origin === expectedOrigin) return false;
        if (ev.is_new_origin !== true) return false;
        return true;
      });

      // Noise guard: require at least 2 events
      if (relevant.length < 2) return null;

      const uniq = Array.from(new Set(relevant.map((ev) => ev.destination_origin))).slice(0, 6);

      let minDelta = null;
      try {
        const nums = relevant
          .map((ev) => (typeof ev.timing_ms_since_auth === "number" ? ev.timing_ms_since_auth : null))
          .filter((x) => typeof x === "number" && isFinite(x));
        if (nums.length) minDelta = Math.min(...nums);
      } catch {}

      return {
        id: "unexpected_cross_origin_post_during_auth",
        severity: "medium",
        explanation:
          "While credentials were being entered/submitted, the page made background requests to new external sites.",
        evidence: {
          expected_origin: expectedOrigin,
          observed_origins: uniq,
          event_count: relevant.length,
          min_timing_ms_since_auth: minDelta,
          window_ms: PW_PHASE3_AUTH_WINDOW_MS,
          counted_only_new_origins: true,
          min_event_count: 2,
        },
      };
    } catch (e) {
      pwLog("phase3NetTreadmillSignal: error", { e: String(e) });
      return null;
    }
  }

  // =========================
  // Utilities
  // =========================
  function hostFromUrl(u) {
    try {
      return new URL(u).hostname || "";
    } catch {
      return "";
    }
  }

  function normalizeForAllowlist(u) {
  try {
    const url = new URL(u);

    // Canonicalize host/protocol and drop query/hash
    const protocol = (url.protocol || "").toLowerCase();
    const host = (url.host || "").toLowerCase(); // includes port if present

    // Normalize pathname: collapse multiple slashes, strip trailing slash (except root)
    let path = url.pathname || "/";
    path = path.replace(/\/{2,}/g, "/");
    if (path.length > 1 && path.endsWith("/")) path = path.slice(0, -1);

    return `${protocol}//${host}${path}`;
  } catch {
    return (u || "").trim();
  }
}


  function looksLikeIpLiteral(host) {
    return /^\d{1,3}(\.\d{1,3}){3}$/.test(host || "");
  }

  function hasPunycode(host) {
    return (host || "").includes("xn--");
  }

  function hasShortenerLikeHost(host) {
    const h = (host || "").toLowerCase();
    return (
      h === "bit.ly" ||
      h === "t.co" ||
      h === "tinyurl.com" ||
      h === "is.gd" ||
      h === "goo.gl" ||
      h === "ow.ly" ||
      h === "buff.ly" ||
      h === "rebrand.ly" ||
      h === "rb.gy"
    );
  }

  function isSilentlyAllowedTarget(url) {
    try {
      const h = hostFromUrl(url).toLowerCase();
      if (!h) return false;
      for (const suf of SILENT_ALLOW_SUFFIXES) {
        const s = (suf || "").toLowerCase();
        if (!s) continue;
        if (h === s.replace(/^\./, "")) return true;
        if (h.endsWith(s)) return true;
      }
      return false;
    } catch {
      return false;
    }
  }

  function prescanHints(url) {
    const hints = [];
    try {
      const u = new URL(url);
      const full = url || "";
      const query = (u.search || "").slice(1);

      if (full.length >= PRESCAN_LONG_URL) hints.push("long_url");
      if (query.length >= PRESCAN_LONG_QUERY) hints.push("long_query");

      const h = (u.hostname || "").toLowerCase();
      if (looksLikeIpLiteral(h)) hints.push("ip_literal_host");
      if (hasPunycode(h)) hints.push("punycode_host");
      if (hasShortenerLikeHost(h)) hints.push("shortener_like_host");

      for (const k of [
        "redirect",
        "redir",
        "url",
        "dest",
        "destination",
        "next",
        "target",
        "continue",
        "return",
      ]) {
        if (u.searchParams.has(k)) hints.push(`param_${k}`);
      }
    } catch {}
    return hints;
  }

  function escapeHtml(s) {
    return String(s || "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");
  }

  function pwHasRuntime() {
    return typeof chrome !== "undefined" && chrome?.runtime?.sendMessage;
  }

  // Replace your existing pwSendMessageSafe with this whole function.
  // It safely handles "Extension context invalidated" and chrome.runtime.lastError.
  function pwSendMessageSafe(payload, timeoutMs = 8000) {
    return new Promise((resolve) => {
      if (!pwHasRuntime()) {
        resolve(null);
        return;
      }

      let done = false;
      const t = setTimeout(() => {
        if (done) return;
        done = true;
        resolve(null);
      }, timeoutMs);

      try {
        chrome.runtime.sendMessage(payload, (resp) => {
          if (done) return;
          done = true;
          clearTimeout(t);

          try {
            const le = chrome.runtime?.lastError;
            if (le) {
              pwLog("pwSendMessageSafe: lastError", { err: String(le.message || le) });
              resolve(null);
              return;
            }
          } catch {}

          resolve(resp);
        });
      } catch (err) {
        pwLog("pwSendMessageSafe: sendMessage failed", { err: String(err) });
        if (done) return;
        done = true;
        clearTimeout(t);
        resolve(null);
      }
    });
  }

  function pwSessionRpc(action, payload, timeoutMs = 2000) {
  return pwSendMessageSafe(
    { type: ALLOW_ACTION_TYPE, action, payload },
    timeoutMs
  ).then((resp) => {
    // resp can be:
    // 1) { ok:true, allowed:true }
    // 2) { ok:true, ok:true }
    // 3) { ok:true, data:{ ... } }   (if you ever wrap later)
    if (!resp || resp.ok !== true) return null;

    const inner = (resp && resp.data && typeof resp.data === "object") ? resp.data : resp;

    // Normalize to a single shape with ok + flattened fields.
    return { ok: true, ...inner };
  });
}



  // CSP-tolerant injection via external script (page context)
  function pwInstallNetTreadmillHook() {
    if (!PW_ENABLE_PHASE3_NET_TREADMILL) return;

    // Marker visible from page console (this one is set by content script)
    try {
      document.documentElement.setAttribute("data-pw-net-hook-content", "1");
    } catch {}

    // Avoid double inject
    if (document.getElementById("pw-net-hook-script")) return;

    try {
      const s = document.createElement("script");
      s.id = "pw-net-hook-script";
      s.async = false;
      s.src = chrome.runtime.getURL("pw-net-hook.js");
      s.onload = () => pwLog("P3 net hook injected (src)", { ok: true });
      s.onerror = () => pwLog("P3 net hook injected (src) FAILED", { ok: false });
      (document.documentElement || document.head || document.body).appendChild(s);
    } catch (e) {
      pwLog("P3 net hook inject exception", { e: String(e) });
    }

    // Single listener: receives events from page hook.
    // Expected event detail shape (from pw-net-hook.js):
    //   { method: "POST", destination_origin: "https://example.com", ts: 1234567890 }
    window.addEventListener(
      "phishwatch_net_event",
      (e) => {
        try {
          const d = e?.detail || null;
          if (!d) return;

          const method = String(d.method || "GET").toUpperCase();
          const destOrigin = String(d.destination_origin || d.origin || "");
          const ts = Number(d.ts || 0);
          const isTest = !!(DEBUG && d.__pw_test);

          if (!destOrigin || !ts) return;
          if (!PW_PHASE3_WATCH_METHODS.has(method)) return;

          const t0 = Math.max(pwLastPasswordFocusTs || 0, pwLastPasswordSubmitTs || 0);
          if (!t0) return;

          const inWindow = ts >= t0 && ts - t0 <= PW_PHASE3_AUTH_WINDOW_MS;
          if (!inWindow && !isTest) return;

          // Ignore same-origin as the page itself (noise)
          if (destOrigin === window.location.origin) return;

          // Allowlist-by-suffix uses a URL; create a pseudo URL from origin
          const pseudoUrl = destOrigin + "/";
          if (isSilentlyAllowedTarget(pseudoUrl)) return;

          const isNewOrigin = !pwSeenRequestOrigins.has(destOrigin);
          pwSeenRequestOrigins.add(destOrigin);

          const deltaMs = isTest ? 0 : ts - t0;

          const evtObj = {
            type: "network_treadmill",
            method,
            destination_origin: destOrigin,
            is_new_origin: isNewOrigin,
            timing_ms_since_auth: typeof deltaMs === "number" ? deltaMs : null,
            ts,
          };

          pwRememberNetEvent(evtObj);
          pwLog("P3 net treadmill event", evtObj);
        } catch (err) {
          pwLog("P3 net treadmill handler error", { err: String(err) });
        }
      },
      true
    );
  }

  // =========================
  // Overlay UI
  // =========================
  function ensureOverlay() {
    let el = document.getElementById(OVERLAY_ID);
    if (el) {
      overlayEl = el;
      return el;
    }

    el = document.createElement("div");
    el.id = OVERLAY_ID;
    el.style.position = "fixed";
    el.style.top = "0";
    el.style.left = "0";
    el.style.right = "0";
    el.style.bottom = "0";
    el.style.zIndex = "2147483647";
    el.style.background = "rgba(0,0,0,0.55)";
    el.style.display = "flex";
    el.style.alignItems = "center";
    el.style.justifyContent = "center";
    el.style.fontFamily = "system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif";

    el.innerHTML = `
      <div style="width:min(720px,92vw);background:#111;border:1px solid rgba(255,255,255,0.12);
                  border-radius:14px;box-shadow:0 14px 60px rgba(0,0,0,0.6);overflow:hidden;">
        <div style="padding:14px 16px;border-bottom:1px solid rgba(255,255,255,0.10);display:flex;gap:10px;align-items:center;justify-content:space-between;">
          <div style="color:#fff;font-weight:700;letter-spacing:0.2px;">PhishWatch</div>
          <button id="pw-close" style="background:transparent;border:1px solid rgba(255,255,255,0.18);
                    color:#fff;border-radius:10px;padding:6px 10px;cursor:pointer;">Close</button>
        </div>
        <div id="pw-body" style="padding:14px 16px;color:#eaeaea;">
          <div style="opacity:0.9">Scanning…</div>
        </div>
        <div id="pw-actions" style="padding:14px 16px;border-top:1px solid rgba(255,255,255,0.10);display:flex;gap:10px;justify-content:flex-end;">
          <button id="pw-continue" style="background:#fff;border:none;color:#111;border-radius:12px;padding:10px 14px;cursor:pointer;font-weight:700;">Continue anyway</button>
          <button id="pw-cancel" style="background:transparent;border:1px solid rgba(255,255,255,0.18);
                    color:#fff;border-radius:12px;padding:10px 14px;cursor:pointer;">Go back</button>
        </div>
      </div>
    `;

    document.documentElement.appendChild(el);
    overlayEl = el;

    const closeBtn = el.querySelector("#pw-close");
    const contBtn = el.querySelector("#pw-continue");
    const cancelBtn = el.querySelector("#pw-cancel");

    if (closeBtn) closeBtn.addEventListener("click", closeOverlay);
    if (cancelBtn) cancelBtn.addEventListener("click", closeOverlay);
    if (contBtn) contBtn.addEventListener("click", continueAnyway);

    return el;
  }

  function closeOverlay() {
    cleanupOverlay();
  }

  function cleanupOverlay() {
    try {
      const el = document.getElementById(OVERLAY_ID);
      if (el) el.remove();
    } catch {}
    overlayEl = null;
  }

  function setActionsEnabled(enabled) {
    try {
      const el = overlayEl || document.getElementById(OVERLAY_ID);
      if (!el) return;
      const cont = el.querySelector("#pw-continue");
      const cancel = el.querySelector("#pw-cancel");
      if (cont) cont.disabled = !enabled;
      if (cancel) cancel.disabled = !enabled;
      if (cont) cont.style.opacity = enabled ? "1" : "0.55";
      if (cancel) cancel.style.opacity = enabled ? "1" : "0.55";
    } catch {}
  }

  function setOverlayScanning(url) {
    const el = ensureOverlay();
    const body = el.querySelector("#pw-body");
    if (body) {
      body.innerHTML = `
        <div style="font-weight:700;color:#fff;margin-bottom:6px;">Scanning link…</div>
        <div style="font-size:13px;opacity:0.85;word-break:break-all;">${escapeHtml(url)}</div>
        <div style="margin-top:10px;font-size:13px;opacity:0.75">Please wait</div>
      `;
    }
    setActionsEnabled(false);
  }

  function setOverlayStillScanning(url) {
    const el = ensureOverlay();
    const body = el.querySelector("#pw-body");
    if (body) {
      body.innerHTML = `
        <div style="font-weight:700;color:#fff;margin-bottom:6px;">Still scanning…</div>
        <div style="font-size:13px;opacity:0.85;word-break:break-all;">${escapeHtml(url)}</div>
      `;
    }
    setActionsEnabled(false);
  }

  function maxSeverityRank(signals) {
    const rank = { low: 1, medium: 2, high: 3 };
    let m = 0;
    for (const s of signals || []) {
      const r = rank[(s?.severity || "").toLowerCase()] || 0;
      if (r > m) m = r;
    }
    return m;
  }

  function renderScanResult(data) {
    const el = ensureOverlay();
    const body = el.querySelector("#pw-body");

    const riskBand = (data?.risk_band || "unknown").toUpperCase();
    const summary = data?.summary || "PhishWatch flagged something unusual on this transition.";
    const url = pendingUrl || "";

    const signals = Array.isArray(data?.signals) ? data.signals : [];
    const sigHtml = signals.length
      ? `<div style="margin-top:12px;">
           <div style="font-weight:700;margin-bottom:8px;">Signals</div>
           <div style="display:flex;flex-direction:column;gap:8px;">
             ${signals
               .slice(0, 10)
               .map((s) => {
                 const sev = (s?.severity || "low").toUpperCase();
                 const id = escapeHtml(s?.id || "");
                 const exp = escapeHtml(s?.explanation || "");
                 const ev = s?.evidence ? escapeHtml(JSON.stringify(s.evidence)) : "";
                 return `
                   <div style="border:1px solid rgba(255,255,255,0.14);border-radius:12px;padding:10px 12px;">
                     <div style="display:flex;gap:10px;align-items:center;justify-content:space-between;">
                       <div style="font-weight:700;">${id}</div>
                       <div style="font-size:12px;opacity:0.85;">${sev}</div>
                     </div>
                     <div style="margin-top:6px;opacity:0.92;font-size:13px;line-height:1.35;">${exp}</div>
                     ${ev ? `<div style="margin-top:6px;opacity:0.7;font-size:12px;word-break:break-all;">${ev}</div>` : ""}
                   </div>
                 `;
               })
               .join("")}
           </div>
         </div>`
      : "";

    if (body) {
      body.innerHTML = `
        <div style="display:flex;align-items:center;justify-content:space-between;gap:10px;">
          <div style="font-weight:800;font-size:14px;">Risk: ${escapeHtml(riskBand)}</div>
          <div style="font-size:12px;opacity:0.75;">${escapeHtml(new Date().toLocaleString())}</div>
        </div>
        <div style="margin-top:10px;font-size:13px;opacity:0.92;line-height:1.35;">${escapeHtml(summary)}</div>
        <div style="margin-top:10px;font-size:12px;opacity:0.75;word-break:break-all;">${escapeHtml(url)}</div>
        ${sigHtml}
      `;
    }

    setActionsEnabled(true);
  }

  // =========================
  // Navigation helpers
  // =========================
  function failOpenNavigate(url) {
    try {
      cleanupOverlay();
      window.location.href = url;
    } catch (e) {
      pwLog("failOpenNavigate: exception", { url, e: String(e) });
    }
  }

  // BFCache reset
  window.addEventListener("pageshow", (e) => {
    try {
      if (e?.persisted) {
        pwLog("pageshow: bfcache restore; resetting state");
        scanInFlight = false;
        pendingUrl = null;
        pendingSubmitForm = null;
        cleanupOverlay();
      }
    } catch {}
  });

  // =========================
  // Phase-2 context detection
  // =========================
  function detectCredentialSurface() {
    try {
      const pw = document.querySelector('input[type="password"]');
      if (pw) return { credential_surface: true, method: "password_input_present" };
      return { credential_surface: false, method: "none" };
    } catch {
      return { credential_surface: false, method: "error" };
    }
  }

  function detectCrossOriginCredentialFormSignal() {
    try {
      if (!PW_ENABLE_PHASE2_CRED_FORM) return null;
      const pw = document.querySelector('input[type="password"]');
      if (!pw) return null;
      const form = pw.closest("form");
      if (!form) return null;

      const action = (form.getAttribute("action") || "").trim();
      if (!action) return null;

      const actionUrl = new URL(action, window.location.href).toString();
      const pageOrigin = window.location.origin;
      const actionOrigin = new URL(actionUrl).origin;

      if (actionOrigin === pageOrigin) return null;
      if (isSilentlyAllowedTarget(actionUrl)) return null;

      return {
        id: "credential_form_action_cross_origin",
        severity: "medium",
        explanation:
          "This page contains a password form that submits credentials to a different site than the page you’re on.",
        evidence: {
          page_origin: pageOrigin,
          form_action: actionUrl,
          form_action_origin: actionOrigin,
        },
      };
    } catch (e) {
      pwLog("detectCrossOriginCredentialFormSignal: error", { e: String(e) });
      return null;
    }
  }

  function resolveFormActionUrl(form) {
    try {
      const raw = (form.getAttribute("action") || "").trim();
      if (!raw) return null;
      return new URL(raw, window.location.href).toString();
    } catch {
      return null;
    }
  }

  function detectCrossOriginCredentialSubmitSignalForForm(form) {
    try {
      if (!PW_ENABLE_PHASE2_CRED_FORM) return null;
      if (!form || typeof form.querySelector !== "function") return null;

      const pw = form.querySelector('input[type="password"]');
      if (!pw) return null;

      const actionUrl = resolveFormActionUrl(form);
      if (!actionUrl) return null;

      const pageOrigin = window.location.origin;
      const actionOrigin = new URL(actionUrl).origin;
      if (actionOrigin === pageOrigin) return null;

      if (isSilentlyAllowedTarget(actionUrl)) return null;

      return {
        id: "credential_form_action_cross_origin",
        severity: "medium",
        explanation: "This password form submits credentials to a different site than the page you’re on.",
        evidence: {
          page_origin: pageOrigin,
          form_action: actionUrl,
          form_action_origin: actionOrigin,
        },
      };
    } catch (e) {
      pwLog("detectCrossOriginCredentialSubmitSignalForForm: error", { e: String(e) });
      return null;
    }
  }

  // =========================
  // Allowlist helpers
  // =========================
  async function addToAllowlist(url) {
  try {
    const target = normalizeForAllowlist(url);
    const data = await pwSessionRpc("allowlist.add", { url: normalizeForAllowlist(target)});
    return !!data?.ok; // <-- now checks the real result
  } catch (e) {
    pwLog("addToAllowlist: error", { e: String(e) });
    return false;
  }
}


  // =========================
  // Continue anyway (submit-safe)
  // =========================
  async function continueAnyway() {
    try {
      const target = pendingUrl;
      if (!target) {
        pwLog("continueAnyway: no pendingUrl");
        cleanupOverlay();
        return;
      }

      const ok = await addToAllowlist(target);
      pwLog("continueAnyway: allowlist add result", { target, ok });

      if (pendingSubmitForm) {
        const form = pendingSubmitForm;
        pendingSubmitForm = null;

        cleanupOverlay();

        submitBypass = true;
        try {
          form.submit();
        } finally {
          setTimeout(() => {
            submitBypass = false;
          }, 0);
        }
        return;
      }

      cleanupOverlay();
      failOpenNavigate(target);
    } catch (e) {
      pwLog("continueAnyway: error", { e: String(e) });
      cleanupOverlay();

      if (pendingSubmitForm) {
        const form = pendingSubmitForm;
        pendingSubmitForm = null;

        submitBypass = true;
        try {
          form.submit();
        } finally {
          setTimeout(() => {
            submitBypass = false;
          }, 0);
        }
        return;
      }

      if (pendingUrl) failOpenNavigate(pendingUrl);
    }
  }

  // =========================
  // Core scan logic
  // =========================
  async function runScan(url, prescanReasonList, opts) {
    opts = opts || {};
    const proceed = typeof opts.proceed === "function" ? opts.proceed : () => failOpenNavigate(url);

    // allowlist short-circuit (handle pwSessionRpc wrapper shape)
try {
  const key = normalizeForAllowlist(url);
  const r = await pwSessionRpc("allowlist.has", { url: key });

  // pwSessionRpc may return either:
  // 1) { ok:true, allowed:true }
  // 2) { ok:true, data:{ ok:true, allowed:true } }
  const inner = r?.data ?? r;
  const innerOk = inner?.ok === true || r?.ok === true; // tolerate either placement
  const allowed = inner?.allowed === true;

  pwLog("runScan: allowlist.has", { url, key, r });

  if (innerOk && allowed) {
    pwLog("runScan: allowlist hit; skipping scan/overlay", { url, key });
    cleanupOverlay();
    proceed();   // <-- this is the important part
    return;
  }
} catch (e) {
  pwLog("runScan: allowlist check failed; continuing scan", { url, e: String(e) });
}


    scanInFlight = true;
    scanSeq += 1;
    const mySeq = scanSeq;

    try {
      if (!overlayEl) setOverlayScanning(url);
      else setOverlayStillScanning(url);

      const resp = await pwSendMessageSafe({ type: SCAN_TYPE, url });

      // Backend fallback
      let data = resp && resp.ok && resp.data ? resp.data : null;
      if (!data) {
        data = {
          risk_band: "low",
          summary: "Scan unavailable. Showing local checks only.",
          signals: [],
        };
      }

      // Local signals
      try {
        data.signals = Array.isArray(data.signals) ? data.signals : [];

        const localSig = detectCrossOriginCredentialFormSignal();
        if (localSig && !data.signals.some((s) => s && s.id === localSig.id)) {
          data.signals.push(localSig);
        }

        let expectedOrigin = null;
        try {
          expectedOrigin = new URL(url, window.location.href).origin;
        } catch {}

        const p3 = phase3NetTreadmillSignal(expectedOrigin);
        if (p3 && !data.signals.some((s) => s && s.id === p3.id)) {
          data.signals.push(p3);
        }

        const maxRank = maxSeverityRank(data.signals);
        if (maxRank >= 3) data.risk_band = "high";
        else if (maxRank >= 2 && (data.risk_band === "low" || !data.risk_band)) data.risk_band = "medium";
        else if (!data.risk_band) data.risk_band = "low";

        const credCtx = detectCredentialSurface();
        data.credential_surface = credCtx?.credential_surface;
        data.credential_surface_method = credCtx?.method;
      } catch (e) {
        pwLog("runScan: local signal inject failed", { e: String(e) });
        if (!data.risk_band) data.risk_band = "low";
      }

      if (!data.summary) data.summary = "PhishWatch completed the scan.";

      // Risk-gated UX
      if (data.risk_band === "low") {
        pwLog("runScan: low risk; proceeding silently", { url });
        pendingSubmitForm = null;
        cleanupOverlay();
        proceed();
        return;
      }

      renderScanResult(data);
    } catch (e) {
      pwLog("runScan: exception; fail-open", { url, e: String(e) });
      cleanupOverlay();
      proceed();
    } finally {
      if (mySeq === scanSeq) scanInFlight = false;
    }
  }

  // =========================
  // Outbound click interception (Phase-1)
  // =========================
  function isOutboundNavigation(href) {
    try {
      const u = new URL(href, window.location.href);
      return u.origin !== window.location.origin;
    } catch {
      return false;
    }
  }

  function findAnchor(el) {
    let cur = el;
    for (let i = 0; i < 6 && cur; i++) {
      if (cur.tagName === "A" && cur.href) return cur;
      cur = cur.parentElement;
    }
    return null;
  }

  function shouldIgnoreClick(evt, a) {
    try {
      if (!a || !a.href) return true;
      if (evt.defaultPrevented) return true;
      if (evt.button !== 0) return true;
      if (evt.metaKey || evt.ctrlKey || evt.shiftKey || evt.altKey) return true;
      const href = a.getAttribute("href") || "";
      if (!href || href.startsWith("#") || href.startsWith("javascript:")) return true;
      return false;
    } catch {
      return true;
    }
  }

  async function onClickCapture(evt) {
    try {
      if (!interceptionEnabled) return;

      const a = findAnchor(evt.target);
      if (!a) return;
      if (shouldIgnoreClick(evt, a)) return;

      const url = a.href;
      if (!url) return;

      if (!isOutboundNavigation(url)) return;

      if (isSilentlyAllowedTarget(url)) {
        pwLog("onClickCapture: silently allowed target", { url });
        return;
      }

      const hints = prescanHints(url);
      if (hints.length === 0) return;

      evt.preventDefault();
      evt.stopPropagation();

      pendingUrl = url;
      pendingSubmitForm = null; // link flow
      setOverlayScanning(url);

      try {
      const resp = await pwSessionRpc("allowlist.has", { url: normalizeForAllowlist(url) });
      if (resp && resp.allowed) {
        pwLog("onClickCapture: allowlist hit; skipping overlay", { url });
        cleanupOverlay();
        failOpenNavigate(url);
        return;
      }
    } catch {}

      runScan(url, hints);
    } catch (e) {
      pwLog("onClickCapture: exception; fail-open", { e: String(e) });
    }
  }

  // =========================
  // Submit interception (Phase-2 Step-1 Option A)
  // =========================
  function onSubmitCapture(evt) {
    try {
      if (!interceptionEnabled) return;
      if (!PW_ENABLE_PHASE2_CRED_FORM) return;
      if (submitBypass) return;

      const form = evt.target && evt.target.tagName === "FORM" ? evt.target : null;
      if (!form) return;

      const sig = detectCrossOriginCredentialSubmitSignalForForm(form);
      if (!sig) return;

      const actionUrl = sig?.evidence?.form_action;
      if (!actionUrl) return;

      evt.preventDefault();
      evt.stopPropagation();

      // Arm Phase-3 auth window on submit too
      pwPhase3ArmAuthWindow("submit");

      pendingUrl = actionUrl;
      pendingSubmitForm = form;

      runScan(actionUrl, ["credential_submit_cross_origin"], {
        proceed: () => {
          const f = pendingSubmitForm || form;
          pendingSubmitForm = null;

          submitBypass = true;
          try {
            f.submit();
          } finally {
            setTimeout(() => {
              submitBypass = false;
            }, 0);
          }
        },
      });
    } catch (e) {
      pwLog("onSubmitCapture: exception; fail-open", { e: String(e) });
    }
  }

  // ============================
  // Wire up listeners
  // ============================
  document.addEventListener("click", onClickCapture, true);
  document.addEventListener("submit", onSubmitCapture, true);

  document.addEventListener("focusin", pwPhase3OnFocusIn, true);
  pwInstallNetTreadmillHook();

  pwLog("content.js loaded", {
    phase2_cred_form: PW_ENABLE_PHASE2_CRED_FORM,
    phase3_net_treadmill: PW_ENABLE_PHASE3_NET_TREADMILL,
    origin: window.location.origin,
  });
})();