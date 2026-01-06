// IMPORTANT:
// This file is wrapped in a single IIFE (() => { ... })();
// Do not add/remove braces without checking the final closure.
// PhishWatch content script
console.log("PhishWatch content script loaded:", window.location.href);

(() => {
  const ID = "phishwatch-overlay";
  let lastHref = window.location.href;
  let scanInFlight = false;
  let lastScanAt = 0;

  function ensureOverlay() {
    let el = document.getElementById(ID);
    if (el) return el;

    el = document.createElement("div");
    el.id = ID;

    el.style.position = "fixed";
    el.style.right = "24px";
    el.style.bottom = "24px";
    el.style.zIndex = "2147483647";
    el.style.width = "420px";
    el.style.maxWidth = "calc(100vw - 48px)";
    el.style.background = "rgba(10, 16, 28, 0.92)";
    el.style.color = "#fff";
    el.style.border = "1px solid rgba(255,255,255,0.10)";
    el.style.borderRadius = "14px";
    el.style.boxShadow = "0 12px 32px rgba(0,0,0,0.35)";
    el.style.fontFamily =
      "-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Inter,Helvetica,Arial,sans-serif";
    el.style.backdropFilter = "blur(10px)";
    el.style.overflow = "hidden";

    el.innerHTML = `
      <div style="display:flex;align-items:flex-start;justify-content:space-between;padding:14px 14px 8px 14px;">
        <div>
          <div style="font-weight:800;font-size:20px;letter-spacing:0.2px;">PhishWatch</div>
          <div id="pw-sub" style="opacity:0.85;margin-top:6px;font-size:14px;">Scanning this page…</div>
        </div>
        <button id="pw-close" aria-label="Close" style="all:unset;cursor:pointer;opacity:0.7;font-size:22px;line-height:1;">×</button>
      </div>

      <div id="pw-body" style="padding:0 14px 14px 14px;font-size:13px;line-height:1.35;opacity:0.95;"></div>

      <div id="pw-toast" style="display:none;margin:0 14px 14px 14px;padding:10px;border-radius:10px;
        border:1px solid rgba(255,255,255,0.10);background:rgba(255,255,255,0.06);opacity:0.95;"></div>
    `;

    document.documentElement.appendChild(el);

    el.querySelector("#pw-close").addEventListener("click", () => el.remove());

    return el;
  }

  function setOverlay(statusLine, bodyHtml = "") {
    const el = ensureOverlay();
    const sub = el.querySelector("#pw-sub");
    const body = el.querySelector("#pw-body");
    if (sub) sub.textContent = statusLine;
    if (body) body.innerHTML = bodyHtml;
  }

  function toast(msg) {
    const el = ensureOverlay();
    const t = el.querySelector("#pw-toast");
    if (!t) return;
    t.textContent = msg;
    t.style.display = "block";
    setTimeout(() => {
      t.style.display = "none";
      t.textContent = "";
    }, 1200);
  }

  function escapeHtml(s) {
    return String(s)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");
  }

  function severityRank(sev) {
    const s = String(sev || "").toLowerCase();
    if (s === "high") return 3;
    if (s === "medium") return 2;
    if (s === "low") return 1;
    return 0;
  }

  function pill(text) {
    return `<span style="display:inline-block;padding:4px 10px;border-radius:999px;
      border:1px solid rgba(255,255,255,0.12);background:rgba(255,255,255,0.06);font-size:12px;opacity:0.95;">${escapeHtml(
        text
      )}</span>`;
  }

  function renderResult(data) {
    const verdict = data?.verdict ?? "UNKNOWN";
    const score = data?.risk_score ?? "?";
    const riskBand = data?.risk_band ?? "";
    const summary = data?.summary ?? "";
    const finalUrl = data?.final_url ?? "";

    const signalsRaw = Array.isArray(data?.signals) ? data.signals : [];
    const signals = signalsRaw
      .slice()
      .sort((a, b) => severityRank(b?.severity) - severityRank(a?.severity));

    const top = signals.slice(0, 2);
    const rest = signals.slice(2);

    const topHtml = top
      .map((s) => {
        const sev = String(s?.severity || "info").toUpperCase();
        const exp = escapeHtml(s?.explanation || "");
        const dot =
          sev === "HIGH"
            ? "●"
            : sev === "MEDIUM"
            ? "●"
            : sev === "LOW"
            ? "●"
            : "●";
        return `
          <div style="margin-top:10px;padding:12px;border-radius:12px;border:1px solid rgba(255,255,255,0.10);background:rgba(255,255,255,0.04);">
            <div style="display:flex;align-items:center;gap:10px;">
              <div style="font-weight:800;font-size:12px;opacity:0.9;">${dot} ${sev}</div>
            </div>
            <div style="margin-top:6px;font-size:14px;opacity:0.95;">${exp}</div>
          </div>
        `;
      })
      .join("");

    const restHtml = rest
      .map((s) => {
        const sev = String(s?.severity || "info").toUpperCase();
        const exp = escapeHtml(s?.explanation || "");
        return `
          <div style="margin-top:10px;padding:12px;border-radius:12px;border:1px solid rgba(255,255,255,0.10);background:rgba(255,255,255,0.03);">
            <div style="font-weight:700;font-size:12px;opacity:0.85;">${sev}</div>
            <div style="margin-top:6px;font-size:13px;opacity:0.92;">${exp}</div>
          </div>
        `;
      })
      .join("");

    const headerRow = `
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px;">
        <div style="font-weight:900;font-size:24px;letter-spacing:0.4px;">${escapeHtml(
          verdict
        )}</div>
        ${pill(`Risk ${score}`)}
      </div>
      ${
        summary
          ? `<div style="opacity:0.92;font-size:15px;margin-bottom:10px;">${escapeHtml(
              summary
            )}</div>`
          : ""
      }
      <div style="opacity:0.75;margin-bottom:10px;font-size:13px;">
        Final URL: <span style="opacity:0.9;">${escapeHtml(finalUrl)}</span>
      </div>
      ${
        riskBand
          ? `<div style="opacity:0.65;margin-bottom:12px;font-size:12px;">Band: ${escapeHtml(
              riskBand
            )}</div>`
          : `<div style="margin-bottom:12px;"></div>`
      }
    `;

    const actions = `
      <div style="display:flex;gap:10px;margin:10px 0 6px 0;">
        <button id="pw-rescan" style="all:unset;cursor:pointer;padding:10px 14px;border-radius:12px;
          border:1px solid rgba(255,255,255,0.12);background:rgba(255,255,255,0.06);font-weight:700;">
          Re-scan
        </button>
        <button id="pw-copy" style="all:unset;cursor:pointer;padding:10px 14px;border-radius:12px;
          border:1px solid rgba(255,255,255,0.12);background:rgba(255,255,255,0.06);font-weight:700;">
          Copy report
        </button>
        ${
          rest.length
            ? `<button id="pw-toggle" style="all:unset;cursor:pointer;padding:10px 14px;border-radius:12px;
              border:1px solid rgba(255,255,255,0.12);background:rgba(255,255,255,0.06);font-weight:700;">
              Show ${rest.length} more
            </button>`
            : ""
        }
      </div>
    `;

    const moreContainer =
      rest.length > 0
        ? `<div id="pw-more" style="display:none;margin-top:6px;">${restHtml}</div>`
        : "";

    const footer = `<div style="opacity:0.55;margin-top:10px;font-size:12px;">Indicators, not proof.</div>`;

    setOverlay(
      "Scan complete",
      `${headerRow}${actions}${topHtml}${moreContainer}${footer}`
    );

    // Wire buttons after render (elements exist now)
    const el = ensureOverlay();

    const rescanBtn = el.querySelector("#pw-rescan");
    if (rescanBtn) {
      rescanBtn.onclick = () => scanCurrentPage(true);
    }

    const copyBtn = el.querySelector("#pw-copy");
    if (copyBtn) {
      copyBtn.onclick = async () => {
        try {
          const report = {
            input_url: data?.input_url,
            final_url: data?.final_url,
            verdict: data?.verdict,
            risk_score: data?.risk_score,
            risk_band: data?.risk_band,
            summary: data?.summary,
            signals: data?.signals || [],
          };
          await navigator.clipboard.writeText(JSON.stringify(report, null, 2));
          toast("Copied.");
        } catch (e) {
          toast("Copy failed.");
        }
      };
    }

    const toggleBtn = el.querySelector("#pw-toggle");
    const moreEl = el.querySelector("#pw-more");
    if (toggleBtn && moreEl) {
      toggleBtn.onclick = () => {
        const open = moreEl.style.display !== "none";
        moreEl.style.display = open ? "none" : "block";
        toggleBtn.textContent = open ? `Show ${rest.length} more` : "Show less";
      };
    }
  }

  function scanCurrentPage(force = false) {
    const now = Date.now();
    if (!force) {
      // simple throttling: avoid hammering scans during rapid redirects
      if (scanInFlight) return;
      if (now - lastScanAt < 600) return;
    }

    scanInFlight = true;
    lastScanAt = now;

    setOverlay("Scanning this page…", "");

    const url = window.location.href;

    // Browser-level redirect count (HTTP redirects)
    let redirectCount = 0;
    try {
      const nav = performance.getEntriesByType("navigation");
      if (nav && nav[0] && typeof nav[0].redirectCount === "number") {
        redirectCount = nav[0].redirectCount;
      }
    } catch (e) {
      // ignore
    }

    chrome.runtime.sendMessage(
      { type: "PHISHWATCH_SCAN", url, redirect_count: redirectCount },
      (resp) => {
        scanInFlight = false;

        const err = chrome.runtime.lastError;
        if (err) {
          setOverlay(
            "PhishWatch: Scan failed",
            `<div style="opacity:0.85;">${escapeHtml(err.message)}</div>`
          );
          return;
        }

        if (!resp?.ok) {
          setOverlay(
            "PhishWatch: Scan failed",
            `<div style="opacity:0.85;">${escapeHtml(
              resp?.error || "Unknown error"
            )}</div>`
          );
          return;
        }

        renderResult(resp.data);
      }
    );
  }

  // --- Redirect / navigation watcher ---
  // This solves: scan fires on a shortener page, then the page redirects and you never re-scan.
  setInterval(() => {
    const href = window.location.href;
    if (href !== lastHref) {
      lastHref = href;
      scanCurrentPage(true);
    }
  }, 750);

  // Initial scan
  scanCurrentPage(true);
})();
