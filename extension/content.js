// PhishWatch content script
console.log("PhishWatch content script loaded:", window.location.href);

(() => {
  const ID = "phishwatch-overlay";

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
          <div style="font-weight:700;font-size:18px;letter-spacing:0.2px;">PhishWatch</div>
          <div id="pw-sub" style="opacity:0.85;margin-top:6px;font-size:14px;">Scanning this page…</div>
        </div>
        <button id="pw-close" aria-label="Close" style="all:unset;cursor:pointer;opacity:0.7;font-size:22px;line-height:1;">×</button>
      </div>
      <div id="pw-body" style="padding:0 14px 14px 14px;font-size:13px;line-height:1.35;opacity:0.95;"></div>
    `;

    document.documentElement.appendChild(el);
    el.querySelector("#pw-close").addEventListener("click", () => el.remove());
    return el;
  }

  function setOverlay(statusLine, bodyHtml = "") {
    const el = ensureOverlay();
    el.querySelector("#pw-sub").textContent = statusLine;
    el.querySelector("#pw-body").innerHTML = bodyHtml;
  }

  function escapeHtml(s) {
    return String(s)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");
  }

  function renderResult(data) {
    const verdict = data?.verdict ?? "UNKNOWN";
    const score = data?.risk_score ?? "?";
    const finalUrl = data?.final_url ?? "";

    const signals = Array.isArray(data?.signals) ? data.signals : [];
    const topSignals = signals.slice(0, 5).map((s) => {
      const sev = escapeHtml(s?.severity || "info").toUpperCase();
      const exp = escapeHtml(s?.explanation || "");
      return `
        <div style="margin-top:8px;padding:10px;border-radius:10px;border:1px solid rgba(255,255,255,0.10);background:rgba(255,255,255,0.04);">
          <div style="font-weight:600;font-size:12px;opacity:0.9;">${sev}</div>
          <div style="margin-top:4px;font-size:13px;opacity:0.95;">${exp}</div>
        </div>
      `;
    }).join("");

    setOverlay(
      `Verdict: ${verdict} • Risk: ${score}`,
      `
        <div style="opacity:0.85;margin-bottom:8px;">
          Final URL: <span style="opacity:0.95;">${escapeHtml(finalUrl)}</span>
        </div>
        ${topSignals || `<div style="opacity:0.85;">No signals reported.</div>`}
      `
    );
  }

  function scanCurrentPage() {
    setOverlay("Scanning this page…");
    const url = window.location.href;

    chrome.runtime.sendMessage({ type: "PHISHWATCH_SCAN", url }, (resp) => {
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
          `<div style="opacity:0.85;">${escapeHtml(resp?.error || "Unknown error")}</div>`
        );
        return;
      }

      renderResult(resp.data);
    });
  }

  scanCurrentPage();
})();
