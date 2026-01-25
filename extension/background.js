console.log("[PhishWatch] BACKGROUND VERSION: 2026-01-19-FAILFAST-FETCHTIMEOUT+CTX");

const API_BASE = "http://127.0.0.1:8080";
const API_TIMEOUT_MS = 4000;

function jsonOk(data) {
  return { ok: true, data };
}
function jsonErr(error) {
  return { ok: false, error: String(error?.message || error) };
}

async function apiCheck(url, context) {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), API_TIMEOUT_MS);

  try {
    const payload = { url };
    if (context && typeof context === "object") payload.context = context;

    const started = Date.now();

    const r = await fetch(`${API_BASE}/api/check`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });

    const ms = Date.now() - started;

    if (!r.ok) {
      const txt = await r.text().catch(() => "");
      throw new Error(`API ${r.status} in ${ms}ms: ${txt || "request failed"}`);
    }

    const data = await r.json();
    return data;
  } catch (e) {
    if (String(e?.name) === "AbortError") {
      throw new Error(`API timeout after ${API_TIMEOUT_MS}ms`);
    }
    throw e;
  } finally {
    clearTimeout(t);
  }
}

// --- session allowlist helpers (chrome.storage.session) ---
async function getAllowlist() {
  const out = await chrome.storage.session.get(["allowlist"]);
  return Array.isArray(out.allowlist) ? out.allowlist : [];
}
async function setAllowlist(list) {
  await chrome.storage.session.set({ allowlist: list });
}
async function allowlistHas(url) {
  const list = await getAllowlist();
  return list.includes(url);
}
async function allowlistAdd(url) {
  const list = await getAllowlist();
  if (!list.includes(url)) {
    list.push(url);
    await setAllowlist(list);
  }
  return true;
}
async function allowlistClear() {
  await setAllowlist([]);
  return true;
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    try {
    // --- session RPC ---
if (msg?.type === "PHISHWATCH_SESSION_RPC") {
  const { action, payload } = msg;

  if (action === "allowlist.has") {
    const allowed = await allowlistHas(payload?.url);
    return sendResponse({ ok: true, allowed });
  }

  if (action === "allowlist.add") {
    const ok = await allowlistAdd(payload?.url);
    return sendResponse({ ok: true, ok });
  }

  if (action === "allowlist.clear") {
    const ok = await allowlistClear();
    return sendResponse({ ok: true, ok });
  }

  return sendResponse({ ok: false, error: `unknown action: ${action}` });
}



      // --- scan ---
      if (msg?.type === "PHISHWATCH_SCAN") {
        const url = msg?.url;
        const context = msg?.context;

        if (!url) return sendResponse(jsonErr("missing url"));

        // Helpful during testing; safe to keep for now
        // console.log("[PhishWatch] scan request", { url, context });

        const data = await apiCheck(url, context);
        return sendResponse(jsonOk(data));
      }

      return sendResponse(jsonErr("unknown message type"));
    } catch (e) {
      // Always respond—never hang the content script
      return sendResponse(jsonErr(e));
    }
  })();

  return true; // required for async sendResponse
});
