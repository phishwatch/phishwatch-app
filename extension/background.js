// background.js (MV3 service worker, ES module-safe)
// - Handles scanning via API (avoids CORS)
// - Handles session allowlist RPC via chrome.storage.session

console.log("✅ PhishWatch background service worker loaded (module)");

const PW_TEST = "medium"; // "low" | "medium" | "high" | "" (off)
const BASE_API = "http://127.0.0.1:8080/api/check";
const API_URL = BASE_API + (PW_TEST ? `?pw_test=${PW_TEST}` : "");

const ALLOWLIST_KEY = "allowlist"; // chrome.storage.session key
const FETCH_TIMEOUT_MS = 3500;

chrome.runtime.onInstalled.addListener(() => {
  console.log("✅ PhishWatch installed / updated");
});

chrome.runtime.onStartup.addListener(() => {
  console.log("✅ PhishWatch onStartup");
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg?.type) return;

  // ===============================
  // 1) Session allowlist RPC
  // ===============================
  if (msg.type === "PHISHWATCH_SESSION_RPC") {
    (async () => {
      try {
        const { action, payload } = msg;

        if (action === "allowlist.add") {
  const url = payload?.url;
  if (!url) return sendResponse({ ok: false, error: "missing url" });

  const existing =
    (await chrome.storage.session.get(ALLOWLIST_KEY))[ALLOWLIST_KEY] || [];

  if (!existing.includes(url)) existing.push(url);

  // NEW: store metadata about why it was allowlisted
  const META_KEY = "allowlist_meta";
  const meta =
    (await chrome.storage.session.get(META_KEY))[META_KEY] || {};

  meta[url] = {
    ts: Date.now(),
    reason: payload?.reason || "unknown",
  };

  await chrome.storage.session.set({
    [ALLOWLIST_KEY]: existing,
    [META_KEY]: meta,
  });

  return sendResponse({ ok: true, data: { size: existing.length } });
}


        if (action === "allowlist.has") {
          const url = payload?.url;
          if (!url) return sendResponse({ ok: false, error: "missing url" });

          const list =
            (await chrome.storage.session.get(ALLOWLIST_KEY))[ALLOWLIST_KEY] || [];

          return sendResponse({ ok: true, data: { allowed: list.includes(url) } });
        }

        if (action === "allowlist.clear") {
          await chrome.storage.session.set({ [ALLOWLIST_KEY]: [] });
          return sendResponse({ ok: true });
        }

        return sendResponse({ ok: false, error: `unknown action: ${action}` });
      } catch (e) {
        return sendResponse({ ok: false, error: String(e?.message || e) });
      }
    })();

    return true; // MV3 async response
  }

  // ===============================
  // 2) Scan handler
  // ===============================
  if (msg.type === "PHISHWATCH_SCAN") {
    (async () => {
      try {
        const url = msg?.url;
        if (!url) return sendResponse({ ok: false, error: "missing url" });

        console.log("[PhishWatch BG] scan request:", { url, API_URL });

        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

        const res = await fetch(API_URL, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Cache-Control": "no-store",
          },
          body: JSON.stringify({
            url,
            redirect_count: msg.redirect_count ?? 0,
          }),
          signal: controller.signal,
        }).finally(() => clearTimeout(timeout));

        if (!res.ok) {
          const text = await res.text().catch(() => "");
          return sendResponse({
            ok: false,
            error: `API ${res.status}: ${text || "No body"}`,
          });
        }

        const data = await res.json();
        return sendResponse({ ok: true, data });
      } catch (err) {
        const msg = err?.name === "AbortError"
          ? `API timeout after ${FETCH_TIMEOUT_MS}ms`
          : String(err?.message || err);
        return sendResponse({ ok: false, error: msg });
      }
    })();

    return true; // MV3 async response
  }

  // ignore anything else
});
