// MV3 service worker — performs API calls (avoids CORS issues)
console.log("✅ PhishWatch background service worker loaded");

const API_URL = "http://127.0.0.1:8080/api/check";

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg?.type !== "PHISHWATCH_SCAN") return;

  (async () => {
    try {
      const res = await fetch(API_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: msg.url, redirect_count: msg.redirect_count ?? 0 }),
      });

      if (!res.ok) {
        const text = await res.text().catch(() => "");
        throw new Error(`API ${res.status}: ${text || "No body"}`);
      }

      const data = await res.json();
      sendResponse({ ok: true, data });
    } catch (err) {
      sendResponse({ ok: false, error: String(err?.message || err) });
    }
  })();

  // Required so sendResponse works asynchronously
  return true;
});
