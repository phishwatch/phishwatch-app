// background.js — PhishWatch (Dev) + Test Helper (fixed routing + ping + aliases)
console.log("[PhishWatch] BACKGROUND VERSION: 2026-02-04-PHASE2-TESTHELPER-FIXED");

const API_BASE = "http://127.0.0.1:8080";
const API_TIMEOUT_MS = 8000;

async function apiCheck(inputUrl, ctx = {}) {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), API_TIMEOUT_MS);

  try {
    const payload = {
      input_url: inputUrl,
      redirect_count: Number(ctx?.redirect_count ?? 0),
      client_signals: Array.isArray(ctx?.client_signals) ? ctx.client_signals : [],
      prescan_reasons: Array.isArray(ctx?.prescan_reasons) ? ctx.prescan_reasons : [],
      is_marketing_infra: Boolean(ctx?.is_marketing_infra),
      treadmill: ctx?.treadmill || null,
    };

    console.log("[PhishWatch] apiCheck payload", payload);

    const r = await fetch(`${API_BASE}/api/check`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });

    const text = await r.text().catch(() => "");
    if (!r.ok) {
      console.warn("[PhishWatch] apiCheck failed", { status: r.status, body: text });
      throw new Error(`API ${r.status}: ${text || "request failed"}`);
    }

    return text ? JSON.parse(text) : null;
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

// --- small helpers for chrome.storage.local with Promises ---
function localGet(keys) {
  return new Promise((resolve) => chrome.storage.local.get(keys, (data) => resolve(data || {})));
}
function localSet(obj) {
  return new Promise((resolve) => chrome.storage.local.set(obj, () => resolve(true)));
}
function localRemove(keys) {
  return new Promise((resolve) => chrome.storage.local.remove(keys, () => resolve(true)));
}

// --- Test Helper handler ---
async function handleTestHelper(actionRaw, payload = {}) {
  const action = String(actionRaw || "").trim();

  // Common aliases (in case pw-test-helper.js uses different names)
  const ALIASES = new Map([
    ["ping", "ping"],
    ["isAvailable", "ping"],
    ["helper.ping", "ping"],

    ["storage.getAll", "storage.getAll"],
    ["storage.get", "storage.getAll"],
    ["getStorage", "storage.getAll"],

    ["storage.clear", "storage.clear"],
    ["storage.clearAll", "storage.clear"],
    ["clearStorage", "storage.clear"],

    ["storage.getBaseline", "storage.getBaseline"],
    ["getBaseline", "storage.getBaseline"],

    ["storage.clearBaseline", "storage.clearBaseline"],
    ["clearBaseline", "storage.clearBaseline"],

    ["storage.seedOrigins", "storage.seedOrigins"],
    ["seedOrigins", "storage.seedOrigins"],

    ["storage.getOrigins", "storage.getOrigins"],
    ["getOrigins", "storage.getOrigins"],
  ]);

  const normalized = ALIASES.get(action) || action;

  console.log("[PhishWatch] Test helper action:", normalized, payload);

  if (normalized === "ping") {
    return { ok: true, data: { alive: true, ts: Date.now(), version: "2026-02-04-PHASE2-TESTHELPER-FIXED" } };
  }

  if (normalized === "storage.getAll") {
    const data = await localGet(null);
    return {
      ok: true,
      data: {
        baseline: data.pw_sequence_baseline || {},
        expectedOrigins: data.pw_expected_origins_by_page_origin || {},
        novelSequences: data.pw_novel_sequences || [],
        lastUpdated: data.pw_baseline_last_updated,
        rawKeys: Object.keys(data || {}),
      },
    };
  }

  if (normalized === "storage.clear") {
    await localRemove([
      "pw_sequence_baseline",
      "pw_expected_origins_by_page_origin",
      "pw_novel_sequences",
      "pw_baseline_last_updated",
    ]);
    return { ok: true, message: "Storage cleared" };
  }

  if (normalized === "storage.getBaseline") {
    const data = await localGet(["pw_sequence_baseline", "pw_novel_sequences"]);
    return {
      ok: true,
      data: {
        baseline: data.pw_sequence_baseline || {},
        novelSequences: data.pw_novel_sequences || [],
      },
    };
  }

  if (normalized === "storage.clearBaseline") {
    await localRemove(["pw_sequence_baseline", "pw_novel_sequences"]);
    return { ok: true, message: "Baseline cleared" };
  }

  if (normalized === "storage.seedOrigins") {
    const pageOrigin = payload.pageOrigin;
    const origins = Array.isArray(payload.origins) ? payload.origins : [];
    if (!pageOrigin) return { ok: false, error: "missing payload.pageOrigin" };

    const data = await localGet(["pw_expected_origins_by_page_origin"]);
    const cache = data.pw_expected_origins_by_page_origin || {};
    cache[pageOrigin] = { origins, last_seen: Date.now() };
    await localSet({ pw_expected_origins_by_page_origin: cache });

    return { ok: true, message: "Origins seeded", pageOrigin, origins };
  }

  if (normalized === "storage.getOrigins") {
    const pageOrigin = payload.pageOrigin;
    if (!pageOrigin) return { ok: false, error: "missing payload.pageOrigin" };

    const data = await localGet(["pw_expected_origins_by_page_origin"]);
    const cache = data.pw_expected_origins_by_page_origin || {};
    const entry = cache[pageOrigin];
    return { ok: true, data: entry ? entry.origins : [], entry: entry || null };
  }

  return { ok: false, error: "Unknown test helper action: " + normalized };
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  console.log("[PhishWatch] onMessage", {
    type: msg?.type,
    from: sender?.tab?.url || sender?.url || "(unknown)",
  });

  // 1) TEST HELPER: ONLY when msg.type matches (do NOT hijack other flows)
  if (msg?.type === "PHISHWATCH_TEST_HELPER") {
    (async () => {
      try {
        const out = await handleTestHelper(msg.action, msg.payload || {});
        sendResponse(out);
      } catch (e) {
        console.error("[PhishWatch] Test helper error", e);
        sendResponse({ ok: false, error: String(e?.message || e) });
      }
    })();
    return true; // keep channel open
  }

  // 2) SESSION RPC (allowlist)
  if (msg?.type === "PHISHWATCH_SESSION_RPC") {
    (async () => {
      try {
        const { action, payload } = msg;

        if (action === "allowlist.has") {
          const allowed = await allowlistHas(payload?.url);
          sendResponse({ ok: true, data: { allowed } });
          return;
        }
        if (action === "allowlist.add") {
          await allowlistAdd(payload?.url);
          sendResponse({ ok: true, data: { ok: true } });
          return;
        }
        if (action === "allowlist.clear") {
          await allowlistClear();
          sendResponse({ ok: true, data: { ok: true } });
          return;
        }

        sendResponse({ ok: false, error: `unknown action: ${action}` });
      } catch (e) {
        console.error("[PhishWatch] SESSION_RPC error", e);
        sendResponse({ ok: false, error: String(e?.message || e) });
      }
    })();
    return true;
  }

  // 3) SCAN
  if (msg?.type === "PHISHWATCH_SCAN") {
    (async () => {
      try {
        const url = msg?.url;
        if (!url) {
          sendResponse({ ok: false, error: "missing url" });
          return;
        }

        console.log("[PhishWatch] SCAN start", {
          url,
          is_marketing_infra: msg.is_marketing_infra,
          has_treadmill: !!msg.treadmill,
        });

        const data = await apiCheck(url, {
          redirect_count: msg.redirect_count ?? 0,
          client_signals: msg.client_signals ?? [],
          prescan_reasons: msg.prescan_reasons ?? [],
          is_marketing_infra: msg.is_marketing_infra ?? false,
          treadmill: msg.treadmill ?? null,
        });

        console.log("[PhishWatch] SCAN done", {
          url,
          risk_band: data?.risk_band,
          treadmill_escalated: data?.treadmill_escalated,
        });

        sendResponse({ ok: true, data });
      } catch (e) {
        console.error("[PhishWatch] SCAN error", e);
        sendResponse({ ok: false, error: String(e?.message || e) });
      }
    })();
    return true;
  }

  sendResponse({ ok: false, error: "unknown message type" });
  return false;
});
