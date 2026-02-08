// pw-net-hook.js
// Page-context hook: emits CustomEvent("phishwatch_net_event")
// detail: { method, destination_origin, url, ts }

(() => {
  "use strict";

  if (window.__pwNetHookInstalled) return;
  window.__pwNetHookInstalled = true;

  function emit(method, url) {
    try {
      const u = new URL(String(url || ""), window.location.href);
      window.dispatchEvent(
        new CustomEvent("phishwatch_net_event", {
          detail: {
            method: String(method || "GET").toUpperCase(),
            destination_origin: u.origin,
            url: u.toString(),
            ts: Date.now(),
          },
        })
      );
    } catch {}
  }

  // --- fetch ---
  try {
    const origFetch = window.fetch;
    if (typeof origFetch === "function") {
      window.fetch = function (input, init) {
        try {
          const method = (init && init.method) || "GET";
          const url =
            typeof input === "string"
              ? input
              : (input && typeof input.url === "string" ? input.url : "");
          emit(method, url);
        } catch {}
        return origFetch.apply(this, arguments);
      };
    }
  } catch {}

  // --- XHR ---
  try {
    const OrigXHR = window.XMLHttpRequest;
    if (typeof OrigXHR === "function") {
      const origOpen = OrigXHR.prototype.open;
      OrigXHR.prototype.open = function (method, url) {
        try {
          // Just record method+url; actual send may happen later.
          emit(method, url);
        } catch {}
        return origOpen.apply(this, arguments);
      };
    }
  } catch {}
})();
