// pw-net-hook.js
// PhishWatch Phase-3 Sensor A: page-context network hook (fetch + XHR)
// Emits CustomEvent("phishwatch_net_event") with detail:
// { method, destination_origin, url, ts }

(() => {
  try {
    const EVENT_NAME = "phishwatch_net_event";

    function safeOriginFromUrl(url) {
      try {
        return new URL(url, window.location.href).origin;
      } catch {
        return null;
      }
    }

    function emit(method, url) {
      try {
        const destination_origin = safeOriginFromUrl(url);
        if (!destination_origin) return;

        window.dispatchEvent(
          new CustomEvent(EVENT_NAME, {
            detail: {
              method: String(method || "GET").toUpperCase(),
              destination_origin,
              url: String(url || ""),
              ts: Date.now(),
            },
          })
        );
      } catch {}
    }

    // -------------------------
    // Hook fetch
    // -------------------------
    try {
      const origFetch = window.fetch;
      if (typeof origFetch === "function") {
        window.fetch = function (input, init) {
          try {
            const method =
              (init && init.method) ||
              (typeof input === "object" && input && input.method) ||
              "GET";

            const url =
              typeof input === "string"
                ? input
                : (input && input.url) || "";

            emit(method, url);
          } catch {}

          return origFetch.apply(this, arguments);
        };
      }
    } catch {}

    // -------------------------
    // Hook XHR
    // -------------------------
    try {
      const origOpen = XMLHttpRequest.prototype.open;
      if (typeof origOpen === "function") {
        XMLHttpRequest.prototype.open = function (method, url) {
          try {
            emit(method, url);
          } catch {}

          return origOpen.apply(this, arguments);
        };
      }
    } catch {}

    // Markers for debugging
    try {
      document.documentElement.setAttribute("data-pw-net-hook-page", "1");
    } catch {}

  } catch {}
})();
