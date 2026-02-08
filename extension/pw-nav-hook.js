// pw-nav-hook.js (authoritative, tokenless-compat)
// Blocks script-driven navigations (assign/replace/href-set) until content.js allows proceed.

(() => {
  "use strict";

  const READY_EVT = "phishwatch_nav_hook_ready";
  const ATTEMPT_EVT = "phishwatch_nav_attempt";
  const PROCEED_EVT = "phishwatch_nav_proceed";

  if (window.__pwNavHookInstalled) {
    try {
      window.dispatchEvent(new CustomEvent(READY_EVT, { detail: { ok: true, already: true } }));
    } catch {}
    return;
  }
  window.__pwNavHookInstalled = true;

  let bypass = false;

  // One-at-a-time gating (sufficient for our use case)
  let pending = null; // { url, method, proceedFn }
  let proceedListenerInstalled = false;

  function toAbs(url) {
    try {
      return new URL(String(url), window.location.href).toString();
    } catch {
      return String(url || "");
    }
  }

  function sameOrigin(a, b) {
    try {
      const ua = new URL(a, window.location.href);
      const ub = new URL(b, window.location.href);
      return ua.origin === ub.origin;
    } catch {
      return false;
    }
  }

  function installProceedListenerOnce() {
    if (proceedListenerInstalled) return;
    proceedListenerInstalled = true;

    window.addEventListener(
      PROCEED_EVT,
      (e) => {
        try {
          if (!pending) return;

          const d = e?.detail || {};
          const url = d.url ? toAbs(d.url) : null;
          const method = d.method || null;

          // Accept proceed if:
          // - no detail provided (treat as proceed)
          // - OR url matches pending (best-effort)
          // - OR method matches pending (best-effort)
          const urlOk = !url || url === pending.url;
          const methodOk = !method || method === pending.method;

          if (!urlOk || !methodOk) return;

          const fn = pending.proceedFn;
          pending = null;

          bypass = true;
          try {
            fn();
          } finally {
            setTimeout(() => (bypass = false), 0);
          }
        } catch {}
      },
      true
    );
  }

  async function gate(url, method, invokeOriginal) {
    const abs = toAbs(url);

    // Optional: ignore same-origin navs (keeps noise down)
    try {
      if (sameOrigin(abs, window.location.href)) {
        invokeOriginal();
        return;
      }
    } catch {}

    if (bypass) {
      invokeOriginal();
      return;
    }

    installProceedListenerOnce();

    // If another nav is pending, fail-open the previous one to avoid deadlocks
    if (pending && pending.proceedFn) {
      try {
        const prevFn = pending.proceedFn;
        pending = null;
        bypass = true;
        try {
          prevFn();
        } finally {
          setTimeout(() => (bypass = false), 0);
        }
      } catch {}
    }

    // Announce attempt
    pending = { url: abs, method: method || "href", proceedFn: invokeOriginal };

    try {
      window.dispatchEvent(new CustomEvent(ATTEMPT_EVT, { detail: { url: abs, method: method || "href" } }));
    } catch {}

    // Timeout fail-open (don’t brick browsing)
    setTimeout(() => {
      try {
        if (!pending) return;
        const fn = pending.proceedFn;
        pending = null;

        bypass = true;
        try {
          fn();
        } finally {
          setTimeout(() => (bypass = false), 0);
        }
      } catch {}
    }, 9000);
  }

  // --- Hook location.assign / location.replace ---
  try {
    const locProto = Object.getPrototypeOf(window.location);

    if (locProto && typeof locProto.assign === "function") {
      const origAssign = locProto.assign;
      locProto.assign = function (url) {
        const self = this;
        return gate(url, "assign", () => origAssign.call(self, url));
      };
    }

    if (locProto && typeof locProto.replace === "function") {
      const origReplace = locProto.replace;
      locProto.replace = function (url) {
        const self = this;
        return gate(url, "replace", () => origReplace.call(self, url));
      };
    }
  } catch {}

  // --- Hook location.href setter (common for timer redirects) ---
  try {
    const locProto = Object.getPrototypeOf(window.location);
    const desc = Object.getOwnPropertyDescriptor(locProto, "href");

    if (desc && typeof desc.set === "function" && typeof desc.get === "function") {
      Object.defineProperty(locProto, "href", {
        configurable: desc.configurable !== false,
        enumerable: desc.enumerable === true,
        get: function () {
          return desc.get.call(this);
        },
        set: function (url) {
          const self = this;
          return gate(url, "href", () => desc.set.call(self, url));
        },
      });
    }
  } catch {}

  // Signal ready
  try {
    window.dispatchEvent(new CustomEvent(READY_EVT, { detail: { ok: true } }));
  } catch {}
})();
