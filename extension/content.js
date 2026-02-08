/* PhishWatch content.js — Phase 4 v2.6.1 (Security Hardened)
   
   v2.6.1 Critical Security Fixes:
   - SYNTAX FIX: Removed space in hasSSOText variable (parse error)
   - SECURITY FIX: Proper domain validation (prevent bypass via login.microsoftonline.com.evil.com)
   - UX FIX: Two-tier copy-blocking (HIGH-confidence + context = block, MEDIUM = warn only)
   - FALSE POSITIVE FIX: Narrow BitB selector + raise threshold to 80
   - PERFORMANCE FIX: Hard rate limiting on DOM mutation monitoring (max 1 scan per 2 sec)
   
   Week 4 Features (Browser-Native Threats):
   - ConsentFix/ClickFix detection (OAuth token hijacking)
   - Browser-in-the-Browser (BitB) detection (fake login windows)
   - Paste event monitoring for OAuth callback URLs
   - Copy event monitoring for malicious commands
   - Fake CAPTCHA/verification page detection
   - Suspicious iframe and fake browser window detection
   - Critical security warnings for browser-native attacks
   
   Week 3 Security Hardening (v2.5):
   - Marketing bypass mitigation (credential keywords = disqualifying)
   - Fail-open exploitation monitoring (detect deliberate fail-open attacks)
   - Baseline learning rate limiting (50 updates/hour per page)
   - Probationary graduation validation (trusted domains only)
   - Defense-in-depth credential checks (direct URL validation)
   
   Week 3 Features (Production Readiness):
   - Probationary learning for first-contact OAuth/SSO flows
   - Two-strike graduation system (learn after 2nd occurrence)
   - 30-day expiry for unconfirmed probationary entries
   - Intelligent heuristic-based marketing infrastructure detection
   - Confidence scoring system (replaces hardcoded domain lists)
   - Multi-tab race condition protection
   - Browser back/forward navigation handling
   - Rapid click debouncing
   - Storage health monitoring
   
   Week 2 Features (SSO-Safe):
   - Three-gate SSO-safe policy:
     Gate 1: Only arm on password field interactions (not OTP/seed)
     Gate 2: Form action mismatch is primary signal (cross-origin alone is weak)
     Gate 3: Expected origins = page_origin + form_action_origin + learned_origins
   - Expected origins learning per page_origin (guarded: only learn benign windows)
   - Sequence hashing (structure only, no content)
   - Local baseline storage (chrome.storage.local) - PAGE-SCOPED
   - "Structurally novel sequence" detector (SSO-aware)
   - Novelty + treadmill correlation (suppress novelty unless treadmill present)
   - Research signal: novel_runtime_sequence_observed
   
   Week 1 Features (preserved):
   - Form-action mismatch detection
   - Enhanced auth window with sequence tracking
   - Navigation context awareness
   - Research-only signal infrastructure
   
   All Phase 4 signals remain research-only:
   - Logged to console for analysis
   - NOT shown in overlay
   
   Design principles preserved:
   - Fail-open: never trap users
   - Deterministic: same inputs = same outputs
   - Minimal privilege: no content/credential access
   - Event-driven: only active during sensitive windows
   - SSO-safe: legitimate OAuth/SSO flows are assumed benign
   
   v2.3 Changes:
   - Heuristic marketing detection (pattern-based, not whitelist-based)
   - Multi-tab baseline merging with conflict detection
   - Rapid click protection (500ms debounce)
   - Browser bfcache handling for back/forward navigation
   - Storage usage monitoring and warnings
   - Debounced storage writes (2-second window)
   
   Note: Uses ES2015+ features (Set, Array.from, Object.assign) which are
   supported in all Chrome MV3 environments. Not ES5-compatible.
*/

(function () {
  "use strict";

  // =========================
  // Constants & Configuration
  // =========================
  var DEBUG = true;
  
  // PHASE 4 FLAGS
  // Controls whether research signals are sent to backend (vs local logging only)
  var PHASE4_SEND_RESEARCH_TO_BACKEND = false;
  // Controls whether research signals appear in UI (always false for now)
  var PHASE4_SHOW_RESEARCH_IN_UI = false;
  
  // Novelty detection thresholds
  var BASELINE_THRESHOLD = 3;  // Pattern seen 3+ times = not novel
  var MAX_BASELINE_ENTRIES_PER_PAGE = 50;  // Limit per page origin
  var MAX_PAGES_IN_BASELINE = 100;  // Limit total pages tracked in baseline
  var MAX_NOVEL_SEQUENCES = 20;  // Keep last 20 novel sequences for analysis
  
  // SSO-safe expected origins limits
  var MAX_EXPECTED_ORIGINS_PER_PAGE = 12;
  var MAX_PAGES_TRACKED = 200;
  
  function pwLog(msg, obj) {
    if (!DEBUG) return;
    try {
      console.log("[PhishWatch] " + msg, obj || "");
    } catch (_) {}
  }
  
  function pwResearchLog(signalId, data) {
    try {
      console.log("[PhishWatch:Research] " + signalId, data || "");
    } catch (_) {}
  }

  var OVERLAY_ID = "phishwatch-overlay";
  var ALLOW_ACTION_TYPE = "PHISHWATCH_SESSION_RPC";
  var SCAN_TYPE = "PHISHWATCH_SCAN";

  // Timing constants
  var SOFT_INDICATOR_DELAY_MS = 800;
  var HARD_TIMEOUT_MS = 2000;
  var API_TIMEOUT_MS = 8000;

  // Treadmill timing constants
  var AUTH_WINDOW_PRE_SUBMIT_MS = 2000;
  var AUTH_WINDOW_SUBMIT_MS = 2000;
  var AUTH_WINDOW_POST_SUBMIT_MS = 1000;

  // =========================
  // Suspicious TLDs
  // =========================
  var SUSPICIOUS_TLDS = [
    "xyz", "top", "tk", "ml", "ga", "cf", "gq",
    "buzz", "club", "work", "link", "click",
    "icu", "monster", "rest", "boats", "cam",
    "info", "biz",
    "pw", "ws", "cc", "su",
  ];

  // =========================
  // Credential Keywords
  // =========================
  var CREDENTIAL_KEYWORDS = [
    "login", "signin", "sign-in", "sign_in",
    "logon", "signon", "sign-on", "sign_on",
    "password", "passwd", "pwd",
    "verify", "verification", "validate", "confirm",
    "account", "secure", "security", "auth", "authenticate",
    "update", "suspend", "locked", "unlock", "restore",
    "billing", "payment", "wallet",
    "credential", "credentials",
  ];

  // =========================
  // Tier 1: Silent Allow
  // =========================
  var SILENT_ALLOW_SUFFIXES = [
    ".google.com", ".googleapis.com", ".gstatic.com",
    ".microsoftonline.com", ".microsoft.com", ".live.com",
    ".github.com", ".gitlab.com",
    ".apple.com", ".icloud.com",
    ".stripe.com", ".paypal.com", ".braintreegateway.com",
    ".okta.com", ".auth0.com", ".onelogin.com",
    ".linkedin.com", ".x.com", ".twitter.com",
    ".facebook.com", ".instagram.com", ".threads.net",
    ".cloudflare.com", ".amazonaws.com", ".azure.com",
    ".vercel.app", ".netlify.app", ".onrender.com",
    ".railway.app", ".heroku.com", ".fly.dev",
    ".ngrok-free.app", ".ngrok.app", ".localhost",
    ".salesforce.com", ".slack.com", ".zoom.us",
    ".dropbox.com", ".box.com",
  ];

  // =========================
  // Tier 2: Marketing Infrastructure
  // =========================
  var MARKETING_INFRA_DOMAINS = [
    "rs6.net", "constantcontact.com", "mailchimp.com",
    "list-manage.com", "campaign-archive.com",
    "sendgrid.net", "sendgrid.com", "mailgun.com", "mailgun.net",
    "postmarkapp.com", "klaviyo.com", "hubspot.com",
    "hs-analytics.net", "hsforms.com", "marketo.com",
    "mktoweb.com", "pardot.com", "eloqua.com",
    "sailthru.com", "braze.com", "iterable.com",
    "customer.io", "intercom.io", "drip.com",
    "convertkit.com", "aweber.com", "getresponse.com",
    "activecampaign.com", "sendinblue.com", "brevo.com",
    "sendibm3.com", "sendibm.com", "sendibm2.com",  // SendInBlue/Brevo tracking subdomains
    "mailerlite.com", "moosend.com", "benchmark.email",
    "emma.com", "e2ma.net", "cmail19.com", "cmail20.com",
    "createsend.com", "doubleclick.net", "googleadservices.com",
    "googlesyndication.com", "googletagmanager.com",
    "google-analytics.com", "facebook.net", "fbcdn.net",
    "bing.com", "linkedin.com", "ads-twitter.com", "t.co",
    "bit.ly", "bitly.com", "rebrandly.com", "short.io",
    "tinyurl.com", "ow.ly", "buff.ly", "lnkd.in",
    "typeform.com", "surveymonkey.com", "jotform.com",
    "wufoo.com", "formstack.com", "cognito.com", "google.com",
    "eventbrite.com", "calendly.com", "meetup.com", "zoom.us",
    "cloudfront.net", "akamaized.net", "fastly.net",
    "jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com",
  ];

  // =========================
  // Trusted Auth Domains
  // =========================
  var TRUSTED_AUTH_DOMAINS = [
    "accounts.google.com",
    "login.microsoftonline.com",
    "login.live.com",
    "appleid.apple.com",
    "github.com",
    "gitlab.com",
    "okta.com",
    "auth0.com",
    "onelogin.com",
    "duo.com",
    "pingidentity.com",
    "checkout.stripe.com",
    "paypal.com",
  ];

  // Prescan thresholds
  var PRESCAN_LONG_URL = 220;
  var PRESCAN_LONG_QUERY = 120;

  // =========================
  // State
  // =========================
  var overlayEl = null;
  var pendingUrl = null;
  var scanInFlight = false;
  var scanSeq = 0;
  var interceptionEnabled = true;
  
  // Rapid click protection
  var lastClickTime = 0;
  var lastClickUrl = null;
  
  // Fail-open attack detection (security monitoring)
  var failOpenCount = 0;
  var FAIL_OPEN_LIMIT_PER_SESSION = 10;
  
  // Baseline rate limiting (prevent learning pollution)
  var baselineUpdateCounts = {};
  var BASELINE_MAX_UPDATES_PER_HOUR = 50;
  
  // Browser-native attack detection
  var clipboardMonitoringActive = true;
  var suspiciousElementsDetected = [];
  
  // ConsentFix/ClickFix detection thresholds
  var OAUTH_CODE_MIN_LENGTH = 20;
  
  // HIGH-CONFIDENCE malicious patterns (BLOCK when combined with lure context)
  var HIGH_CONFIDENCE_MALICIOUS = [
    /powershell.*-w(indowstyle)?.*hidden.*(iex|invoke-expression)/i,
    /powershell.*-w(indowstyle)?.*hidden.*invoke-webrequest/i,
    /powershell.*-enc\s+[A-Za-z0-9+\/=]{20,}/i,  // Base64 encoded payload
    /curl.*http.*\|.*bash/i,
    /wget.*http.*\|.*sh/i,
    /cmd.*\/c.*certutil.*-urlcache.*&&/i,
    /mshta.*http.*\.hta/i
  ];
  
  // MEDIUM-CONFIDENCE suspicious patterns (WARN only, don't block)
  var MEDIUM_CONFIDENCE_SUSPICIOUS = [
    /powershell.*(iex|invoke-expression)/i,
    /invoke-expression.*invoke-webrequest/i,
    /certutil.*http/i,
    /cmd.*\/c.*curl/i,
    /Start-Process.*-windowstyle.*hidden/i
  ];
  
  // ClickFix lure page indicators (required for HIGH-confidence blocking)
  var CLICKFIX_LURE_INDICATORS = [
    /press.*windows.*\+.*r/i,
    /press.*win.*\+.*r/i,
    /paste.*command/i,
    /run.*following/i,
    /verify.*human.*command/i,
    /fix.*error.*paste/i,
    /copy.*paste.*command/i
  ];

  // =========================
  // Enhanced Treadmill State (Phase 4 SSO-Safe)
  // =========================
  var treadmillState = {
    armed: false,
    trigger: null,
    armedAt: 0,
    expectedOrigin: null,
    observedOrigins: [],
    windowMs: 0,
    sequence: [],
    formActionOrigin: null,
    formActionMismatch: false,
    navigationContext: null,
    // SSO-safe: track if this was armed by password-only (for Phase 4 novelty)
    isPasswordTriggered: false,
  };

  // Origins seen since page load (for logging context, NOT detection primitive)
  // Note: hasNewOrigin vs expectedSet is the real detection primitive
  var seenOriginsSincePageLoad = new Set();
  
  // Navigation context
  var navigationContext = {
    referrer: null,
    referrerOrigin: null,
    isFromTrustedContext: false,
    entryTime: Date.now(),
  };

  // Research signals collected this session
  var researchSignals = [];
  
  // =========================
  // Baseline Cache (loaded from storage) - PAGE-SCOPED
  // Structure: { "pageOrigin||hash": count, ... }
  // =========================
  var baselineCache = null;
  var baselineLoaded = false;
  
  // =========================
  // Expected Origins Cache (SSO-safe)
  // Structure: { pageOrigin: { origins: [...], last_seen: timestamp }, ... }
  // =========================
  var expectedOriginsCache = null;
  var expectedOriginsLoaded = false;
  
  // =========================
  // Probationary Origins Cache (SSO-safe learning)
  // Structure: { "pageOrigin||destOrigin": { first_seen, count, last_seen }, ... }
  // Tracks new origins during probation period before graduation
  // =========================
  var probationaryOriginsCache = null;
  var probationaryOriginsLoaded = false;
  
  // Probation settings
  var PROBATION_GRADUATION_COUNT = 2;  // Promote after 2 successful occurrences
  var PROBATION_EXPIRY_DAYS = 30;  // Expire if not confirmed within 30 days
  
  // Storage write debouncing timers (to prevent quota exhaustion)
  var baselineSaveTimer = null;
  var expectedOriginsSaveTimer = null;
  var probationarySaveTimer = null;

  // =========================
  // Initialize Navigation Context
  // =========================
  function initNavigationContext() {
    try {
      var ref = document.referrer || "";
      navigationContext.referrer = ref;
      
      if (ref) {
        try {
          var refUrl = new URL(ref);
          navigationContext.referrerOrigin = refUrl.origin;
          navigationContext.isFromTrustedContext = isTrustedAuthDomain(refUrl.hostname);
        } catch (_) {}
      }
      
      pwLog("navigation context initialized", navigationContext);
    } catch (_) {}
  }

  // =========================
  // Utilities
  // =========================
  function hostFromUrl(u) {
    try {
      return new URL(u).hostname || "";
    } catch (_) {
      return "";
    }
  }

  function originFromUrl(u) {
    try {
      return new URL(u).origin || "";
    } catch (_) {
      return "";
    }
  }

  function normalizeForAllowlist(u) {
    try {
      var url = new URL(u);
      var protocol = String(url.protocol || "").toLowerCase();
      var host = String(url.host || "").toLowerCase();
      var path = url.pathname || "/";
      path = path.replace(/\/{2,}/g, "/");
      if (path.length > 1 && path.endsWith("/")) path = path.slice(0, -1);
      return protocol + "//" + host + path;
    } catch (_) {
      return String(u || "").trim();
    }
  }

  function getRegistrableDomain(hostname) {
    var h = String(hostname || "").toLowerCase();
    var parts = h.split(".");
    if (parts.length <= 2) return h;
    
    var commonMultipartTlds = ["co.uk", "com.au", "co.nz", "co.jp", "com.br"];
    var lastTwo = parts.slice(-2).join(".");
    
    for (var i = 0; i < commonMultipartTlds.length; i++) {
      if (lastTwo === commonMultipartTlds[i]) {
        return parts.slice(-3).join(".");
      }
    }
    
    return parts.slice(-2).join(".");
  }

  function isSameSite(origin1, origin2) {
    try {
      var host1 = new URL(origin1).hostname;
      var host2 = new URL(origin2).hostname;
      return getRegistrableDomain(host1) === getRegistrableDomain(host2);
    } catch (_) {
      return false;
    }
  }

  function isTrustedAuthDomain(hostname) {
    var h = String(hostname || "").toLowerCase();
    for (var i = 0; i < TRUSTED_AUTH_DOMAINS.length; i++) {
      var trusted = TRUSTED_AUTH_DOMAINS[i];
      if (h === trusted || h.endsWith("." + trusted)) {
        return true;
      }
    }
    return false;
  }

  function looksLikeIpLiteral(host) {
    return /^\d{1,3}(\.\d{1,3}){3}$/.test(host || "");
  }

  function hasPunycode(host) {
    return String(host || "").indexOf("xn--") !== -1;
  }

  function hasShortenerLikeHost(host) {
    var h = String(host || "").toLowerCase();
    return (
      h === "is.gd" ||
      h === "goo.gl" ||
      h === "rb.gy" ||
      h === "shorturl.at" ||
      h === "cutt.ly"
    );
  }

  function hasSuspiciousTld(host) {
    var h = String(host || "").toLowerCase();
    var parts = h.split(".");
    if (parts.length < 2) return false;
    var tld = parts[parts.length - 1];
    
    for (var i = 0; i < SUSPICIOUS_TLDS.length; i++) {
      if (tld === SUSPICIOUS_TLDS[i]) return true;
    }
    return false;
  }

  function hasCredentialKeywords(url) {
    try {
      var u = new URL(url);
      var path = String(u.pathname || "").toLowerCase();
      var host = String(u.hostname || "").toLowerCase();
      var searchText = path + " " + host;
      
      for (var i = 0; i < CREDENTIAL_KEYWORDS.length; i++) {
        if (searchText.indexOf(CREDENTIAL_KEYWORDS[i]) !== -1) {
          return true;
        }
      }
      return false;
    } catch (_) {
      return false;
    }
  }

  function hasManySubdomains(host) {
    var h = String(host || "").toLowerCase();
    var parts = h.split(".");
    return parts.length >= 4;
  }

  function isSilentlyAllowedTarget(url) {
    try {
      var h = hostFromUrl(url).toLowerCase();
      if (!h) return false;

      for (var i = 0; i < SILENT_ALLOW_SUFFIXES.length; i++) {
        var suf = String(SILENT_ALLOW_SUFFIXES[i] || "").toLowerCase();
        if (!suf) continue;
        var bare = suf.replace(/^\./, "");
        if (h === bare) return true;
        if (h.endsWith(suf)) return true;
      }
      return false;
    } catch (_) {
      return false;
    }
  }

  function isMarketingInfraTarget(url) {
    try {
      var h = hostFromUrl(url).toLowerCase();
      if (!h) return false;

      for (var i = 0; i < MARKETING_INFRA_DOMAINS.length; i++) {
        var domain = String(MARKETING_INFRA_DOMAINS[i] || "").toLowerCase();
        if (!domain) continue;
        if (h === domain) return true;
        if (h.endsWith("." + domain)) return true;
      }
      return false;
    } catch (_) {
      return false;
    }
  }

  // =========================
  // Intelligent Marketing Detection (Heuristic-Based)
  // =========================
  function intelligentMarketingDetection(url, context) {
    var confidence = 0;
    var signals = [];
    
    try {
      var u = new URL(url);
      var hostname = u.hostname.toLowerCase();
      var path = u.pathname.toLowerCase();
      var params = u.searchParams;
      
      // TIER 1: Strong signals (each adds +40 confidence)
      
      // Email tracking path patterns
      if (/\/(mk|cl|track|click|link|l|c|e|r)\//.test(path)) {
        confidence += 40;
        signals.push('email_tracking_path');
      }
      
      // Long random token in path (40+ chars of alphanumeric)
      var pathSegments = path.split('/').filter(function(s) { return s.length > 0; });
      for (var i = 0; i < pathSegments.length; i++) {
        var segment = pathSegments[i];
        if (segment.length >= 40 && /^[a-zA-Z0-9_-]+$/.test(segment)) {
          confidence += 40;
          signals.push('long_tracking_token');
          break;
        }
      }
      
      // Email tracking parameters
      var trackingParams = ['utm_source', 'utm_campaign', 'utm_medium', 'email', 
                           'subscriber', 'recipient', 'mc_cid', 'mc_eid', 'mkt_tok'];
      for (var j = 0; j < trackingParams.length; j++) {
        if (params.has(trackingParams[j])) {
          confidence += 30;
          signals.push('tracking_params');
          break;
        }
      }
      
      // TIER 2: Supporting signals (each adds +20 confidence)
      
      // Marketing domain prefixes
      var marketingPrefixes = ['click', 'track', 'link', 'mail', 'email', 
                              'newsletter', 'analytics', 'metrics', 'go', 'redirect'];
      for (var k = 0; k < marketingPrefixes.length; k++) {
        var prefix = marketingPrefixes[k];
        if (hostname.startsWith(prefix + '.') || hostname.startsWith(prefix + '-')) {
          confidence += 20;
          signals.push('marketing_domain_prefix');
          break;
        }
      }
      
      // Referrer is webmail
      if (context && context.referrer) {
        try {
          var refUrl = new URL(context.referrer);
          var refHost = refUrl.hostname.toLowerCase();
          var webmailDomains = ['gmail.com', 'mail.google.com', 'outlook.com', 
                               'mail.yahoo.com', 'protonmail.com', 'mail.proton.me'];
          for (var m = 0; m < webmailDomains.length; m++) {
            if (refHost.indexOf(webmailDomains[m]) !== -1) {
              confidence += 20;
              signals.push('webmail_referrer');
              break;
            }
          }
        } catch (_) {}
      }
      
      // Complex subdomain + legitimate TLD
      var parts = hostname.split('.');
      var tld = parts[parts.length - 1];
      var legitimateTlds = ['com', 'net', 'org', 'io', 'co'];
      if (parts.length >= 4 && legitimateTlds.indexOf(tld) !== -1) {
        confidence += 15;
        signals.push('complex_subdomain_legitimate_tld');
      }
      
      // NEGATIVE SIGNALS (reduce confidence)
      
      // Credential keywords in URL - DISQUALIFYING for marketing
      // Security: Prevents phishing disguised as email tracking
      // Example attack: https://click.evil.com/login?utm_source=email
      if (hasCredentialKeywords(url)) {
        confidence -= 100;  // Changed from -30 to -100 (disqualifying)
        signals.push('credential_keywords_present');
      }
      
      // IP address
      if (looksLikeIpLiteral(hostname)) {
        confidence -= 40;
        signals.push('ip_literal');
      }
      
      // Suspicious TLD
      if (hasSuspiciousTld(hostname)) {
        confidence -= 25;
        signals.push('suspicious_tld');
      }
      
    } catch (e) {
      pwLog("intelligentMarketingDetection: error", e);
    }
    
    // Decision threshold
    var isMarketingInfra = confidence >= 50;
    
    return {
      isMarketingInfra: isMarketingInfra,
      confidence: confidence,
      signals: signals
    };
  }
  
  // Hybrid approach: heuristic first, whitelist fallback
  function detectMarketingInfrastructure(url, context) {
    // Try heuristic detection first
    var result = intelligentMarketingDetection(url, context);
    
    // High confidence? Trust it
    if (result.confidence >= 50 || result.confidence <= -30) {
      return {
        isMarketingInfra: result.isMarketingInfra,
        method: 'heuristic',
        confidence: result.confidence,
        signals: result.signals
      };
    }
    
    // Low confidence? Check whitelist as fallback
    var whitelistMatch = isMarketingInfraTarget(url);
    
    return {
      isMarketingInfra: whitelistMatch,
      method: whitelistMatch ? 'whitelist' : 'heuristic',
      confidence: whitelistMatch ? 100 : result.confidence,
      signals: whitelistMatch ? ['whitelist_match'] : result.signals
    };
  }

  function prescanHints(url) {
    var hints = [];
    try {
      var u = new URL(url);
      var full = String(url || "");
      var query = String(u.search || "").slice(1);

      if (full.length >= PRESCAN_LONG_URL) hints.push("long_url");
      if (query.length >= PRESCAN_LONG_QUERY) hints.push("long_query");

      var h = String(u.hostname || "").toLowerCase();
      if (looksLikeIpLiteral(h)) hints.push("ip_literal_host");
      if (hasPunycode(h)) hints.push("punycode_host");
      if (hasShortenerLikeHost(h)) hints.push("shortener_like_host");
      if (hasSuspiciousTld(h)) hints.push("suspicious_tld");
      if (hasCredentialKeywords(url)) hints.push("credential_keywords");
      if (hasManySubdomains(h)) hints.push("many_subdomains");

      var keys = ["redirect", "redir", "url", "dest", "destination", "next", "target", "continue", "return"];
      for (var i = 0; i < keys.length; i++) {
        if (u.searchParams.has(keys[i])) hints.push("param_" + keys[i]);
      }
    } catch (_) {}
    return hints;
  }

  function escapeHtml(s) {
    return String(s || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  // =========================
  // MV3 messaging
  // =========================
  function pwSendMessageSafe(msg, timeoutMs) {
    if (typeof timeoutMs !== "number") timeoutMs = 3500;

    function isTransient(em) {
      em = String(em || "");
      return (
        em.indexOf("Extension context invalidated") !== -1 ||
        em.indexOf("The message port closed") !== -1 ||
        em.indexOf("Receiving end does not exist") !== -1
      );
    }

    function sendOnce(m, ms) {
      return new Promise(function (resolve) {
        try {
          if (!chrome || !chrome.runtime || !chrome.runtime.sendMessage) {
            resolve({ ok: false, error: "sendMessage_unavailable" });
            return;
          }
          if (!chrome.runtime.id) {
            resolve({ ok: false, error: "sendMessage_threw: Error: Extension context invalidated." });
            return;
          }

          var done = false;
          var t = setTimeout(function () {
            if (done) return;
            done = true;
            resolve({ ok: false, error: "sendMessage_timeout: " + ms + "ms" });
          }, ms);

          chrome.runtime.sendMessage(m, function (resp) {
            if (done) return;
            done = true;
            clearTimeout(t);

            var err = chrome.runtime.lastError;
            if (err) {
              resolve({ ok: false, error: "sendMessage_threw: " + String(err.message || err) });
              return;
            }
            resolve(resp);
          });
        } catch (e) {
          resolve({ ok: false, error: "sendMessage_threw: " + String(e) });
        }
      });
    }

    return sendOnce({ type: "PHISHWATCH_PING" }, 600).then(function () {
      return sendOnce(msg, timeoutMs).then(function (resp) {
        if (resp && resp.ok === false && resp.error && isTransient(resp.error)) {
          return new Promise(function (r) {
            setTimeout(r, 120);
          }).then(function () {
            return sendOnce(msg, timeoutMs);
          });
        }
        return resp;
      });
    });
  }

  function pwSessionRpc(action, payload, timeoutMs) {
    if (typeof timeoutMs !== "number") timeoutMs = 2000;
    return pwSendMessageSafe({ type: ALLOW_ACTION_TYPE, action: action, payload: payload }, timeoutMs).then(function (resp) {
      if (!resp || resp.ok !== true) return null;

      var inner = resp && resp.data && typeof resp.data === "object" ? resp.data : resp;
      var innerObj = inner && typeof inner === "object" ? inner : {};
      var out = { ok: true, data: innerObj };
      try {
        for (var k in innerObj) out[k] = innerObj[k];
      } catch (_) {}
      return out;
    });
  }

  // =========================
  // SSO-Safe Expected Origins (Gate 3) - with LRU pruning
  // Storage structure: { pageOrigin: { origins: [...], last_seen: timestamp }, ... }
  // =========================
  function loadExpectedOrigins() {
    return new Promise(function(resolve) {
      try {
        if (!chrome || !chrome.storage || !chrome.storage.local) {
          pwLog("expected origins: storage unavailable");
          resolve({});
          return;
        }
        
        chrome.storage.local.get(["pw_expected_origins_by_page_origin"], function(result) {
          if (chrome.runtime.lastError) {
            pwLog("expected origins: load error", chrome.runtime.lastError);
            resolve({});
            return;
          }
          
          var raw = result.pw_expected_origins_by_page_origin || {};
          var migrated = false;
          
          // Schema migration: v2.1 used arrays, v2.2 uses {origins, last_seen}
          var keys = Object.keys(raw);
          for (var i = 0; i < keys.length; i++) {
            var key = keys[i];
            var value = raw[key];
            if (Array.isArray(value)) {
              // Migrate from v2.1 array format to v2.2 object format
              raw[key] = { origins: value, last_seen: 0 };
              migrated = true;
            }
          }
          
          expectedOriginsCache = raw;
          expectedOriginsLoaded = true;
          
          if (migrated) {
            pwLog("expected origins: migrated from v2.1 format", {
              pagesTracked: keys.length
            });
            // Save migrated data
            saveExpectedOrigins();
          }
          
          pwLog("expected origins: loaded", {
            pagesTracked: Object.keys(expectedOriginsCache).length
          });
          
          resolve(expectedOriginsCache);
        });
      } catch (e) {
        pwLog("expected origins: load exception", e);
        resolve({});
      }
    });
  }

  function getExpectedOriginsForPage(pageOrigin) {
    if (!expectedOriginsCache || !pageOrigin) return [];
    var entry = expectedOriginsCache[pageOrigin];
    if (!entry) return [];
    return Array.isArray(entry.origins) ? entry.origins : [];
  }

  function pruneExpectedOriginsMap(map) {
    var keys = Object.keys(map);
    if (keys.length <= MAX_PAGES_TRACKED) return map;
    
    // LRU-ish pruning: sort by last_seen ascending (oldest first)
    keys.sort(function(a, b) {
      var aTime = (map[a] && map[a].last_seen) || 0;
      var bTime = (map[b] && map[b].last_seen) || 0;
      return aTime - bTime;
    });
    
    var dropCount = keys.length - MAX_PAGES_TRACKED;
    for (var i = 0; i < dropCount; i++) {
      delete map[keys[i]];
    }
    
    pwLog("expected origins: pruned", { dropped: dropCount, remaining: Object.keys(map).length });
    return map;
  }

  function updateExpectedOriginsForPage(pageOrigin, originsToAdd) {
    if (!pageOrigin || !Array.isArray(originsToAdd) || originsToAdd.length === 0) return;
    
    if (!expectedOriginsCache) expectedOriginsCache = {};
    
    var entry = expectedOriginsCache[pageOrigin];
    var existingOrigins = (entry && Array.isArray(entry.origins)) ? entry.origins : [];
    var set = new Set(existingOrigins);
    
    for (var i = 0; i < originsToAdd.length; i++) {
      var o = originsToAdd[i];
      if (o && typeof o === "string") set.add(o);
    }
    
    // Cap per-page list size deterministically
    var next = Array.from(set);
    next.sort();
    var capped = next.slice(0, MAX_EXPECTED_ORIGINS_PER_PAGE);
    
    expectedOriginsCache[pageOrigin] = {
      origins: capped,
      last_seen: Date.now()
    };
    
    pruneExpectedOriginsMap(expectedOriginsCache);
    
    // Save async (don't block)
    saveExpectedOrigins();
    
    pwLog("expected origins: updated for page", {
      pageOrigin: pageOrigin,
      origins: capped,
      totalPages: Object.keys(expectedOriginsCache).length
    });
  }

  function saveExpectedOrigins() {
    return new Promise(function(resolve) {
      try {
        if (!chrome || !chrome.storage || !chrome.storage.local) {
          resolve(false);
          return;
        }
        
        // Debounced save with immediate flush option
        clearTimeout(expectedOriginsSaveTimer);
        expectedOriginsSaveTimer = setTimeout(function() {
          chrome.storage.local.set({
            pw_expected_origins_by_page_origin: expectedOriginsCache
          }, function() {
            if (chrome.runtime.lastError) {
              pwLog("expected origins: save error", chrome.runtime.lastError);
              resolve(false);
              return;
            }
            resolve(true);
          });
        }, 2000);
      } catch (e) {
        pwLog("expected origins: save exception", e);
        resolve(false);
      }
    });
  }
  
  // =========================
  // Probationary Origins Storage (SSO-safe learning)
  // =========================
  function loadProbationaryOrigins() {
    return new Promise(function(resolve) {
      try {
        if (!chrome || !chrome.storage || !chrome.storage.local) {
          pwLog("probationary origins: storage unavailable");
          resolve({});
          return;
        }
        
        chrome.storage.local.get(["pw_probationary_origins"], function(result) {
          if (chrome.runtime.lastError) {
            pwLog("probationary origins: load error", chrome.runtime.lastError);
            resolve({});
            return;
          }
          
          probationaryOriginsCache = result.pw_probationary_origins || {};
          probationaryOriginsLoaded = true;
          
          // Clean up expired entries on load
          var now = Date.now();
          var expiryMs = PROBATION_EXPIRY_DAYS * 24 * 60 * 60 * 1000;
          var expired = 0;
          
          for (var key in probationaryOriginsCache) {
            var entry = probationaryOriginsCache[key];
            if (entry && entry.first_seen) {
              var age = now - entry.first_seen;
              if (age > expiryMs) {
                delete probationaryOriginsCache[key];
                expired++;
              }
            }
          }
          
          if (expired > 0) {
            pwLog("probationary origins: expired entries removed", { count: expired });
            saveProbationaryOrigins();
          }
          
          pwLog("probationary origins: loaded", {
            entriesTracked: Object.keys(probationaryOriginsCache).length
          });
          
          resolve(probationaryOriginsCache);
        });
      } catch (e) {
        pwLog("probationary origins: load exception", e);
        resolve({});
      }
    });
  }
  
  function saveProbationaryOrigins() {
    return new Promise(function(resolve) {
      try {
        if (!chrome || !chrome.storage || !chrome.storage.local) {
          resolve(false);
          return;
        }
        
        // Debounced save
        clearTimeout(probationarySaveTimer);
        probationarySaveTimer = setTimeout(function() {
          chrome.storage.local.set({
            pw_probationary_origins: probationaryOriginsCache
          }, function() {
            if (chrome.runtime.lastError) {
              pwLog("probationary origins: save error", chrome.runtime.lastError);
              resolve(false);
              return;
            }
            resolve(true);
          });
        }, 2000);
      } catch (e) {
        pwLog("probationary origins: save exception", e);
        resolve(false);
      }
    });
  }
  
  function checkProbationStatus(pageOrigin, destOrigin) {
    if (!probationaryOriginsCache) probationaryOriginsCache = {};
    
    var key = pageOrigin + "||" + destOrigin;
    var entry = probationaryOriginsCache[key];
    var now = Date.now();
    
    if (!entry) {
      // First time seeing this origin pair - add to probation
      probationaryOriginsCache[key] = {
        first_seen: now,
        count: 1,
        last_seen: now
      };
      saveProbationaryOrigins();
      
      pwLog("probationary origins: new entry", {
        pageOrigin: pageOrigin,
        destOrigin: destOrigin,
        count: 1
      });
      
      return { shouldLearn: false, graduated: false, count: 1 };
    }
    
    // Existing probationary entry - increment count
    entry.count++;
    entry.last_seen = now;
    
    // Check if ready to graduate
    if (entry.count >= PROBATION_GRADUATION_COUNT) {
      // SECURITY: Only graduate trusted OAuth origins
      // Prevents attacker from graduating malicious domains to "expected"
      if (!isTrustedOAuthOrigin(destOrigin)) {
        pwLog("probationary origins: REJECTED (untrusted origin)", {
          pageOrigin: pageOrigin,
          destOrigin: destOrigin,
          count: entry.count,
          reason: "not_in_trusted_auth_domains"
        });
        console.warn("[PhishWatch] SECURITY: Refused to graduate untrusted OAuth origin:", destOrigin);
        
        // Remove from probation (don't keep trying to graduate)
        delete probationaryOriginsCache[key];
        saveProbationaryOrigins();
        
        return { shouldLearn: false, graduated: false, rejected: true, count: entry.count };
      }
      
      // Graduate! Remove from probation and add to expected origins
      delete probationaryOriginsCache[key];
      saveProbationaryOrigins();
      
      pwLog("probationary origins: GRADUATED", {
        pageOrigin: pageOrigin,
        destOrigin: destOrigin,
        count: entry.count,
        daysSinceFirst: Math.floor((now - entry.first_seen) / (24 * 60 * 60 * 1000))
      });
      
      return { shouldLearn: true, graduated: true, count: entry.count };
    }
    
    // Still in probation
    saveProbationaryOrigins();
    
    pwLog("probationary origins: incremented", {
      pageOrigin: pageOrigin,
      destOrigin: destOrigin,
      count: entry.count,
      needsMore: PROBATION_GRADUATION_COUNT - entry.count
    });
    
    return { shouldLearn: false, graduated: false, count: entry.count };
  }
  
  // Helper: Check if origin is in trusted auth domains list
  function isTrustedOAuthOrigin(origin) {
    try {
      var u = new URL(origin);
      var hostname = u.hostname;
      
      // Check against trusted auth domains list
      for (var i = 0; i < TRUSTED_AUTH_DOMAINS.length; i++) {
        var trusted = TRUSTED_AUTH_DOMAINS[i];
        if (hostname === trusted || hostname.endsWith("." + trusted)) {
          return true;
        }
      }
      
      return false;
    } catch (_) {
      return false;
    }
  }

  // Build SSO-safe expected origins set for current auth window
  function buildExpectedOriginsSet(pageOrigin, formActionOrigin) {
    var expected = new Set();
    
    // 1. Page origin
    if (pageOrigin) expected.add(pageOrigin);
    
    // 2. Form action origin (if present)
    if (formActionOrigin) expected.add(formActionOrigin);
    
    // 3. Learned origins for this page_origin
    var learned = getExpectedOriginsForPage(pageOrigin);
    for (var i = 0; i < learned.length; i++) {
      expected.add(learned[i]);
    }
    
    return expected;
  }

  // =========================
  // Sequence Hashing (Week 2 - 5-part structure)
  // =========================
  function computeSequenceHash(windowData) {
    // Hash structure only, not content
    var parts = [];
    
    // 1. Trigger type
    parts.push(windowData.trigger || "unknown");
    
    // 2. Form action status
    if (windowData.formActionMismatch) {
      parts.push("mismatch");
    } else {
      parts.push("ok");
    }
    
    // 3. Cross-origin request status
    var xoriginCount = (windowData.observedOrigins || []).length;
    if (xoriginCount === 0) {
      parts.push("same");
    } else if (xoriginCount === 1) {
      parts.push("xorigin1");
    } else {
      parts.push("xoriginN");
    }
    
    // 4. New origin flag (SSO-safe: relative to expected origins set)
    var hasNewOrigin = windowData.hasNewOrigin || false;
    parts.push(hasNewOrigin ? "new" : "known");
    
    // 5. Sequence complexity (number of events)
    var seqLen = (windowData.sequence || []).length;
    if (seqLen <= 3) {
      parts.push("simple");
    } else if (seqLen <= 6) {
      parts.push("medium");
    } else {
      parts.push("complex");
    }
    
    return parts.join("|");
  }

  // =========================
  // Baseline Storage (Week 2) - PAGE-SCOPED
  // Composite key: "pageOrigin||hash"
  // =========================
  function makeBaselineKey(pageOrigin, hash) {
    return pageOrigin + "||" + hash;
  }

  function parseBaselineKey(compositeKey) {
    var idx = compositeKey.indexOf("||");
    if (idx === -1) return { pageOrigin: "", hash: compositeKey };
    return {
      pageOrigin: compositeKey.substring(0, idx),
      hash: compositeKey.substring(idx + 2)
    };
  }

  function loadBaseline() {
    return new Promise(function(resolve) {
      try {
        if (!chrome || !chrome.storage || !chrome.storage.local) {
          pwLog("baseline: storage unavailable");
          resolve({});
          return;
        }
        
        chrome.storage.local.get(["pw_sequence_baseline", "pw_novel_sequences"], function(result) {
          if (chrome.runtime.lastError) {
            pwLog("baseline: load error", chrome.runtime.lastError);
            resolve({});
            return;
          }
          
          baselineCache = result.pw_sequence_baseline || {};
          baselineLoaded = true;
          
          pwLog("baseline: loaded", {
            entries: Object.keys(baselineCache).length,
            novelCount: (result.pw_novel_sequences || []).length
          });
          
          resolve(baselineCache);
        });
      } catch (e) {
        pwLog("baseline: load exception", e);
        resolve({});
      }
    });
  }

  function saveBaseline() {
    return new Promise(function(resolve) {
      try {
        if (!chrome || !chrome.storage || !chrome.storage.local) {
          resolve(false);
          return;
        }
        
        // Multi-tab safety: reload and merge before saving
        chrome.storage.local.get(["pw_sequence_baseline"], function(freshData) {
          var fresh = freshData.pw_sequence_baseline || {};
          
          // Merge fresh data with in-memory changes (keep higher counts)
          for (var key in fresh) {
            if (!baselineCache[key]) {
              baselineCache[key] = fresh[key];
            } else {
              baselineCache[key] = Math.max(baselineCache[key], fresh[key]);
            }
          }
          
          // Prune baseline if too large
          var keys = Object.keys(baselineCache);
          var totalLimit = MAX_BASELINE_ENTRIES_PER_PAGE * MAX_PAGES_IN_BASELINE;
          
          if (keys.length > totalLimit) {
            // Group by page origin, keep highest-count entries per page
            var byPage = {};
            for (var i = 0; i < keys.length; i++) {
              var parsed = parseBaselineKey(keys[i]);
              if (!byPage[parsed.pageOrigin]) byPage[parsed.pageOrigin] = [];
              byPage[parsed.pageOrigin].push({ key: keys[i], count: baselineCache[keys[i]] });
            }
            
            var newBaseline = {};
            var pageOrigins = Object.keys(byPage);
            
            // Sort pages by total activity (sum of counts), keep most active
            pageOrigins.sort(function(a, b) {
              var sumA = byPage[a].reduce(function(s, e) { return s + e.count; }, 0);
              var sumB = byPage[b].reduce(function(s, e) { return s + e.count; }, 0);
              return sumB - sumA;
            });
            
            var pagesToKeep = pageOrigins.slice(0, MAX_PAGES_IN_BASELINE);
            
            for (var j = 0; j < pagesToKeep.length; j++) {
              var pageEntries = byPage[pagesToKeep[j]];
              // Sort by count descending, keep top N per page
              pageEntries.sort(function(a, b) { return b.count - a.count; });
              var entriesToKeep = pageEntries.slice(0, MAX_BASELINE_ENTRIES_PER_PAGE);
              for (var k = 0; k < entriesToKeep.length; k++) {
                newBaseline[entriesToKeep[k].key] = entriesToKeep[k].count;
              }
            }
            
            baselineCache = newBaseline;
            pwLog("baseline: pruned", { 
              before: keys.length, 
              after: Object.keys(newBaseline).length 
            });
          }
          
          chrome.storage.local.set({
            pw_sequence_baseline: baselineCache,
            pw_baseline_last_updated: Date.now()
          }, function() {
            if (chrome.runtime.lastError) {
              pwLog("baseline: save error", chrome.runtime.lastError);
              resolve(false);
              return;
            }
            resolve(true);
          });
        });
      } catch (e) {
        pwLog("baseline: save exception", e);
        resolve(false);
      }
    });
  }

  function incrementBaseline(pageOrigin, hash) {
    if (!baselineCache) baselineCache = {};
    
    // Safety guard: ensure pageOrigin is never empty
    var safePageOrigin = pageOrigin || window.location.origin || "unknown";
    
    // Rate limiting: prevent learning pollution via multi-tab attacks
    // Track updates per page per hour
    var now = Date.now();
    var hourKey = Math.floor(now / (60 * 60 * 1000));
    var countKey = safePageOrigin + "||" + hourKey;
    
    baselineUpdateCounts[countKey] = (baselineUpdateCounts[countKey] || 0) + 1;
    
    if (baselineUpdateCounts[countKey] > BASELINE_MAX_UPDATES_PER_HOUR) {
      pwLog("baseline: rate limit exceeded (possible attack)", { 
        pageOrigin: safePageOrigin,
        updatesThisHour: baselineUpdateCounts[countKey],
        limit: BASELINE_MAX_UPDATES_PER_HOUR
      });
      console.warn("[PhishWatch] SECURITY: Baseline update rate limit exceeded");
      return;  // Don't increment
    }
    
    var key = makeBaselineKey(safePageOrigin, hash);
    baselineCache[key] = (baselineCache[key] || 0) + 1;
    
    pwLog("baseline: incremented", { 
      pageOrigin: safePageOrigin, 
      hash: hash, 
      count: baselineCache[key],
      updatesThisHour: baselineUpdateCounts[countKey]
    });
    
    // Debounced save: only write after 2 seconds of inactivity
    // This prevents quota exhaustion on busy pages with many auth events
    clearTimeout(baselineSaveTimer);
    baselineSaveTimer = setTimeout(function() {
      saveBaseline();
    }, 2000);
  }

  function isNovelSequence(pageOrigin, hash) {
    if (!baselineCache) return true;
    
    var key = makeBaselineKey(pageOrigin, hash);
    var count = baselineCache[key] || 0;
    return count < BASELINE_THRESHOLD;
  }

  function getBaselineCount(pageOrigin, hash) {
    if (!baselineCache) return 0;
    var key = makeBaselineKey(pageOrigin, hash);
    return baselineCache[key] || 0;
  }
  
  // =========================
  // Storage Health Monitoring
  // =========================
  function monitorStorageHealth() {
    try {
      if (!chrome || !chrome.storage || !chrome.storage.local) return;
      
      chrome.storage.local.getBytesInUse(null, function(bytes) {
        var quota = 10485760; // 10MB quota for local storage
        var percentUsed = (bytes / quota) * 100;
        
        pwLog("storage health", {
          bytesUsed: bytes,
          percentUsed: percentUsed.toFixed(2) + "%",
          baselineEntries: Object.keys(baselineCache || {}).length,
          expectedOriginsPages: Object.keys(expectedOriginsCache || {}).length,
          probationaryEntries: Object.keys(probationaryOriginsCache || {}).length
        });
        
        // Alert if approaching quota
        if (percentUsed > 80) {
          console.warn("[PhishWatch] Storage usage high:", percentUsed.toFixed(2) + "%");
        }
        
        if (percentUsed > 90) {
          console.error("[PhishWatch] CRITICAL: Storage usage critical:", percentUsed.toFixed(2) + "%");
        }
      });
    } catch (e) {
      pwLog("storage health: error", e);
    }
  }

  function recordNovelSequence(hash, context) {
    try {
      if (!chrome || !chrome.storage || !chrome.storage.local) return;
      
      // PRIVACY NOTE: This stores page_origin and form_action_origin locally.
      // If PHASE4_SEND_RESEARCH_TO_BACKEND is enabled in the future, implement
      // URL masking (e.g., SHA256 hashing) before transmission to protect privacy.
      
      chrome.storage.local.get(["pw_novel_sequences"], function(result) {
        var sequences = result.pw_novel_sequences || [];
        
        sequences.push({
          hash: hash,
          first_seen: Date.now(),
          context: context
        });
        
        // Keep only recent sequences
        if (sequences.length > MAX_NOVEL_SEQUENCES) {
          sequences = sequences.slice(-MAX_NOVEL_SEQUENCES);
        }
        
        chrome.storage.local.set({ pw_novel_sequences: sequences });
      });
    } catch (_) {}
  }

  // =========================
  // SSO-Safe Novelty Detection (Week 2)
  // =========================
  function analyzeNoveltySSO(windowData) {
    // Gate 1: Only evaluate if password-triggered (not OTP/seed)
    if (!windowData.isPasswordTriggered) {
      pwLog("novelty: skipped (not password-triggered)", {
        trigger: windowData.trigger
      });
      return null;
    }
    
    // Safety guards: ensure origins are never empty
    var pageOrigin = windowData.expectedOrigin || window.location.origin || "unknown";
    var formActionOrigin = windowData.formActionOrigin || "";
    var observedOrigins = windowData.observedOrigins || [];
    
    // Build SSO-safe expected origins set (Gate 3)
    var expectedSet = buildExpectedOriginsSet(pageOrigin, formActionOrigin);
    
    // Determine has_new_origin relative to expected set (this is the detection primitive)
    var hasNewOrigin = false;
    var newOriginsList = [];
    for (var i = 0; i < observedOrigins.length; i++) {
      var destOrigin = observedOrigins[i].origin;
      if (destOrigin && !expectedSet.has(destOrigin)) {
        hasNewOrigin = true;
        newOriginsList.push(destOrigin);
      }
    }
    
    // Update windowData with SSO-aware has_new_origin
    windowData.hasNewOrigin = hasNewOrigin;
    
    // Gate 2: Mismatch is primary, cross-origin alone is weak
    var hasMismatch = windowData.formActionMismatch;
    var crossOriginCount = observedOrigins.length;
    
    // Treadmill indicator (your existing rule, now SSO-safe)
    var hasTreadmill = hasMismatch || hasNewOrigin || crossOriginCount > 0;
    
    // Compute structural hash
    var hash = computeSequenceHash(windowData);
    var isNovel = isNovelSequence(pageOrigin, hash);
    var currentCount = getBaselineCount(pageOrigin, hash);
    
    pwLog("novelty: SSO-safe analysis", {
      hash: hash,
      isNovel: isNovel,
      hasTreadmill: hasTreadmill,
      hasMismatch: hasMismatch,
      hasNewOrigin: hasNewOrigin,
      crossOriginCount: crossOriginCount,
      expectedOriginsCount: expectedSet.size,
      newOrigins: newOriginsList,
      baselineCount: currentCount,
      pageOrigin: pageOrigin
    });
    
    // Always increment baseline count (learning the structure)
    incrementBaseline(pageOrigin, hash);
    
    // Enhanced learning criteria with probationary period
    var shouldLearnOrigins = false;
    var probationResults = [];
    
    if (!hasMismatch && !hasNewOrigin && observedOrigins.length > 0) {
      // Clean window - learn immediately
      shouldLearnOrigins = true;
      var observedOriginList = observedOrigins.map(function(o) { return o.origin; });
      updateExpectedOriginsForPage(pageOrigin, observedOriginList);
      pwLog("novelty: learning origins (benign window)", { 
        pageOrigin: pageOrigin, 
        origins: observedOriginList,
        reason: "clean_window"
      });
    } else if (!hasMismatch && hasNewOrigin && observedOrigins.length === 1) {
      // New origin but no mismatch - possible legitimate first-contact SSO
      // Add to probationary list instead of rejecting outright
      var newDestOrigin = observedOrigins[0].origin;
      var probationStatus = checkProbationStatus(pageOrigin, newDestOrigin);
      probationResults.push(probationStatus);
      
      if (probationStatus.graduated) {
        // This origin just graduated from probation - learn it now
        shouldLearnOrigins = true;
        updateExpectedOriginsForPage(pageOrigin, [newDestOrigin]);
        pwLog("novelty: learning origin (probation graduated)", {
          pageOrigin: pageOrigin,
          origin: newDestOrigin,
          occurrences: probationStatus.count,
          reason: "probation_graduated"
        });
      } else {
        pwLog("novelty: origin on probation", {
          pageOrigin: pageOrigin,
          origin: newDestOrigin,
          count: probationStatus.count,
          needsMore: PROBATION_GRADUATION_COUNT - probationStatus.count,
          reason: "first_contact_sso_probation"
        });
      }
    } else if (observedOrigins.length > 0) {
      // Suspicious window - don't learn
      pwLog("novelty: NOT learning origins (suspicious indicators)", {
        hasMismatch: hasMismatch,
        hasNewOrigin: hasNewOrigin,
        observedCount: observedOrigins.length,
        reason: hasMismatch ? "form_action_mismatch" : "multiple_new_origins"
      });
    }
    
    // Only emit if BOTH novel AND treadmill indicator present
    if (isNovel && hasTreadmill) {
      // Determine treadmill type for research logging
      var treadmillType = "none";
      if (hasMismatch) {
        treadmillType = "form_action_mismatch";
      } else if (hasNewOrigin) {
        treadmillType = "new_origin";
      } else if (crossOriginCount > 0) {
        treadmillType = "cross_origin_post";
      }
      
      var signal = {
        id: "novel_runtime_sequence_observed",
        severity: "research",
        explanation: "A previously unseen combination of authentication flow mechanics was detected, combined with suspicious network activity.",
        evidence: {
          sequence_hash: hash,
          is_novel: true,
          baseline_count: currentCount,
          has_form_action_mismatch: hasMismatch,
          has_new_origin: hasNewOrigin,
          cross_origin_count: crossOriginCount,
          trigger: windowData.trigger,
          treadmill_type: treadmillType,
          page_origin: pageOrigin,
          form_action_origin: formActionOrigin,
          expected_origins_count: expectedSet.size,
          new_origins: newOriginsList.slice(0, 5), // Limit for privacy
        },
        research_only: true,
      };
      
      recordResearchSignal(signal);
      
      // Record in novel sequences storage for later analysis
      recordNovelSequence(hash, {
        page_origin: pageOrigin,
        form_action_origin: formActionOrigin,
        form_action_mismatch: hasMismatch,
        has_new_origin: hasNewOrigin,
        trigger: windowData.trigger,
        treadmill_type: treadmillType,
      });
      
      return signal;
    }
    
    // Log why we didn't emit
    if (!isNovel) {
      pwLog("novelty: not novel for this page (seen " + currentCount + " times)", { 
        pageOrigin: pageOrigin, 
        hash: hash 
      });
    } else if (!hasTreadmill) {
      pwLog("novelty: novel but no treadmill indicator", { hash: hash });
    }
    
    return null;
  }

  // =========================
  // Overlay UI
  // =========================
  function ensureOverlay() {
    var el = document.getElementById(OVERLAY_ID);
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

    el.innerHTML =
      '<div style="width:min(720px,92vw);background:#111;border:1px solid rgba(255,255,255,0.12);' +
      "border-radius:14px;box-shadow:0 14px 60px rgba(0,0,0,0.6);overflow:hidden;\">" +
      '<div style="padding:14px 16px;border-bottom:1px solid rgba(255,255,255,0.10);display:flex;gap:10px;align-items:center;justify-content:space-between;">' +
      '<div style="color:#fff;font-weight:700;letter-spacing:0.2px;">PhishWatch</div>' +
      '<button id="pw-close" style="background:transparent;border:1px solid rgba(255,255,255,0.18);color:#fff;border-radius:10px;padding:6px 10px;cursor:pointer;">Close</button>' +
      "</div>" +
      '<div id="pw-body" style="padding:14px 16px;color:#eaeaea;"><div style="opacity:0.9">Checking…</div></div>' +
      '<div id="pw-actions" style="padding:14px 16px;border-top:1px solid rgba(255,255,255,0.10);display:flex;gap:10px;justify-content:flex-end;">' +
      '<button id="pw-continue" style="background:#fff;border:none;color:#111;border-radius:12px;padding:10px 14px;cursor:pointer;font-weight:700;">Continue anyway</button>' +
      '<button id="pw-cancel" style="background:transparent;border:1px solid rgba(255,255,255,0.18);color:#fff;border-radius:12px;padding:10px 14px;cursor:pointer;">Go back</button>' +
      "</div>" +
      "</div>";

    document.documentElement.appendChild(el);
    overlayEl = el;

    var closeBtn = el.querySelector("#pw-close");
    var contBtn = el.querySelector("#pw-continue");
    var cancelBtn = el.querySelector("#pw-cancel");

    if (closeBtn) closeBtn.addEventListener("click", closeOverlay);
    if (cancelBtn) cancelBtn.addEventListener("click", closeOverlay);
    if (contBtn) contBtn.addEventListener("click", continueAnyway);

    return el;
  }

  function cleanupOverlay() {
    try {
      var el = document.getElementById(OVERLAY_ID);
      if (el) el.remove();
    } catch (_) {}
    overlayEl = null;
  }

  function closeOverlay() {
    cleanupOverlay();
  }

  function setActionsEnabled(enabled) {
    try {
      var el = overlayEl || document.getElementById(OVERLAY_ID);
      if (!el) return;
      var cont = el.querySelector("#pw-continue");
      var cancel = el.querySelector("#pw-cancel");
      if (cont) cont.disabled = !enabled;
      if (cancel) cancel.disabled = !enabled;
      if (cont) cont.style.opacity = enabled ? "1" : "0.55";
      if (cancel) cancel.style.opacity = enabled ? "1" : "0.55";
    } catch (_) {}
  }

  function setOverlayChecking(url) {
    var el = ensureOverlay();
    var body = el.querySelector("#pw-body");
    if (body) {
      body.innerHTML =
        '<div style="font-weight:600;color:#fff;margin-bottom:6px;">Checking link…</div>' +
        '<div style="font-size:13px;opacity:0.85;word-break:break-all;">' +
        escapeHtml(url) +
        "</div>" +
        '<div style="margin-top:10px;font-size:13px;opacity:0.65">This will only take a moment</div>';
    }
    setActionsEnabled(true);
  }

  function renderScanResult(data) {
    var el = ensureOverlay();
    var body = el.querySelector("#pw-body");

    var riskBand = String((data && data.risk_band) || "unknown").toUpperCase();
    var summary = String((data && data.summary) || "PhishWatch flagged something unusual on this transition.");
    var url = String(pendingUrl || "");

    var signals = (data && Array.isArray(data.signals)) ? data.signals : [];
    var displaySignals = signals.filter(function(s) {
      // Filter out research-only signals from UI display
      return !s.research_only;
    });
    
    var sigHtml = "";
    if (displaySignals.length) {
      var parts = [];
      for (var i = 0; i < Math.min(10, displaySignals.length); i++) {
        var s = displaySignals[i] || {};
        var sev = String(s.severity || "low").toUpperCase();
        var id = escapeHtml(String(s.id || ""));
        var exp = escapeHtml(String(s.explanation || ""));
        var ev = s.evidence ? escapeHtml(JSON.stringify(s.evidence)) : "";
        parts.push(
          '<div style="border:1px solid rgba(255,255,255,0.14);border-radius:12px;padding:10px 12px;">' +
            '<div style="display:flex;gap:10px;align-items:center;justify-content:space-between;">' +
              '<div style="font-weight:700;">' + id + "</div>" +
              '<div style="font-size:12px;opacity:0.85;">' + sev + "</div>" +
            "</div>" +
            '<div style="margin-top:6px;opacity:0.92;font-size:13px;line-height:1.35;">' + exp + "</div>" +
            (ev ? '<div style="margin-top:6px;opacity:0.7;font-size:12px;word-break:break-all;">' + ev + "</div>" : "") +
          "</div>"
        );
      }
      sigHtml =
        '<div style="margin-top:12px;">' +
          '<div style="font-weight:700;margin-bottom:8px;">Signals</div>' +
          '<div style="display:flex;flex-direction:column;gap:8px;">' + parts.join("") + "</div>" +
        "</div>";
    }

    if (body) {
      body.innerHTML =
        '<div style="display:flex;align-items:center;justify-content:space-between;gap:10px;">' +
          '<div style="font-weight:800;font-size:14px;">Risk: ' + escapeHtml(riskBand) + "</div>" +
          '<div style="font-size:12px;opacity:0.75;">' + escapeHtml(new Date().toLocaleString()) + "</div>" +
        "</div>" +
        '<div style="margin-top:10px;font-size:13px;opacity:0.92;line-height:1.35;">' + escapeHtml(summary) + "</div>" +
        '<div style="margin-top:10px;font-size:12px;opacity:0.75;word-break:break-all;">' + escapeHtml(url) + "</div>" +
        sigHtml;
    }

    setActionsEnabled(true);
  }

  // =========================
  // Navigation helpers
  // =========================
  function failOpenNavigate(url) {
    try {
      // Security monitoring: Track fail-open events
      // Detects potential fail-open exploitation attacks
      failOpenCount++;
      
      if (failOpenCount > FAIL_OPEN_LIMIT_PER_SESSION) {
        console.error("[PhishWatch] SECURITY ALERT: Excessive fail-opens detected", {
          count: failOpenCount,
          limit: FAIL_OPEN_LIMIT_PER_SESSION,
          url: url,
          warning: "Possible fail-open exploitation attack"
        });
        // Don't block (fail-open is by design), but log for telemetry
      } else if (failOpenCount === FAIL_OPEN_LIMIT_PER_SESSION) {
        console.warn("[PhishWatch] SECURITY: Approaching fail-open limit", {
          count: failOpenCount,
          limit: FAIL_OPEN_LIMIT_PER_SESSION
        });
      }
      
      pwLog("failOpenNavigate", { 
        url: url,
        failOpenCount: failOpenCount,
        reason: "fail_open_by_design"
      });
      
      cleanupOverlay();
      window.location.href = url;
    } catch (e) {
      pwLog("failOpenNavigate: exception", { url: url, e: String(e) });
    }
  }

  function continueAnyway() {
    try {
      var t = String(pendingUrl || "");
      if (!t) {
        cleanupOverlay();
        return;
      }

      var key = normalizeForAllowlist(t);

      pwSessionRpc("allowlist.add", { url: key }).then(function (r) {
        pwLog("continueAnyway: allowlist.add", { t: t, key: key, r: r });
      });

      cleanupOverlay();
      failOpenNavigate(t);
    } catch (e) {
      pwLog("continueAnyway: error", { e: String(e) });
      cleanupOverlay();
      if (pendingUrl) failOpenNavigate(pendingUrl);
    }
  }

  // BFCache reset
  // BFCache restore handler moved to initialization section below

  // =========================
  // Phase 4: Research Signal System
  // =========================
  function recordResearchSignal(signal) {
    signal.research_only = true;
    signal.timestamp = Date.now();
    signal.page_url = window.location.href;
    signal.page_origin = window.location.origin;
    
    researchSignals.push(signal);
    pwResearchLog(signal.id, signal);
    
    if (researchSignals.length > 50) {
      researchSignals = researchSignals.slice(-50);
    }
  }

  function getResearchSignals() {
    return researchSignals.slice();
  }

  // =========================
  // Phase 4: Form-Action Mismatch Detection
  // =========================
  function analyzeFormAction(form) {
    try {
      if (!form || !form.action) return null;
      
      var formAction = form.action;
      var formActionOrigin;
      
      try {
        formActionOrigin = new URL(formAction, window.location.href).origin;
      } catch (_) {
        return null;
      }
      
      var pageOrigin = window.location.origin;
      var formActionHost = hostFromUrl(formAction);
      
      var originMismatch = formActionOrigin !== pageOrigin;
      var sameSite = isSameSite(formActionOrigin, pageOrigin);
      var isTrustedAuth = isTrustedAuthDomain(formActionHost);
      
      var result = {
        formAction: formAction,
        formActionOrigin: formActionOrigin,
        pageOrigin: pageOrigin,
        originMismatch: originMismatch,
        sameSite: sameSite,
        isTrustedAuth: isTrustedAuth,
        isSuspicious: originMismatch && !sameSite && !isTrustedAuth,
      };
      
      pwLog("form action analysis", result);
      
      return result;
    } catch (e) {
      pwLog("analyzeFormAction error", { e: String(e) });
      return null;
    }
  }

  function detectFormActionMismatch(form) {
    var analysis = analyzeFormAction(form);
    if (!analysis) return;
    
    if (analysis.isSuspicious) {
      var signal = {
        id: "form_action_origin_mismatch",
        severity: "research",
        explanation: "Form submits credentials to a different origin than the current page.",
        evidence: {
          page_origin: analysis.pageOrigin,
          form_action_origin: analysis.formActionOrigin,
          form_action: analysis.formAction,
        },
      };
      
      recordResearchSignal(signal);
      
      treadmillState.formActionOrigin = analysis.formActionOrigin;
      treadmillState.formActionMismatch = true;
    } else if (analysis.formActionOrigin && analysis.formActionOrigin !== analysis.pageOrigin) {
      // Not suspicious (same-site or trusted), but still record for expected origins
      treadmillState.formActionOrigin = analysis.formActionOrigin;
    }
  }

  // =========================
  // Enhanced Treadmill Event System (Phase 4 SSO-Safe)
  // =========================
  function resetTreadmillState() {
    treadmillState.armed = false;
    treadmillState.trigger = null;
    treadmillState.armedAt = 0;
    treadmillState.expectedOrigin = null;
    treadmillState.observedOrigins = [];
    treadmillState.windowMs = 0;
    treadmillState.sequence = [];
    treadmillState.formActionOrigin = null;
    treadmillState.formActionMismatch = false;
    treadmillState.navigationContext = null;
    treadmillState.isPasswordTriggered = false;
  }

  function armTreadmill(trigger, windowMs, isPasswordTriggered) {
    treadmillState.armed = true;
    treadmillState.trigger = trigger;
    treadmillState.armedAt = Date.now();
    treadmillState.expectedOrigin = window.location.origin;
    treadmillState.observedOrigins = [];
    treadmillState.windowMs = windowMs;
    treadmillState.sequence = [];
    treadmillState.formActionOrigin = null;
    treadmillState.formActionMismatch = false;
    treadmillState.navigationContext = Object.assign({}, navigationContext);
    treadmillState.isPasswordTriggered = !!isPasswordTriggered;

    recordSequenceEvent("treadmill_armed", { trigger: trigger, isPasswordTriggered: isPasswordTriggered });

    pwLog("treadmill: armed (Phase 4 SSO-safe)", {
      trigger: trigger,
      expectedOrigin: treadmillState.expectedOrigin,
      windowMs: windowMs,
      isPasswordTriggered: isPasswordTriggered,
      navigationContext: treadmillState.navigationContext,
    });

    var armTime = treadmillState.armedAt;
    setTimeout(function () {
      if (treadmillState.armed && treadmillState.armedAt === armTime) {
        disarmTreadmill("window_expired");
      }
    }, windowMs + 100);
  }

  function disarmTreadmill(reason) {
    if (!treadmillState.armed) return null;

    recordSequenceEvent("treadmill_disarmed", { reason: reason });

    var result = {
      trigger: treadmillState.trigger,
      expectedOrigin: treadmillState.expectedOrigin,
      observedOrigins: treadmillState.observedOrigins.slice(),
      windowMs: treadmillState.windowMs,
      disarmReason: reason,
      sequence: treadmillState.sequence.slice(),
      formActionMismatch: treadmillState.formActionMismatch,
      formActionOrigin: treadmillState.formActionOrigin,
      navigationContext: treadmillState.navigationContext,
      isPasswordTriggered: treadmillState.isPasswordTriggered,
    };

    pwLog("treadmill: disarmed (Phase 4 SSO-safe)", result);
    
    // Week 1: Analyze auth window signals
    analyzeAuthWindowSignals(result);
    
    // Week 2 SSO-safe: Analyze novelty with SSO-aware logic
    analyzeNoveltySSO(result);
    
    resetTreadmillState();

    return result;
  }

  function recordSequenceEvent(eventType, data) {
    if (!treadmillState.armed) return;
    
    var elapsed = Date.now() - treadmillState.armedAt;
    treadmillState.sequence.push({
      event: eventType,
      elapsed_ms: elapsed,
      data: data || {},
    });
  }

  function recordTreadmillEvent(origin, method) {
    if (!treadmillState.armed) return;

    var elapsed = Date.now() - treadmillState.armedAt;
    if (elapsed > treadmillState.windowMs) {
      disarmTreadmill("window_expired");
      return;
    }

    if (origin === treadmillState.expectedOrigin) return;

    var m = String(method || "").toUpperCase();
    if (m !== "POST" && m !== "PUT" && m !== "PATCH") return;

    // is_new_origin_since_page_load: for logging context only
    // Note: The real detection primitive is hasNewOrigin vs expectedSet (computed in analyzeNoveltySSO)
    var isNewSincePageLoad = !seenOriginsSincePageLoad.has(origin);

    treadmillState.observedOrigins.push({
      origin: origin,
      method: m,
      elapsed_ms: elapsed,
      is_new_origin_since_page_load: isNewSincePageLoad,
    });

    recordSequenceEvent("cross_origin_request", {
      origin: origin,
      method: m,
      is_new_origin_since_page_load: isNewSincePageLoad,
    });

    pwLog("treadmill: recorded event (Phase 4 SSO-safe)", {
      origin: origin,
      method: m,
      elapsed_ms: elapsed,
      is_new_origin_since_page_load: isNewSincePageLoad,
      trigger: treadmillState.trigger,
      sequence_length: treadmillState.sequence.length,
    });
  }

  function analyzeAuthWindowSignals(windowData) {
    if (windowData.trigger === "form_submit" && windowData.observedOrigins.length > 0) {
      var crossOriginPosts = windowData.observedOrigins.filter(function(o) {
        return o.method === "POST";
      });
      
      if (crossOriginPosts.length > 0) {
        var signal = {
          id: "treadmill_submit_cross_origin_post",
          severity: "research",
          explanation: "Cross-origin POST request detected during credential submission window.",
          evidence: {
            expected_origin: windowData.expectedOrigin,
            trigger: windowData.trigger,
            cross_origin_posts: crossOriginPosts.map(function(o) { return o.origin; }),
            timing_ms: crossOriginPosts.map(function(o) { return o.elapsed_ms; }),
          },
        };
        recordResearchSignal(signal);
      }
    }
    
    if (windowData.formActionMismatch && windowData.observedOrigins.length > 0) {
      var signal = {
        id: "aitm_pattern_correlation",
        severity: "research",
        explanation: "Form action mismatch combined with cross-origin network activity during auth window - potential AiTM proxy pattern.",
        evidence: {
          form_action_origin: windowData.formActionOrigin,
          page_origin: windowData.expectedOrigin,
          cross_origin_count: windowData.observedOrigins.length,
          sequence_events: windowData.sequence.length,
        },
      };
      recordResearchSignal(signal);
    }
    
    if (windowData.sequence.length > 5) {
      var signal = {
        id: "auth_window_high_activity",
        severity: "research",
        explanation: "Unusually high activity during authentication window.",
        evidence: {
          event_count: windowData.sequence.length,
          window_ms: windowData.windowMs,
          events_per_second: (windowData.sequence.length / (windowData.windowMs / 1000)).toFixed(2),
        },
      };
      recordResearchSignal(signal);
    }
  }

  function buildTreadmillSignal() {
    if (treadmillState.observedOrigins.length === 0 && !treadmillState.formActionMismatch) {
      return null;
    }

    var isSubmit = treadmillState.trigger === "form_submit";
    var signalId = isSubmit
      ? "treadmill_submit_window_cross_origin_post"
      : "treadmill_pre_submit_cross_origin_post";
    
    var severity = "low";
    if (isSubmit && treadmillState.observedOrigins.length > 0) {
      severity = "medium";
    }
    if (treadmillState.formActionMismatch) {
      severity = "medium";
    }

    var origins = treadmillState.observedOrigins.map(function (o) { return o.origin; });
    var methods = treadmillState.observedOrigins.map(function (o) { return o.method; });
    var minTiming = treadmillState.observedOrigins.length > 0 
      ? Math.min.apply(null, treadmillState.observedOrigins.map(function (o) { return o.elapsed_ms; }))
      : 0;

    var explanation = isSubmit
      ? "During credential submission, the page sent data to an unexpected external origin."
      : "Unexpected cross-origin network activity occurred shortly after you interacted with a credential field.";
    
    if (treadmillState.formActionMismatch) {
      explanation += " Additionally, the form's action URL points to a different domain than this page.";
    }

    return {
      id: signalId,
      severity: severity,
      explanation: explanation,
      evidence: {
        expected_origin: treadmillState.expectedOrigin,
        trigger: treadmillState.trigger,
        window_ms: treadmillState.windowMs,
        observed_origins: origins,
        methods: methods,
        event_count: treadmillState.observedOrigins.length,
        min_timing_ms_since_trigger: minTiming,
        form_action_mismatch: treadmillState.formActionMismatch,
        form_action_origin: treadmillState.formActionOrigin,
        sequence_length: treadmillState.sequence.length,
      },
    };
  }

  // =========================
  // Credential Field Detection
  // =========================
  
  // General credential field detection (Phase 2/3 - broader)
  function isCredentialField(el) {
    if (!el || !el.tagName) return false;
    var tag = el.tagName.toLowerCase();
    if (tag !== "input") return false;

    var type = String(el.type || "").toLowerCase();

    if (type === "password") return true;

    var name = String(el.name || "").toLowerCase();
    var id = String(el.id || "").toLowerCase();
    var placeholder = String(el.placeholder || "").toLowerCase();
    var autocomplete = String(el.autocomplete || "").toLowerCase();

    var otpPatterns = ["otp", "code", "verification", "2fa", "mfa", "token", "pin"];
    for (var i = 0; i < otpPatterns.length; i++) {
      var p = otpPatterns[i];
      if (name.indexOf(p) !== -1 || id.indexOf(p) !== -1 ||
          placeholder.indexOf(p) !== -1 || autocomplete.indexOf(p) !== -1) {
        return true;
      }
    }

    var seedPatterns = ["seed", "phrase", "recovery", "mnemonic", "backup"];
    for (var j = 0; j < seedPatterns.length; j++) {
      var sp = seedPatterns[j];
      if (name.indexOf(sp) !== -1 || id.indexOf(sp) !== -1 || placeholder.indexOf(sp) !== -1) {
        return true;
      }
    }

    return false;
  }

  // SSO-safe: Password-only detection for Phase 4 novelty (Gate 1)
  function isPasswordFieldOnly(el) {
    if (!el || !el.tagName) return false;
    var tag = el.tagName.toLowerCase();
    if (tag !== "input") return false;

    var type = String(el.type || "").toLowerCase();
    
    // Strict: only type="password"
    if (type === "password") return true;
    
    // Supportive hint: autocomplete for password
    var autocomplete = String(el.autocomplete || "").toLowerCase();
    if (autocomplete === "current-password" || autocomplete === "new-password") {
      return true;
    }
    
    return false;
  }

  // Check if form contains a password field (for Phase 4 submit arming)
  function formContainsPasswordField(form) {
    if (!form) return false;
    try {
      var inputs = form.querySelectorAll("input");
      for (var i = 0; i < inputs.length; i++) {
        if (isPasswordFieldOnly(inputs[i])) {
          return true;
        }
      }
    } catch (_) {}
    return false;
  }

  function findParentForm(el) {
    var cur = el;
    for (var i = 0; i < 10 && cur; i++) {
      if (cur.tagName && cur.tagName.toLowerCase() === "form") {
        return cur;
      }
      cur = cur.parentElement;
    }
    return null;
  }

  function onCredentialFieldFocus(evt) {
    try {
      // Check if it's any credential field (for general tracking)
      var isAnyCred = isCredentialField(evt.target);
      if (!isAnyCred) return;
      
      // Check if it's specifically a password field (for Phase 4 SSO-safe novelty)
      var isPassword = isPasswordFieldOnly(evt.target);

      pwLog("credential field focus detected (Phase 4 SSO-safe)", {
        type: evt.target.type,
        name: evt.target.name,
        id: evt.target.id,
        isPasswordField: isPassword,
      });

      // Arm with password trigger flag for SSO-safe novelty
      armTreadmill("credential_focus", AUTH_WINDOW_PRE_SUBMIT_MS, isPassword);
      
      var form = findParentForm(evt.target);
      if (form) {
        detectFormActionMismatch(form);
      }
    } catch (_) {}
  }

  function onFormSubmit(evt) {
    try {
      var form = evt.target;
      if (!form || !form.tagName || form.tagName.toLowerCase() !== "form") return;

      var inputs = form.querySelectorAll("input");
      var hasCredential = false;
      var hasPassword = false;
      
      for (var i = 0; i < inputs.length; i++) {
        if (isCredentialField(inputs[i])) {
          hasCredential = true;
        }
        if (isPasswordFieldOnly(inputs[i])) {
          hasPassword = true;
        }
      }

      if (!hasCredential) return;

      pwLog("credential form submit detected (Phase 4 SSO-safe)", {
        action: form.action,
        method: form.method,
        hasPassword: hasPassword,
      });

      detectFormActionMismatch(form);
      
      // Arm with password trigger flag for SSO-safe novelty
      armTreadmill("form_submit", AUTH_WINDOW_SUBMIT_MS, hasPassword);
      
      recordSequenceEvent("form_submit", {
        action: form.action,
        method: form.method,
        hasPassword: hasPassword,
      });
    } catch (_) {}
  }

  function onNetworkEvent(evt) {
    try {
      var detail = evt.detail;
      if (!detail) return;

      var origin = detail.destination_origin;
      var method = detail.method;

      // Track for "since page load" context (not detection primitive)
      if (origin) seenOriginsSincePageLoad.add(origin);
      recordTreadmillEvent(origin, method);
    } catch (_) {}
  }

  // =========================
  // Immediate risk detection
  // =========================
  function detectImmediateHighRisk(url, hints) {
    var result = { isHighRisk: false, signals: [], riskBand: "low", summary: "" };
    
    try {
      var u = new URL(url);
      var host = (u.hostname || "").toLowerCase();
      
      if (hints.indexOf("ip_literal_host") !== -1 || looksLikeIpLiteral(host)) {
        result.isHighRisk = true;
        result.riskBand = "high";
        result.summary = "This link uses a raw IP address instead of a domain name — common in phishing.";
        result.signals.push({
          id: "ip_in_url",
          severity: "high",
          explanation: "This link uses a raw IP address instead of a normal domain name — common in phishing and malware delivery.",
          evidence: { host: host }
        });
      }
      
      if (hints.indexOf("punycode_host") !== -1 || hasPunycode(host)) {
        result.isHighRisk = true;
        result.riskBand = result.riskBand === "high" ? "high" : "medium";
        if (!result.summary) {
          result.summary = "This domain uses special characters (punycode) that can disguise lookalike domains.";
        }
        result.signals.push({
          id: "punycode_idn",
          severity: "medium",
          explanation: "The domain uses punycode (IDN), which can hide lookalike characters (e.g., 'paypaI' vs 'paypal').",
          evidence: { host: host }
        });
      }
      
      var hasSusTld = hints.indexOf("suspicious_tld") !== -1 || hasSuspiciousTld(host);
      var hasCredKw = hints.indexOf("credential_keywords") !== -1 || hasCredentialKeywords(url);
      
      if (hasSusTld && hasCredKw) {
        result.isHighRisk = true;
        result.riskBand = "high";
        if (!result.summary) {
          result.summary = "This URL combines a suspicious domain extension with credential-related keywords — a common phishing pattern.";
        }
        result.signals.push({
          id: "suspicious_tld_credential_combo",
          severity: "high",
          explanation: "The domain uses a suspicious TLD often abused for phishing, combined with login/account keywords in the URL.",
          evidence: { 
            host: host,
            tld: host.split(".").pop(),
            path: u.pathname
          }
        });
      } else if (hasSusTld) {
        result.isHighRisk = true;
        result.riskBand = result.riskBand === "high" ? "high" : "medium";
        if (!result.summary) {
          result.summary = "This domain uses an extension (.xyz, .tk, etc.) commonly associated with phishing sites.";
        }
        result.signals.push({
          id: "suspicious_tld",
          severity: "medium",
          explanation: "This TLD is frequently used for phishing and disposable malicious sites.",
          evidence: { 
            host: host,
            tld: host.split(".").pop()
          }
        });
      }
      
      if (hints.indexOf("many_subdomains") !== -1 || hasManySubdomains(host)) {
        result.isHighRisk = true;
        result.riskBand = result.riskBand === "high" ? "high" : "medium";
        if (!result.summary) {
          result.summary = "This URL has an unusually complex domain structure with many subdomains.";
        }
        result.signals.push({
          id: "excessive_subdomains",
          severity: "medium",
          explanation: "The domain has 3+ subdomain levels, which is often used to disguise the true destination.",
          evidence: { 
            host: host,
            subdomain_count: host.split(".").length - 2
          }
        });
      }
    } catch (_) {}
    
    return result;
  }

  // =========================
  // Core scan flow
  // =========================
  function runScan(url, prescanReasonList, isMarketingInfra) {
    return Promise.resolve().then(function () {
      scanSeq++;
      var mySeq = scanSeq;
      scanInFlight = true;

      var immediateResult = detectImmediateHighRisk(url, prescanReasonList);
      
      if (immediateResult.isHighRisk) {
        pwLog("runScan: immediate high-risk detection (client-side)", {
          url: url,
          riskBand: immediateResult.riskBand,
          signals: immediateResult.signals
        });
        
        ensureOverlay();
        renderScanResult({
          risk_band: immediateResult.riskBand,
          summary: immediateResult.summary,
          signals: immediateResult.signals
        });
        
        scanInFlight = false;
        return;
      }

      var overlayShown = false;
      var scanComplete = false;

      var softTimer = setTimeout(function () {
        if (mySeq === scanSeq && !scanComplete) {
          setOverlayChecking(url);
          overlayShown = true;
        }
      }, SOFT_INDICATOR_DELAY_MS);

      var hardTimer = setTimeout(function () {
        if (mySeq === scanSeq && !scanComplete) {
          pwLog("runScan: hard timeout, failing open", { url: url });
          scanComplete = true;
          clearTimeout(softTimer);
          cleanupOverlay();
          failOpenNavigate(url);
        }
      }, HARD_TIMEOUT_MS);

      var key = normalizeForAllowlist(url);
      return pwSessionRpc("allowlist.has", { url: key }).then(function (r) {
        if (scanComplete) return null;

        pwLog("runScan: allowlist.has", { url: url, key: key, r: r });
        var allowed = r && r.ok === true && (r.allowed === true || (r.data && r.data.allowed === true));
        if (allowed) {
          scanComplete = true;
          clearTimeout(softTimer);
          clearTimeout(hardTimer);
          cleanupOverlay();
          failOpenNavigate(url);
          return null;
        }

        var treadmillPayload = null;
        if (treadmillState.armed && (treadmillState.observedOrigins.length > 0 || treadmillState.formActionMismatch)) {
          treadmillPayload = {
            trigger: treadmillState.trigger,
            expected_origin: treadmillState.expectedOrigin,
            window_ms: treadmillState.windowMs,
            form_action_mismatch: treadmillState.formActionMismatch,
            form_action_origin: treadmillState.formActionOrigin,
            sequence_length: treadmillState.sequence.length,
            is_password_triggered: treadmillState.isPasswordTriggered,
            observed_events: treadmillState.observedOrigins.map(function (o) {
              return {
                origin: o.origin,
                method: o.method,
                elapsed_ms: o.elapsed_ms,
              };
            }),
          };
          pwLog("runScan: including treadmill observation (Phase 4 SSO-safe)", treadmillPayload);
        }

        var researchPayload = null;
        if (PHASE4_SEND_RESEARCH_TO_BACKEND && researchSignals.length > 0) {
          researchPayload = getResearchSignals();
        }

        pwLog("runScan: sending SCAN message to background", { url: url });
        return pwSendMessageSafe({
          type: SCAN_TYPE,
          url: url,
          redirect_count: 0,
          client_signals: [],
          prescan_reasons: Array.isArray(prescanReasonList) ? prescanReasonList : [],
          is_marketing_infra: !!isMarketingInfra,
          treadmill: treadmillPayload,
          research_signals: researchPayload,
          navigation_context: navigationContext,
        }, API_TIMEOUT_MS).then(function (resp) {
          if (scanComplete) return null;
          scanComplete = true;
          clearTimeout(softTimer);
          clearTimeout(hardTimer);

          var ok = resp && resp.ok === true;
          var data = resp && resp.data ? resp.data : null;

          if (!ok || !data) {
            var errText = (resp && resp.error) ? String(resp.error) : "Scan unavailable.";
            pwLog("runScan: backend scan failed, failing open", { url: url, resp: resp, errText: errText });
            cleanupOverlay();
            failOpenNavigate(url);
            return null;
          }

          var riskBand = String(data.risk_band || "").toLowerCase();

          if (riskBand === "low") {
            pwLog("runScan: LOW risk, navigating silently", { url: url });
            cleanupOverlay();
            failOpenNavigate(url);
            return null;
          }

          // Marketing infrastructure graceful handling:
          // For email/analytics tracking links, only show overlay if:
          // - Risk is HIGH, OR
          // - Multiple suspicious signals present (not just subdomain depth)
          if (isMarketingInfra && riskBand !== "high") {
            var signalCount = (data.signals || []).length;
            var hasMultipleSignals = signalCount >= 2;
            var hasStrongSignal = (data.signals || []).some(function(s) {
              return s.id === "ip_in_url" || 
                     s.id === "punycode_idn" || 
                     s.id === "suspicious_tld_credential_combo";
            });
            
            if (!hasMultipleSignals && !hasStrongSignal) {
              pwLog("runScan: marketing infra + single weak signal, navigating silently", { 
                url: url, 
                riskBand: riskBand,
                signalCount: signalCount 
              });
              cleanupOverlay();
              failOpenNavigate(url);
              return null;
            }
          }

          pwLog("runScan: showing overlay", { url: url, riskBand: riskBand });
          if (!overlayShown) {
            ensureOverlay();
          }
          renderScanResult(data);
          return null;
        });
      }).catch(function (e) {
        if (scanComplete) return;
        scanComplete = true;
        clearTimeout(softTimer);
        clearTimeout(hardTimer);
        pwLog("runScan: exception; fail-open", { url: url, e: String(e) });
        cleanupOverlay();
        failOpenNavigate(url);
      }).finally(function () {
        if (mySeq === scanSeq) scanInFlight = false;
      });
    });
  }

  // =========================
  // Outbound click interception
  // =========================
  function isOutboundNavigation(href) {
    try {
      var u = new URL(href, window.location.href);
      return u.origin !== window.location.origin;
    } catch (_) {
      return false;
    }
  }

  function findAnchor(el) {
    var cur = el;
    for (var i = 0; i < 6 && cur; i++) {
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
      var href = a.getAttribute("href") || "";
      if (!href || href.startsWith("#") || href.startsWith("javascript:")) return true;
      return false;
    } catch (_) {
      return true;
    }
  }

  function onClickCapture(evt) {
    try {
      if (!interceptionEnabled) return;

      var a = findAnchor(evt.target);
      if (!a) return;
      if (shouldIgnoreClick(evt, a)) return;

      var url = a.href;
      if (!url) return;
      if (!isOutboundNavigation(url)) return;

      // Check Tier 1 allowed targets FIRST (before any interception)
      if (isSilentlyAllowedTarget(url)) {
        pwLog("onClickCapture: silently allowed target (Tier 1)", { url: url });
        return;
      }

      var marketingResult = detectMarketingInfrastructure(url, {
        referrer: document.referrer
      });
      var isMarketingInfra = marketingResult.isMarketingInfra;
      var hints = prescanHints(url);

      pwLog("onClickCapture: marketing detection", {
        url: url,
        isMarketing: isMarketingInfra,
        method: marketingResult.method,
        confidence: marketingResult.confidence,
        signals: marketingResult.signals
      });

      if (isMarketingInfra) {
        // Security: Marketing links with high-risk indicators must still be scanned
        // Defense in depth: Check URL directly, not just hints array
        var hasHighRiskHint = 
          hints.indexOf("ip_literal_host") !== -1 || 
          hints.indexOf("punycode_host") !== -1 ||
          hints.indexOf("suspicious_tld") !== -1 ||
          hasCredentialKeywords(url);  // Direct check (not just hints)
          
        if (!hasHighRiskHint) {
          pwLog("onClickCapture: marketing infra, no high-risk hints, allowing", { url: url, hints: hints });
          return;
        }
        
        // If we get here: marketing link BUT has credential keywords or other red flags
        // Proceed to scan (don't suppress)
        pwLog("onClickCapture: marketing infra but has high-risk hints, scanning", { 
          url: url, 
          hints: hints,
          hasCredentialKeywords: hasCredentialKeywords(url)
        });
      }

      if (!hints.length) {
        pwLog("onClickCapture: no hints, allowing", { url: url });
        return;
      }

      // Rapid click protection: ONLY debounce links we're actually intercepting
      // Placed AFTER all allow branches to avoid blocking legitimate navigation
      var now = Date.now();
      if (url === lastClickUrl && (now - lastClickTime) < 500) {
        pwLog("onClickCapture: rapid click ignored (intercepted link)", { url: url, elapsed: now - lastClickTime });
        evt.preventDefault();
        evt.stopPropagation();
        return;
      }
      lastClickTime = now;
      lastClickUrl = url;

      pwLog("onClickCapture: intercepting for scan", { url: url, hints: hints, isMarketingInfra: isMarketingInfra });

      evt.preventDefault();
      evt.stopPropagation();
      if (typeof evt.stopImmediatePropagation === "function") evt.stopImmediatePropagation();

      pendingUrl = url;
      runScan(url, hints, isMarketingInfra);
    } catch (e) {
      pwLog("onClickCapture: exception; fail-open", { e: String(e) });
      if (pendingUrl) failOpenNavigate(pendingUrl);
    }
  }

  // =========================
  // Wire up event listeners
  // =========================
  
  // Initialize
  initNavigationContext();
  loadBaseline();  // Week 2: Load baseline from storage (page-scoped)
  loadExpectedOrigins();  // Week 2 SSO-safe: Load expected origins (with LRU)
  loadProbationaryOrigins();  // Week 3: Load probationary origins for SSO learning
  monitorStorageHealth();  // Monitor storage usage on page load
  
  // Click interception
  document.addEventListener("click", onClickCapture, true);

  // Credential field detection
  document.addEventListener("focusin", onCredentialFieldFocus, true);
  document.addEventListener("submit", onFormSubmit, true);

  // Network event listener
  window.addEventListener("phishwatch_net_event", onNetworkEvent, true);
  
  // Browser back/forward navigation handling
  // Browser back/forward navigation handling (BFCache restore)
  // Consolidated single handler for all BFCache scenarios
  window.addEventListener('pageshow', function(evt) {
    try {
      if (evt && evt.persisted) {
        pwLog("pageshow: BFCache restore detected");
        
        // Step 1: Clear active state (scan in progress, pending navigation, overlay)
        scanInFlight = false;
        pendingUrl = null;
        cleanupOverlay();
        
        // Step 2: Reload storage caches (may be stale after navigation)
        try { loadBaseline(); } catch (e) { pwLog("pageshow: baseline reload failed", e); }
        try { loadExpectedOrigins(); } catch (e) { pwLog("pageshow: expected origins reload failed", e); }
        try { loadProbationaryOrigins(); } catch (e) { pwLog("pageshow: probationary reload failed", e); }
        
        // Step 3: Disarm treadmill (auth window state is stale after navigation)
        // Use disarmTreadmill (analyzes window) instead of resetTreadmillState (silent clear)
        if (treadmillState && treadmillState.armed) {
          try {
            disarmTreadmill("page_restored_from_cache");
          } catch (e) {
            // If disarm fails, fall back to reset
            pwLog("pageshow: disarm failed, forcing reset", e);
            resetTreadmillState();
          }
        } else {
          // Not armed, just reset to be safe
          resetTreadmillState();
        }
        
        pwLog("pageshow: BFCache restore complete");
      }
    } catch (e) {
      pwLog("pageshow: handler error", e);
    }
  });
  
  // Form detection on page load
  document.addEventListener("DOMContentLoaded", function() {
    try {
      var forms = document.querySelectorAll("form");
      for (var f = 0; f < forms.length; f++) {
        var form = forms[f];
        var inputs = form.querySelectorAll("input");
        for (var i = 0; i < inputs.length; i++) {
          if (isCredentialField(inputs[i])) {
            pwLog("credential form detected on page load", { action: form.action });
            break;
          }
        }
      }
    } catch (_) {}
  });

  // Inject page-context hooks
  function injectPageHook(filename) {
    try {
      if (document.querySelector('script[data-phishwatch="' + filename + '"]')) return;

      var script = document.createElement("script");
      script.src = chrome.runtime.getURL(filename);
      script.dataset.phishwatch = filename;
      (document.head || document.documentElement).appendChild(script);

      pwLog("injected page hook", { filename: filename });
    } catch (e) {
      pwLog("failed to inject page hook", { filename: filename, error: String(e) });
    }
  }

  injectPageHook("pw-net-hook.js");
  injectPageHook("pw-nav-hook.js");

  // =========================
  // Test Helper Support (for SSO-safe gate testing)
  // =========================
  // NOTE: chrome.runtime is NOT available in the page context. The page must talk to us
  // via CustomEvent -> content script bridge -> background -> response event back to page.
  window.addEventListener("phishwatch_test_request", function (evt) {
    var detail = (evt && evt.detail) ? evt.detail : {};
    var requestId = detail.requestId;
    var action = detail.action;
    var payload = detail.payload || {};

    function respond(response) {
      try {
        window.dispatchEvent(new CustomEvent("phishwatch_test_response", {
          detail: { requestId: requestId, response: response }
        }));
      } catch (_) {}
    }

    try {
      pwLog("test helper request", { action: action, requestId: requestId });

      // Guard: extension context might be unavailable (e.g., not installed / invalidated)
      if (!chrome || !chrome.runtime || typeof chrome.runtime.sendMessage !== "function") {
        respond({ ok: false, error: "extension_unavailable" });
        return;
      }

      chrome.runtime.sendMessage(
        { type: "PHISHWATCH_TEST_HELPER", action: action, payload: payload },
        function (response) {
          try {
            var err = chrome.runtime.lastError;
            if (err) {
              respond({ ok: false, error: String(err.message || err) });
              return;
            }
            respond(response || { ok: false, error: "no_response_from_background" });
          } catch (e2) {
            respond({ ok: false, error: "callback_exception: " + String(e2) });
          }
        }
      );
    } catch (e) {
      pwLog("test helper error", { error: String(e) });
      respond({ ok: false, error: "bridge_exception: " + String(e) });
    }
  });

  pwLog("test helper bridge initialized");

  pwLog("content.js loaded (Phase 4 v2.5 - Security Hardened)", {
    origin: window.location.origin,
    phase4_send_research_to_backend: PHASE4_SEND_RESEARCH_TO_BACKEND,
    phase4_show_research_in_ui: PHASE4_SHOW_RESEARCH_IN_UI,
    baseline_threshold: BASELINE_THRESHOLD,
    max_expected_origins_per_page: MAX_EXPECTED_ORIGINS_PER_PAGE,
    probation_graduation_count: PROBATION_GRADUATION_COUNT,
    probation_expiry_days: PROBATION_EXPIRY_DAYS,
    baseline_max_updates_per_hour: BASELINE_MAX_UPDATES_PER_HOUR,
    fail_open_limit_per_session: FAIL_OPEN_LIMIT_PER_SESSION,
    features: [
      "form_action_mismatch_detection",
      "enhanced_auth_window",
      "sequence_tracking",
      "navigation_context",
      "research_signal_infrastructure",
      "sequence_hashing_5part",
      "local_baseline_storage_page_scoped",
      "novelty_detection",
      "novelty_treadmill_correlation",
      "sso_safe_gate1_password_only",
      "sso_safe_gate2_mismatch_primary",
      "sso_safe_gate3_expected_origins",
      "expected_origins_learning_guarded",
      "expected_origins_lru_pruning",
      "probationary_learning_two_strike",
      "probationary_expiry_30_days",
      "probationary_graduation_validation",
      "intelligent_marketing_detection_heuristic",
      "marketing_credential_bypass_mitigation",
      "baseline_rate_limiting",
      "fail_open_monitoring",
      "multi_tab_conflict_resolution",
      "rapid_click_protection",
      "bfcache_navigation_handling",
      "storage_health_monitoring",
      "test_helper_support",
      "consentfix_detection",
      "clickfix_detection",
      "bitb_detection",
      "browser_native_attack_protection",
    ],
  });
  
  // =========================
  // Browser-Native Attack Detection
  // =========================
  
  // Initialize browser-native attack monitoring
  initBrowserNativeProtection();
  
  function initBrowserNativeProtection() {
    pwLog("browser-native: initializing protection");
    
    // ConsentFix/ClickFix: Monitor paste events
    initPasteMonitoring();
    
    // ClickFix: Monitor copy events
    initCopyMonitoring();
    
    // ConsentFix/BitB: Scan page on load
    setTimeout(function() {
      detectConsentFixLurePage();
      detectBitBWindows();
    }, 1000);
    
    // ConsentFix/BitB: Monitor DOM changes for dynamically added threats
    initDOMMonitoring();
    
    pwLog("browser-native: protection active");
  }
  
  // =========================
  // ConsentFix Detection
  // =========================
  
  function initPasteMonitoring() {
    document.addEventListener('paste', function(evt) {
      if (!clipboardMonitoringActive) return;
      
      try {
        var pastedText = (evt.clipboardData || window.clipboardData).getData('text');
        
        if (!pastedText || pastedText.length < 10) return;
        
        var threat = detectOAuthCodePaste(pastedText);
        
        if (threat) {
          pwLog("SECURITY: ConsentFix threat detected", threat);
          
          if (threat.action === 'BLOCK') {
            // Critical OAuth code - BLOCK the paste
            evt.preventDefault();
            evt.stopPropagation();
            
            showBrowserNativeAttackWarning({
              type: 'ConsentFix',
              title: '⛔ Critical Security Warning',
              message: 'OAuth Token Hijacking Attempt Blocked',
              details: 'You attempted to paste an OAuth authorization code into an untrusted website. This is a common technique used in "ConsentFix" attacks to steal your account credentials.',
              recommendation: 'Never paste authentication URLs or codes into websites unless you are certain they are legitimate. Close this page immediately.',
              technicalInfo: threat
            });
          } else if (threat.action === 'WARN') {
            // Custom URI scheme or other warning - don't block, just warn
            showBrowserNativeWarningBanner({
              type: 'Suspicious Paste',
              message: '⚠️ You pasted a custom authentication URL. Be cautious - only paste auth URLs on legitimate sites.',
              severity: 'medium'
            });
          }
        }
      } catch (e) {
        pwLog("paste monitoring error", e);
      }
    }, true); // Capture phase
  }
  
  function detectOAuthCodePaste(text) {
    // Detect OAuth 2.0 authorization code patterns
    var oauthPatterns = [
      /localhost[:/].*[?&]code=/i,
      /127\.0\.0\.1[:/].*[?&]code=/i,
      /0\.0\.0\.0[:/].*[?&]code=/i,
      /\[::1\][:/].*[?&]code=/i,
      /callback.*[?&]code=/i,
      /redirect.*[?&]code=/i,
      /auth.*[?&]code=/i
    ];
    
    // Check for OAuth patterns
    var matchedPattern = null;
    for (var i = 0; i < oauthPatterns.length; i++) {
      if (oauthPatterns[i].test(text)) {
        matchedPattern = oauthPatterns[i].toString();
        break;
      }
    }
    
    if (!matchedPattern) {
      // Check for long authorization codes (even without localhost)
      var codeMatch = text.match(/[?&]code=([a-zA-Z0-9_-]+)/);
      if (codeMatch && codeMatch[1].length >= OAUTH_CODE_MIN_LENGTH) {
        matchedPattern = 'long_auth_code';
      }
    }
    
    if (!matchedPattern) {
      // Optional: Detect custom URI schemes with OAuth parameters
      var customSchemeMatch = text.match(/^([a-z][a-z0-9+.-]*):\/\/.*(code=|token=)/i);
      if (customSchemeMatch) {
        // Custom scheme detected - warn only, don't block
        pwLog("paste monitoring: Custom URI scheme with OAuth param", {
          scheme: customSchemeMatch[1],
          text: text.substring(0, 100)
        });
        
        // Return warning-level threat (not critical)
        return {
          signal: 'custom_uri_scheme_oauth',
          riskLevel: 'MEDIUM',
          action: 'WARN',
          matchedPattern: 'custom_scheme_' + customSchemeMatch[1],
          currentDomain: window.location.hostname,
          pastedTextPreview: text.substring(0, 100),
          note: 'Custom URI scheme - cannot validate handler safety'
        };
      }
      return null;
    }
    
    // Check if current page is a trusted OAuth provider
    var currentDomain = window.location.hostname;
    var trustedOAuthDomains = [
      'login.microsoftonline.com',
      'accounts.google.com',
      'github.com',
      'auth0.com',
      'okta.com',
      'login.live.com',
      'login.yahoo.com'
    ];
    
    var isTrustedContext = trustedOAuthDomains.some(function(d) {
      // Proper registrable domain boundary matching
      // Prevents bypass like: login.microsoftonline.com.evil.com
      return currentDomain === d || currentDomain.endsWith('.' + d);
    });
    
    if (isTrustedContext) {
      pwLog("paste monitoring: OAuth code paste on trusted domain", {
        domain: currentDomain
      });
      return null; // Allow paste on trusted OAuth providers
    }
    
    // THREAT DETECTED
    return {
      signal: 'oauth_code_paste_suspicious_context',
      riskLevel: 'CRITICAL',
      action: 'BLOCK',
      matchedPattern: matchedPattern,
      currentDomain: currentDomain,
      pastedTextPreview: text.substring(0, 100)
    };
  }
  
  function detectConsentFixLurePage() {
    var pageText = document.body ? document.body.innerText.toLowerCase() : '';
    var pageHTML = document.documentElement ? document.documentElement.outerHTML : '';
    
    // ConsentFix signature patterns
    var lurePatterns = [
      // Copy-paste instructions with OAuth context
      { pattern: /paste.*localhost.*url/i, weight: 40, name: 'paste_localhost_instruction' },
      { pattern: /paste.*verification.*code/i, weight: 30, name: 'paste_verification_code' },
      { pattern: /copy.*authorization.*code/i, weight: 35, name: 'copy_auth_code' },
      { pattern: /paste.*callback.*url/i, weight: 40, name: 'paste_callback_url' },
      
      // Fake Cloudflare Turnstile
      { pattern: /cloudflare.*verification.*paste/i, weight: 50, name: 'fake_cloudflare_paste' },
      { pattern: /turnstile.*verification.*paste/i, weight: 50, name: 'fake_turnstile_paste' },
      
      // Multi-step verification (social engineering)
      { pattern: /step 1.*step 2.*paste/i, weight: 35, name: 'multi_step_paste' },
      { pattern: /verify.*human.*paste.*url/i, weight: 40, name: 'verify_human_paste_url' },
      { pattern: /complete.*verification.*paste/i, weight: 30, name: 'complete_verification_paste' }
    ];
    
    var score = 0;
    var matchedPatterns = [];
    
    for (var i = 0; i < lurePatterns.length; i++) {
      if (lurePatterns[i].pattern.test(pageText)) {
        score += lurePatterns[i].weight;
        matchedPatterns.push(lurePatterns[i].name);
      }
    }
    
    // Check for fake Cloudflare branding (not on cloudflare domain)
    var hasFakeTurnstile = pageHTML.includes('turnstile') && 
                           !window.location.hostname.includes('cloudflare') &&
                           !window.location.hostname.includes('challenges.cloudflare.com');
    
    if (hasFakeTurnstile) {
      score += 40;
      matchedPatterns.push('fake_cloudflare_branding');
    }
    
    // Threat threshold
    if (score >= 30) {
      pwLog("SECURITY: ConsentFix lure page detected", {
        score: score,
        patterns: matchedPatterns,
        url: window.location.href
      });
      
      suspiciousElementsDetected.push({
        type: 'ConsentFixLure',
        score: score,
        patterns: matchedPatterns
      });
      
      // Show warning banner (non-blocking)
      showBrowserNativeWarningBanner({
        type: 'ConsentFix Lure',
        message: '⚠️ This page may be attempting a ConsentFix attack. Be very careful about pasting any URLs or codes.',
        severity: 'high'
      });
    }
  }
  
  // =========================
  // ClickFix Detection
  // =========================
  
  function initCopyMonitoring() {
    document.addEventListener('copy', function(evt) {
      if (!clipboardMonitoringActive) return;
      
      try {
        var selection = window.getSelection();
        var copiedText = selection ? selection.toString() : '';
        
        if (!copiedText || copiedText.length < 10) return;
        
        var threat = detectMaliciousCommand(copiedText);
        
        if (threat) {
          pwLog("SECURITY: ClickFix threat detected", threat);
          
          if (threat.action === 'BLOCK') {
            // HIGH-confidence + lure context: BLOCK the copy
            evt.preventDefault();
            evt.stopPropagation();
            
            showBrowserNativeAttackWarning({
              type: 'ClickFix',
              title: '🛑 Malicious Command Blocked',
              message: 'Attempted to Copy Dangerous Command',
              details: 'You attempted to copy a command that matches patterns commonly used in "ClickFix" attacks designed to trick users into running malware on their computers. The page you\'re on contains instructions to paste and run this command.',
              recommendation: 'DO NOT run this command under any circumstances. Close this page immediately and run an antivirus scan if you\'ve already executed similar commands.',
              technicalInfo: threat
            });
          } else if (threat.action === 'WARN') {
            // MEDIUM-confidence: WARN only, don't block
            showBrowserNativeWarningBanner({
              type: 'Suspicious Command',
              message: '⚠️ You copied a command that may be dangerous. Only run commands from trusted sources. Verify before executing.',
              severity: 'medium'
            });
          }
        }
      } catch (e) {
        pwLog("copy monitoring error", e);
      }
    }, true); // Capture phase
  }
  
  function detectMaliciousCommand(text) {
    // Check page context for ClickFix lure indicators
    var pageText = document.body ? document.body.innerText.toLowerCase() : '';
    var hasLureIndicators = CLICKFIX_LURE_INDICATORS.some(function(pattern) {
      return pattern.test(pageText);
    });
    
    // Check for HIGH-confidence patterns
    var highConfidenceMatch = null;
    for (var i = 0; i < HIGH_CONFIDENCE_MALICIOUS.length; i++) {
      if (HIGH_CONFIDENCE_MALICIOUS[i].test(text)) {
        highConfidenceMatch = HIGH_CONFIDENCE_MALICIOUS[i].toString();
        break;
      }
    }
    
    // BLOCK only if high-confidence AND lure context present
    if (highConfidenceMatch && hasLureIndicators) {
      return {
        signal: 'malicious_command_high_confidence',
        riskLevel: 'CRITICAL',
        action: 'BLOCK',
        matchedPattern: highConfidenceMatch,
        hasLureContext: true,
        commandPreview: text.substring(0, 100)
      };
    }
    
    // Check for MEDIUM-confidence patterns (warn only)
    var mediumConfidenceMatch = null;
    for (var i = 0; i < MEDIUM_CONFIDENCE_SUSPICIOUS.length; i++) {
      if (MEDIUM_CONFIDENCE_SUSPICIOUS[i].test(text)) {
        mediumConfidenceMatch = MEDIUM_CONFIDENCE_SUSPICIOUS[i].toString();
        break;
      }
    }
    
    // WARN if medium-confidence OR high-confidence without lure context
    if (mediumConfidenceMatch || (highConfidenceMatch && !hasLureIndicators)) {
      return {
        signal: 'suspicious_command_medium_confidence',
        riskLevel: 'MEDIUM',
        action: 'WARN',
        matchedPattern: mediumConfidenceMatch || highConfidenceMatch,
        hasLureContext: hasLureIndicators,
        commandPreview: text.substring(0, 100)
      };
    }
    
    return null;
  }
  
  // =========================
  // Browser-in-the-Browser (BitB) Detection
  // =========================
  
  function detectBitBWindows() {
    // Narrow selector: only target explicitly fake-window-like elements
    // Reduces false positives from legitimate modals/dialogs
    var suspiciousElements = document.querySelectorAll(
      'div[class*="browser-window"], div[class*="fake-window"], ' +
      'div[class*="browser-chrome"], div[class*="window-frame"]'
    );
    
    for (var i = 0; i < suspiciousElements.length; i++) {
      var el = suspiciousElements[i];
      
      // Pre-filter: Check size constraints BEFORE scoring
      // Avoids wasting CPU on banners, chat widgets, small modals
      var styles = window.getComputedStyle(el);
      var width = parseInt(styles.width);
      var height = parseInt(styles.height);
      var position = styles.position;
      
      // Skip if not window-like dimensions
      if (position !== 'fixed' && position !== 'absolute') continue;
      if (width < 400 || width > 900) continue;
      if (height < 400 || height > 900) continue;
      
      // Passed pre-filter, now score it
      var threat = analyzePotentialBitB(el);
      
      if (threat) {
        pwLog("SECURITY: BitB threat detected", threat);
        
        suspiciousElementsDetected.push({
          type: 'BitB',
          element: el,
          threat: threat
        });
        
        // Only take user-visible action if score >= 80 (conservative)
        if (threat.score >= 80) {
          // Add visual indicator to fake window
          try {
            el.style.border = '3px solid red';
            el.style.boxShadow = '0 0 20px red';
          } catch (e) {}
          
          // Show warning
          showBrowserNativeWarningBanner({
            type: 'Fake Login Window (BitB)',
            message: '⚠️ This page contains a fake browser window. This may be a phishing attempt. Verify the real URL in your browser\'s address bar.',
            severity: 'high'
          });
        }
      }
    }
  }
  
  function analyzePotentialBitB(element) {
    try {
      // Size already checked in detectBitBWindows() pre-filter
      var styles = window.getComputedStyle(element);
      
      var score = 0;
      var indicators = [];
      
      // Check if contains iframe
      var hasIframe = element.querySelector('iframe') !== null;
      if (hasIframe) {
        score += 40;
        indicators.push('contains_iframe');
      }
      
      // Check if has password field
      var hasPasswordField = element.querySelector('input[type="password"]') !== null;
      if (hasPasswordField) {
        score += 35;
        indicators.push('has_password_field');
      }
      
      // Check if has fake URL bar content
      var text = element.innerText.toLowerCase();
      var hasFakeURL = /https?:\/\//.test(text) &&
                       (text.includes('google.com') ||
                        text.includes('microsoft.com') ||
                        text.includes('github.com') ||
                        text.includes('facebook.com') ||
                        text.includes('apple.com'));
      
      if (hasFakeURL) {
        score += 40;
        indicators.push('fake_url_text');
      }
      
      // Check for fake browser chrome elements
      var hasTitleBar = element.querySelector('[class*="title"]') !== null ||
                       element.querySelector('[class*="chrome"]') !== null;
      if (hasTitleBar) {
        score += 25;
        indicators.push('fake_title_bar');
      }
      
      // Check for fake window controls (close button, etc.)
      var controlsText = element.innerHTML;
      var hasFakeControls = /×|✕|⨯/.test(controlsText) || 
                           controlsText.includes('close') ||
                           controlsText.includes('minimize');
      if (hasFakeControls) {
        score += 20;
        indicators.push('fake_window_controls');
      }
      
      // Check if contains login form with SSO branding
      var hasSSOText = /sign in with|log in with|continue with/i.test(text);
      if (hasSSOText && hasPasswordField) {
        score += 30;
        indicators.push('sso_login_form');
      }
      
      // Log at 60+ for telemetry, user action at 80+
      var BITB_SCORE_LOG_ONLY = 60;
      var BITB_SCORE_USER_ACTION = 80;
      
      if (score >= BITB_SCORE_LOG_ONLY) {
        return {
          signal: 'fake_browser_window_detected',
          riskLevel: score >= BITB_SCORE_USER_ACTION ? 'HIGH' : 'MEDIUM',
          score: score,
          indicators: indicators,
          dimensions: {
            width: styles.width,
            height: styles.height,
            position: styles.position
          }
        };
      }
      
      return null;
    } catch (e) {
      return null;
    }
  }
  
  function initDOMMonitoring() {
    // Monitor for dynamically added BitB windows
    if (!window.MutationObserver) return;
    
    // Rate limiting state
    var lastBitBScanTime = 0;
    var BITB_SCAN_MIN_INTERVAL_MS = 2000;  // Max once per 2 seconds
    
    var observer = new MutationObserver(function(mutations) {
      var now = Date.now();
      var timeSinceLastScan = now - lastBitBScanTime;
      
      if (timeSinceLastScan < BITB_SCAN_MIN_INTERVAL_MS) {
        // Too soon, skip this mutation
        return;
      }
      
      for (var i = 0; i < mutations.length; i++) {
        var addedNodes = mutations[i].addedNodes;
        for (var j = 0; j < addedNodes.length; j++) {
          var node = addedNodes[j];
          if (node.nodeType === 1) { // Element node
            // Schedule scan (debounced)
            setTimeout(function() {
              var nowCheck = Date.now();
              if (nowCheck - lastBitBScanTime >= BITB_SCAN_MIN_INTERVAL_MS) {
                detectBitBWindows();
                lastBitBScanTime = nowCheck;
              }
            }, 500);
            return; // Only check once per mutation batch
          }
        }
      }
    });
    
    observer.observe(document.body || document.documentElement, {
      childList: true,
      subtree: true
    });
  }
  
  // =========================
  // Browser-Native Attack Warning UI
  // =========================
  
  function showBrowserNativeAttackWarning(config) {
    // Critical blocking warning for ConsentFix/ClickFix
    var warningHTML = 
      '<div style="position:fixed; top:0; left:0; width:100%; height:100%; ' +
      'background:rgba(0,0,0,0.95); z-index:2147483647; display:flex; ' +
      'align-items:center; justify-content:center; font-family:system-ui,-apple-system,sans-serif;">' +
        '<div style="background:white; padding:40px; border-radius:12px; ' +
        'max-width:600px; box-shadow:0 20px 60px rgba(0,0,0,0.5);">' +
          '<div style="font-size:48px; text-align:center; margin-bottom:20px;">' +
            (config.type === 'ConsentFix' ? '⛔' : '🛑') +
          '</div>' +
          '<h1 style="margin:0 0 10px; font-size:24px; color:#d32f2f; text-align:center;">' +
            config.title +
          '</h1>' +
          '<h2 style="margin:0 0 20px; font-size:18px; color:#333; text-align:center;">' +
            config.message +
          '</h2>' +
          '<div style="background:#fff3e0; padding:15px; border-radius:8px; margin-bottom:20px; border-left:4px solid #ff9800;">' +
            '<p style="margin:0; color:#333; font-size:14px; line-height:1.6;">' +
              '<strong>What happened:</strong><br>' +
              config.details +
            '</p>' +
          '</div>' +
          '<div style="background:#e3f2fd; padding:15px; border-radius:8px; margin-bottom:20px; border-left:4px solid #2196f3;">' +
            '<p style="margin:0; color:#333; font-size:14px; line-height:1.6;">' +
              '<strong>What to do:</strong><br>' +
              config.recommendation +
            '</p>' +
          '</div>' +
          '<div style="text-align:center;">' +
            '<button id="pw-close-warning" style="background:#d32f2f; color:white; ' +
            'padding:12px 30px; border:none; border-radius:6px; font-size:16px; ' +
            'cursor:pointer; font-weight:bold;">Close This Page</button>' +
            '<div style="margin-top:10px;">' +
              '<a href="#" id="pw-dismiss-warning" style="color:#666; font-size:14px; text-decoration:underline;">I understand the risk, continue anyway</a>' +
            '</div>' +
          '</div>' +
          '<div style="margin-top:20px; padding-top:20px; border-top:1px solid #ddd;">' +
            '<p style="margin:0; color:#666; font-size:12px; text-align:center;">' +
              'Protected by PhishWatch Browser-Native Attack Detection' +
            '</p>' +
          '</div>' +
        '</div>' +
      '</div>';
    
    var warningDiv = document.createElement('div');
    warningDiv.id = 'pw-browser-native-warning';
    warningDiv.innerHTML = warningHTML;
    document.body.appendChild(warningDiv);
    
    // Close page button
    var closeBtn = document.getElementById('pw-close-warning');
    if (closeBtn) {
      closeBtn.addEventListener('click', function(e) {
        e.preventDefault();
        window.location.href = 'about:blank';
      });
    }
    
    // Dismiss button (risky)
    var dismissBtn = document.getElementById('pw-dismiss-warning');
    if (dismissBtn) {
      dismissBtn.addEventListener('click', function(e) {
        e.preventDefault();
        var confirmed = confirm(
          'WARNING: This action may compromise your security.\n\n' +
          'PhishWatch detected a ' + config.type + ' attack attempt. ' +
          'Continuing may result in your account being stolen.\n\n' +
          'Are you absolutely sure you want to proceed?'
        );
        if (confirmed) {
          warningDiv.remove();
        }
      });
    }
    
    pwLog("browser-native warning shown", {
      type: config.type,
      threat: config.technicalInfo
    });
  }
  
  function showBrowserNativeWarningBanner(config) {
    // Non-blocking banner for ConsentFix lure pages / BitB
    var existingBanner = document.getElementById('pw-browser-native-banner');
    if (existingBanner) return; // Only show one banner
    
    var bannerHTML =
      '<div id="pw-browser-native-banner" style="position:fixed; top:0; left:0; width:100%; ' +
      'background:' + (config.severity === 'high' ? '#d32f2f' : '#ff9800') + '; ' +
      'color:white; padding:15px; z-index:2147483646; box-shadow:0 2px 10px rgba(0,0,0,0.3); ' +
      'font-family:system-ui,-apple-system,sans-serif; font-size:14px;">' +
        '<div style="max-width:1200px; margin:0 auto; display:flex; align-items:center; justify-content:space-between;">' +
          '<div style="flex:1;">' +
            '<strong>' + config.type + ' Detected:</strong> ' + config.message +
          '</div>' +
          '<button id="pw-close-banner" style="background:rgba(255,255,255,0.2); color:white; ' +
          'border:1px solid white; padding:5px 15px; border-radius:4px; cursor:pointer; margin-left:15px;">' +
            'Dismiss' +
          '</button>' +
        '</div>' +
      '</div>';
    
    var bannerDiv = document.createElement('div');
    bannerDiv.innerHTML = bannerHTML;
    var banner = bannerDiv.firstChild;
    document.body.insertBefore(banner, document.body.firstChild);
    
    // Dismiss button
    var closeBtn = document.getElementById('pw-close-banner');
    if (closeBtn) {
      closeBtn.addEventListener('click', function() {
        banner.remove();
      });
    }
    
    // Auto-dismiss after 30 seconds
    setTimeout(function() {
      if (banner && banner.parentNode) {
        banner.remove();
      }
    }, 30000);
  }
})();
