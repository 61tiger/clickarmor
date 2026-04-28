// page-analyzer.js — pure-ish helpers (used by content.js). Exposes functions on window.__ClickGuardAnalyzer
(function () {
  const Analyzer = {};

  function cap100(n) { return Math.max(0, Math.min(100, n)); }
  function uniq(arr) { return Array.from(new Set(arr)); }

  // --- Homoglyph + Unicode normalization for page text scanning ---
  // Mirrors detector.js HIGH-3/3a: Cyrillic/Greek lookalikes and exotic whitespace
  // defeat regex-based lure detection. Normalize BEFORE matching.
  const _HOMOGLYPHS = {"\u0410":"A","\u0412":"B","\u0421":"C","\u0415":"E","\u041D":"H","\u041A":"K","\u041C":"M","\u041E":"O","\u0420":"P","\u0422":"T","\u0425":"X","\u0423":"Y","\u0430":"a","\u0435":"e","\u043E":"o","\u0440":"p","\u0441":"c","\u0443":"y","\u0445":"x","\u0456":"i","\u0455":"s","\u0458":"j","\u0501":"d","\u04BB":"h","\u0405":"S","\u0406":"I","\u0407":"I","\u0457":"i","\u04C0":"I","\u0391":"A","\u0392":"B","\u0395":"E","\u0397":"H","\u0399":"I","\u039A":"K","\u039C":"M","\u039D":"N","\u039F":"O","\u03A1":"P","\u03A4":"T","\u03A5":"Y","\u03A7":"X","\u03B1":"a","\u03BF":"o","\u03C1":"p"};
  function normalizeText(s) {
    if (!s) return "";
    let t = s;
    // NFKD decomposition (collapses compatibility chars like ﬁ → fi)
    try { t = t.normalize("NFKD"); } catch {}
    // Strip combining diacritical marks
    t = t.replace(/[\u0300-\u036F]/g, "");
    // Strip zero-width chars, soft hyphens, invisible formatters
    t = t.replace(/[\u200B\u200C\u200D\u200E\u200F\uFEFF\u00AD\u2060\u2061-\u2064\u2066-\u2069\u061C]/g, "");
    // Normalize exotic whitespace (thin/hair/em/en/four-per-em/etc.) to regular space
    t = t.replace(/[\u2000-\u200A\u205F\u3000\u00A0]/g, " ");
    // Map Cyrillic/Greek homoglyphs to ASCII
    t = t.replace(/[\u0391-\u03C9\u0400-\u04FF\u0500-\u052F]/g, ch => _HOMOGLYPHS[ch] || ch);
    // Normalize dash-like chars to ASCII hyphen
    t = t.replace(/[\u2013\u2014\u2015\u2212\uFE58\uFE63\uFF0D]/g, "-");
    return t;
  }

  const SAFE_LOADER_HOST_RE = /(^|\.)((googletagmanager|google-analytics|googlesyndication|googleadservices|doubleclick|gstatic|google|facebook|clarity|bat\.bing|amazon-adsystem|privacy-center|didomi|cookielaw|onetrust|jsdelivr|cloudflareinsights|sentry|segment|hotjar|newrelic|adobedtm|criteo|pubmatic|taboola|outbrain|scorecardresearch)\.(com|net|org|io|ms)|sftcdn\.net|softonic\.com|eweek\.com|technologyadvice\.com)$/i;

  function extractHostname(rawUrl) {
    if (!rawUrl) return "";
    try {
      const normalized = rawUrl.startsWith("//") ? (location.protocol + rawUrl) : rawUrl;
      return new URL(normalized, location.href).hostname.replace(/^www\./i, "").toLowerCase();
    } catch {
      return "";
    }
  }

  function isSafeLoaderHost(host) {
    if (!host) return true;
    const cleanHost = host.replace(/^www\./i, "").toLowerCase();
    const current = (location.hostname || "").replace(/^www\./i, "").toLowerCase();
    if (current && (cleanHost === current || cleanHost.endsWith("." + current) || current.endsWith("." + cleanHost))) {
      return true;
    }
    return SAFE_LOADER_HOST_RE.test(cleanHost);
  }

  function normalizeHostName(host) {
    return (host || "").toLowerCase().replace(/^www\./, "").replace(/^\.+/, "");
  }

  function hostMatchesSuffix(host, suffixes) {
    const clean = normalizeHostName(host);
    return suffixes.some((suffix) => clean === suffix || clean.endsWith("." + suffix));
  }

  const AITM_BRANDS = [
    {
      brand: "Microsoft",
      officialHosts: [
        "microsoft.com", "microsoftonline.com", "live.com", "office.com",
        "office365.com", "sharepoint.com", "outlook.com", "windows.net"
      ],
      assetHosts: [
        "login.microsoftonline.com", "aadcdn.msauth.net", "aadcdn.msftauth.net",
        "login.live.com", "outlook.office.com", "office.com"
      ],
      aliasRules: [
        /\bmicrosoft\b/i, /\boffice(?:\s*365)?\b/i, /\bone ?drive\b/i,
        /\bsharepoint\b/i, /\boutlook\b/i, /\bteams\b/i
      ],
      uiRules: [
        /sign\s+in\s+to\s+your\s+account/i,
        /use\s+your\s+microsoft\s+account/i,
        /stay\s+signed\s+in/i,
        /keep\s+me\s+signed\s+in/i,
        /use\s+another\s+account/i,
        /pick\s+an\s+account/i
      ],
      reauthRules: [
        /session\s+(?:has\s+)?expired/i,
        /sign\s+in\s+again/i,
        /reauthenticate|re-authenticate/i,
        /verify\s+your\s+(?:identity|account)/i,
        /confirm\s+your\s+identity/i
      ],
      otpRules: [
        /verification\s+code/i,
        /security\s+code/i,
        /approve\s+sign[\s-]?in\s+request/i,
        /microsoft\s+authenticator/i,
        /one[\s-]?time\s+(?:code|passcode)/i,
        /enter\s+code/i
      ],
      allowCustomDomains: false
    },
    {
      brand: "Google",
      officialHosts: [
        "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com"
      ],
      assetHosts: [
        "accounts.google.com", "ssl.gstatic.com", "apis.google.com",
        "gstatic.com", "accounts.youtube.com"
      ],
      aliasRules: [
        /\bgoogle\b/i, /\bgmail\b/i, /\bgoogle\s+workspace\b/i,
        /\bgoogle\s+drive\b/i, /\bdocs\b/i, /\bsheets\b/i, /\bslides\b/i
      ],
      uiRules: [
        /choose\s+an\s+account/i,
        /to\s+continue\s+to/i,
        /use\s+your\s+google\s+account/i,
        /verify\s+it'?s\s+you/i,
        /sign\s+in\s+with\s+google/i
      ],
      reauthRules: [
        /session\s+(?:has\s+)?expired/i,
        /sign\s+in\s+again/i,
        /verify\s+it'?s\s+you/i,
        /confirm\s+it'?s\s+you/i,
        /reauthenticate|re-authenticate/i
      ],
      otpRules: [
        /verification\s+code/i,
        /security\s+code/i,
        /google\s+prompt/i,
        /one[\s-]?time\s+(?:code|passcode)/i,
        /enter\s+code/i
      ],
      allowCustomDomains: false
    },
    {
      brand: "Okta",
      officialHosts: [
        "okta.com", "okta-emea.com", "oktapreview.com", "okta-gov.com", "oktacdn.com"
      ],
      assetHosts: [
        "oktacdn.com", "okta.com", "okta-emea.com", "oktapreview.com", "okta-gov.com"
      ],
      aliasRules: [
        /\bokta\b/i, /\bokta\s+verify\b/i, /\bokta\s+fastpass\b/i
      ],
      uiRules: [
        /\bokta\s+verify\b/i,
        /push\s+notification\s+sent/i,
        /verify\s+with\s+okta/i,
        /enter\s+code/i
      ],
      reauthRules: [
        /session\s+(?:has\s+)?expired/i,
        /sign\s+in\s+again/i,
        /reauthenticate|re-authenticate/i,
        /verify\s+your\s+(?:identity|account)/i
      ],
      otpRules: [
        /\bokta\s+verify\b/i,
        /push\s+notification\s+sent/i,
        /verification\s+code/i,
        /security\s+code/i,
        /enter\s+code/i
      ],
      allowCustomDomains: true
    }
  ];

  const AITM_OFFICIAL_HOST_SUFFIXES = Array.from(new Set(AITM_BRANDS.flatMap((brand) => brand.officialHosts)));

  function isKnownOfficialIdpHost(host) {
    return hostMatchesSuffix(host, AITM_OFFICIAL_HOST_SUFFIXES);
  }

  function isAiTMAbuseProneOfficialHost(host) {
    return normalizeHostName(host) === "sites.google.com";
  }

  function isSuspiciousServerlessHost(host) {
    const clean = normalizeHostName(host);
    return clean === "workers.dev" ||
           clean.endsWith(".workers.dev") ||
           clean === "pages.dev" ||
           clean.endsWith(".pages.dev") ||
           clean === "web.app" ||
           clean.endsWith(".web.app") ||
           clean === "firebaseapp.com" ||
           clean.endsWith(".firebaseapp.com");
  }

  function findAiTMBrandInHost(host) {
    const hostText = normalizeText(normalizeHostName(host).replace(/[._-]+/g, " "));
    return AITM_BRANDS.find((brand) =>
      !hostMatchesSuffix(host, brand.officialHosts) &&
      brand.aliasRules.some((rule) => rule.test(hostText))
    ) || null;
  }

  function countRuleHits(text, rules) {
    let hits = 0;
    for (const rule of rules || []) {
      if (rule.test(text)) hits++;
    }
    return hits;
  }

  function collectAiTMReferenceHosts() {
    const hosts = new Set();
    const selectors = [
      ["script[src]", "src"],
      ["link[href]", "href"],
      ["iframe[src]", "src"],
      ["form[action]", "action"],
      ["img[src]", "src"]
    ];
    for (const [selector, attr] of selectors) {
      const nodes = document.querySelectorAll(selector);
      for (const node of nodes) {
        const raw = node.getAttribute(attr) || "";
        const host = extractHostname(raw);
        if (host) hosts.add(host);
      }
    }
    return Array.from(hosts);
  }

  function collectAiTMRedirectTargets() {
    const targets = [];
    const anchors = document.querySelectorAll("a[href]");
    for (const anchor of anchors) {
      const href = anchor.getAttribute("href") || "";
      if (!href) continue;

      let parsed;
      try {
        parsed = new URL(href, location.href);
      } catch {
        continue;
      }

      let targetRaw = parsed.href;
      let isGoogleRedirect = false;
      if (hostMatchesSuffix(parsed.hostname, ["google.com"]) && /^\/url$/i.test(parsed.pathname)) {
        const redirectTarget = parsed.searchParams.get("q") || parsed.searchParams.get("url") || "";
        if (redirectTarget) {
          targetRaw = redirectTarget;
          isGoogleRedirect = true;
        }
      }

      const targetHost = extractHostname(targetRaw);
      if (!targetHost) continue;
      targets.push({ targetHost, isGoogleRedirect, anchor });
    }
    return targets;
  }

  function analyzeAiTMFields() {
    const inputs = document.querySelectorAll("input, textarea, select");
    let hasPassword = false;
    let hasUsername = false;
    let hasOtp = false;
    let numericOtp = 0;

    const usernameRe = /\b(email|e-?mail|username|user\s*id|login|sign[\s-]?in)\b/i;
    const otpRe = /\b(otp|mfa|2fa|auth(?:entication)?\s*code|verification\s*code|security\s*code|one[\s-]?time\s*(?:code|passcode)|token|passcode|authenticator|push\s+notification|number\s+matching)\b/i;

    for (const input of inputs) {
      const context = [
        input.getAttribute("type") || "",
        input.getAttribute("name") || "",
        input.getAttribute("id") || "",
        input.getAttribute("placeholder") || "",
        input.getAttribute("aria-label") || "",
        input.getAttribute("autocomplete") || "",
        input.closest("label")?.textContent || "",
        input.parentElement?.textContent || ""
      ].join(" ");
      const normalized = normalizeText(context).toLowerCase();
      const type = (input.getAttribute("type") || "").toLowerCase();
      const maxLength = Number(input.getAttribute("maxlength") || input.maxLength || 0);
      const inputMode = (input.getAttribute("inputmode") || "").toLowerCase();

      if (type === "password") {
        hasPassword = true;
      }
      if (type === "email" || /username|current-username|email/.test(input.getAttribute("autocomplete") || "") || usernameRe.test(normalized)) {
        hasUsername = true;
      }
      if (otpRe.test(normalized)) {
        hasOtp = true;
      }
      if ((maxLength >= 4 && maxLength <= 8) && (inputMode === "numeric" || /\b\d+\b/.test((input.value || "").trim()) || /code|otp|passcode|verification/.test(normalized))) {
        numericOtp++;
      }
    }

    if (numericOtp >= 2) hasOtp = true;

    return {
      hasPassword,
      hasUsername,
      hasOtp,
      hasCredentialSurface: hasPassword || (hasUsername && hasOtp)
    };
  }

  function collectScriptHosts(blob) {
    const hosts = new Set();
    const urlMatches = blob.match(/(?:https?:)?\/\/[^\s"'`<>\\]+/g) || [];
    for (const raw of urlMatches) {
      const host = extractHostname(raw);
      if (host) hosts.add(host);
    }
    return Array.from(hosts);
  }

  function decodedPayloadLooksSuspicious(decoded) {
    if (!decoded) return false;
    if (/^https?:\/\//i.test(decoded)) {
      const host = extractHostname(decoded);
      return !!host && !isSafeLoaderHost(host);
    }
    return /<script|<iframe|document\.write|navigator\s*\.\s*clipboard|powershell|cmd\.exe|mshta|\biex\b|\biwr\b|invoke-webrequest|downloadfile/i.test(decoded);
  }

  Analyzer.scanLurePhrases = function (bodyText) {
    const text = normalizeText(bodyText || "").toLowerCase();
    const hits = [];
    const rules = [
      { re: /press\s+(win(dows)?\s*\+\s*r|⊞\s*\+\s*r)/i, score: 40, label: "Win+R instruction" },
      { re: /open\s+(run\s+dialog|command\s+prompt|terminal|powershell)/i, score: 40, label: "Open Run/Terminal instruction" },
      { re: /ctrl\s*\+\s*v[\s\S]{0,80}?(run|dialog|terminal|powershell)/i, score: 40, label: "Ctrl+V then run" },
      { re: /(right[\s-]?click|paste)[\s\S]{0,80}?(address\s*bar|terminal|powershell|cmd)/i, score: 40, label: "Paste into address bar/terminal" },

      // Broader keyboard instruction patterns (catches SVG-icon variants)
      { re: /hold[\s\S]{0,40}?press[\s\S]{0,40}?["']?r["']?\s/i, score: 40, label: "Hold+Press R instruction" },
      { re: /(hold|press)[\s\S]{0,60}?ctrl[\s\S]{0,60}?(press|paste)[\s\S]{0,30}?["']?v["']?/i, score: 40, label: "Ctrl+V instruction (hold/press variant)" },
      { re: /step\s*1[\s\S]{0,80}?step\s*2[\s\S]{0,80}?step\s*3/i, score: 35, label: "Multi-step instruction sequence (1-2-3)", weak: true },
      { re: /press[\s\S]{0,40}?["']?(ok|enter)["']?\b/i, score: 15, label: "Press OK/Enter instruction", weak: true },

      // Fake update / driver install screens
      { re: /working\s+on\s+updates[\s\S]*?do\s+not\s+turn\s+off/i, score: 40, label: "Fake Windows Update screen" },
      { re: /install(ing)?\s+(the\s+)?critical\s+(security\s+)?update/i, score: 35, label: "Install critical security update" },
      { re: /installing\s+(features|updates)\s+(and\s+)?drivers/i, score: 30, label: "Fake driver installation" },

      { re: /paste[\s\S]{0,60}?(command|code|script|fix|verification|solution)/i, score: 25, label: "Paste a command/script" },
      { re: /(verify|prove|confirm)[\s\S]{0,80}?(human|not\s+a?\s*bot|captcha)[\s\S]{0,80}?(paste|run|execute|command)/i, score: 25, label: "Verify human via paste/run" },
      { re: /(fix|repair|update)[\s\S]{0,80}?(browser|computer|driver)[\s\S]{0,80}?(paste|run|copy)/i, score: 25, label: "Fix/update via paste/run" },
      { re: /press\s+enter\s+(to\s+)?(verify|confirm|fix)/i, score: 25, label: "Press Enter to verify/fix" },
      { re: /copy[\s\S]{0,60}?(verification|security)\s*(code|command|key)/i, score: 25, label: "Copy verification code/command" },
      { re: /step\s*[123][\s\S]{0,100}?(press|open|paste|run)/i, score: 25, label: "Step-by-step press/paste/run" },

      { re: /(verify|confirm)[\s\S]{0,40}?(human|not\s+a?\s*bot|robot)/i, score: 10, label: "Human verification language", weak: true },
      { re: /(security|verification)\s*(check|required|needed)/i, score: 10, label: "Verification required", weak: true },
      { re: /(browser|system)[\s\S]{0,40}?(update|fix|patch)\s*(required|needed|available)/i, score: 10, label: "Update/fix required", weak: true }
    ];

    // Additional lure phrases for fake browser update flows
    const updateLureRules = [
      { re: /copy[\s\S]{0,40}?(and\s+)?(run|paste)[\s\S]{0,40}?(this\s+)?command/i, score: 35, label: "Copy and run this command instruction" },
      { re: /run\s*(the\s+)?following\s*command/i, score: 35, label: "Run the following command" },
      { re: /open\s*(the\s+)?run\s*dialog[\s\S]{0,80}?(copy|paste|command)/i, score: 40, label: "Open Run dialog then copy/paste" },
      { re: /won'?t\s*be\s*able\s*to\s*use[\s\S]{0,80}?until[\s\S]{0,80}?(command|executed|run)/i, score: 35, label: "Service blocked until command executed" },
      { re: /this\s*step\s*is\s*required\s*to\s*complete/i, score: 25, label: "Step required to complete (pressure)", weak: true },
      { re: /i'?ve?\s*completed?\s*(the\s*)?(update|installation|verification)/i, score: 20, label: "I've completed the update button", weak: true },
    ];

    let strongScore = 0;
    let weakScore = 0;

    for (const r of updateLureRules) {
      if (r.re.test(text)) {
        if (r.weak) weakScore += r.score;
        else strongScore += r.score;
        hits.push(r.label);
      }
    }
    for (const r of rules) {
      if (r.re.test(text)) {
        if (r.weak) weakScore += r.score;
        else strongScore += r.score;
        hits.push(r.label);
      }
    }
    const score = strongScore > 0 ? strongScore + Math.min(20, weakScore) : Math.min(15, weakScore);
    return { score: cap100(score), matches: uniq(hits) };
  };

  function textWithinRadius(el, px) {
    try {
      const rect = el.getBoundingClientRect();
      const candidates = [];
      const all = document.querySelectorAll("body *");
      for (const node of all) {
        if (node === el) continue;
        const r = node.getBoundingClientRect();
        const near = Math.abs(r.left - rect.left) < px && Math.abs(r.top - rect.top) < px;
        if (near) {
          const t = (node.innerText || "").trim();
          if (t) candidates.push(t);
        }
      }
      return normalizeText(candidates.join(" ").slice(0, 2000));
    } catch {
      return "";
    }
  }

  Analyzer.detectFakeCAPTCHA = function () {
      const signals = [];
      const bodyText = normalizeText(document.body?.innerText || "").toLowerCase();
      const fullText = normalizeText(document.body?.textContent || "").toLowerCase();

      const hasCaptchaKeywords = /(captcha|i'?m\s+not\s+a\s+robot|not\s+a\s+bot|human\s+verification)/i.test(bodyText);
      const captchaIframes = document.querySelectorAll(
        'iframe[src*="challenges.cloudflare.com"],iframe[src*="captcha.cloudflare.com"],iframe[src*="google.com/recaptcha"],iframe[src*="gstatic.com/recaptcha"],iframe[src*="hcaptcha.com"],iframe[title*="Cloudflare"],iframe[title*="Turnstile"],iframe[title*="hCaptcha"],iframe[title*="reCAPTCHA"]'
      );
      const realCaptchaScript = document.querySelector(
        'script[src*="challenges.cloudflare.com"],script[src*="turnstile"],script[src*="js.hcaptcha.com"],script[src*="hcaptcha.com/1/api.js"],script[src*="google.com/recaptcha"],script[src*="gstatic.com/recaptcha"]'
      );
      const realCaptchaWidget = document.querySelector(
        '.cf-turnstile,.h-captcha,.g-recaptcha,[name="cf-turnstile-response"],[name="h-captcha-response"],[name="g-recaptcha-response"],textarea[name="cf-turnstile-response"],textarea[name="h-captcha-response"],textarea[name="g-recaptcha-response"]'
      );
      const hasRealCaptcha = captchaIframes.length > 0 || !!realCaptchaScript || !!realCaptchaWidget;

      // checkbox-like elements (includes Turnstile internal widget classes)
      if (!hasRealCaptcha) {
        const checkboxes = document.querySelectorAll('input[type="checkbox"], [role="checkbox"], .checkbox, [class*="checkbox"], .cb, .cb-lb input, .cb-i, #human-check, [id*="human"], [id*="verify"]');
        for (const cb of checkboxes) {
          const near = textWithinRadius(cb, 260).toLowerCase();
          if (/(not\s+a\s+robot|not\s+a\s+bot|human|bot\s*check|verify)/i.test(near)) {
            signals.push({ score: 35, label: "Fake CAPTCHA checkbox near robot/verify text" });
            break;
          }
        }
      }

    if (!hasRealCaptcha && hasCaptchaKeywords) {
      signals.push({ score: 30, label: "CAPTCHA language but no real CAPTCHA iframe" });
    }

    // static logos (includes SVG with aria-label)
    const imgs = document.querySelectorAll("img");
    const svgs = document.querySelectorAll("svg");
    for (const img of imgs) {
      const src = (img.getAttribute("src") || "").toLowerCase();
      const alt = (img.getAttribute("alt") || "").toLowerCase();
      if (!hasRealCaptcha && (/cloudflare|turnstile|recaptcha|hcaptcha/.test(src) || /cloudflare|turnstile|recaptcha|hcaptcha/.test(alt))) {
        signals.push({ score: 25, label: "CAPTCHA logo present as static image" });
        break;
      }
    }
    for (const svg of svgs) {
      const ariaLabel = (svg.getAttribute("aria-label") || "").toLowerCase();
      const id = (svg.getAttribute("id") || "").toLowerCase();
      if (/cloudflare|turnstile|recaptcha|hcaptcha/.test(ariaLabel) || /cloudflare|turnstile|recaptcha|hcaptcha/.test(id)) {
        if (!hasRealCaptcha) {
          signals.push({ score: 30, label: "Cloudflare/CAPTCHA SVG logo without real CAPTCHA" });
          break;
        }
      }
    }

      // spoofed Cloudflare class names (original + Turnstile internal widget classes)
      const spoofed = document.querySelector(".cf-turnstile, #cf-turnstile-container, .cf-challenge, #challenge-container, .cb-lb .cb-i, .cb-c .cb-lb, a.cf-link");
      if (spoofed && !hasRealCaptcha) {
        signals.push({ score: 20, label: "Spoofed Cloudflare/Turnstile structure" });
      }

      const hasHiddenVerificationFlow =
        /(verification\s*steps?|check\s+the\s+box|not\s+a\s+robot|robot\s+or\s+human|human\s+verification)/i.test(fullText) &&
        /(win(dows)?\s*(button|key)?\s*\+?\s*r|ctrl\s*\+\s*v|press\s+enter)/i.test(fullText);
      if (hasHiddenVerificationFlow) {
        signals.push({ score: 40, label: "Fake CAPTCHA verification steps (Win+R / Ctrl+V / Enter)" });
      }

      const inlineScripts = document.querySelectorAll("script:not([src])");
      for (const script of inlineScripts) {
        const code = normalizeText(script.textContent || "").toLowerCase();
        if (!code) continue;
        const hasCopyFlow =
          /execcommand\s*\(\s*['"]copy['"]\s*\)|navigator\s*\.\s*clipboard\s*\.\s*writetext|createelement\s*\(\s*['"]textarea['"]\s*\)/i.test(code);
        const hasVerificationFlow =
          /(captcha|robot|human|verify|verification|check\s+the\s+box)/i.test(code);
        if (hasCopyFlow && hasVerificationFlow) {
          signals.push({ score: 35, label: "Inline verification script stages clipboard copy" });
          break;
        }
      }

      // minimal lure-only page
      const len = (document.body?.innerText || "").trim().length;
    if (len < 500 && signals.length > 0) {
      signals.push({ score: 15, label: "Minimal page content (lure-only)" });
    }

    const score = cap100(signals.reduce((a, s) => a + s.score, 0));
    return { score, signals };
  };

  Analyzer.detectFakeErrors = function () {
    const signals = [];
    const text = normalizeText(document.body?.innerText || "").toLowerCase();
    const errRules = [
      { re: /(virus|malware|threat|trojan)\s*(detected|found|alert)/i, score: 30, label: "Malware detected claim" },
      { re: /(your\s+)?(computer|device|system|pc)\s*(is\s+)?(infected|compromised|at\s*risk)/i, score: 30, label: "System infected/at risk claim" },
      { re: /(browser|chrome|firefox|edge)\s*(is\s+)?(outdated|corrupted|not\s+supported)/i, score: 30, label: "Browser outdated/corrupted claim" },
      { re: /(critical|urgent|immediate)\s*(update|action|fix)\s*(required|needed)/i, score: 30, label: "Urgent action required" },
      { re: /windows\s*defender\s*(alert|warning|detected)/i, score: 30, label: "Windows Defender alert impersonation" },
      { re: /(your\s+)?firewall[\s\S]*?(disabled|compromised|turned\s+off)/i, score: 30, label: "Firewall disabled claim" },
      { re: /(download|install)[\s\S]{0,40}?(protection|antivirus|security\s+update)/i, score: 20, label: "Install protection prompt" },
      { re: /required\s*to\s*continue\s*using/i, score: 30, label: "Required to continue using service (coercion)" }
    ];
    let hasStrongScareSignal = false;
    for (const r of errRules) {
      if (!r.re.test(text)) continue;
      if (r.label === "Install protection prompt") {
        if (/(required|needed|continue|protect|browser|system|device|malware|virus|threat)/i.test(text)) {
          signals.push({ score: r.score, label: r.label });
        }
        continue;
      }
      signals.push({ score: r.score, label: r.label });
      hasStrongScareSignal = true;
    }

    // urgency amplifiers
    const amps = [];
    if (hasStrongScareSignal) {
    if (/(warning|alert|danger|critical)!{0,3}/i.test(text)) amps.push({ score: 10, label: "Urgency words" });
    if (/[⚠️🔴❌🛡️🔒]/.test(document.body?.innerText || "")) amps.push({ score: 10, label: "Urgency emojis" });
    if (/(immediately|now|urgent|asap)/i.test(text)) amps.push({ score: 10, label: "Immediate action language" });
    if (/(countdown\s*timer|(\d+:\d+)\s*(remaining|left))/i.test(text)) amps.push({ score: 10, label: "Countdown timer language" });
    }

    // cap amplifiers at 20 total
    let ampScore = 0;
    for (const a of amps) {
      if (ampScore >= 20) break;
      ampScore += a.score;
      signals.push(a);
    }

    const score = cap100(signals.reduce((a, s) => a + s.score, 0));
    return { score, signals };
  };

  // NEW LAYER: Detect fake browser update dialogs (ClickFix variant)
  // Catches pages that impersonate Chrome/Edge/Firefox update prompts and guide users
  // through fake download → install → "run this command to finalize" flows.
  Analyzer.detectFakeBrowserUpdate = function () {
    const signals = [];
    // Use textContent to include display:none / hidden elements (progressive reveal evasion)
    const text = normalizeText(document.body?.textContent || "").toLowerCase();
    const visibleText = normalizeText(document.body?.innerText || "").toLowerCase();

    const updateRules = [
      // Version comparison UI (shows "Current Version" vs "Latest Version")
      { re: /current\s*version[\s\S]{0,80}?latest\s*version/i, score: 35, label: "Version comparison UI (fake update lure)" },
      { re: /your\s*version[\s\S]{0,80}?(latest|newest|new)\s*version/i, score: 35, label: "Your version vs latest (fake update)" },

      // Browser-specific update claims
      { re: /(chrome|edge|firefox|browser)\s*(update|upgrade)\s*(required|needed|available)/i, score: 30, label: "Browser update required/available" },
      { re: /(chrome|edge|firefox)\s*update[\s\S]{0,40}?(critical|security|important)/i, score: 35, label: "Critical browser update claim" },

      // Fake download/install progress simulation
      { re: /downloading\s*(update|security\s*patch|browser\s*component)/i, score: 30, label: "Downloading update simulation" },
      { re: /installing\s*update[\s\S]{0,80}?(verif|extract|finaliz)/i, score: 30, label: "Fake installation progress sequence" },
      { re: /update\s*size[\s\S]{0,20}?\d+(\.\d+)?\s*mb/i, score: 25, label: "Fake download size display" },
      { re: /connecting\s*to\s*update\s*server/i, score: 30, label: "Connecting to update server claim" },
      { re: /verifying\s*(download|update)\s*integrity/i, score: 25, label: "Verifying download integrity claim" },
      { re: /download\s*complete[\s\S]{0,100}?install/i, score: 25, label: "Download complete then install flow" },

      // Finalize update via command execution (the kill shot)
      { re: /finalize\s*update[\s\S]{0,200}?(command|powershell|terminal|run)/i, score: 45, label: "Finalize update via command execution" },
      { re: /complete\s*(the\s*)?update[\s\S]{0,200}?(run|command|powershell|win\s*\+\s*r)/i, score: 45, label: "Complete update via run command" },
      { re: /to\s*complete\s*(the\s*)?(update|installation)[\s\S]{0,200}?(following\s*command|run\s*dialog)/i, score: 45, label: "Complete installation via command" },

      // Update dialog structural patterns
      { re: /update\s*required[\s\S]{0,200}?install\s*update/i, score: 30, label: "Update required with install button context" },
      { re: /critical\s*security\s*update\s*is\s*available/i, score: 35, label: "Critical security update available claim" },

      // Browser detection + version spoofing (page dynamically detects browser)
      { re: /navigator\.useragent[\s\S]{0,300}?(chrome|edg|firefox)/i, score: 25, label: "Browser UA detection (update targeting)" },
    ];

    for (const r of updateRules) {
      if (r.re.test(text)) {
        signals.push({ score: r.score, label: r.label });
      }
    }

    // Structural signal: page has both a version comparison AND a command/powershell reference
    const hasVersionCompare = /version/i.test(text) && /(current|your|installed)[\s\S]{0,60}?version/i.test(text);
    const hasCommandRef = /(powershell|cmd|terminal|run\s*dialog|win\s*\+\s*r)/i.test(text);
    if (hasVersionCompare && hasCommandRef && signals.length > 0) {
      signals.push({ score: 15, label: "Version compare + command reference combo" });
    }

    // Structural signal: hidden content contains more dangerous instructions than visible
    // (progressive reveal evasion — dangerous steps hidden until user clicks through)
    if (text.length > visibleText.length + 100) {
      const hiddenOnly = text.replace(visibleText, "");
      if (/(powershell|iex|iwr|invoke-|win\s*\+\s*r|run\s*dialog)/i.test(hiddenOnly)) {
        signals.push({ score: 30, label: "Hidden content contains command execution instructions" });
      }
    }

    const score = cap100(signals.reduce((a, s) => a + s.score, 0));
    return { score, signals };
  };

  Analyzer.detectInstructionImages = function () {
    const signals = [];
    const imgs = document.querySelectorAll("img, svg, canvas");
    let hasAltShortcutHit = false;
    let hasSrcShortcutHit = false;
    let hasDiagramHit = false;
    for (const el of imgs) {
      const alt = ((el.getAttribute?.("alt") || "") + " " + (el.getAttribute?.("title") || "") + " " + (el.getAttribute?.("aria-label") || "")).toLowerCase();
      const src = (el.getAttribute?.("src") || "").toLowerCase();
      const near = textWithinRadius(el, 150).toLowerCase();

      if (!hasAltShortcutHit && /(win\+r|windows\+r|ctrl\+v|run\s+dialog|powershell|cmd|press\s+(enter|ok)|key.*press)/i.test(alt)) {
        signals.push({ score: 30, label: "Image alt/title references keyboard shortcuts" });
        hasAltShortcutHit = true;
      }
      if (!hasSrcShortcutHit && /(win(?:dows)?[-_+ ]?r|ctrl[-_+ ]?v|winkey|run[-_ ]?dialog|powershell|cmd(?:\.exe)?|press[-_ ]?(enter|ok))/i.test(src)) {
        signals.push({ score: 25, label: "Image filename/src suggests shortcuts" });
        hasSrcShortcutHit = true;
      }
      if (!hasDiagramHit && /(press\s+(win|windows)|ctrl\s*\+\s*v|run\s+dialog|powershell)/i.test(near)) {
        const w = el.width || el.getBoundingClientRect?.().width || 0;
        const h = el.height || el.getBoundingClientRect?.().height || 0;
        if (w >= 100 && w <= 600 && h >= 50 && h <= 300) {
          signals.push({ score: 20, label: "Diagram-sized image near lure text" });
          hasDiagramHit = true;
        } else if ((src || "").startsWith("data:image")) {
          signals.push({ score: 15, label: "Inline image near lure text" });
          hasDiagramHit = true;
        }
      }
    }

    const score = cap100(signals.reduce((a, s) => a + s.score, 0));
    return { score, signals };
  };

  // NEW LAYER: Detect obfuscated remote script loaders (ClickFix evasion via dynamic C2)
  // Catches patterns like heartofthepiedmont.com where the payload is fetched from a
  // remote C2 server via heavily obfuscated JS, hiding the actual ClickFix content.
  Analyzer.detectObfuscatedLoaders = function () {
    const signals = [];
    const scripts = document.querySelectorAll("script:not([src])");
    const allInlineJS = [];

    for (const s of scripts) {
      const code = (s.textContent || "").trim();
      if (code.length < 30) continue;
      allInlineJS.push(code);
    }

    const blob = allInlineJS.join("\n");
    if (!blob) return { score: 0, signals };

    const externalHosts = collectScriptHosts(blob);
    const suspiciousHosts = externalHosts.filter(host => !isSafeLoaderHost(host));
    const hasSuspiciousRemoteHost = suspiciousHosts.length > 0;
    let hasSuspiciousAtob = false;
    let hasHeavyObfuscation = false;

    // --- Signal 1: atob() call (Base64-encoded string, often hiding C2 URLs) ---
    const atobMatches = Array.from(blob.matchAll(/atob\s*\(\s*['"]([A-Za-z0-9+/=]{40,})['"]\s*\)/g));
    for (const m of atobMatches) {
      try {
        const decoded = atob(m[1]);
        if (!decodedPayloadLooksSuspicious(decoded)) continue;
        hasSuspiciousAtob = true;
        signals.push({ score: 35, label: "atob() with long Base64 string (likely hidden URL)" });
        if (/^https?:\/\//i.test(decoded)) {
          signals.push({ score: 30, label: "atob() decodes to URL: " + decoded.slice(0, 60) });
        }
        break;
      } catch {}
    }

    // --- Signal 2: Heavy JS obfuscation (_0x prefix pattern from obfuscator.io) ---
    const oxMatches = blob.match(/_0x[a-f0-9]{4,}/g);
    if (oxMatches && oxMatches.length >= 5) {
      hasHeavyObfuscation = true;
      signals.push({ score: 30, label: "Heavy JS obfuscation (_0x pattern, " + oxMatches.length + " instances)" });
    }

    // --- Signal 3: Dynamic script element injection with src assignment ---
    // createElement('script') + .src = ... pattern (both direct and bracket notation)
    const dynamicScript = /createElement\s*\(\s*['"]script['"]\s*\)[\s\S]{0,500}?\.\s*src\s*=/;
    const dynamicScriptBracket = /\[\s*['"]?createElement['"]?\s*\]\s*\(\s*['"]?script['"]?\s*\)/;
    // Also catch when 'script' is passed as a variable argument to createElement
    const createElWithScriptArg = /createElement\s*\([^)]*\)[\s\S]{0,2000}?getElementsByTagName\s*\(\s*[^)]*\)\s*\[\s*0/;
    if ((dynamicScript.test(blob) || dynamicScriptBracket.test(blob) || createElWithScriptArg.test(blob)) &&
        (hasSuspiciousRemoteHost || hasSuspiciousAtob || hasHeavyObfuscation)) {
      signals.push({ score: 25, label: "Dynamic script injection (createElement + src)" });
    }

    // --- Signal 4: CSS body-hide trick (opacity:0 or display:none on body, with animation reveal) ---
    // Check both inline styles and injected <style> elements
    const styleEls = document.querySelectorAll("style");
    let bodyHide = false;
    for (const st of styleEls) {
      const css = (st.textContent || "").toLowerCase();
      if (/body\s*\{[^}]*opacity\s*:\s*0/.test(css) || /body\s*\{[^}]*display\s*:\s*none/.test(css) || /body\s*\{[^}]*visibility\s*:\s*hidden/.test(css)) {
        bodyHide = true;
        break;
      }
    }
    // Also check if the obfuscated JS itself contains CSS body-hide strings
    if (!bodyHide && /body\s*\{\s*opacity\s*:\s*0/.test(blob)) bodyHide = true;
    if (!bodyHide && /opacity:\s*0[\s\S]{0,200}?animation[\s\S]{0,200}?fadeIn/.test(blob)) bodyHide = true;

    if (bodyHide && (hasSuspiciousRemoteHost || hasSuspiciousAtob || hasHeavyObfuscation)) {
      signals.push({ score: 25, label: "CSS body-hide trick (opacity:0/hidden with delayed reveal)" });
    }

    // --- Signal 5: sessionStorage gating (run-once evasion) ---
    if (/sessionStorage\s*[\[.]\s*['"]?\w*getItem/.test(blob) || /sessionStorage\.getItem/.test(blob)) {
      if (hasSuspiciousRemoteHost || hasSuspiciousAtob || hasHeavyObfuscation) {
        signals.push({ score: 15, label: "sessionStorage gating (run-once evasion)" });
      }
    }

    // --- Signal 6: Data exfil pattern (JSON.stringify + encodeURIComponent sent to remote) ---
    if (/encodeURIComponent\s*\(\s*JSON\.stringify/.test(blob)) {
      signals.push({ score: 20, label: "Data exfil pattern (JSON.stringify + encodeURIComponent)" });
    }

    // --- Signal 7: String array rotation pattern (common obfuscator technique) ---
    // Array of strings being rotated with push/shift in a while loop
    if (/while\s*\(\s*!!\s*\[\s*\]\s*\)[\s\S]{0,500}?push[\s\S]{0,200}?shift/.test(blob)) {
      signals.push({ score: 20, label: "String array rotation obfuscation (push/shift loop)" });
    }

    // --- Signal 8: parseInt chain used for array shuffling (obfuscator.io signature) ---
    const parseIntChain = blob.match(/parseInt\s*\(\s*_0x/g);
    if (parseIntChain && parseIntChain.length >= 3) {
      signals.push({ score: 20, label: "parseInt chain obfuscation (" + parseIntChain.length + " calls)" });
    }

    // --- Signal 9: Combination amplifier — if we see BOTH dynamic script injection AND atob/obfuscation,
    // this is almost certainly a malicious loader ---
    const hasLoader = signals.some(s => s.label.includes("Dynamic script injection"));
    const hasObfuscation = signals.some(s => s.label.includes("obfuscation") || s.label.includes("atob"));
    if (hasLoader && hasObfuscation && hasSuspiciousRemoteHost) {
      signals.push({ score: 15, label: "Obfuscated remote loader combo (script injection + obfuscation)" });
    }

    // --- Signal 10: Non-obfuscated ClickFix script patterns ---
    // Catches clean (non-obfuscated) JS like coinmarket.js that combines clipboard write
    // functions with fake update/download simulation logic. These scripts are readable
    // and don't trigger obfuscation rules, but the functional combo is a dead giveaway.
    const hasClipboardWrite = /navigator\.clipboard\.writeText|document\.execCommand\s*\(\s*['"]copy['"]\s*\)/i.test(blob);
    const hasUpdateSim = /(download|progress|install)[a-z]*\s*(message|interval|step|bar|text)/i.test(blob) &&
                         /(connecting|downloading|verifying|finaliz|extracting)/i.test(blob);
    const hasDetectBrowser = /navigator\.userAgent[\s\S]{0,300}?(chrome|edg|firefox)/i.test(blob);
    if (hasClipboardWrite && hasUpdateSim) {
      signals.push({ score: 40, label: "Clipboard write + update simulation script combo" });
      if (hasDetectBrowser) {
        signals.push({ score: 15, label: "Browser UA sniffing in update script" });
      }
    }

    const score = cap100(signals.reduce((a, s) => a + s.score, 0));
    return { score, signals };
  };

  // NEW LAYER: Detect command payloads embedded in DOM elements (code/pre/textarea/input)
  // Catches ClickFix variants that embed the malicious command directly in the page HTML
  // (e.g. <code id="psCommand">powershell -command "iwr ... | iex"</code>) with a copy button.
  // Unlike clipboard hooking which is reactive, this detects the payload BEFORE the user copies.
  Analyzer.detectEmbeddedPayloads = function () {
    const signals = [];
    const candidates = document.querySelectorAll("code, pre, textarea, input[type='text'], input[type='hidden'], [data-clipboard-text], [data-copy]");
    let foundPayload = false;

    for (const el of candidates) {
      const val = normalizeText(
        (el.value || el.textContent || el.getAttribute?.("data-clipboard-text") || "").trim()
      );
      if (val.length < 8 || val.length > 4000) continue;

      // Check for command patterns (subset of detector.js CRITICAL_PATTERNS adapted for DOM context)
      const cmdPatterns = [
        { re: /powershell[\s\S]*?(\biex\b|invoke-expression|downloadfile|invoke-webrequest|\biwr\b|-enc\b|-encodedcommand)/i, label: "PowerShell execution/download command" },
        { re: /mshta\s+https?:\/\//i, label: "mshta remote HTA command" },
        { re: /cmd[\s\S]*?(\/c|\/k)[\s\S]*?(powershell|mshta|curl|bitsadmin|certutil|wscript)/i, label: "cmd wrapping execution tool" },
        { re: /curl[\s\S]*?(-o|--output)[\s\S]*?\.(bat|exe|ps1|cmd|vbs)/i, label: "curl downloading executable" },
        { re: /\biex\b[\s\S]*?(irm|iwr|invoke-|net\.webclient)/i, label: "iex with download method" },
        { re: /\biwr\b[\s\S]*?\|\s*\biex\b/i, label: "iwr piped to iex" },
        { re: /bitsadmin[\s\S]*?\/transfer[\s\S]*?https?:\/\//i, label: "bitsadmin remote download" },
        { re: /certutil[\s\S]*?-urlcache[\s\S]*?https?:\/\//i, label: "certutil URL download" },
        { re: /nslookup[\s\S]*?\|[\s\S]*?(findstr|for\s+\/f)/i, label: "nslookup DNS staging" },
        { re: /conhost[\s\S]*?(--headless|cmd)/i, label: "conhost LOLBin" },
        { re: /msiexec[\s\S]*?\/i\s+https?:\/\//i, label: "msiexec remote MSI install" },
        { re: /regsvr32[\s\S]*?(scrobj|https?:\/\/)/i, label: "regsvr32 proxy execution" },
      ];

      for (const p of cmdPatterns) {
        if (p.re.test(val)) {
          signals.push({ score: 45, label: "Embedded payload in DOM: " + p.label });
          foundPayload = true;
          break; // one match per element is enough
        }
      }
    }

    // Amplifier: if we found an embedded payload AND there's a copy button nearby
    if (foundPayload) {
      const copyBtns = document.querySelectorAll("button, [role='button'], a.btn, [onclick*='copy'], [onclick*='clipboard']");
      for (const btn of copyBtns) {
        const btnText = ((btn.textContent || "") + " " + (btn.getAttribute?.("class") || "") + " " + (btn.getAttribute?.("onclick") || "")).toLowerCase();
        if (/(copy|clipboard)/i.test(btnText)) {
          signals.push({ score: 20, label: "Copy button adjacent to embedded command payload" });
          break;
        }
      }
    }

    const score = cap100(signals.reduce((a, s) => a + s.score, 0));
    return { score, signals };
  };

  // NEW LAYER: Detect AiTM phishing kits and reverse-proxied login relays
  // Conservative by design: only scores on non-official hosts and requires
  // combinations like branded credential UI, MFA relay collection, device-code
  // polling scripts, or fake reauthentication prompts.
  Analyzer.detectAiTMPhish = function () {
    const host = normalizeHostName(location.hostname || "");
    if (!host || (isKnownOfficialIdpHost(host) && !isAiTMAbuseProneOfficialHost(host))) {
      return { score: 0, signals: [] };
    }

    const signals = [];
    const titleText = normalizeText(document.title || "").toLowerCase();
    const visibleText = normalizeText(document.body?.innerText || "").toLowerCase();
    const fullText = normalizeText(document.body?.textContent || "").toLowerCase();
    const textBlob = (titleText + " " + fullText).slice(0, 60000);
    const inlineScriptBlob = Array.from(document.querySelectorAll("script:not([src])"))
      .map((script) => script.textContent || "")
      .join("\n")
      .slice(0, 150000);
    const refHosts = collectAiTMReferenceHosts();
    const redirectTargets = collectAiTMRedirectTargets();
    const fieldInfo = analyzeAiTMFields();
    const isGoogleSites = host === "sites.google.com";
    const isServerlessHost = isSuspiciousServerlessHost(host);
    const brandedServerlessBrand = isServerlessHost ? findAiTMBrandInHost(host) : null;
    const imageOnlyAnchorCount = Array.from(document.querySelectorAll("a[href]")).filter((anchor) =>
      !!anchor.querySelector("img") && normalizeText(anchor.textContent || "").trim().length < 40
    ).length;

    const brandStats = AITM_BRANDS.map((brand) => {
      const textHits = countRuleHits(textBlob, brand.aliasRules);
      const uiHits = countRuleHits(textBlob, brand.uiRules);
      const reauthHits = countRuleHits(textBlob, brand.reauthRules);
      const otpHits = countRuleHits(textBlob, brand.otpRules);
      const assetHits = refHosts.filter((refHost) => hostMatchesSuffix(refHost, brand.assetHosts)).length;
      return {
        ...brand,
        textHits,
        uiHits,
        reauthHits,
        otpHits,
        assetHits,
        isOfficialHost: hostMatchesSuffix(host, brand.officialHosts)
      };
    }).sort((a, b) => (b.textHits + b.uiHits + b.assetHits + b.reauthHits + b.otpHits) - (a.textHits + a.uiHits + a.assetHits + a.reauthHits + a.otpHits));

    const strongestBrand = brandStats[0];
    const hasStrongBrandContext = strongestBrand && strongestBrand.textHits > 0 && (strongestBrand.uiHits > 0 || strongestBrand.assetHits > 0 || strongestBrand.reauthHits > 0 || strongestBrand.otpHits > 0);

    const hasCredentialRelaySurface = fieldInfo.hasPassword && (fieldInfo.hasUsername || hasStrongBrandContext);
    const hasMfaRelaySurface = fieldInfo.hasOtp && (fieldInfo.hasPassword || hasStrongBrandContext);
    const hasReauthLanguage = /\b(session\s+(?:has\s+)?expired|session\s+timed\s+out|sign\s+in\s+again|reauthenticate|re-authenticate|verify\s+your\s+(?:identity|account)|confirm\s+it'?s\s+you)\b/i.test(textBlob);
    const suspiciousRedirectTargets = redirectTargets.filter(({ targetHost }) =>
      targetHost && !isKnownOfficialIdpHost(targetHost) && !isSafeLoaderHost(targetHost)
    );
    const serverlessRedirectTargets = suspiciousRedirectTargets.filter(({ targetHost }) => isSuspiciousServerlessHost(targetHost));
    const brandedRedirectTargets = serverlessRedirectTargets.filter(({ targetHost }) => !!findAiTMBrandInHost(targetHost));

    if (fieldInfo.hasPassword && fieldInfo.hasOtp) {
      signals.push({ score: 40, label: "Credential + OTP collection on non-official host" });
    }

    if (isGoogleSites && serverlessRedirectTargets.length > 0) {
      signals.push({ score: 35, label: "Google Sites redirect laundering to serverless host" });
    }
    if (isGoogleSites && brandedRedirectTargets.length > 0) {
      signals.push({ score: 25, label: "Google Sites lure points to branded impersonation host" });
    }
    if (isGoogleSites && imageOnlyAnchorCount >= 1 && brandedRedirectTargets.length > 0) {
      signals.push({ score: 20, label: "Image-only click lure on Google Sites" });
    }

    if (brandedServerlessBrand) {
      signals.push({ score: 35, label: brandedServerlessBrand.brand + " impersonation on serverless host" });
    }

    if (hasStrongBrandContext && strongestBrand.brand !== "Okta" && !strongestBrand.isOfficialHost && hasCredentialRelaySurface && (strongestBrand.uiHits >= 2 || strongestBrand.assetHits >= 2)) {
      signals.push({ score: 45, label: strongestBrand.brand + " login relay UI on non-official host" });
    }

    if (hasStrongBrandContext && strongestBrand.brand !== "Okta" && !strongestBrand.isOfficialHost && strongestBrand.assetHits >= 2 && (hasCredentialRelaySurface || hasMfaRelaySurface)) {
      signals.push({ score: 35, label: "Official " + strongestBrand.brand + " auth assets referenced from non-official credential flow" });
    }

    if (hasStrongBrandContext && hasReauthLanguage && (hasCredentialRelaySurface || hasMfaRelaySurface)) {
      signals.push({ score: 30, label: "Branded reauthentication / session-expired prompt on non-official host" });
    }

    if (hasStrongBrandContext && hasMfaRelaySurface && (strongestBrand.otpHits > 0 || strongestBrand.reauthHits > 0)) {
      signals.push({ score: 30, label: "Suspicious MFA relay / OTP collection flow" });
    }

    const deviceCodeUiRules = [
      /verification\s+code/i,
      /copy\s+code/i,
      /return\s+to\s+this\s+tab/i,
      /open\s+the\s+sign[\s-]?in\s+window/i,
      /authenticate\s+with\s+your\s+(?:microsoft|google)\s+account/i,
      /secure(?:d)?\s+with\s+(?:microsoft|google)\s+authentication/i,
      /document\s+access\s+granted|access\s+granted\.\s+you\s+may\s+close\s+this\s+window/i
    ];
    const deviceCodeUiHits = countRuleHits(textBlob, deviceCodeUiRules);
    const hasDeviceCodeRelayScript =
      /(login\.microsoftonline\.com\/common\/oauth2\/deviceauth|www\.google\.com\/device)/i.test(inlineScriptBlob) &&
      /(\/api\/google\/status\/|\/api\/status\/|status\s*===?\s*['"]captured['"]|verification_uri_complete|cookie_lure_url|buildPollScript|buildCodeBlock|window\.top\.location\.href)/i.test(inlineScriptBlob);
    const hasEncryptedBootstrap =
      /crypto\.subtle\.decrypt\s*\(/i.test(inlineScriptBlob) &&
      /AES-GCM/i.test(inlineScriptBlob) &&
      /(document\.(?:open|write|close)|new\s+TextDecoder\s*\()/i.test(inlineScriptBlob);
    const hasLargeEncryptedBlob = /["'][A-Za-z0-9+/=]{1000,}["']/.test(inlineScriptBlob);

    if (deviceCodeUiHits >= 3) {
      signals.push({ score: 40, label: "Device-code phishing UI on non-official host" });
    }
    if (hasDeviceCodeRelayScript) {
      signals.push({ score: 45, label: "Device-code relay polling kit inline script" });
    }
    if (deviceCodeUiHits >= 2 && hasDeviceCodeRelayScript) {
      signals.push({ score: 20, label: "Device-code phishing kit combo" });
    }

    const proxiedLoginAssets =
      /(aadcdn\.msauth\.net|aadcdn\.msftauth\.net|login\.microsoftonline\.com|accounts\.google\.com|ssl\.gstatic\.com|oktacdn\.com)/i.test(inlineScriptBlob);
    if (proxiedLoginAssets && hasStrongBrandContext && (hasCredentialRelaySurface || hasMfaRelaySurface)) {
      signals.push({ score: 30, label: "Proxied IdP login assets embedded on attacker-controlled host" });
    }
    if (hasEncryptedBootstrap) {
      signals.push({ score: 45, label: "Encrypted AES-GCM payload bootstrap with document.write()" });
    }
    if (hasEncryptedBootstrap && hasLargeEncryptedBlob) {
      signals.push({ score: 25, label: "Large inline encrypted blob decrypted at runtime" });
    }
    if (hasEncryptedBootstrap && (isServerlessHost || brandedServerlessBrand)) {
      signals.push({ score: 20, label: "Encrypted phishing loader hosted on disposable serverless domain" });
    }
    if (brandedServerlessBrand && (hasDeviceCodeRelayScript || proxiedLoginAssets || hasEncryptedBootstrap)) {
      signals.push({ score: 20, label: "Serverless branded host + login relay indicators" });
    }

    const strongSignalCount = signals.filter((signal) => signal.score >= 30).length;
    if (strongSignalCount >= 2) {
      signals.push({ score: 15, label: "Layered AiTM indicators confirmed" });
    }

    const score = cap100(signals.reduce((sum, signal) => sum + signal.score, 0));
    return { score, signals };
  };

  Analyzer.calculatePageThreat = function (layers) {
    const lure = cap100(layers.lure?.score || 0);
    const captcha = cap100(layers.captcha?.score || 0);
    const fakeErr = cap100(layers.fakeErr?.score || 0);
    const img = cap100(layers.img?.score || 0);
    const loader = cap100(layers.obfLoader?.score || 0);
    const fakeUpdate = cap100(layers.fakeUpdate?.score || 0);
    const embedded = cap100(layers.embeddedPayload?.score || 0);

    const base = Math.max(lure, captcha, fakeErr, loader, fakeUpdate, embedded, (img * 0.5));
    const bonus = Math.min(20, img * 0.3);
    // If loader is high and any other signal is present, amplify
    const loaderBonus = (loader >= 40 && (lure > 0 || captcha > 0 || fakeErr > 0 || fakeUpdate > 0)) ? Math.min(15, loader * 0.2) : 0;
    // If fake update layer and lure layer both fire, amplify (multi-step attack confirmation)
    const updateLureBonus = (fakeUpdate >= 30 && lure >= 25) ? Math.min(15, fakeUpdate * 0.2) : 0;
    // If embedded payload found alongside update or lure signals, amplify (command + social engineering)
    const embeddedComboBonus = (embedded >= 40 && (fakeUpdate >= 30 || lure >= 25 || fakeErr >= 25)) ? Math.min(15, embedded * 0.2) : 0;
    const pageThreat = cap100(base + bonus + loaderBonus + updateLureBonus + embeddedComboBonus);

    let adjustedThreshold = 60;
    if (pageThreat >= 60) adjustedThreshold = 25;
    else if (pageThreat >= 30) adjustedThreshold = 40;

    const allSignals = [];
    if (layers.lure?.matches?.length) allSignals.push(...layers.lure.matches.map(m => ({ label: m, score: null, layer: "lure" })));
    if (layers.captcha?.signals?.length) allSignals.push(...layers.captcha.signals.map(s => ({ ...s, layer: "captcha" })));
    if (layers.fakeErr?.signals?.length) allSignals.push(...layers.fakeErr.signals.map(s => ({ ...s, layer: "fakeErr" })));
    if (layers.img?.signals?.length) allSignals.push(...layers.img.signals.map(s => ({ ...s, layer: "image" })));
    if (layers.fakeUpdate?.signals?.length) allSignals.push(...layers.fakeUpdate.signals.map(s => ({ ...s, layer: "fakeUpdate" })));
    if (layers.embeddedPayload?.signals?.length) allSignals.push(...layers.embeddedPayload.signals.map(s => ({ ...s, layer: "embeddedPayload" })));
    if (layers.obfLoader?.signals?.length) allSignals.push(...layers.obfLoader.signals.map(s => ({ ...s, layer: "obfLoader" })));

    return { pageThreat, adjustedThreshold, signals: allSignals };
  };

  // ===================================================================
  // ADDITIONS (v1.0.8 — new multi-stage C2 loader detection)
  // Everything below is NEW — nothing above was modified.
  // ===================================================================

  // --- detectMultiStageLoader (catches 68gamewin-style multi-stage C2 attacks) ---
  Analyzer.detectMultiStageLoader = function () {
    const signals = [];

    const dataScripts = document.querySelectorAll('script[src^="data:text/javascript"], script[src^="data:application/javascript"]');
    for (const s of dataScripts) {
      const src = s.getAttribute("src") || "";
      const b64Match = src.match(/;base64,([A-Za-z0-9+/=]{20,})/);
      if (b64Match) {
        signals.push({ score: 40, label: "data:text/javascript;base64 script src (bootstrap loader)" });
        try {
          const decoded = atob(b64Match[1]);
          if (/atob\s*\([^)]*atob/i.test(decoded)) {
            signals.push({ score: 30, label: "Double-base64 encoding in data: URI (nested atob)" });
          }
          if (/\.map\s*\(\s*\w+\s*=>\s*atob/i.test(decoded)) {
            signals.push({ score: 25, label: "Base64 URL array with map decode (C2 URL list)" });
          }
          if (/\.onerror\s*=/.test(decoded) && /createElement\s*\(\s*['"]script/.test(decoded)) {
            signals.push({ score: 25, label: "Script onerror fallback chain (C2 resilience)" });
          }
          if (/window\s*\[\s*['"]us['"]\s*\]\s*=/.test(decoded)) {
            signals.push({ score: 20, label: "window.us C2 URL staging variable" });
          }
        } catch {}
      }
    }

    const inlineScripts = document.querySelectorAll("script:not([src])");
    let hasDocWrite = false;
    let hasScriptTextContentInjection = false;
    let junkCommentRatio = false;

    for (const s of inlineScripts) {
      const code = (s.textContent || "").trim();
      if (code.length < 20) continue;

      if (/\bdoc(ument)?\s*\.\s*open\s*\([^)]*\)\s*[;\s]*\w*\s*\.\s*write\b/.test(code) ||
          /\bdocument\s*\.\s*write\s*\(\s*\w+\s*\.\s*response/i.test(code) ||
          /\.open\s*\(\s*['"]text\/html['"]\s*\)[;\s]*\w+\.write\b/.test(code)) {
        hasDocWrite = true;
      }

      if (/createElement\s*\(\s*['"]script['"]\s*\)[^}]*\.textContent\s*=\s*\w+\.response/i.test(code)) {
        hasScriptTextContentInjection = true;
      }

      const commentLen = (code.match(/\/\/[^\n]*/g) || []).join("").length +
                         (code.match(/\/\*[\s\S]*?\*\//g) || []).join("").length;
      if (code.length > 5000 && commentLen / code.length > 0.75) {
        junkCommentRatio = true;
      }
    }

    if (hasDocWrite) {
      signals.push({ score: 30, label: "document.write() page replacement (DOM nuke pattern)" });
    }
    if (hasScriptTextContentInjection) {
      signals.push({ score: 35, label: "XHR response injected as script.textContent (code injection)" });
    }
    if (junkCommentRatio && (hasDocWrite || hasScriptTextContentInjection)) {
      signals.push({ score: 20, label: "Junk comment flooding (>75% comments, code burial)" });
    }

    for (const s of inlineScripts) {
      const code = (s.textContent || "").trim();
      if (/XMLHttpRequest|fetch\s*\(/.test(code) && /\.write\s*\(/.test(code) && /\.response/.test(code)) {
        signals.push({ score: 35, label: "Remote XHR + document.write page replacement combo" });
        break;
      }
    }

    const prefetches = document.querySelectorAll('link[rel="dns-prefetch"]');
    let suspiciousPrefetch = 0;
    for (const p of prefetches) {
      const href = (p.getAttribute("href") || "").replace(/^\/\//, "").toLowerCase();
      const host = extractHostname(href);
      if (!host || isSafeLoaderHost(host)) continue;
      const label = host.split(".")[0] || "";
      const vowelRatio = label.length ? ((label.match(/[aeiou]/g) || []).length / label.length) : 1;
      if ((label.length >= 12 && /^[a-z0-9-]+$/.test(label) && vowelRatio < 0.25) ||
          /[bcdfghjklmnpqrstvwxz]{6,}/.test(label)) {
        suspiciousPrefetch++;
      }
    }
    if (suspiciousPrefetch >= 1) {
      signals.push({ score: 20, label: "DNS-prefetch to suspicious random domain(s) (" + suspiciousPrefetch + ")" });
    }

    if (document.querySelector('.sync_event_click')) {
      signals.push({ score: 30, label: "sync_event_click class (known C2 click tracking)" });
    }

    for (const s of inlineScripts) {
      const code = (s.textContent || "").trim();
      if ((hasDocWrite || hasScriptTextContentInjection || suspiciousPrefetch >= 1 || document.querySelector('.sync_event_click')) &&
          (/sessionStorage[^}]*__sync_load/i.test(code) || /sessionStorage[^}]*load_num/i.test(code))) {
        signals.push({ score: 20, label: "sessionStorage counter-based run-once gating" });
        break;
      }
    }

    const hasDataUri = signals.some(s => s.label.includes("data:text/javascript"));
    const hasDocNuke = signals.some(s => s.label.includes("document.write") || s.label.includes("page replacement"));
    const hasCodeInject = signals.some(s => s.label.includes("textContent") || s.label.includes("code injection"));
    if ((hasDataUri && hasDocNuke) || (hasDataUri && hasCodeInject) || (hasDocNuke && hasCodeInject)) {
      signals.push({ score: 15, label: "Multi-stage loader combo (data URI + DOM nuke/code injection)" });
    }

    const score = cap100(signals.reduce((a, s) => a + s.score, 0));
    return { score, signals };
  };

  // --- Enhanced calculatePageThreat wrapper ---
  // Wraps the original to incorporate multiStageLoader without modifying existing logic
  const _origCalcPageThreat = Analyzer.calculatePageThreat;
  Analyzer.calculatePageThreat = function (layers) {
    const base = _origCalcPageThreat.call(this, layers);

    const multiStage = cap100(layers.multiStageLoader?.score || 0);

    let newThreat = Math.max(base.pageThreat, multiStage);

    const lure = cap100(layers.lure?.score || 0);
    const fakeUpdate = cap100(layers.fakeUpdate?.score || 0);
    const loader = cap100(layers.obfLoader?.score || 0);

    const multiStageBonus = (multiStage >= 30 && loader >= 25) ? Math.min(15, multiStage * 0.2) : 0;
    const multiStageLureBonus = (multiStage >= 30 && (lure > 0 || fakeUpdate > 0)) ? Math.min(20, multiStage * 0.3) : 0;

    const pageThreat = Math.max(base.pageThreat, cap100(newThreat + multiStageBonus + multiStageLureBonus));

    let adjustedThreshold = base.adjustedThreshold;
    if (pageThreat >= 60) adjustedThreshold = 25;
    else if (pageThreat >= 30) adjustedThreshold = Math.min(adjustedThreshold, 40);

    const allSignals = [...base.signals];
    if (layers.multiStageLoader?.signals?.length) allSignals.push(...layers.multiStageLoader.signals.map(s => ({ ...s, layer: "multiStageLoader" })));

    return { pageThreat, adjustedThreshold, signals: allSignals };
  };

  // ===================================================================
  // ADDITIONS (v1.2.5 — srcdoc iframe, base64 decode, & CF impersonation evasion)
  // Catches 4 evading domains: dflows.net, portal-idos.network,
  // lubazra.com, primetimehost.me. Everything below is NEW.
  // ===================================================================

  // --- Detect ClickFix lure hidden inside iframe[srcdoc] ---
  // Evasion: dflows.net, portal-idos.network stuff the entire ClickFix lure
  // (fake reCAPTCHA + Win+R/cmd/Ctrl+V modal + powershell payload) inside
  // an <iframe srcdoc="..."> that covers the viewport. page-analyzer scans
  // document.body text but never reaches inside the srcdoc attribute.
  Analyzer.scanSrcdocIframes = function () {
    const signals = [];
    const iframes = document.querySelectorAll("iframe[srcdoc]");
    for (const iframe of iframes) {
      const srcdoc = iframe.getAttribute("srcdoc") || "";
      if (srcdoc.length < 50) continue;

      // Structural: full-page iframe overlay
      const style = (iframe.getAttribute("style") || "").toLowerCase();
      const isFullPage = /position\s*:\s*fixed/i.test(style) &&
                         /width\s*:\s*100%/i.test(style) &&
                         /height\s*:\s*100%/i.test(style);
      if (isFullPage) {
        signals.push({ score: 25, label: "Full-page iframe with srcdoc overlay" });
      }

      // Decode HTML entities in srcdoc
      let decoded = srcdoc;
      try {
        const tmp = document.createElement("textarea");
        tmp.innerHTML = srcdoc;
        decoded = tmp.value;
      } catch {}

      // Strip tags to get text
      const textOnly = normalizeText(decoded.replace(/<[^>]*>/g, " ")).toLowerCase();

      // Lure phrases inside srcdoc
      const rules = [
        { re: /press[\s\S]{0,30}?win(dows)?\s*(key)?[\s\S]{0,20}?\+\s*r/i, score: 40, label: "Win+R instruction in srcdoc iframe" },
        { re: /ctrl\s*\+\s*v/i, score: 20, label: "Ctrl+V instruction in srcdoc iframe" },
        { re: /(type|open)\s+(cmd|powershell)/i, score: 35, label: "cmd/powershell instruction in srcdoc iframe" },
        { re: /i['']?m\s+not\s+a\s+robot/i, score: 15, label: "Fake CAPTCHA text in srcdoc iframe" },
        { re: /complete\s+these\s+verification/i, score: 30, label: "Complete verification steps in srcdoc iframe" },
        { re: /verification\s*(step|id|code)/i, score: 20, label: "Fake verification in srcdoc iframe" },
        { re: /in\s+the\s+cmd\s+window/i, score: 35, label: "cmd window instruction in srcdoc iframe" },
      ];
      for (const r of rules) {
        if (r.re.test(textOnly)) {
          signals.push({ score: r.score, label: r.label });
        }
      }

      // Clipboard write inside srcdoc
      if (/execCommand\s*\(\s*['"]copy['"]\s*\)/i.test(decoded) ||
          /navigator\s*\.\s*clipboard\s*\.\s*writeText/i.test(decoded)) {
        signals.push({ score: 30, label: "Clipboard write inside srcdoc iframe" });
      }

      // PowerShell base64 payload in srcdoc scripts
      if (/powershell[\s\S]{0,80}?-e\s+[A-Za-z0-9+\/=]{20,}/i.test(decoded)) {
        signals.push({ score: 45, label: "PowerShell base64 payload in srcdoc iframe" });
      }
    }

    const score = cap100(signals.reduce((a, s) => a + s.score, 0));
    return { score, signals };
  };

  // --- Detect base64-encoded ClickFix payloads in inline scripts ---
  // Evasion: lubazra.com, primetimehost.me use
  //   document.write(decodeURIComponent(escape(atob('...'))))
  // to decode the entire ClickFix page at runtime. Zero lure text in initial DOM.
  Analyzer.scanBase64ScriptPayloads = function () {
    const signals = [];
    const scripts = document.querySelectorAll("script:not([src])");

    for (const script of scripts) {
      const src = script.textContent || "";
      if (src.length < 100) continue;

      // document.write + atob pattern (triple-encoding)
      const hasDocWriteAtob = /document\s*\.\s*write\s*\(\s*(decodeURIComponent\s*\(\s*)?(escape\s*\(\s*)?atob\s*\(/i.test(src);
      if (hasDocWriteAtob) {
        signals.push({ score: 30, label: "document.write(atob()) pattern detected" });

        // Try to decode and scan
        const b64Match = src.match(/atob\s*\(\s*['"]([A-Za-z0-9+\/=]{100,})['"]\s*\)/);
        if (b64Match) {
          try {
            let decoded = atob(b64Match[1]);
            try { decoded = decodeURIComponent(escape(decoded)); } catch {}
            const decodedLower = (decoded || "").toLowerCase();

            const payloadRules = [
              { re: /verify\s+you\s+are\s+human/i, score: 30, label: "Verify-human text in base64 payload" },
              { re: /win\s*\+\s*r/i, score: 40, label: "Win+R instruction in base64 payload" },
              { re: /ctrl\s*\+\s*v/i, score: 20, label: "Ctrl+V instruction in base64 payload" },
              { re: /press\s+(enter|ok)/i, score: 15, label: "Press Enter in base64 payload" },
              { re: /unusual\s+web\s+traffic/i, score: 35, label: "Unusual traffic claim in base64 payload" },
              { re: /cloudflare\s+protection/i, score: 25, label: "Cloudflare impersonation in base64 payload" },
              { re: /navigator\s*\.\s*clipboard\s*\.\s*writeText/i, score: 30, label: "Clipboard.writeText in base64 payload" },
              { re: /powershell/i, score: 35, label: "PowerShell reference in base64 payload" },
              { re: /security\s+of\s+your\s+connection/i, score: 20, label: "Security review claim in base64 payload" },
            ];
            for (const r of payloadRules) {
              if (r.re.test(decodedLower) || r.re.test(decoded)) {
                signals.push({ score: r.score, label: r.label });
              }
            }
          } catch {}
        }
      }

      // Base64-encoded command strings in variable assignments
      const cmdB64Vars = src.match(/(?:let|var|const)\s+\w*(?:COPY|copy|cmd|CMD|payload|Payload)\w*\s*=\s*['"]([A-Za-z0-9+\/=]{40,})['"]/g);
      if (cmdB64Vars && cmdB64Vars.length > 0) {
        signals.push({ score: 20, label: "Base64 command variable in inline script" });
        for (const varMatch of cmdB64Vars) {
          const b64 = varMatch.match(/['"]([A-Za-z0-9+\/=]{40,})['"]/);
          if (b64) {
            try {
              const decoded = atob(b64[1]);
              if (/powershell|cmd\.exe|iex|iwr|invoke-/i.test(decoded)) {
                signals.push({ score: 40, label: "Base64-encoded PowerShell/cmd command in script" });
              }
            } catch {}
          }
        }
      }
    }

    const score = cap100(signals.reduce((a, s) => a + s.score, 0));
    return { score, signals };
  };

  // --- Detect Cloudflare verification impersonation ---
  // Evasion: progressive reveal — CF-themed page with spinner, checkbox, Ray ID.
  // ClickFix instructions only appear AFTER user clicks checkbox 2x.
  // Detect the structural pattern even before lure text is revealed.
  Analyzer.detectCloudflareImpersonation = function () {
    const signals = [];
    const allText = normalizeText(document.body?.textContent || "").toLowerCase();

    const cfRules = [
      { re: /needs?\s+to\s+review\s+(the\s+)?security\s+of\s+your\s+connection/i, score: 35, label: "CF impersonation: review security of connection" },
      { re: /just\s+a\s+moment/i, score: 10, label: "CF impersonation: Just a moment title" },
      { re: /ray\s*id\s*:/i, score: 10, label: "CF impersonation: Ray ID display" },
      { re: /performance\s*[&]\s*security\s+by\s+cloudflare/i, score: 15, label: "CF impersonation: Performance & security by Cloudflare" },
      { re: /unusual\s+web\s+traffic\s+detected/i, score: 35, label: "CF impersonation: Unusual Web Traffic Detected" },
      { re: /automated\s+verification\s+attempts?\s+have\s+failed/i, score: 30, label: "CF impersonation: Automated verification failed" },
      { re: /verify\s+you\s+are\s+human/i, score: 15, label: "CF impersonation: Verify you are human" },
      { re: /press\s+.*windows\s+key\s*\+?\s*r/i, score: 40, label: "CF impersonation: Win+R instruction" },
      { re: /i\s+am\s+not\s+a\s+robot\s*[-–—]\s*cloudflare\s+id/i, score: 35, label: "CF impersonation: fake Cloudflare ID agreement" },
      { re: /ctrl\s*\+?\s*v\s*.*verification|verification\s*.*ctrl\s*\+?\s*v/i, score: 30, label: "CF impersonation: Ctrl+V verification instruction" },
    ];
    for (const r of cfRules) {
      if (r.re.test(allText)) {
        signals.push({ score: r.score, label: r.label });
      }
    }

    // Structural match (expanded for new kit variants: instruction-modal, modal-overlay, etc.)
    const hasCFStructure = document.querySelector("#modalBlock, #center, .captcha-box, #instruction-modal, .modal-overlay, .modal-content");
    const hasCheckbox = document.querySelector("#checkbox, #captchaCheck, .sync_event_click, #captcha-checkbox, .captcha-check");
    const hasRayId = document.querySelector("#ray-id, [id*='ray']");
    const hasLoaderRing = document.querySelector(".loader-ring, .spinner");

    if (hasCFStructure && hasCheckbox && hasRayId) {
      signals.push({ score: 25, label: "CF impersonation: structural match (modal + checkbox + ray-id)" });
    }
    if (hasCFStructure && hasLoaderRing && hasCheckbox) {
      const realCF = document.querySelector('script[src*="challenges.cloudflare.com"]');
      if (!realCF) {
        signals.push({ score: 20, label: "CF impersonation: fake loader + checkbox without real CF challenge" });
      }
    }

    // Clipboard write tied to verification flow in inline scripts
    const inlineScripts = document.querySelectorAll("script:not([src])");
    for (const s of inlineScripts) {
      const code = s.textContent || "";
      if (/navigator\s*\.\s*clipboard\s*\.\s*writeText/i.test(code) &&
          /(verify|human|captcha|checkbox|robot)/i.test(code)) {
        signals.push({ score: 30, label: "Clipboard.writeText tied to verification flow" });
        break;
      }
      if (/setClipboardCopyData|execCommand\s*\(\s*['"]copy/i.test(code) &&
          /(verify|captcha|checkbox|robot|modal)/i.test(code)) {
        signals.push({ score: 30, label: "execCommand copy tied to verification flow" });
        break;
      }
    }

    const score = cap100(signals.reduce((a, s) => a + s.score, 0));
    return { score, signals };
  };

  // --- Enhanced calculatePageThreat wrapper v2 ---
  // Wraps the EXISTING wrapper to incorporate the 3 new layers without
  // modifying any prior logic. Chains: original → multiStageLoader wrapper → this.
  const _prevCalcPageThreat = Analyzer.calculatePageThreat;
  Analyzer.calculatePageThreat = function (layers) {
    const prev = _prevCalcPageThreat.call(this, layers);

    const srcdoc    = cap100(layers.srcdocIframe?.score || 0);
    const b64script = cap100(layers.base64Script?.score || 0);
    const cfImpersonate = cap100(layers.cfImpersonation?.score || 0);

    // New layers participate via max (any single high-scoring layer triggers)
    let newThreat = Math.max(prev.pageThreat, srcdoc, b64script, cfImpersonate);

    // Cross-layer amplification: srcdoc iframe + lure/captcha signals in parent
    const lure = cap100(layers.lure?.score || 0);
    const captcha = cap100(layers.captcha?.score || 0);
    const srcdocCombo = (srcdoc >= 30 && (lure > 0 || captcha > 0)) ? Math.min(15, srcdoc * 0.2) : 0;

    // CF impersonation + base64 script combo (lubazra/primetimehost pattern)
    const cfB64Combo = (cfImpersonate >= 20 && b64script >= 30) ? Math.min(20, (cfImpersonate + b64script) * 0.15) : 0;

    const pageThreat = Math.max(prev.pageThreat, cap100(newThreat + srcdocCombo + cfB64Combo));

    let adjustedThreshold = prev.adjustedThreshold;
    if (pageThreat >= 60) adjustedThreshold = 25;
    else if (pageThreat >= 30) adjustedThreshold = Math.min(adjustedThreshold, 40);

    const allSignals = [...prev.signals];
    if (layers.srcdocIframe?.signals?.length) allSignals.push(...layers.srcdocIframe.signals.map(s => ({ ...s, layer: "srcdocIframe" })));
    if (layers.base64Script?.signals?.length) allSignals.push(...layers.base64Script.signals.map(s => ({ ...s, layer: "base64Script" })));
    if (layers.cfImpersonation?.signals?.length) allSignals.push(...layers.cfImpersonation.signals.map(s => ({ ...s, layer: "cfImpersonation" })));

    return { pageThreat, adjustedThreshold, signals: allSignals };
  };

  // ===================================================================
  // ADDITIONS (v1.2.6 — Detect clipboard staging in inline scripts)
  // Catches pages where inline <script> contains clipboard-write code
  // (execCommand('copy'), clipboard.writeText, textarea staging) combined
  // with command/payload patterns (irm, iex, powershell, mshta, etc.).
  // Reads script source text, not execution — works even when CSP blocks
  // our hook injection. Critical for sites with strict CSP.
  // ===================================================================
  Analyzer.detectScriptClipboardStaging = function () {
    const signals = [];
    const scripts = document.querySelectorAll("script:not([src])");

    for (const script of scripts) {
      const code = script.textContent || "";
      if (code.length < 50) continue;

      const hasExecCopy = /execCommand\s*\(\s*['"]copy['"]\s*\)/i.test(code);
      const hasClipboardWrite = /navigator\s*\.\s*clipboard\s*\.\s*writeText/i.test(code);
      const hasTextareaStaging = /createElement\s*\(\s*['"]textarea['"]\s*\)[\s\S]{0,300}?(\.select\s*\(\)|execCommand)/i.test(code);

      const hasClipboardMechanism = hasExecCopy || hasClipboardWrite || hasTextareaStaging;
      if (!hasClipboardMechanism) continue;

      const payloadRules = [
        { re: /\birm\b[\s\S]{0,100}?\biex\b/i, score: 45, label: "irm|iex pipe in script with clipboard staging" },
        { re: /\biwr\b[\s\S]{0,100}?\biex\b/i, score: 45, label: "iwr|iex pipe in script with clipboard staging" },
        { re: /\birm\s+['"]?https?:\/\//i, score: 35, label: "irm URL fetch in script with clipboard staging" },
        { re: /\|\s*iex\b/i, score: 40, label: "Pipe to iex in script with clipboard staging" },
        { re: /powershell[\s\S]{0,200}?(-e\s+|-enc\s+|-command\s+)/i, score: 45, label: "PowerShell encoded command in script with clipboard staging" },
        { re: /mshta|certutil|bitsadmin|regsvr32|rundll32/i, score: 40, label: "LOLBin in script with clipboard staging" },
        { re: /cmd[\s\S]{0,50}?(\/c|\/k)\s/i, score: 30, label: "cmd /c execution in script with clipboard staging" },
      ];

      for (const r of payloadRules) {
        if (r.re.test(code)) {
          signals.push({ score: r.score, label: r.label });
        }
      }

      if (hasTextareaStaging) {
        signals.push({ score: 20, label: "Textarea clipboard staging pattern" });
      }

      if (signals.length === 0 && hasClipboardMechanism) {
        if (/['"]https?:\/\/['"\s]*\+\s*[\w.]+/i.test(code) || /location\s*\.\s*hostname/i.test(code)) {
          signals.push({ score: 25, label: "Dynamic URL construction with clipboard staging" });
        }
      }
    }

    const score = cap100(signals.reduce((a, s) => a + s.score, 0));
    return { score, signals };
  };

  // --- Enhanced calculatePageThreat wrapper v3 (scriptClipboardStaging) ---
  const _prev2CalcPageThreat = Analyzer.calculatePageThreat;
  Analyzer.calculatePageThreat = function (layers) {
    const prev = _prev2CalcPageThreat.call(this, layers);

    const clipStaging = cap100(layers.scriptClipboardStaging?.score || 0);
    if (clipStaging === 0) return prev;

    const lure = cap100(layers.lure?.score || 0);
    let newThreat = Math.max(prev.pageThreat, clipStaging);
    const comboBonus = (clipStaging >= 30 && lure >= 25) ? Math.min(20, clipStaging * 0.3) : 0;
    const pageThreat = Math.max(prev.pageThreat, cap100(newThreat + comboBonus));

    let adjustedThreshold = prev.adjustedThreshold;
    if (pageThreat >= 60) adjustedThreshold = 25;
    else if (pageThreat >= 30) adjustedThreshold = Math.min(adjustedThreshold, 40);

    const allSignals = [...prev.signals];
    if (layers.scriptClipboardStaging?.signals?.length) {
      allSignals.push(...layers.scriptClipboardStaging.signals.map(s => ({ ...s, layer: "scriptClipboardStaging" })));
    }

    return { pageThreat, adjustedThreshold, signals: allSignals };
  };

  // --- Enhanced calculatePageThreat wrapper v4 (AiTM phishing) ---
  const _prev3CalcPageThreat = Analyzer.calculatePageThreat;
  Analyzer.calculatePageThreat = function (layers) {
    const prev = _prev3CalcPageThreat.call(this, layers);

    const aitm = cap100(layers.aitm?.score || 0);
    if (aitm === 0) return prev;

    const lure = cap100(layers.lure?.score || 0);
    const fakeErr = cap100(layers.fakeErr?.score || 0);
    const embedded = cap100(layers.embeddedPayload?.score || 0);
    const b64script = cap100(layers.base64Script?.score || 0);
    const comboBonus = (aitm >= 40 && (lure >= 20 || fakeErr >= 20 || embedded >= 20 || b64script >= 20))
      ? Math.min(20, aitm * 0.25)
      : 0;
    const pageThreat = Math.max(prev.pageThreat, cap100(Math.max(prev.pageThreat, aitm) + comboBonus));

    let adjustedThreshold = prev.adjustedThreshold;
    if (pageThreat >= 60) adjustedThreshold = 25;
    else if (pageThreat >= 30) adjustedThreshold = Math.min(adjustedThreshold, 40);

    const allSignals = [...prev.signals];
    if (layers.aitm?.signals?.length) {
      allSignals.push(...layers.aitm.signals.map(s => ({ ...s, layer: "aitm" })));
    }

    return { pageThreat, adjustedThreshold, signals: allSignals };
  };

  // ===================================================================
  // ADDITIONS (v1.2.6 — Remote rules loader)
  // Reads cached rule definitions from chrome.storage.local (written by
  // background.js fetcher). Rules are data — regex pattern strings, scores,
  // labels. They get compiled into RegExp objects here and appended to
  // the appropriate detection layers. Built-in rules are NEVER modified.
  //
  // Rules JSON schema (each key maps to a detection layer):
  // {
  //   "version": 1,
  //   "lure": [{ "re": "some\\s+regex", "flags": "i", "score": 40, "label": "Description" }],
  //   "captcha": [...],
  //   "fakeErr": [...],
  //   "fakeUpdate": [...],
  //   "srcdocIframe": [...],
  //   "base64Script": [...],
  //   "cfImpersonation": [...],
  //   "clipboard": [{ "re": "pattern", "flags": "i", "score": 40, "label": "Desc" }]
  // }
  //
  // "clipboard" rules are text-match rules applied to intercepted clipboard content.
  // All other keys match the existing Analyzer layer names.
  // ===================================================================

  let _remoteRulesCache = null; // in-memory cache per page lifecycle

  Analyzer.loadRemoteRules = async function () {
    if (_remoteRulesCache !== null) return _remoteRulesCache;
    try {
      const data = await chrome.storage.local.get("cg_remote_rules");
      const raw = data?.cg_remote_rules;
      if (!raw || typeof raw.version !== "number") {
        _remoteRulesCache = {};
        return _remoteRulesCache;
      }

      // Compile regex strings into RegExp objects, grouped by layer
      const compiled = {};
      for (const [layer, rules] of Object.entries(raw)) {
        if (layer === "version") continue;
        if (!Array.isArray(rules)) continue;
        compiled[layer] = [];
        for (const r of rules) {
          if (!r.re || typeof r.re !== "string") continue;
          try {
            compiled[layer].push({
              re: new RegExp(r.re, r.flags || "i"),
              score: typeof r.score === "number" ? r.score : 0,
              label: r.label || "Remote rule"
            });
          } catch {} // skip invalid regex
        }
      }
      _remoteRulesCache = compiled;
      return compiled;
    } catch {
      _remoteRulesCache = {};
      return {};
    }
  };

  // Run remote rules against a text string for a given layer
  // Returns { score, signals } — same shape as built-in layers
  Analyzer.runRemoteTextRules = function (layerName, text, remoteRules) {
    const signals = [];
    const rules = remoteRules?.[layerName];
    if (!rules || !rules.length) return { score: 0, signals };
    const normalized = normalizeText(text || "").toLowerCase();
    for (const r of rules) {
      if (r.re.test(normalized)) {
        signals.push({ score: r.score, label: "[R] " + r.label });
      }
    }
    const score = cap100(signals.reduce((a, s) => a + s.score, 0));
    return { score, signals };
  };

  // Run remote rules against DOM for structural layers (captcha, srcdocIframe, etc.)
  // These get the full document HTML as input
  Analyzer.runRemoteDomRules = function (layerName, remoteRules) {
    const signals = [];
    const rules = remoteRules?.[layerName];
    if (!rules || !rules.length) return { score: 0, signals };
    const text = normalizeText(document.body?.textContent || "").toLowerCase();
    const html = document.body?.innerHTML || "";
    for (const r of rules) {
      if (r.re.test(text) || r.re.test(html)) {
        signals.push({ score: r.score, label: "[R] " + r.label });
      }
    }
    const score = cap100(signals.reduce((a, s) => a + s.score, 0));
    return { score, signals };
  };

  // Merge a built-in layer result with its remote counterpart
  // Built-in always runs first. Remote can only ADD score and signals.
  Analyzer.mergeWithRemote = function (builtinResult, layerName, remoteRules, text) {
    const remote = text !== undefined
      ? Analyzer.runRemoteTextRules(layerName, text, remoteRules)
      : Analyzer.runRemoteDomRules(layerName, remoteRules);

    if (remote.score === 0) return builtinResult;

    // Merge — take max score, concat signals
    const mergedScore = cap100((builtinResult?.score || 0) + remote.score);
    const mergedSignals = [
      ...(builtinResult?.signals || builtinResult?.matches?.map(m => ({ label: m, score: null })) || []),
      ...remote.signals
    ];
    const mergedMatches = [
      ...(builtinResult?.matches || []),
      ...remote.signals.map(s => s.label)
    ];

    return {
      ...builtinResult,
      score: mergedScore,
      signals: mergedSignals,
      matches: mergedMatches
    };
  };

  window.__ClickGuardAnalyzer = Analyzer;
})();
