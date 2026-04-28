// form-detector.js — Sensitive form field detection (opt-in feature)
// Detects forms requesting passwords, MFA codes, SSN, banking info, etc.
// and warns users before submission. Does NOT collect or store any form values.
// Exposed on window.__ClickArmorFormDetector for use by content.js
(function () {
  const FormDetector = {};

  // Sensitive field patterns — matched against input name, id, placeholder, label text, aria-label
  const SENSITIVE_PATTERNS = [
    // Credentials
    { re: /\b(passwords?|passwd|pass_?words?|pwds?|pwd)\b/i, label: "Password field", score: 50 },
    { re: /\b(passcode|pin_?code|access_?code)\b/i, label: "Passcode / PIN field", score: 50 },
    { re: /\b(login|log[\s_-]?in|sign[\s_-]?in)\b.*\b(credential|password|pwd)\b/i, label: "Login credential field", score: 50 },
    { re: /\b(login|log[\s_-]?in|sign[\s_-]?in)\b.*\b(email|e-?mail|username|user_?name|user_?id|account)\b/i, label: "Login email / username field", score: 35 },
    { re: /\b(office\s*365|microsoft\s*365|o365|outlook)\b.*\b(login|log[\s_-]?in|sign[\s_-]?in)\b.*\b(email|e-?mail|username|pwds?|passwords?|passwd|pass_?word|pwd)\b/i, label: "Microsoft 365 sign-in field", score: 60 },

    // MFA / OTP / 2FA
    { re: /\b(mfa|otp|2fa|two.?factor|totp)\b/i, label: "MFA / OTP code field", score: 60 },
    { re: /\b(verification_?code|verify_?code|auth_?code|authenticat)/i, label: "Verification / auth code field", score: 55 },
    { re: /\b(duo|duo_?code|duo_?passcode)\b/i, label: "Duo MFA code field", score: 60 },
    { re: /\b(recovery_?code|backup_?code)\b/i, label: "Recovery / backup code field", score: 55 },
    { re: /\b(one.?time|single.?use)\b.*\b(code|password|token)\b/i, label: "One-time code field", score: 55 },

    // SSN / Government ID
    { re: /\b(ssn|social_?security|social_?sec)\b/i, label: "SSN field", score: 70 },
    { re: /\b(tax_?id|tin|ein|itin)\b/i, label: "Tax ID field", score: 60 },

    // Student / institutional ID
    { re: /\b(student_?id|puid|university_?id|campus_?id|employee_?id)\b/i, label: "Student / institutional ID field", score: 45 },

    // Banking / financial
    { re: /\b(bank_?account|account_?number|acct_?num)\b/i, label: "Bank account number field", score: 65 },
    { re: /\b(routing_?number|aba_?number|sort_?code)\b/i, label: "Routing / sort code field", score: 65 },
    { re: /\b(credit_?card|card_?number|cc_?num|debit_?card)\b/i, label: "Credit / debit card number field", score: 60 },
    { re: /\b(cvv|cvc|security_?code|card_?code)\b/i, label: "Card security code field", score: 60 },
    { re: /\b(exp(iry|iration)?_?date)\b.*\b(card|credit|debit)\b/i, label: "Card expiration field", score: 50 },

    // Crypto
    { re: /\b(seed_?phrase|private_?key|wallet_?key|mnemonic)\b/i, label: "Crypto seed / private key field", score: 70 },
    { re: /\b(secret_?key|api_?key|api_?secret)\b/i, label: "Secret / API key field", score: 50 },

    // ===================================================================
    // ADDITIONS (v1.2.2 — expanded sensitive field coverage)
    // Everything below is NEW — nothing above was modified.
    // ===================================================================

    // Misspelled / obfuscated password variants (deliberate evasion)
    { re: /\b(p[a@][s$][s$]?w[o0]r?d|pwsd|pswrd|pswd|passwrd|p4ssw0rd|passw[o0]rd)\b/i, label: "Password field (misspelled/obfuscated)", score: 50 },

    // Sign-in / login context with email (catches "Sign in Email", "Login Email" etc)
    { re: /\bsign[\s_-]?in\b[\s\S]{0,30}\b(email|e-?mail)\b/i, label: "Sign-in email field", score: 40 },
    { re: /\bsign[\s_-]?in\b[\s\S]{0,30}\b(pw|pwd|pswd|pwsd|pass)\b/i, label: "Sign-in password field (abbreviated)", score: 50 },

    // School / university / institution (phishing targeting students — like the WordPress screenshot)
    { re: /\b(school[\s_-]?name|university[\s_-]?name|college[\s_-]?name|institution[\s_-]?name)\b/i, label: "School / university name field", score: 35 },
    { re: /\b(former[\s_-]?school|present[\s_-]?school|current[\s_-]?school)\b/i, label: "School context field", score: 35 },
    { re: /\b(faculty[\s_-]?name|department[\s_-]?name|major|program[\s_-]?of[\s_-]?study)\b/i, label: "Academic program field", score: 30 },
    { re: /\b(graduation[\s_-]?(date|year)|enrollment[\s_-]?(date|year)|matriculation)\b/i, label: "Academic date field", score: 25 },

    // DOB / personal identity (common in credential harvesting forms)
    { re: /\b(date[\s_-]?of[\s_-]?birth|dob|birth[\s_-]?date|birthday)\b/i, label: "Date of birth field", score: 40 },
    { re: /\b(mother'?s?[\s_-]?maiden[\s_-]?name|maiden[\s_-]?name)\b/i, label: "Mother's maiden name field (security question)", score: 55 },
    { re: /\b(place[\s_-]?of[\s_-]?birth|city[\s_-]?of[\s_-]?birth|country[\s_-]?of[\s_-]?birth)\b/i, label: "Place of birth field", score: 35 },

    // National ID / government docs (non-US)
    { re: /\b(national[\s_-]?id|national[\s_-]?identity|nric|aadhaar|pan[\s_-]?card|passport[\s_-]?(number|no|num))\b/i, label: "National ID / passport field", score: 60 },
    { re: /\b(driver'?s?[\s_-]?licen[cs]e[\s_-]?(number|no|num)?|dl[\s_-]?number)\b/i, label: "Driver's license field", score: 55 },

    // Multi-credential / "former + current" patterns (like the WordPress phish)
    { re: /\b(former|previous|old)[\s\S]{0,30}(email|e-?mail|sign[\s_-]?in|login|password|pwd|pwsd)\b/i, label: "Former/previous credential request", score: 55 },
    { re: /\b(present|current|new)[\s\S]{0,30}(sign[\s_-]?in|login)[\s\S]{0,30}(email|password|pwd|pwsd)\b/i, label: "Current credential request", score: 50 },

    // Employment / HR phishing
    { re: /\b(employer[\s_-]?name|company[\s_-]?name|workplace)\b.*\b(password|login|sign[\s_-]?in)\b/i, label: "Employer + credential combo field", score: 55 },

    // Security questions
    { re: /\b(security[\s_-]?question|secret[\s_-]?question|security[\s_-]?answer)\b/i, label: "Security question field", score: 45 },

    // Full name + password combo context (generic harvesters)
    { re: /\b(full[\s_-]?name)\b/i, label: "Full name field", score: 15 },
  ];

  // Known form platforms — used to boost confidence when sensitive fields appear on these
  // tier 1: Pure form builders — a password field here is ALWAYS suspicious
  // tier 2: Hosting/site-builder platforms — apps may have legitimate login forms
  //         Tier 2 requires additional signals (brand impersonation, high-severity fields,
  //         threatening text, or unusual field combos) beyond just email+password
  const FORM_PLATFORMS = [
    { re: /docs\.google\.com\/forms/i, label: "Google Forms", tier: 1 },
    { re: /docs\.google\.com\/drawings/i, label: "Google Drawings", tier: 1 },
    { re: /docs\.google\.com\/presentation/i, label: "Google Slides", tier: 1 },
    { re: /docs\.google\.com\/document/i, label: "Google Docs", tier: 1 },
    { re: /sites\.google\.com/i, label: "Google Sites", tier: 1 },
    { re: /drive\.google\.com/i, label: "Google Drive", tier: 1 },
    { re: /forms\.office\.com|forms\.microsoft\.com/i, label: "Microsoft Forms", tier: 1 },
    { re: /typeform\.com/i, label: "Typeform", tier: 1 },
    { re: /jotform\.com/i, label: "Jotform", tier: 1 },
    { re: /surveymonkey\.com/i, label: "SurveyMonkey", tier: 1 },
    { re: /airtable\.com\/form/i, label: "Airtable Form", tier: 1 },
    { re: /wufoo\.com/i, label: "Wufoo", tier: 1 },
    { re: /cognito(forms)?\.com/i, label: "Cognito Forms", tier: 1 },
    { re: /bubbleapps\.io/i, label: "Bubble", tier: 2 },
    { re: /godaddysites\.com/i, label: "GoDaddy Sites", tier: 2 },

    // ===================================================================
    // ADDITIONS (v1.2.2 — free-hosting / site-builder phishing platforms)
    // Everything below is NEW — nothing above was modified.
    // ===================================================================

    // Free hosting / site builders (tier 2 — may host legitimate apps with logins)
    { re: /\.wordpress\.com/i, label: "WordPress.com", tier: 2 },
    { re: /\.blogspot\.com|\.blogger\.com/i, label: "Blogger / Blogspot", tier: 2 },
    { re: /\.weebly\.com/i, label: "Weebly", tier: 2 },
    { re: /\.wixsite\.com|\.wix\.com/i, label: "Wix", tier: 2 },
    { re: /\.squarespace\.com/i, label: "Squarespace", tier: 2 },
    { re: /sites\.google\.com/i, label: "Google Sites", tier: 1 },
    { re: /\.carrd\.co/i, label: "Carrd", tier: 1 },
    { re: /\.webflow\.io/i, label: "Webflow", tier: 2 },
    { re: /\.netlify\.app/i, label: "Netlify", tier: 2 },
    { re: /\.glitch\.me/i, label: "Glitch", tier: 2 },
    { re: /\.web\.app|\.firebaseapp\.com/i, label: "Firebase Hosting", tier: 2 },
    { re: /\.github\.io/i, label: "GitHub Pages", tier: 2 },
    { re: /\.pages\.dev/i, label: "Cloudflare Pages", tier: 2 },
    { re: /\.vercel\.app/i, label: "Vercel", tier: 2 },
    { re: /\.render\.com/i, label: "Render", tier: 2 },
    { re: /\.canva\.site/i, label: "Canva Sites", tier: 1 },
    { re: /\.softr\.app/i, label: "Softr", tier: 2 },
    { re: /\.notion\.site/i, label: "Notion Site", tier: 1 },
    { re: /\.framer\.website|\.framer\.app/i, label: "Framer", tier: 2 },
    { re: /\.webnode\.\w+/i, label: "Webnode", tier: 2 },
    { re: /\.strikingly\.com/i, label: "Strikingly", tier: 2 },
    { re: /\.site123\.me/i, label: "Site123", tier: 2 },
    { re: /\.yolasite\.com/i, label: "Yola", tier: 2 },
    { re: /\.jimdo\.com|\.jimdofree\.com/i, label: "Jimdo", tier: 2 },
    { re: /\.hubspotpagebuilder\.com|\.hs-sites\.com/i, label: "HubSpot Sites", tier: 2 },
    { re: /\.leadpages\.net/i, label: "Leadpages", tier: 1 },
    { re: /\.unbounce\.com/i, label: "Unbounce", tier: 1 },
    { re: /\.systeme\.io/i, label: "Systeme.io", tier: 1 },
    { re: /\.mailchimp\.com\/landing/i, label: "Mailchimp Landing Page", tier: 1 },
    { re: /\.sharepoint\.com/i, label: "SharePoint", tier: 2 },
    { re: /\.onrender\.com/i, label: "Render", tier: 2 },
    { re: /\.herokuapp\.com/i, label: "Heroku", tier: 2 },
    { re: /\.fly\.dev/i, label: "Fly.io", tier: 2 },
    { re: /\.replit\.app|\.repl\.co/i, label: "Replit", tier: 2 },
    { re: /\.stackblitz\.io/i, label: "StackBlitz", tier: 2 },
    { re: /\.surge\.sh/i, label: "Surge", tier: 2 },
    { re: /\.tiiny\.site/i, label: "Tiiny.site", tier: 1 },
    { re: /\.teleporthq\.app/i, label: "TeleportHQ", tier: 2 },
    { re: /\.webador\.\w+/i, label: "Webador", tier: 2 },
    { re: /\.crd\.co/i, label: "Carrd (alt)", tier: 1 },
    { re: /\.my\.canva\.site/i, label: "Canva Sites", tier: 1 },
    { re: /\.mypressonline\.com/i, label: "MyPressOnline", tier: 2 },
    { re: /\.webs\.com/i, label: "Webs.com", tier: 2 },
    { re: /\.doodlekit\.com/i, label: "DoodleKit", tier: 2 },
    { re: /\.tilda\.ws|\.tildacdn\.com/i, label: "Tilda", tier: 2 },
  ];

  // Get text context around a form field (label, placeholder, aria-label, nearby text)
  function getFieldContext(input) {
    const parts = [];

    // Direct attributes
    const name = (input.getAttribute("name") || "").toLowerCase();
    const id = (input.getAttribute("id") || "").toLowerCase();
    const dataAid = (input.getAttribute("data-aid") || "").toLowerCase();
    const placeholder = (input.getAttribute("placeholder") || "").toLowerCase();
    const ariaLabel = (input.getAttribute("aria-label") || "").toLowerCase();
    const autocomplete = (input.getAttribute("autocomplete") || "").toLowerCase();
    const title = (input.getAttribute("title") || "").toLowerCase();

    parts.push(name, id, dataAid, placeholder, ariaLabel, autocomplete, title);

    // Associated <label>
    if (input.id) {
      const label = document.querySelector(`label[for="${CSS.escape(input.id)}"]`);
      if (label) parts.push((label.textContent || "").toLowerCase().trim());
    }

    // Parent label (wrapping)
    const parentLabel = input.closest("label");
    if (parentLabel) parts.push((parentLabel.textContent || "").toLowerCase().trim());

    // Nearby text — check previous sibling
    try {
      const rect = input.getBoundingClientRect();
      const prev = input.previousElementSibling;
      if (prev) {
        const prevRect = prev.getBoundingClientRect();
        if (Math.abs(prevRect.bottom - rect.top) < 50) {
          parts.push((prev.textContent || "").toLowerCase().trim());
        }
      }
    } catch {}

    // Parent container text — walk up to 3 levels to find question/label text
    // Catches Google Forms (div-based), Typeform, and other non-standard form layouts
    try {
      let parent = input.parentElement;
      for (let i = 0; i < 3 && parent; i++) {
        // Look for text nodes or heading/span/div elements that serve as labels
        for (const child of parent.children) {
          if (child === input || child.contains(input)) continue;
          const tag = child.tagName;
          if (["SPAN", "DIV", "H1", "H2", "H3", "H4", "P", "LEGEND"].includes(tag)) {
            const text = (child.textContent || "").toLowerCase().trim();
            if (text.length > 2 && text.length < 200) {
              parts.push(text);
            }
          }
        }
        parent = parent.parentElement;
      }
    } catch {}

    // aria-describedby
    const describedBy = input.getAttribute("aria-describedby");
    if (describedBy) {
      const descEl = document.getElementById(describedBy);
      if (descEl) parts.push((descEl.textContent || "").toLowerCase().trim());
    }

    // ===================================================================
    // ADDITIONS (v1.2.3 — deep parent walk for Google Forms / Docs / Sites)
    // Google Forms nests inputs 6-8 levels deep from the question text.
    // The 3-level walk above never reaches the question heading. This
    // extended walk looks for role="listitem" ancestors (Google Forms
    // question containers) and extracts the question/heading text from
    // the first heading-like child that is NOT an ancestor of the input.
    // Also catches contenteditable regions (Google Docs phishing) and
    // data-params attributes (Google Forms stores question text there).
    // Nothing above was modified.
    // ===================================================================
    try {
      // Deep walk: climb up to 10 levels looking for a role="listitem"
      // container or any ancestor with data-params (Google Forms question)
      let deepParent = input.parentElement;
      let _deepFound = false;
      for (let d = 0; d < 10 && deepParent && !_deepFound; d++) {
        const role = (deepParent.getAttribute("role") || "").toLowerCase();
        const dataParams = deepParent.getAttribute("data-params") || "";

        // Google Forms: role="listitem" wraps each question block
        if (role === "listitem" || role === "list") {
          // Extract heading text from children of this container
          const headings = deepParent.querySelectorAll(
            'div[role="heading"], [aria-level], h1, h2, h3, h4, h5, h6, ' +
            'span[dir="auto"], .freebirdFormviewItemViewHeaderTitleText, ' +
            '.M7eMe, .exportItemTitle'
          );
          for (const h of headings) {
            if (h.contains(input)) continue;
            const hText = (h.textContent || "").toLowerCase().trim();
            if (hText.length > 2 && hText.length < 300) {
              parts.push(hText);
              _deepFound = true;
            }
          }
          // Also grab any direct span/div text children in the question block
          if (!_deepFound) {
            for (const child of deepParent.children) {
              if (child.contains(input)) continue;
              const cText = (child.textContent || "").toLowerCase().trim();
              if (cText.length > 2 && cText.length < 300) {
                parts.push(cText);
                _deepFound = true;
              }
            }
          }
        }

        // Google Forms: data-params contains the question text as a JSON-ish string
        if (dataParams.length > 10 && !_deepFound) {
          const dpLower = dataParams.toLowerCase();
          if (dpLower.length < 2000) {
            parts.push(dpLower);
            _deepFound = true;
          }
        }

        deepParent = deepParent.parentElement;
      }
    } catch {}

    // ===================================================================
    // ADDITIONS (v1.2.3 — contenteditable detection for Google Docs phishing)
    // Google Docs pages use contenteditable divs instead of <input> elements.
    // If the input itself is contenteditable, or sits inside a contenteditable
    // ancestor, scan the surrounding text in that editable region.
    // Nothing above was modified.
    // ===================================================================
    try {
      const editableAncestor = input.closest("[contenteditable='true']");
      if (editableAncestor) {
        const editText = (editableAncestor.textContent || "").toLowerCase().trim();
        if (editText.length > 2 && editText.length < 2000) {
          parts.push(editText);
        }
      }
    } catch {}

    return parts.filter(Boolean).join(" ");
  }

  // Scan a single form field for sensitive patterns
  function scanField(input) {
    const context = getFieldContext(input);
    if (!context || context.length < 3) return null;

    const type = (input.getAttribute("type") || "text").toLowerCase();

    // Password type inputs are inherently sensitive
    if (type === "password") {
      return { score: 50, label: "Password-type input field", context: context.slice(0, 80) };
    }

    for (const pattern of SENSITIVE_PATTERNS) {
      if (pattern.re.test(context)) {
        return { score: pattern.score, label: pattern.label, context: context.slice(0, 80) };
      }
    }

    return null;
  }

  // Scan all forms on the page
  FormDetector.scanPage = function () {
    const results = {
      sensitiveFields: [],
      platform: null,
      isFormPlatform: false,
      platformTier: 0, // 0 = not a platform, 1 = pure form builder, 2 = hosting platform
      totalScore: 0
    };

    // Detect platform
    const url = location.href;
    for (const p of FORM_PLATFORMS) {
      if (p.re.test(url)) {
        results.platform = p.label;
        results.isFormPlatform = true;
        results.platformTier = p.tier || 1;
        break;
      }
    }

    // Scan all input/textarea/select elements (not just inside <form> tags — Google Forms
    // uses div-based forms with role="listitem")
    const inputs = document.querySelectorAll(
      'input:not([type="hidden"]):not([type="submit"]):not([type="button"]):not([type="reset"]):not([type="image"]):not([type="file"]):not([type="checkbox"]):not([type="radio"]), textarea, select'
    );

    const seen = new Set(); // avoid duplicate labels
    for (const input of inputs) {
      const hit = scanField(input);
      if (hit && !seen.has(hit.label)) {
        seen.add(hit.label);
        results.sensitiveFields.push(hit);
        results.totalScore += hit.score;
      }
    }

    // Also scan visible page text for surrounding sensitive context — BUT only if
    // actual sensitive form fields were already detected. Page text alone (e.g. a page
    // mentioning "seed phrase" with only a basic contact form) should not trigger.

    // ===================================================================
    // ADDITIONS (v1.2.3 — Google Forms question-text credential scanning)
    // Google Forms renders questions as div-based containers with
    // role="listitem". The actual question text (e.g. "Enter your password")
    // lives in a heading div, while the input is deeply nested. Even with
    // the deeper parent walk in getFieldContext, some Google Forms variants
    // use textarea or short-answer fields that may not trigger patterns.
    // This block scans ALL question headings on the page as text signals,
    // independent of whether the field-level scan found anything.
    // Nothing above was modified.
    // ===================================================================
    try {
      const _isGoogleFormPlatform = /docs\.google\.com\/(forms|document|drawings|presentation)|sites\.google\.com|forms\.(office|microsoft)\.com/i.test(location.href);
      if (_isGoogleFormPlatform || results.isFormPlatform) {
        // Scan Google Forms question headings directly
        const questionHeadings = document.querySelectorAll(
          '[role="heading"], .freebirdFormviewItemViewHeaderTitleText, ' +
          '.M7eMe, .exportItemTitle, [data-item-id] [aria-level]'
        );
        for (const heading of questionHeadings) {
          const qText = (heading.textContent || "").toLowerCase().trim();
          if (!qText || qText.length < 3 || qText.length > 500) continue;

          for (const pattern of SENSITIVE_PATTERNS) {
            if (pattern.re.test(qText) && !seen.has(pattern.label + " (question)")) {
              seen.add(pattern.label + " (question)");
              results.sensitiveFields.push({
                score: pattern.score,
                label: pattern.label,
                context: "Google/form platform question: " + qText.slice(0, 80)
              });
              results.totalScore += pattern.score;
            }
          }
        }

        // Scan data-params attributes (Google Forms stores question text there)
        const paramEls = document.querySelectorAll("[data-params]");
        for (const el of paramEls) {
          const dp = (el.getAttribute("data-params") || "").toLowerCase();
          if (dp.length < 10 || dp.length > 3000) continue;

          for (const pattern of SENSITIVE_PATTERNS) {
            if (pattern.re.test(dp) && !seen.has(pattern.label + " (data-params)")) {
              seen.add(pattern.label + " (data-params)");
              results.sensitiveFields.push({
                score: pattern.score,
                label: pattern.label,
                context: "Form platform data-params match"
              });
              results.totalScore += pattern.score;
            }
          }
        }
      }
    } catch {}

    // ===================================================================
    // ADDITIONS (v1.2.3 — contenteditable phishing detection for Google Docs)
    // Google Docs phishing pages use contenteditable divs to display fake
    // login forms. They don't use <input> elements at all — the "form" is
    // just styled text with editable regions. Scan all contenteditable
    // elements for credential-related text patterns.
    // Nothing above was modified.
    // ===================================================================
    try {
      const editables = document.querySelectorAll('[contenteditable="true"]');
      for (const editable of editables) {
        const editText = (editable.textContent || "").toLowerCase().trim();
        if (editText.length < 10 || editText.length > 5000) continue;

        for (const pattern of SENSITIVE_PATTERNS) {
          if (pattern.re.test(editText) && !seen.has(pattern.label + " (editable)")) {
            seen.add(pattern.label + " (editable)");
            results.sensitiveFields.push({
              score: pattern.score,
              label: pattern.label,
              context: "Editable region: " + editText.slice(0, 80)
            });
            results.totalScore += pattern.score;
          }
        }
      }
    } catch {}

    if (results.sensitiveFields.length > 0) {
      const bodyText = (document.body?.innerText || "").toLowerCase();
      const textPatterns = [
        { re: /enter\s+(your\s+)?(password|passcode|pin|mfa|otp|duo\s+code)/i, label: "Text asks for password/MFA entry", score: 40 },
        { re: /office\s*365|microsoft(\s*365)?|outlook/i, label: "Text references Microsoft 365 login", score: 25 },
        { re: /social\s+security\s+(number|#)/i, label: "Text asks for SSN", score: 50 },
        { re: /(bank\s+account|routing)\s+(number|#|info)/i, label: "Text asks for banking info", score: 50 },
        { re: /enter\s+(your\s+)?(student\s+id|puid|employee\s+id)/i, label: "Text asks for institutional ID", score: 35 },
        { re: /credit\s+card\s+(number|info|details)/i, label: "Text asks for credit card info", score: 50 },
        { re: /recovery\s+(code|key|phrase)/i, label: "Text asks for recovery codes", score: 45 },
        { re: /seed\s+phrase|private\s+key|wallet\s+(key|phrase)/i, label: "Text asks for crypto keys", score: 60 },
        { re: /verification\s+code\s+(from|sent|received)/i, label: "Text asks for verification code", score: 45 },
        { re: /termination|closure|suspend|deactivat|disabled/i, label: "Text threatens account termination", score: 35 },

        // ===================================================================
        // ADDITIONS (v1.2.2 — expanded page text patterns)
        // Everything below is NEW — nothing above was modified.
        // ===================================================================

        // Threatening / urgency language (credential harvesting pressure tactics)
        { re: /failure\s+to\s+(verify|confirm|comply|respond|complete)/i, label: "Text threatens failure consequences", score: 40 },
        { re: /will\s+result\s+in\s+(closure|termination|suspension|deletion|deactivation|loss)/i, label: "Text threatens account action", score: 40 },
        { re: /within\s+\d+\s*(hours?|hrs?|days?|minutes?)/i, label: "Text imposes time deadline", score: 25 },
        { re: /account\s+(will\s+be|has\s+been)\s+(locked|suspended|closed|terminated|restricted|deactivated)/i, label: "Text claims account lockout", score: 40 },
        { re: /unauthorized\s+(access|activity|login|sign[\s-]?in)/i, label: "Text claims unauthorized access", score: 35 },
        { re: /(verify|confirm|validate)\s+(your\s+)?(identity|account|ownership|information)/i, label: "Text demands identity verification", score: 30 },
        { re: /unusual\s+(activity|sign[\s-]?in|login|access)/i, label: "Text claims unusual activity", score: 30 },
        { re: /strictly\s+adhere|read\s+(this|the)\s+information\s+carefully/i, label: "Text uses authoritative compliance language", score: 25 },
        { re: /two\s+different\s+(logins?|accounts?|portals?)/i, label: "Text references multiple login confusion", score: 35 },

        // University / school phishing context
        { re: /(university|college|school|campus)\s+(portal|login|account|email)/i, label: "Text references university portal/login", score: 30 },
        { re: /(student|faculty|staff)\s+(email|portal|account|login)/i, label: "Text references student/staff account", score: 30 },
        { re: /\.(edu)\b/i, label: "Text references .edu domain", score: 15 },

        // Multi-credential harvesting (asking for both current AND former credentials)
        { re: /(former|previous|old)\s+(and\s+)?(present|current|new)\s+(email|password|login|sign[\s-]?in|credentials?)/i, label: "Text requests both former and current credentials", score: 50 },
        { re: /(present|current)\s+.*\s+(former|previous|old)\s+(email|password|login|sign[\s-]?in)/i, label: "Text requests current then former credentials", score: 50 },

        // Generic phishing indicators
        { re: /kindly\s+(enter|provide|indicate|submit|fill|input|update)/i, label: "Text uses 'kindly' phrasing (phishing indicator)", score: 20 },
        { re: /do\s+not\s+(share|disclose|reveal)[\s\S]{0,60}(anyone|third[\s-]?party)/i, label: "Text includes ironic secrecy warning", score: 15 },
      ];

      for (const p of textPatterns) {
        if (p.re.test(bodyText) && !seen.has(p.label)) {
          seen.add(p.label);
          results.sensitiveFields.push({ score: p.score, label: p.label, context: "(page text)" });
          results.totalScore += p.score;
        }
      }
    }

    // ===================================================================
    // ADDITIONS (v1.2.2 — standalone credential harvester detection)
    // Catches pages that combine threatening text with multiple input fields
    // even when field labels don't match known sensitive patterns.
    // This is a SEPARATE scoring path — doesn't modify anything above.
    // ===================================================================

    // If we have 3+ input fields on a form platform and the page text contains
    // threatening / urgency language, flag as suspicious even if field patterns
    // didn't match (catches generic or misspelled field labels)
    if (results.isFormPlatform && results.sensitiveFields.length === 0) {
      const inputs = document.querySelectorAll(
        'input:not([type="hidden"]):not([type="submit"]):not([type="button"]):not([type="reset"]):not([type="image"]):not([type="file"]):not([type="checkbox"]):not([type="radio"]), textarea'
      );
      const bodyText = (document.body?.innerText || "").toLowerCase();

      const threatIndicators = [
        /failure\s+to\s+(verify|confirm|comply)/i,
        /will\s+result\s+in\s+(closure|termination|suspension)/i,
        /account\s+(will\s+be|has\s+been)\s+(locked|suspended|closed|terminated)/i,
        /within\s+\d+\s*(hours?|hrs?|days?)/i,
        /termination|closure|suspend|deactivat/i,
        /unauthorized\s+(access|activity)/i,
        /(verify|confirm)\s+(your\s+)?(identity|account|ownership)/i,
      ];

      let threatCount = 0;
      for (const t of threatIndicators) {
        if (t.test(bodyText)) threatCount++;
      }

      // 3+ inputs on a form platform with threatening language = suspicious
      if (inputs.length >= 3 && threatCount >= 1) {
        results.sensitiveFields.push({
          score: 40,
          label: "Multiple input fields on form platform with threatening language",
          context: "(standalone harvester detection)"
        });
        results.totalScore += 40;
      }

      // 5+ inputs on a form platform even without threats = worth flagging
      // (legitimate forms on wordpress.com don't usually need 5+ text inputs)
      if (inputs.length >= 5) {
        results.sensitiveFields.push({
          score: 25,
          label: "Excessive input fields on free hosting platform (" + inputs.length + " fields)",
          context: "(standalone harvester detection)"
        });
        results.totalScore += 25;
      }
    }

    // Platform boost: if on a known form platform with any sensitive fields, amplify
    if (results.isFormPlatform && results.sensitiveFields.length > 0) {
      results.totalScore = Math.min(100, results.totalScore + 15);
    }

    results.totalScore = Math.min(100, results.totalScore);
    return results;
  };

  window.__ClickArmorFormDetector = FormDetector;
})();
