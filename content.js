// content.js — runs per tab (isolated world)
(function () {
  const Analyzer = window.__ClickGuardAnalyzer;
  if (!Analyzer) return;

  function getHost() {
    try { return new URL(location.href).hostname; } catch { return ""; }
  }

  function isSharePointHost(host = getHost()) {
    return /(^|\.)sharepoint\.com$/i.test(host);
  }

  const _MICROSOFT_COLLAB_HOSTS = new Set([
    "onedrive.live.com",
    "office.com",
    "www.office.com",
    "outlook.office.com",
    "teams.microsoft.com"
  ]);

  function isMicrosoftCollabHost(host = getHost()) {
    return /(^|\.)sharepoint\.com$/i.test(host) || _MICROSOFT_COLLAB_HOSTS.has(host);
  }

  function hasPotentialCredentialSurface() {
    try {
      return !!document.querySelector(
        "input:not([type='hidden']):not([disabled]), textarea:not([disabled]), select:not([disabled]), [contenteditable='true'], [contenteditable='']"
      );
    } catch {
      return false;
    }
  }

  function hasSharePointLoginLanguage() {
    const loginRe = /\b(sign[\s-]*in|log[\s-]*in|password|passcode|verification code|enter code|reauthenticate|verify (?:your )?account|session expired|microsoft account|office 365|sharepoint access|view document|open document|secure document|unlock document)\b/i;
    try {
      const nodes = Array.from(document.querySelectorAll("main, [role='main'], article, form, section, dialog, h1, h2, h3, p, label, button, a, div, span")).slice(0, 160);
      const text = nodes.map((el) => (el?.textContent || "").replace(/\s+/g, " ").trim()).filter(Boolean).join(" ").slice(0, 12000);
      return loginRe.test(text);
    } catch {
      try {
        return loginRe.test((document.body?.textContent || "").slice(0, 12000));
      } catch {
        return false;
      }
    }
  }

  function hasSharePointPhishSignal() {
    const { hasStrongCredentialInput } = hasStrongCredentialSurface();
    return hasStrongCredentialInput || (hasPotentialCredentialSurface() && hasSharePointLoginLanguage());
  }

  function hasStrongCredentialSurface(brandAliases) {
    const inputs = document.querySelectorAll(
      'input:not([type="hidden"]):not([type="submit"]):not([type="button"]):not([type="reset"]):not([type="image"]):not([type="file"]):not([type="checkbox"]):not([type="radio"]), textarea'
    );
    let hasStrongCredentialInput = false;
    let brandNearCredentialInput = false;
    const strongCredPatterns = [
      /pass|pwd|pwsd|pswrd|password|secret/i,
      /mfa|otp|2fa|verification|auth[\s_-]?code/i,
      /ssn|social[\s_-]?sec|tax[\s_-]?id/i,
      /card[\s_-]?num|credit|cvv|routing|account[\s_-]?num/i,
      /seed|private[\s_-]?key|wallet/i,
    ];

    for (const input of inputs) {
      const context = [
        input.getAttribute("name") || "",
        input.getAttribute("id") || "",
        input.getAttribute("placeholder") || "",
        input.getAttribute("aria-label") || "",
        input.getAttribute("type") || "",
      ].join(" ").toLowerCase();

      let labelText = "";
      if (input.id) {
        const label = document.querySelector(`label[for="${CSS.escape(input.id)}"]`);
        if (label) labelText = (label.textContent || "").toLowerCase();
      }
      const parentLabel = input.closest("label");
      if (parentLabel) labelText += " " + (parentLabel.textContent || "").toLowerCase();

      let parent = input.parentElement;
      for (let i = 0; i < 3 && parent; i++) {
        for (const child of parent.children) {
          if (child === input || child.contains(input)) continue;
          const tag = child.tagName;
          if (["SPAN", "DIV", "H1", "H2", "H3", "H4", "P", "LEGEND", "LABEL"].includes(tag)) {
            const t = (child.textContent || "").toLowerCase().trim();
            if (t.length > 2 && t.length < 200) labelText += " " + t;
          }
        }
        parent = parent.parentElement;
      }

      const fullContext = (context + " " + labelText).trim();
      if (brandAliases?.some(alias => textContainsAlias(fullContext, alias))) {
        brandNearCredentialInput = true;
      }

      if (input.type === "password") {
        hasStrongCredentialInput = true;
      } else {
        for (const p of strongCredPatterns) {
          if (p.test(fullContext)) {
            hasStrongCredentialInput = true;
            break;
          }
        }
      }
    }

    return { inputs, hasStrongCredentialInput, brandNearCredentialInput };
  }

  function shouldUseMicrosoftBudgetMode() {
    if (!isMicrosoftCollabHost() || CG.pageThreat >= 30) return false;
    try {
      if (!hasPotentialCredentialSurface()) return true;
      const nodeCount = document.getElementsByTagName("*").length;
      const scriptCount = document.scripts?.length || 0;
      return nodeCount > 2200 || scriptCount > 80;
    } catch {
      return false;
    }
  }

  function collectBudgetTextSample(limit = 16000) {
    let sample = "";
    const seen = new Set();
    const appendText = (value) => {
      if (!value || sample.length >= limit) return;
      const text = String(value).replace(/\s+/g, " ").trim();
      if (!text || seen.has(text)) return;
      seen.add(text);
      sample += (sample ? " " : "") + text;
    };
    try {
      const preferred = Array.from(document.querySelectorAll("main, [role='main'], article, form, section, dialog, aside, h1, h2, h3, p, li, button, a, label")).slice(0, 180);
      const fallback = preferred.length ? preferred : Array.from(document.body?.children || []).slice(0, 80);
      for (const el of fallback) {
        appendText(el?.textContent || "");
        if (sample.length >= limit) break;
      }
    } catch {}
    if (!sample) {
      try {
        appendText((document.body?.textContent || "").slice(0, limit));
      } catch {}
    }
    return sample.slice(0, limit);
  }

  function sendRuntimeMessage(message) {
    return new Promise((resolve) => {
      let settled = false;
      try {
        const maybePromise = chrome.runtime.sendMessage(message, (resp) => {
          if (settled) return;
          settled = true;
          if (chrome.runtime.lastError) {
            resolve({ ok: false, error: chrome.runtime.lastError.message });
            return;
          }
          resolve(resp);
        });
        if (maybePromise && typeof maybePromise.then === "function") {
          maybePromise.then((resp) => {
            if (settled) return;
            settled = true;
            resolve(resp);
          }).catch((error) => {
            if (settled) return;
            settled = true;
            resolve({ ok: false, error: error?.message || String(error) });
          });
        }
      } catch (error) {
        resolve({ ok: false, error: error?.message || String(error) });
      }
    });
  }

  function getLocalStorage(keys) {
    return new Promise((resolve) => {
      try {
        chrome.storage.local.get(keys, (result) => resolve(result || {}));
      } catch {
        resolve({});
      }
    });
  }

  function setLocalStorage(values) {
    return new Promise((resolve) => {
      try {
        chrome.storage.local.set(values, () => resolve());
      } catch {
        resolve();
      }
    });
  }

  function normalizeHostLocal(host) {
    return (host || "").toLowerCase().replace(/^www\./, "").replace(/^\.+/, "");
  }

  function sanitizeTempWhitelistLocal(raw) {
    const now = Date.now();
    const next = {};
    for (const [host, expiresAt] of Object.entries(raw || {})) {
      const cleanHost = normalizeHostLocal(host);
      const expiry = Number(expiresAt || 0);
      if (cleanHost && Number.isFinite(expiry) && expiry > now) next[cleanHost] = expiry;
    }
    return next;
  }

  function hostMatchesEntriesLocal(host, entries = []) {
    const cleanHost = normalizeHostLocal(host);
    return entries.some((entry) => {
      const cleanEntry = normalizeHostLocal(entry);
      return cleanHost === cleanEntry || cleanHost.endsWith("." + cleanEntry);
    });
  }

  async function isLocallyWhitelisted(host) {
    const cleanHost = normalizeHostLocal(host);
    if (!cleanHost) return false;
    const data = await getLocalStorage(["cg_enabled", "cg_whitelist", "cg_temp_whitelist"]);
    const enabled = data.cg_enabled !== false;
    const whitelist = (Array.isArray(data.cg_whitelist) ? data.cg_whitelist : []).map(normalizeHostLocal);
    const tempWhitelist = sanitizeTempWhitelistLocal(data.cg_temp_whitelist);
    if (JSON.stringify(tempWhitelist) !== JSON.stringify(data.cg_temp_whitelist || {})) {
      await setLocalStorage({ cg_temp_whitelist: tempWhitelist });
    }
    const hostNoWww = cleanHost.replace(/^www\./, "");
    return !enabled
      || whitelist.includes(cleanHost)
      || whitelist.includes(hostNoWww)
      || whitelist.some((entry) => cleanHost.endsWith("." + entry))
      || hostMatchesEntriesLocal(cleanHost, Object.keys(tempWhitelist));
  }

  async function whitelistCurrentHost() {
    const host = normalizeHostLocal(getHost());
    if (!host || !host.includes(".")) return;
    const data = await getLocalStorage(["cg_whitelist"]);
    const whitelist = (Array.isArray(data.cg_whitelist) ? data.cg_whitelist : []).map(normalizeHostLocal);
    if (!whitelist.includes(host)) whitelist.push(host);
    await setLocalStorage({ cg_whitelist: whitelist });
  }

  // --- Built-in whitelist (synchronous, no message needed) ---
  // Mirrors BUILTIN_WHITELIST in background.js for instant local check.
  const _BUILTIN_WL = [
    "chat.openai.com","chatgpt.com","claude.ai","gemini.google.com",
    "copilot.microsoft.com","poe.com","perplexity.ai","bard.google.com",
    "www.google.com","mail.google.com","search.google.com",
    "sheets.google.com","slides.google.com",
    "calendar.google.com","meet.google.com","accounts.google.com",
    "myaccount.google.com","maps.google.com","news.google.com",
    "play.google.com","photos.google.com","translate.google.com",
    "youtube.com","www.youtube.com","m.youtube.com","music.youtube.com",
    "studio.youtube.com",
    "microsoft.com","www.microsoft.com","outlook.live.com","outlook.office.com",
    "office.com","www.office.com","teams.microsoft.com",
    "login.microsoftonline.com","portal.azure.com",
    "linkedin.com","www.linkedin.com",
    "twitter.com","x.com","facebook.com","www.facebook.com",
    "instagram.com","www.instagram.com","reddit.com","www.reddit.com",
    "old.reddit.com","tiktok.com","www.tiktok.com",
    "twitch.tv","www.twitch.tv","threads.net","www.threads.net",
    "developer.mozilla.org","npmjs.com","www.npmjs.com",
    "pypi.org","crates.io",
    "hcaptcha.com","www.hcaptcha.com","newassets.hcaptcha.com","js.hcaptcha.com","accounts.hcaptcha.com",
    "recaptcha.net","www.recaptcha.net","challenges.cloudflare.com",
    "netflix.com","www.netflix.com",
    "spotify.com","open.spotify.com","apple.com","www.apple.com",
    "wikipedia.org","en.wikipedia.org",
    "notion.so","www.notion.so","slack.com","app.slack.com",
    "trello.com","figma.com","www.figma.com","canva.com","www.canva.com",
    "virustotal.com","www.virustotal.com","urlscan.io",
    "any.run","app.any.run","threatfox.abuse.ch",
    "archive.org","web.archive.org",
    "stackoverflow.com","www.stackoverflow.com",
    "stackexchange.com","opendata.stackexchange.com",
    "superuser.com","serverfault.com","askubuntu.com",
    "stackapps.com","mathoverflow.net",
    "chrome.google.com","addons.mozilla.org","microsoftedge.microsoft.com",
    "extensions.gnome.org",
    "amazon.com","www.amazon.com","smile.amazon.com",
    "amazon.co.uk","www.amazon.co.uk","amazon.de","www.amazon.de",
    "amazon.ca","www.amazon.ca","amazon.co.jp","www.amazon.co.jp",
    "amazon.com.au","www.amazon.com.au","amazon.in","www.amazon.in",
    "amazon.fr","www.amazon.fr","amazon.it","www.amazon.it",
    "amazon.es","www.amazon.es",
    "ebay.com","www.ebay.com",
    "walmart.com","www.walmart.com",
    "target.com","www.target.com",
    "bestbuy.com","www.bestbuy.com",
    "paypal.com","www.paypal.com",
    "chase.com","www.chase.com",
    "bankofamerica.com","www.bankofamerica.com",
    "wellsfargo.com","www.wellsfargo.com",
    "cnn.com","www.cnn.com",
    "bbc.com","www.bbc.com","bbc.co.uk","www.bbc.co.uk",
    "nytimes.com","www.nytimes.com",
    "washingtonpost.com","www.washingtonpost.com",
    "bing.com","www.bing.com","cn.bing.com",
    "search.brave.com",
    "duckduckgo.com","www.duckduckgo.com",
    "search.yahoo.com","yahoo.com","www.yahoo.com",
    "yandex.com","yandex.ru",
    "ecosia.org","www.ecosia.org",
    "startpage.com","www.startpage.com",
    "baidu.com","www.baidu.com",
    "naver.com","www.naver.com",
    // --- DiTM Security ---
    "ditmsecurity.com", "www.ditmsecurity.com",
    // --- Security Vendors: EDR / XDR / Endpoint ---
    "crowdstrike.com", "www.crowdstrike.com",
    "sentinelone.com", "www.sentinelone.com",
    "cybereason.com", "www.cybereason.com",
    "carbonblack.com", "www.carbonblack.com",
    "cylance.com", "www.cylance.com",
    "malwarebytes.com", "www.malwarebytes.com",
    "sophos.com", "www.sophos.com",
    "trendmicro.com", "www.trendmicro.com",
    "mcafee.com", "www.mcafee.com",
    "norton.com", "www.norton.com",
    "kaspersky.com", "www.kaspersky.com",
    "bitdefender.com", "www.bitdefender.com",
    "eset.com", "www.eset.com",
    "fortinet.com", "www.fortinet.com",
    "paloaltonetworks.com", "www.paloaltonetworks.com",
    "checkpoint.com", "www.checkpoint.com",
    // --- Security Vendors: SIEM / SOAR / Analytics ---
    "splunk.com", "www.splunk.com",
    "elastic.co", "www.elastic.co",
    "ibm.com", "www.ibm.com",
    "exabeam.com", "www.exabeam.com",
    "logrhythm.com", "www.logrhythm.com",
    "sumologic.com", "www.sumologic.com",
    "datadog.com", "www.datadog.com",
    "dynatrace.com", "www.dynatrace.com",
    // --- Security Vendors: Email Security ---
    "proofpoint.com", "www.proofpoint.com",
    "mimecast.com", "www.mimecast.com",
    "abnormalsecurity.com", "www.abnormalsecurity.com",
    "barracuda.com", "www.barracuda.com",
    "cofense.com", "www.cofense.com",
    // --- Security Vendors: Cloud Security ---
    "zscaler.com", "www.zscaler.com",
    "netskope.com", "www.netskope.com",
    "wiz.io", "www.wiz.io",
    "lacework.com", "www.lacework.com",
    "orca.security",
    "snyk.io", "www.snyk.io",
    // --- Security Vendors: Network / Firewall ---
    "cisco.com", "www.cisco.com",
    "juniper.net", "www.juniper.net",
    "arista.com", "www.arista.com",
    // --- Security Vendors: Identity (corporate sites only, NOT login portals) ---
    "beyondtrust.com", "www.beyondtrust.com",
    "sailpoint.com", "www.sailpoint.com",
    "thalesgroup.com", "www.thalesgroup.com",
    // --- Security Vendors: Vuln Management ---
    "tenable.com", "www.tenable.com",
    "qualys.com", "www.qualys.com",
    "rapid7.com", "www.rapid7.com",
    // --- Security Vendors: Threat Intel ---
    "mandiant.com", "www.mandiant.com",
    "recordedfuture.com", "www.recordedfuture.com",
    "flashpoint.io", "www.flashpoint.io",
    "intel471.com", "www.intel471.com",
    "greynoise.io", "www.greynoise.io",
    "intezer.com", "www.intezer.com",
    "team-cymru.com", "www.team-cymru.com",
    // --- Security Vendors: Browser Security ---
    "pushsecurity.com", "www.pushsecurity.com",
    "island.io", "www.island.io",
    "talon-sec.com", "www.talon-sec.com",
    // --- Security Vendors: Consulting / Services ---
    "reliaquest.com", "www.reliaquest.com",
    "secureworks.com", "www.secureworks.com",
    "optiv.com", "www.optiv.com",
    "trustwave.com", "www.trustwave.com",
    // --- Security Vendors: Bug Bounty / Pentesting ---
    "hackerone.com", "www.hackerone.com",
    "bugcrowd.com", "www.bugcrowd.com",
    "cobalt.io", "www.cobalt.io",
    "synack.com", "www.synack.com",
    // --- Security Research / Analysis Tools ---
    "shodan.io", "www.shodan.io",
    "censys.io", "www.censys.io", "search.censys.io",
    "binaryedge.io", "www.binaryedge.io",
    "hybrid-analysis.com", "www.hybrid-analysis.com",
    "joesandbox.com", "www.joesandbox.com",
    "talosintelligence.com", "www.talosintelligence.com",
    "abuse.ch", "bazaar.abuse.ch", "feodotracker.abuse.ch",
    "malshare.com", "www.malshare.com",
    "otx.alienvault.com",
    "phishtank.org", "www.phishtank.org",
    "openphish.com", "www.openphish.com",
    "mxtoolbox.com", "www.mxtoolbox.com",
    "dnsdumpster.com",
    "securitytrails.com", "www.securitytrails.com",
    "crt.sh",
    // --- Security News / Blogs ---
    "thehackernews.com", "www.thehackernews.com",
    "bleepingcomputer.com", "www.bleepingcomputer.com",
    "krebsonsecurity.com",
    "darkreading.com", "www.darkreading.com",
    "securityweek.com", "www.securityweek.com",
    "therecord.media", "www.therecord.media",
    "threatpost.com", "www.threatpost.com",
    "schneier.com", "www.schneier.com",
    "sans.org", "www.sans.org",
    "infosecurity-magazine.com", "www.infosecurity-magazine.com",
    "csoonline.com", "www.csoonline.com",
    // --- Security Training / CTF ---
    "tryhackme.com", "www.tryhackme.com",
    "hackthebox.com", "www.hackthebox.com", "app.hackthebox.com",
    "portswigger.net", "www.portswigger.net",
    "pentesterlab.com", "www.pentesterlab.com",
    "cyberdefenders.org", "www.cyberdefenders.org",
    "letsdefend.io", "www.letsdefend.io",
    "attackiq.com", "www.attackiq.com",
    // --- Security Standards / Government ---
    "nist.gov", "www.nist.gov", "nvd.nist.gov",
    "cisa.gov", "www.cisa.gov",
    "cve.org", "www.cve.org",
    "mitre.org", "www.mitre.org", "attack.mitre.org",
    "owasp.org", "www.owasp.org",
    "first.org", "www.first.org",
    // --- Cloud Documentation ---
    "learn.microsoft.com",
    "cloud.google.com",
    "docs.aws.amazon.com",
    // --- Major SaaS ---
    "zoom.us", "www.zoom.us",
    "webex.com", "www.webex.com",
    "atlassian.com", "www.atlassian.com",
    "jira.atlassian.com", "confluence.atlassian.com",
    "asana.com", "www.asana.com",
    "monday.com", "www.monday.com",
    "airtable.com", "www.airtable.com",
    "hubspot.com", "www.hubspot.com",
    "salesforce.com", "www.salesforce.com",
    "zendesk.com", "www.zendesk.com",
    "freshdesk.com", "www.freshdesk.com",
    "intercom.com", "www.intercom.com",
    "grammarly.com", "www.grammarly.com",
    // --- Password Managers ---
    "1password.com", "www.1password.com",
    "bitwarden.com", "www.bitwarden.com",
    "lastpass.com", "www.lastpass.com",
    "dashlane.com", "www.dashlane.com",
    // --- VPN / Privacy ---
    "nordvpn.com", "www.nordvpn.com",
    "expressvpn.com", "www.expressvpn.com",
    "proton.me", "www.proton.me", "mail.proton.me",
    // --- Additional Commerce ---
    "costco.com", "www.costco.com",
    "homedepot.com", "www.homedepot.com",
    "lowes.com", "www.lowes.com",
    "macys.com", "www.macys.com",
    "nordstrom.com", "www.nordstrom.com",
    "kohls.com", "www.kohls.com",
    // --- Additional Banking / Finance ---
    "usbank.com", "www.usbank.com",
    "capitalone.com", "www.capitalone.com",
    "americanexpress.com", "www.americanexpress.com",
    "discover.com", "www.discover.com",
    "fidelity.com", "www.fidelity.com",
    "schwab.com", "www.schwab.com",
    "vanguard.com", "www.vanguard.com",
    "robinhood.com", "www.robinhood.com",
    "coinbase.com", "www.coinbase.com",
    "kraken.com", "www.kraken.com",
    "venmo.com", "www.venmo.com",
    "cash.app",
    // --- Streaming ---
    "hulu.com", "www.hulu.com",
    "disneyplus.com", "www.disneyplus.com",
    "max.com", "www.max.com",
    "peacocktv.com", "www.peacocktv.com",
    "paramountplus.com", "www.paramountplus.com",
    "crunchyroll.com", "www.crunchyroll.com",
    "primevideo.com", "www.primevideo.com",
    // --- Education ---
    "purdue.edu", "www.purdue.edu", "canvas.purdue.edu",
    "coursera.org", "www.coursera.org",
    "edx.org", "www.edx.org",
    "udemy.com", "www.udemy.com",
    "khanacademy.org", "www.khanacademy.org",
    // --- Travel / Airlines ---
    "united.com", "www.united.com",
    "delta.com", "www.delta.com",
    "aa.com", "www.aa.com",
    "southwest.com", "www.southwest.com",
    "airbnb.com", "www.airbnb.com",
    "booking.com", "www.booking.com",
    "expedia.com", "www.expedia.com",
    // --- Government / Utilities / Shipping ---
    "irs.gov", "www.irs.gov",
    "ssa.gov", "www.ssa.gov",
    "usps.com", "www.usps.com",
    "ups.com", "www.ups.com",
    "fedex.com", "www.fedex.com",
    "dhl.com", "www.dhl.com","forbes.com","www.forbes.com","reuters.com","www.reuters.com","apnews.com","www.apnews.com","bloomberg.com","www.bloomberg.com","cnbc.com","www.cnbc.com","foxnews.com","www.foxnews.com","nbcnews.com","www.nbcnews.com","abcnews.go.com","cbsnews.com","www.cbsnews.com","usatoday.com","www.usatoday.com","wsj.com","www.wsj.com","theguardian.com","www.theguardian.com","time.com","www.time.com","newsweek.com","www.newsweek.com","huffpost.com","www.huffpost.com","politico.com","www.politico.com","axios.com","www.axios.com","thehill.com","www.thehill.com","npr.org","www.npr.org","pbs.org","www.pbs.org","aljazeera.com","www.aljazeera.com","ft.com","www.ft.com","economist.com","www.economist.com","businessinsider.com","www.businessinsider.com","insider.com","www.insider.com","techcrunch.com","www.techcrunch.com","wired.com","www.wired.com","theverge.com","www.theverge.com","arstechnica.com","www.arstechnica.com","engadget.com","www.engadget.com","mashable.com","www.mashable.com","cnet.com","www.cnet.com","zdnet.com","www.zdnet.com","vice.com","www.vice.com","vox.com","www.vox.com","slate.com","www.slate.com","salon.com","www.salon.com","thedailybeast.com","www.thedailybeast.com","buzzfeed.com","www.buzzfeed.com","latimes.com","www.latimes.com","chicagotribune.com","www.chicagotribune.com","nypost.com","www.nypost.com","dailymail.co.uk","www.dailymail.co.uk","telegraph.co.uk","www.telegraph.co.uk","independent.co.uk","www.independent.co.uk","sky.com","news.sky.com","france24.com","www.france24.com","dw.com","www.dw.com","japantimes.co.jp","www.japantimes.co.jp","scmp.com","www.scmp.com","straitstimes.com","www.straitstimes.com","abc.net.au","www.abc.net.au","news.com.au","www.news.com.au","cbc.ca","www.cbc.ca","globalnews.ca","theatlantic.com","www.theatlantic.com","newyorker.com","www.newyorker.com","vanityfair.com","www.vanityfair.com","rollingstone.com","www.rollingstone.com","people.com","www.people.com","ew.com","www.ew.com","variety.com","www.variety.com","hollywoodreporter.com","www.hollywoodreporter.com","deadline.com","www.deadline.com","espn.com","www.espn.com","sports.yahoo.com","bleacherreport.com","www.bleacherreport.com","cbssports.com","www.cbssports.com","foxsports.com","www.foxsports.com","nba.com","www.nba.com","nfl.com","www.nfl.com","mlb.com","www.mlb.com","nhl.com","www.nhl.com","si.com","www.si.com","theathletic.com","www.theathletic.com","tomshardware.com","www.tomshardware.com","pcmag.com","www.pcmag.com","pcworld.com","www.pcworld.com","macrumors.com","www.macrumors.com","9to5mac.com","www.9to5mac.com","9to5google.com","www.9to5google.com","androidcentral.com","www.androidcentral.com","xda-developers.com","www.xda-developers.com","howtogeek.com","www.howtogeek.com","tomsguide.com","www.tomsguide.com","gizmodo.com","www.gizmodo.com","lifehacker.com","www.lifehacker.com","kotaku.com","www.kotaku.com","ign.com","www.ign.com","gamespot.com","www.gamespot.com","polygon.com","www.polygon.com","eurogamer.net","www.eurogamer.net","destructoid.com","www.destructoid.com","bild.de","www.bild.de","spiegel.de","www.spiegel.de","zeit.de","www.zeit.de","lemonde.fr","www.lemonde.fr","lefigaro.fr","www.lefigaro.fr","elpais.com","www.elpais.com","corriere.it","www.corriere.it","repubblica.it","www.repubblica.it","asahi.com","www.asahi.com","mainichi.jp","timesofindia.indiatimes.com","ndtv.com","www.ndtv.com","hindustantimes.com","www.hindustantimes.com","marketwatch.com","www.marketwatch.com","barrons.com","www.barrons.com","fool.com","www.fool.com","seekingalpha.com","www.seekingalpha.com","investopedia.com","www.investopedia.com","finance.yahoo.com","money.cnn.com","weather.com","www.weather.com","accuweather.com","www.accuweather.com","wunderground.com","www.wunderground.com","imdb.com","www.imdb.com","rottentomatoes.com","www.rottentomatoes.com","yelp.com","www.yelp.com","tripadvisor.com","www.tripadvisor.com","quora.com","www.quora.com","medium.com","www.medium.com","substack.com","www.substack.com","tumblr.com","www.tumblr.com","pinterest.com","www.pinterest.com","flickr.com","www.flickr.com","deviantart.com","www.deviantart.com","etsy.com","www.etsy.com","craigslist.org","www.craigslist.org","zillow.com","www.zillow.com","realtor.com","www.realtor.com","glassdoor.com","www.glassdoor.com","indeed.com","www.indeed.com","webmd.com","www.webmd.com","mayoclinic.org","www.mayoclinic.org","healthline.com","www.healthline.com","clevelandclinic.org","www.clevelandclinic.org","nih.gov","www.nih.gov","cdc.gov","www.cdc.gov","steampowered.com","store.steampowered.com","epicgames.com","www.epicgames.com","gog.com","www.gog.com","ea.com","www.ea.com","ubisoft.com","www.ubisoft.com","playstation.com","www.playstation.com","xbox.com","www.xbox.com","nintendo.com","www.nintendo.com","roblox.com","www.roblox.com","github.com","www.github.com","gitlab.com","www.gitlab.com","bitbucket.org","www.bitbucket.org","codepen.io","jsfiddle.net","replit.com","www.replit.com","vercel.com","www.vercel.com","netlify.com","www.netlify.com","heroku.com","www.heroku.com","digitalocean.com","www.digitalocean.com","linode.com","www.linode.com","cloudflare.com","www.cloudflare.com","aws.amazon.com","console.cloud.google.com","allrecipes.com","www.allrecipes.com","foodnetwork.com","www.foodnetwork.com","epicurious.com","www.epicurious.com","tasty.co","discord.com","www.discord.com","signal.org","www.signal.org","telegram.org","web.telegram.org","whatsapp.com","web.whatsapp.com","snapchat.com","www.snapchat.com","mastodon.social","bsky.app","carsonww.com","clickfix.carsonww.com","clickfixhunter.com","www.clickfixhunter.com"];

  function _isBuiltinWL(host) {
    const h = (host || "").toLowerCase();
    if (_BUILTIN_WL.includes(h)) return true;
    for (const entry of _BUILTIN_WL) {
      if (h.endsWith("." + entry)) return true;
    }
    return false;
  }

  // --- FAST PATH: if builtin-whitelisted, bail out immediately. No scanning, no hooks, nothing. ---
  const _currentHost = getHost();
  if (_isBuiltinWL(_currentHost)) return;

  // --- For user-whitelisted domains, we need an async check. ---
  // CRITICAL FIX: Do NOT start scanning until we know whether the site is whitelisted.
  // The old code fired sendPageThreat() synchronously while the CHECK_WHITELIST callback
  // was still pending, causing banners to flash on whitelisted sites.
  function _initAfterWhitelistCheck(isWhitelisted) {
    if (isWhitelisted) return; // bail entirely — no observers, no hooks, no scans
    _startClickArmor();
  }

  try {
    sendRuntimeMessage({ type: "CHECK_WHITELIST", host: _currentHost }).then((resp) => {
      if (resp === undefined || resp?.error) {
        setTimeout(() => {
          sendRuntimeMessage({ type: "CHECK_WHITELIST", host: _currentHost })
            .then(async (resp2) => {
              if (resp2 === undefined || resp2?.error) {
                _initAfterWhitelistCheck(await isLocallyWhitelisted(_currentHost));
                return;
              }
              _initAfterWhitelistCheck(resp2?.whitelisted === true);
            })
            .catch(async () => _initAfterWhitelistCheck(await isLocallyWhitelisted(_currentHost)));
        }, 150);
        return;
      }
      _initAfterWhitelistCheck(resp?.whitelisted === true);
    });
  } catch {
    isLocallyWhitelisted(_currentHost).then(_initAfterWhitelistCheck).catch(() => _startClickArmor());
  }

  // Return early — everything below is wrapped in _startClickArmor
  // which only runs if the site is NOT whitelisted.
  function _startClickArmor() {

  // --- Mid-session whitelist kill switch ---
  // If the user adds this domain to whitelist while the page is already open
  // (e.g. via popup or overlay button), kill all scanning immediately.
  // Without this, the content script keeps running until the tab is reloaded.
  let _killed = false;
  function _killAllScanning() {
    _killed = true;
    try { observer.disconnect(); } catch {}
    try { clearInterval(_heartbeatInterval); } catch {}
    try { clearTimeout(scanTimer); } catch {}
    // Remove any existing banner/overlay
    try { document.getElementById(DOM_IDS.bannerHost)?.remove(); } catch {}
    try { document.getElementById(DOM_IDS.overlayHost)?.remove(); } catch {}
  }

  try {
    chrome.storage.onChanged.addListener((changes, area) => {
      if (area !== "local" || (!changes.cg_whitelist && !changes.cg_temp_whitelist)) return;
      const host = _currentHost.toLowerCase();
      const hostNoWww = host.replace(/^www\./, "");
      const newList = (changes.cg_whitelist?.newValue || []).map(h => (h || "").toLowerCase());
      const tempEntries = Object.keys(changes.cg_temp_whitelist?.newValue || {}).map(h => (h || "").toLowerCase());
      if (
        newList.includes(host) ||
        newList.includes(hostNoWww) ||
        newList.some(e => host.endsWith("." + e)) ||
        tempEntries.includes(host) ||
        tempEntries.includes(hostNoWww) ||
        tempEntries.some(e => host.endsWith("." + e))
      ) {
        _killAllScanning();
      }
    });
  } catch {}

  const CG = {
    pageThreat: 0,
    adjustedThreshold: 60,
    signals: [],
    heightened: false,
    bannerShown: false,
    bannerDismissed: false, // persists across rescans — user explicitly dismissed
    overlayShown: false,
    sessionWrites: [], // for staged writes
    lastWriteAt: 0,
    scanCount: 0,       // track how many scans we've done
    lastScore: -1,       // track score stability for scan throttling
    stableCount: 0       // how many consecutive scans returned same score
  };

  const DOM_IDS = {
    overlayHost: "cg-" + Math.random().toString(36).slice(2),
    bannerHost: "cg-" + Math.random().toString(36).slice(2)
  };

  // Read the nonce set by clipboard-hook-early.js (CRIT-1)
  function getNonce() {
    try {
      const m = document.querySelector('meta[name="cg-nonce"]');
      return m ? m.getAttribute("content") : null;
    } catch { return null; }
  }
  const CG_NONCE = getNonce();

  function cssUrl(name) { return chrome.runtime.getURL(name); }

  function safeText(s) {
    // Strip null bytes, all control chars (U+0000-001F, U+007F-009F), and zero-width chars (HIGH-3d)
    return (s || "").toString()
      .replace(/[\u0000-\u001F\u007F-\u009F]/g, "")
      .replace(/[\u200B\u200C\u200D\u200E\u200F\uFEFF\u00AD\u2060\u2061-\u2064\u2066-\u2069\u061C]/g, "");
  }

  function localClipboardFallbackScore(inputText) {
    let sample = safeText(inputText || "");
    if (!sample || sample.trim().length < 8) return null;
    try { sample = sample.normalize("NFKD"); } catch {}
    sample = sample
      .replace(/[\u0300-\u036F]/g, "")
      .replace(/[\u2013\u2014\u2015\u2212\uFE58\uFE63\uFF0D]/g, "-");

    const rules = [
      { re: /mshta\s+https?:\/\//i, score: 100, label: "mshta remote HTA execution" },
      { re: /powershell[\s\S]*?\biex\b/i, score: 95, label: "PowerShell code execution (iex)" },
      { re: /powershell[\s\S]*?invoke-expression/i, score: 95, label: "PowerShell Invoke-Expression" },
      { re: /powershell[\s\S]*?(-enc\b|-encodedcommand|\s-e\s+[A-Za-z0-9+\/=]{20,})/i, score: 95, label: "Encoded PowerShell command" },
      { re: /powershell[\s\S]*?(invoke-webrequest|\biwr\b|irm|downloadfile|net\.webclient)/i, score: 85, label: "PowerShell downloader" },
      { re: /cmd[\s\S]*?(\/c|\/k)[\s\S]*?(powershell|mshta|curl|bitsadmin|certutil|regsvr32|rundll32)/i, score: 85, label: "cmd wrapper launching execution tool" },
      { re: /curl[\s\S]*?-o[\s\S]*?\.(bat|exe|cmd|ps1|vbs|msi)\b/i, score: 85, label: "curl downloading executable/script" },
      { re: /bitsadmin[\s\S]*?\/transfer[\s\S]*?https?:\/\//i, score: 90, label: "bitsadmin remote download" },
      { re: /certutil[\s\S]*?-urlcache[\s\S]*?https?:\/\//i, score: 90, label: "certutil URL cache download" },
      { re: /regsvr32[\s\S]*?https?:\/\//i, score: 90, label: "regsvr32 remote script registration" },
      { re: /nslookup[\s\S]*?\|[\s\S]*?(findstr|for\s+\/f)/i, score: 90, label: "nslookup DNS staging" }
    ];

    const matches = [];
    let score = 0;
    for (const rule of rules) {
      if (rule.re.test(sample)) {
        score = Math.max(score, rule.score);
        matches.push({ label: rule.label });
      }
    }
    if (/\b\d{1,3}(\.\d{1,3}){3}(:\d+)?\b/.test(sample)) {
      score = Math.max(score, Math.min(100, score + 15));
      matches.push({ label: "bare IP address" });
    }
    if (!matches.length || score < 60) return null;
    return {
      ok: true,
      action: "block",
      verdict: "malicious",
      score,
      threshold: 25,
      matches,
      ctx: { signals: CG.signals || [] }
    };
  }

  async function clearClipboard() {
    try {
      await navigator.clipboard.writeText("");
      return true;
    } catch {
      try {
        const ta = document.createElement("textarea");
        ta.value = "";
        ta.style.position = "fixed";
        ta.style.top = "-9999px";
        document.documentElement.appendChild(ta);
        ta.focus();
        ta.select();
        document.execCommand("copy");
        ta.remove();
        return true;
      } catch {
        return false;
      }
    }
  }

  // Inline CSS strings to avoid web_accessible_resources fingerprinting (MED-2)
  const WARNING_CSS = `/* warning.css v2 — DiTM brand */
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Outfit:wght@300;400;500;600;700;800&display=swap');
.cg-overlay{position:fixed;inset:0;z-index:2147483647;display:flex;align-items:center;justify-content:center;background:rgba(0,0,0,.6);backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px);padding:24px;font-family:'Outfit',ui-sans-serif,system-ui,-apple-system,'Segoe UI',Roboto,Arial,sans-serif}
.cg-card{width:min(740px,94vw);max-height:92vh;overflow:auto;background:#f5f5f0;border:1px solid #d0cfc8;border-radius:16px;box-shadow:0 40px 80px rgba(0,0,0,.4);background-image:linear-gradient(rgba(0,0,0,.03) 1px,transparent 1px),linear-gradient(90deg,rgba(0,0,0,.03) 1px,transparent 1px);background-size:40px 40px;background-color:#f5f5f0}
.cg-header{padding:22px 28px;display:flex;align-items:center;gap:14px;border-bottom:2px solid #ff3366;background:#f5f5f0}
.cg-logo{width:36px;height:36px;min-width:36px;flex-shrink:0}
h1{margin:0 0 4px;font-size:17px;font-weight:700;color:#111;letter-spacing:-.3px;font-family:'Outfit',sans-serif}
.cg-sub{margin:0;color:#555550;font-size:12px;line-height:1.45}
.cg-body{padding:22px 28px}
.cg-section{margin-top:16px}
.cg-section-title{font-family:'JetBrains Mono',monospace;font-size:10px;text-transform:uppercase;letter-spacing:2px;color:#888880;margin-bottom:8px;font-weight:500}
.cg-code{margin:0;background:#111;border:1px solid #222;color:#ff6b8a;border-radius:10px;padding:14px;font-family:'JetBrains Mono',monospace;font-size:11px;overflow:auto;white-space:pre-wrap;word-break:break-word;max-height:100px;line-height:1.6}
.cg-row{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px;margin-top:16px}
.cg-metric{background:#eeede8;border:1px solid #d0cfc8;border-radius:10px;padding:12px}
.cg-metric__k{font-family:'JetBrains Mono',monospace;font-size:10px;color:#888880;margin-bottom:4px;text-transform:uppercase;letter-spacing:1.5px}
.cg-metric__v{font-family:'JetBrains Mono',monospace;font-size:16px;color:#111;font-weight:700;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.cg-metric__v--danger{color:#ff3366}
.cg-chips{display:flex;flex-wrap:wrap;gap:6px}
.cg-chip{font-family:'JetBrains Mono',monospace;font-size:10px;font-weight:600;border-radius:6px;padding:5px 12px;letter-spacing:.3px;background:rgba(255,51,102,.1);color:#ff3366;border:1px solid rgba(255,51,102,.2)}
.cg-chip--muted{background:#eeede8;color:#888880;border:1px solid #d0cfc8}
.cg-actions{display:flex;flex-wrap:wrap;gap:10px;padding:0 28px 22px}
.cg-btn{font-family:'JetBrains Mono',monospace;padding:12px 22px;border-radius:8px;font-size:12px;font-weight:600;cursor:pointer;border:1px solid transparent;transition:all .2s;letter-spacing:.3px}
.cg-btn:hover{transform:translateY(-1px)}
.cg-btn--primary{background:#ff3366;border-color:#ff3366;color:#fff}
.cg-btn--primary:hover{background:#e6294f;box-shadow:0 8px 30px rgba(255,51,102,.25)}
.cg-btn--secondary{background:transparent;color:#555550;border-color:#aaa}
.cg-btn--secondary:hover{border-color:#555550}
.cg-btn--ghost{background:transparent;color:#888880;border-color:#d0cfc8}
.cg-btn--ghost:hover{color:#555550}
.cg-foot{padding:0 28px 18px;color:#888880;font-size:11px}`

  const BANNER_CSS = `/* banner.css v2 — DiTM brand */
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Outfit:wght@300;400;500;600;700;800&display=swap');
.cg-banner{position:fixed;top:0;left:0;right:0;z-index:2147483647;background:#f5f5f0;color:#111;border-bottom:2px solid #ff3366;font-family:'Outfit',ui-sans-serif,system-ui,-apple-system,'Segoe UI',Roboto,Arial,sans-serif;box-shadow:0 4px 20px rgba(0,0,0,.12);animation:cgSlide .25s ease-out;background-image:linear-gradient(rgba(0,0,0,.025) 1px,transparent 1px),linear-gradient(90deg,rgba(0,0,0,.025) 1px,transparent 1px);background-size:40px 40px;background-color:#f5f5f0}
@keyframes cgSlide{from{transform:translateY(-100%)}to{transform:translateY(0)}}
.cg-banner__inner{display:flex;gap:14px;align-items:center;justify-content:space-between;padding:10px 18px;max-width:1200px;margin:0 auto}
.cg-banner__msg{display:flex;gap:10px;align-items:center;font-size:13px;line-height:1.3}
.cg-badge{font-family:'JetBrains Mono',monospace;display:inline-flex;align-items:center;gap:6px;font-weight:700;font-size:11px;color:#ff3366;letter-spacing:1px}
.cg-banner__actions{display:flex;gap:8px;align-items:center;flex-shrink:0;flex-wrap:wrap}
.cg-btn{font-family:'JetBrains Mono',monospace;padding:7px 14px;border-radius:6px;font-size:11px;font-weight:600;cursor:pointer;border:1px solid transparent;transition:all .15s;white-space:nowrap;letter-spacing:.3px}
.cg-btn--safety{background:#ff3366;color:#fff;border-color:#ff3366}
.cg-btn--safety:hover{background:#e6294f;box-shadow:0 4px 16px rgba(255,51,102,.25)}
.cg-btn--report{background:transparent;color:#555550;border-color:#d0cfc8}
.cg-btn--report:hover{border-color:#555550}
.cg-btn--ghost{background:transparent;color:#888880;border:none;font-size:11px}
.cg-btn--ghost:hover{color:#555550}
.cg-banner__more{padding:0 18px 14px;max-width:1200px;margin:0 auto}
.cg-more-title{font-family:'JetBrains Mono',monospace;font-size:10px;font-weight:700;color:#888880;text-transform:uppercase;letter-spacing:2px;margin-bottom:8px}
.cg-more-list{margin:0;padding:0;list-style:none;display:flex;flex-wrap:wrap;gap:5px}
.cg-more-list li{font-family:'JetBrains Mono',monospace;font-size:10px;padding:4px 10px;border-radius:5px;background:rgba(255,51,102,.1);border:1px solid rgba(255,51,102,.18);color:#ff3366;font-weight:600;letter-spacing:.3px}
.cg-more-note{margin-top:10px;font-size:11px;color:#888880}`

  function injectShadowUI(kind, html, cssText) {
    const hostId = kind === "overlay" ? DOM_IDS.overlayHost : DOM_IDS.bannerHost;
    if (document.getElementById(hostId)) return;

    const host = document.createElement("div");
    host.id = hostId;
    // No data-clickguard attribute — reduces fingerprinting (MED-3)
    const shadow = host.attachShadow({ mode: "closed" });

    // Inline CSS via <style> instead of <link> — no web_accessible_resources needed (MED-2)
    const style = document.createElement("style");
    style.textContent = cssText;

    const wrapper = document.createElement("div");
    wrapper.innerHTML = html;

    shadow.appendChild(style);
    shadow.appendChild(wrapper);

    document.documentElement.appendChild(host);
    return { host, shadow };
  }

  function collectBannerBrands(details) {
    const brands = new Set();
    try {
      if (_detectedPageBrand?.brand) brands.add(_detectedPageBrand.brand);
    } catch {}
    try {
      const pageBrand = _detectPageBrand();
      if (pageBrand?.brand) brands.add(pageBrand.brand);
    } catch {}
    for (const sig of (details?.signals || [])) {
      const label = String(sig?.label || "");
      const match = label.match(/^([A-Za-z0-9&.' -]+) impersonation on /i);
      if (match && match[1]) brands.add(match[1].trim());
    }
    return [...brands].filter(Boolean);
  }

  function inferBannerPresentation(details) {
    const signals = details?.signals || [];
    const labels = signals.map(s => String(s?.label || ""));
    const combined = labels.join(" || ");
    const brands = collectBannerBrands(details);
    const hasBrandImpersonation = brands.length > 0 || /impersonat/i.test(combined);
    const hasAiTM = signals.some(s => s?.layer === "aitm") ||
      /(^|[^a-z])aitm([^a-z]|$)|adversary.?in.?the.?middle|device code|verification code|login relay|mfa|otp|workers\.dev|serverless branded host|encrypted aes-gcm payload bootstrap|redirect laundering/i.test(combined);

    let bannerType = details?.bannerType || "clickfix";
    let bannerMsg = details?.message || "This page shows signs of a social engineering (ClickFix) attack. Be cautious of instructions to copy/paste commands.";

    if (!details?.message) {
      if (hasAiTM && hasBrandImpersonation) {
        const brandText = brands.length ? ` targeting ${brands.slice(0, 2).join(" / ")}` : "";
        bannerType = "brand-aitm";
        bannerMsg = `This page shows signs of brand impersonation and adversary-in-the-middle (AiTM) phishing${brandText}. Do not copy codes, continue sign-in, or authenticate through this page.`;
      } else if (hasAiTM) {
        bannerType = "aitm";
        bannerMsg = "This page shows signs of adversary-in-the-middle (AiTM) phishing. Do not copy verification codes or continue sign-in through this page.";
      } else if (hasBrandImpersonation) {
        const brandText = brands.length ? ` targeting ${brands.slice(0, 2).join(" / ")}` : "";
        bannerType = "brand";
        bannerMsg = `This page shows signs of brand impersonation phishing${brandText}. Verify the domain before entering credentials or opening protected content.`;
      }
    }

    return { bannerType, bannerMsg };
  }

  function showBanner(details) {
    if (_killed) return; // whitelist kill switch — no banners after user whitelisted
    if (CG.bannerShown || CG.bannerDismissed) return;
    CG.bannerShown = true;

    const signals = (details?.signals || []).slice(0, 8).map(s => `<li>${escapeHtml(s.label)}</li>`).join("");
    const presentation = inferBannerPresentation(details);
    const bannerType = presentation.bannerType; // "clickfix" | "blocklist" | "form" | "aitm" | "brand" | "brand-aitm"
    const bannerMsg = presentation.bannerMsg;

    const html = `
      <div class="cg-banner">
        <div class="cg-banner__inner">
          <div class="cg-banner__msg">
            <span class="cg-badge"><svg viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg" style="width:24px;height:24px"><polygon points="16,2 28,9 28,23 16,30 4,23 4,9" fill="#111" stroke="#111" stroke-width="0.5"/><line x1="4" y1="20" x2="13" y2="16" stroke="#f5f5f0" stroke-width="1.1" stroke-linecap="round"/><line x1="19" y1="16" x2="28" y2="20" stroke="#f5f5f0" stroke-width="1.1" stroke-linecap="round"/><circle cx="4" cy="20" r="1.8" fill="#f5f5f0"/><circle cx="28" cy="20" r="1.8" fill="#f5f5f0"/><path d="M13,16 Q16,11 19,16 Q16,21 13,16 Z" fill="none" stroke="#f5f5f0" stroke-width="1.1"/><ellipse cx="16" cy="16" rx="4" ry="2.2" fill="none" stroke="#f5f5f0" stroke-width="0.7" opacity="0.35"/><circle cx="16" cy="16" r="1.8" fill="none" stroke="#f5f5f0" stroke-width="0.9"/><circle cx="16" cy="16" r="0.9" fill="#f5f5f0"/><line x1="16" y1="2" x2="16" y2="12.5" stroke="#f5f5f0" stroke-width="0.9" stroke-linecap="round" stroke-dasharray="2 1.5" opacity="0.55"/><polygon points="16,12.5 14.5,9.5 17.5,9.5" fill="#f5f5f0" opacity="0.55"/></svg> ClickArmor V2</span>
            <span>${escapeHtml(bannerMsg)}</span>
          </div>
          <div class="cg-banner__actions">
            <button class="cg-btn cg-btn--safety" id="cgSafety">Take me to safety</button>
            <button class="cg-btn cg-btn--report" id="cgReport">Report this website</button>
            <button class="cg-btn" id="cgBannerWhitelist">Whitelist this site</button>
            <button class="cg-btn cg-btn--ghost" id="cgMore">More info</button>
            <button class="cg-btn" id="cgDismiss">Dismiss</button>
          </div>
        </div>
        <div class="cg-banner__more" id="cgMoreBox" hidden>
          <div class="cg-more-title">Signals detected</div>
          <ul class="cg-more-list">${signals || "<li>(none)</li>"}</ul>
          <div class="cg-more-note">Heightened mode remains active for this page session.</div>
        </div>
      </div>
    `;
    const ui = injectShadowUI("banner", html, BANNER_CSS);
    if (!ui) return;

    // Signal for automated testing — confirms banner is in the DOM
    try { document.documentElement.dataset.cgBannerShown = bannerType; } catch {}
    const btnMore = ui.shadow.querySelector("#cgMore");
    const btnDismiss = ui.shadow.querySelector("#cgDismiss");
    const btnSafety = ui.shadow.querySelector("#cgSafety");
    const btnReport = ui.shadow.querySelector("#cgReport");
    const btnBannerWhitelist = ui.shadow.querySelector("#cgBannerWhitelist");
    const moreBox = ui.shadow.querySelector("#cgMoreBox");

    if (btnDismiss) btnDismiss.addEventListener("click", () => {
      CG.bannerDismissed = true; // persist across rescans — never show again this session
      ui.host.remove();
    });
    if (btnMore && moreBox) btnMore.addEventListener("click", () => {
      moreBox.hidden = !moreBox.hidden;
    });
      if (btnBannerWhitelist) btnBannerWhitelist.addEventListener("click", () => {
        whitelistCurrentHost().then(() => {
          _killAllScanning();
          CG.bannerDismissed = true;
          ui.host.remove();
        }).catch(() => {
          _killAllScanning();
          sendRuntimeMessage({ type: "ADD_WHITELIST", host: getHost() }).then(() => {});
          CG.bannerDismissed = true;
          ui.host.remove();
        });
      });

    // Take me to safety: navigate back if possible, otherwise go to about:blank
    if (btnSafety) btnSafety.addEventListener("click", () => {
      CG.bannerDismissed = true;
      ui.host.remove();
      if (history.length > 1) {
        try { history.back(); } catch {}
      } else {
        try { location.replace("about:blank"); } catch {}
      }
    });

    // Report this website: 1-click silent submit to Google Form
    // TODO: Replace GOOGLE_FORM_ID and GOOGLE_FORM_ENTRY_ID with your actual values.
    //   1. Create a Google Form with one short-answer field
    //   2. Click ⋮ → "Get pre-filled link" → fill any value → "Get link"
    //   3. URL will look like: https://docs.google.com/forms/d/e/FORM_ID/viewform?usp=pp_url&entry.ENTRY_ID=test
    //   4. Copy FORM_ID and ENTRY_ID below
    const _REPORT_FORM_ID = "1FAIpQLSfYiCdgqFjuJTjNiiaVLv-HJMDVpWUf_jdOSkxI53g8qEaERw";
    const _REPORT_ENTRY_ID = "1270056904";
    if (btnReport) btnReport.addEventListener("click", () => {
      const reportDomain = getHost();
      const reportUrl = location.href;
      const reportTime = new Date().toISOString();
      const reportType = bannerType === "blocklist"
        ? "blocklist"
        : bannerType === "form"
        ? "form"
        : bannerType === "aitm"
        ? "aitm"
        : bannerType === "brand"
        ? "brand_impersonation"
        : bannerType === "brand-aitm"
        ? "brand_impersonation_aitm"
        : "clickfix";
      const payload = `${reportDomain} | ${reportUrl} | ${reportType} | ${reportTime}`;
      const formUrl = `https://docs.google.com/forms/d/e/${_REPORT_FORM_ID}/formResponse`;
      const body = new URLSearchParams();
      body.append(`entry.${_REPORT_ENTRY_ID}`, payload);
      try {
        fetch(formUrl, { method: "POST", body, mode: "no-cors" }).catch(() => {});
      } catch {}
      btnReport.textContent = "Reported!";
      btnReport.disabled = true;
      setTimeout(() => { btnReport.textContent = "Report this website"; btnReport.disabled = false; }, 2500);
    });
  }

  function escapeHtml(s) {
    return (s || "").toString()
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");
  }

  // Upgrade an existing auto-escalate overlay with the real clipboard payload
  function upgradeOverlay(payload, decision) {
    try {
      const host = document.getElementById(DOM_IDS.overlayHost);
      if (!host) return false;
      const shadow = CG._overlayShadow;
      if (!shadow) return false;
      const pre = shadow.querySelector(".cg-code");
      if (pre) pre.textContent = (payload || "").slice(0, 800);
      const chipsEl = shadow.querySelectorAll(".cg-chips")[0];
      if (chipsEl && decision?.matches?.length) {
        chipsEl.innerHTML = (decision.matches || []).slice(0, 10)
          .map(m => '<span class="cg-chip">' + escapeHtml(m.label) + '</span>').join("");
      }
      const metricV = shadow.querySelectorAll(".cg-metric__v");
      if (metricV[0] && decision?.score != null) metricV[0].textContent = decision.score + "/100";
      CG.overlayFromHook = true;
      return true;
    } catch { return false; }
  }

  function isOfficialAiTMIdentityHost(host) {
    const normalized = String(host || "").toLowerCase();
    if (!normalized) return false;
    const officialDomains = [
      "microsoft.com",
      "microsoftonline.com",
      "live.com",
      "office.com",
      "google.com",
      "gstatic.com",
      "okta.com",
      "oktapreview.com",
      "okta-emea.com",
      "auth0.com"
    ];
    if (officialDomains.some(domain => normalized === domain || normalized.endsWith("." + domain))) return true;
    try { return isOfficialBrandHost(normalized); } catch {}
    return false;
  }

  function shouldAutoBlockAiTMPage(layers) {
    const host = getHost();
    if (!host || isOfficialAiTMIdentityHost(host)) return null;

    const aitmScore = Number(layers?.aitm?.score || 0);
    if (aitmScore < 60) return null;

    const signals = [
      ...(layers?.aitm?.signals || []),
      ...(CG.signals || []).filter(s => s?.layer === "aitm")
    ];
    const labels = signals.map(s => String(s?.label || ""));
    const combined = labels.join(" || ");
    const brands = collectBannerBrands({ signals });

    const hasBrandImpersonation = brands.length > 0 || /impersonat/i.test(combined);
    if (!hasBrandImpersonation) return null;

    const activeRelaySignals = labels.filter(label =>
      /device-code phishing ui|device-code relay polling kit|login relay ui|official .* auth assets referenced from non-official credential flow|credential \+ otp collection|suspicious mfa relay|proxied idp login assets embedded|encrypted aes-gcm payload bootstrap|serverless branded host \+ login relay indicators/i.test(label)
    );

    if (activeRelaySignals.length === 0) return null;

    return {
      score: aitmScore,
      brands,
      signals,
      labels,
      title: brands.length
        ? "ClickArmor V2 blocked a brand impersonation + AiTM phishing page"
        : "ClickArmor V2 blocked an AiTM phishing page",
      subtitle: brands.length
        ? `This page appears to impersonate ${brands.slice(0, 2).join(" / ")} on an attacker-controlled domain and relay authentication or harvest session access. Do not copy codes or continue sign-in from this page.`
        : "This page appears to relay authentication through an attacker-controlled domain. Do not copy codes or continue sign-in from this page."
    };
  }

  function showAiTMThreatOverlay(context) {
    if (_killed) return;
    if (CG.overlayShown) return;
    CG.overlayShown = true;

    const matched = (context?.signals || []).slice(0, 10).map(m => `<span class="cg-chip">${escapeHtml(m.label || "")}</span>`).join("");
    const brandText = (context?.brands || []).length
      ? escapeHtml(context.brands.slice(0, 3).join(" / "))
      : "Unknown";

    const html = `
      <div class="cg-overlay">
        <div class="cg-card" role="dialog" aria-modal="true">
          <div class="cg-header">
            <div class="cg-logo"><svg viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg" style="width:36px;height:36px"><polygon points="16,2 28,9 28,23 16,30 4,23 4,9" fill="#111" stroke="#111" stroke-width="0.5"/><line x1="4" y1="20" x2="13" y2="16" stroke="#f5f5f0" stroke-width="1.1" stroke-linecap="round"/><line x1="19" y1="16" x2="28" y2="20" stroke="#f5f5f0" stroke-width="1.1" stroke-linecap="round"/><circle cx="4" cy="20" r="1.8" fill="#f5f5f0"/><circle cx="28" cy="20" r="1.8" fill="#f5f5f0"/><path d="M13,16 Q16,11 19,16 Q16,21 13,16 Z" fill="none" stroke="#f5f5f0" stroke-width="1.1"/><ellipse cx="16" cy="16" rx="4" ry="2.2" fill="none" stroke="#f5f5f0" stroke-width="0.7" opacity="0.35"/><circle cx="16" cy="16" r="1.8" fill="none" stroke="#f5f5f0" stroke-width="0.9"/><circle cx="16" cy="16" r="0.9" fill="#f5f5f0"/><line x1="16" y1="2" x2="16" y2="12.5" stroke="#f5f5f0" stroke-width="0.9" stroke-linecap="round" stroke-dasharray="2 1.5" opacity="0.55"/><polygon points="16,12.5 14.5,9.5 17.5,9.5" fill="#f5f5f0" opacity="0.55"/></svg></div>
            <div>
              <h1>${escapeHtml(context?.title || "ClickArmor V2 blocked an AiTM phishing page")}</h1>
              <p class="cg-sub">${escapeHtml(context?.subtitle || "")}</p>
            </div>
          </div>
          <div class="cg-body">
            <div class="cg-row">
              <div class="cg-metric"><div class="cg-metric__k">Confidence</div><div class="cg-metric__v cg-metric__v--danger">${escapeHtml(String(context?.score ?? "?"))}/100</div></div>
              <div class="cg-metric"><div class="cg-metric__k">Impersonating</div><div class="cg-metric__v">${brandText}</div></div>
              <div class="cg-metric"><div class="cg-metric__k">Site</div><div class="cg-metric__v">${escapeHtml(getHost())}</div></div>
            </div>

            <div class="cg-section">
              <div class="cg-section-title">Why this page was blocked</div>
              <div class="cg-chips">${matched || "<span class='cg-chip cg-chip--muted'>(none)</span>"}</div>
            </div>
          </div>
          <div class="cg-actions">
            <button class="cg-btn cg-btn--primary" id="cgLeave">Leave this site</button>
            <button class="cg-btn cg-btn--secondary" id="cgWhitelist">I trust this site — whitelist</button>
            <button class="cg-btn cg-btn--ghost" id="cgContinue">Continue anyway</button>
          </div>
          <p class="cg-foot">
            Tip: real identity flows do not ask you to complete Microsoft or Google authentication from lookalike domains like this.
          </p>
        </div>
      </div>
    `;

    const ui = injectShadowUI("overlay", html, WARNING_CSS);
    if (!ui) return;
    CG._overlayShadow = ui.shadow;

    try {
      document.documentElement.dataset.cgOverlayShown = "true";
      document.documentElement.dataset.cgOverlayType = "aitm-brand";
    } catch {}

    ui.host.style.all = "initial";
    ui.host.style.position = "fixed";
    ui.host.style.inset = "0";
    ui.host.style.zIndex = "2147483647";

    const btnLeave = ui.shadow.querySelector("#cgLeave");
    const btnWhitelist = ui.shadow.querySelector("#cgWhitelist");
    const btnContinue = ui.shadow.querySelector("#cgContinue");

    let _userDismissed = false;
    const mo = new MutationObserver(() => {
      if (_userDismissed) return;
      if (!document.getElementById(DOM_IDS.overlayHost)) {
        mo.disconnect();
        CG.overlayShown = false;
      }
    });
    mo.observe(document.documentElement, { childList: true });

    if (btnLeave) btnLeave.addEventListener("click", () => {
      _userDismissed = true;
      mo.disconnect();
      try { history.back(); } catch {}
      try { window.close(); } catch {}
      try { location.replace("about:blank"); } catch {}
    });
    if (btnWhitelist) btnWhitelist.addEventListener("click", () => {
      whitelistCurrentHost().then(() => {
        _userDismissed = true;
        mo.disconnect();
        _killAllScanning();
        ui.host.remove();
      }).catch(() => {
        _userDismissed = true;
        mo.disconnect();
        _killAllScanning();
        sendRuntimeMessage({ type: "ADD_WHITELIST", host: getHost() }).then(() => {});
        ui.host.remove();
      });
    });
    if (btnContinue) btnContinue.addEventListener("click", () => {
      _userDismissed = true;
      mo.disconnect();
      ui.host.remove();
    });
  }

  function showOverlay(payload, decision) {
    if (_killed) return; // whitelist kill switch
    if (CG.overlayShown) return;
    CG.overlayShown = true;

    const cmd = escapeHtml((payload || "").slice(0, 800));
    const matched = (decision?.matches || []).slice(0, 10).map(m => `<span class="cg-chip">${escapeHtml(m.label)}</span>`).join("");
    const pageSignals = (decision?.ctx?.signals || []).slice(0, 8).map(s => `<span class="cg-chip cg-chip--muted">${escapeHtml(s.label)}</span>`).join("");

    const html = `
      <div class="cg-overlay">
        <div class="cg-card" role="dialog" aria-modal="true">
          <div class="cg-header">
            <div class="cg-logo"><svg viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg" style="width:36px;height:36px"><polygon points="16,2 28,9 28,23 16,30 4,23 4,9" fill="#111" stroke="#111" stroke-width="0.5"/><line x1="4" y1="20" x2="13" y2="16" stroke="#f5f5f0" stroke-width="1.1" stroke-linecap="round"/><line x1="19" y1="16" x2="28" y2="20" stroke="#f5f5f0" stroke-width="1.1" stroke-linecap="round"/><circle cx="4" cy="20" r="1.8" fill="#f5f5f0"/><circle cx="28" cy="20" r="1.8" fill="#f5f5f0"/><path d="M13,16 Q16,11 19,16 Q16,21 13,16 Z" fill="none" stroke="#f5f5f0" stroke-width="1.1"/><ellipse cx="16" cy="16" rx="4" ry="2.2" fill="none" stroke="#f5f5f0" stroke-width="0.7" opacity="0.35"/><circle cx="16" cy="16" r="1.8" fill="none" stroke="#f5f5f0" stroke-width="0.9"/><circle cx="16" cy="16" r="0.9" fill="#f5f5f0"/><line x1="16" y1="2" x2="16" y2="12.5" stroke="#f5f5f0" stroke-width="0.9" stroke-linecap="round" stroke-dasharray="2 1.5" opacity="0.55"/><polygon points="16,12.5 14.5,9.5 17.5,9.5" fill="#f5f5f0" opacity="0.55"/></svg></div>
            <div>
              <h1>ClickArmor V2 blocked a suspicious clipboard attack</h1>
              <p class="cg-sub">This site attempted to copy a command that looks like a ClickFix payload.</p>
            </div>
          </div>
          <div class="cg-body">
          <div class="cg-section">
            <div class="cg-section-title">Blocked command (truncated)</div>
            <pre class="cg-code">${cmd || "(empty)"}</pre>
          </div>

          <div class="cg-row">
            <div class="cg-metric"><div class="cg-metric__k">Confidence</div><div class="cg-metric__v cg-metric__v--danger">${decision?.score ?? "?"}/100</div></div>
            <div class="cg-metric"><div class="cg-metric__k">Threshold</div><div class="cg-metric__v">${decision?.threshold ?? "?"}</div></div>
            <div class="cg-metric"><div class="cg-metric__k">Site</div><div class="cg-metric__v">${escapeHtml(getHost())}</div></div>
          </div>

          <div class="cg-section">
            <div class="cg-section-title">Matched patterns</div>
            <div class="cg-chips">${matched || "<span class='cg-chip cg-chip--muted'>(none)</span>"}</div>
          </div>

          <div class="cg-section">
            <div class="cg-section-title">Page signals</div>
            <div class="cg-chips">${pageSignals || "<span class='cg-chip cg-chip--muted'>(none)</span>"}</div>
          </div>

          </div><!-- end cg-body -->
          <div class="cg-actions">
            <button class="cg-btn cg-btn--primary" id="cgLeave">Leave this site</button>
            <button class="cg-btn cg-btn--secondary" id="cgWhitelist">I trust this site — whitelist</button>
            <button class="cg-btn cg-btn--ghost" id="cgContinue">Continue anyway</button>
          </div>

          <p class="cg-foot">
            Tip: legitimate sites rarely ask you to paste commands into Run/Terminal/PowerShell.
          </p>
        </div>
      </div>
    `;

    const ui = injectShadowUI("overlay", html, WARNING_CSS);
    if (!ui) return;
    CG._overlayShadow = ui.shadow;

    // Signal for automated testing — confirms overlay is in the DOM
    try { document.documentElement.dataset.cgOverlayShown = "true"; } catch {}

    // prevent underlying interactions
    ui.host.style.all = "initial";
    ui.host.style.position = "fixed";
    ui.host.style.inset = "0";
    ui.host.style.zIndex = "2147483647";

    // Attach click listeners INSIDE the shadow (closed shadow hides composedPath from outside)
    const btnLeave = ui.shadow.querySelector("#cgLeave");
    const btnWhitelist = ui.shadow.querySelector("#cgWhitelist");
    const btnContinue = ui.shadow.querySelector("#cgContinue");

    // Anti-tamper: reinject with exponential backoff if removed (MED-3)
    let _tamperRetries = 0;
    const MAX_TAMPER_RETRIES = 5;
    let _userDismissed = false;
    const mo = new MutationObserver(() => {
      if (_userDismissed) return;
      if (!document.getElementById(DOM_IDS.overlayHost)) {
        if (_tamperRetries < MAX_TAMPER_RETRIES) {
          _tamperRetries++;
          CG.overlayShown = false;
          setTimeout(() => showOverlay(payload, decision), Math.pow(2, _tamperRetries) * 100);
        } else {
          mo.disconnect();
          CG.overlayShown = false;
        }
      }
    });
    mo.observe(document.documentElement, { childList: true });

    if (btnLeave) btnLeave.addEventListener("click", () => {
      _userDismissed = true;
      mo.disconnect();
      try { history.back(); } catch {}
      try { window.close(); } catch {}
    });
      if (btnWhitelist) btnWhitelist.addEventListener("click", () => {
        whitelistCurrentHost().then(() => {
          _userDismissed = true;
          mo.disconnect();
          _killAllScanning();
          ui.host.remove();
        }).catch(() => {
          _userDismissed = true;
          mo.disconnect();
          _killAllScanning();
          sendRuntimeMessage({ type: "ADD_WHITELIST", host: getHost() }).then(() => {});
          ui.host.remove();
        });
      });
    if (btnContinue) btnContinue.addEventListener("click", () => {
      _userDismissed = true;
      mo.disconnect();
      ui.host.remove();
    });
  }

  async function sendPageThreat() {
    if (_killed) return;
    if (isSharePointHost() && !hasSharePointPhishSignal()) {
      CG.pageThreat = 0;
      CG.adjustedThreshold = 60;
      CG.signals = [];
      CG.heightened = false;
      CG.scanCount++;
      CG.platformBudgetMode = true;
      try { document.documentElement.dataset.cgPageThreat = "0"; } catch {}
      sendRuntimeMessage({
        type: "PAGE_THREAT",
        pageThreat: 0,
        adjustedThreshold: 60,
        signals: []
      }).then(() => {});
      return;
    }
    const useMsBudgetMode = shouldUseMicrosoftBudgetMode();
    const budgetTextSample = useMsBudgetMode ? collectBudgetTextSample() : "";
    const bodyText = useMsBudgetMode ? budgetTextSample : (document.body?.innerText || "");
    // Also grab textContent which includes display:none / hidden elements
    // (catches progressive-reveal attacks where malicious steps are initially hidden)
    const hiddenText = useMsBudgetMode ? budgetTextSample : (document.body?.textContent || "");
    const zeroLayer = { score: 0, signals: [] };

    // If the banner was previously shown but got destroyed (e.g. C2 script replaced the DOM),
    // reset the flag so it can be re-injected on the next qualifying scan
    // BUT: if user explicitly dismissed, never re-show (bannerDismissed persists)
    if (CG.bannerShown && !CG.bannerDismissed && !document.getElementById(DOM_IDS.bannerHost)) {
      CG.bannerShown = false;
    }
    // Same for overlay
    if (CG.overlayShown && !document.getElementById(DOM_IDS.overlayHost)) {
      CG.overlayShown = false;
    }

    // Scan both visible and hidden text for lure phrases, take the higher score
    const lureVisible = Analyzer.scanLurePhrases(bodyText);
    const lureHidden = Analyzer.scanLurePhrases(hiddenText);
    const lure = lureHidden.score > lureVisible.score ? lureHidden : lureVisible;

    const layers = {
      lure,
      aitm: useMsBudgetMode ? zeroLayer : Analyzer.detectAiTMPhish(),
      captcha: Analyzer.detectFakeCAPTCHA(),
      fakeErr: useMsBudgetMode ? zeroLayer : Analyzer.detectFakeErrors(),
      fakeUpdate: useMsBudgetMode ? zeroLayer : Analyzer.detectFakeBrowserUpdate(),
      img: useMsBudgetMode ? zeroLayer : Analyzer.detectInstructionImages(),
      embeddedPayload: Analyzer.detectEmbeddedPayloads(),
      obfLoader: useMsBudgetMode ? zeroLayer : Analyzer.detectObfuscatedLoaders(),
      multiStageLoader: useMsBudgetMode ? zeroLayer : Analyzer.detectMultiStageLoader(),
      srcdocIframe: Analyzer.scanSrcdocIframes(),
      base64Script: Analyzer.scanBase64ScriptPayloads(),
      cfImpersonation: Analyzer.detectCloudflareImpersonation(),
      scriptClipboardStaging: Analyzer.detectScriptClipboardStaging()
    };

    // --- Remote rules merge (v1.2.6) ---
    // Load cached remote rules (async on first call, then in-memory).
    // Merge into each layer — built-in results are never replaced, only appended to.
    try {
      const rr = await Analyzer.loadRemoteRules();
      if (rr && Object.keys(rr).length) {
        const fullText = bodyText + " " + hiddenText;
        layers.lure = Analyzer.mergeWithRemote(layers.lure, "lure", rr, fullText);
        layers.captcha = Analyzer.mergeWithRemote(layers.captcha, "captcha", rr);
        layers.fakeErr = Analyzer.mergeWithRemote(layers.fakeErr, "fakeErr", rr);
        layers.fakeUpdate = Analyzer.mergeWithRemote(layers.fakeUpdate, "fakeUpdate", rr);
        layers.srcdocIframe = Analyzer.mergeWithRemote(layers.srcdocIframe, "srcdocIframe", rr);
        layers.base64Script = Analyzer.mergeWithRemote(layers.base64Script, "base64Script", rr);
        layers.cfImpersonation = Analyzer.mergeWithRemote(layers.cfImpersonation, "cfImpersonation", rr);
      }
    } catch {} // fail silently — built-in rules already populated layers

    const combined = Analyzer.calculatePageThreat(layers);

    CG.pageThreat = combined.pageThreat;
    CG.adjustedThreshold = combined.adjustedThreshold;
    CG.signals = combined.signals || [];
    CG.heightened = CG.pageThreat >= 30;
    CG.scanCount++;
    CG.platformBudgetMode = useMsBudgetMode;

    // Expose to page context for automated testing (read-only, no security impact)
    try { document.documentElement.dataset.cgPageThreat = String(CG.pageThreat); } catch {}

    // Track score stability — if score hasn't changed for 3 consecutive scans,
    // disconnect the MutationObserver to stop burning CPU on stable pages.
    // The heartbeat still runs as a safety net for document.write() attacks.
    if (CG.pageThreat === CG.lastScore) {
      CG.stableCount++;
    } else {
      CG.stableCount = 0;
      CG.lastScore = CG.pageThreat;
    }

    if (CG.stableCount >= 3 && CG.pageThreat < 30) {
      // Page is stable and clean — stop observing DOM mutations
      try { observer.disconnect(); } catch {}
    }

      sendRuntimeMessage({
        type: "PAGE_THREAT",
        pageThreat: CG.pageThreat,
        adjustedThreshold: CG.adjustedThreshold,
        signals: CG.signals
      }).then(() => {});

    const aitmBlockContext = shouldAutoBlockAiTMPage(layers);
    if (aitmBlockContext && !_formOverlayShown) {
      showAiTMThreatOverlay(aitmBlockContext);
    }

    if (CG.pageThreat >= 60 && !CG.overlayShown) showBanner({ signals: CG.signals });
    maybeStartPolling();

    // ===================================================================
    // ADDITIONS (v1.2.5 — auto-escalate to overlay for evasion-layer attacks)
    // When srcdoc iframe or base64 document.write attacks are detected with
    // high confidence AND a clipboard write mechanism is present, the normal
    // clipboard interception hooks cannot fire because:
    //   - srcdoc iframes run in a separate browsing context (hooks don't inject)
    //   - document.write() destroys the page-world hook script
    // Auto-escalate to block overlay without waiting for clipboard interception.
    // Nothing above was modified.
    // ===================================================================
    if (!CG.overlayShown && CG.pageThreat >= 60) {
      const srcdocScore  = layers.srcdocIframe?.score || 0;
      const b64Score     = layers.base64Script?.score || 0;
      const cfScore      = layers.cfImpersonation?.score || 0;
      const clipStagingScore = layers.scriptClipboardStaging?.score || 0;

      // Only auto-escalate if one of the NEW evasion layers is the primary driver
      // (score >= 50 means high confidence: multiple signals confirmed)
      const evasionDriven = srcdocScore >= 50 || b64Score >= 50 || cfScore >= 50 || (cfScore >= 30 && b64Score >= 30) || clipStagingScore >= 50;

      if (evasionDriven) {
        // Build a synthetic decision object matching showOverlay's expected format
        const evasionSignals = [
          ...(layers.srcdocIframe?.signals || []),
          ...(layers.base64Script?.signals || []),
          ...(layers.cfImpersonation?.signals || []),
          ...(layers.scriptClipboardStaging?.signals || [])
        ];
        const evasionType = srcdocScore >= 50 ? "srcdoc iframe ClickFix"
                          : b64Score >= 50 ? "base64-encoded ClickFix"
                          : clipStagingScore >= 50 ? "CSP-blocked clipboard staging ClickFix"
                          : "Cloudflare impersonation ClickFix";

        // Extract payload preview from srcdoc or base64 if available
        let payloadPreview = "(clipboard payload hidden via " + evasionType + " evasion — hooks could not intercept)";
        for (const sig of evasionSignals) {
          if (/powershell/i.test(sig.label)) {
            payloadPreview = "[PowerShell payload detected in " + evasionType + " — command hidden from clipboard hooks]";
            break;
          }
        }

        showOverlay(payloadPreview, {
          action: "block",
          score: CG.pageThreat,
          threshold: CG.adjustedThreshold,
          matches: evasionSignals.slice(0, 10).map(s => ({ label: s.label })),
          ctx: { signals: CG.signals }
        });
      }
    }

    // ===================================================================
    // ADDITIONS (v1.2.2 — brand detection on page-threat banner)
    // Runs AFTER the banner is shown (non-blocking) to detect brand
    // impersonation and upgrade the banner message with brand context.
    // Nothing above was modified.
    // ===================================================================
    if (CG.pageThreat >= 30) {
      try { _detectAndStoreBrandSignals(); } catch {}
    }
  }

  // Debounced rescans — adaptive delay based on threat level
  let scanTimer = null;
  function scheduleScan() {
    if (_killed) return;
    clearTimeout(scanTimer);
    // Clean pages get longer debounce to save CPU; high-threat pages stay responsive
    const delay = CG.pageThreat >= 30
      ? 600
      : (CG.platformBudgetMode ? (CG.scanCount > 2 ? 4000 : 1500) : (CG.scanCount > 3 ? 2000 : 600));
    scanTimer = setTimeout(sendPageThreat, delay);
  }

  // Initial scan
  sendPageThreat();

  // MutationObserver for page changes
  let observer = new MutationObserver(() => scheduleScan());
  function attachObserver() {
    try {
      observer.disconnect();
    } catch {}
    try {
      observer = new MutationObserver(() => scheduleScan());
      observer.observe(
        document.documentElement,
        CG.platformBudgetMode
          ? { childList: true, subtree: true }
          : { childList: true, subtree: true, characterData: true }
      );
    } catch {}
  }
  attachObserver();

  // --- document.write() survival mechanism ---
  // When a C2 script calls document.open()/document.write(), the entire DOM is replaced,
  // killing the MutationObserver and any injected UI. The content script's isolated world
  // JS context survives, but has no way to know the DOM was nuked.
  // Solution: periodic heartbeat that checks if our DOM marker still exists.
  // If it's gone, we know the document was replaced — re-attach observer, re-scan, re-inject hooks.
  let _heartbeatMarker = "cg-hb-" + Math.random().toString(36).slice(2);
  function placeHeartbeat() {
    try {
      const el = document.createElement("meta");
      el.setAttribute("name", _heartbeatMarker);
      (document.head || document.documentElement).appendChild(el);
    } catch {}
  }
  placeHeartbeat();

  let _heartbeatInterval = setInterval(() => {
    try {
      const alive = document.querySelector('meta[name="' + _heartbeatMarker + '"]');
      if (!alive) {
        // Document was replaced (document.open/write nuked it)
        // Reset UI flags since the banner/overlay elements are gone
        CG.bannerShown = false;
        CG.overlayShown = false;

        // Re-place heartbeat marker in the new document
        placeHeartbeat();

        // Re-attach MutationObserver to new document
        attachObserver();

        // Re-attach copy event listener (document events die with document.open)
        attachCopyListener();

        // Re-inject page-world clipboard hooks into the new document
        try {
          const s = document.createElement("script");
          s.textContent = `(function(){
            if (window.__clickguard_hooks_installed) return;
            window.__clickguard_hooks_installed = true;
            var _cgn = "${CG_NONCE || ""}";
            function _cgPost(type, text) {
              try { window.postMessage({__clickguard:true,_cgn:_cgn,type:type,text:String(text||"")}, "*"); } catch {}
            }
            try {
              var origWT = navigator.clipboard && navigator.clipboard.writeText
                ? navigator.clipboard.writeText.bind(navigator.clipboard)
                : null;
              if (origWT) {
                var hookedWT = async function(text){
                  _cgPost("CLIPBOARD_WRITE", text);
                  return origWT(text);
                };
                try { Object.defineProperty(navigator.clipboard, 'writeText', { value: hookedWT, writable: false, configurable: false }); } catch { navigator.clipboard.writeText = hookedWT; }
              }
              var origEC = document.execCommand ? document.execCommand.bind(document) : null;
              if (origEC) {
                var hookedEC = function(cmd, ui, value){
                  try {
                    if (String(cmd).toLowerCase() === "copy") {
                      var t = "";
                      try { t = (window.getSelection && window.getSelection().toString()) ? window.getSelection().toString() : ""; } catch {}
                      try { if (!t) { var ae = document.activeElement; if (ae && (ae.tagName === "TEXTAREA" || ae.tagName === "INPUT")) t = ae.value || ""; } } catch {}
                      if (t) _cgPost("CLIPBOARD_WRITE", t);
                      else _cgPost("CLIPBOARD_COPY_EVENT", "");
                    }
                  } catch {}
                  return origEC(cmd, ui, value);
                };
                try { Object.defineProperty(document, 'execCommand', { value: hookedEC, writable: false, configurable: false }); } catch { document.execCommand = hookedEC; }
              }
              try {
                var origSetData = DataTransfer.prototype.setData;
                if (origSetData) {
                  DataTransfer.prototype.setData = function(format, data) {
                    try { if (/text/i.test(String(format)) && data && String(data).length > 5) { _cgPost("CLIPBOARD_WRITE", String(data)); } } catch {}
                    return origSetData.call(this, format, data);
                  };
                }
              } catch {}
            } catch {}
          })();`;
          document.documentElement.appendChild(s);
          s.remove();
        } catch {} // CSP may block this — clipboard hooks via copy event listener still work

        // Re-scan the new document immediately
        sendPageThreat();
      }
    } catch {}
  }, 800);

  // --- Clipboard interception ---
  // 1) Listen for postMessage events from injected page hook (with nonce validation — CRIT-1)
  window.addEventListener("message", async (event) => {
    const data = event.data;
    if (!data || data.__clickguard !== true) return;
    const sourceOk = event.source === window || event.source == null || event.target === window;
    if (!sourceOk) return;
    // Firefox has been flaky here with page-world -> content-script message identity.
    // Keep the nonce check when it matches, but don't drop known clipboard events solely
    // because Firefox reports a different source/nonce shape.
    const type = String(data.type || "");
    const clipboardEvent = type === "CLIPBOARD_WRITE" || type === "CLIPBOARD_COPY_EVENT";
    if (CG_NONCE && data._cgn !== CG_NONCE && !clipboardEvent) return;
    if (data.type === "CLIPBOARD_COPY_EVENT") {
    try {
      const sel = (window.getSelection && window.getSelection().toString()) ? window.getSelection().toString() : "";
      if (sel) await handleClipboardWrite(safeText(sel), { source: "execCommand-copy" });
    } catch {}
    return;
  }
  if (data.type !== "CLIPBOARD_WRITE") return;

    const text = safeText(data.text || "");
    await handleClipboardWrite(text, { source: "page" });
  }, true);

  
  // 2) Also catch copy events (manual copy / execCommand('copy') selection tricks)
  // Extracted to a named function so it can be re-attached after document.write() nukes the DOM
  async function _cgCopyHandler() {
    try {
      // Prefer what the user/page actually selected (works even when clipboard read is blocked)
      const sel = (window.getSelection && window.getSelection().toString()) ? window.getSelection().toString() : "";
      let candidate = sel;

      // If selection is empty, fall back to active element value (hidden textarea tricks)
      if (!candidate) {
        const ae = document.activeElement;
        if (ae && (ae.tagName === "TEXTAREA" || (ae.tagName === "INPUT" && /text|search|url|tel|email|password/i.test(ae.type)))) {
          candidate = ae.value || "";
        }
      }

      // As a last resort, attempt clipboard read (may fail depending on browser policies)
      if (!candidate) {
        try {
          const t = await navigator.clipboard.readText();
          candidate = t || "";
        } catch {}
      }

      candidate = safeText(candidate);
      if (candidate) await handleClipboardWrite(candidate, { source: "copy-event" });
    } catch {
      // ignore
    }
  }
    function attachCopyListener() {
      document.addEventListener("copy", _cgCopyHandler, true);
    }
    attachCopyListener();

    const _processedClipboardNodes = new WeakSet();
    function maybeInspectClipboardNode(node, source = "staging-observer") {
      if (!node || _processedClipboardNodes.has(node)) return;
      _processedClipboardNodes.add(node);
      const inspect = async () => {
        try {
          const tag = (node.tagName || "").toUpperCase();
          if (tag !== "TEXTAREA" && tag !== "INPUT") return;
          const type = (node.type || "").toLowerCase();
          if (tag === "INPUT" && !/^(text|search|url|tel|email|password)?$/.test(type)) return;
          const value = safeText(node.value || node.getAttribute?.("value") || "");
          if (!value || value.trim().length < 8) return;
          await handleClipboardWrite(value, { source });
        } catch {}
      };
      setTimeout(inspect, 15);
      setTimeout(inspect, 75);
      setTimeout(inspect, 200);
      try {
        node.addEventListener("focus", inspect, true);
        node.addEventListener("select", inspect, true);
      } catch {}
    }

    try {
      const _clipboardStageObserver = new MutationObserver((mutations) => {
        for (const mut of mutations) {
          for (const node of mut.addedNodes) {
            if (!node || node.nodeType !== 1) continue;
            if (node.nodeName === "TEXTAREA" || node.nodeName === "INPUT") {
              maybeInspectClipboardNode(node, "textarea-staging");
            }
            if (typeof node.querySelectorAll === "function") {
              const staged = node.querySelectorAll("textarea,input");
              for (const candidate of staged) maybeInspectClipboardNode(candidate, "textarea-staging");
            }
          }
        }
      });
      _clipboardStageObserver.observe(document.documentElement, { childList: true, subtree: true });
    } catch {}

    // --- Active clipboard monitoring for high-threat pages ---
  // When page-world hooks can't be installed (CSP blocks inline scripts) and the page
  // uses navigator.clipboard.writeText() from click handlers, the copy event never fires.
  // Solution: on high-threat pages, monitor clicks and poll clipboard contents afterward.
  // Also intercept clicks on elements that look like copy/verification buttons to catch
  // the write before the user can paste it into Run dialog.
  let _clipboardPollActive = false;

  function startClipboardPolling() {
    if (_clipboardPollActive) return;
    _clipboardPollActive = true;

    // Monitor for hidden textarea clipboard staging (common ClickFix pattern):
    // The page creates a textarea, sets its value, selects it, calls execCommand('copy'), then removes it.
    // We intercept by observing DOM additions for textareas and reading their value before they're removed.
    const _textareaObserver = new MutationObserver((mutations) => {
      if (CG.pageThreat < 30) return;
      for (const mut of mutations) {
        for (const node of mut.addedNodes) {
          if (node.nodeName === "TEXTAREA" || node.nodeName === "INPUT") {
            // Defer slightly to let the page set the value
            setTimeout(async () => {
              try {
                const val = node.value || "";
                if (val && val.trim().length > 5) {
                  await handleClipboardWrite(safeText(val), { source: "textarea-intercept" });
                }
              } catch {}
            }, 50);
          }
        }
      }
    });
    try {
      _textareaObserver.observe(document.documentElement, { childList: true, subtree: true });
    } catch {}

    // Capture-phase click listener catches all clicks before the page handles them
    document.addEventListener("click", async (e) => {
      if (CG.pageThreat < 30) return;

      const target = e.target;
      if (!target) return;

      // Check if the clicked element or its parent looks like a copy/action button
      const elText = ((target.textContent || "") + " " + (target.getAttribute?.("class") || "") + " " + (target.getAttribute?.("id") || "")).toLowerCase();
      const parentText = ((target.parentElement?.textContent || "") + " " + (target.parentElement?.getAttribute?.("class") || "")).toLowerCase();
      const isCopyLike = /(copy|clipboard|verify|confirm|execute|run|paste)/i.test(elText) ||
                         /(copy|clipboard|sync_event)/i.test(target.getAttribute?.("class") || "") ||
                         /(copy|clipboard|sync_event)/i.test(target.getAttribute?.("id") || "") ||
                         target.closest?.(".sync_event_click, [data-copy], [data-clipboard-text], [onclick*=copy], [onclick*=clipboard]");

      if (!isCopyLike && CG.pageThreat < 60) return;

      // Small delay to let the page's click handler write to clipboard
      await new Promise(r => setTimeout(r, 150));

      // Try to read what was written to clipboard
      try {
        const clipText = await navigator.clipboard.readText();
        if (clipText && clipText.trim().length > 5) {
          await handleClipboardWrite(safeText(clipText), { source: "clipboard-poll" });
        }
      } catch {
        // Clipboard read may be denied — try via selection as fallback
        try {
          const sel = window.getSelection?.()?.toString() || "";
          if (sel && sel.trim().length > 5) {
            await handleClipboardWrite(safeText(sel), { source: "selection-poll" });
          }
        } catch {}
      }
    }, true);
  }

  // Activate polling whenever page threat is elevated
  // Check after each scan
  function maybeStartPolling() {
    if (CG.pageThreat >= 30 && !_clipboardPollActive) {
      startClipboardPolling();
    }
  }


  async function handleClipboardWrite(text, meta) {
    if (_killed) return;
    // session-based staging: concatenate if multiple writes within 3 seconds
    const now = Date.now();
    if (now - CG.lastWriteAt < 3000) {
      CG.sessionWrites.push(text);
    } else {
      CG.sessionWrites = [text];
    }
    CG.lastWriteAt = now;

    const combined = CG.sessionWrites.join("\n");
      const resp = await sendRuntimeMessage({ type: "SCORE_CLIPBOARD", text: combined, meta });
      const localFallback = localClipboardFallbackScore(combined);
      const decision = (() => {
        if (localFallback && (!resp || !resp.ok)) return localFallback;
        if (localFallback && resp?.ok && (localFallback.score > ((resp?.score || 0) + 20))) return localFallback;
        return resp;
      })();

    if (!decision || !decision.ok) return;

    if (decision.action === "block") {
        await clearClipboard();
        if (CG.overlayShown && !CG.overlayFromHook) {
          upgradeOverlay(combined, decision);
        } else {
          showOverlay(combined, decision);
        }
      }
    }

    // Inject a page-world hook to intercept clipboard writes in the page JS world.
  // Pages run in a different JS world than content scripts.
  // NOTE: clipboard-hook-early.js (document_start) should handle this first,
  // but we re-inject here as a fallback in case the early hook didn't fire.
  try {
    const s = document.createElement("script");
    s.textContent = `(function(){
      if (window.__clickguard_hooks_installed) return; // early hook already ran
      window.__clickguard_hooks_installed = true;
      var _cgn = "${CG_NONCE || ""}";
      function _cgPost(type, text) {
        try { window.postMessage({__clickguard:true,_cgn:_cgn,type:type,text:String(text||"")}, "*"); } catch {}
      }
      try {
        var origWT = navigator.clipboard && navigator.clipboard.writeText
          ? navigator.clipboard.writeText.bind(navigator.clipboard)
          : null;
        if (origWT) {
          var hookedWT = async function(text){
            _cgPost("CLIPBOARD_WRITE", text);
            return origWT(text);
          };
          try { Object.defineProperty(navigator.clipboard, 'writeText', { value: hookedWT, writable: false, configurable: false }); } catch { navigator.clipboard.writeText = hookedWT; }
        }
        try {
          var protoWT = Clipboard.prototype.writeText;
          if (protoWT) {
            var hpWT = async function(text){ _cgPost("CLIPBOARD_WRITE", text); return protoWT.call(this, text); };
            try { Object.defineProperty(Clipboard.prototype, 'writeText', { value: hpWT, writable: false, configurable: false }); } catch { Clipboard.prototype.writeText = hpWT; }
          }
        } catch {}
        var origW = navigator.clipboard && navigator.clipboard.write
          ? navigator.clipboard.write.bind(navigator.clipboard)
          : null;
        if (origW) {
          var hookedW = async function(items){
            try { if(items&&items.length){for(var i=0;i<items.length;i++){var it=items[i];if(it&&it.types&&it.types.indexOf("text/plain")!==-1){try{var b=await it.getType("text/plain");var t=await b.text();if(t)_cgPost("CLIPBOARD_WRITE",t);}catch{}}}} } catch {}
            return origW(items);
          };
          try { Object.defineProperty(navigator.clipboard, 'write', { value: hookedW, writable: false, configurable: false }); } catch { navigator.clipboard.write = hookedW; }
        }
        try {
          var protoW = Clipboard.prototype.write;
          if (protoW) {
            var hpW = async function(items){
              try { if(items&&items.length){for(var i=0;i<items.length;i++){var it=items[i];if(it&&it.types&&it.types.indexOf("text/plain")!==-1){try{var b=await it.getType("text/plain");var t=await b.text();if(t)_cgPost("CLIPBOARD_WRITE",t);}catch{}}}} } catch {}
              return protoW.call(this, items);
            };
            try { Object.defineProperty(Clipboard.prototype, 'write', { value: hpW, writable: false, configurable: false }); } catch { Clipboard.prototype.write = hpW; }
          }
        } catch {}
        var origEC = document.execCommand ? document.execCommand.bind(document) : null;
        if (origEC) {
          var hookedEC = function(cmd, ui, value){
            try {
              if (String(cmd).toLowerCase() === "copy") {
                var t = "";
                try { t = (window.getSelection && window.getSelection().toString()) ? window.getSelection().toString() : ""; } catch {}
                try { if (!t) { var ae = document.activeElement; if (ae && (ae.tagName === "TEXTAREA" || ae.tagName === "INPUT")) t = ae.value || ""; } } catch {}
                if (t) _cgPost("CLIPBOARD_WRITE", t);
                else _cgPost("CLIPBOARD_COPY_EVENT", "");
              }
            } catch {}
            return origEC(cmd, ui, value);
          };
          try { Object.defineProperty(document, 'execCommand', { value: hookedEC, writable: false, configurable: false }); } catch { document.execCommand = hookedEC; }
        }
        try {
          var origSetData = DataTransfer.prototype.setData;
          if (origSetData) {
            DataTransfer.prototype.setData = function(format, data) {
              try { if (/text/i.test(String(format)) && data && String(data).length > 5) { _cgPost("CLIPBOARD_WRITE", String(data)); } } catch {}
              return origSetData.call(this, format, data);
            };
          }
        } catch {}
      } catch {}
    })();`;
    document.documentElement.appendChild(s);
    s.remove();
  } catch {}

  // --- Form Phishing Overlay ---
  // Full-screen blocking overlay for sensitive form detection.
  // More aggressive than the banner — forces user to make a conscious decision.
  const FORM_IMPERSONATION_BRANDS = [
    { aliases: ["steam","steampowered","steam guard","valve"], brand: "Steam", officialDisplay: "steampowered.com", officialDomains: ["steampowered.com","steamcommunity.com"] },
    { aliases: ["paypal"], brand: "PayPal", officialDisplay: "paypal.com", officialDomains: ["paypal.com"] },
    { aliases: ["microsoft","outlook","hotmail","office 365","office365","onedrive","sharepoint","microsoft account"], brand: "Microsoft", officialDisplay: "login.microsoftonline.com or microsoft.com", officialDomains: ["microsoft.com","live.com","microsoftonline.com","office.com","outlook.com"] },
    { aliases: ["google","gmail","google drive","google docs","google account"], brand: "Google", officialDisplay: "accounts.google.com or google.com", officialDomains: ["google.com","gmail.com"] },
    { aliases: ["facebook","meta"], brand: "Facebook", officialDisplay: "facebook.com", officialDomains: ["facebook.com","fb.com"] },
    { aliases: ["instagram"], brand: "Instagram", officialDisplay: "instagram.com", officialDomains: ["instagram.com"] },
    { aliases: ["apple","icloud","apple id"], brand: "Apple", officialDisplay: "apple.com or appleid.apple.com", officialDomains: ["apple.com","icloud.com"] },
    { aliases: ["amazon","amazon.com"], brand: "Amazon", officialDisplay: "amazon.com", officialDomains: ["amazon.com"] },
    { aliases: ["netflix"], brand: "Netflix", officialDisplay: "netflix.com", officialDomains: ["netflix.com"] },
    { aliases: ["chase","jpmorgan","jpmorgan chase","jpmorgan chase and co"], brand: "Chase", officialDisplay: "chase.com", officialDomains: ["chase.com","jpmorgan.com"] },
    { aliases: ["wells fargo","wellsfargo","wachovia"], brand: "Wells Fargo", officialDisplay: "wellsfargo.com", officialDomains: ["wellsfargo.com"] },
    { aliases: ["bank of america","bankofamerica","bofa","bank of america corporation"], brand: "Bank of America", officialDisplay: "bankofamerica.com", officialDomains: ["bankofamerica.com"] },
    { aliases: ["dhl","dhl express"], brand: "DHL", officialDisplay: "dhl.com", officialDomains: ["dhl.com"] },
    { aliases: ["usps","postal service","united states postal service"], brand: "USPS", officialDisplay: "usps.com", officialDomains: ["usps.com"] },
    { aliases: ["fedex"], brand: "FedEx", officialDisplay: "fedex.com", officialDomains: ["fedex.com"] },
    { aliases: ["linkedin"], brand: "LinkedIn", officialDisplay: "linkedin.com", officialDomains: ["linkedin.com"] },
    { aliases: ["twitter","x.com","x login"], brand: "X", officialDisplay: "x.com", officialDomains: ["x.com","twitter.com"] },
    { aliases: ["discord"], brand: "Discord", officialDisplay: "discord.com", officialDomains: ["discord.com"] },
    { aliases: ["ebay","ebay inc","ebay inc."], brand: "eBay", officialDisplay: "ebay.com", officialDomains: ["ebay.com"] },
    { aliases: ["shopee"], brand: "Shopee", officialDisplay: "shopee.com", officialDomains: ["shopee.com","shopee.co.id","shopee.sg","shopee.ph"] },
    { aliases: ["allegro"], brand: "Allegro", officialDisplay: "allegro.pl", officialDomains: ["allegro.pl"] },
    { aliases: ["adobe","creative cloud","document cloud"], brand: "Adobe", officialDisplay: "adobe.com", officialDomains: ["adobe.com"] },
    { aliases: ["dropbox"], brand: "Dropbox", officialDisplay: "dropbox.com", officialDomains: ["dropbox.com"] },
    { aliases: ["coinbase"], brand: "Coinbase", officialDisplay: "coinbase.com", officialDomains: ["coinbase.com"] },
    { aliases: ["binance"], brand: "Binance", officialDisplay: "binance.com", officialDomains: ["binance.com"] },
    { aliases: ["ledger","ledger wallet"], brand: "Ledger", officialDisplay: "ledger.com", officialDomains: ["ledger.com"] },
    { aliases: ["metamask"], brand: "MetaMask", officialDisplay: "metamask.io", officialDomains: ["metamask.io"] },
    { aliases: ["at&t","at&amp;t","att"], brand: "AT&T", officialDisplay: "att.com", officialDomains: ["att.com"] },
    { aliases: ["optus"], brand: "Optus", officialDisplay: "optus.com.au", officialDomains: ["optus.com.au"] },
    { aliases: ["irs","internal revenue","internal revenue service"], brand: "IRS", officialDisplay: "irs.gov", officialDomains: ["irs.gov"] },
    { aliases: ["hsbc","hsbc group"], brand: "HSBC", officialDisplay: "hsbc.com", officialDomains: ["hsbc.com","hsbc.co.uk"] },
    { aliases: ["american express","amex"], brand: "American Express", officialDisplay: "americanexpress.com", officialDomains: ["americanexpress.com"] },
    { aliases: ["docusign","docusign envelope","review document"], brand: "DocuSign", officialDisplay: "docusign.com", officialDomains: ["docusign.com"] },
    { aliases: ["xfinity","comcast"], brand: "Xfinity", officialDisplay: "xfinity.com or comcast.net", officialDomains: ["xfinity.com","comcast.net"] },
    { aliases: ["capital one","capitalone"], brand: "Capital One", officialDisplay: "capitalone.com", officialDomains: ["capitalone.com"] },
    { aliases: ["bradesco"], brand: "Bradesco", officialDisplay: "bradesco.com.br", officialDomains: ["bradesco.com.br","banco.bradesco"] },
    { aliases: ["smbc","sumitomo mitsui","sumitomo mitsui banking","sumitomo mitsui banking corporation"], brand: "SMBC", officialDisplay: "smbc.co.jp", officialDomains: ["smbc.co.jp"] },
    { aliases: ["barclays","barclays bank plc"], brand: "Barclays", officialDisplay: "barclays.com", officialDomains: ["barclays.com","barclays.co.uk"] },
    { aliases: ["aeon card","aeon"], brand: "AEON Card", officialDisplay: "aeon.co.jp", officialDomains: ["aeon.co.jp"] },
    { aliases: ["bt","british telecom","bt mail","btinternet"], brand: "BT", officialDisplay: "bt.com or btinternet.com", officialDomains: ["bt.com","btinternet.com"] },
    { aliases: ["orange"], brand: "Orange", officialDisplay: "orange.com or orange.fr", officialDomains: ["orange.com","orange.fr"] },
    { aliases: ["volksbanken raiffeisenbanken","vr bank","vr banking"], brand: "Volksbanken Raiffeisenbanken", officialDisplay: "vr.de", officialDomains: ["vr.de"] },
    { aliases: ["interactive brokers","ibkr"], brand: "Interactive Brokers", officialDisplay: "interactivebrokers.com", officialDomains: ["interactivebrokers.com"] },
    { aliases: ["ing","ing direct","ing bank","mijn ing"], brand: "ING", officialDisplay: "ing.com", officialDomains: ["ing.com","ing.nl"] },
    { aliases: ["runescape","jagex"], brand: "RuneScape", officialDisplay: "runescape.com", officialDomains: ["runescape.com"] },
    { aliases: ["paypay bank","japan net bank"], brand: "PayPay Bank", officialDisplay: "paypay-bank.co.jp", officialDomains: ["paypay-bank.co.jp"] },
    { aliases: ["unicredit","unicredit bank"], brand: "UniCredit", officialDisplay: "unicredit.it", officialDomains: ["unicredit.it","unicreditgroup.eu"] },
    { aliases: ["banco do brasil","banco de brasil"], brand: "Banco do Brasil", officialDisplay: "bb.com.br or bancodobrasil.com.br", officialDomains: ["bb.com.br","bancodobrasil.com.br"] },
    { aliases: ["wetransfer","we transfer"], brand: "WeTransfer", officialDisplay: "wetransfer.com", officialDomains: ["wetransfer.com"] },
    { aliases: ["abn amro","abn amro bank"], brand: "ABN AMRO", officialDisplay: "abnamro.nl", officialDomains: ["abnamro.nl"] },
    { aliases: ["santander","banco santander","banco santander s a","santander uk"], brand: "Santander", officialDisplay: "santander.com or santander.co.uk", officialDomains: ["santander.com","santander.co.uk"] },
    { aliases: ["absa","absa bank"], brand: "ABSA", officialDisplay: "absa.co.za", officialDomains: ["absa.co.za"] },
    { aliases: ["scotiabank","scotia"], brand: "Scotiabank", officialDisplay: "scotiabank.com", officialDomains: ["scotiabank.com"] },
    { aliases: ["rakuten"], brand: "Rakuten", officialDisplay: "rakuten.co.jp or rakuten.com", officialDomains: ["rakuten.co.jp","rakuten.com"] },
    { aliases: ["accurint","lexisnexis accurint","lexisnexis"], brand: "Accurint", officialDisplay: "accurint.com or lexisnexis.com", officialDomains: ["accurint.com","lexisnexis.com"] },
    { aliases: ["allied bank","allied bank limited"], brand: "Allied Bank", officialDisplay: "abl.com", officialDomains: ["abl.com"] },
    { aliases: ["intesa sanpaolo"], brand: "Intesa Sanpaolo", officialDisplay: "intesasanpaolo.com", officialDomains: ["intesasanpaolo.com"] },
    { aliases: ["capitec","capitec bank"], brand: "Capitec", officialDisplay: "capitecbank.co.za", officialDomains: ["capitecbank.co.za"] },
    { aliases: ["westpac"], brand: "Westpac", officialDisplay: "westpac.com.au", officialDomains: ["westpac.com.au"] },
    { aliases: ["dbs","development bank of singapore"], brand: "DBS", officialDisplay: "dbs.com or dbs.com.sg", officialDomains: ["dbs.com","dbs.com.sg"] },
    { aliases: ["itau","itau unibanco"], brand: "Itau", officialDisplay: "itau.com.br", officialDomains: ["itau.com.br"] },
    { aliases: ["bbva","banco bilbao vizcaya argentaria"], brand: "BBVA", officialDisplay: "bbva.com", officialDomains: ["bbva.com","bbva.es"] },
    { aliases: ["huntington","huntington national bank"], brand: "Huntington", officialDisplay: "huntington.com", officialDomains: ["huntington.com"] },
    { aliases: ["caixa","caixa economica federal"], brand: "Caixa", officialDisplay: "caixa.gov.br", officialDomains: ["caixa.gov.br"] },
    { aliases: ["habbo","sulake","sulake corporation","hotel hideaway"], brand: "Habbo", officialDisplay: "habbo.com or sulake.com", officialDomains: ["habbo.com","sulake.com"] },
    { aliases: ["tesco","tesco bank"], brand: "Tesco", officialDisplay: "tesco.com or tescobank.com", officialDomains: ["tesco.com","tescobank.com"] },
    { aliases: ["tsb","tsb bank"], brand: "TSB", officialDisplay: "tsb.co.uk", officialDomains: ["tsb.co.uk"] },
    { aliases: ["swiss post","postfinance"], brand: "Swiss Post", officialDisplay: "post.ch or postfinance.ch", officialDomains: ["post.ch","postfinance.ch"] },
    { aliases: ["visa"], brand: "Visa", officialDisplay: "visa.com", officialDomains: ["visa.com"] },
    { aliases: ["bndes","the brazilian development bank"], brand: "BNDES", officialDisplay: "bndes.gov.br", officialDomains: ["bndes.gov.br"] },
    { aliases: ["aol"], brand: "AOL", officialDisplay: "aol.com", officialDomains: ["aol.com"] },
    { aliases: ["o2","telefonica uk"], brand: "O2", officialDisplay: "o2.co.uk", officialDomains: ["o2.co.uk"] },
    { aliases: ["free mobile","abonne free mobile","espace abonne"], brand: "Free Mobile", officialDisplay: "mobile.free.fr or free.fr", officialDomains: ["mobile.free.fr","free.fr"] },
    { aliases: ["raiffeisen","raiffeisen bank"], brand: "Raiffeisen", officialDisplay: "raiffeisen.at or raiffeisen.ch", officialDomains: ["raiffeisen.at","raiffeisen.ch"] },
    { aliases: ["nets"], brand: "Nets", officialDisplay: "nets.eu", officialDomains: ["nets.eu"] },
    { aliases: ["bank millennium","millennium bank"], brand: "Bank Millennium", officialDisplay: "bankmillennium.pl", officialDomains: ["bankmillennium.pl"] },
    { aliases: ["sparkasse"], brand: "Sparkasse", officialDisplay: "sparkasse.de", officialDomains: ["sparkasse.de"] },
    { aliases: ["jcb","jcb card"], brand: "JCB", officialDisplay: "jcb.co.jp or jcbcard.com", officialDomains: ["jcb.co.jp","jcbcard.com"] },
    { aliases: ["cembra","cembra money bank"], brand: "Cembra", officialDisplay: "cembra.ch", officialDomains: ["cembra.ch"] },
    { aliases: ["standard bank","standard bank ltd"], brand: "Standard Bank", officialDisplay: "standardbank.co.za or standardbank.com", officialDomains: ["standardbank.co.za","standardbank.com"] },
    { aliases: ["bitfinex"], brand: "Bitfinex", officialDisplay: "bitfinex.com", officialDomains: ["bitfinex.com"] },
    { aliases: ["pko","pko polish bank","pko bank polski","ipko"], brand: "PKO Bank Polski", officialDisplay: "pkobp.pl or ipko.pl", officialDomains: ["pkobp.pl","ipko.pl"] },
    { aliases: ["navy federal","navy federal credit union"], brand: "Navy Federal", officialDisplay: "navyfederal.org", officialDomains: ["navyfederal.org"] },
    { aliases: ["nubank"], brand: "Nubank", officialDisplay: "nubank.com.br or nubank.com", officialDomains: ["nubank.com.br","nubank.com"] },
    { aliases: ["aetna","aetna health plans dental coverage"], brand: "Aetna", officialDisplay: "aetna.com", officialDomains: ["aetna.com"] },
    { aliases: ["rackspace"], brand: "Rackspace", officialDisplay: "rackspace.com", officialDomains: ["rackspace.com"] },
    { aliases: ["hmrc","her majesty s revenue and customs","her majesty revenue and customs"], brand: "HMRC", officialDisplay: "hmrc.gov.uk or tax.service.gov.uk", officialDomains: ["hmrc.gov.uk","tax.service.gov.uk"] },
    { aliases: ["mastercard"], brand: "Mastercard", officialDisplay: "mastercard.com", officialDomains: ["mastercard.com"] },
    { aliases: ["co operative bank","co-operative bank"], brand: "Co-operative Bank", officialDisplay: "co-operativebank.co.uk", officialDomains: ["co-operativebank.co.uk"] },
    { aliases: ["dkb","das kann bank"], brand: "DKB", officialDisplay: "dkb.de", officialDomains: ["dkb.de"] },
    { aliases: ["virustotal","virus total"], brand: "VirusTotal", officialDisplay: "virustotal.com", officialDomains: ["virustotal.com"] },
    { aliases: ["royal bank of canada","rbc"], brand: "Royal Bank of Canada", officialDisplay: "rbc.com or rbcroyalbank.com", officialDomains: ["rbc.com","rbcroyalbank.com"] },
  ];

  function hostMatchesBrandDomain(host, domains) {
    const normalizedHost = (host || "").toLowerCase();
    if (!normalizedHost) return false;
    for (const domain of domains) {
      const normalizedDomain = (domain || "").toLowerCase();
      if (!normalizedDomain) continue;
      if (normalizedHost === normalizedDomain || normalizedHost.endsWith("." + normalizedDomain)) return true;
    }
    return false;
  }

  function isOfficialBrandHost(host) {
    return FORM_IMPERSONATION_BRANDS.some(brand => hostMatchesBrandDomain(host, brand.officialDomains));
  }

  function escapeRegex(value) {
    return String(value || "").replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }

  function normalizeBrandText(value) {
    return String(value || "")
      .replace(/&amp;/gi, " and ")
      .replace(/&nbsp;/gi, " ")
      .normalize("NFKD")
      .replace(/[\u0300-\u036f]/g, "")
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, " ")
      .trim();
  }

  function textContainsAlias(text, alias) {
    const normalizedText = normalizeBrandText(text);
    const normalizedAlias = normalizeBrandText(alias);
    if (!normalizedText || !normalizedAlias) return false;
    const aliasPattern = escapeRegex(normalizedAlias).replace(/\s+/g, "\\s+");
    return new RegExp(`(^|[^a-z0-9])${aliasPattern}([^a-z0-9]|$)`, "i").test(normalizedText);
  }

  function collectBrandTextCandidates() {





    const title = (document.title || "").toLowerCase();
    const metaDesc = (document.querySelector('meta[name="description"]')?.content || "").toLowerCase();
    const ogSiteName = (document.querySelector('meta[property="og:site_name"]')?.content || "").toLowerCase();
    const ogTitle = (document.querySelector('meta[property="og:title"]')?.content || "").toLowerCase();
    const uiTexts = [];
    const formTexts = [];
    const candidates = document.querySelectorAll("h1, h2, h3, h4, h5, h6, label, button, [role='button'], legend, img[alt], input[placeholder], input[aria-label]");

    for (const node of candidates) {
      const rawText = (
        node.getAttribute?.("alt") ||
        node.getAttribute?.("placeholder") ||
        node.getAttribute?.("aria-label") ||
        node.textContent ||
        ""
      ).replace(/\s+/g, " ").trim().toLowerCase();
      if (!rawText || rawText.length < 3 || rawText.length > 160) continue;
      uiTexts.push(rawText);
      if (uiTexts.length >= 60) break;
    }

    const formInputs = document.querySelectorAll('input:not([type="hidden"]):not([type="submit"]):not([type="button"]):not([type="reset"]):not([type="image"]):not([type="file"]), textarea, select');
    const seenFormTexts = new Set();
    for (const input of formInputs) {
      let parent = input.parentElement;
      for (let depth = 0; depth < 4 && parent; depth += 1) {
        const rawText = String(parent.innerText || parent.textContent || "")
          .replace(/\s+/g, " ")
          .trim()
          .toLowerCase();
        parent = parent.parentElement;
        if (!rawText || rawText.length < 12 || rawText.length > 500) continue;
        if (seenFormTexts.has(rawText)) continue;
        seenFormTexts.add(rawText);
        formTexts.push(rawText);
        if (formTexts.length >= 24) break;
      }
      if (formTexts.length >= 24) break;
    }

    return { title, metaDesc, ogSiteName, ogTitle, uiTexts, formTexts };
  }

  function hasHighSeveritySensitiveField(result) {
    const labels = (result?.sensitiveFields || []).map(field => (field.label || "").toLowerCase());
    return labels.some(label => /ssn|tax id|bank|routing|account number|card|cvv|seed|private key|secret|api key|student|institutional|national id|passport|driver|maiden|former.*credential|previous.*credential|standalone harvester|brand impersonation/i.test(label));
  }

  function detectImpersonatedBrand(rawHost, result) {
    const textCandidates = collectBrandTextCandidates();
    const credentialForm = (result?.sensitiveFields || []).some(field => /password|passcode|pin|credential|mfa|verification/i.test(field.label || ""));

    // Platform abuse: docs.google.com, sites.google.com, etc. can host phishing for OTHER brands
    const _PLATFORM_ABUSE_RE = /^(docs|sites|drawings|drive|forms|presentations)\.google\.com$|^.+\.sharepoint\.com$|^onedrive\.live\.com$/;
    const _isOnPlatformHost = _PLATFORM_ABUSE_RE.test(rawHost);
    const _hostingBrand = _isOnPlatformHost
      ? FORM_IMPERSONATION_BRANDS.find(b => hostMatchesBrandDomain(rawHost, b.officialDomains))
      : null;

    for (const brand of FORM_IMPERSONATION_BRANDS) {
      if (hostMatchesBrandDomain(rawHost, brand.officialDomains)) {
        if (!_isOnPlatformHost) continue;
        // On platform host: skip only the hosting brand (don't flag Google-on-Google)
        if (_hostingBrand && _hostingBrand.brand === brand.brand) continue;
      }

      const titleHit = brand.aliases.some(alias => (
        textContainsAlias(textCandidates.title, alias) ||
        textContainsAlias(textCandidates.metaDesc, alias) ||
        textContainsAlias(textCandidates.ogSiteName, alias) ||
        textContainsAlias(textCandidates.ogTitle, alias)
      ));
      if (titleHit) return brand;

      let uiHitCount = 0;
      for (const text of textCandidates.uiTexts) {
        if (brand.aliases.some(alias => textContainsAlias(text, alias))) {
          uiHitCount += 1;
        }
      }

      const formAliasHits = new Set();
      for (const text of textCandidates.formTexts) {
        for (const alias of brand.aliases) {
          if (textContainsAlias(text, alias)) {
            formAliasHits.add(normalizeBrandText(alias));
          }
        }
      }

      if (credentialForm && uiHitCount >= 2) return brand;
      if (credentialForm && result?.isFormPlatform && formAliasHits.size >= 2) return brand;

      // ===================================================================
      // ADDITIONS (v1.2.2 — relaxed brand detection for form platforms)
      // On form platforms with credential fields, a SINGLE alias appearing
      // in 2+ different form fields is sufficient (e.g. "Office365" in both
      // the email and password field labels). The original check required
      // 2 DIFFERENT aliases which missed pages using only one brand variant.
      // Nothing above was modified.
      // ===================================================================

      // Count total form text elements containing ANY brand alias (not unique aliases)
      let formFieldHitCount = 0;
      for (const text of textCandidates.formTexts) {
        if (brand.aliases.some(alias => textContainsAlias(text, alias))) {
          formFieldHitCount++;
        }
      }

      // Form platform + credential form + brand alias in 2+ field contexts = impersonation
      if (credentialForm && result?.isFormPlatform && formFieldHitCount >= 2) return brand;

      // Form platform + brand alias in 3+ field contexts (even without detected credential patterns)
      if (result?.isFormPlatform && formFieldHitCount >= 3) return brand;

      // Any site (not just form platforms): credential form + 1 alias in title-area + 1 in form = impersonation
      if (credentialForm && uiHitCount >= 1 && formAliasHits.size >= 1) return brand;

      // Credential form + brand alias in body text (catches pages where brand is only in page text, not UI elements)
      if (credentialForm && result?.isFormPlatform) {
        const bodySnippet = (document.body?.innerText || "").toLowerCase().slice(0, 5000);
        if (brand.aliases.some(alias => textContainsAlias(bodySnippet, alias))) return brand;
      }
    }

    // ===================================================================
    // ADDITIONS (v1.2.3 — Platform abuse body text scan)
    // On platform hosts (Google Docs/Drawings/Sites/etc), brand text may
    // be rendered as images/SVG/canvas that standard selectors miss.
    // Fall back to scanning document.body.innerText for brand keywords.
    // This catches Google Drawings phishing (Amazon, Xfinity, AT&T, etc)
    // where the entire page is an image with text overlaid.
    // Nothing above was modified.
    // ===================================================================
    if (_isOnPlatformHost) {
      const bodyText = (document.body?.innerText || "").toLowerCase().slice(0, 8000);
      if (bodyText.length > 30) {
        for (const brand of FORM_IMPERSONATION_BRANDS) {
          if (_hostingBrand && _hostingBrand.brand === brand.brand) continue;
          if (brand.aliases.some(alias => textContainsAlias(bodyText, alias))) {
            return brand;
          }
        }
      }
    }

    return null;
  }

  let _formOverlayShown = false;
  function showFormOverlay(result, detectedBrandOverride) {
    if (_killed || _formOverlayShown) return;
    _formOverlayShown = true;

    const platform = result.platform ? escapeHtml(result.platform) : "Unknown";
    const fieldChips = result.sensitiveFields.slice(0, 8).map(f => `<span class="cg-chip">${escapeHtml(f.label)}</span>`).join("") || `<span class="cg-chip">Sensitive fields detected</span>`;
    const rawHost = getHost();
    const hostText = rawHost || "(unknown host)";
    const host = escapeHtml(hostText);
    const detectedBrand = detectedBrandOverride || detectImpersonatedBrand(rawHost, result);
    const brandLabel = detectedBrand ? escapeHtml(detectedBrand.brand) : "";
    const officialDisplay = detectedBrand ? escapeHtml(detectedBrand.officialDisplay) : "";

    // Build "why this might be fake" indicators
    const reasons = [];

    if (detectedBrand) {
      reasons.push(`This page is trying to impersonate <strong>${brandLabel}</strong>. Real ${brandLabel} sign-in pages start with <strong>${officialDisplay}</strong>, not <strong>${host}</strong>.`);
    }

    if (result.platform) {
      reasons.push(`This is a <strong>${escapeHtml(result.platform)}</strong> page - legitimate services do not collect passwords or sensitive data through third-party form builders.`);
    }
    const fieldTypes = result.sensitiveFields.map(f => f.label.toLowerCase());
    if (fieldTypes.some(f => f.includes("password")) && fieldTypes.some(f => f.includes("ssn") || f.includes("social security"))) {
      reasons.push("This form requests both a <strong>password and SSN</strong> - no legitimate login page asks for both.");
    }
    if (fieldTypes.some(f => f.includes("password")) && fieldTypes.some(f => f.includes("mfa") || f.includes("2fa") || f.includes("verification code"))) {
      reasons.push("This form requests both a <strong>password and MFA code</strong> - real services handle these on separate authenticated pages.");
    }
    if (fieldTypes.some(f => f.includes("bank") || f.includes("routing") || f.includes("account number"))) {
      reasons.push("This form requests <strong>banking information</strong> - legitimate banks never collect account details through external forms.");
    }
    if (fieldTypes.some(f => f.includes("credit card") || f.includes("cvv") || f.includes("card number"))) {
      reasons.push("This form requests <strong>credit card details</strong> - this should only be entered on verified payment processors, not form platforms.");
    }

    // ===================================================================
    // ADDITIONS (v1.2.2 — expanded "why this might be fake" reasons)
    // Everything below is NEW — nothing above was modified.
    // ===================================================================

    if (fieldTypes.some(f => f.includes("former") || f.includes("previous"))) {
      reasons.push("This form requests <strong>former/previous credentials</strong> - no legitimate service asks for old passwords alongside current ones.");
    }
    if (fieldTypes.some(f => f.includes("national id") || f.includes("passport") || f.includes("driver"))) {
      reasons.push("This form requests <strong>government-issued ID details</strong> - legitimate identity verification uses secure, dedicated portals.");
    }
    if (fieldTypes.some(f => f.includes("maiden name") || f.includes("security question"))) {
      reasons.push("This form requests <strong>security question answers</strong> - these are used to reset passwords and should never be entered on third-party sites.");
    }
    if (fieldTypes.some(f => f.includes("date of birth"))) {
      reasons.push("This form requests your <strong>date of birth</strong> alongside other credentials - this combination is a strong phishing indicator.");
    }
    if (fieldTypes.some(f => f.includes("school") || f.includes("university") || f.includes("academic"))) {
      reasons.push("This form requests <strong>school/university information</strong> alongside login credentials — this is consistent with credential phishing targeting educational institutions.");
    }
    if (fieldTypes.some(f => f.includes("standalone harvester") || f.includes("brand impersonation"))) {
      reasons.push("This page appears to be a <strong>credential harvesting page</strong> impersonating a trusted brand on an unrelated domain.");
    }
    if (fieldTypes.some(f => f.includes("threatening language") || f.includes("excessive input"))) {
      reasons.push("This page uses <strong>threatening language</strong> combined with data collection - a hallmark of phishing attacks.");
    }

    if (reasons.length === 0) {
      reasons.push(`This page is requesting sensitive information that is unusual for <strong>${host}</strong>.`);
    }
    const reasonsHtml = reasons.map(r => `<li style="margin-bottom:6px;line-height:1.4">${r}</li>`).join("");

    // Dynamic heading based on brand detection
    const heading = detectedBrand
      ? `ClickArmor V2 detected a fake ${brandLabel} page`
      : "ClickArmor V2 detected a suspicious form";

    const subtext = detectedBrand
      ? `This page is trying to impersonate ${brandLabel}. Real ${brandLabel} sign-in pages start with <strong>${officialDisplay}</strong>, not <strong>${host}</strong>.`
      : "This page appears to be collecting sensitive information through a form that may be a phishing attempt. Do not enter personal data unless you are certain this is legitimate.";

    const html = `
      <div class="cg-overlay">
        <div class="cg-card" role="dialog" aria-modal="true">
          <div class="cg-header">
            <div class="cg-logo"><svg viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg" style="width:36px;height:36px"><polygon points="16,2 28,9 28,23 16,30 4,23 4,9" fill="#111" stroke="#111" stroke-width="0.5"/><line x1="4" y1="20" x2="13" y2="16" stroke="#f5f5f0" stroke-width="1.1" stroke-linecap="round"/><line x1="19" y1="16" x2="28" y2="20" stroke="#f5f5f0" stroke-width="1.1" stroke-linecap="round"/><circle cx="4" cy="20" r="1.8" fill="#f5f5f0"/><circle cx="28" cy="20" r="1.8" fill="#f5f5f0"/><path d="M13,16 Q16,11 19,16 Q16,21 13,16 Z" fill="none" stroke="#f5f5f0" stroke-width="1.1"/><ellipse cx="16" cy="16" rx="4" ry="2.2" fill="none" stroke="#f5f5f0" stroke-width="0.7" opacity="0.35"/><circle cx="16" cy="16" r="1.8" fill="none" stroke="#f5f5f0" stroke-width="0.9"/><circle cx="16" cy="16" r="0.9" fill="#f5f5f0"/><line x1="16" y1="2" x2="16" y2="12.5" stroke="#f5f5f0" stroke-width="0.9" stroke-linecap="round" stroke-dasharray="2 1.5" opacity="0.55"/><polygon points="16,12.5 14.5,9.5 17.5,9.5" fill="#f5f5f0" opacity="0.55"/></svg></div>
            <div>
              <h1>${heading}</h1>
              <p class="cg-sub">${subtext}</p>
            </div>
          </div>
          <div class="cg-body">
          <div class="cg-section">
            <div class="cg-section-title">Why this might be fake</div>
            <ul style="margin:8px 0 0;padding-left:18px;font-size:13px;color:#555550;line-height:1.6">${reasonsHtml}</ul>
          </div>

          <div class="cg-section">
            <div class="cg-section-title">Sensitive fields detected</div>
            <div class="cg-chips">${fieldChips}</div>
          </div>

          <div class="cg-row">
            <div class="cg-metric"><div class="cg-metric__k">${detectedBrand ? "Impersonating" : "Platform"}</div><div class="cg-metric__v">${detectedBrand ? brandLabel : platform}</div></div>
            <div class="cg-metric"><div class="cg-metric__k">Risk Score</div><div class="cg-metric__v cg-metric__v--danger">${result.totalScore}</div></div>
            <div class="cg-metric"><div class="cg-metric__k">Site</div><div class="cg-metric__v">${host}</div></div>
          </div>

          </div><!-- end cg-body -->
          <div class="cg-actions">
            <button class="cg-btn cg-btn--primary" id="cgFormLeave">Leave this site</button>
            <button class="cg-btn cg-btn--secondary" id="cgFormWhitelist">I trust this site - whitelist</button>
            <button class="cg-btn cg-btn--ghost" id="cgFormContinue">I understand the risk - continue</button>
          </div>

          <p class="cg-foot">
            Tip: always check the URL in your address bar. Legitimate ${detectedBrand ? `${brandLabel} sign-in pages start with <strong>${officialDisplay}</strong>` : "login pages use their official domain"}.
          </p>
        </div>
      </div>
    `;

    const ui = injectShadowUI("overlay", html, WARNING_CSS);
    if (!ui) return;

    try {
      document.documentElement.dataset.cgFormOverlayShown = "true";
      document.documentElement.dataset.cgImpersonatedBrand = detectedBrand ? detectedBrand.brand : "";
      document.documentElement.dataset.cgExpectedDomain = detectedBrand ? detectedBrand.officialDisplay : "";
    } catch {}

    ui.host.style.all = "initial";
    ui.host.style.position = "fixed";
    ui.host.style.inset = "0";
    ui.host.style.zIndex = "2147483647";

    const btnLeave = ui.shadow.querySelector("#cgFormLeave");
    const btnWhitelist = ui.shadow.querySelector("#cgFormWhitelist");
    const btnContinue = ui.shadow.querySelector("#cgFormContinue");

    if (btnLeave) btnLeave.addEventListener("click", () => {
      // Try to close tab via background, fall back to safe navigation
        try {
          sendRuntimeMessage({ type: "CLOSE_TAB" }).then(() => {
            // If tab didn't close (e.g. it's the last tab), navigate away
            try { window.location.href = "about:blank"; } catch {}
          });
      } catch {
        try { window.location.href = "about:blank"; } catch {}
      }
      // Also try history.back as a parallel attempt
      try { history.back(); } catch {}
    });
      if (btnWhitelist) btnWhitelist.addEventListener("click", () => {
        whitelistCurrentHost().then(() => {
          _killAllScanning();
          ui.host.remove();
        }).catch(() => {
          _killAllScanning();
          sendRuntimeMessage({ type: "ADD_WHITELIST", host: getHost() }).then(() => {});
          ui.host.remove();
        });
      });
    if (btnContinue) btnContinue.addEventListener("click", () => {
      ui.host.remove();
    });
  }

  // ===================================================================
  // ADDITIONS — Blocklist check + Sensitive form detection
  // Everything below is NEW — nothing above was modified.
  // ===================================================================

  // --- Feature: Local Blocklist ---
  // Check if current domain is on the user's blocklist and show banner if so.
  try {
    sendRuntimeMessage({ type: "CHECK_BLOCKLIST", host: _currentHost }).then((resp) => {
      if (resp?.blocked) {
        showBanner({
          bannerType: "blocklist",
          message: "This domain is on your ClickArmor V2 blocklist. This site has been flagged as potentially dangerous.",
          signals: [{ label: "Domain on local blocklist: " + _currentHost }]
        });
      }
    });
  } catch {}

  // --- Feature: Sensitive Form Detection (built in) ---
  // Official brand domains are exempt only from this overlay path so the
  // ClickFix detection logic stays untouched.
  const FormDetector = window.__ClickArmorFormDetector;
  if (FormDetector) {
    let _formScanDone = false;
    let _formBannerShown = false;

    function runFormScan() {
      if (_killed || _formScanDone || _formBannerShown) return;

      try {
        const rawHost = getHost();
        const _platRe = /^(docs|sites|drawings|drive|forms|presentations)\.google\.com$|^.+\.sharepoint\.com$|^onedrive\.live\.com$/;
        if (isOfficialBrandHost(rawHost) && !_platRe.test(rawHost)) return;

        const result = FormDetector.scanPage();
        // ===================================================================
        // FIX (v1.2.3 — early return logic bug)
        // The old code had: if (result.sensitiveFields.length === 0) return;
        // This bailed BEFORE the Tier 1 body-text password check at line ~1419
        // could ever fire. On Tier 1 platforms (Google Forms, Typeform, etc.),
        // we must NOT bail early — the body-text fallback needs to run even
        // when the field-level scan found nothing (which happens on Google Forms
        // due to deeply nested DOM). For non-platform pages with zero field hits,
        // the early return is still correct to avoid noise.
        // ===================================================================
        const _isPlatformPage = result.isFormPlatform;
        if (result.sensitiveFields.length === 0 && !_isPlatformPage) return;
        const detectedBrand = detectImpersonatedBrand(rawHost, result);

        // Generic first-party login/signup forms are too noisy on their own.
        // Keep warnings for form platforms, clear brand impersonation, or
        // high-severity data collection like SSN/banking/card/seed fields.
        //
        // Tier 1 platforms (Google Forms, Typeform, etc.): password field = always suspicious
        // Tier 2 platforms (WordPress, Netlify, Heroku, etc.): legit apps may have logins,
        //   so require additional signals beyond just email+password
        const isTier1 = result.isFormPlatform && result.platformTier === 1;
        const isTier2 = result.isFormPlatform && result.platformTier === 2;

        // Tier 2 "simple login" check: if the ONLY sensitive fields are basic
        // login fields (password + email/username), this could be a legit app login.
        // Phishing forms will have EXTRA fields (SSN, school, former credentials, etc.)
        const onlyBasicLogin = result.sensitiveFields.every(f =>
          /^(password|login email|full name)/i.test(f.label || "")
        ) && result.sensitiveFields.length <= 3;
        const tier2HasExtraSignals = !!detectedBrand || hasHighSeveritySensitiveField(result) || !onlyBasicLogin;

        // Google Forms / Tier 1 platform password harvesting detection:
        // If page body text mentions "password" and there are input fields,
        // this is credential harvesting regardless of brand match.
        // Google itself warns: "Never submit passwords through Google Forms."
        if (isTier1 && result.sensitiveFields.length === 0) {
          const _bodyLower = (document.body?.innerText || "").toLowerCase();
          const _hasPasswordQuestion = /password|passcode|pass\s*word|pwd|pin\s*code/i.test(_bodyLower);
          const _hasInputs = document.querySelectorAll('input:not([type="hidden"]):not([type="submit"]):not([type="button"])').length >= 1;
          if (_hasPasswordQuestion && _hasInputs) {
            result.sensitiveFields.push({ score: 55, label: "Password requested via form question", context: "Tier 1 platform password harvesting" });
            result.totalScore += 55;
          }
        }

        // ===================================================================
        // ADDITIONS (v1.2.3 — expanded Tier 1 body-text credential detection)
        // The original fallback only checked for "password" in body text.
        // This expanded version catches MFA codes, SSN, banking, crypto,
        // and other credential patterns. Also catches Google Docs phishing
        // that uses contenteditable regions instead of <input> elements,
        // and Google Forms that use textarea/short-answer fields.
        // Nothing above was modified.
        // ===================================================================
        if (isTier1 && result.sensitiveFields.length === 0) {
          const _bodyLower2 = (document.body?.innerText || "").toLowerCase();
          const _hasAnyInputOrEditable = (
            document.querySelectorAll('input:not([type="hidden"]):not([type="submit"]):not([type="button"]), textarea, [contenteditable="true"]').length >= 1
          );
          const _credPatterns2 = [
            { re: /\b(mfa|otp|2fa|two.?factor|verification.?code|auth.?code)\b/i, label: "MFA/OTP code requested via form question", score: 55 },
            { re: /\b(ssn|social.?security.?number)\b/i, label: "SSN requested via form question", score: 65 },
            { re: /\b(credit.?card|card.?number|cvv|bank.?account|routing.?number)\b/i, label: "Financial info requested via form question", score: 60 },
            { re: /\b(seed.?phrase|private.?key|wallet.?key|mnemonic)\b/i, label: "Crypto keys requested via form question", score: 65 },
            { re: /\b(enter|type|provide|input)\s+(your\s+)?(email|e-?mail).{0,40}(password|pwd|pass\s*word)/i, label: "Email + password requested in form text", score: 55 },
            { re: /\b(sign.?in|log.?in)\s+(to\s+)?(your\s+)?(account|email|portal|dashboard)/i, label: "Sign-in prompt on form platform", score: 45 },
            { re: /\b(student.?id|employee.?id|puid|university.?id)\b/i, label: "Institutional ID requested via form question", score: 45 },
            { re: /\bnever\s+submit\s+passwords?\b/i, label: "Google password warning detected (confirms phishing attempt)", score: 40 },
          ];

          if (_hasAnyInputOrEditable) {
            for (const cp of _credPatterns2) {
              if (cp.re.test(_bodyLower2)) {
                result.sensitiveFields.push({ score: cp.score, label: cp.label, context: "Tier 1 body text credential pattern" });
                result.totalScore += cp.score;
                break; // one hit is enough to trigger
              }
            }
          }
        }

        const shouldWarn = isTier1 || (isTier2 && tier2HasExtraSignals) || (!result.isFormPlatform && (!!detectedBrand || hasHighSeveritySensitiveField(result)));
        if (!shouldWarn) return;

        // Only warn if score is meaningful (avoid single low-confidence hit)
        // Tier 1 + brand → low threshold (35), Tier 2 without brand → higher (50)
        const minimumScore = (isTier1 || detectedBrand) ? 35 : (isTier2 ? 50 : 60);
        if (result.totalScore < minimumScore) return;

        _formScanDone = true;
        _formBannerShown = true;

        showFormOverlay(result, detectedBrand);
      } catch {}
    }

    // Scan after page settles (forms may load dynamically)
    setTimeout(runFormScan, 1500);

    // Also scan on form-related DOM changes (Typeform/Jotform load forms dynamically)
    let _formObserver = new MutationObserver(() => {
      if (!_formBannerShown) {
        clearTimeout(_formScanTimer);
        _formScanTimer = setTimeout(runFormScan, 1000);
      }
    });
    let _formScanTimer = null;
    try {
      _formObserver.observe(document.documentElement, { childList: true, subtree: true });
    } catch {}

    // Also intercept form submissions on high-risk forms
    document.addEventListener("submit", (e) => {
      if (_killed || !_formBannerShown) return;
      // If we already showed a form warning, the user is aware — don't block submission
      // Just let the existing banner serve as the warning
    }, true);
  }

  // ===================================================================
  // ADDITIONS (v1.2.2 — Brand signal detection for ALL detection paths)
  // Standalone brand detection that works independently of the form scan.
  // Used to add "This page is impersonating [Brand]" to ClickFix banners,
  // clipboard block overlays, and as a standalone page-level threat signal.
  // Nothing above was modified.
  // ===================================================================

  // Lightweight brand detection using existing FORM_IMPERSONATION_BRANDS
  // but callable from any detection path (not just form scan)
  function _detectPageBrand() {
    const rawHost = getHost();
    const _platRe2 = /^(docs|sites|drawings|drive|forms|presentations)\.google\.com$|^.+\.sharepoint\.com$|^onedrive\.live\.com$/;
    if (isOfficialBrandHost(rawHost) && !_platRe2.test(rawHost)) return null;
    const weakSsoBrands = new Set(["Google", "Facebook", "Apple", "LinkedIn", "Microsoft", "X", "Discord"]);

    const textCandidates = collectBrandTextCandidates();

    for (const brand of FORM_IMPERSONATION_BRANDS) {
      if (hostMatchesBrandDomain(rawHost, brand.officialDomains)) continue;

      // Check title, meta, og tags
      const titleHit = brand.aliases.some(alias => (
        textContainsAlias(textCandidates.title, alias) ||
        textContainsAlias(textCandidates.metaDesc, alias) ||
        textContainsAlias(textCandidates.ogSiteName, alias) ||
        textContainsAlias(textCandidates.ogTitle, alias)
      ));
      if (titleHit) {
        if (textCandidates.formTexts.length > 0) return brand;
        const result = Object.assign({}, brand);
        if (weakSsoBrands.has(brand.brand)) {
          result._bodyOnlyHit = true;
        }
        return result;
      }

      // Check UI text (headings, labels, buttons)
      let uiHitCount = 0;
      // SSO/OAuth buttons like "Log in with Google" or "Sign up using Facebook"
      // appear on millions of legitimate sites — exclude them from brand impersonation.
      const ssoPattern = /\b(log\s*in|sign\s*in|sign\s*up|continue|register|connect|auth)\b.{0,15}\b(with|using|via|through)\b/i;
      for (const text of textCandidates.uiTexts) {
        if (ssoPattern.test(text)) continue; // skip SSO buttons
        if (brand.aliases.some(alias => textContainsAlias(text, alias))) {
          uiHitCount++;
        }
      }
      if (uiHitCount >= 2) return brand;

      // Check body text for strong brand indicators
      // Body-text-only hits are lower confidence — mark them so the caller
      // can require stronger evidence (e.g., a password field) before triggering.
      const bodyText = (document.body?.innerText || "").toLowerCase().slice(0, 5000);
      let bodyHitCount = 0;
      for (const alias of brand.aliases) {
        if (textContainsAlias(bodyText, alias)) {
          bodyHitCount++;
        }
      }
      if (bodyHitCount >= 2) {
        const result = Object.assign({}, brand);
        result._bodyOnlyHit = true;
        return result;
      }

      // Single body hit + form context = likely impersonation
      // Also mark as body-only since it's still a weak signal
      if (bodyHitCount >= 1 && textCandidates.formTexts.length > 0) {
        for (const text of textCandidates.formTexts) {
          if (brand.aliases.some(alias => textContainsAlias(text, alias))) {
            const result = Object.assign({}, brand);
            result._bodyOnlyHit = true;
            return result;
          }
        }
      }
    }
    return null;
  }

  // Store detected brand for the session (used by banner upgrade + overlay)
  let _detectedPageBrand = null;

  function _detectAndStoreBrandSignals() {
    if (_detectedPageBrand) return; // already detected
    _detectedPageBrand = _detectPageBrand();

    if (_detectedPageBrand) {
      // Expose for automated testing
      try {
        document.documentElement.dataset.cgDetectedBrand = _detectedPageBrand.brand;
        document.documentElement.dataset.cgOfficialDomain = _detectedPageBrand.officialDisplay;
      } catch {}

      // If banner is already showing, upgrade it with brand info
      _upgradeBannerWithBrand(_detectedPageBrand);
    }
  }

  function _upgradeBannerWithBrand(brand) {
    if (!brand || !CG.bannerShown) return;

    // Find the banner shadow host
    const host = document.getElementById(DOM_IDS.bannerHost);
    if (!host || !host.shadowRoot) return;

    // Try to find the message span in the banner and append brand info
    const msgSpan = host.shadowRoot.querySelector(".cg-banner__msg span:last-child");
    if (!msgSpan) return;

    const brandLabel = escapeHtml(brand.brand);
    const officialDisplay = escapeHtml(brand.officialDisplay);
    const currentHost = escapeHtml(getHost());

    // Don't duplicate if already upgraded
    if (msgSpan.innerHTML.includes("impersonating")) return;

    msgSpan.innerHTML += ` <strong style="color:#b00020">This page appears to be impersonating ${brandLabel}.</strong> Real ${brandLabel} pages use <strong>${officialDisplay}</strong>, not <strong>${currentHost}</strong>.`;
  }

  // --- Enhanced showOverlay with brand detection ---
  // Upgrade the clipboard block overlay to show brand info too
  // This hooks into the existing showOverlay by watching for the overlay DOM element
  // and injecting brand context after it appears
  function _upgradeOverlayWithBrand() {
    if (!_detectedPageBrand) {
      _detectedPageBrand = _detectPageBrand();
    }
    if (!_detectedPageBrand) return;

    const host = document.getElementById(DOM_IDS.overlayHost);
    if (!host || !host.shadowRoot) return;

    const sub = host.shadowRoot.querySelector(".cg-sub");
    if (!sub) return;

    const brandLabel = escapeHtml(_detectedPageBrand.brand);
    const officialDisplay = escapeHtml(_detectedPageBrand.officialDisplay);
    const currentHost = escapeHtml(getHost());

    if (sub.innerHTML.includes("impersonating")) return;

    sub.innerHTML += `<br><strong style="color:#b00020">⚠ This page is impersonating ${brandLabel}.</strong> Legitimate ${brandLabel} pages use <strong>${officialDisplay}</strong>, not <strong>${currentHost}</strong>.`;
  }

  // Watch for overlay injection and upgrade it
  const _overlayUpgradeObserver = new MutationObserver(() => {
    if (document.getElementById(DOM_IDS.overlayHost)) {
      try { _upgradeOverlayWithBrand(); } catch {}
    }
  });
  try {
    _overlayUpgradeObserver.observe(document.documentElement, { childList: true });
  } catch {}

  // --- Standalone brand impersonation detection (page-level, not form-gated) ---
  // Catches credential harvesting pages that impersonate a brand but don't use
  // ClickFix techniques or known form platforms. If the page references a brand
  // heavily but the domain doesn't match, AND has input fields, show warning.
  function _runStandaloneBrandCheck() {
    if (_killed || _formOverlayShown || CG.overlayShown) return;

    const rawHost = getHost();
    const _platReSB = /^(docs|sites|drawings|drive|forms|presentations)\.google\.com$|^.+\.sharepoint\.com$|^onedrive\.live\.com$/;
    const _isOnPlatSB = _platReSB.test(rawHost);
    if (isOfficialBrandHost(rawHost) && !_isOnPlatSB) return;

    const brand = _detectPageBrand();
    if (!brand) return;
    if (isSharePointHost(rawHost) && brand._bodyOnlyHit) return;

    // If the brand was detected only from body text (not title/headings/UI),
    // it's likely an editorial mention (e.g., blog post discussing Facebook).
    // Require an actual password field to reduce false positives on news sites,
    // archive pages, and other non-phishing pages that mention brands.
    if (brand._bodyOnlyHit && !_isOnPlatSB) {
      const hasPasswordField = document.querySelector('input[type="password"]');
      if (!hasPasswordField) return;
    }

    // Count input fields on the page
    const { inputs, hasStrongCredentialInput, brandNearCredentialInput } = hasStrongCredentialSurface(brand.aliases);

    // Need at least 2 inputs to consider this a credential harvester
    // Exception: on platform abuse hosts, brand impersonation alone is the signal
    if (inputs.length < 2 && !_isOnPlatSB) return;

    // Check if any inputs look like real credential fields.
    // Generic email/newsletter boxes on article pages were creating false
    // positives for brand mentions like "Facebook" in titles/meta.
    if (isSharePointHost(rawHost)) {
      if (!hasStrongCredentialInput) return;
      if (!brandNearCredentialInput) return;
    }

    if (!hasStrongCredentialInput && !_isOnPlatSB) return;

    // We have: brand impersonation + credential inputs + wrong domain = show overlay
    _detectedPageBrand = brand;
    try {
      document.documentElement.dataset.cgDetectedBrand = brand.brand;
      document.documentElement.dataset.cgOfficialDomain = brand.officialDisplay;
    } catch {}

    // Build a synthetic form result for showFormOverlay
    const syntheticResult = {
      sensitiveFields: [{ score: 60, label: "Brand impersonation with credential inputs", context: "(standalone brand check)" }],
      platform: null,
      isFormPlatform: false,
      totalScore: 60
    };

    // Only show if form overlay hasn't already fired
    if (!_formOverlayShown) {
      showFormOverlay(syntheticResult, brand);
    }
  }

  // Run standalone brand check after page settles
  const _initialBrandCheckDelay = isMicrosoftCollabHost() ? 5000 : 2500;
  if (!isMicrosoftCollabHost() || !isSharePointHost() || hasSharePointPhishSignal()) {
    setTimeout(_runStandaloneBrandCheck, _initialBrandCheckDelay);
  }
  // Also on DOM changes
  let _brandCheckTimer = null;
  const _brandCheckObserver = new MutationObserver(() => {
    if (!_formOverlayShown && !_detectedPageBrand) {
      clearTimeout(_brandCheckTimer);
      if (!isMicrosoftCollabHost() || !isSharePointHost() || hasSharePointPhishSignal()) {
        _brandCheckTimer = setTimeout(_runStandaloneBrandCheck, isMicrosoftCollabHost() ? 5000 : 2000);
      }
    }
  });
  try {
    _brandCheckObserver.observe(document.documentElement, { childList: true, subtree: true });
  } catch {}

  } // end _startClickArmor

})();
