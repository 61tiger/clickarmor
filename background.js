// background.js — MV3 service worker (module)
import { scoreClipboard } from "./detector.js";

const STORAGE_KEYS = {
  enabled: "cg_enabled",
  whitelist: "cg_whitelist",
  log: "cg_log",
  stats: "cg_stats",
  pageCtx: "cg_page_ctx", // per-tab: { [tabId]: { pageThreat, adjustedThreshold, signals, ts } }
  blocklist: "cg_blocklist",
  formDetection: "cg_form_detection" // retained for compatibility; form detection now ships on
};

async function getStorage(keys) {
  return await chrome.storage.local.get(keys);
}
async function setStorage(obj) {
  return await chrome.storage.local.set(obj);
}

function nowISO() { return new Date().toISOString(); }

async function ensureDefaults() {
  const data = await getStorage([STORAGE_KEYS.enabled, STORAGE_KEYS.whitelist, STORAGE_KEYS.log, STORAGE_KEYS.stats, STORAGE_KEYS.pageCtx, STORAGE_KEYS.blocklist, STORAGE_KEYS.formDetection]);
  const patch = {};
  if (typeof data[STORAGE_KEYS.enabled] !== "boolean") patch[STORAGE_KEYS.enabled] = true;
  if (!Array.isArray(data[STORAGE_KEYS.whitelist])) patch[STORAGE_KEYS.whitelist] = [];
  if (!Array.isArray(data[STORAGE_KEYS.log])) patch[STORAGE_KEYS.log] = [];
  if (!data[STORAGE_KEYS.stats]) patch[STORAGE_KEYS.stats] = { blocked: 0, scanned: 0, lastBlockAt: null };
  if (!data[STORAGE_KEYS.pageCtx]) patch[STORAGE_KEYS.pageCtx] = {};
  if (!Array.isArray(data[STORAGE_KEYS.blocklist])) patch[STORAGE_KEYS.blocklist] = [];
  if (data[STORAGE_KEYS.formDetection] !== true) patch[STORAGE_KEYS.formDetection] = true;
  if (Object.keys(patch).length) await setStorage(patch);
}

function normalizeHost(host) {
  return (host || "").toLowerCase().replace(/^\.+/, "");
}

// Built-in whitelist: well-known sites that will never serve ClickFix attacks.
// These cannot be removed by the user — they're hardcoded to reduce noise.
const BUILTIN_WHITELIST = [
  // AI / LLM
  "chat.openai.com", "chatgpt.com", "claude.ai", "gemini.google.com",
  "copilot.microsoft.com", "poe.com", "perplexity.ai", "bard.google.com",
  // Google
  "www.google.com", "mail.google.com", "search.google.com", 
  "sheets.google.com", "slides.google.com",
  "calendar.google.com", "meet.google.com", "accounts.google.com",
  "myaccount.google.com", "maps.google.com", "news.google.com",
  "play.google.com", "photos.google.com", "translate.google.com",
  // YouTube
  "youtube.com", "www.youtube.com", "m.youtube.com", "music.youtube.com",
  "studio.youtube.com",
  // Microsoft
  "microsoft.com", "www.microsoft.com", "outlook.live.com", "outlook.office.com",
  "office.com", "www.office.com", "teams.microsoft.com",
  "login.microsoftonline.com", "portal.azure.com",
  "linkedin.com", "www.linkedin.com",
  // Social
  "twitter.com", "x.com", "facebook.com", "www.facebook.com",
  "instagram.com", "www.instagram.com", "reddit.com", "www.reddit.com",
  "old.reddit.com", "tiktok.com", "www.tiktok.com",
  "twitch.tv", "www.twitch.tv", "threads.net", "www.threads.net",
  // Dev
  "developer.mozilla.org", "npmjs.com", "www.npmjs.com",
  "pypi.org", "crates.io",
  // Commerce / streaming / misc
  "netflix.com", "www.netflix.com",
  "spotify.com", "open.spotify.com", "apple.com", "www.apple.com",
  "wikipedia.org", "en.wikipedia.org",
  // Productivity
  "notion.so", "www.notion.so", "slack.com", "app.slack.com",
  "trello.com", "figma.com", "www.figma.com", "canva.com", "www.canva.com",
  // Security tools (don't scan the analyst)
  "virustotal.com", "www.virustotal.com", "urlscan.io",
  "any.run", "app.any.run", "threatfox.abuse.ch",
  "archive.org", "web.archive.org",
  "stackoverflow.com", "www.stackoverflow.com",
  "stackexchange.com", "opendata.stackexchange.com",
  "superuser.com", "serverfault.com", "askubuntu.com",
  "stackapps.com", "mathoverflow.net",
  // Commerce / shopping
  "amazon.com", "www.amazon.com", "smile.amazon.com",
  "amazon.co.uk", "www.amazon.co.uk", "amazon.de", "www.amazon.de",
  "amazon.ca", "www.amazon.ca", "amazon.co.jp", "www.amazon.co.jp",
  "amazon.com.au", "www.amazon.com.au", "amazon.in", "www.amazon.in",
  "amazon.fr", "www.amazon.fr", "amazon.it", "www.amazon.it",
  "amazon.es", "www.amazon.es",
  "ebay.com", "www.ebay.com",
  "walmart.com", "www.walmart.com",
  "target.com", "www.target.com",
  "bestbuy.com", "www.bestbuy.com",
  // Banking / finance
  "paypal.com", "www.paypal.com",
  "chase.com", "www.chase.com",
  "bankofamerica.com", "www.bankofamerica.com",
  "wellsfargo.com", "www.wellsfargo.com",
  // Major content / news
  "cnn.com", "www.cnn.com",
  "bbc.com", "www.bbc.com", "bbc.co.uk", "www.bbc.co.uk",
  "nytimes.com", "www.nytimes.com",
  "washingtonpost.com", "www.washingtonpost.com",
  // Browser internals
  "chrome.google.com", "addons.mozilla.org", "microsoftedge.microsoft.com",
  "extensions.gnome.org",
  // Search engines
  "bing.com", "www.bing.com",
  "search.brave.com",
  "duckduckgo.com", "www.duckduckgo.com",
  "search.yahoo.com", "yahoo.com", "www.yahoo.com",
  "yandex.com", "yandex.ru",
  "ecosia.org", "www.ecosia.org",
  "startpage.com", "www.startpage.com",
  "baidu.com", "www.baidu.com",
  "naver.com", "www.naver.com",
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
    "dhl.com", "www.dhl.com",
    // --- Major News Outlets (expanded v1.3.1-public) ---
    "forbes.com", "www.forbes.com",
    "reuters.com", "www.reuters.com",
    "apnews.com", "www.apnews.com",
    "bloomberg.com", "www.bloomberg.com",
    "cnbc.com", "www.cnbc.com",
    "foxnews.com", "www.foxnews.com",
    "nbcnews.com", "www.nbcnews.com",
    "abcnews.go.com",
    "cbsnews.com", "www.cbsnews.com",
    "usatoday.com", "www.usatoday.com",
    "wsj.com", "www.wsj.com",
    "theguardian.com", "www.theguardian.com",
    "time.com", "www.time.com",
    "newsweek.com", "www.newsweek.com",
    "huffpost.com", "www.huffpost.com",
    "politico.com", "www.politico.com",
    "axios.com", "www.axios.com",
    "thehill.com", "www.thehill.com",
    "npr.org", "www.npr.org",
    "pbs.org", "www.pbs.org",
    "aljazeera.com", "www.aljazeera.com",
    "ft.com", "www.ft.com",
    "economist.com", "www.economist.com",
    "businessinsider.com", "www.businessinsider.com",
    "insider.com", "www.insider.com",
    "techcrunch.com", "www.techcrunch.com",
    "wired.com", "www.wired.com",
    "theverge.com", "www.theverge.com",
    "arstechnica.com", "www.arstechnica.com",
    "engadget.com", "www.engadget.com",
    "mashable.com", "www.mashable.com",
    "cnet.com", "www.cnet.com",
    "zdnet.com", "www.zdnet.com",
    "vice.com", "www.vice.com",
    "vox.com", "www.vox.com",
    "slate.com", "www.slate.com",
    "salon.com", "www.salon.com",
    "thedailybeast.com", "www.thedailybeast.com",
    "buzzfeed.com", "www.buzzfeed.com",
    "latimes.com", "www.latimes.com",
    "chicagotribune.com", "www.chicagotribune.com",
    "nypost.com", "www.nypost.com",
    "dailymail.co.uk", "www.dailymail.co.uk",
    "telegraph.co.uk", "www.telegraph.co.uk",
    "independent.co.uk", "www.independent.co.uk",
    "sky.com", "news.sky.com",
    "france24.com", "www.france24.com",
    "dw.com", "www.dw.com",
    "japantimes.co.jp", "www.japantimes.co.jp",
    "scmp.com", "www.scmp.com",
    "straitstimes.com", "www.straitstimes.com",
    "abc.net.au", "www.abc.net.au",
    "news.com.au", "www.news.com.au",
    "cbc.ca", "www.cbc.ca",
    "globalnews.ca",
    "theatlantic.com", "www.theatlantic.com",
    "newyorker.com", "www.newyorker.com",
    "vanityfair.com", "www.vanityfair.com",
    "rollingstone.com", "www.rollingstone.com",
    "people.com", "www.people.com",
    "ew.com", "www.ew.com",
    "variety.com", "www.variety.com",
    "hollywoodreporter.com", "www.hollywoodreporter.com",
    "deadline.com", "www.deadline.com",
    // --- Sports ---
    "espn.com", "www.espn.com",
    "sports.yahoo.com",
    "bleacherreport.com", "www.bleacherreport.com",
    "cbssports.com", "www.cbssports.com",
    "foxsports.com", "www.foxsports.com",
    "nba.com", "www.nba.com",
    "nfl.com", "www.nfl.com",
    "mlb.com", "www.mlb.com",
    "nhl.com", "www.nhl.com",
    "si.com", "www.si.com",
    "theathletic.com", "www.theathletic.com",
    // --- Tech News ---
    "tomshardware.com", "www.tomshardware.com",
    "pcmag.com", "www.pcmag.com",
    "pcworld.com", "www.pcworld.com",
    "macrumors.com", "www.macrumors.com",
    "9to5mac.com", "www.9to5mac.com",
    "9to5google.com", "www.9to5google.com",
    "androidcentral.com", "www.androidcentral.com",
    "xda-developers.com", "www.xda-developers.com",
    "howtogeek.com", "www.howtogeek.com",
    "tomsguide.com", "www.tomsguide.com",
    "gizmodo.com", "www.gizmodo.com",
    "lifehacker.com", "www.lifehacker.com",
    "kotaku.com", "www.kotaku.com",
    "ign.com", "www.ign.com",
    "gamespot.com", "www.gamespot.com",
    "polygon.com", "www.polygon.com",
    "eurogamer.net", "www.eurogamer.net",
    "destructoid.com", "www.destructoid.com",
    // --- International News ---
    "bild.de", "www.bild.de",
    "spiegel.de", "www.spiegel.de",
    "zeit.de", "www.zeit.de",
    "lemonde.fr", "www.lemonde.fr",
    "lefigaro.fr", "www.lefigaro.fr",
    "elpais.com", "www.elpais.com",
    "corriere.it", "www.corriere.it",
    "repubblica.it", "www.repubblica.it",
    "asahi.com", "www.asahi.com",
    "mainichi.jp",
    "timesofindia.indiatimes.com",
    "ndtv.com", "www.ndtv.com",
    "hindustantimes.com", "www.hindustantimes.com",
    // --- Finance / Business ---
    "marketwatch.com", "www.marketwatch.com",
    "barrons.com", "www.barrons.com",
    "fool.com", "www.fool.com",
    "seekingalpha.com", "www.seekingalpha.com",
    "investopedia.com", "www.investopedia.com",
    "finance.yahoo.com",
    "money.cnn.com",
    // --- Weather ---
    "weather.com", "www.weather.com",
    "accuweather.com", "www.accuweather.com",
    "wunderground.com", "www.wunderground.com",
    // --- Reference / Major Sites ---
    "imdb.com", "www.imdb.com",
    "rottentomatoes.com", "www.rottentomatoes.com",
    "yelp.com", "www.yelp.com",
    "tripadvisor.com", "www.tripadvisor.com",
    "quora.com", "www.quora.com",
    "medium.com", "www.medium.com",
    "substack.com", "www.substack.com",
    "tumblr.com", "www.tumblr.com",
    "pinterest.com", "www.pinterest.com",
    "flickr.com", "www.flickr.com",
    "deviantart.com", "www.deviantart.com",
    "etsy.com", "www.etsy.com",
    "craigslist.org", "www.craigslist.org",
    "zillow.com", "www.zillow.com",
    "realtor.com", "www.realtor.com",
    "glassdoor.com", "www.glassdoor.com",
    "indeed.com", "www.indeed.com",
    // --- Health ---
    "webmd.com", "www.webmd.com",
    "mayoclinic.org", "www.mayoclinic.org",
    "healthline.com", "www.healthline.com",
    "clevelandclinic.org", "www.clevelandclinic.org",
    "nih.gov", "www.nih.gov",
    "cdc.gov", "www.cdc.gov",
    // --- Gaming Platforms ---
    "steampowered.com", "store.steampowered.com",
    "epicgames.com", "www.epicgames.com",
    "gog.com", "www.gog.com",
    "ea.com", "www.ea.com",
    "ubisoft.com", "www.ubisoft.com",
    "playstation.com", "www.playstation.com",
    "xbox.com", "www.xbox.com",
    "nintendo.com", "www.nintendo.com",
    "roblox.com", "www.roblox.com",
    // --- Dev Platforms ---
    "github.com", "www.github.com",
    "gitlab.com", "www.gitlab.com",
    "bitbucket.org", "www.bitbucket.org",
    "codepen.io",
    "jsfiddle.net",
    "replit.com", "www.replit.com",
    "vercel.com", "www.vercel.com",
    "netlify.com", "www.netlify.com",
    "heroku.com", "www.heroku.com",
    "digitalocean.com", "www.digitalocean.com",
    "linode.com", "www.linode.com",
    "cloudflare.com", "www.cloudflare.com",
    "aws.amazon.com",
    "console.cloud.google.com",
    // --- Food / Recipes ---
    "allrecipes.com", "www.allrecipes.com",
    "foodnetwork.com", "www.foodnetwork.com",
    "epicurious.com", "www.epicurious.com",
    "tasty.co",
    // --- Social / Messaging ---
    "discord.com", "www.discord.com",
    "signal.org", "www.signal.org",
    "telegram.org", "web.telegram.org",
    "whatsapp.com", "web.whatsapp.com",
    "snapchat.com", "www.snapchat.com",
    "mastodon.social",
    "bsky.app",
    // --- ClickFix Research / Threat Intel ---
    "carsonww.com", "clickfix.carsonww.com",
    "clickfixhunter.com", "www.clickfixhunter.com"

];


// ===================================================================
// REMOTE WHITELIST (v1.3.1-public — GitHub-hosted)
// Fetches additional whitelist domains from public GitHub repo.
// Merged with built-in whitelist. Cannot REMOVE built-in entries.
// ===================================================================

const WHITELIST_URL = "https://raw.githubusercontent.com/ditm-security/rules/main/whitelist.json";
const WHITELIST_STORAGE_KEY = "cg_remote_whitelist";
const WHITELIST_META_KEY = "cg_remote_whitelist_meta";
const WHITELIST_POLL_MS = 4 * 60 * 60 * 1000; // 4 hours

async function loadBundledWhitelist() {
  try {
    const existing = await getStorage([WHITELIST_STORAGE_KEY]);
    if (existing[WHITELIST_STORAGE_KEY]?.length) return;
    const url = chrome.runtime.getURL("whitelist.json");
    const resp = await fetch(url);
    if (!resp.ok) return;
    const json = await resp.json();
    if (!json || !Array.isArray(json.domains)) return;
    await setStorage({ [WHITELIST_STORAGE_KEY]: json.domains });
  } catch {}
}

async function fetchRemoteWhitelist() {
  try {
    const meta = (await getStorage([WHITELIST_META_KEY]))[WHITELIST_META_KEY] || {};
    const now = Date.now();
    if (meta.lastFetch && (now - meta.lastFetch) < WHITELIST_POLL_MS) return;

    const headers = {};
    if (meta.etag) headers["If-None-Match"] = meta.etag;

    const resp = await fetch(WHITELIST_URL, { headers, cache: "no-cache" });

    if (resp.status === 304) {
      await setStorage({ [WHITELIST_META_KEY]: { ...meta, lastFetch: now } });
      return;
    }

    if (!resp.ok) {
      await setStorage({ [WHITELIST_META_KEY]: { ...meta, lastFetch: now, lastError: resp.status } });
      return;
    }

    const json = await resp.json();
    if (!json || !Array.isArray(json.domains)) {
      await setStorage({ [WHITELIST_META_KEY]: { ...meta, lastFetch: now, lastError: "invalid_schema" } });
      return;
    }

    const etag = resp.headers.get("etag") || "";
    await setStorage({
      [WHITELIST_STORAGE_KEY]: json.domains,
      [WHITELIST_META_KEY]: { lastFetch: now, etag, count: json.domains.length }
    });
  } catch (e) {
    try {
      const meta = (await getStorage([WHITELIST_META_KEY]))[WHITELIST_META_KEY] || {};
      await setStorage({ [WHITELIST_META_KEY]: { ...meta, lastFetch: Date.now(), lastError: String(e?.message || e) } });
    } catch {}
  }
}

// Cached remote whitelist for sync lookups
let _remoteWhitelistCache = [];
async function refreshRemoteWhitelistCache() {
  try {
    const data = await getStorage([WHITELIST_STORAGE_KEY]);
    _remoteWhitelistCache = (data[WHITELIST_STORAGE_KEY] || []).map(d => normalizeHost(d));
  } catch {}
}

function isBuiltinWhitelisted(host) {
  const h = normalizeHost(host);
  if (BUILTIN_WHITELIST.includes(h)) return true;
  for (const entry of BUILTIN_WHITELIST) {
    if (h.endsWith("." + entry)) return true;
  }
  // Also check remote whitelist (cached in memory for sync access)
  if (_remoteWhitelistCache.includes(h)) return true;
  for (const entry of _remoteWhitelistCache) {
    if (h.endsWith("." + entry)) return true;
  }
  return false;
}

function truncate(s, n=100) {
  const t = (s || "").toString();
  return t.length > n ? t.slice(0, n) + "…" : t;
}

async function updateBadge() {
  const { [STORAGE_KEYS.stats]: stats } = await getStorage([STORAGE_KEYS.stats]);
  const blocked = stats?.blocked || 0;
  await chrome.action.setBadgeText({ text: blocked ? String(blocked) : "" });

  const recent = stats?.lastBlockAt ? (Date.now() - Date.parse(stats.lastBlockAt) < 5 * 60 * 1000) : false;
  // red-ish badge if recent; default if not
  await chrome.action.setBadgeBackgroundColor({ color: recent ? "#ff3366" : "#555555" });
}

chrome.runtime.onInstalled.addListener(async () => {
  await ensureDefaults();
  await updateBadge();
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  // Use named async handler + .then(sendResponse) to prevent Chrome MV3 service worker
  // race condition where the message port closes before sendResponse is called.
  // (The old fire-and-forget IIFE pattern allowed the service worker to go idle between
  // awaits, orphaning sendResponse and silently dropping block verdicts back to content.js.)
  const handleMessage = async () => {
    await ensureDefaults();

    if (msg?.type === "PAGE_THREAT") {
      const tabId = sender.tab?.id;
      if (typeof tabId !== "number") return ({ ok: false });

      const { [STORAGE_KEYS.pageCtx]: pageCtx, [STORAGE_KEYS.stats]: stats } = await getStorage([STORAGE_KEYS.pageCtx, STORAGE_KEYS.stats]);
      const next = { ...(pageCtx || {}) };
      next[String(tabId)] = {
        pageThreat: msg.pageThreat ?? 0,
        adjustedThreshold: msg.adjustedThreshold ?? 60,
        signals: msg.signals ?? [],
        ts: nowISO()
      };

      await setStorage({
        [STORAGE_KEYS.pageCtx]: next,
        [STORAGE_KEYS.stats]: { ...(stats || { blocked: 0, scanned: 0 }), scanned: (stats?.scanned || 0) + 1 }
      });

      await updateBadge();
      return ({ ok: true });
    }

    if (msg?.type === "SCORE_CLIPBOARD") {
      const tabId = sender.tab?.id;
      const url = sender.tab?.url || "";
      const host = normalizeHost((new URL(url)).hostname);

      const data = await getStorage([STORAGE_KEYS.enabled, STORAGE_KEYS.whitelist, STORAGE_KEYS.pageCtx, STORAGE_KEYS.log, STORAGE_KEYS.stats]);
      const enabled = data[STORAGE_KEYS.enabled] !== false;
      const whitelist = (data[STORAGE_KEYS.whitelist] || []).map(normalizeHost);
      const pageCtx = data[STORAGE_KEYS.pageCtx] || {};
      const ctx = tabId != null ? pageCtx[String(tabId)] : null;

      if (!enabled) return ({ ok: true, verdict: "disabled", action: "allow", score: 0, threshold: 999, matches: [], ctx });

      const hostNoWww = host.replace(/^www\./, "");
      if (isBuiltinWhitelisted(host) || whitelist.includes(host) || whitelist.includes(hostNoWww) || whitelist.some(e => host.endsWith("." + e))) return ({ ok: true, verdict: "whitelisted", action: "allow", score: 0, threshold: 999, matches: [], ctx });

      const threshold = ctx?.adjustedThreshold ?? 60;

      const result = scoreClipboard(msg.text || "");

      // --- Remote clipboard rules (v1.2.6) ---
      // Merge remote clipboard rules on top of built-in scoreClipboard result.
      // Remote rules can only ADD score, never reduce it.
      try {
        const rData = await getStorage([RULES_STORAGE_KEY]);
        const remoteRules = rData?.[RULES_STORAGE_KEY];
        if (remoteRules?.clipboard && Array.isArray(remoteRules.clipboard)) {
          const clipText = (msg.text || "").toLowerCase();
          for (const r of remoteRules.clipboard) {
            if (!r.re || typeof r.re !== "string") continue;
            try {
              const regex = new RegExp(r.re, r.flags || "i");
              if (regex.test(clipText) || regex.test(msg.text || "")) {
                result.score = Math.min(100, (result.score || 0) + (r.score || 0));
                result.matches = result.matches || [];
                result.matches.push({ label: "[R] " + (r.label || "Remote clipboard rule"), weight: r.score || 0 });
              }
            } catch {}
          }
          if (result.score >= 60 && result.verdict === "clean") {
            result.verdict = "suspicious";
          }
        }
      } catch {} // fail silently — built-in scoring already ran

      const score = result.score;
      const verdict = result.verdict;

      // Decide action with your spec rules
      let action = "allow";
      if (score >= 60) action = "block";
      else if (score >= threshold) action = "block"; // page lowered threshold
      else if (score >= 30) action = "log";

      // write log entry for suspicious + blocked
      if (action !== "allow") {
        const log = Array.isArray(data[STORAGE_KEYS.log]) ? data[STORAGE_KEYS.log] : [];
        const entry = {
          timestamp: nowISO(),
          domain: host,
          url,
          clipboardPreview: truncate(msg.text || "", 100),
          score,
          threshold,
          action,
          verdict,
          matchedPatterns: result.matches.map(m => m.label),
          pageSignals: (ctx?.signals || []).slice(0, 12).map(s => s.label)
        };
        const nextLog = [entry, ...log].slice(0, 100);

        const stats = data[STORAGE_KEYS.stats] || { blocked: 0, scanned: 0, lastBlockAt: null };
        const nextStats = { ...stats };
        if (action === "block") {
          nextStats.blocked = (nextStats.blocked || 0) + 1;
          nextStats.lastBlockAt = nowISO();
        }

        await setStorage({ [STORAGE_KEYS.log]: nextLog, [STORAGE_KEYS.stats]: nextStats });
        await updateBadge();
      }

      return ({ ok: true, score, threshold, action, verdict, matches: result.matches, ctx });
    }

    if (msg?.type === "ADD_WHITELIST") {
      const host = normalizeHost(msg.host);
      const data = await getStorage([STORAGE_KEYS.whitelist]);
      const list = (data[STORAGE_KEYS.whitelist] || []).map(normalizeHost);
      if (host && !list.includes(host)) list.push(host);
      await setStorage({ [STORAGE_KEYS.whitelist]: list });
      return ({ ok: true, whitelist: list });
    }

    if (msg?.type === "CHECK_WHITELIST") {
      const host = normalizeHost(msg.host || "");
      const hostNoWww = host.replace(/^www\./, "");
      const data = await getStorage([STORAGE_KEYS.enabled, STORAGE_KEYS.whitelist]);
      const enabled = data[STORAGE_KEYS.enabled] !== false;
      const list = (data[STORAGE_KEYS.whitelist] || []).map(normalizeHost);
      // Match: exact, without www, or as subdomain of a whitelist entry
      const userWhitelisted = list.includes(host) || list.includes(hostNoWww) || list.some(e => host.endsWith("." + e));
      // If extension is disabled or host is whitelisted (builtin or user), content script should bail out
      const whitelisted = !enabled || isBuiltinWhitelisted(host) || userWhitelisted;
      return ({ ok: true, whitelisted });
    }

    if (msg?.type === "REMOVE_WHITELIST") {
      const host = normalizeHost(msg.host);
      const data = await getStorage([STORAGE_KEYS.whitelist]);
      const list = (data[STORAGE_KEYS.whitelist] || []).map(normalizeHost).filter(h => h !== host);
      await setStorage({ [STORAGE_KEYS.whitelist]: list });
      return ({ ok: true, whitelist: list });
    }

    if (msg?.type === "CLOSE_TAB") {
      const tabId = sender.tab?.id;
      if (tabId) {
        try { await chrome.tabs.remove(tabId); } catch {}
      }
      return ({ ok: true });
    }

    if (msg?.type === "GET_STATE") {
      const data = await getStorage([STORAGE_KEYS.enabled, STORAGE_KEYS.whitelist, STORAGE_KEYS.log, STORAGE_KEYS.stats, STORAGE_KEYS.blocklist, STORAGE_KEYS.formDetection]);
      return ({ ok: true, enabled: data[STORAGE_KEYS.enabled] !== false, whitelist: data[STORAGE_KEYS.whitelist] || [], builtinWhitelist: BUILTIN_WHITELIST, log: data[STORAGE_KEYS.log] || [], stats: data[STORAGE_KEYS.stats] || { blocked: 0, scanned: 0 }, blocklist: data[STORAGE_KEYS.blocklist] || [], formDetection: true });
    }

    // --- Blocklist CRUD ---
    if (msg?.type === "ADD_BLOCKLIST") {
      const host = normalizeHost(msg.host);
      const data = await getStorage([STORAGE_KEYS.blocklist]);
      const list = (data[STORAGE_KEYS.blocklist] || []).map(normalizeHost);
      if (host && !list.includes(host)) list.push(host);
      await setStorage({ [STORAGE_KEYS.blocklist]: list });
      return ({ ok: true, blocklist: list });
    }

    if (msg?.type === "REMOVE_BLOCKLIST") {
      const host = normalizeHost(msg.host);
      const data = await getStorage([STORAGE_KEYS.blocklist]);
      const list = (data[STORAGE_KEYS.blocklist] || []).map(normalizeHost).filter(h => h !== host);
      await setStorage({ [STORAGE_KEYS.blocklist]: list });
      return ({ ok: true, blocklist: list });
    }

    if (msg?.type === "CHECK_BLOCKLIST") {
      const host = normalizeHost(msg.host || "");
      const data = await getStorage([STORAGE_KEYS.blocklist]);
      const list = (data[STORAGE_KEYS.blocklist] || []).map(normalizeHost);
      const blocked = list.includes(host);
      return ({ ok: true, blocked });
    }

    // --- Sensitive form detection (always on) ---
    if (msg?.type === "SET_FORM_DETECTION") {
      await setStorage({ [STORAGE_KEYS.formDetection]: true });
      return ({ ok: true, enabled: true });
    }

    if (msg?.type === "GET_FORM_DETECTION") {
      return ({ ok: true, enabled: true });
    }

    if (msg?.type === "SET_ENABLED") {
      await setStorage({ [STORAGE_KEYS.enabled]: !!msg.enabled });
      await updateBadge();
      return ({ ok: true });
    }

    if (msg?.type === "CLEAR_LOG") {
      await setStorage({ [STORAGE_KEYS.log]: [] });
      return ({ ok: true });
    }

    return { ok: false, error: "unknown_message" };
  };

  // Firefox-proven pattern: explicit .then() chain keeps the promise tracked by the
  // runtime so sendResponse can't get orphaned by service worker idle timeouts.
  handleMessage().then(result => {
    try { sendResponse(result); } catch {}
  }).catch(() => {
    try { sendResponse({ ok: false, error: "internal" }); } catch {}
  });

  // keep channel open for async response
  return true;
});

chrome.tabs.onRemoved.addListener(async (tabId) => {
  const data = await getStorage([STORAGE_KEYS.pageCtx]);
  const ctx = data[STORAGE_KEYS.pageCtx] || {};
  if (ctx[String(tabId)]) {
    delete ctx[String(tabId)];
    await setStorage({ [STORAGE_KEYS.pageCtx]: ctx });
  }
});

// LOW-1: Reset page context on navigation (prevents stale heightened thresholds)
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo) => {
  if (changeInfo.url) {
    const data = await getStorage([STORAGE_KEYS.pageCtx]);
    const ctx = data[STORAGE_KEYS.pageCtx] || {};
    if (ctx[String(tabId)]) {
      delete ctx[String(tabId)];
      await setStorage({ [STORAGE_KEYS.pageCtx]: ctx });
    }
  }
});

// MED-1: Prune stale pageCtx entries on startup (tabs don't survive restarts)
chrome.runtime.onStartup.addListener(async () => {
  await setStorage({ [STORAGE_KEYS.pageCtx]: {} });
  await updateBadge();
  fetchRemoteRules(); // refresh rules on browser start
  refreshRemoteWhitelistCache(); // restore in-memory cache from storage
  fetchRemoteWhitelist().then(() => refreshRemoteWhitelistCache());
});

// ===================================================================
// REMOTE RULES (v1.3.1-public — GitHub-hosted, no API key)
// ===================================================================

const RULES_URL = "https://raw.githubusercontent.com/ditm-security/rules/main/rules.json";
const RULES_STORAGE_KEY = "cg_remote_rules";
const RULES_META_KEY = "cg_remote_rules_meta";
const RULES_POLL_MS = 4 * 60 * 60 * 1000;

async function loadBundledRules() {
  try {
    const existing = await getStorage([RULES_STORAGE_KEY]);
    if (existing[RULES_STORAGE_KEY]) return;
    const url = chrome.runtime.getURL("rules.json");
    const resp = await fetch(url);
    if (!resp.ok) return;
    const json = await resp.json();
    if (!json || typeof json.version !== "number") return;
    await setStorage({ [RULES_STORAGE_KEY]: json });
  } catch {}
}

async function fetchRemoteRules() {
  try {
    const meta = (await getStorage([RULES_META_KEY]))[RULES_META_KEY] || {};
    const now = Date.now();
    if (meta.lastFetch && (now - meta.lastFetch) < RULES_POLL_MS) return;
    const headers = {};
    if (meta.etag) headers["If-None-Match"] = meta.etag;
    const resp = await fetch(RULES_URL, { headers, cache: "no-cache" });
    if (resp.status === 304) {
      await setStorage({ [RULES_META_KEY]: { ...meta, lastFetch: now } });
      return;
    }
    if (!resp.ok) {
      await setStorage({ [RULES_META_KEY]: { ...meta, lastFetch: now, lastError: resp.status } });
      return;
    }
    const json = await resp.json();
    if (!json || typeof json.version !== "number") {
      await setStorage({ [RULES_META_KEY]: { ...meta, lastFetch: now, lastError: "invalid_schema" } });
      return;
    }
    const etag = resp.headers.get("etag") || "";
    await setStorage({
      [RULES_STORAGE_KEY]: json,
      [RULES_META_KEY]: { lastFetch: now, etag, version: json.version, ruleCount: countRules(json) }
    });
  } catch (e) {
    try {
      const meta = (await getStorage([RULES_META_KEY]))[RULES_META_KEY] || {};
      await setStorage({ [RULES_META_KEY]: { ...meta, lastFetch: Date.now(), lastError: String(e?.message || e) } });
    } catch {}
  }
}

function countRules(json) {
  let n = 0;
  for (const layer of Object.keys(json)) {
    if (Array.isArray(json[layer])) n += json[layer].length;
  }
  return n;
}

// Always restore remote whitelist cache from storage on service worker init
refreshRemoteWhitelistCache();

chrome.runtime.onInstalled.addListener(() => {
  loadBundledRules().then(() => fetchRemoteRules());
  loadBundledWhitelist().then(() => fetchRemoteWhitelist()).then(() => refreshRemoteWhitelistCache());
});

try {
  chrome.alarms.create("cg_rules_poll", { periodInMinutes: 240 });
  chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === "cg_rules_poll") { fetchRemoteRules(); fetchRemoteWhitelist().then(() => refreshRemoteWhitelistCache()); }
  });
} catch {
  setInterval(() => { fetchRemoteRules(); fetchRemoteWhitelist().then(() => refreshRemoteWhitelistCache()); }, RULES_POLL_MS);
}
