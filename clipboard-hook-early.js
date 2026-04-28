// clipboard-hook-early.js — Injects clipboard hooks at document_start
// This MUST run before page scripts to intercept clipboard.writeText / execCommand('copy')
// before the page can register click handlers that use them.
(function () {
  // --- Built-in whitelist fast-path: skip hook injection on known-safe sites ---
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
    "netflix.com","www.netflix.com",
    "spotify.com","open.spotify.com","apple.com","www.apple.com",
    "wikipedia.org","en.wikipedia.org",
    "notion.so","www.notion.so","slack.com","app.slack.com",
    "trello.com","figma.com","www.figma.com","canva.com","www.canva.com",
    "virustotal.com","www.virustotal.com","urlscan.io",
    "any.run","app.any.run","threatfox.abuse.ch",
    "chrome.google.com","addons.mozilla.org","microsoftedge.microsoft.com",
    "extensions.gnome.org",
    "bing.com","www.bing.com",
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
  try {
    const h = location.hostname.toLowerCase();
    if (_BUILTIN_WL.includes(h) || _BUILTIN_WL.some(e => h.endsWith("." + e))) return;
  } catch {}

  // Generate per-session nonce for postMessage authentication (CRIT-1)
  const NONCE = crypto.randomUUID ? crypto.randomUUID() : (Math.random().toString(36) + Math.random().toString(36)).slice(2, 34);
  // Expose nonce to content script world via a DOM marker the content script can read
  try {
    const marker = document.createElement("meta");
    marker.setAttribute("name", "cg-nonce");
    marker.setAttribute("content", NONCE);
    (document.head || document.documentElement).appendChild(marker);
  } catch {}

  try {
    const s = document.createElement("script");
    s.textContent = `(function(){
      if (window.__clickguard_hooks_installed) return;
      window.__clickguard_hooks_installed = true;
      var _cgn = "${NONCE}";
      function _cgPost(type, text) {
        try { window.postMessage({__clickguard:true,_cgn:_cgn,type:type,text:String(text||"")}, "*"); } catch {}
      }
      try {
        // --- Hook navigator.clipboard.writeText (instance + prototype) ---
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
        // Also hook Clipboard.prototype.writeText (CRIT-2c)
        try {
          var protoWT = Clipboard.prototype.writeText;
          if (protoWT) {
            var hookedProtoWT = async function(text){
              _cgPost("CLIPBOARD_WRITE", text);
              return protoWT.call(this, text);
            };
            try { Object.defineProperty(Clipboard.prototype, 'writeText', { value: hookedProtoWT, writable: false, configurable: false }); } catch { Clipboard.prototype.writeText = hookedProtoWT; }
          }
        } catch {}

        // --- Hook navigator.clipboard.write (CRIT-3: complete bypass via ClipboardItem) ---
        var origW = navigator.clipboard && navigator.clipboard.write
          ? navigator.clipboard.write.bind(navigator.clipboard)
          : null;
        if (origW) {
          var hookedW = async function(items){
            try {
              if (items && items.length) {
                for (var i = 0; i < items.length; i++) {
                  var it = items[i];
                  if (it && it.types && it.types.indexOf("text/plain") !== -1) {
                    try {
                      var blob = await it.getType("text/plain");
                      var txt = await blob.text();
                      if (txt) _cgPost("CLIPBOARD_WRITE", txt);
                    } catch {}
                  }
                }
              }
            } catch {}
            return origW(items);
          };
          try { Object.defineProperty(navigator.clipboard, 'write', { value: hookedW, writable: false, configurable: false }); } catch { navigator.clipboard.write = hookedW; }
        }
        // Also hook Clipboard.prototype.write
        try {
          var protoW = Clipboard.prototype.write;
          if (protoW) {
            var hookedProtoW = async function(items){
              try {
                if (items && items.length) {
                  for (var i = 0; i < items.length; i++) {
                    var it = items[i];
                    if (it && it.types && it.types.indexOf("text/plain") !== -1) {
                      try {
                        var blob = await it.getType("text/plain");
                        var txt = await blob.text();
                        if (txt) _cgPost("CLIPBOARD_WRITE", txt);
                      } catch {}
                    }
                  }
                }
              } catch {}
              return protoW.call(this, items);
            };
            try { Object.defineProperty(Clipboard.prototype, 'write', { value: hookedProtoW, writable: false, configurable: false }); } catch { Clipboard.prototype.write = hookedProtoW; }
          }
        } catch {}

        // --- Hook document.execCommand('copy') ---
        var origEC = document.execCommand ? document.execCommand.bind(document) : null;
        if (origEC) {
          var hookedEC = function(cmd, ui, value){
            try {
              if (String(cmd).toLowerCase() === "copy") {
                var t = "";
                try { t = (window.getSelection && window.getSelection().toString()) ? window.getSelection().toString() : ""; } catch {}
                try {
                  if (!t) {
                    var ae = document.activeElement;
                    if (ae && (ae.tagName === "TEXTAREA" || ae.tagName === "INPUT")) t = ae.value || "";
                  }
                } catch {}
                if (t) _cgPost("CLIPBOARD_WRITE", t);
                else _cgPost("CLIPBOARD_COPY_EVENT", "");
              }
            } catch {}
            return origEC(cmd, ui, value);
          };
          try { Object.defineProperty(document, 'execCommand', { value: hookedEC, writable: false, configurable: false }); } catch { document.execCommand = hookedEC; }
        }

        // --- Hook ClipboardEvent.clipboardData.setData ---
        // Catches ClickFix attacks that use copy event listeners with e.clipboardData.setData()
        // to silently replace clipboard contents (bypasses execCommand hook since the real payload
        // is injected via the event, not the selection)
        try {
          var origSetData = DataTransfer.prototype.setData;
          if (origSetData) {
            DataTransfer.prototype.setData = function(format, data) {
              try {
                if (/text/i.test(String(format)) && data && String(data).length > 5) {
                  _cgPost("CLIPBOARD_WRITE", String(data));
                }
              } catch {}
              return origSetData.call(this, format, data);
            };
          }
        } catch {}
      } catch {}
    })();`;
    (document.documentElement || document.head || document.body || document).appendChild(s);
    s.remove();
  } catch {}
})();
