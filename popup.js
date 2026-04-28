function el(id){ return document.getElementById(id); }

function timeAgo(iso) {
  try {
    const t = Date.parse(iso);
    const s = Math.max(1, Math.floor((Date.now() - t)/1000));
    if (s < 60) return s + "s ago";
    const m = Math.floor(s/60);
    if (m < 60) return m + "m ago";
    const h = Math.floor(m/60);
    if (h < 48) return h + "h ago";
    const d = Math.floor(h/24);
    return d + "d ago";
  } catch { return ""; }
}

function renderLog(log) {
  const box = el("log");
  box.innerHTML = "";
  if (!log.length) {
    box.innerHTML = `<div class="item"><div class="sub">No detections yet.</div></div>`;
    return;
  }
  for (const entry of log.slice(0,5)) {
    const sev = entry.action === "block" ? "BLOCKED" : "SUSPICIOUS";
    const host = entry.domain || "(unknown)";
    const ago = timeAgo(entry.timestamp);
    const sub = (entry.clipboardPreview || "").replace(/\s+/g," ").slice(0,120);

    const div = document.createElement("div");
    div.className = "item";

    const topDiv = document.createElement("div");
    topDiv.className = "top";
    const hostSpan = document.createElement("span");
    hostSpan.textContent = host;
    const badge = document.createElement("span");
    badge.className = "tag";
    badge.textContent = `${sev} \u2022 ${entry.score}/100`;
    topDiv.appendChild(hostSpan);
    topDiv.appendChild(badge);

    const subDiv = document.createElement("div");
    subDiv.className = "sub";
    subDiv.textContent = `${ago} \u2022 ${sub || "(no preview)"}`;

    div.appendChild(topDiv);
    div.appendChild(subDiv);
    box.appendChild(div);
  }
}

function renderWhitelist(list) {
  const box = el("whitelist");
  box.innerHTML = "";
  if (!list.length) {
    box.innerHTML = `<div class="item"><div class="sub">No whitelisted domains.</div></div>`;
    return;
  }
  for (const host of list) {
    const row = document.createElement("div");
    row.className = "wl";
    const span = document.createElement("span");
    span.textContent = host;
    const btn = document.createElement("button");
    btn.textContent = "Remove";
    btn.addEventListener("click", async () => {
      await chrome.runtime.sendMessage({ type: "REMOVE_WHITELIST", host });
      await refresh();
    });
    row.appendChild(span);
    row.appendChild(btn);
    box.appendChild(row);
  }
}

function renderBlocklist(list) {
  const box = el("blocklist");
  box.innerHTML = "";
  if (!list.length) {
    box.innerHTML = `<div class="item"><div class="sub">No blocklisted domains.</div></div>`;
    return;
  }
  for (const host of list) {
    const row = document.createElement("div");
    row.className = "wl";
    const span = document.createElement("span");
    span.textContent = host;
    const btn = document.createElement("button");
    btn.textContent = "Remove";
    btn.addEventListener("click", async () => {
      await chrome.runtime.sendMessage({ type: "REMOVE_BLOCKLIST", host });
      await refresh();
    });
    row.appendChild(span);
    row.appendChild(btn);
    box.appendChild(row);
  }
}

async function refresh() {
  const state = await chrome.runtime.sendMessage({ type: "GET_STATE" });
  if (!state || !state.ok) return;

  el("enabled").checked = !!state.enabled;
  el("blocked").textContent = String(state.stats?.blocked || 0);
  el("scanned").textContent = String(state.stats?.scanned || 0);
  renderLog(state.log || []);
  renderWhitelist(state.whitelist || []);
  renderBlocklist(state.blocklist || []);
}

el("enabled").addEventListener("change", async (e) => {
  await chrome.runtime.sendMessage({ type: "SET_ENABLED", enabled: e.target.checked });
  await refresh();
});

el("clearLog").addEventListener("click", async () => {
  await chrome.runtime.sendMessage({ type: "CLEAR_LOG" });
  await refresh();
});

// Whitelist: manual domain input
async function addWhitelistDomain(raw) {
  const domain = (raw || "").trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/^www\./, "");
  if (!domain || !domain.includes(".")) return;
  await chrome.runtime.sendMessage({ type: "ADD_WHITELIST", host: domain });
  el("wlInput").value = "";
  await refresh();
}

el("wlAdd").addEventListener("click", () => addWhitelistDomain(el("wlInput").value));
el("wlInput").addEventListener("keydown", (e) => {
  if (e.key === "Enter") addWhitelistDomain(el("wlInput").value);
});

// Whitelist: add current active tab's domain
el("wlAddCurrent").addEventListener("click", async () => {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab?.url) {
      const host = new URL(tab.url).hostname;
      if (host) {
        await addWhitelistDomain(host);
      }
    }
  } catch {}
});

// --- Blocklist ---
async function addBlocklistDomain(raw) {
  const domain = (raw || "").trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/^www\./, "");
  if (!domain || !domain.includes(".")) return;
  await chrome.runtime.sendMessage({ type: "ADD_BLOCKLIST", host: domain });
  el("blInput").value = "";
  await refresh();
}

el("blAdd").addEventListener("click", () => addBlocklistDomain(el("blInput").value));
el("blInput").addEventListener("keydown", (e) => {
  if (e.key === "Enter") addBlocklistDomain(el("blInput").value);
});

el("blAddCurrent").addEventListener("click", async () => {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab?.url) {
      const host = new URL(tab.url).hostname;
      if (host) {
        await addBlocklistDomain(host);
      }
    }
  } catch {}
});

refresh();
