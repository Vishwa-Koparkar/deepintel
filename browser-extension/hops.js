// Redirect chain tracking for main-frame navigations. State lives in chrome.storage.session (the worker sleeps).
const chains = {};
function withTab(tabId, fn) {
  chains[tabId] = (chains[tabId] || Promise.resolve()).then(fn).catch(console.error);
  return chains[tabId];
}

const HOP_CAP = 20;
const RISK_RANK = { safe: 0, low: 1, medium: 2, high: 3, critical: 4 };
const isWeb = (u) => /^https?:\/\//i.test(u || "");
const hostOf = (u) => { try { return new URL(u).hostname; } catch { return ""; } };

// Same rule as urlForAnalysis in background.js (kept local so this stays pure): a bare http:// address is Chrome's fallback.
function schemeOf(url) {
  try {
    const u = new URL(url);
    if (u.protocol === "http:" && u.pathname === "/" && !u.search && !u.hash) return "https:";
    return u.protocol;
  } catch { return ""; }
}
const isIp = (h) => /^\d{1,3}(\.\d{1,3}){3}$/.test(h) || h.startsWith("[");
// shortcut: wrong for co.uk-style suffixes, use a public suffix list if that matters
const regDomain = (h) => h.split(".").slice(-2).join(".");

// Worst high/critical risk among a stored chain's hops, or null.
function worstHopRisk(state) {
  let worst = null;
  for (const h of state?.hops || []) if (RISK_RANK[h.risk] >= 3 && (worst === null || RISK_RANK[h.risk] > RISK_RANK[worst])) worst = h.risk;
  return worst;
}

// Pure: returns one flags array per hop.
function hopFlags(hops) {
  const out = hops.map((h, i) => {
    const flags = [];
    const host = h.host || hostOf(h.url);
    if (isIp(host)) flags.push("raw IP host");
    if (i > 0) {
      const prev = hops[i - 1];
      if (schemeOf(prev.url) === "https:" && schemeOf(h.url) === "http:") flags.push("https→http downgrade");
      const ph = prev.host || hostOf(prev.url);
      if (!isIp(host) && !isIp(ph) && regDomain(host) !== regDomain(ph)) flags.push("domain change");
    }
    return flags;
  });
  if (hops.length - 1 > 3) out[out.length - 1].push("long chain");
  return out;
}

async function analyzeHops(tabId) {
  const key = `hops_${tabId}`;
  const state = (await chrome.storage.session.get(key))[key];
  if (!state || state.hops.length < 2) return;
  const { hops } = state;
  const flags = hopFlags(hops);
  hops.forEach((h, i) => { h.flags = flags[i]; });

  const targets = hops.slice(0, -1).filter(h => isWeb(h.url) && !isOnionHost(h.host)).slice(0, 5);
  await Promise.all(targets.map(async h => {
    const r = await analyzeUrl(urlForAnalysis(h.url).url);
    h.risk = r?.risk_level || null;
  }));
  await chrome.storage.session.set({ [key]: state });

  const worst = worstHopRisk(state);
  if (!worst) return;
  const cur = (await chrome.storage.local.get(`result_${tabId}`))[`result_${tabId}`];
  if (RISK_RANK[worst] > (RISK_RANK[cur?.risk_level] ?? -1)) {
    updateBadge(tabId, { risk_level: worst });
    notifyThreat({ prediction: "redirect through risky hop", risk_level: worst });
  }
}

if (typeof chrome !== "undefined" && chrome.webRequest) {
  const get = async (tabId) => {
    const key = `hops_${tabId}`;
    return { key, state: (await chrome.storage.session.get(key))[key] || { pending: false, hops: [] } };
  };

  chrome.webRequest.onBeforeRequest.addListener(d => {
    if (d.tabId < 0 || !isWeb(d.url)) return;
    withTab(d.tabId, async () => {
      const { key, state } = await get(d.tabId);
      // Redirects reuse the requestId; a new one means a new navigation.
      if (state.requestId === d.requestId) return;
      await chrome.storage.session.set({ [key]: { pending: true, requestId: d.requestId, lastUrl: state.lastUrl, hops: [] } });
    });
  }, { urls: ["<all_urls>"], types: ["main_frame"] });

  chrome.webRequest.onBeforeRedirect.addListener(d => {
    if (d.tabId < 0 || !isWeb(d.url)) return;
    withTab(d.tabId, async () => {
      const { key, state } = await get(d.tabId);
      if (state.hops.length >= HOP_CAP) return;
      state.hops.push({ url: d.url, host: hostOf(d.url), status: d.statusCode, via: "http", ip: d.ip || "" });
      await chrome.storage.session.set({ [key]: state });
    });
  }, { urls: ["<all_urls>"], types: ["main_frame"] });

  chrome.webNavigation.onCommitted.addListener(d => {
    if (d.frameId !== 0 || d.tabId < 0 || !isWeb(d.url)) return;
    withTab(d.tabId, async () => {
      const { key, state } = await get(d.tabId);
      const hops = state.pending ? state.hops : [];
      if (d.transitionQualifiers?.includes("client_redirect") && state.lastUrl && state.lastUrl !== d.url && isWeb(state.lastUrl)) {
        hops.unshift({ url: state.lastUrl, host: hostOf(state.lastUrl), status: null, via: "client", ip: "" });
      }
      hops.push({ url: d.url, host: hostOf(d.url), status: null, via: "final", ip: "" });
      await chrome.storage.session.set({ [key]: { pending: false, requestId: state.requestId, lastUrl: d.url, hops: hops.slice(0, HOP_CAP + 2) } });
      await analyzeHops(d.tabId);
    });
  });

  chrome.tabs.onRemoved.addListener(tabId => {
    withTab(tabId, () => chrome.storage.session.remove(`hops_${tabId}`)).then(() => delete chains[tabId]);
  });
}

if (typeof module !== "undefined") module.exports = { hopFlags };
