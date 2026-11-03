// Cookie usage + security audit for the current tab. Loaded by background.js (importScripts, after hops.js, whose
// withTab/regDomain/hostOf/isWeb it reuses). PRIVACY: cookie values never leave this file unmasked, are never stored or logged.
const CK_DOMS = 100, CK_NAMES = 50, CK_PER_DOMAIN = 50, CK_TOTAL = 200, CK_FLUSH_MS = 500;
const CK_TRACK = /^(_ga|_gid|_gat|_fbp|_fbc|_gcl|__utm|_hj|ajs_|mp_|_pk_|_uet|_clck|_clsk|IDE$|test_cookie)/i;
const CK_CONSENT = /consent|cookieconsent|OptanonConsent|euconsent/i;
const CK_AUTH = /sess|sid$|^sid|auth|token|jwt|login|csrf|xsrf/i;
const CK_EMAIL = /[^@\s]+@[^@\s]+\.[a-z]{2,}/i;

// First 3 + "…" + last 2, or "***" when short.
function mask(v) {
  v = String(v ?? "");
  return v.length < 8 ? "***" : v.slice(0, 3) + "…" + v.slice(-2);
}

// Pure: c is a chrome.cookies.Cookie-like plus {party}. Returns {kind, flags (human warnings), penalty}.
function classifyCookie(c, pageIsHttps) {
  const flags = []; let penalty = 0;
  const add = (p, msg) => { penalty += p; flags.push(msg); };
  const name = c.name || "", value = String(c.value ?? "");
  let decoded = value;
  try { decoded = decodeURIComponent(value); } catch {}

  let kind = "other";
  if (CK_TRACK.test(name)) kind = "tracking";
  else if (CK_CONSENT.test(name)) kind = "consent";
  else if (CK_AUTH.test(name)) kind = "session/auth";
  else if (/^eyJ[\w-]+\.[\w-]+\.[\w-]*$/.test(value)) kind = "jwt";
  else if (/^[A-Za-z0-9+/=_-]{24,}$/.test(value) && !CK_EMAIL.test(decoded)) kind = "identifier";
  if (CK_EMAIL.test(value) || CK_EMAIL.test(decoded)) add(2, "contains an email address");

  if (!c.secure) { add(2, "not Secure"); if (!pageIsHttps) add(1, "sent over plain http"); }
  if ((kind === "session/auth" || kind === "jwt") && !c.httpOnly) add(3, "readable by page scripts");
  if (c.sameSite === "no_restriction" && !c.secure) add(3, "SameSite=None without Secure");
  if (c.sameSite === "unspecified") add(1, "SameSite not set");
  if (!c.session && c.expirationDate && c.expirationDate * 1000 - Date.now() > 400 * 864e5) add(1, "expires in over 400 days");
  if (name.length + value.length > 4000) add(1, "very large cookie");
  if (kind === "tracking" && c.party === "3p") add(1, "third-party tracker");
  if (name.startsWith("__Host-") && !(c.secure && c.path === "/" && c.hostOnly)) add(2, "__Host- prefix rules violated");
  if (name.startsWith("__Secure-") && !c.secure) add(2, "__Secure- prefix without Secure");
  return { kind, flags, penalty };
}

// Score = 100 - 15 * mean(per-cookie penalty capped at 6). Averaging (not summing) keeps a site with 80 mildly
// flagged cookies from trivially hitting 0, while a page of uniformly bad cookies still lands in Poor.
function pageScore(classified) {
  const n = classified.length;
  const mean = n ? classified.reduce((s, c) => s + Math.min(c.penalty, 6), 0) / n : 0;
  const score = Math.max(0, Math.round(100 - 15 * mean));
  const freq = {};
  for (const c of classified) for (const f of c.flags) freq[f] = (freq[f] || 0) + 1;
  return {
    score, grade: score >= 80 ? "Good" : score >= 50 ? "Fair" : "Poor",
    counts: {
      total: n,
      firstParty: classified.filter(c => c.party === "1p").length,
      thirdParty: classified.filter(c => c.party === "3p").length,
      tracking: classified.filter(c => c.kind === "tracking").length,
      insecure: classified.filter(c => c.flags.includes("not Secure")).length,
    },
    top: Object.keys(freq).sort((a, b) => freq[b] - freq[a]).slice(0, 3),
  };
}

if (typeof chrome !== "undefined" && chrome.webRequest) {
  // shortcut: counts are buffered in memory and flushed to storage.session every 500ms; if the worker sleeps, the last buffer is lost. Fine for an audit.
  const mem = {}, timers = {};
  const key = (t) => `ck_${t}`;
  const load = async (t) => mem[t] ||= (await chrome.storage.session.get(key(t)))[key(t)] || { top: "", doms: {} };
  const flush = (t) => {
    clearTimeout(timers[t]);
    timers[t] = setTimeout(() => withTab(t, async () => { if (mem[t]) await chrome.storage.session.set({ [key(t)]: mem[t] }); }), CK_FLUSH_MS);
  };
  const dom = (st, host) => {
    if (!st.doms[host] && Object.keys(st.doms).length >= CK_DOMS) return null;
    return st.doms[host] ||= { party: st.top && regDomain(host) !== regDomain(st.top) ? "3p" : "1p", set: [], sent: 0, reqs: 0 };
  };

  chrome.webRequest.onBeforeRequest.addListener(d => {
    if (d.tabId < 0 || !isWeb(d.url)) return;
    withTab(d.tabId, async () => {
      if ((await load(d.tabId)).requestId === d.requestId) return; // redirects reuse the requestId
      mem[d.tabId] = { top: hostOf(d.url), requestId: d.requestId, doms: {} };
      flush(d.tabId);
    });
  }, { urls: ["<all_urls>"], types: ["main_frame"] });

  chrome.webRequest.onSendHeaders.addListener(d => {
    if (d.tabId < 0 || !isWeb(d.url)) return;
    withTab(d.tabId, async () => {
      const st = await load(d.tabId);
      if (d.type === "main_frame") st.top = hostOf(d.url); // follow redirects to the final host
      const e = dom(st, hostOf(d.url));
      if (!e) return;
      e.reqs++;
      if (d.requestHeaders?.some(h => h.name.toLowerCase() === "cookie")) e.sent++;
      flush(d.tabId);
    });
  }, { urls: ["<all_urls>"] }, ["requestHeaders", "extraHeaders"]);

  chrome.webRequest.onHeadersReceived.addListener(d => {
    if (d.tabId < 0 || !isWeb(d.url)) return;
    const names = (d.responseHeaders || []).filter(h => h.name.toLowerCase() === "set-cookie").map(h => String(h.value).split("=")[0].trim());
    if (!names.length) return;
    withTab(d.tabId, async () => {
      const e = dom(await load(d.tabId), hostOf(d.url));
      if (!e) return;
      for (const n of names) if (!e.set.includes(n) && e.set.length < CK_NAMES) e.set.push(n);
      flush(d.tabId);
    });
  }, { urls: ["<all_urls>"] }, ["responseHeaders", "extraHeaders"]);

  chrome.tabs.onRemoved.addListener(tabId => {
    clearTimeout(timers[tabId]);
    withTab(tabId, async () => { delete mem[tabId]; await chrome.storage.session.remove(key(tabId)); });
  });

  async function cookieReport(tabId, url) {
    if (!isWeb(url) || isOnionHost(hostOf(url))) return { skipped: true };
    const st = await load(tabId);
    const top = hostOf(url);
    const isHttps = url.startsWith("https:");
    // Incognito tabs have their own cookie store.
    let storeId;
    try { storeId = (await chrome.cookies.getAllCookieStores()).find(s => s.tabIds.includes(tabId))?.id; } catch {}
    const base = storeId ? { storeId } : {};
    const queries = [{ ...base, url }, ...Object.keys(st.doms).map(h => ({ ...base, url: `https://${h}/` }))];
    const jobs = queries.map(q => chrome.cookies.getAll(q).then(l => l.map(c => ({ ...c, partitioned: false }))).catch(() => []));
    // Partitioned (CHIPS) cookies; throws on older Chrome.
    jobs.push(chrome.cookies.getAll({ ...base, partitionKey: { topLevelSite: new URL(url).origin } }).then(l => l.map(c => ({ ...c, partitioned: true }))).catch(() => []));

    const seen = new Set(), all = [];
    for (const c of (await Promise.all(jobs)).flat()) {
      const k = [c.name, c.domain, c.path, c.partitioned].join("\0");
      if (!seen.has(k)) { seen.add(k); all.push(c); }
    }
    const classified = all.map(c => {
      const domain = c.domain.replace(/^\./, "");
      const party = regDomain(domain) === regDomain(top) ? "1p" : "3p";
      const r = classifyCookie({ ...c, party }, isHttps);
      return { ...r, party, domain, c };
    });
    const score = pageScore(classified);

    const groups = {};
    let truncated = 0, kept = 0;
    for (const x of classified) {
      const g = groups[x.domain] ||= { host: x.domain, party: x.party, cookies: [] };
      if (g.cookies.length >= CK_PER_DOMAIN || kept >= CK_TOTAL) { truncated++; continue; }
      kept++;
      // value is masked here, before anything leaves this function
      g.cookies.push({
        name: x.c.name, masked: mask(x.c.value), size: x.c.name.length + String(x.c.value).length,
        expires: x.c.session || !x.c.expirationDate ? "session" : new Date(x.c.expirationDate * 1000).toISOString(),
        kind: x.kind, secure: !!x.c.secure, httpOnly: !!x.c.httpOnly, sameSite: x.c.sameSite, partitioned: x.c.partitioned, flags: x.flags,
      });
    }
    for (const h of Object.keys(st.doms)) groups[h] ||= { host: h, party: st.doms[h].party, cookies: [] };
    for (const g of Object.values(groups)) {
      // Request stats are per request host; a cookie domain covers itself and its subdomains.
      const hosts = Object.keys(st.doms).filter(h => h === g.host || h.endsWith("." + g.host));
      g.party = regDomain(g.host) === regDomain(top) ? "1p" : "3p";
      g.setNames = [...new Set(hosts.flatMap(h => st.doms[h].set))].slice(0, CK_NAMES);
      g.sent = hosts.reduce((s, h) => s + st.doms[h].sent, 0);
      g.reqs = hosts.reduce((s, h) => s + st.doms[h].reqs, 0);
    }
    return { ...score, domains: Object.values(groups), truncated };
  }

  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (msg?.type !== "cookies") return;
    cookieReport(msg.tabId, msg.url).then(sendResponse).catch(err => { console.error("DeepIntel: cookies failed", err); sendResponse(null); });
    return true;
  });
}

if (typeof module !== "undefined") module.exports = { classifyCookie, pageScore, mask };
