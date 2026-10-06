const API_BASE = "http://localhost:8000";
const API_URL = `${API_BASE}/analyze`;

// Cache results so we don't re-analyze the same URL repeatedly
const cache = new Map();

async function analyzeUrl(url) {
  if (cache.has(url)) return cache.get(url);

  try {
    const res = await fetch(API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });
    if (!res.ok) throw new Error(`API responded with ${res.status}`);

    const data = await res.json();
    // Only cache well-formed results so a bad response isn't remembered
    if (data && data.ml_probs) cache.set(url, data);
    return data;
  } catch (err) {
    console.error("DeepIntel: analysis failed", err);
    return null;
  }
}

function updateBadge(tabId, result) {
  if (!result) {
    chrome.action.setBadgeText({ tabId, text: "" });
    return;
  }

  const level = result.risk_level;
  const badgeMap = {
    safe:     { text: "✓", color: "#0a7c5c" },
    low:      { text: "!", color: "#5a8f3c" },
    medium:   { text: "!", color: "#e6a817" },
    high:     { text: "⚠", color: "#e67e22" },
    critical: { text: "⚠", color: "#c0392b" }
  };

  const badge = badgeMap[level] || { text: "?", color: "#888" };
  chrome.action.setBadgeText({ tabId, text: badge.text });
  chrome.action.setBadgeBackgroundColor({ tabId, color: badge.color });
}

function notifyThreat(result) {
  // chrome.notifications is undefined until the extension is reloaded with the
  // "notifications" permission, so guard instead of throwing.
  if (!chrome.notifications || typeof chrome.notifications.create !== "function") return;

  chrome.notifications.create({
    type: "basic",
    iconUrl: "icons/icon128.png",
    title: "DeepIntel — Threat Detected",
    message: `${String(result.prediction || "threat").toUpperCase()} detected on this page. Risk: ${result.risk_level}.`
  });
}

// Chrome only puts "http://" in front of an address typed without a scheme after https:// has failed, so on a
// bare address (no path or query) the http is Chrome's fallback, not the user's or the site's choice. Score
// those as https:// instead of flagging "not encrypted". Links with a path or query keep their real scheme.
function urlForAnalysis(url) {
  try {
    const u = new URL(url);
    if (u.protocol === "http:" && u.pathname === "/" && !u.search && !u.hash) {
      u.protocol = "https:";
      return { url: u.toString(), upgraded: true };
    }
  } catch {}
  return { url, upgraded: false };
}

// Analyze a tab, update its badge, store the result for the popup, notify on threats.
async function processTab(tabId, url) {
  if (!url || !url.startsWith("http")) return null; // skip chrome://, about:, etc.

  const target = urlForAnalysis(url);
  const analysed = await analyzeUrl(target.url);
  const result = analysed && analysed.ml_probs ? { ...analysed, upgraded: target.upgraded } : analysed;
  if (!result || !result.ml_probs) {
    updateBadge(tabId, null);
    chrome.storage.local.remove(`result_${tabId}`);
    return null;
  }
  updateBadge(tabId, result);
  chrome.storage.local.set({ [`result_${tabId}`]: result });
  return result;
}

// Trigger analysis whenever a tab finishes loading a new URL
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status !== "complete" || !tab.url) return;

  const result = await processTab(tabId, tab.url);
  if (result && (result.risk_level === "high" || result.risk_level === "critical")) {
    notifyThreat(result);
  }
});

// Tabs opened before the extension was installed/reloaded never fire "complete",
// so analyze everything already open.
async function analyzeOpenTabs() {
  const tabs = await chrome.tabs.query({});
  await Promise.all(tabs.map(t => processTab(t.id, t.url)));
}
chrome.runtime.onInstalled.addListener(analyzeOpenTabs);
chrome.runtime.onStartup.addListener(analyzeOpenTabs);

// Send the user's correction to the API; the API stores it in the personal feedback database.
async function sendFeedback(url, correctLabel) {
  const res = await fetch(`${API_BASE}/feedback`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url: urlForAnalysis(url).url, correct_label: correctLabel })   // same URL that was analysed
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.detail || `API responded with ${res.status}`);
  }
}

async function deleteFeedback(id) {
  const res = await fetch(`${API_BASE}/feedback/${id}`, { method: "DELETE" });
  if (!res.ok) throw new Error(`API responded with ${res.status}`);
}

// A correction can change verdicts for other URLs (a whole domain), so drop every cached result
// and re-check all open tabs. The current tab is re-analysed first so the popup can show it at once.
async function afterFeedbackChange(tabId, url) {
  cache.clear();
  const result = await processTab(tabId, url);
  analyzeOpenTabs();
  return result;
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (!msg) return;

  if (msg.type === "analyze") {
    // Popup asks for an on-demand analysis when it has no stored result yet
    processTab(msg.tabId, msg.url).then(sendResponse);
    return true; // keep the channel open for the async response
  }

  if (msg.type === "feedback") {
    sendFeedback(msg.url, msg.correctLabel)
      .then(() => afterFeedbackChange(msg.tabId, msg.url))
      .then(result => sendResponse({ ok: true, result }))
      .catch(err => sendResponse({ ok: false, error: err.message }));
    return true;
  }

  if (msg.type === "undoFeedback") {
    deleteFeedback(msg.id)
      .then(() => afterFeedbackChange(msg.tabId, msg.url))
      .then(result => sendResponse({ ok: true, result }))
      .catch(err => sendResponse({ ok: false, error: err.message }));
    return true;
  }
});

// Clean up storage when tab closes
chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.local.remove(`result_${tabId}`);
});
