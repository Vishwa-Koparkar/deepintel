// Tor (.onion) detection + warning-page redirect. Loaded by background.js (importScripts) and warning.html.
const V3_RE = /^[a-z2-7]{56}$/;

function onionInfo(host) {
  const h = String(host || "").toLowerCase();
  const labels = h.split(".");
  const ends = h.endsWith(".onion");
  const v3labels = labels.filter(l => V3_RE.test(l));
  return {
    v3: v3labels.length > 0,
    v2: ends && /^[a-z2-7]{16}$/.test(labels[labels.length - 2] || ""),
    gateway: v3labels.length > 0 && !ends,
    malformed: v3labels.some(l => !l.endsWith("d")),
  };
}

function isOnionHost(host) {
  const h = String(host || "").toLowerCase();
  return h.endsWith(".onion") || h.split(".").some(l => V3_RE.test(l));
}

const ONION_REGEX = "^(https?://(?:[^/?#]*\\.)?(?:[^./?#]+\\.onion|[a-z2-7]{56}(?:\\.[^/?#]*)?)(?::\\d+)?(?:[/?#].*)?)$";
const ONION_RULE_ID = 1;

if (typeof module !== "undefined") module.exports = { isOnionHost, onionInfo, ONION_REGEX };

// Service-worker-only setup (this file is also loaded in warning.html)
if (typeof importScripts === "function") {
  const installRule = () => chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: [ONION_RULE_ID],
    addRules: [{
      id: ONION_RULE_ID,
      priority: 1,
      action: { type: "redirect", redirect: { regexSubstitution: `chrome-extension://${chrome.runtime.id}/warning.html?url=\\1` } },
      condition: { regexFilter: ONION_REGEX, resourceTypes: ["main_frame"] },
    }],
  }).catch(e => console.error("DeepIntel: onion rule failed", e));
  chrome.runtime.onInstalled.addListener(installRule);
  chrome.runtime.onStartup.addListener(installRule);

  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (!msg || msg.type !== "allowOnion") return;
    if (!isOnionHost(msg.host)) { sendResponse({ ok: false }); return; }
    chrome.declarativeNetRequest.getSessionRules().then(rules => {
      const id = Math.max(999, ...rules.map(r => r.id)) + 1;
      return chrome.declarativeNetRequest.updateSessionRules({
        addRules: [{
          id,
          priority: 2,
          action: { type: "allow" },
          condition: { requestDomains: [String(msg.host).toLowerCase()], resourceTypes: ["main_frame"] },
        }],
      });
    }).then(() => sendResponse({ ok: true }), e => sendResponse({ ok: false, error: e.message }));
    return true;
  });
}
