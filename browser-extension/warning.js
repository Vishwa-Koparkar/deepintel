// The redirect inserts the target URL raw, so it may hold unencoded ? & #: take everything after the first "url=".
const i = location.href.indexOf("url=");
const raw = i < 0 ? "" : location.href.slice(i + 4);
let target = null, host = "";
try {
  const u = new URL(raw);
  if ((u.protocol === "http:" || u.protocol === "https:") && isOnionHost(u.hostname)) { target = u.href; host = u.hostname; }
} catch {}

const $ = id => document.getElementById(id);
const risks = ["Onion sites are unmoderated and unindexed, with high rates of scams, malware and illegal content.",
  "DeepIntel cannot check this site, and never sends onion addresses to its API."];

if (!target) {
  $("target").textContent = "Invalid link";
  $("go").classList.add("hidden");
} else {
  const info = onionInfo(host);
  $("target").textContent = target;
  risks.push("If this page is not routed through Tor, your identity and this lookup can leak.");
  if (info.gateway) risks.push("This is a tor2web gateway: the gateway can read and alter everything you send and receive.");
  if (info.v2) risks.push("This is a v2 onion address. v2 has been dead since October 2021, so the link is stale or fake.");
  if (info.malformed) risks.push("This v3 address is malformed (valid ones end in 'd'), so it is likely fake or a typo.");
}
for (const t of risks) { const li = document.createElement("li"); li.textContent = t; $("risks").appendChild(li); }

$("back").onclick = () => {
  if (history.length > 1) history.back();
  else chrome.tabs.getCurrent(t => t && chrome.tabs.remove(t.id));
};
$("go").onclick = async () => {
  const r = await chrome.runtime.sendMessage({ type: "allowOnion", host });
  if (r && r.ok) location.replace(target);
};
