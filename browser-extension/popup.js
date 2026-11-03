document.addEventListener("DOMContentLoaded", async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.url) return showError();

  try {
    // Chrome hides "http://" in its address bar, so show the scheme we actually analysed
    const u = new URL(tab.url);
    document.getElementById("current-url").textContent = `${u.protocol}//${u.hostname}`;
  } catch {
    document.getElementById("current-url").textContent = tab.url;
  }

  renderHops(tab.id).catch(err => console.error("DeepIntel: hops failed", err));
  renderCookies(tab).catch(err => console.error("DeepIntel: cookies failed", err));

  const stored = await chrome.storage.local.get(`result_${tab.id}`);
  let result = stored[`result_${tab.id}`];

  // No stored result (extension just reloaded, or page still loading): ask the background to analyze now
  if (!result) {
    try {
      result = await chrome.runtime.sendMessage({ type: "analyze", tabId: tab.id, url: tab.url });
    } catch (err) {
      console.error("DeepIntel: analyze request failed", err);
    }
  }

  if (result?.tor) return showTor(result);
  if (!result || !result.ml_probs) return showError();

  currentTab = tab;
  // Chrome hides "http://" in its address bar, so say which scheme was actually scored
  if (result.url) {
    const scored = new URL(result.url);
    document.getElementById("current-url").textContent = `${scored.protocol}//${scored.hostname}`;
  }
  if (result.upgraded) {
    const note = document.getElementById("scheme-note");
    note.textContent = "Scored as https://. Chrome adds http:// to addresses typed without a scheme.";
    note.classList.remove("hidden");
  }
  try {
    render(result);
  } catch (err) {
    console.error("DeepIntel: failed to render result", err, result);
    showError();
  }
});

let currentTab = null;

function render(result) {
  document.getElementById("loading").classList.add("hidden");
  const card = document.getElementById("result");
  card.classList.remove("hidden");

  const riskLevel = result.risk_level || "unknown";
  const badge = document.getElementById("risk-badge");
  badge.textContent = riskLevel.toUpperCase();
  badge.className = `risk-badge risk-${riskLevel}`;
  card.className = `card verdict lvl-${riskLevel}`;
  card.dataset.risk = riskLevel;

  document.getElementById("prediction").textContent = result.prediction || "unknown";

  // Confidence in the final verdict (API field); fall back to the model probability for older API versions
  const probs = Object.values(result.ml_probs).filter(v => typeof v === "number");
  const confidence = typeof result.confidence === "number"
    ? result.confidence
    : (result.ml_probs[result.prediction] ?? (probs.length ? Math.max(...probs) : null));
  document.getElementById("confidence").textContent =
    typeof confidence === "number" ? `${(confidence * 100).toFixed(1)}%` : "N/A";
  document.getElementById("conf-fill").style.width =
    typeof confidence === "number" ? `${Math.max(0, Math.min(100, confidence * 100))}%` : "0";

  const reasonsList = document.getElementById("reasons");
  reasonsList.replaceChildren();

  if (!result.reasons || result.reasons.length === 0) {
    const li = document.createElement("li");
    li.textContent = "No specific risk indicators detected.";
    reasonsList.appendChild(li);
  } else {
    // API returns reasons as { priority, impact, reason, source } objects
    result.reasons.slice(0, 5).forEach(reason => {
      const li = document.createElement("li");
      li.textContent = typeof reason === "string" ? reason : reason.reason || JSON.stringify(reason);
      reasonsList.appendChild(li);
    });
  }

  // API returns suggestion as { type, message, safe_url } or null
  const suggestion = result.suggestion;
  if (suggestion) {
    const safeAlt = document.getElementById("safe-alt");
    const link = document.getElementById("safe-alt-link");
    const message = typeof suggestion === "string" ? suggestion : suggestion.message;
    const safeUrl = typeof suggestion === "string" ? suggestion : suggestion.safe_url;

    safeAlt.classList.remove("hidden");
    document.getElementById("safe-alt-text").textContent = message || "Safe alternative:";

    if (safeUrl) {
      link.href = safeUrl;
      link.textContent = safeUrl;
      link.classList.remove("hidden");
    } else {
      link.classList.add("hidden");
    }
  } else {
    document.getElementById("safe-alt").classList.add("hidden");
  }

  renderFeedback(result);
}

// --- Personal feedback: report a false positive / false negative ------------------------------
const SCOPE_TEXT = { url: "this exact page", host: "this site", domain: "this whole domain" };

function renderFeedback(result) {
  const box = document.getElementById("feedback");
  const btn = document.getElementById("fb-btn");
  const status = document.getElementById("fb-status");
  const msg = document.getElementById("fb-msg");
  box.classList.remove("hidden");
  msg.textContent = "";
  btn.disabled = false;
  btn.classList.remove("confirm");
  delete btn.dataset.armed;

  const fb = result.feedback;
  if (fb) {
    status.classList.remove("hidden");
    const what = fb.correct_label === "benign" ? "safe" : fb.correct_label;
    document.getElementById("fb-status-text").textContent = `You marked ${SCOPE_TEXT[fb.scope] || "this"} as ${what}.`;
    document.getElementById("fb-undo").onclick = () => submitFeedback({ undoId: fb.id });
    btn.classList.add("hidden");
    return;
  }

  status.classList.add("hidden");
  btn.classList.remove("hidden");
  // Offer the correction that fixes the mistake the user would be reporting
  const flagged = result.prediction !== "benign";
  btn.dataset.label = flagged ? "benign" : "phishing";
  btn.textContent = flagged ? "Wrong? This site is safe" : "Wrong? This site is phishing";
  btn.onclick = onFeedbackClick;
}

function onFeedbackClick() {
  const btn = document.getElementById("fb-btn");
  // Two steps, so a stray click can't silently mark a phishing site as safe
  if (!btn.dataset.armed) {
    btn.dataset.armed = "1";
    btn.classList.add("confirm");
    btn.textContent = btn.dataset.label === "benign" ? "Click again to mark as SAFE" : "Click again to mark as PHISHING";
    setTimeout(() => {
      if (btn.dataset.armed) renderFeedbackReset();
    }, 4000);
    return;
  }
  submitFeedback({ correctLabel: btn.dataset.label });
}

function renderFeedbackReset() {
  const btn = document.getElementById("fb-btn");
  delete btn.dataset.armed;
  btn.classList.remove("confirm");
  btn.textContent = btn.dataset.label === "benign" ? "Wrong? This site is safe" : "Wrong? This site is phishing";
}

async function submitFeedback({ correctLabel, undoId }) {
  const btn = document.getElementById("fb-btn");
  const msg = document.getElementById("fb-msg");
  btn.disabled = true;
  msg.textContent = "";
  try {
    const reply = await chrome.runtime.sendMessage(undoId
      ? { type: "undoFeedback", id: undoId, tabId: currentTab.id, url: currentTab.url }
      : { type: "feedback", correctLabel, tabId: currentTab.id, url: currentTab.url });
    if (!reply || !reply.ok) throw new Error((reply && reply.error) || "No response from the extension");
    if (!reply.result || !reply.result.ml_probs) throw new Error("Saved, but the page could not be re-analysed. Is the API running?");
    render(reply.result);
  } catch (err) {
    console.error("DeepIntel: feedback failed", err);
    msg.textContent = err.message;
    btn.disabled = false;
    renderFeedbackReset();
  }
}

function showError() {
  document.getElementById("loading").classList.add("hidden");
  document.getElementById("error").classList.remove("hidden");
}

function showTor(result) {
  document.getElementById("loading").classList.add("hidden");
  const box = document.getElementById("tor-note");
  box.replaceChildren(el("h2", null, "Tor site"));
  const lines = ["Tor (.onion) site \u2014 not analyzed. DeepIntel never sends onion addresses to the API."];
  const i = result.info || {};
  if (i.gateway) lines.push("Tor2web gateway: the gateway can read and alter everything you send.");
  if (i.v2) lines.push("v2 address: dead since Oct 2021, so this link is stale or fake.");
  if (i.malformed) lines.push("Malformed v3 address: likely fake or a typo.");
  for (const t of lines) box.appendChild(el("p", null, t));
  box.classList.remove("hidden");
}

async function renderHops(tabId) {
  const hops = (await chrome.storage.session.get(`hops_${tabId}`))[`hops_${tabId}`]?.hops || [];
  if (hops.length < 2) return;
  const list = document.getElementById("hop-list");
  list.replaceChildren();
  for (const h of hops) {
    const li = document.createElement("li");
    li.title = h.url;
    const head = el("div", "hop-head");
    head.append(el("span", "hop-status", String(h.status || h.via)), el("span", "hop-host", h.host));
    if (h.risk) head.appendChild(el("span", `pill risk-${h.risk}`, h.risk));
    li.appendChild(head);
    if (h.ip) li.appendChild(el("small", "hop-ip", h.ip));
    if (h.flags?.length) {
      const f = el("div", "hop-flags");
      for (const x of h.flags) f.appendChild(el("span", "tag", x));
      li.appendChild(f);
    }
    list.appendChild(li);
  }
  document.getElementById("hop-count").textContent = String(hops.length);
  document.getElementById("hops").open = hops.some(h => h.risk === "high" || h.risk === "critical" || h.flags?.length);
  document.getElementById("hops").classList.remove("hidden");
}

const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text !== undefined) e.textContent = text; return e; };

// Cookie names are attacker-controlled: textContent only.
async function renderCookies(tab) {
  const r = await chrome.runtime.sendMessage({ type: "cookies", tabId: tab.id, url: tab.url });
  if (!r || r.skipped) return;
  const grade = el("span", `chip grade-${String(r.grade).toLowerCase()}`, r.grade);
  grade.title = `score ${r.score}`;
  document.getElementById("ck-summary").replaceChildren(
    el("span", "c-title", "Cookies"), el("span", "chip", String(r.counts.total)), grade);
  const stats = document.getElementById("ck-stats");
  for (const [n, label] of [[r.counts.firstParty, "1st-party"], [r.counts.thirdParty, "3rd-party"],
    [r.counts.tracking, "tracking"], [r.counts.insecure, "insecure"]]) {
    const t = el("div", "stat"); t.append(el("b", null, String(n)), el("span", null, label)); stats.appendChild(t);
  }
  const warns = document.getElementById("ck-warnings");
  for (const w of r.top) warns.appendChild(el("li", "ck-warn", w));
  const box = document.getElementById("ck-domains");
  for (const d of r.domains) {
    const det = el("details", "ck-dom");
    const sum = el("summary");
    sum.append(el("span", "ck-host", d.host), el("span", "chip", d.party === "1p" ? "1P" : "3P"),
      el("span", "ck-sub", `sets ${d.setNames.length} \u00b7 sent ${d.sent}/${d.reqs} req`));
    det.appendChild(sum);
    for (const c of d.cookies) {
      const row = el("div", "ck-row");
      const meta = el("small", "ck-meta");
      meta.append(el("span", "ck-val", c.masked),
        ` \u00b7 ${c.size} B \u00b7 ${c.expires === "session" ? "session" : c.expires.slice(0, 10)} \u00b7 `, el("span", "chip", c.kind));
      row.append(el("div", "ck-name", c.name), meta);
      const chips = el("div", "ck-chips");
      if (c.secure) chips.appendChild(el("span", "chip", "Secure"));
      if (c.httpOnly) chips.appendChild(el("span", "chip", "HttpOnly"));
      chips.appendChild(el("span", "chip", `SameSite=${c.sameSite}`));
      if (c.partitioned) chips.appendChild(el("span", "chip", "Partitioned"));
      for (const f of c.flags) chips.appendChild(el("span", "chip warn", f));
      row.appendChild(chips);
      det.appendChild(row);
    }
    box.appendChild(det);
  }
  if (r.truncated) box.appendChild(el("small", "ck-more", `${r.truncated} more cookies not shown`));
  document.getElementById("cookies").classList.remove("hidden");
}
