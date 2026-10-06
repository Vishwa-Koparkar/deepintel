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
  document.getElementById("result").classList.remove("hidden");

  const riskLevel = result.risk_level || "unknown";
  const badge = document.getElementById("risk-badge");
  badge.textContent = riskLevel.toUpperCase();
  badge.className = `risk-badge risk-${riskLevel}`;

  document.getElementById("prediction").textContent = result.prediction || "unknown";

  // Confidence in the final verdict (API field); fall back to the model probability for older API versions
  const probs = Object.values(result.ml_probs).filter(v => typeof v === "number");
  const confidence = typeof result.confidence === "number"
    ? result.confidence
    : (result.ml_probs[result.prediction] ?? (probs.length ? Math.max(...probs) : null));
  document.getElementById("confidence").textContent =
    typeof confidence === "number" ? `${(confidence * 100).toFixed(1)}%` : "N/A";

  const reasonsList = document.getElementById("reasons");
  reasonsList.innerHTML = "";

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
