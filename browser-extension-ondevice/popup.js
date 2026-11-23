(() => {
  "use strict";

  const $ = id => document.getElementById(id);
  const status = $("engine-status");
  const form = $("check-form");
  const input = $("url");
  const button = $("check-button");
  const error = $("error");
  const result = $("result");

  function showResult(value) {
    $("verdict").textContent = value.prediction === "benign" ? "No threat found" : `${value.prediction} detected`;
    $("risk").textContent = `${value.risk_level} risk · ${Math.round(value.score * 100)}% combined score`;
    $("decider").textContent = `Primary signal: ${value.decided_by_label}`;
    const list = $("reasons");
    list.replaceChildren();
    for (const item of value.reasons) {
      const reason = document.createElement("li");
      reason.textContent = item.reason;
      list.append(reason);
    }
    result.hidden = false;
  }

  form.addEventListener("submit", async event => {
    event.preventDefault();
    error.hidden = true;
    result.hidden = true;
    button.disabled = true;
    button.textContent = "Checking…";
    try {
      showResult(await DeepIntelBrowserEngine.analyze(input.value));
    } catch (reason) {
      error.textContent = reason instanceof Error ? reason.message : "Could not check this URL.";
      error.hidden = false;
    } finally {
      button.disabled = false;
      button.textContent = "Check URL";
    }
  });

  DeepIntelBrowserEngine.initialize({ assetBase: chrome.runtime.getURL("") }).then(() => {
    status.textContent = "Local model ready";
    status.className = "ready";
    button.disabled = false;
  }).catch(reason => {
    status.textContent = "Local model unavailable";
    status.className = "error";
    error.textContent = reason instanceof Error ? reason.message : "Could not load local model files.";
    error.hidden = false;
  });
})();
