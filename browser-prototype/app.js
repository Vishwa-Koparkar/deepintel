(() => {
  "use strict";

  const $ = id => document.getElementById(id);
  const status = $("model-status");
  const statusDot = $("status-dot");
  const form = $("analysis-form");
  const input = $("url-input");
  const button = $("analyze-button");
  const error = $("form-error");
  let metadata;
  let session;

  function setStatus(message, state) {
    status.textContent = message;
    statusDot.className = `status-dot${state ? ` ${state}` : ""}`;
  }

  function formatPercent(value) {
    return new Intl.NumberFormat(undefined, { style: "percent", maximumFractionDigits: 2 }).format(value);
  }

  function formatBytes(bytes) {
    return `${(bytes / 1_000_000).toFixed(2)} MB`;
  }

  function validateInput(raw) {
    const value = raw.trim();
    if (!value) throw new Error("Enter a URL to analyze.");

    const explicitScheme = /^([a-z][a-z0-9+.-]*):/i.test(value);
    if (explicitScheme && !/^https?:/i.test(value)) throw new Error("Only HTTP and HTTPS URLs are supported.");
    const candidate = explicitScheme ? value : `https://${value}`;
    if (DeepIntelFeatures.codePointLength(candidate) > 4096) throw new Error("The URL is longer than 4,096 characters.");

    const parsed = DeepIntelFeatures.parseUrl(candidate);
    if (!parsed || !["http", "https"].includes(parsed.scheme) || !parsed.netloc) {
      throw new Error("Enter a valid HTTP or HTTPS URL with a host.");
    }
    if (/[\s\u0000-\u001f]/u.test(parsed.netloc)) throw new Error("Spaces and control characters are not allowed in the host.");
    return DeepIntelFeatures.normalizeForAnalysis(candidate);
  }

  function valuesFromMap(value, classes) {
    const entries = value instanceof Map ? value : (value && typeof value === "object" ? value : null);
    if (!entries) return null;
    const has = key => entries instanceof Map ? entries.has(key) : Object.prototype.hasOwnProperty.call(entries, key);
    const get = key => entries instanceof Map ? entries.get(key) : entries[key];
    const vector = classes.map((label, index) => {
      for (const key of [label, index, String(index)]) if (has(key)) return Number(get(key));
      return NaN;
    });
    return vector.every(Number.isFinite) ? vector : null;
  }

  function flattenNumbers(value) {
    const data = value && value.data !== undefined ? value.data : value;
    if (ArrayBuffer.isView(data)) return Array.from(data, Number);
    if (Array.isArray(data) && data.every(Number.isFinite)) return data.map(Number);
    if (Array.isArray(data) && data.length === 1) return flattenNumbers(data[0]);
    return null;
  }

  function probabilityVector(outputs, outputNames, classes) {
    const names = [...outputNames].sort((a, b) => Number(/prob/i.test(b)) - Number(/prob/i.test(a)));
    for (const name of names) {
      const output = outputs[name];
      const numeric = flattenNumbers(output);
      if (numeric && numeric.length >= classes.length) return numeric.slice(0, classes.length);
      const mapped = valuesFromMap(output, classes);
      if (mapped) return mapped;
      if (Array.isArray(output) && output.length) {
        const sequence = valuesFromMap(output[0], classes);
        if (sequence) return sequence;
      }
    }
    throw new Error("The ONNX model did not return a class-probability vector.");
  }

  function renderProbabilities(probabilities) {
    const highest = probabilities.indexOf(Math.max(...probabilities));
    $("result-title").textContent = `Model predicts ${metadata.classes[highest]}`;
    $("result-summary").textContent = "The highest-probability class from the on-device XGBoost model. This is not the full DeepIntel verdict.";
    const container = $("probabilities");
    container.replaceChildren();

    metadata.classes.forEach((className, index) => {
      const probability = probabilities[index];
      const row = document.createElement("div");
      row.className = "probability-row";
      const label = document.createElement("span");
      label.className = "probability-label";
      label.textContent = className;
      const track = document.createElement("div");
      track.className = "probability-track";
      track.setAttribute("role", "meter");
      track.setAttribute("aria-label", `${className} probability`);
      track.setAttribute("aria-valuemin", "0");
      track.setAttribute("aria-valuemax", "100");
      track.setAttribute("aria-valuenow", String(Math.round(probability * 10000) / 100));
      const fill = document.createElement("div");
      fill.className = `probability-fill ${className}`;
      fill.style.width = `${Math.max(0, Math.min(100, probability * 100))}%`;
      track.append(fill);
      const value = document.createElement("span");
      value.className = "probability-value";
      value.textContent = formatPercent(probability);
      row.append(label, track, value);
      container.append(row);
    });
  }

  async function loadParityReport() {
    try {
      const response = await fetch("./browser-results.json");
      if (!response.ok) return;
      const report = await response.json();
      if (report.rows !== metadata.testRows || report.labelChanges !== 0) return;
      $("parity-copy").textContent = `Python ↔ browser WASM parity: all ${report.rows.toLocaleString()} held-out test rows kept the same predicted class; maximum probability difference ${report.maxProbabilityError.toExponential(2)}. This checks the model export, not detection accuracy or the full pipeline.`;
      $("parity-card").hidden = false;
    } catch (_) {
      // The demo still works if the optional parity report is absent.
    }
  }

  async function loadModel() {
    try {
      if (typeof ort === "undefined") throw new Error("ONNX Runtime Web did not load. Serve this directory with `npm run serve`.");
      ort.env.wasm.wasmPaths = new URL("./runtime/", document.baseURI).href;
      ort.env.wasm.numThreads = 1;

      const response = await fetch("./metadata.json");
      if (!response.ok) throw new Error(`Could not load metadata.json (${response.status}).`);
      metadata = await response.json();
      if (!Array.isArray(metadata.features) || !Array.isArray(metadata.classes) || metadata.features.length !== DeepIntelFeatures.FEATURES.length) {
        throw new Error("Model metadata is missing its feature or class list.");
      }
      if (metadata.features.some((name, index) => name !== DeepIntelFeatures.FEATURES[index])) {
        throw new Error("Model feature order does not match the browser extractor.");
      }
      if (metadata.classes.length !== 3 || !metadata.featureConfig) throw new Error("Model metadata is incomplete.");

      session = await ort.InferenceSession.create("./model.onnx", { executionProviders: ["wasm"] });
      $("model-specs").textContent = `ONNX model · ${formatBytes(metadata.modelBytes)} · ${metadata.features.length} features · ${metadata.classes.length} classes · WebAssembly CPU`;
      $("model-specs").hidden = false;
      button.disabled = false;
      setStatus("Model ready on this device", "ready");
      await loadParityReport();
    } catch (reason) {
      const message = reason instanceof Error ? reason.message : "The local model could not be loaded.";
      setStatus("Model unavailable", "error");
      error.textContent = message;
      error.hidden = false;
    }
  }

  form.addEventListener("submit", async event => {
    event.preventDefault();
    error.hidden = true;
    button.disabled = true;
    button.textContent = "Analyzing…";

    try {
      const url = validateInput(input.value);
      const featureValues = DeepIntelFeatures.extractFeatures(url, metadata.featureConfig);
      const vector = Float32Array.from(metadata.features, name => featureValues[name]);
      if (vector.length !== metadata.features.length || vector.some(value => !Number.isFinite(value))) {
        throw new Error("The URL could not be converted to model features.");
      }

      const tensor = new ort.Tensor("float32", vector, [1, vector.length]);
      const started = performance.now();
      const outputs = await session.run({ [session.inputNames[0]]: tensor });
      const elapsed = performance.now() - started;
      const probabilities = probabilityVector(outputs, session.outputNames, metadata.classes);
      if (probabilities.some(value => !Number.isFinite(value) || value < 0 || value > 1)) {
        throw new Error("The model returned invalid probabilities.");
      }
      renderProbabilities(probabilities);
      $("inference-time").textContent = `Model inference: ${elapsed.toFixed(1)} ms · the URL stayed in this browser tab.`;
      $("inference-time").hidden = false;
    } catch (reason) {
      error.textContent = reason instanceof Error ? reason.message : "Analysis failed. Check the URL and try again.";
      error.hidden = false;
    } finally {
      button.disabled = !session;
      button.textContent = "Analyze URL";
    }
  });

  loadModel();
})();
