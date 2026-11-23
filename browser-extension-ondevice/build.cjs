"use strict";

const fs = require("node:fs");
const path = require("node:path");

const root = __dirname;
const output = path.join(root, "dist");
const prototype = path.resolve(root, "../browser-prototype");
const runtime = path.join(root, "node_modules/onnxruntime-web");
const requiredRuntimeVersion = "1.31.1";

if (require(path.join(runtime, "package.json")).version !== requiredRuntimeVersion) {
  throw new Error(`Expected onnxruntime-web ${requiredRuntimeVersion}.`);
}

fs.rmSync(output, { recursive: true, force: true });
fs.mkdirSync(output, { recursive: true });

function copy(source, destination = path.basename(source)) {
  const from = path.isAbsolute(source) ? source : path.join(root, source);
  const to = path.join(output, destination);
  fs.mkdirSync(path.dirname(to), { recursive: true });
  fs.copyFileSync(from, to);
}

for (const file of ["manifest.json", "popup.html", "popup.css", "popup.js"]) copy(file);
for (const file of ["features.js", "engine.js", "metadata.json", "engine-data.json", "model.onnx"]) {
  copy(path.join(prototype, file));
}
for (const file of ["ort.wasm.min.js", "ort-wasm-simd-threaded.mjs", "ort-wasm-simd-threaded.wasm"]) {
  copy(path.join(runtime, "dist", file), `runtime/${file}`);
}
console.log(`Built unpacked extension at ${output}`);
