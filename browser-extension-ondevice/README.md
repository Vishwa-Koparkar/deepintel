# Optional on-device browser extension

This is a separate Manifest V3 extension from [`browser-extension/`](../browser-extension/), which uses DeepIntel's API. This extension bundles the browser engine, model, threat data, and pinned ONNX Runtime Web 1.31.1. Its popup checks a URL locally; it does not open the URL, request host access, or send it to an API.

Build an unpacked extension from the repository root:

```bash
cd browser-extension-ondevice
npm ci
npm run build
```

Load the generated `browser-extension-ondevice/dist/` directory as an unpacked extension in Chrome or Brave. The build copies the shared `browser-prototype/engine.js`, `features.js`, `metadata.json`, `engine-data.json`, and model, plus only the ONNX WASM runtime files this extension uses. Rebuild after changing the shared browser engine or its data.

The manifest allows WebAssembly execution in extension pages through `wasm-unsafe-eval`, as required by ONNX Runtime. No network or tab permissions are declared. Model and threat-data limitations apply; this is an optional prototype and its result can be wrong.
