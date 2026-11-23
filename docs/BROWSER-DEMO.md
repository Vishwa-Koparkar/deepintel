# Static browser dashboard

The Pages workflow publishes `dashboard.html` beside a self-contained `browser-prototype/` bundle. Open `/deepintel/dashboard.html` and analyze a URL without calling the Python API. Inference and URL feature extraction run in the browser with ONNX Runtime Web on CPU; the page does not submit the entered URL to a server. The model, trusted-domain data, and threat-intel lists are downloaded as static assets.

For a local preview from the repository root:

```sh
python3 -m http.server 4181
```

Open `http://127.0.0.1:4181/dashboard.html`. The static browser build is read-only. It uses bundled data snapshots, so threat-intel and trusted-domain changes require a new build. Personal feedback and updates are not available. TreeSHAP feature contributions are not included; the dashboard says so beside the decision trail.

## Parity check

`browser-prototype/full-parity.cjs` compares browser results against Python output for 6,556 held-out URLs plus 12 targeted cases. Current result: 6,568 rows, no label, risk, decider, reason, trace, or suggestion mismatches. Numeric score and probability comparisons allow 0.000101 to account for sub-micro differences between ONNX Runtime and sklearn inference before four-decimal rounding. Feature extraction was also checked against Python on all 6,556 held-out URLs: 131,120 feature values, zero mismatches.

The extension package in `browser-extension-ondevice/` reuses this engine and bundle. It was packaged and checked but has not been loaded in Chrome or Brave.
