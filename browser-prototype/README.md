# On-device feasibility prototype

This is a runnable **model-only** experiment, not a replacement for the full DeepIntel detector. Open <http://127.0.0.1:4180/> while the local server is running.

```bash
cd browser-prototype
npm ci
npm run serve
```

The URL stays in the tab. The page loads a local ONNX model and CPU-only ONNX Runtime Web. It does not fetch submitted URLs. No quantization, pruning, or substitute classifier was used.

Measured in headless Brave on the development Mac:

| Check | Result |
| --- | --- |
| Raw URLs | 6,556 |
| Float32 feature values compared to Python | 131,120; zero mismatches |
| Browser vs Python ML labels | Zero changes |
| Maximum class probability difference | 6.26e-7 |
| Native pickle | 2,983,542 bytes |
| ONNX | 2,054,745 bytes; 282,933 bytes gzip |
| WASM runtime | 14,848,852 bytes; 3,809,536 bytes gzip |
| Initialization on local loopback | 232 ms |
| Inference over full batch | 230 ms |
| Warm single-row inference | Median 0.1 ms; p95 1 ms |

These are local measurements, not first-visit internet/mobile guarantees. Gzip sizes are calculated compression sizes; the simple Python server serves uncompressed files. Browser/runtime memory has not been measured. See `browser-results.json` and `metadata.json` for machine-readable evidence.

The fresh model was trained with the existing `scripts/evaluation/tune_model.py` recipe on the committed train/validation splits. Its model-only result is separate from the older committed full-system report (6,555 URLs, 92.75%). Native artifacts were also copied into ignored `models/` for local use; the browser proof ships its own ONNX model and reference fixtures.

To reproduce the training/export without rewriting the project splits or existing model files:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
# Apple Silicon XGBoost requires the OpenMP runtime (brew install libomp).
python train.py
# With the static server running in another terminal:
npm run verify
node features.test.cjs
```

The converter needs positional feature names; `export.py` changes those names on a copy of the trained model and compares every probability against Python before accepting export. The browser test then re-extracts raw URL features and scores the model in real WASM.

Before shipping on-device detection, port and verify heuristics, score fusion, blocklist snapshots, trusted-domain/lookalike logic, risk levels, readable reasons, TreeSHAP contributions, and correction behavior. Training/feed updates can remain an offline release job; publish versioned static snapshots. Do not remove the Python reference or change production behavior until full-system parity passes.
