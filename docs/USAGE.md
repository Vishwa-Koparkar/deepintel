# DeepIntel Usage Guide

This guide covers a fresh local setup, the dashboard and browser extension, corrections, model training, and evaluation. DeepIntel analyzes URL text; the analyzer does not fetch the submitted page.

## Set up a fresh clone

Use Python 3.12 with the pinned packages in `requirements.txt`. Trained model files are git-ignored, so a fresh clone needs a label encoder and model before `/analyze` can run. The tracked `data/dataset_clean.csv` is the input for the first training run.

```bash
git clone https://github.com/Vishwa-Koparkar/deepintel.git
cd deepintel
python3.12 -m venv venv
source venv/bin/activate
python -m pip install -r requirements.txt
```

Create the label encoder once, then build the features, domain-based splits, and model:

```bash
python - <<'PY'
import joblib
from sklearn.preprocessing import LabelEncoder

joblib.dump(LabelEncoder().fit(["benign", "malware", "phishing"]), "models/label_encoder.pkl")
PY
python scripts/pipeline/retrain.py
```

Start the local API and dashboard:

```bash
uvicorn api:app --reload
```

- Dashboard: <http://localhost:8000/dashboard>
- Interactive API docs: <http://localhost:8000/docs>
- Health response: <http://localhost:8000/>

The dashboard should be served by the API so it can use the local feedback endpoints.

## Use the Chrome extension

Keep the API running at `http://localhost:8000`. In Chrome, open `chrome://extensions`, enable **Developer mode**, choose **Load unpacked**, and select this repository's `browser-extension/` directory. The extension analyzes an HTTP(S) tab when it finishes loading, shows a badge and verdict in the popup, and can report a correction. It sends URL text to the local API; onion URLs are kept local to the extension.

The extension is configured for localhost. Pointing it at a hosted service requires a deliberate endpoint and permission change.

## Call the API

The `/analyze` endpoint accepts a URL string and returns the prediction, risk level, confidence, reasons, model probabilities, feature drivers, deciding layer, and a decision trace.

```bash
curl -X POST http://localhost:8000/analyze \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://example.com"}'
```

For one URL per line, use `scripts/evaluation/check_urls.py`:

```bash
python scripts/evaluation/check_urls.py urls.txt
python scripts/evaluation/check_urls.py --no-allowlist urls.txt
python scripts/evaluation/check_urls.py --fetch openphish 50
python scripts/evaluation/check_urls.py --fetch urlhaus 50
```

`--no-allowlist` evaluates without the trusted-domain allowlist. `--with-feedback` applies saved corrections; corrections are off by default for this command. The `--fetch` modes read current public feeds, so their results can change over time.

## Correct a verdict

Use the extension popup or the local dashboard to mark a result safe or phishing. The local feedback API also accepts malware corrections. Public read-only deployments disable corrections. A saved correction can affect later analyses immediately. The scope is intentionally limited: corrections on IPs or domains with threat history apply to the exact URL; a benign correction on an ordinary domain applies to that domain; malicious corrections generally apply to the host, with narrower handling for trusted sites.

Corrections are stored in `data/feedback.db`, which is local and git-ignored. A URL on a threat-intelligence blocklist cannot be marked safe. You can remove a correction from the dashboard or extension popup.

## Rebuild data and retrain

`python scripts/pipeline/retrain.py` is the supported retraining entry point. It rebuilds URL features, augments benign URLs, splits by a domain-derived key into 70/15/15 train/validation/test sets, adds eligible corrections to the training split at 5x weight, then tunes the XGBoost model. Do not run the legacy `scripts/pipeline/split_dataset.py` afterward; it splits by host and overwrites the domain-grouped files.

When a prior model exists, training keeps a backup at `models/best_model.prev.pkl` and rejects a replacement if validation accuracy falls by more than one percentage point. The API notices a changed model file and reloads it. Run evaluation separately after training:

```bash
DEEPINTEL_ALLOWLIST=0 DEEPINTEL_FEEDBACK=0 python scripts/evaluation/evaluate_system.py
```

The evaluation writes `models/system_eval.json` and `models/system_eval_report.html`. It reports overall accuracy, false-positive rate (benign URLs predicted as malicious), false-negative rate (malicious URLs predicted as benign), per-class metrics, and a trailing-slash regression count. The committed report uses a domain-held-out test set; the domain key is a project heuristic, not a public-suffix-list implementation. Benign data comes from Majestic Million domains with synthetic browsing variants, and threat labels come from public feeds. This offline result does not establish performance on live startup traffic or under production load.

## Refresh the source datasets

The collector scripts fetch current source files and overwrite their corresponding CSVs in `data/`. `clean_and_merge.py` then rebuilds `data/dataset_clean.csv`; review the fetched files before running this sequence if you need to preserve a local dataset snapshot.

```bash
python scripts/collectors/fetch_benign.py
python scripts/collectors/fetch_phishing.py
python scripts/collectors/fetch_malware_ransomware.py
python scripts/pipeline/clean_and_merge.py
python scripts/pipeline/retrain.py
DEEPINTEL_ALLOWLIST=0 DEEPINTEL_FEEDBACK=0 python scripts/evaluation/evaluate_system.py
```

The full collectors use Majestic Million for benign domains, OpenPhish and PhishTank for phishing URLs, and URLhaus for malware and ransomware. Ransomware rows are folded into the malware class during cleaning. Threat-feed contents and labels can change between runs.

## Run the update scheduler

Run one ingestion cycle with `python auto_update.py`. It reads URLhaus and OpenPhish, adds up to 500 new URLs per threat class in a cycle, and records update counts in `data/update_log.csv`. This command ingests and records updates; it does not train a new model itself.

To run the scheduler, use a separate terminal:

```bash
python scheduler.py
```

The scheduler runs a cycle at startup and every 24 hours. It retrains after 2,000 accumulated feed URLs or at least 10 unlearned corrections. Scheduler output is also written to `logs/scheduler.log`. Keep this process separate from the API in local use.

## Local showcase

The static project showcase is in `website/` and does not call the API. Preview it from the repository root with:

```bash
python3 -m http.server 4173 --directory website
```

Open <http://localhost:4173>. Hosting considerations and the deployment plan are in [DEPLOYMENT.md](DEPLOYMENT.md).
