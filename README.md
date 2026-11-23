# DeepIntel

**Explainable URL threat detection, from machine learning to the browser.**

DeepIntel helps teams investigate suspicious links with a verdict they can inspect. It combines XGBoost, heuristic rules, threat intelligence, and lookalike-domain detection to classify URLs as **benign, phishing, or malware**, then shows the evidence behind each decision.

A FastAPI backend powers an analyst dashboard and Chrome extension. Corrections feed back into training, and a scheduled pipeline ingests new threat URLs and triggers model updates. For startup teams exploring link screening in support, moderation, or internal security workflows, DeepIntel provides a working local system to evaluate and extend.

[Try it locally](#run-it-locally) · [Engineering decisions](#engineering-decisions) · [Evaluation](#evaluation) · [Code map](#project-structure)

## What’s built

| Capability | Implementation |
|---|---|
| API and browser integration | A shared detection engine behind a FastAPI endpoint, dashboard, and Manifest V3 browser extension. |
| Data quality and feature engineering | Real browsing exposed dataset shortcuts; URL augmentation and consistent normalization address them. |
| ML evaluation | A held-out domain split, per-class metrics, false-positive and false-negative rates, and explicit benchmark limitations. |
| Explainable AI | Human-readable evidence, per-layer decision traces, and XGBoost feature contributions. |
| Feedback-driven learning | SQLite-backed corrections apply immediately and enter the training split on retraining. |
| Model lifecycle automation | Scheduled feed ingestion, retraining triggers, a validation gate, and a backup of the previous model. |

The dashboard brings together a risk gauge, confidence charts, analysis history, and a decision trace. The extension checks browsing URLs against the local API and offers correction controls; detected impersonation can also produce an official-site suggestion.

## Engineering decisions

### Fix the data before chasing a better score

An earlier benchmark reported **96.58% accuracy**, but browser testing exposed two shortcuts. Bare-domain benign examples taught the model to treat real page paths as suspicious. Inconsistent trailing slashes also became an accidental label signal.

The pipeline now augments benign URLs with realistic subdomains, paths, and queries, and the analyzer normalizes URLs consistently with the dataset. Evaluation includes a trailing-slash regression check; the committed report records **zero verdict flips**. The current **92.75%** result comes from a larger, different test set and is not directly comparable to the earlier figure.

Relevant code: [benign augmentation](scripts/pipeline/augment_benign.py), [feature rebuilding and domain splits](scripts/pipeline/rebuild_features.py), [system evaluation](scripts/evaluation/evaluate_system.py).

### Use multiple signals and expose how they interact

The model scores 20 URL features, including domain entropy, brand impersonation, TLD risk, and URL structure. Heuristics and local threat-intelligence blocklists add independent signals. A separate lookalike detector handles domains such as `rnicrosoft.com` and brands hidden in subdomains such as `login.paypal.evil.com`.

The response includes the deciding layer, a decision trace, and feature contributions. This makes it possible to investigate a verdict rather than accept a label without evidence.

Relevant code: [fusion engine](analyzer.py), [lookalike detection](lookalike.py), [explanations](explainer.py).

### Let corrections improve the system without blindly trusting them

Corrections take effect immediately and receive extra weight in the next training run. Their scope stays narrow on shared hosting platforms, and a known threat-intelligence hit cannot be marked safe. Retraining rejects a model if validation accuracy drops by more than one percentage point and keeps a backup of the previous model.

Relevant code: [feedback and scope rules](feedback.py), [API validation](api.py), [retraining entry point](scripts/pipeline/retrain.py), [model validation gate](scripts/evaluation/tune_model.py).

## Run it locally

The project currently runs locally. Model artifacts are git-ignored, so a fresh clone needs training before URL analysis works. Run the following from the repository root.

```bash
git clone https://github.com/Vishwa-Koparkar/deepintel.git
cd deepintel
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Initialize the label encoder on first setup, then train using the included dataset:

```bash
python - <<'PYTHON'
import joblib
from sklearn.preprocessing import LabelEncoder

encoder = LabelEncoder().fit(["benign", "malware", "phishing"])
joblib.dump(encoder, "models/label_encoder.pkl")
PYTHON
python scripts/pipeline/retrain.py
uvicorn api:app --reload
```

- **Dashboard:** open [localhost:8000/dashboard](http://localhost:8000/dashboard). Serve it through the API so the feedback controls work.
- **API docs:** open [localhost:8000/docs](http://localhost:8000/docs).
- **Chrome extension:** open `chrome://extensions`, enable *Developer mode*, choose *Load unpacked*, and select `browser-extension/`. Keep the backend running on `localhost:8000`.

Try the API without visiting the submitted URL:

```bash
curl -X POST http://localhost:8000/analyze \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://example.com"}'
```

The response includes `prediction`, `risk_level`, `score`, `reasons`, `drivers`, `decided_by`, `trace`, and an optional safe-site `suggestion`. The core analyzer works on URL text and local data; it does not fetch the submitted page's content.

## Evaluation

The [committed evaluation report](models/system_eval.json) measures the full detection pipeline with the allowlist and personal feedback disabled. This avoids crediting the system for trusted domains drawn from the same benign source as the test data.

| Metric | Result |
|---|---|
| Accuracy | 92.75% |
| False-positive rate | 4.94% |
| False-negative rate | 8.64% |
| Test set | 6,555 URLs |
| Split | 70/15/15 by registered domain |
| Trailing-slash verdict flips | 0 |

| Class | Precision | Recall | Test URLs |
|---|---|---|---|
| Benign | 95.5% | 95.1% | 4,309 |
| Malware | 97.8% | 90.5% | 798 |
| Phishing | 82.6% | 87.2% | 1,448 |

**What still needs work:** phishing is the weakest class. The test set includes 204 benign URLs flagged as phishing and 179 phishing URLs classified as benign. Benign examples are synthetically augmented Majestic domains, so these results do not establish accuracy on live startup traffic. The project has not been deployed or benchmarked under production load.

The API is configured for local development, with permissive analysis CORS and origin checks on feedback. A shared deployment would need authentication, tighter access controls, and operational validation.

To regenerate the report after training:

```bash
python scripts/evaluation/evaluate_system.py
```

## Architecture

```
URL Input → Normalisation → Feature Extraction → ML Model (70%)
                                               → Heuristic Rules (15%)
                                               → Threat Intel Lookup (15%)
                                               → Score Fusion
                         → Allowlist (trusted top-ranked domains)
                         → Lookalike / typosquat check
                         → Your corrections (feedback.py)
                         → Verdict + Risk Level + Explanation + Decision Trace
```

The three weighted layers produce a fused risk score. The allowlist, lookalike check and personal corrections then
adjust the verdict, in that order. A threat-intel blocklist hit can only be overridden by a "phishing/malware"
correction, never by a "safe" one. The API response includes `decided_by` and a `trace` showing, for every layer,
whether it decided the verdict, agreed with it, or was overruled.

## Fixing false positives and false negatives (personal feedback)

Wrong verdicts can be corrected from the extension popup ("Wrong? This site is safe / phishing", with a
confirm click) or from the dashboard at `http://localhost:8000/dashboard`. Corrections go into a local SQLite
database (`data/feedback.db`, git-ignored) and work in two stages:

1. **Immediately:** the correction overrides the verdict for that URL, site or domain. Scope stays narrow on shared
   platforms (`github.io`, `docs.google.com`, ...), so one report can't whitelist a whole hosting service. A
   threat-intel blocklist hit always wins over a "safe" correction (the API answers 409). Corrections can be undone
   from the popup or the dashboard's *Your Corrections* table.
2. **On retrain:** corrected URLs are added to the training set (train split only, weight 5x) so the model itself learns
   from them. `python scripts/pipeline/retrain.py` rebuilds the features and trains; the scheduler runs it automatically
   when new threat-feed URLs or 10+ unlearned corrections have accumulated. The previous model is kept as
   `models/best_model.prev.pkl`, and a retrain that lowers validation accuracy by more than 1 point is rejected.

The feedback endpoints (`/feedback`) check browser origins and accept Chrome-extension and localhost origins.
These checks support local use; they are not a substitute for authentication on a shared service.

## Data and training

The dataset combines **Majestic Million** benign domains, **OpenPhish** and **PhishTank** phishing URLs, and **URLhaus** malware URLs. Benign domains are augmented with realistic browsing variants. Train, validation, and test sets are separated by registered domain; user corrections enter the training split only.

A third-party Kaggle dataset was removed during development after inconsistent labels were found to hurt model performance. The current pipeline uses the sources above.

### Pipeline commands

**Check URLs from the command line (no visiting, URL text only):**
```bash
python scripts/evaluation/check_urls.py urls.txt                  # one URL per line
python scripts/evaluation/check_urls.py --fetch openphish 50      # fresh phishing URLs from the live feed
python scripts/evaluation/check_urls.py --fetch urlhaus 50        # fresh malware URLs from the live feed
python scripts/evaluation/check_urls.py --no-allowlist urls.txt   # test the model on unknown sites
```

**Rebuild the dataset and retrain the model from scratch:**
```bash
python scripts/collectors/fetch_benign.py
python scripts/collectors/fetch_phishing.py
python scripts/collectors/fetch_malware_ransomware.py
python scripts/pipeline/clean_and_merge.py
python scripts/pipeline/retrain.py        # rebuilds features + domain split (+ augmentation, corrections), then trains
python scripts/evaluation/evaluate_system.py
```

`retrain.py` runs `rebuild_features.py` (augment, extract features, split by registered domain, add corrections) and
then `tune_model.py`. Don't run `split_dataset.py` afterwards: it is an older script that re-splits by host and would
overwrite the split and the weighted corrections. `train_models.py` is a baseline comparison of the candidate models.

**Run the auto-update pipeline manually (one cycle):**
```bash
python auto_update.py
```

**Start the auto-update scheduler (runs every 24 hours):**
```bash
python scheduler.py
```

Each run fetches new URLs from URLhaus and OpenPhish, deduplicates against the existing dataset, caps growth at 500
URLs/class/run, extracts features, and appends to the dataset. A retrain is triggered once 2,000 new URLs have
accumulated or 10 user corrections are waiting to be learned. Runs are logged to `data/update_log.csv` and
`logs/scheduler.log`. The running API reloads the model and dataset-derived caches when they change.

## Project Structure

```
deepintel/
├── data/                      # Datasets, threat intel files, feedback.db (local, git-ignored)
├── models/                    # Trained model, label encoder, evaluation reports
├── logs/                      # Scheduler logs
├── browser-extension/         # Manifest V3 extension (popup, background worker)
├── scripts/
│   ├── collectors/            # URL fetcher scripts (benign, phishing, malware)
│   ├── pipeline/              # Cleaning, augmentation, feature extraction, splitting, retrain
│   └── evaluation/            # Training, tuning, full-system evaluation, URL checker
├── analyzer.py                # Core fusion engine, allowlist, decision trace
├── heuristic_scorer.py        # Layer 2: rule-based scoring
├── threat_intel.py            # Layer 3: blocklist lookup
├── lookalike.py               # Typosquat / confusable-domain detection
├── feedback.py                # Personal corrections (SQLite) and training rows
├── explainer.py               # Human-readable explanations
├── safe_alternative.py        # Safe URL suggestions
├── api.py                     # FastAPI backend
├── auto_update.py             # Auto-updating data pipeline (single run)
├── scheduler.py               # APScheduler wrapper: runs auto_update.py every 24h, triggers retrains
└── dashboard.html             # SOC analyst dashboard
```

## Tech Stack

Python, XGBoost, scikit-learn, FastAPI, APScheduler, SQLite, HTML/CSS/JS, Chrome Extension (Manifest V3)
