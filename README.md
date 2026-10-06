# DeepIntel

AI-powered URL threat detection system with a multi-layer detection engine, explainability module, SOC analyst dashboard and a browser extension.

## Features

- **Multi-Layer Detection Engine** — ML model (XGBoost) + heuristic rule scoring + threat intelligence lookup, plus lookalike/typosquat detection and a trusted-domain allowlist
- **20 URL Features** — entropy, brand impersonation, TLD analysis, keyword detection, and more
- **Lookalike Detection** — catches typosquats and confusable-character domains (`rnicrosoft.com`, `g00gle.com`, `google.coms`) and brands hidden in subdomains (`login.paypal.evil.com`)
- **Explainability** — human-readable reasons naming the actual evidence in each URL, a per-layer decision trace, and the ML features that moved the score
- **Safe Alternatives** — suggests official websites when brand impersonation is detected
- **Personal Feedback Loop** — correct wrong verdicts from the extension or dashboard; corrections apply immediately and are learned on the next retrain
- **Browser Extension** — Manifest V3 extension that checks pages against the local API
- **SOC Dashboard** — URL analysis with risk gauge, confidence charts, decision trace and history
- **Auto-Updating Pipeline** — scheduled ingestion from live threat feeds with balanced dataset growth and automatic retraining
- **FastAPI Backend** — `/analyze` for verdicts, `/feedback` for corrections, `/dashboard` for the UI

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

## Performance

Measured on the full pipeline (ML + heuristics + threat intel + lookalike) with the allowlist and personal
feedback switched off, so the figures reflect detection on unknown sites.

| Metric | Value |
|---|---|
| Accuracy | 92.75% |
| False Positive Rate | 4.94% |
| False Negative Rate | 8.64% |
| Benign Recall | 95.1% |
| Malware Recall | 90.5% |
| Phishing Recall | 87.2% |
| Test Set Size | 6,555 URLs (held out, registered-domain-level split) |

Per-class results on the test set:

| Class | Precision | Recall | Support |
|---|---|---|---|
| Benign | 0.955 | 0.951 | 4,309 |
| Malware | 0.978 | 0.905 | 798 |
| Phishing | 0.826 | 0.872 | 1,448 |

Phishing is the weakest class; most errors are benign URLs flagged as phishing (204) and phishing flagged as benign (179).

### Why the accuracy is lower than in earlier versions

An earlier version reported **96.58%** accuracy (5,379 URLs). That figure came from a benchmark whose benign side was
bare domains (`https://example.com`), and it did not survive real browsing, for two reasons found by testing in the browser:

1. **"Has a path means not benign."** Trained on bare domains only, the model classified almost every real page
   (YouTube, Google, Wikipedia) as phishing. Benign training URLs are now augmented with realistic `www.`, subdomain,
   path and query variants (`scripts/pipeline/augment_benign.py`, two variants per domain).
2. **"Trailing slash means safe."** Benign URLs carried a trailing `/` that threat URLs never had, so the model
   learned the slash as a shortcut and waved phishing sites through. The analyzer now normalises URLs the same way
   the dataset does, the augmentation no longer creates the shortcut, and `evaluate_system.py` fails loudly if a
   trailing slash ever changes a verdict (`slash_flips` is reported in `models/system_eval.json`).

The current benchmark is harder and closer to real traffic, so the numbers are lower. They are **not directly
comparable** to the old ones: the test set is larger (6,555 vs 5,379) and has a different class mix.

### Caveats

- The benchmark's benign side is synthetic (augmented Majestic domains), so these numbers are a floor-style sanity
  check, not a prediction of real-world accuracy.
- The allowlist (top-ranked domains with no threat history) lowers the benign false-positive rate on real browsing
  to near zero, but that is not reported as accuracy because the allowlist is built from the same benign source as
  the test set.
- Lookalike/typosquat domains are caught by `lookalike.py`, not the ML model, which cannot detect them because they
  look like ordinary short domains.
- The system runs against a local API and has not been deployed.

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

The feedback endpoints (`/feedback`) answer only the extension and the dashboard served by the API, not other
websites in your browser.

## Dataset

Built from 4 verified, actively-maintained threat intelligence sources:

- **Majestic Million** — benign ground truth, ranked by referring subnets
- **OpenPhish** — researcher-verified live phishing feed
- **PhishTank (Cisco Talos)** — community + machine-verified phishing feed
- **URLhaus (abuse.ch)** — malware URL feed, coordinated with Europol/FBI

Benign URLs are augmented as described above. Train/val/test are split 70/15/15 by **registered domain** so the same
domain never appears in more than one split. User corrections are added to the train split only.

> A merged third-party dataset (Kaggle) was evaluated during development but removed
> from the final pipeline after diagnosis showed inconsistent labeling was degrading
> model performance (85.4% → 96.6% accuracy on the benchmark of that time, before the
> benign-augmentation change above). The final dataset uses only verified sources.

## Setup

```bash
git clone https://github.com/YOUR_USERNAME/deepintel.git
cd deepintel
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

**Run the backend:**
```bash
uvicorn api:app --reload
```

Open `http://localhost:8000/dashboard` to use the SOC dashboard. Open it from the API rather than as a local file:
the feedback controls only work from the API's own origin.

**Install the browser extension:** open `chrome://extensions`, enable *Developer mode*, choose *Load unpacked* and
select the `browser-extension/` folder. The backend must be running on `localhost:8000`.

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
