# DeepIntel

AI-powered URL threat detection system with a 3-layer detection engine, explainability module, and SOC analyst dashboard.

## Features

- **3-Layer Detection Engine** — ML model (XGBoost) + heuristic rule scoring + threat intelligence lookup
- **20 URL Features** — entropy, brand impersonation, TLD analysis, keyword detection, and more
- **Explainability** — top 3-5 human-readable reasons for every flagged URL
- **Safe Alternatives** — suggests official websites when brand impersonation is detected
- **SOC Dashboard** — real-time URL analysis with risk gauge, confidence charts, and history
- **Auto-Updating Pipeline** — scheduled ingestion from live threat feeds with balanced dataset growth and automatic retraining
- **FastAPI Backend** — single `/analyze` endpoint powering the dashboard

## Architecture

```
URL Input → Feature Extraction → ML Model (Layer 1, 70%)
                                → Heuristic Rules (Layer 2, 15%)
                                → Threat Intel Lookup (Layer 3, 15%)
                                → Score Fusion → Risk Level + Explanation
```

## Performance

| Metric | Value |
|---|---|
| Accuracy | 96.58% |
| False Negative Rate | 2.58% |
| False Positive Rate | 1.97% |
| Benign Recall | 98.0% |
| Malware Recall | 92.2% |
| Phishing Recall | 96.4% |
| Test Set Size | 5,379 URLs (held out, domain-level split) |

Evaluated on the full 3-layer pipeline (ML + heuristic + threat intel fusion), not the ML model in isolation.

## Dataset

Built from 4 verified, actively-maintained threat intelligence sources:

- **Majestic Million** — benign ground truth, ranked by referring subnets
- **OpenPhish** — researcher-verified live phishing feed
- **PhishTank (Cisco Talos)** — community + machine-verified phishing feed
- **URLhaus (abuse.ch)** — malware URL feed, coordinated with Europol/FBI

> A merged third-party dataset (Kaggle) was evaluated during development but removed
> from the final pipeline after diagnosis showed inconsistent labeling was degrading
> model performance (85.4% → 96.6% accuracy after removal). Final dataset uses only
> verified sources with domain-level train/val/test splitting to prevent data leakage.

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

Open `dashboard.html` in your browser to use the SOC dashboard.

**Rebuild the dataset and retrain the model from scratch:**
```bash
python scripts/collectors/fetch_benign.py
python scripts/collectors/fetch_phishing.py
python scripts/collectors/fetch_malware_ransomware.py
python scripts/pipeline/clean_and_merge.py
python scripts/pipeline/rebuild_features.py
python scripts/pipeline/split_dataset.py
python scripts/evaluation/train_models.py
python scripts/evaluation/tune_model.py
python scripts/evaluation/evaluate_system.py
```

**Run the auto-update pipeline manually (one cycle):**
```bash
python auto_update.py
```

**Start the auto-update scheduler (runs every 24 hours):**
```bash
python scheduler.py
```

Fetches new URLs from URLhaus and OpenPhish, deduplicates against the existing dataset, caps growth at 500 URLs/class/run, extracts features, and appends to the dataset. Automatically flags a retrain once 2,000 new URLs have accumulated. Logs every run to `data/update_log.csv`.

## Project Structure

```
deepintel/
├── data/                      # Datasets and threat intel files
├── models/                    # Trained model, label encoder, evaluation reports
├── logs/                      # Scheduler logs
├── scripts/
│   ├── collectors/            # URL fetcher scripts (benign, phishing, malware)
│   ├── pipeline/               # Cleaning, normalization, feature extraction, splitting
│   └── evaluation/            # Training, tuning, full-system evaluation
├── analyzer.py                # Core 3-layer fusion engine
├── heuristic_scorer.py        # Layer 2: rule-based scoring
├── threat_intel.py            # Layer 3: blocklist lookup
├── explainer.py                # Human-readable explanations
├── safe_alternative.py        # Safe URL suggestions
├── api.py                     # FastAPI backend
├── auto_update.py             # Auto-updating data pipeline (single run)
├── scheduler.py                # APScheduler wrapper — runs auto_update.py every 24h
└── dashboard.html             # SOC analyst dashboard
```

## Tech Stack

Python, XGBoost, scikit-learn, FastAPI, APScheduler, HTML/CSS/JS