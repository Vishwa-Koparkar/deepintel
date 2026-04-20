# DeepIntel

AI-powered URL threat detection system with a 3-layer detection engine, explainability module, and SOC analyst dashboard.

## Features

- **3-Layer Detection Engine** — ML model (XGBoost) + heuristic rule scoring + threat intelligence lookup
- **20 URL Features** — entropy, brand impersonation, TLD analysis, keyword detection, and more
- **Explainability** — top 3-5 human-readable reasons for every flagged URL
- **Safe Alternatives** — suggests official websites when brand impersonation is detected
- **SOC Dashboard** — real-time URL analysis with risk gauge, confidence charts, and history
- **Auto-Updating Pipeline** — periodic ingestion from threat feeds with balanced dataset growth
- **FastAPI Backend** — single `/analyze` endpoint powering the dashboard

## Architecture

```
URL Input → Feature Extraction → ML Model (Layer 1)
                                → Heuristic Rules (Layer 2)
                                → Threat Intel Lookup (Layer 3)
                                → Score Fusion → Risk Level + Explanation
```

## Performance

| Metric | Value |
|---|---|
| Accuracy | 87.59% |
| False Negative Rate | 6.14% |
| False Positive Rate | 13.9% |
| Phishing Recall | 90.4% |
| Malware Recall | 86.5% |
| Dataset Size | 60,000 URLs |

## Setup

```bash
git clone https://github.com/YOUR_USERNAME/deepintel.git
cd deepintel
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

Start the backend:
```bash
uvicorn api:app --reload
```

Open `dashboard.html` in your browser to use the SOC dashboard.

## Project Structure

```
deepintel/
├── data/                      # Datasets and threat intel files
├── models/                    # Trained models and evaluation reports
├── scripts/
│   ├── collectors/            # URL fetcher scripts
│   ├── pipeline/              # Cleaning, features, splitting
│   └── evaluation/            # Training, tuning, reports
├── analyzer.py                # Core 3-layer fusion engine
├── heuristic_scorer.py        # Layer 2: rule-based scoring
├── threat_intel.py            # Layer 3: blocklist lookup
├── explainer.py               # Human-readable explanations
├── safe_alternative.py        # Safe URL suggestions
├── api.py                     # FastAPI backend
├── auto_update.py             # Auto-updating data pipeline
└── dashboard.html             # SOC analyst dashboard
```

## Tech Stack

Python, XGBoost, scikit-learn, FastAPI, HTML/CSS/JS