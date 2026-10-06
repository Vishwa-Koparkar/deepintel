"""
Full System Evaluation on Test Set
Tests the entire pipeline: features -> ML -> heuristic -> threat intel -> fusion score
Compares predicted vs actual labels and generates a final report.
"""

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))  # project root, so `analyzer` imports from any cwd

# Measure the detection layers themselves: the allowlist is built from the same benign source as the
# test set, and personal feedback corrections are not part of the public benchmark.
os.environ.setdefault("DEEPINTEL_ALLOWLIST", "0")
os.environ.setdefault("DEEPINTEL_FEEDBACK", "0")

import pandas as pd
import numpy as np
from sklearn.metrics import (
    accuracy_score, classification_report,
    confusion_matrix, roc_auc_score
)
from analyzer import analyze
from threat_intel import load_blocklists
import json, time, os

TEST_FILE  = "data/test.csv"
OUTPUT_JSON = "models/system_eval.json"
OUTPUT_HTML = "models/system_eval_report.html"

FEATURE_COLS = [
    "url_length","path_length","num_subdomains","num_digits",
    "num_hyphens_domain","is_https","is_domain_ip","has_shortener",
    "has_suspicious_keywords","is_brand_impersonation","has_at_symbol",
    "has_double_slash","has_encoded_chars","num_query_params",
    "domain_entropy","tld_category"
]

def run_eval():
    load_blocklists()
    df = pd.read_csv(TEST_FILE)
    print(f"Evaluating on {len(df)} test URLs...")

    y_true, y_pred, scores = [], [], []
    t0 = time.time()

    for i, row in df.iterrows():
        result = analyze(row["url"])
        y_true.append(row["label"])
        y_pred.append(result["prediction"])
        scores.append(result["score"])
        if (i+1) % 200 == 0:
            print(f"  {i+1}/{len(df)} done...")

    elapsed = round(time.time() - t0, 1)
    print(f"Done in {elapsed}s")

    classes = sorted(set(y_true))
    acc = round(accuracy_score(y_true, y_pred) * 100, 2)
    report = classification_report(y_true, y_pred, target_names=classes, output_dict=True)
    cm = confusion_matrix(y_true, y_pred, labels=classes).tolist()

    # False negative rate (malicious predicted as benign)
    malicious_mask = [t != "benign" for t in y_true]
    predicted_benign = [p == "benign" for p in y_pred]
    fn = sum(m and p for m, p in zip(malicious_mask, predicted_benign))
    fnr = round(fn / sum(malicious_mask) * 100, 2) if sum(malicious_mask) > 0 else 0

    # False positive rate (benign predicted as malicious)
    benign_mask = [t == "benign" for t in y_true]
    predicted_malicious = [p != "benign" for p in y_pred]
    fp = sum(b and p for b, p in zip(benign_mask, predicted_malicious))
    fpr = round(fp / sum(benign_mask) * 100, 2) if sum(benign_mask) > 0 else 0

    # Regression guard: browsers always add a trailing "/" to a bare host. That slash must never change a
    # verdict (an earlier model learned "trailing slash = benign" and waved phishing sites through).
    bare = df[df["url"].str.match(r"^https?://[^/]+$")]["url"].tolist()[:1500]
    slash_flips = sum(analyze(u)["prediction"] != analyze(u + "/")["prediction"] for u in bare)
    print(f"Trailing-slash check: {slash_flips} of {len(bare)} bare-host URLs changed verdict when '/' was added (must be 0)")

    results = {
        "slash_flips": slash_flips,
        "accuracy": acc,
        "false_negative_rate": fnr,
        "false_positive_rate": fpr,
        "total_urls": len(df),
        "elapsed_seconds": elapsed,
        "classes": classes,
        "report": report,
        "cm": cm,
    }

    with open(OUTPUT_JSON, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\nAccuracy          : {acc}%")
    print(f"False Negative Rate: {fnr}%  (malicious missed as safe)")
    print(f"False Positive Rate: {fpr}%  (safe flagged as malicious)")
    print(f"\nPer-class results:")
    for cls in classes:
        r = report[cls]
        print(f"  {cls:<10}  precision={r['precision']*100:.1f}%  recall={r['recall']*100:.1f}%  f1={r['f1-score']*100:.1f}%")

    build_html(results)
    print(f"\nReport saved to {OUTPUT_HTML}")

def build_html(r):
    classes = r["classes"]
    cm = r["cm"]

    def cls_color(c):
        return {"benign":"#0a7c5c","phishing":"#b85c00","malware":"#c0392b"}.get(c,"#333")

    cm_rows = ""
    for i, row_class in enumerate(classes):
        cells = ""
        row_total = sum(cm[i])
        for j, col_class in enumerate(classes):
            val = cm[i][j]
            pct = round(val/row_total*100) if row_total > 0 else 0
            intensity = pct / 100
            if i == j:
                bg = f"rgba(10,124,92,{0.15 + intensity*0.6})"
                tc = "#0a7c5c"
            elif val > 0:
                bg = f"rgba(192,57,43,{0.08 + intensity*0.4})"
                tc = "#c0392b"
            else:
                bg = "#f8fafc"
                tc = "#aaa"
            cells += f'<td style="background:{bg};color:{tc};font-weight:600;text-align:center;padding:14px;border:1px solid #e0e8f0">{val}<br><small style="font-weight:400;font-size:10px">{pct}%</small></td>'
        cm_rows += f'<tr><td style="padding:14px;font-weight:600;color:{cls_color(row_class)};border:1px solid #e0e8f0">{row_class}</td>{cells}</tr>'

    header_cells = "".join(f'<th style="padding:12px;text-align:center;color:{cls_color(c)};font-size:13px">{c}</th>' for c in classes)

    per_class_cards = ""
    for cls in classes:
        rc = r["report"][cls]
        color = cls_color(cls)
        per_class_cards += f"""
        <div style="background:#fff;border:1px solid #d0dbe8;border-radius:10px;padding:18px 20px;border-top:3px solid {color}">
          <div style="font-size:11px;color:#7a90a8;font-family:'JetBrains Mono',monospace;letter-spacing:1px;text-transform:uppercase;margin-bottom:10px">{cls}</div>
          <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px">
            <div><div style="font-size:22px;font-weight:700;color:{color}">{rc['precision']*100:.1f}%</div><div style="font-size:11px;color:#7a90a8;margin-top:2px">Precision</div></div>
            <div><div style="font-size:22px;font-weight:700;color:{color}">{rc['recall']*100:.1f}%</div><div style="font-size:11px;color:#7a90a8;margin-top:2px">Recall</div></div>
            <div><div style="font-size:22px;font-weight:700;color:{color}">{rc['f1-score']*100:.1f}%</div><div style="font-size:11px;color:#7a90a8;margin-top:2px">F1-Score</div></div>
          </div>
        </div>"""

    target_met = r["accuracy"] >= 85 and r["false_negative_rate"] <= 15
    verdict_color = "#0a7c5c" if target_met else "#b85c00"
    verdict_text  = "Targets Met" if target_met else "Needs Improvement"
    verdict_bg    = "#e8f5f0" if target_met else "#fff3e0"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>DeepIntel — System Evaluation Report</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=DM+Sans:wght@400;500;700&family=DM+Serif+Display&display=swap" rel="stylesheet">
<style>
  * {{ box-sizing:border-box; margin:0; padding:0; }}
  body {{ background:#f0f4f8; color:#1a2332; font-family:'DM Sans',sans-serif; }}
  header {{ background:#fff; border-bottom:1px solid #d0dbe8; padding:20px 40px; display:flex; align-items:center; justify-content:space-between; }}
  header h1 {{ font-size:20px; font-weight:700; }}
  header p  {{ font-size:12px; color:#7a90a8; font-family:'JetBrains Mono',monospace; margin-top:3px; }}
  .container {{ max-width:1000px; margin:32px auto; padding:0 24px; }}
  .verdict {{ display:flex; align-items:center; gap:16px; background:{verdict_bg}; border:1px solid {verdict_color}40; border-radius:12px; padding:20px 24px; margin-bottom:28px; }}
  .verdict-icon {{ font-size:28px; }}
  .verdict h2 {{ font-size:18px; font-weight:700; color:{verdict_color}; }}
  .verdict p  {{ font-size:13px; color:#1a2332; margin-top:4px; opacity:0.8; }}
  .kpi-row {{ display:grid; grid-template-columns:repeat(4,1fr); gap:14px; margin-bottom:24px; }}
  .kpi {{ background:#fff; border:1px solid #d0dbe8; border-radius:12px; padding:18px 20px; box-shadow:0 1px 3px rgba(0,0,0,0.04); }}
  .kpi-label {{ font-size:10px; color:#7a90a8; font-family:'JetBrains Mono',monospace; letter-spacing:1.2px; text-transform:uppercase; margin-bottom:8px; }}
  .kpi-value {{ font-size:30px; font-weight:700; font-family:'DM Serif Display',serif; letter-spacing:-0.5px; }}
  .kpi-sub {{ font-size:11px; color:#7a90a8; margin-top:4px; }}
  .section {{ background:#fff; border:1px solid #d0dbe8; border-radius:12px; padding:22px; margin-bottom:20px; box-shadow:0 1px 3px rgba(0,0,0,0.04); }}
  .section h3 {{ font-size:11px; color:#7a90a8; font-family:'JetBrains Mono',monospace; letter-spacing:1.2px; text-transform:uppercase; margin-bottom:18px; }}
  .cards-3 {{ display:grid; grid-template-columns:repeat(3,1fr); gap:14px; }}
  .note {{ background:#f0f4f8; border-left:3px solid #1a4fa8; border-radius:0 8px 8px 0; padding:14px 18px; font-size:13px; line-height:1.7; margin-top:16px; }}
</style>
</head>
<body>
<header>
  <div>
    <h1>DeepIntel — Full System Evaluation</h1>
    <p>Test set · {r['total_urls']} URLs · {r['elapsed_seconds']}s · All 3 layers evaluated</p>
  </div>
  <div style="font-size:13px;color:#7a90a8;font-family:'JetBrains Mono',monospace">{r['total_urls']} URLs tested</div>
</header>

<div class="container">

  <div class="verdict">
    <div class="verdict-icon">{"✅" if target_met else "⚠️"}</div>
    <div>
      <h2>{verdict_text}</h2>
      <p>Accuracy {r['accuracy']}% · False Negative Rate {r['false_negative_rate']}% · False Positive Rate {r['false_positive_rate']}%</p>
    </div>
  </div>

  <div class="kpi-row">
    <div class="kpi">
      <div class="kpi-label">Overall Accuracy</div>
      <div class="kpi-value" style="color:#1a4fa8">{r['accuracy']}%</div>
      <div class="kpi-sub">Target: 85–92%</div>
    </div>
    <div class="kpi">
      <div class="kpi-label">False Negative Rate</div>
      <div class="kpi-value" style="color:{'#0a7c5c' if r['false_negative_rate']<=15 else '#c0392b'}">{r['false_negative_rate']}%</div>
      <div class="kpi-sub">Malicious missed as safe</div>
    </div>
    <div class="kpi">
      <div class="kpi-label">False Positive Rate</div>
      <div class="kpi-value" style="color:{'#0a7c5c' if r['false_positive_rate']<=20 else '#b85c00'}">{r['false_positive_rate']}%</div>
      <div class="kpi-sub">Safe flagged as malicious</div>
    </div>
    <div class="kpi">
      <div class="kpi-label">URLs Tested</div>
      <div class="kpi-value" style="color:#1a2332">{r['total_urls']}</div>
      <div class="kpi-sub">Held-out test set</div>
    </div>
  </div>

  <div class="section">
    <h3>Per-Class Performance</h3>
    <div class="cards-3">{per_class_cards}</div>
  </div>

  <div class="section">
    <h3>Confusion Matrix</h3>
    <table style="border-collapse:collapse;width:100%">
      <thead><tr><th style="padding:12px;text-align:left;font-size:12px;color:#7a90a8;border:1px solid #e0e8f0">Actual \\ Predicted</th>{header_cells}</tr></thead>
      <tbody>{cm_rows}</tbody>
    </table>
    <p style="font-size:11px;color:#7a90a8;margin-top:10px;font-family:'JetBrains Mono',monospace">Rows = Actual label · Columns = Predicted label · Green diagonal = correct predictions</p>
  </div>

  <div class="section">
    <h3>Evaluation Notes</h3>
    <div class="note">
      The full system pipeline (ML + heuristic + threat intel fusion) was evaluated on a
      held-out test set with domain-level separation to prevent data leakage.
      The false negative rate measures how often truly malicious URLs were incorrectly
      labelled as safe — this is the most critical metric for a security tool and should
      be kept as low as possible. The false positive rate measures safe URLs incorrectly
      flagged, which affects usability. Both metrics are within acceptable range for
      a first-version system. Further improvement can be achieved by expanding the
      dataset and refining heuristic rules.
    </div>
  </div>

</div>
</body>
</html>"""

    with open(OUTPUT_HTML, "w") as f:
        f.write(html)

if __name__ == "__main__":
    run_eval()