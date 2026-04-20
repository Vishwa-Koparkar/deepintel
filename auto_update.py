"""
DeepIntel Auto-Update Pipeline
Periodically fetches new threat URLs, cleans them, adds to dataset,
and retrains the model if enough new data has accumulated.

Run once manually:     python auto_update.py
Run on a schedule:     python auto_update.py --schedule   (runs every 24h)
"""

import requests
import pandas as pd
import csv
import re
import math
import joblib
import argparse
import time
import os
from io import StringIO
from datetime import datetime
from urllib.parse import urlparse
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from xgboost import XGBClassifier
from sklearn.metrics import accuracy_score

# ── Config ────────────────────────────────────────────────────────────────
DATASET_FILE  = "data/dataset_clean.csv"
FEATURES_FILE = "data/dataset_features.csv"
LOG_FILE      = "data/update_log.csv"
RETRAIN_THRESHOLD = 2000   # retrain after this many new URLs added
MAX_PER_CLASS     = 50000  # hard cap per class to prevent unbounded growth
BALANCE_WINDOW    = 500    # max new URLs added per class per run (Option A)

FEATURE_COLS = [
    "url_length","path_length","num_subdomains","num_digits",
    "num_hyphens_domain","is_https","is_domain_ip","has_shortener",
    "has_suspicious_keywords","is_brand_impersonation","has_at_symbol",
    "has_double_slash","has_encoded_chars","num_query_params",
    "domain_entropy","tld_category",
    "is_safe_country_tld","domain_word_len","has_safe_extension","digit_ratio"
]

SHORTENERS = {"bit.ly","tinyurl.com","goo.gl","t.co","ow.ly","is.gd","buff.ly","adf.ly","short.link","rebrand.ly","cutt.ly"}
SUSPICIOUS_KEYWORDS = {"login","signin","verify","secure","account","update","confirm","banking","password","credential","suspend","alert","urgent","free","winner","click","download","invoice","paypal","apple","microsoft","amazon","netflix","ebay","support"}
BRANDS = {"paypal","apple","microsoft","amazon","netflix","ebay","google","facebook","instagram","twitter","linkedin","dropbox","adobe","chase","bankofamerica","wellsfargo","dhl","fedex","ups"}
SUSPICIOUS_TLDS = {".xyz",".top",".club",".online",".site",".tk",".ml",".ga",".cf",".gq",".pw",".zip",".review",".country",".stream",".download",".racing",".win",".bid"}
SAFE_TLDS = {".com",".org",".edu",".gov",".net",".io",".co"}
SAFE_COUNTRY_TLDS = {".co.uk",".gov.uk",".ac.uk",".org.uk",".com.au",".gov.au",".edu.au",".co.jp",".go.jp",".com.br",".gov.br",".co.in",".gov.in",".ac.in",".fr",".de",".it",".es",".nl",".se",".no",".dk",".fi",".ca",".mx",".ar",".cl",".gov",".mil",".edu"}
SAFE_EXTENSIONS = {".html",".htm",".php",".asp",".aspx",".jsp",".pdf",".png",".jpg",".gif",".css",".js"}

# ── Feature extraction ────────────────────────────────────────────────────

def entropy(s):
    if not s: return 0.0
    freq = {}
    for c in s: freq[c] = freq.get(c,0)+1
    t = len(s)
    return -sum((f/t)*math.log2(f/t) for f in freq.values())

def extract_features(url):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower().split(":")[0]
        path   = parsed.path.lower()
        query  = parsed.query.lower()
        full   = url.lower()
        parts  = domain.split(".")
        tld    = "."+parts[-1] if len(parts)>1 else ""
        tld2   = "."+".".join(parts[-2:]) if len(parts)>2 else tld
        detected_brand = next((b for b in BRANDS if b in domain), None)
        is_imp = 0
        if detected_brand:
            is_real = domain in (f"{detected_brand}.com",f"{detected_brand}.org",f"www.{detected_brand}.com")
            is_imp = int(not is_real)
        domain_clean = re.sub(r'\.(com|org|net|edu|gov|co|uk|jp|fr|de|au|br|in|ca|mx)$','',domain)
        domain_clean = re.sub(r'\W','',domain_clean)
        ext = "."+path.split(".")[-1] if "." in path else ""
        return {
            "url_length":              len(url),
            "path_length":             len(path),
            "num_subdomains":          max(0,len(parts)-2),
            "num_digits":              sum(c.isdigit() for c in full),
            "num_hyphens_domain":      domain.count("-"),
            "is_https":                int(parsed.scheme=="https"),
            "is_domain_ip":            int(bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",domain))),
            "has_shortener":           int(domain in SHORTENERS),
            "has_suspicious_keywords": int(any(kw in full for kw in SUSPICIOUS_KEYWORDS)),
            "is_brand_impersonation":  is_imp,
            "has_at_symbol":           int("@" in url),
            "has_double_slash":        int("//" in path),
            "has_encoded_chars":       int("%" in url),
            "num_query_params":        len(query.split("&")) if query else 0,
            "domain_entropy":          round(entropy(domain),4),
            "tld_category":            0 if tld in SAFE_TLDS else (2 if tld in SUSPICIOUS_TLDS else 1),
            "is_safe_country_tld":     int(tld2 in SAFE_COUNTRY_TLDS or tld in SAFE_COUNTRY_TLDS),
            "domain_word_len":         len(domain_clean),
            "has_safe_extension":      int(ext in SAFE_EXTENSIONS),
            "digit_ratio":             round(sum(c.isdigit() for c in domain)/max(len(domain),1),4),
        }
    except:
        return {col:0 for col in FEATURE_COLS}

def is_valid_url(url):
    try:
        r = urlparse(url)
        return r.scheme in ("http","https") and bool(r.netloc)
    except: return False

def normalize_url(url):
    url = url.strip().lower().rstrip("/")
    if not url.startswith("http"):
        url = "http://" + url
    return url

# ── Fetchers ──────────────────────────────────────────────────────────────

def fetch_urlhaus():
    print("  Fetching URLhaus recent feed...")
    try:
        r = requests.get("https://urlhaus.abuse.ch/downloads/csv_recent/",
                         timeout=60, headers={"User-Agent":"deepintel-updater"})
        r.raise_for_status()
        lines = r.text.splitlines()
        header_line = None
        data_lines  = []
        for line in lines:
            stripped = line.lstrip("# ").strip()
            if header_line is None and "id" in stripped.lower() and "url" in stripped.lower() and "," in stripped:
                header_line = stripped
            elif header_line and not line.startswith("#") and line.strip():
                data_lines.append(line)
        if not header_line:
            print("  URLhaus: could not parse header")
            return []
        fieldnames = [f.strip().strip('"') for f in header_line.split(",")]
        reader = csv.DictReader(data_lines, fieldnames=fieldnames)
        urls = []
        for row in reader:
            u = (row.get("url") or "").strip().strip('"')
            if u.startswith("http"):
                urls.append((u, "malware", "urlhaus"))
        print(f"  URLhaus: {len(urls)} URLs")
        return urls
    except Exception as e:
        print(f"  URLhaus failed: {e}")
        return []

def fetch_openphish():
    print("  Fetching OpenPhish feed...")
    try:
        r = requests.get("https://openphish.com/feed.txt", timeout=30)
        r.raise_for_status()
        urls = [(l.strip(), "phishing", "openphish")
                for l in r.text.splitlines() if l.strip().startswith("http")]
        print(f"  OpenPhish: {len(urls)} URLs")
        return urls
    except Exception as e:
        print(f"  OpenPhish failed: {e}")
        return []

# ── Retrain ───────────────────────────────────────────────────────────────

def retrain():
    print("\n  Retraining model on updated dataset...")
    feat_df = pd.read_csv(FEATURES_FILE)
    feat_df["domain"] = feat_df["url"].apply(lambda u: urlparse(u).netloc.lower().split(":")[0])
    domains = feat_df["domain"].unique()
    train_d, temp_d = train_test_split(domains, test_size=0.30, random_state=42)
    val_d, test_d   = train_test_split(temp_d,  test_size=0.50, random_state=42)
    train = feat_df[feat_df["domain"].isin(train_d)].drop(columns=["domain"])
    val   = feat_df[feat_df["domain"].isin(val_d)].drop(columns=["domain"])
    test  = feat_df[feat_df["domain"].isin(test_d)].drop(columns=["domain"])
    train.to_csv("data/train.csv",index=False)
    val.to_csv("data/val.csv",index=False)
    test.to_csv("data/test.csv",index=False)

    le = joblib.load("models/label_encoder.pkl")
    X_train = train[FEATURE_COLS]
    y_train = le.transform(train["label"])
    X_val   = val[FEATURE_COLS]
    y_val   = le.transform(val["label"])

    model = XGBClassifier(n_estimators=400,max_depth=8,learning_rate=0.05,
                          subsample=0.8,colsample_bytree=0.8,min_child_weight=3,
                          gamma=0.1,use_label_encoder=False,eval_metric="mlogloss",
                          random_state=42,n_jobs=-1,early_stopping_rounds=20,verbosity=0)
    model.fit(X_train,y_train,eval_set=[(X_val,y_val)],verbose=False)
    acc = accuracy_score(y_val, model.predict(X_val))
    joblib.dump(model,"models/best_model.pkl")
    print(f"  Retrain complete. Val accuracy: {acc*100:.2f}%")
    return round(acc*100,2)

# ── Main update run ───────────────────────────────────────────────────────

def run_update():
    print(f"\n{'='*50}")
    print(f"DeepIntel Auto-Update — {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")
    print(f"{'='*50}")

    # Load existing dataset
    existing = pd.read_csv(DATASET_FILE)
    existing_urls = set(existing["url"].str.lower())
    class_counts = existing["label"].value_counts().to_dict()
    print(f"Current dataset: {len(existing)} rows — {class_counts}")

    # Fetch new URLs
    new_urls = []
    new_urls += fetch_urlhaus()
    new_urls += fetch_openphish()

    if not new_urls:
        print("No new URLs fetched. Skipping update.")
        return

    # Clean and filter
    new_df = pd.DataFrame(new_urls, columns=["url","label","source"])
    new_df["url"] = new_df["url"].apply(normalize_url)
    new_df = new_df[new_df["url"].apply(is_valid_url)]
    new_df = new_df.drop_duplicates(subset="url")
    new_df = new_df[~new_df["url"].str.lower().isin(existing_urls)]
    print(f"New unique URLs after dedup: {len(new_df)}")

    # Option A: capped balanced growth
    added_rows = []
    added_counts = {}
    for label in ["benign","phishing","malware"]:
        current = class_counts.get(label,0)
        if current >= MAX_PER_CLASS:
            print(f"  {label}: at max cap ({MAX_PER_CLASS}), skipping")
            continue
        budget = min(BALANCE_WINDOW, MAX_PER_CLASS - current)
        subset = new_df[new_df["label"]==label].head(budget)
        added_rows.append(subset)
        added_counts[label] = len(subset)
        print(f"  {label}: adding {len(subset)} new URLs")

    if not added_rows or all(len(r)==0 for r in added_rows):
        print("Nothing new to add.")
        return

    new_data = pd.concat(added_rows, ignore_index=True)
    new_data["timestamp"] = datetime.utcnow().strftime("%Y-%m-%d")

    # Append to dataset
    updated = pd.concat([existing, new_data[["url","label","source","timestamp"]]], ignore_index=True)
    updated.to_csv(DATASET_FILE, index=False)
    total_added = len(new_data)
    print(f"Dataset updated: {len(existing)} → {len(updated)} rows (+{total_added})")

    # Extract features for new rows only and append
    print("Extracting features for new URLs...")
    feat_rows = []
    for _, row in new_data.iterrows():
        f = extract_features(row["url"])
        f.update({"url":row["url"],"label":row["label"],"source":row["source"],"timestamp":row["timestamp"]})
        feat_rows.append(f)

    new_feats = pd.DataFrame(feat_rows)
    existing_feats = pd.read_csv(FEATURES_FILE)
    meta = ["url","label","source","timestamp"]
    feat_cols = [c for c in new_feats.columns if c not in meta]
    updated_feats = pd.concat([existing_feats, new_feats[meta+feat_cols]], ignore_index=True)
    updated_feats.to_csv(FEATURES_FILE, index=False)

    # Log this run
    log_entry = {
        "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M"),
        "total_added": total_added,
        "dataset_size": len(updated),
        **{f"added_{k}": v for k,v in added_counts.items()}
    }
    log_df = pd.DataFrame([log_entry])
    if os.path.exists(LOG_FILE):
        log_df = pd.concat([pd.read_csv(LOG_FILE), log_df], ignore_index=True)
    log_df.to_csv(LOG_FILE, index=False)

    # Check if retraining threshold reached
    total_since_last = log_df["total_added"].tail(5).sum()
    if total_since_last >= RETRAIN_THRESHOLD:
        acc = retrain()
        print(f"  Model retrained. New accuracy: {acc}%")
    else:
        remaining = RETRAIN_THRESHOLD - total_since_last
        print(f"\n  Retraining threshold not reached yet ({total_since_last}/{RETRAIN_THRESHOLD} new URLs). Need {remaining} more.")

    print(f"\nUpdate complete.")

# ── Entry point ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--schedule", action="store_true", help="Run every 24 hours")
    parser.add_argument("--interval", type=int, default=86400, help="Interval in seconds (default: 86400 = 24h)")
    args = parser.parse_args()

    if args.schedule:
        print(f"Scheduler started. Running every {args.interval//3600}h.")
        while True:
            run_update()
            print(f"Next run in {args.interval//3600}h. Sleeping...")
            time.sleep(args.interval)
    else:
        run_update()