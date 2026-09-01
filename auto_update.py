import os
import sys
import requests
import pandas as pd
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from analyzer import extract_features, FEATURE_COLS

DATASET_PATH      = "data/dataset_clean.csv"
FEATURES_PATH     = "data/dataset_features.csv"
LOG_PATH          = "data/update_log.csv"
COUNT_FILE        = "data/new_url_count.txt"
RETRAIN_FLAG      = "retrain_trigger.flag"
MAX_PER_CLASS     = 500
RETRAIN_THRESHOLD = 2000

URLHAUS_FEED   = "https://urlhaus.abuse.ch/downloads/text_recent/"
OPENPHISH_FEED = "https://openphish.com/feed.txt"


def normalize_url(url):
    from urllib.parse import urlparse, urlunparse
    try:
        url = url.strip()
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "http://" + url
        p = urlparse(url)
        norm = urlunparse((p.scheme.lower(), p.netloc.lower(), p.path,
                            p.params, p.query, p.fragment))
        if norm.endswith("/") and norm.count("/") == 3:
            norm = norm.rstrip("/")
        return norm
    except:
        return url.strip()


def fetch_urlhaus():
    try:
        r = requests.get(URLHAUS_FEED, timeout=15)
        urls = [l.strip() for l in r.text.splitlines()
                if l.strip() and not l.startswith("#")]
        print(f"URLhaus: fetched {len(urls)} URLs")
        return urls
    except Exception as e:
        print(f"URLhaus fetch failed: {e}")
        return []


def fetch_openphish():
    try:
        r = requests.get(OPENPHISH_FEED, timeout=15)
        urls = [l.strip() for l in r.text.splitlines() if l.strip()]
        print(f"OpenPhish: fetched {len(urls)} URLs")
        return urls
    except Exception as e:
        print(f"OpenPhish fetch failed: {e}")
        return []


def update_count_and_check_trigger(new_count):
    accumulated = 0
    if os.path.exists(COUNT_FILE):
        with open(COUNT_FILE) as f:
            try:
                accumulated = int(f.read().strip())
            except:
                accumulated = 0
    accumulated += new_count
    print(f"Accumulated new URLs since last retrain: {accumulated}")
    if accumulated >= RETRAIN_THRESHOLD:
        with open(RETRAIN_FLAG, "w") as f:
            f.write("retrain")
        accumulated = 0
        print(f"Retrain trigger set (threshold {RETRAIN_THRESHOLD} reached)")
    with open(COUNT_FILE, "w") as f:
        f.write(str(accumulated))


def write_log(added_malware, added_phishing, total_new):
    entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "added_malware": added_malware,
        "added_phishing": added_phishing,
        "total_added": total_new,
    }
    log_df = pd.read_csv(LOG_PATH) if os.path.exists(LOG_PATH) else pd.DataFrame()
    log_df = pd.concat([log_df, pd.DataFrame([entry])], ignore_index=True)
    log_df.to_csv(LOG_PATH, index=False)
    print(f"Log updated: {entry}")


def run_pipeline():
    print(f"\n{'='*50}\nDeepIntel Auto-Update Pipeline")
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n{'='*50}\n")

    if not os.path.exists(DATASET_PATH):
        print(f"Dataset not found at {DATASET_PATH}. Exiting.")
        return

    existing = pd.read_csv(DATASET_PATH)
    existing_urls = set(existing["url"].apply(normalize_url).tolist())
    print(f"Existing dataset: {len(existing)} URLs")

    malware_urls  = [normalize_url(u) for u in fetch_urlhaus()]
    phishing_urls = [normalize_url(u) for u in fetch_openphish()]

    malware_urls  = [u for u in malware_urls  if u not in existing_urls][:MAX_PER_CLASS]
    phishing_urls = [u for u in phishing_urls if u not in existing_urls][:MAX_PER_CLASS]
    print(f"New (deduped, capped) — malware: {len(malware_urls)}, phishing: {len(phishing_urls)}")

    if not malware_urls and not phishing_urls:
        print("No new URLs to add. Pipeline complete.")
        return

    all_new = [(u, "malware") for u in malware_urls] + \
              [(u, "phishing") for u in phishing_urls]

    clean_rows, feat_rows = [], []
    for url, label in all_new:
        feats = extract_features(url)
        if feats:
            clean_rows.append({"url": url, "label": label, "source": "auto_update"})
            feats["label"] = label
            feats["url"] = url
            feat_rows.append(feats)

    if not clean_rows:
        print("Feature extraction returned no valid rows.")
        return

    clean_df = pd.DataFrame(clean_rows)
    pd.concat([existing, clean_df], ignore_index=True).to_csv(DATASET_PATH, index=False)

    feat_df = pd.DataFrame(feat_rows)
    if os.path.exists(FEATURES_PATH):
        existing_feats = pd.read_csv(FEATURES_PATH)
        pd.concat([existing_feats, feat_df], ignore_index=True).to_csv(FEATURES_PATH, index=False)
    else:
        feat_df.to_csv(FEATURES_PATH, index=False)

    total_new = len(clean_rows)
    added_malware  = sum(1 for r in clean_rows if r["label"] == "malware")
    added_phishing = sum(1 for r in clean_rows if r["label"] == "phishing")
    print(f"\nAdded {total_new} new URLs (malware: {added_malware}, phishing: {added_phishing})")

    update_count_and_check_trigger(total_new)
    write_log(added_malware, added_phishing, total_new)
    print(f"\nPipeline complete: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")


if __name__ == "__main__":
    run_pipeline()