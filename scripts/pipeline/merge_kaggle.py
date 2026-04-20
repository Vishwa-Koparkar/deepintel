"""
Merges the Kaggle malicious URLs dataset into our existing dataset.
- Maps Kaggle labels to our 3-class system (benign/phishing/malware)
- Deduplicates against existing URLs
- Maintains class balance (Option A: capped growth)
- Re-extracts features and rebuilds train/val/test split
"""

import pandas as pd
import re
import math
from urllib.parse import urlparse
from sklearn.model_selection import train_test_split

KAGGLE_FILE   = "data/kaggle/malicious_phish.csv"
EXISTING_FILE = "data/dataset_clean.csv"
MERGED_FILE   = "data/dataset_clean.csv"        # overwrite with merged
FEATURES_FILE = "data/dataset_features.csv"

# Kaggle label -> our label
LABEL_MAP = {
    "benign":   "benign",
    "phishing": "phishing",
    "malware":  "malware",
    "defacement": "malware",  # defacement = malware class
}

# Cap per class to keep balance (existing ~5k each, add up to 15k more each)
CAP_PER_CLASS = 20000

# ── feature extraction (same as extract_features.py) ──────────────────────

SHORTENERS = {"bit.ly","tinyurl.com","goo.gl","t.co","ow.ly","is.gd","buff.ly","adf.ly","short.link","rebrand.ly","cutt.ly"}
SUSPICIOUS_KEYWORDS = {"login","signin","verify","secure","account","update","confirm","banking","password","credential","suspend","alert","urgent","free","winner","click","download","invoice","paypal","apple","microsoft","amazon","netflix","ebay","support"}
BRANDS = {"paypal","apple","microsoft","amazon","netflix","ebay","google","facebook","instagram","twitter","linkedin","dropbox","adobe","chase","bankofamerica","wellsfargo","dhl","fedex","ups"}
SUSPICIOUS_TLDS = {".xyz",".top",".club",".online",".site",".tk",".ml",".ga",".cf",".gq",".pw",".zip",".review",".country",".stream",".download",".racing",".win",".bid"}
SAFE_TLDS = {".com",".org",".edu",".gov",".net",".io",".co"}

def entropy(s):
    if not s: return 0.0
    freq = {}
    for c in s: freq[c] = freq.get(c,0)+1
    t = len(s)
    return -sum((f/t)*math.log2(f/t) for f in freq.values())

def is_valid_url(url):
    try:
        r = urlparse(url if url.startswith("http") else "http://"+url)
        return bool(r.netloc)
    except: return False

def normalize_url(url):
    url = url.strip().lower().rstrip("/")
    if not url.startswith("http"):
        url = "http://" + url
    return url

def extract_features(url):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower().split(":")[0]
        path   = parsed.path.lower()
        query  = parsed.query.lower()
        full   = url.lower()
        parts  = domain.split(".")
        tld    = "."+parts[-1] if len(parts)>1 else ""
        detected_brand = next((b for b in BRANDS if b in domain), None)
        is_imp = 0
        if detected_brand:
            is_real = domain in (f"{detected_brand}.com",f"{detected_brand}.org",f"www.{detected_brand}.com")
            is_imp = int(not is_real)
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
        }
    except:
        return {k:0 for k in ["url_length","path_length","num_subdomains","num_digits","num_hyphens_domain","is_https","is_domain_ip","has_shortener","has_suspicious_keywords","is_brand_impersonation","has_at_symbol","has_double_slash","has_encoded_chars","num_query_params","domain_entropy","tld_category"]}

# ── main ──────────────────────────────────────────────────────────────────

def main():
    # Load existing
    existing = pd.read_csv(EXISTING_FILE)
    existing_urls = set(existing["url"].str.lower())
    print(f"Existing dataset: {len(existing)} rows")
    print(f"  {existing['label'].value_counts().to_dict()}")

    # Load Kaggle
    kaggle = pd.read_csv(KAGGLE_FILE)
    print(f"\nKaggle dataset: {len(kaggle)} rows")
    print(f"  {kaggle['type'].value_counts().to_dict()}")

    # Map labels
    kaggle = kaggle[kaggle["type"].isin(LABEL_MAP)].copy()
    kaggle["label"] = kaggle["type"].map(LABEL_MAP)
    kaggle = kaggle.drop(columns=["type"])

    # Normalize URLs
    kaggle["url"] = kaggle["url"].astype(str).apply(normalize_url)
    kaggle = kaggle[kaggle["url"].apply(is_valid_url)]
    kaggle = kaggle.drop_duplicates(subset="url")

    # Remove URLs already in our dataset
    kaggle = kaggle[~kaggle["url"].str.lower().isin(existing_urls)]
    print(f"\nNew unique Kaggle URLs after dedup: {len(kaggle)}")

    # Cap per class for balance (Option A)
    existing_counts = existing["label"].value_counts().to_dict()
    new_rows = []
    for label in ["benign", "phishing", "malware"]:
        current = existing_counts.get(label, 0)
        budget  = max(0, CAP_PER_CLASS - current)
        subset  = kaggle[kaggle["label"] == label].head(budget)
        new_rows.append(subset)
        print(f"  Adding {len(subset)} {label} URLs (current: {current}, cap: {CAP_PER_CLASS})")

    new_data = pd.concat(new_rows, ignore_index=True)
    new_data["source"]    = "kaggle_sid321axn"
    new_data["timestamp"] = pd.Timestamp.utcnow().strftime("%Y-%m-%d")

    # Merge
    merged = pd.concat([existing[["url","label","source","timestamp"]], new_data[["url","label","source","timestamp"]]], ignore_index=True)
    merged = merged.drop_duplicates(subset="url").reset_index(drop=True)

    print(f"\nMerged dataset: {len(merged)} rows")
    print(f"  {merged['label'].value_counts().to_dict()}")

    merged.to_csv(MERGED_FILE, index=False)
    print(f"Saved to {MERGED_FILE}")

    # Re-extract features
    print(f"\nExtracting features for {len(merged)} URLs...")
    feature_rows = []
    for _, row in merged.iterrows():
        feats = extract_features(row["url"])
        feats.update({"url": row["url"], "label": row["label"], "source": row["source"], "timestamp": row["timestamp"]})
        feature_rows.append(feats)

    feat_df = pd.DataFrame(feature_rows)
    meta = ["url","label","source","timestamp"]
    feat_cols = [c for c in feat_df.columns if c not in meta]
    feat_df = feat_df[meta + feat_cols]
    feat_df.to_csv(FEATURES_FILE, index=False)
    print(f"Features saved to {FEATURES_FILE}")

    # Rebuild split
    print("\nRebuilding train/val/test split...")
    feat_df["domain"] = feat_df["url"].apply(lambda u: urlparse(u).netloc.lower().split(":")[0])
    domains = feat_df["domain"].unique()
    train_d, temp_d = train_test_split(domains, test_size=0.30, random_state=42)
    val_d,   test_d = train_test_split(temp_d,  test_size=0.50, random_state=42)

    train = feat_df[feat_df["domain"].isin(train_d)].drop(columns=["domain"])
    val   = feat_df[feat_df["domain"].isin(val_d)].drop(columns=["domain"])
    test  = feat_df[feat_df["domain"].isin(test_d)].drop(columns=["domain"])

    train.to_csv("data/train.csv", index=False)
    val.to_csv("data/val.csv",     index=False)
    test.to_csv("data/test.csv",   index=False)

    print(f"  Train: {len(train)}  Val: {len(val)}  Test: {len(test)}")
    print(f"\nDone. Now re-run train_models.py to retrain on the larger dataset.")

if __name__ == "__main__":
    main()