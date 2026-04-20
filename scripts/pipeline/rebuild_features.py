"""
Rebuilds dataset_features.csv with 4 additional features
to reduce false positives on legitimate international/non-HTTPS domains.
Then retrains and re-evaluates.
"""

import pandas as pd
import re
import math
from urllib.parse import urlparse
from sklearn.model_selection import train_test_split

INPUT_FILE   = "data/dataset_clean.csv"
FEATURES_FILE = "data/dataset_features.csv"

SHORTENERS = {"bit.ly","tinyurl.com","goo.gl","t.co","ow.ly","is.gd","buff.ly","adf.ly","short.link","rebrand.ly","cutt.ly"}
SUSPICIOUS_KEYWORDS = {"login","signin","verify","secure","account","update","confirm","banking","password","credential","suspend","alert","urgent","free","winner","click","download","invoice","paypal","apple","microsoft","amazon","netflix","ebay","support"}
BRANDS = {"paypal","apple","microsoft","amazon","netflix","ebay","google","facebook","instagram","twitter","linkedin","dropbox","adobe","chase","bankofamerica","wellsfargo","dhl","fedex","ups"}
SUSPICIOUS_TLDS = {".xyz",".top",".club",".online",".site",".tk",".ml",".ga",".cf",".gq",".pw",".zip",".review",".country",".stream",".download",".racing",".win",".bid"}
SAFE_TLDS = {".com",".org",".edu",".gov",".net",".io",".co"}

# NEW: expanded safe TLD set including country codes
SAFE_COUNTRY_TLDS = {
    ".co.uk",".gov.uk",".ac.uk",".org.uk",
    ".com.au",".gov.au",".edu.au",
    ".co.jp",".go.jp",
    ".com.br",".gov.br",
    ".co.in",".gov.in",".ac.in",
    ".fr",".de",".it",".es",".nl",".se",".no",".dk",".fi",
    ".ca",".mx",".ar",".cl",
    ".gov",".mil",".edu",
}

# Legitimate non-suspicious path extensions
SAFE_EXTENSIONS = {".html",".htm",".php",".asp",".aspx",".jsp",".pdf",".png",".jpg",".gif",".css",".js"}

def entropy(s):
    if not s: return 0.0
    freq = {}
    for c in s: freq[c] = freq.get(c,0)+1
    t = len(s)
    return -sum((f/t)*math.log2(f/t) for f in freq.values())

def extract_features(url):
    try:
        parsed  = urlparse(url)
        domain  = parsed.netloc.lower().split(":")[0]
        path    = parsed.path.lower()
        query   = parsed.query.lower()
        full    = url.lower()
        parts   = domain.split(".")
        tld     = "."+parts[-1] if len(parts)>1 else ""
        tld2    = "."+".".join(parts[-2:]) if len(parts)>2 else tld  # e.g. .co.uk

        detected_brand = next((b for b in BRANDS if b in domain), None)
        is_imp = 0
        if detected_brand:
            is_real = domain in (f"{detected_brand}.com",f"{detected_brand}.org",f"www.{detected_brand}.com")
            is_imp = int(not is_real)

        # NEW feature 1: is domain a known safe country/institutional TLD
        is_safe_country_tld = int(tld2 in SAFE_COUNTRY_TLDS or tld in SAFE_COUNTRY_TLDS)

        # NEW feature 2: domain word count (legit domains tend to be 1-2 real words)
        domain_clean = re.sub(r'\.(com|org|net|edu|gov|co|uk|jp|fr|de|au|br|in|ca|mx)$','',domain)
        domain_clean = re.sub(r'\W','',domain_clean)
        domain_word_len = len(domain_clean)

        # NEW feature 3: path has known safe file extension
        ext = "." + path.split(".")[-1] if "." in path else ""
        has_safe_extension = int(ext in SAFE_EXTENSIONS)

        # NEW feature 4: ratio of digits to domain length (high = suspicious)
        digit_ratio = round(sum(c.isdigit() for c in domain) / max(len(domain),1), 4)

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
            # new
            "is_safe_country_tld":     is_safe_country_tld,
            "domain_word_len":         domain_word_len,
            "has_safe_extension":      has_safe_extension,
            "digit_ratio":             digit_ratio,
        }
    except:
        return {k:0 for k in ["url_length","path_length","num_subdomains","num_digits","num_hyphens_domain","is_https","is_domain_ip","has_shortener","has_suspicious_keywords","is_brand_impersonation","has_at_symbol","has_double_slash","has_encoded_chars","num_query_params","domain_entropy","tld_category","is_safe_country_tld","domain_word_len","has_safe_extension","digit_ratio"]}

def main():
    df = pd.read_csv(INPUT_FILE)
    print(f"Re-extracting features for {len(df)} URLs...")

    rows = []
    for _, row in df.iterrows():
        f = extract_features(row["url"])
        f.update({"url":row["url"],"label":row["label"],"source":row["source"],"timestamp":row["timestamp"]})
        rows.append(f)

    feat_df = pd.DataFrame(rows)
    meta = ["url","label","source","timestamp"]
    feat_cols = [c for c in feat_df.columns if c not in meta]
    feat_df = feat_df[meta+feat_cols]
    feat_df.to_csv(FEATURES_FILE, index=False)
    print(f"Saved {len(feat_df)} rows with {len(feat_cols)} features to {FEATURES_FILE}")

    # Rebuild split
    feat_df["domain"] = feat_df["url"].apply(lambda u: urlparse(u).netloc.lower().split(":")[0])
    domains = feat_df["domain"].unique()
    train_d, temp_d = train_test_split(domains, test_size=0.30, random_state=42)
    val_d,   test_d = train_test_split(temp_d,  test_size=0.50, random_state=42)
    train = feat_df[feat_df["domain"].isin(train_d)].drop(columns=["domain"])
    val   = feat_df[feat_df["domain"].isin(val_d)].drop(columns=["domain"])
    test  = feat_df[feat_df["domain"].isin(test_d)].drop(columns=["domain"])
    train.to_csv("data/train.csv",index=False)
    val.to_csv("data/val.csv",index=False)
    test.to_csv("data/test.csv",index=False)
    print(f"Split: train={len(train)} val={len(val)} test={len(test)}")
    print("\nNow run: python tune_model.py && python evaluate_system.py")

if __name__ == "__main__":
    main()