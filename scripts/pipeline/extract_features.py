import pandas as pd
import re
import math
from urllib.parse import urlparse, unquote

INPUT_FILE = "data/dataset_clean.csv"
OUTPUT_FILE = "data/dataset_features.csv"

SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "short.link", "rebrand.ly", "cutt.ly"
}

SUSPICIOUS_KEYWORDS = {
    "login", "signin", "verify", "secure", "account", "update", "confirm",
    "banking", "password", "credential", "suspend", "alert", "urgent",
    "free", "winner", "click", "download", "invoice", "paypal", "apple",
    "microsoft", "amazon", "netflix", "ebay", "support"
}

BRANDS = {
    "paypal", "apple", "microsoft", "amazon", "netflix", "ebay", "google",
    "facebook", "instagram", "twitter", "linkedin", "dropbox", "adobe",
    "chase", "bankofamerica", "wellsfargo", "dhl", "fedex", "ups"
}

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".club", ".online", ".site", ".tk", ".ml", ".ga",
    ".cf", ".gq", ".pw", ".zip", ".review", ".country", ".stream",
    ".download", ".racing", ".win", ".bid"
}

SAFE_TLDS = {".com", ".org", ".edu", ".gov", ".net", ".io", ".co"}

def entropy(s):
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    total = len(s)
    return -sum((f/total) * math.log2(f/total) for f in freq.values())

def extract_features(url):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        query = parsed.query.lower()
        full = url.lower()

        # Remove port from domain if present
        domain_clean = domain.split(":")[0]
        parts = domain_clean.split(".")
        tld = "." + parts[-1] if len(parts) > 1 else ""

        features = {}

        # 1. URL length
        features["url_length"] = len(url)

        # 2. Path length
        features["path_length"] = len(path)

        # 3. Number of subdomains
        features["num_subdomains"] = max(0, len(parts) - 2)

        # 4. Number of digits in URL
        features["num_digits"] = sum(c.isdigit() for c in full)

        # 5. Number of hyphens in domain
        features["num_hyphens_domain"] = domain_clean.count("-")

        # 6. Is HTTPS
        features["is_https"] = int(parsed.scheme == "https")

        # 7. Is domain an IP address
        features["is_domain_ip"] = int(bool(re.match(
            r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain_clean
        )))

        # 8. Has URL shortener
        features["has_shortener"] = int(domain_clean in SHORTENERS)

        # 9. Has suspicious keywords
        features["has_suspicious_keywords"] = int(any(
            kw in full for kw in SUSPICIOUS_KEYWORDS
        ))

        # 10. Is brand impersonation (brand in domain but not the real domain)
        detected_brand = next((b for b in BRANDS if b in domain_clean), None)
        if detected_brand:
            # Real domain would be exactly brand.com or brand.org etc.
            is_real = domain_clean in (f"{detected_brand}.com", f"{detected_brand}.org",
                                        f"www.{detected_brand}.com")
            features["is_brand_impersonation"] = int(not is_real)
        else:
            features["is_brand_impersonation"] = 0

        # 11. Has @ symbol
        features["has_at_symbol"] = int("@" in url)

        # 12. Has double slash redirect
        features["has_double_slash"] = int("//" in path)

        # 13. Has encoded characters
        features["has_encoded_chars"] = int("%" in url)

        # 14. Number of query parameters
        features["num_query_params"] = len(query.split("&")) if query else 0

        # 15. Domain entropy
        features["domain_entropy"] = round(entropy(domain_clean), 4)

        # 16. TLD category
        if tld in SAFE_TLDS:
            features["tld_category"] = 0  # safe
        elif tld in SUSPICIOUS_TLDS:
            features["tld_category"] = 2  # suspicious
        else:
            features["tld_category"] = 1  # neutral

        return features

    except Exception:
        return None

def main():
    df = pd.read_csv(INPUT_FILE)
    print(f"Extracting features for {len(df)} URLs...")

    feature_rows = []
    failed = 0

    for _, row in df.iterrows():
        feats = extract_features(row["url"])
        if feats is None:
            failed += 1
            # Fill defaults for failed rows
            feats = {k: 0 for k in [
                "url_length", "path_length", "num_subdomains", "num_digits",
                "num_hyphens_domain", "is_https", "is_domain_ip", "has_shortener",
                "has_suspicious_keywords", "is_brand_impersonation", "has_at_symbol",
                "has_double_slash", "has_encoded_chars", "num_query_params",
                "domain_entropy", "tld_category"
            ]}
        feats["url"] = row["url"]
        feats["label"] = row["label"]
        feats["source"] = row["source"]
        feats["timestamp"] = row["timestamp"]
        feature_rows.append(feats)

    result = pd.DataFrame(feature_rows)

    # Reorder columns cleanly
    meta_cols = ["url", "label", "source", "timestamp"]
    feat_cols = [c for c in result.columns if c not in meta_cols]
    result = result[meta_cols + feat_cols]

    result.to_csv(OUTPUT_FILE, index=False)

    print(f"Done. Failed extractions (filled with defaults): {failed}")
    print(f"\nFeature preview:")
    print(result[feat_cols].describe().round(2))
    print(f"\nSaved to {OUTPUT_FILE} ({len(result)} rows)")

if __name__ == "__main__":
    main()