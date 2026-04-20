import pandas as pd
import re
from datetime import datetime
from urllib.parse import urlparse

FILES = {
    "benign":   "data/benign.csv",
    "phishing": "data/phishing.csv",
    "malware":  "data/malware.csv",
    "ransomware": "data/ransomware.csv",  # will be folded into malware
}

OUTPUT_FILE = "data/dataset_clean.csv"

# Priority order for conflict resolution (higher index = higher priority)
PRIORITY = {"benign": 0, "phishing": 1, "malware": 2, "ransomware": 2}

def is_valid_url(url):
    try:
        result = urlparse(url)
        return result.scheme in ("http", "https") and bool(result.netloc)
    except:
        return False

def normalize_url(url):
    url = url.strip().lower()
    url = url.rstrip("/")
    return url

def clean_df(df, label):
    original = len(df)
    df = df.dropna(subset=["url"])
    df["url"] = df["url"].astype(str).apply(normalize_url)
    df = df[df["url"].apply(is_valid_url)]
    df = df.drop_duplicates(subset="url")
    print(f"  {label}: {original} → {len(df)} after cleaning")
    return df

def clean_and_merge():
    dfs = []

    for label, filepath in FILES.items():
        try:
            df = pd.read_csv(filepath)
            df["label"] = label
            df = clean_df(df, label)
            dfs.append(df)
        except Exception as e:
            print(f"  Skipping {filepath}: {e}")

    combined = pd.concat(dfs, ignore_index=True)

    # Fold ransomware into malware
    combined["label"] = combined["label"].replace("ransomware", "malware")
    print(f"\nAfter folding ransomware → malware: {len(combined)} total rows")

    # Resolve conflicts: same URL appearing in multiple categories
    # Keep the one with highest priority label
    combined["priority"] = combined["label"].map(PRIORITY)
    combined = combined.sort_values("priority", ascending=False)
    combined = combined.drop_duplicates(subset="url", keep="first")
    combined = combined.drop(columns=["priority"])

    # Add metadata
    combined["timestamp"] = datetime.utcnow().strftime("%Y-%m-%d")

    # Keep only needed columns
    combined = combined[["url", "label", "source", "timestamp"]]
    combined = combined.reset_index(drop=True)

    # Print class distribution
    print("\nClass distribution:")
    print(combined["label"].value_counts())

    combined.to_csv(OUTPUT_FILE, index=False)
    print(f"\nSaved cleaned dataset to {OUTPUT_FILE} ({len(combined)} rows)")

if __name__ == "__main__":
    clean_and_merge()