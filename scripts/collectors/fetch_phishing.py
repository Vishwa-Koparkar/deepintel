import requests
import pandas as pd
import csv
from io import StringIO

OUTPUT_FILE = "data/phishing.csv"
TARGET_COUNT = 15000

def fetch_from_openphish():
    print("Fetching from OpenPhish...")
    #Downloads a plain text feed of phishing URLs
    url = "https://openphish.com/feed.txt"
    response = requests.get(url, timeout=30)
    response.raise_for_status()
    urls = [line.strip() for line in response.text.splitlines() if line.strip().startswith("http")]
    print(f"  OpenPhish: {len(urls)} URLs")
    return urls

def fetch_from_phishtank():
    print("Fetching from PhishTank...")
    # PhishTank public CSV (no API key needed for this endpoint)
    url = "http://data.phishtank.com/data/online-valid.csv"
    response = requests.get(url, timeout=60, headers={"User-Agent": "phishtank/deepintel"})
    response.raise_for_status()
    reader = csv.DictReader(StringIO(response.text))
    urls = []
    for row in reader:
        u = row.get("url", "").strip()
        if u.startswith("http"):
            urls.append(u)
    print(f"  PhishTank: {len(urls)} URLs")
    return urls

def fetch_phishing_urls():
    all_urls = []

    try:
        all_urls += fetch_from_openphish()
    except Exception as e:
        print(f"  OpenPhish failed: {e}")

    try:
        all_urls += fetch_from_phishtank()
    except Exception as e:
        print(f"  PhishTank failed: {e}")

    # Deduplicate
    all_urls = list(dict.fromkeys(all_urls))
    all_urls = all_urls[:TARGET_COUNT]

    print(f"Total collected: {len(all_urls)} phishing URLs")

    df = pd.DataFrame({"url": all_urls, "label": "phishing", "source": "openphish+phishtank"})
    df.to_csv(OUTPUT_FILE, index=False)
    print(f"Saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    fetch_phishing_urls()