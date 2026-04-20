import requests
import pandas as pd
from tqdm import tqdm
import time

OUTPUT_FILE = "data/benign.csv"
TARGET_COUNT = 5000

def fetch_benign_urls():
    print("Fetching Majestic Million top domains...")

    url = "https://downloads.majestic.com/majestic_million.csv"
    response = requests.get(url, stream=True, timeout=60)
    response.raise_for_status()

    lines = []
    for chunk in response.iter_lines():
        if chunk:
            lines.append(chunk.decode("utf-8"))
        if len(lines) > TARGET_COUNT + 10:
            break

    # Parse CSV manually (first line is header)
    from io import StringIO
    import csv

    reader = csv.DictReader(lines)
    urls = []
    for row in reader:
        domain = row.get("Domain", "").strip().lower()
        if domain:
            url_entry = f"https://{domain}"
            urls.append(url_entry)
        if len(urls) >= TARGET_COUNT:
            break

    print(f"Collected {len(urls)} benign URLs")

    df = pd.DataFrame({"url": urls, "label": "benign", "source": "majestic_million"})
    df.drop_duplicates(subset="url", inplace=True)
    df.to_csv(OUTPUT_FILE, index=False)
    print(f"Saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    fetch_benign_urls()