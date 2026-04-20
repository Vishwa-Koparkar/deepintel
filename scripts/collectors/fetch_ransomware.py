import requests
import pandas as pd

RANSOMWARE_FILE = "data/ransomware.csv"
TARGET = 3000

def fetch_feodotracker():
    """Feodo Tracker - tracks botnet C2 servers including ransomware loaders"""
    print("Fetching from Feodo Tracker...")
    url = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
    response = requests.get(url, timeout=30, headers={"User-Agent": "deepintel-research"})
    response.raise_for_status()
    lines = [l for l in response.text.splitlines() if not l.startswith("#") and l.strip()]
    # Format is IP-based, convert to URLs
    urls = []
    for line in lines:
        parts = line.split(",")
        if parts:
            ip = parts[0].strip().strip('"')
            if ip:
                urls.append(f"http://{ip}")
    print(f"  Feodo Tracker: {len(urls)} URLs")
    return urls

def fetch_urlhaus_ransomware_tags():
    """Pull full URLhaus dataset and grab any ransomware-tagged entries"""
    print("Fetching URLhaus full CSV for ransomware tags...")
    url = "https://urlhaus.abuse.ch/downloads/csv/"  # full archive, not just recent
    response = requests.get(url, timeout=120, headers={"User-Agent": "deepintel-research"})
    response.raise_for_status()

    import csv
    lines = response.text.splitlines()

    header_line = None
    data_lines = []
    for line in lines:
        stripped = line.lstrip("# ").strip()
        if header_line is None and "id" in stripped.lower() and "url" in stripped.lower() and "," in stripped:
            header_line = stripped
        elif header_line is not None and not line.startswith("#") and line.strip():
            data_lines.append(line)

    if not header_line:
        print("  Could not parse URLhaus full CSV")
        return []

    fieldnames = [f.strip().strip('"') for f in header_line.split(",")]
    reader = csv.DictReader(data_lines, fieldnames=fieldnames)

    ransomware_tags = {"ransomware", "cryptolocker", "locky", "ryuk", "revil",
                       "darkside", "conti", "emotet", "trickbot", "dridex", "maze"}
    urls = []
    for row in reader:
        u = (row.get("url") or "").strip().strip('"')
        tags = (row.get("tags") or "").lower().strip('"')
        if u.startswith("http") and any(t in tags for t in ransomware_tags):
            urls.append(u)

    print(f"  URLhaus full archive ransomware: {len(urls)} URLs")
    return urls

def fetch_ransomware_urls():
    all_urls = []

    try:
        all_urls += fetch_feodotracker()
    except Exception as e:
        print(f"  Feodo Tracker failed: {e}")

    try:
        all_urls += fetch_urlhaus_ransomware_tags()
    except Exception as e:
        print(f"  URLhaus full archive failed: {e}")

    # Deduplicate
    all_urls = list(dict.fromkeys(all_urls))
    print(f"\nTotal unique ransomware URLs collected: {len(all_urls)}")

    if len(all_urls) < TARGET:
        print(f"NOTE: Got {len(all_urls)} instead of {TARGET}.")
        print("This is acceptable — ransomware URLs are rare by nature.")
        print("We will oversample this class during training to compensate.")

    all_urls = all_urls[:TARGET]

    df = pd.DataFrame({"url": all_urls, "label": "ransomware", "source": "feodotracker+urlhaus"})
    df.drop_duplicates(subset="url", inplace=True)
    df.to_csv(RANSOMWARE_FILE, index=False)
    print(f"Saved {len(df)} ransomware URLs to {RANSOMWARE_FILE}")

if __name__ == "__main__":
    fetch_ransomware_urls()