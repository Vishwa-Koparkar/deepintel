"""
Layer 3: Threat Intelligence Lookup
Checks URL against known malicious domain/IP blocklists.
"""

import re
from urllib.parse import urlparse
from pathlib import Path

BLOCKLIST_FILES = {
    "urlhaus_domains": "data/ti_urlhaus_domains.txt",
    "openphish":       "data/ti_openphish.txt",
}

_blocklists = None

def load_blocklists():
    global _blocklists
    if _blocklists is not None:
        return _blocklists

    _blocklists = {}

    # URLhaus hostfile format: "127.0.0.1 somedomain.com" or just "somedomain.com"
    name = "urlhaus_domains"
    try:
        domains = set()
        with open(BLOCKLIST_FILES[name]) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                # Handle "127.0.0.1 domain.com" format
                domain = parts[1] if len(parts) >= 2 else parts[0]
                domains.add(domain.lower())
        _blocklists[name] = domains
        print(f"Loaded {name}: {len(domains)} entries")
    except FileNotFoundError:
        print(f"Not found: {BLOCKLIST_FILES[name]}")
        print("  → Download https://urlhaus.abuse.ch/downloads/hostfile/ and save as data/ti_urlhaus_domains.txt")
        _blocklists[name] = set()

    # OpenPhish format: one full URL per line
    name = "openphish"
    try:
        domains = set()
        with open(BLOCKLIST_FILES[name]) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    # Could be a full URL or just a domain
                    if line.startswith("http"):
                        d = urlparse(line).netloc.lower().split(":")[0]
                    else:
                        d = line.lower()
                    if d:
                        domains.add(d)
                except:
                    pass
        _blocklists[name] = domains
        print(f"Loaded {name}: {len(domains)} entries")
    except FileNotFoundError:
        print(f"Not found: {BLOCKLIST_FILES[name]}")
        print("  → Download https://openphish.com/feed.txt and save as data/ti_openphish.txt")
        _blocklists[name] = set()

    return _blocklists


def lookup(url):
    """
    Returns:
      threat_score : float 0-1
      threat_flag  : bool
      matched_lists: list of blocklist names that matched
    """
    try:
        domain = urlparse(url).netloc.lower().split(":")[0]
    except:
        return 1.0, True, ["parse_error"]

    lists = load_blocklists()
    matched = []

    for name, entries in lists.items():
        if domain in entries:
            matched.append(name)
            continue
        # Check if domain is a subdomain of a blocked domain
        parts = domain.split(".")
        for i in range(1, len(parts)):
            parent = ".".join(parts[i:])
            if parent in entries:
                matched.append(f"{name}(subdomain)")
                break

    if not matched:
        return 0.0, False, []

    score = min(0.5 + (len(matched) - 1) * 0.25, 1.0)
    return round(score, 4), True, matched


if __name__ == "__main__":
    print("Loading blocklists...")
    load_blocklists()

    test_urls = [
        "https://www.google.com",
        "https://www.amazon.com",
        "http://paypal-secure-login.xyz/verify/account",
        "http://192.168.1.1/admin",
    ]

    print(f"\n{'URL':<55} {'Score':>6}  {'Flag':<6}  Matched Lists")
    print("-" * 100)
    for url in test_urls:
        score, flag, matched = lookup(url)
        print(f"{url[:54]:<55} {score:>6.3f}  {str(flag):<6}  {matched or 'none'}")