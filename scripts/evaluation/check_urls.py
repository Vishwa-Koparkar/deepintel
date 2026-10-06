"""
Score URLs with the full DeepIntel pipeline WITHOUT visiting them (only the URL text is analysed).

    python scripts/evaluation/check_urls.py urls.txt            # one URL per line
    python scripts/evaluation/check_urls.py --fetch openphish 50   # fresh phishing URLs from the live feed
    python scripts/evaluation/check_urls.py --fetch urlhaus 50     # fresh malware URLs from the live feed
    echo "http://rnicrosoft.com/" | python scripts/evaluation/check_urls.py -

Options: --with-feedback   also apply your personal corrections (off by default: tests the detection itself)
         --no-allowlist    disable the trusted-domain allowlist (tests the model on unknown sites)
"""
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

FEEDS = {"openphish": "https://openphish.com/feed.txt", "urlhaus": "https://urlhaus.abuse.ch/downloads/text_recent/"}


def main(argv):
    args = [a for a in argv if not a.startswith("--")]
    if "--no-allowlist" in argv:
        os.environ["DEEPINTEL_ALLOWLIST"] = "0"
    from analyzer import analyze, normalize_for_analysis     # imported after the env var is set
    from threat_intel import load_blocklists
    load_blocklists()

    if "--fetch" in argv:
        import requests
        name = argv[argv.index("--fetch") + 1]
        count = int(argv[argv.index("--fetch") + 2]) if len(argv) > argv.index("--fetch") + 2 and argv[argv.index("--fetch") + 2].isdigit() else 50
        text = requests.get(FEEDS[name], timeout=20, headers={"User-Agent": "Mozilla/5.0 (DeepIntel URL checker)"}).text
        urls = [l.strip() for l in text.splitlines() if l.strip() and not l.startswith("#")][:count]
        expected = "benign" if False else "threat"
    else:
        src = sys.stdin if (args and args[0] == "-") or not args else open(args[0])
        urls = [l.strip() for l in src if l.strip() and not l.startswith("#")]
        expected = None

    known = set()
    try:
        import pandas as pd
        known = set(pd.read_csv("data/dataset_clean.csv", usecols=["url"])["url"])
    except Exception:
        pass

    counts, rows = Counter(), []
    for u in urls:
        r = analyze(u if u.startswith(("http://", "https://")) else "https://" + u, use_feedback="--with-feedback" in argv)
        counts[r["prediction"]] += 1
        rows.append((r["prediction"], r["risk_level"], r["decided_by"], u in known or normalize_for_analysis(u) in known, u))
    for pred, risk, by, seen, u in rows:
        print(f"{pred:9} {risk:8} {by:9} {'(in training data) ' if seen else ''}{u[:90]}")
    print(f"\n{len(rows)} URLs: " + ", ".join(f"{k} {v}" for k, v in counts.most_common()))
    if expected == "threat" and rows:
        fresh = [r for r in rows if not r[3]]
        caught = sum(r[0] != "benign" for r in fresh)
        print(f"Of the {len(fresh)} not seen in training data, {caught} were flagged ({caught / max(len(fresh), 1):.0%}); these are the honest numbers.")


if __name__ == "__main__":
    main(sys.argv[1:])
