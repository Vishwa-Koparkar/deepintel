"""Build Python full-detector fixtures for the current test split and adversarial cases."""
import json
import os
from pathlib import Path
import runpy
import sys

ROOT = Path(__file__).resolve().parents[1]
OUT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
os.environ["DEEPINTEL_ALLOWLIST"] = "1"
os.environ["DEEPINTEL_FEEDBACK"] = "0"

import analyzer
import explainer
from safe_alternative import suggest
from threat_intel import load_blocklists

# Re-export the lookup snapshot in this process so its set-backed target order matches the fixtures.
runpy.run_path(str(OUT / "export-engine-data.py"))
load_blocklists()
analyzer.ml_drivers = lambda *_args, **_kwargs: []  # Full verdict parity does not depend on TreeSHAP.

base_urls = json.loads((OUT / "reference.json").read_text())["urls"]
lists = load_blocklists()
urlhaus = sorted(lists["urlhaus_domains"])
openphish = sorted(lists["openphish"])
fixtures = [
    "https://example.com", "https://example.com/", "https://example.com/?q=1",
    "https://rnicrosoft.com/account/verify", "https://google.coms/login",
    "https://login.paypal.evil.com/verify", "http://192.168.1.1/admin/login.php",
    "http://paypal-secure-login.xyz/verify/account", "https://www.google.com/",
]
if urlhaus:
    fixtures.extend([f"https://{urlhaus[0]}/", f"https://sub.{urlhaus[0]}/"])
if openphish:
    fixtures.append(f"https://{openphish[0]}/")
urls = list(dict.fromkeys(base_urls + fixtures))

# Reuse the analyzer result while building the Python explanation response to avoid a second model call.
analysis_cache = {}
for index, url in enumerate(urls, 1):
    analysis_cache[url] = analyzer.analyze(url, use_feedback=False)
    if index % 1000 == 0:
        print(f"Python reference: {index}/{len(urls)}")
explainer.analyze = lambda url, use_feedback=True: analysis_cache[url]

rows = []
for url in urls:
    result = explainer.explain(url, use_feedback=False)
    result["suggestion"] = suggest(url, result["risk_level"], result["prediction"])
    rows.append(result)

payload = {"schema": 1, "count": len(rows), "feedback": "disabled", "results": rows}
(OUT / "full-reference.json").write_text(json.dumps(payload, separators=(",", ":")))
print(f"Wrote {len(rows)} Python full-detector results to {OUT / 'full-reference.json'}")
