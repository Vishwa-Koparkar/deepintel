"""Export the small runtime lookup snapshot; never copy the training CSVs to Pages."""
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
OUT = Path(__file__).resolve().parent / "engine-data.json"
sys.path.insert(0, str(ROOT))
os.environ.setdefault("DEEPINTEL_ALLOWLIST", "1")
os.environ["DEEPINTEL_FEEDBACK"] = "0"

import analyzer
from threat_intel import load_blocklists

clean, apex, threat = analyzer.load_trusted()
platforms = analyzer.load_platforms()
targets, folded = analyzer.load_lookalike_targets()
blocklists = load_blocklists()

payload = {
    "schema": 1,
    "trusted": {
        "clean": sorted(clean),
        "apex": sorted(apex),
        "threat": sorted(threat),
    },
    "platforms": platforms,
    # Keep the Python set iteration order so ambiguous one-edit matches use the same target order.
    "lookalikeTargets": list(targets),
    "foldedLookalikes": folded,
    "blocklists": {name: sorted(entries) for name, entries in blocklists.items()},
    "counts": {
        "trustedClean": len(clean),
        "trustedApex": len(apex),
        "threatDomains": len(threat),
        "lookalikeTargets": len(targets),
        "urlhausDomains": len(blocklists.get("urlhaus_domains", ())),
        "openphishDomains": len(blocklists.get("openphish", ())),
    },
}
OUT.write_text(json.dumps(payload, separators=(",", ":")) + "\n")
print(json.dumps(payload["counts"], indent=2))
