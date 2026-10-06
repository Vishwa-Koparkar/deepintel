"""
Layer 4: Explanation System
Maps ML predictions + heuristic rules + threat intel into human-readable reasons.
Prioritizes and returns top 3-5 most important reasons.
"""

import re
from urllib.parse import urlparse

from analyzer import BRANDS, SUSPICIOUS_KEYWORDS, _brand_fold, analyze, base_domain, entropy, load_platforms
from threat_intel import load_blocklists

# ---------------------------------------------------------------------------
# Human-readable reason map
# Priority: 1=highest (shown first), 3=lowest
# ---------------------------------------------------------------------------
RULE_REASONS = {
    # Priority 1 — high risk signals
    "has_brand_impersonation": (1, "High",   "Domain impersonates a known brand"),
    "is_ip_address":           (1, "High",   "Domain is a raw IP address, not a real website name"),
    "has_at_symbol":           (1, "High",   "URL contains @ symbol which can redirect to a different site"),
    "has_double_slash":        (1, "High",   "URL contains // redirect pattern in the path"),
    "has_shortener":           (1, "Medium", "URL uses a shortener service hiding the real destination"),

    # Priority 2 — structural risks
    "high_domain_entropy":     (2, "Medium", "Domain name appears randomly generated"),
    "excessive_subdomains":    (2, "Medium", "Unusually high number of subdomains"),
    "suspicious_tld":          (2, "Medium", "Domain uses a TLD commonly associated with malicious sites"),
    "long_url":                (2, "Low",    "URL is abnormally long"),
    "has_suspicious_keywords": (2, "High",   "URL contains keywords commonly used in phishing attacks"),

    # Priority 3 — security issues
    "is_http_not_https":       (3, "Medium", "Website does not use secure HTTPS connection"),
    "has_encoded_chars":       (3, "Low",    "URL contains encoded characters used to obfuscate content"),
}

ML_REASONS = {
    "phishing": (3, "Medium", "The overall shape of this URL closely matches known phishing sites"),
    "malware":  (3, "Medium", "The overall shape of this URL closely matches known malware download links"),
    "benign":   (3, "None",   "No suspicious signals found in the URL"),
}

TI_REASON = (1, "Critical", "Domain found in known threat intelligence blocklist")

MAX_REASONS = 5


def _host(url):
    return urlparse(url).netloc.lower().split(":")[0]


def specific_reason(rule_name, url):
    """Turn a fired heuristic rule into a sentence that names the actual evidence in THIS url."""
    host, full = _host(url), url.lower()
    if rule_name == "has_suspicious_keywords":
        words = [k for k in sorted(SUSPICIOUS_KEYWORDS - BRANDS) if k in full]
        if words:
            return "URL contains words used to bait victims: " + ", ".join(words[:4])
    elif rule_name == "suspicious_tld":
        return f"Uses the .{host.rsplit('.', 1)[-1]} ending, which is heavily abused for phishing and malware"
    elif rule_name == "high_domain_entropy":
        # The rule measures character variety over the whole domain string, which also fires on readable
        # hyphenated names (paypal-secure-login). Only claim "random" for a name that really looks random.
        base = base_domain(host)
        skip = {base.split(".")[0]} if base in load_platforms() else set()     # the platform's own name (duckdns)
        for label in (l for l in host.split(".")[:-1] if l not in skip and len(l) >= 6):
            letters = [c for c in label if c.isalpha()]
            digits = sum(c.isdigit() for c in label)
            vowel_ratio = sum(c in "aeiou" for c in letters) / max(len(letters), 1)
            if (digits >= 2 and len(letters) >= 3) or (letters and vowel_ratio < 0.3 and "-" not in label):
                return f"The name \"{label}\" looks randomly generated"
        return False   # the rule fired, but there is no honest specific claim to make: leave it out
    elif rule_name == "has_brand_impersonation":
        brand = next((b for b in sorted(BRANDS) if b in _brand_fold(host)), None)
        if brand:
            return f"Uses the brand name \"{brand}\" but is not {brand}'s real website"
    elif rule_name == "excessive_subdomains":
        return f"{len(host.split('.')) - 2} subdomains are stacked in front of the real domain, which can hide where the link goes"
    elif rule_name == "long_url":
        return f"The URL is unusually long ({len(url)} characters), which can bury the real domain"
    elif rule_name == "is_http_not_https":
        return "The address starts with http://, so the connection is not encrypted"
    return None


def extra_facts(url):
    """URL properties worth explaining that no heuristic rule covers. Returns [(priority, impact, text)]."""
    host = _host(url)
    base = base_domain(host)
    out = []
    platforms = load_platforms()
    if base in platforms and host not in (base, "www." + base):
        out.append((2, "Medium", f"Hosted on {base}, a free hosting service where {platforms[base]} phishing or malware sites were found in our data"))
    hyphens = host.count("-")
    if hyphens >= 2:
        out.append((2, "Medium", f"The domain has {hyphens} hyphens, a common trick to imitate a brand name"))
    digits = sum(c.isdigit() for c in host)
    if host and digits / len(host) >= 0.25 and not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        out.append((2, "Medium", "The domain is full of digits, typical of auto-generated names"))
    return out


def explain(url, use_feedback=True):
    result = analyze(url, use_feedback=use_feedback)

    reasons = []

    # --- From threat intel (highest priority if flagged) ---
    if result["threat_intel"]["flag"]:
        lists = ", ".join(result["threat_intel"]["matched_lists"])
        priority, impact, desc = TI_REASON
        reasons.append({
            "priority": priority,
            "impact":   impact,
            "reason":   f"{desc} ({lists})",
            "source":   "threat_intel"
        })

    # --- User feedback ---
    fb = result.get("feedback")
    if fb:
        where = {"url": "this exact URL", "host": "this site", "domain": "this domain"}[fb["scope"]]
        reasons.append({
            "priority": 0,
            "impact":   "None" if fb["correct_label"] == "benign" else "Critical",
            "reason":   f"You marked {where} as {'safe' if fb['correct_label'] == 'benign' else fb['correct_label']}",
            "source":   "feedback"
        })
    if result.get("feedback_conflict"):
        reasons.append({
            "priority": 0,
            "impact":   "Critical",
            "reason":   "You marked this as safe, but it is on a threat blocklist, so the blocklist verdict was kept",
            "source":   "threat_intel"
        })

    # --- Lookalike / typosquat / brand in subdomain ---
    if result.get("lookalike"):
        la = result["lookalike"]
        reasons.append({
            "priority": 1,
            "impact":   "Critical" if la["kind"] == "confusable" else "High",
            "reason":   la["detail"],
            "source":   "lookalike"
        })

    # --- Trusted domain ---
    if result.get("trusted_domain"):
        reasons.append({
            "priority": 3,
            "impact":   "None",
            "reason":   "Domain is a well-known, highly ranked website with no threat history",
            "source":   "allowlist"
        })

    # --- From ML prediction ---
    label = result["ml"]["label"]
    # For a lookalike domain the ML label is "benign" (it looks like an ordinary short domain); skip that misleading line
    if label != "benign" and not result.get("trusted_domain"):
        priority, impact, desc = ML_REASONS[label]
        reasons.append({
            "priority": priority,
            "impact":   impact,
            "reason":   desc,
            "source":   "ml"
        })

    # --- From heuristic rules ---
    for rule_name, rule_desc in result["heuristic"]["triggered_rules"]:
        if rule_name in RULE_REASONS:
            priority, impact, human_desc = RULE_REASONS[rule_name]
            text = specific_reason(rule_name, result["url"])
            if text is False:
                continue
            reasons.append({
                "priority": priority,
                "impact":   impact,
                "reason":   text or human_desc,
                "source":   "heuristic"
            })

    # --- Extra evidence from the URL itself (only worth listing for a threat verdict) ---
    if result["prediction"] != "benign":
        for priority, impact, text in extra_facts(result["url"]):
            reasons.append({"priority": priority, "impact": impact, "reason": text, "source": "heuristic"})

    # A benign verdict shouldn't list risk signals as reasons; keep only the trust/lookalike-free explanation
    if result["prediction"] == "benign":
        reasons = [r for r in reasons if r["source"] in ("allowlist", "ml", "feedback")]
        if not reasons:
            reasons.append({"priority": 3, "impact": "None",
                            "reason": "No suspicious signals found in the URL", "source": "ml"})

    # Sort by priority then impact
    impact_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "None": 4}
    reasons.sort(key=lambda x: (x["priority"], impact_order.get(x["impact"], 5)))

    # Deduplicate
    seen = set()
    unique_reasons = []
    for r in reasons:
        if r["reason"] not in seen:
            seen.add(r["reason"])
            unique_reasons.append(r)

    top_reasons = unique_reasons[:MAX_REASONS]

    return {
        "url":         result["url"],
        "prediction":  result["prediction"],
        "risk_level":  result["risk_level"],
        "score":       result["score"],
        "reasons":     top_reasons,
        "confidence":  result["confidence"],
        "drivers":     result["ml"]["drivers"],
        "decided_by":  result["decided_by"],
        "trace":       result["trace"],
        "feedback":    result.get("feedback"),
        "layers": {
            "ml":           result["ml"]["score"],
            "heuristic":    result["heuristic"]["score"],
            "threat_intel": result["threat_intel"]["score"],
            "lookalike":    result["lookalike_score"],
            "trusted":      bool(result.get("trusted_domain")),
            "feedback":     result["feedback"]["correct_label"] if result.get("feedback") else None,
        },
        "ml_probs":    result["ml"]["probabilities"],
    }


# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    load_blocklists()

    test_urls = [
        "https://www.google.com",
        "http://paypal-secure-login.xyz/verify/account",
        "http://192.168.1.1/admin/login.php",
        "http://amaz0n-update.tk/signin?user=confirm&password=reset",
    ]

    for url in test_urls:
        r = explain(url)
        print(f"\n{'='*60}")
        print(f"URL        : {r['url']}")
        print(f"Prediction : {r['prediction']}")
        print(f"Risk Level : {r['risk_level']}")
        print(f"Score      : {r['score']}")
        if r["reasons"]:
            print(f"Reasons:")
            for i, reason in enumerate(r["reasons"], 1):
                print(f"  {i}. [{reason['impact']:8}] {reason['reason']}")
        else:
            print("Reasons    : No suspicious signals detected")