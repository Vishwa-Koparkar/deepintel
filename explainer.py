"""
Layer 4: Explanation System
Maps ML predictions + heuristic rules + threat intel into human-readable reasons.
Prioritizes and returns top 3-5 most important reasons.
"""

from analyzer import analyze
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
    "phishing": (1, "High",   "Machine learning model detected phishing patterns"),
    "malware":  (1, "High",   "Machine learning model detected malware distribution patterns"),
    "benign":   (3, "None",   "Machine learning model considers this URL safe"),
}

TI_REASON = (1, "Critical", "Domain found in known threat intelligence blocklist")

MAX_REASONS = 5

def explain(url):
    result = analyze(url)

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

    # --- From ML prediction ---
    label = result["ml"]["label"]
    if label != "benign":
        conf = result["ml"]["confidence"]
        priority, impact, desc = ML_REASONS[label]
        reasons.append({
            "priority": priority,
            "impact":   impact,
            "reason":   f"{desc} (confidence: {conf*100:.0f}%)",
            "source":   "ml"
        })

    # --- From heuristic rules ---
    for rule_name, rule_desc in result["heuristic"]["triggered_rules"]:
        if rule_name in RULE_REASONS:
            priority, impact, human_desc = RULE_REASONS[rule_name]
            reasons.append({
                "priority": priority,
                "impact":   impact,
                "reason":   human_desc,
                "source":   "heuristic"
            })

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