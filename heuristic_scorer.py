"""
Layer 2: Heuristic Scoring Engine
Each rule triggers yes/no and contributes a weight to a final score (0-1).
"""

from urllib.parse import urlparse
import re
import math

# ---------------------------------------------------------------------------
# Rule definitions: (name, weight, description)
# Higher weight = more suspicious
# Total max possible = sum of all weights; score is normalized to 0-1
# ---------------------------------------------------------------------------
RULES = [
    ("is_ip_address",           0.15, "Domain is a raw IP address"),
    ("is_http_not_https",       0.08, "URL uses HTTP instead of HTTPS"),
    ("has_brand_impersonation", 0.15, "Domain mimics a known brand"),
    ("has_suspicious_keywords", 0.08, "URL contains phishing-related keywords"),
    ("has_at_symbol",           0.10, "URL contains @ symbol (redirects real domain)"),
    ("has_double_slash",        0.08, "Path contains // redirect pattern"),
    ("has_encoded_chars",       0.05, "URL contains encoded characters"),
    ("excessive_subdomains",    0.08, "Domain has 3+ subdomains"),
    ("long_url",                0.05, "URL is unusually long (>75 chars)"),
    ("high_domain_entropy",     0.08, "Domain name looks randomly generated"),
    ("suspicious_tld",          0.08, "TLD is commonly abused"),
    ("has_shortener",           0.08, "Uses a URL shortening service"),
]

MAX_SCORE = sum(w for _, w, _ in RULES)

BRANDS = {
    "paypal", "apple", "microsoft", "amazon", "netflix", "ebay", "google",
    "facebook", "instagram", "twitter", "linkedin", "dropbox", "adobe",
    "chase", "bankofamerica", "wellsfargo", "dhl", "fedex", "ups"
}

SUSPICIOUS_KEYWORDS = {
    "login", "signin", "verify", "secure", "account", "update", "confirm",
    "banking", "password", "credential", "suspend", "alert", "urgent",
    "free", "winner", "click", "download", "invoice", "paypal", "apple",
    "microsoft", "amazon", "netflix", "ebay", "support"
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "short.link", "rebrand.ly", "cutt.ly"
}

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".club", ".online", ".site", ".tk", ".ml", ".ga",
    ".cf", ".gq", ".pw", ".zip", ".review", ".country", ".stream",
    ".download", ".racing", ".win", ".bid"
}

def _brand_fold(s):
    """Fold look-alike characters so amaz0n / paypa1 / rnicrosoft still match their brand."""
    return s.replace("rn", "m").replace("vv", "w").translate(str.maketrans("0135$", "oless"))


def entropy(s):
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    total = len(s)
    return -sum((f/total) * math.log2(f/total) for f in freq.values())

def score_url(url):
    """
    Returns:
      heuristic_score  : float 0-1
      triggered_rules  : list of (rule_name, weight, description)
    """
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower().split(":")[0]
        path   = parsed.path.lower()
        full   = url.lower()
        parts  = domain.split(".")
        tld    = "." + parts[-1] if len(parts) > 1 else ""
    except Exception:
        return 1.0, [("parse_error", 1.0, "Could not parse URL")]

    triggered = []

    def check(rule_name, condition):
        for name, weight, desc in RULES:
            if name == rule_name and condition:
                triggered.append((name, weight, desc))

    check("is_ip_address",
          bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain)))

    check("is_http_not_https",
          parsed.scheme == "http")

    detected_brand = next((b for b in BRANDS if b in _brand_fold(domain)), None)
    if detected_brand:
        is_real = bool(re.search(rf"(^|\.){detected_brand}\.((com|org|net)|[a-z]{{2}}|(co|com|org|gov|ac)\.[a-z]{{2}})$", domain))
        check("has_brand_impersonation", not is_real)

    check("has_suspicious_keywords",
          any(kw in full for kw in SUSPICIOUS_KEYWORDS))

    check("has_at_symbol", "@" in url)

    check("has_double_slash", "//" in path)

    check("has_encoded_chars", "%" in url)

    check("excessive_subdomains", len(parts) - 2 >= 3)

    check("long_url", len(url) > 75)

    check("high_domain_entropy", entropy(domain) > 3.5)

    check("suspicious_tld", tld in SUSPICIOUS_TLDS)

    check("has_shortener", domain in SHORTENERS)

    raw_score = sum(w for _, w, _ in triggered)
    normalized = round(min(raw_score / MAX_SCORE, 1.0), 4)

    return normalized, triggered


def risk_level(score):
    if score < 0.20:
        return "safe"
    elif score < 0.40:
        return "low"
    elif score < 0.60:
        return "medium"
    elif score < 0.80:
        return "high"
    else:
        return "critical"


# ---------------------------------------------------------------------------
# Quick test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    test_urls = [
        "https://www.google.com",
        "http://paypal-secure-login.xyz/verify/account",
        "http://192.168.1.1/admin/login.php",
        "https://bit.ly/3xFakeUrl",
        "http://amaz0n-update.tk/signin?user=confirm&password=reset",
    ]

    print(f"{'URL':<55} {'Score':>6}  {'Risk':<10}  Triggered Rules")
    print("-" * 110)
    for url in test_urls:
        score, rules = score_url(url)
        level = risk_level(score)
        rule_names = ", ".join(r[0] for r in rules) if rules else "none"
        print(f"{url[:54]:<55} {score:>6.3f}  {level:<10}  {rule_names}")