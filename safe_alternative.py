"""
Layer 5: Safe Alternative Suggestion
If a URL is malicious, detect the brand/intent and suggest the real safe domain.
Only suggests when confidence is high.
"""

from urllib.parse import urlparse
import re

# Trusted domain map: brand keyword -> official safe URL
TRUSTED_DOMAINS = {
    "paypal":        "https://www.paypal.com",
    "apple":         "https://www.apple.com",
    "microsoft":     "https://www.microsoft.com",
    "amazon":        "https://www.amazon.com",
    "netflix":       "https://www.netflix.com",
    "ebay":          "https://www.ebay.com",
    "google":        "https://www.google.com",
    "facebook":      "https://www.facebook.com",
    "instagram":     "https://www.instagram.com",
    "twitter":       "https://www.twitter.com",
    "linkedin":      "https://www.linkedin.com",
    "dropbox":       "https://www.dropbox.com",
    "adobe":         "https://www.adobe.com",
    "chase":         "https://www.chase.com",
    "bankofamerica": "https://www.bankofamerica.com",
    "wellsfargo":    "https://www.wellsfargo.com",
    "dhl":           "https://www.dhl.com",
    "fedex":         "https://www.fedex.com",
    "ups":           "https://www.ups.com",
}

# Intent keywords -> safe alternative suggestion
INTENT_MAP = {
    "login":    "Please visit the official website directly and log in from there.",
    "signin":   "Please visit the official website directly and sign in from there.",
    "banking":  "Please visit your bank's official website directly.",
    "download": "Please download software only from the official vendor website.",
    "invoice":  "Please verify invoices directly on the sender's official website.",
    "verify":   "Please verify your account on the official website directly.",
    "confirm":  "Please confirm your details on the official website directly.",
}

def suggest(url, risk_level, prediction):
    """
    Returns a suggestion dict or None if no suggestion available.
    Only suggests for high/critical risk URLs.
    """
    if risk_level in ("safe", "low"):
        return None

    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower().split(":")[0]
        full   = url.lower()
        path   = parsed.path.lower()
        query  = parsed.query.lower()
    except:
        return None

    # Step 1: detect brand in domain or path
    detected_brand = None
    for brand in TRUSTED_DOMAINS:
        if brand in domain or brand in path:
            detected_brand = brand
            break

    # Step 2: if brand found, check it's not the real domain already
    if detected_brand:
        safe_url = TRUSTED_DOMAINS[detected_brand]
        real_domain = urlparse(safe_url).netloc.lower()
        if domain == real_domain or domain == f"www.{real_domain}":
            return None  # Already the real domain, no suggestion needed

        return {
            "type":       "brand",
            "brand":      detected_brand,
            "safe_url":   safe_url,
            "message":    f"This URL appears to impersonate {detected_brand.title()}. "
                          f"Visit the official website instead."
        }

    # Step 3: detect intent from URL if no brand found
    detected_intent = None
    for keyword, advice in INTENT_MAP.items():
        if keyword in full:
            detected_intent = (keyword, advice)
            break

    if detected_intent:
        keyword, advice = detected_intent
        return {
            "type":     "intent",
            "intent":   keyword,
            "safe_url": None,
            "message":  advice
        }

    return None


# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    from explainer import explain
    from threat_intel import load_blocklists

    load_blocklists()

    test_urls = [
        "https://www.google.com",
        "http://paypal-secure-login.xyz/verify/account",
        "http://192.168.1.1/admin/login.php",
        "http://amaz0n-update.tk/signin?user=confirm&password=reset",
        "http://fake-netflix-billing.top/update/payment",
    ]

    for url in test_urls:
        r = explain(url)
        suggestion = suggest(url, r["risk_level"], r["prediction"])

        print(f"\nURL        : {url}")
        print(f"Risk Level : {r['risk_level']}")
        if suggestion:
            print(f"Suggestion : {suggestion['message']}")
            if suggestion["safe_url"]:
                print(f"Safe URL   : {suggestion['safe_url']}")
        else:
            print(f"Suggestion : None")