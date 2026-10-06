"""
Benign URL augmentation.

The Majestic Million feed only gives bare domains (https://example.com), while
real browsing traffic looks like https://www.example.com/some/page?id=1. Trained
on bare domains only, the model learned "has a path / www / subdomain => not
benign", which flags YouTube, Google, Wikipedia etc. as phishing.

This turns each benign domain into ONE realistic variant (www., subdomains,
paths, query strings, occasional http) so the model has to learn from real
signals instead of URL shape. Deterministic per-URL, so reruns are stable.
"""

import hashlib
import random
from urllib.parse import urlparse

SUBDOMAINS = ["en", "docs", "mail", "blog", "support", "accounts", "app", "m",
              "login", "shop", "help", "api", "cdn", "news", "store", "learn"]

WORDS = ["about", "contact", "pricing", "products", "features", "careers",
         "team", "press", "events", "guide", "overview", "getting-started",
         "release-notes", "terms", "privacy", "faq", "community", "pricing-plans",
         "how-to-choose-a-laptop", "best-practices", "annual-report-2023",
         "top-10-tips", "summer-sale", "new-arrivals", "case-studies"]

# Legit sites use "login", "account", "download", "support", "update"... in
# paths all the time; the model must not treat those keywords as proof of phishing.
KEYWORD_PATHS = ["/login", "/signin", "/account", "/account/settings", "/support",
                 "/download", "/downloads", "/download.html", "/update", "/verify-email",
                 "/help/account", "/secure/checkout", "/billing/invoice", "/free-trial"]


def _token(rng, n, alphabet="abcdefghijklmnopqrstuvwxyz0123456789"):
    return "".join(rng.choice(alphabet) for _ in range(n))


def _path(rng):
    w = lambda: rng.choice(WORDS)
    kind = rng.randrange(14)
    if kind == 0:  return "/" + w()
    if kind == 1:  return f"/{w()}/{w()}"
    if kind == 2:  return f"/{w()}.html"
    if kind == 3:  return rng.choice(KEYWORD_PATHS)
    if kind == 4:  return f"/products/{rng.randrange(1, 99999)}"
    if kind == 5:  return f"/blog/{rng.randrange(2015, 2025)}/{rng.randrange(1, 13):02d}/{w()}"
    if kind == 6:  return f"/wiki/{w().title()}_{w().title()}"
    if kind == 7:  return f"/watch?v={_token(rng, 11, 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-')}"
    if kind == 8:  return f"/search?q={w()}+{w()}&page={rng.randrange(1, 20)}"
    if kind == 9:  return f"/en/{w()}/"
    if kind == 10: return f"/user/{w()}{rng.randrange(1, 9999)}/posts/{rng.randrange(100000, 9999999)}"
    if kind == 11: return f"/docs/{w()}/{w()}#section-{rng.randrange(1, 9)}"
    if kind == 12: return f"/oauth/authorize?client_id={_token(rng, 16)}&redirect_uri=https%3A%2F%2F{_token(rng, 6)}.com%2Fcb&state={_token(rng, 12)}"
    return f"/{w()}/{_token(rng, rng.randrange(6, 24))}?utm_source={w()}&utm_medium=email&ref={rng.randrange(1, 999)}"


def augment_url(bare_url, variant=0):
    """bare_url like https://example.com -> one realistic variant (deterministic per url+variant)."""
    rng = random.Random(int(hashlib.md5(f"{bare_url}#{variant}".encode()).hexdigest(), 16))
    host = urlparse(bare_url).netloc.lower()
    scheme = "https" if rng.random() < 0.92 else "http"

    r = rng.random()
    if r < 0.20:                       # keep some bare domains (still valid input)
        return f"{scheme}://{host}"
    if r < 0.40:                       # www home page. No trailing slash: the dataset (and analyzer) strip a bare
        return f"{scheme}://www.{host}"  # host's "/", and a slash that only benign rows have becomes a learnable shortcut

    prefix = "www." if rng.random() < 0.55 else (rng.choice(SUBDOMAINS) + "." if rng.random() < 0.6 else "")
    return f"{scheme}://{prefix}{host}{_path(rng)}"


def augment_benign(df, url_col="url", label_col="label", variants=2):
    """Return df with each benign URL replaced by `variants` realistic variants (other classes untouched)."""
    import pandas as pd
    benign = df[df[label_col] == "benign"]
    others = df[df[label_col] != "benign"]
    parts = []
    for v in range(variants):
        b = benign.copy()
        b[url_col] = b[url_col].map(lambda u: augment_url(u, v))
        parts.append(b)
    out = pd.concat([others] + parts, ignore_index=True).drop_duplicates(subset=url_col)
    return out
