"""
Lookalike / typosquat detection.

A URL-string ML model sees "rnicrosoft.com" or "google.coms" as an ordinary short
bare domain. This compares a registered domain to well-known targets using
(1) visually confusable character folding (rn->m, vv->w, 0->o, 1/i->l ...) and
(2) edit distance <= 1 on the full registered domain (typos, extra/missing/swapped
letters, TLD typos like .coms).
"""

import re

MIN_LEN = 7   # shortest registered domain (incl. TLD) we edit-distance match; avoids noise on tiny names

_CONFUSABLE_SEQS = [("rn", "m"), ("vv", "w"), ("cl", "d")]
_CONFUSABLE_CHARS = str.maketrans({"0": "o", "1": "l", "i": "l", "3": "e", "5": "s", "$": "s", "|": "l"})

# Extra high-profile targets that may not be in the dataset's top ranks
EXTRA_TARGETS = {
    "paypal.com", "apple.com", "microsoft.com", "amazon.com", "netflix.com", "ebay.com",
    "google.com", "facebook.com", "instagram.com", "twitter.com", "linkedin.com",
    "dropbox.com", "adobe.com", "chase.com", "bankofamerica.com", "wellsfargo.com",
    "dhl.com", "fedex.com", "ups.com", "youtube.com", "whatsapp.com", "gmail.com",
    "outlook.com", "office.com", "live.com", "icloud.com", "github.com", "openai.com",
    "anthropic.com", "claude.ai", "spotify.com", "telegram.org", "binance.com",
    "coinbase.com", "steampowered.com", "roblox.com", "discord.com", "zoom.us",
}


def fold(s):
    s = s.lower()
    for a, b in _CONFUSABLE_SEQS:
        s = s.replace(a, b)
    return s.translate(_CONFUSABLE_CHARS)


def _edit_distance_le1(a, b):
    """True if Damerau-Levenshtein distance(a, b) <= 1 (and a != b)."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        diff = [i for i in range(len(a)) if a[i] != b[i]]
        if len(diff) == 1:
            return True
        return len(diff) == 2 and diff[1] == diff[0] + 1 and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]]
    if len(a) > len(b):
        a, b = b, a
    i = 0
    while i < len(a) and a[i] == b[i]:
        i += 1
    return a[i:] == b[i + 1:]


def _split(domain):
    """'google.com.ph' -> ('google', 'com.ph')"""
    sld, _, tld = domain.partition(".")
    return sld, tld


def _is_country_tld(tld):
    parts = tld.split(".")
    return bool(parts) and len(parts[-1]) == 2 and parts[-1].isalpha()


def build_targets(ranked_domains, top_n=300):
    """
    Curated impersonation targets: the top_n ranked domains plus EXTRA_TARGETS, collapsed to one
    domain per name (google.com, not google.co.ke) so legitimate regional sites aren't flagged.
    Returns (targets, folded_targets).
    """
    by_name = {}
    for d in list(ranked_domains)[:top_n] + sorted(EXTRA_TARGETS):
        sld, tld = _split(d)
        cur = by_name.get(sld)
        if cur is None or (tld == "com" and _split(cur)[1] != "com"):
            by_name[sld] = d
    targets = set(by_name.values())
    folded = {}
    for t in sorted(targets):
        folded.setdefault(fold(t), t)
    return targets, folded


def find_lookalike(registered_domain, targets, folded_targets):
    """
    registered_domain: e.g. 'rnicrosoft.com'. Returns (target, kind) or None.
    kind = 'confusable' (visually identical after folding) or 'typo' (edit distance 1).
    """
    d = registered_domain.lower()
    if d in targets:
        return None
    sld, tld = _split(d)

    hit = folded_targets.get(fold(d))
    if hit and hit != d:
        return hit, "confusable"

    for t in targets:
        t_sld, t_tld = _split(t)
        if sld == t_sld:
            # Same brand name on a different TLD: google.hu is legit, google.coms / google.xyz are not
            if tld != t_tld and not _is_country_tld(tld):
                return t, "typo"
            continue
        if len(sld) >= 6 and len(t_sld) >= 6 and _edit_distance_le1(sld, t_sld) and (tld == t_tld or not _is_country_tld(tld)):
            return t, "typo"
    return None


_SEQ_NAMES = {"rn": "m", "vv": "w", "cl": "d"}
_CHAR_NAMES = {"0": "o", "1": "l", "i": "l", "3": "e", "5": "s", "$": "s", "|": "l"}


def describe(domain, target, kind):
    """One plain-English sentence on HOW `domain` imitates `target` (used in explanations)."""
    d_sld, d_tld = _split(domain.lower())
    t_sld, t_tld = _split(target.lower())
    if kind == "confusable":
        subs = [f"'{a}' looks like '{b}'" for a, b in list(_SEQ_NAMES.items()) + list(_CHAR_NAMES.items())
                if a in d_sld and a not in t_sld and b in t_sld]
        how = "; ".join(dict.fromkeys(subs)) or "it reads the same as the real name once look-alike characters are swapped"
        return f"{domain} imitates {target}: {how}"
    if kind == "subdomain":
        return f"'{t_sld}' appears in the subdomain of {domain}, which is not {target}"
    if d_sld == t_sld:
        return f"{domain} is {target} with a different ending (.{d_tld} instead of .{t_tld})"
    return f"{domain} is one character away from {target} (a missing, extra, swapped or wrong letter)"
