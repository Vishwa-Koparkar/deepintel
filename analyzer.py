import os
import joblib
import pandas as pd
from urllib.parse import urlparse
import re
import math

from heuristic_scorer import score_url, risk_level
from threat_intel import lookup, load_blocklists
from lookalike import build_targets, find_lookalike, describe as describe_lookalike

_model = None
_encoder = None
_trusted = None
_lookalike = None
_platforms = None
_model_stamp = None
_dataset_stamp = None

DATASET_PATH = "data/dataset_clean.csv"
# Evaluation runs set DEEPINTEL_ALLOWLIST=0 / DEEPINTEL_FEEDBACK=0 to measure the raw ML + heuristic + threat-intel + lookalike layers
USE_ALLOWLIST = os.environ.get("DEEPINTEL_ALLOWLIST", "1") != "0"
USE_FEEDBACK  = os.environ.get("DEEPINTEL_FEEDBACK", "1") != "0"
MODEL_PATH = "models/best_model.pkl"
FUSED_OVERRIDE = 0.30    # ML said "benign" but fused risk is at least this -> reclassify as the likelier threat class
TRUSTED_SCORE_CAP = 0.10
LOOKALIKE_SCORE = {"confusable": 0.80, "typo": 0.65, "subdomain": 0.65}   # fused-score floor when a domain imitates a top site

_TWO_LEVEL_SLDS = {"co","com","org","net","gov","edu","ac","go","or","ne"}

def base_domain(host):
    parts = host.lower().split(":")[0].split(".")
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in _TWO_LEVEL_SLDS:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host

def _stamp(path):
    try:
        return os.path.getmtime(path)
    except OSError:
        return None

def _refresh_dataset_caches():
    """auto_update.py appends to the dataset while the API is running; drop the derived caches when it changes."""
    global _trusted, _lookalike, _platforms, _dataset_stamp
    stamp = _stamp(DATASET_PATH)
    if stamp != _dataset_stamp:
        _trusted = None
        _lookalike = None
        _platforms = None
        _dataset_stamp = stamp

def load_trusted():
    """
    Returns (clean_bases, apex_hosts, threat_bases).
    clean_bases: registered domains from the benign (Majestic) set that never show
        up in the phishing/malware data -> every subdomain is trusted.
    apex_hosts: for benign domains that DO show up in threat data (user-content
        hosts like google.com, github.io, webflow.io), only the bare and www host
        are trusted; other subdomains/paths still get scored on their URLs.
    threat_bases: every registered domain that appears in the threat data (shared platforms included).
    """
    global _trusted
    _refresh_dataset_caches()
    if _trusted is None:
        try:
            df = pd.read_csv(DATASET_PATH, usecols=["url", "label"])
            bases = df["url"].map(lambda u: base_domain(urlparse(u).netloc))
            benign = set(bases[df["label"] == "benign"])
            threat = set(bases[df["label"] != "benign"])
            apex = set()
            for b in benign & threat:
                apex.update((b, "www." + b))
            _trusted = (benign - threat, apex, threat)
        except Exception:
            _trusted = (set(), set(), set())
    return _trusted

PLATFORM_MIN_HOSTS = 20   # distinct phishing/malware hosts before a hosting service counts as "frequently abused"

def load_platforms():
    """{base domain: number of distinct phishing/malware sites hosted on it} for free-hosting / dynamic-DNS services."""
    global _platforms
    _refresh_dataset_caches()
    if _platforms is None:
        try:
            df = pd.read_csv(DATASET_PATH, usecols=["url", "label"])
            df = df[df["label"] != "benign"]
            hosts = df["url"].map(lambda u: urlparse(u).netloc.lower().split(":")[0])
            tenant = hosts[hosts != hosts.map(base_domain)]
            tenant = tenant[tenant != "www." + tenant.map(base_domain)]
            counts = tenant.groupby(tenant.map(base_domain)).nunique()
            _platforms = {b: int(n) for b, n in counts.items() if n >= PLATFORM_MIN_HOSTS}
        except Exception:
            _platforms = {}
    return _platforms

def load_lookalike_targets():
    """Top-ranked benign domains (dataset order == Majestic rank) + curated brands."""
    global _lookalike
    _refresh_dataset_caches()
    if _lookalike is None:
        try:
            df = pd.read_csv(DATASET_PATH, usecols=["url", "label"])
            ranked = df.loc[df["label"] == "benign", "url"].map(lambda u: base_domain(urlparse(u).netloc))
            _lookalike = build_targets(dict.fromkeys(ranked), top_n=300)
        except Exception:
            _lookalike = build_targets([], top_n=0)
    return _lookalike

def is_trusted_host(host):
    clean, apex, _ = load_trusted()
    return base_domain(host) in clean or host in apex

def has_threat_history(host):
    return base_domain(host) in load_trusted()[2]

def load_model():
    """Loads the model, and reloads it when a retrain replaces the file while the API is running."""
    global _model, _encoder, _model_stamp
    stamp = _stamp(MODEL_PATH)
    if _model is None or stamp != _model_stamp:
        _model   = joblib.load(MODEL_PATH)
        _encoder = joblib.load("models/label_encoder.pkl")
        _model_stamp = stamp

FEATURE_COLS = [
    "url_length","path_length","num_subdomains","num_digits",
    "num_hyphens_domain","is_https","is_domain_ip","has_shortener",
    "has_suspicious_keywords","is_brand_impersonation","has_at_symbol",
    "has_double_slash","has_encoded_chars","num_query_params",
    "domain_entropy","tld_category",
    "is_safe_country_tld","domain_word_len","has_safe_extension","digit_ratio"
]

BRANDS = {"paypal","apple","microsoft","amazon","netflix","ebay","google","facebook","instagram","twitter","linkedin","dropbox","adobe","chase","bankofamerica","wellsfargo","dhl","fedex","ups"}
SUSPICIOUS_KEYWORDS = {"login","signin","verify","secure","account","update","confirm","banking","password","credential","suspend","alert","urgent","free","winner","click","download","invoice","paypal","apple","microsoft","amazon","netflix","ebay","support"}
SHORTENERS = {"bit.ly","tinyurl.com","goo.gl","t.co","ow.ly","is.gd","buff.ly","adf.ly","short.link","rebrand.ly","cutt.ly"}
SUSPICIOUS_TLDS = {".xyz",".top",".club",".online",".site",".tk",".ml",".ga",".cf",".gq",".pw",".zip",".review",".country",".stream",".download",".racing",".win",".bid"}
SAFE_TLDS = {".com",".org",".edu",".gov",".net",".io",".co"}
SAFE_COUNTRY_TLDS = {".co.uk",".gov.uk",".ac.uk",".org.uk",".com.au",".gov.au",".edu.au",".co.jp",".go.jp",".com.br",".gov.br",".co.in",".gov.in",".ac.in",".fr",".de",".it",".es",".nl",".se",".no",".dk",".fi",".ca",".mx",".ar",".cl",".gov",".mil",".edu"}
SAFE_EXTENSIONS = {".html",".htm",".php",".asp",".aspx",".jsp",".pdf",".png",".jpg",".gif",".css",".js"}

def _brand_fold(s):
    """Fold look-alike characters so amaz0n / paypa1 / rnicrosoft still match their brand."""
    return s.replace("rn", "m").replace("vv", "w").translate(str.maketrans("0135$", "oless"))


def entropy(s):
    if not s: return 0.0
    freq = {}
    for c in s: freq[c] = freq.get(c,0)+1
    t = len(s)
    return -sum((f/t)*math.log2(f/t) for f in freq.values())

def extract_features(url):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower().split(":")[0]
        path   = parsed.path.lower()
        query  = parsed.query.lower()
        full   = url.lower()
        parts  = domain.split(".")
        tld    = "."+parts[-1] if len(parts)>1 else ""
        tld2   = "."+".".join(parts[-2:]) if len(parts)>2 else tld
        detected_brand = next((b for b in BRANDS if b in _brand_fold(domain)), None)
        is_imp = 0
        if detected_brand:
            is_real = bool(re.search(rf"(^|\.){detected_brand}\.((com|org|net)|[a-z]{{2}}|(co|com|org|gov|ac)\.[a-z]{{2}})$", domain))
            is_imp = int(not is_real)
        is_safe_country_tld = int(tld2 in SAFE_COUNTRY_TLDS or tld in SAFE_COUNTRY_TLDS)
        domain_clean = re.sub(r'\.(com|org|net|edu|gov|co|uk|jp|fr|de|au|br|in|ca|mx)$','',domain)
        domain_clean = re.sub(r'\W','',domain_clean)
        ext = "."+path.split(".")[-1] if "." in path else ""
        digit_ratio = round(sum(c.isdigit() for c in domain)/max(len(domain),1),4)
        return {
            "url_length":              len(url),
            "path_length":             len(path),
            "num_subdomains":          max(0,len(parts)-2),
            "num_digits":              sum(c.isdigit() for c in full),
            "num_hyphens_domain":      domain.count("-"),
            "is_https":                int(parsed.scheme=="https"),
            "is_domain_ip":            int(bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",domain))),
            "has_shortener":           int(domain in SHORTENERS),
            "has_suspicious_keywords": int(any(kw in full for kw in SUSPICIOUS_KEYWORDS)),
            "is_brand_impersonation":  is_imp,
            "has_at_symbol":           int("@" in url),
            "has_double_slash":        int("//" in path),
            "has_encoded_chars":       int("%" in url),
            "num_query_params":        len(query.split("&")) if query else 0,
            "domain_entropy":          round(entropy(domain),4),
            "tld_category":            0 if tld in SAFE_TLDS else (2 if tld in SUSPICIOUS_TLDS else 1),
            "is_safe_country_tld":     is_safe_country_tld,
            "domain_word_len":         len(domain_clean),
            "has_safe_extension":      int(ext in SAFE_EXTENSIONS),
            "digit_ratio":             digit_ratio,
        }
    except:
        return {col:0 for col in FEATURE_COLS}

FEATURE_LABELS = {
    "url_length": "URL length", "path_length": "Path length", "num_subdomains": "Number of subdomains",
    "num_digits": "Digits in URL", "num_hyphens_domain": "Hyphens in domain", "is_https": "Uses HTTPS",
    "is_domain_ip": "Domain is a raw IP", "has_shortener": "URL shortener", "has_suspicious_keywords": "Phishing keywords",
    "is_brand_impersonation": "Brand impersonation", "has_at_symbol": "@ symbol in URL", "has_double_slash": "// in path",
    "has_encoded_chars": "Encoded characters", "num_query_params": "Query parameters", "domain_entropy": "Domain randomness (entropy)",
    "tld_category": "TLD risk", "is_safe_country_tld": "Trusted country TLD", "domain_word_len": "Domain name length",
    "has_safe_extension": "Common file extension", "digit_ratio": "Digit ratio in domain",
}
BINARY_FEATURES = {"is_https", "is_domain_ip", "has_shortener", "has_suspicious_keywords", "is_brand_impersonation",
                   "has_at_symbol", "has_double_slash", "has_encoded_chars", "is_safe_country_tld", "has_safe_extension"}
TLD_TEXT = {0: "common (.com, .org...)", 1: "neutral", 2: "frequently abused"}

def ml_drivers(X, classes, top_n=6):
    """
    Which features moved the ML model's score, from XGBoost's built-in per-feature contributions
    (TreeSHAP-style values, no extra dependency). push > 0 moves toward phishing/malware, push < 0 toward benign.
    """
    try:
        import xgboost as xgb
        contrib = _model.get_booster().predict(xgb.DMatrix(X), pred_contribs=True)[0]   # (classes, features + bias)
        push = -contrib[classes.index("benign"), :-1]
    except Exception:
        return []
    out = []
    for i in sorted(range(len(FEATURE_COLS)), key=lambda i: -abs(push[i]))[:top_n]:
        name, val = FEATURE_COLS[i], X.iloc[0, i]
        if name in BINARY_FEATURES:
            shown = "yes" if val else "no"
        elif name == "tld_category":
            shown = TLD_TEXT.get(int(val), str(val))
        else:
            shown = f"{val:.2f}".rstrip("0").rstrip(".")
        out.append({"feature": name, "label": FEATURE_LABELS[name], "value": shown, "push": round(float(push[i]), 3)})
    return out

W_ML        = 0.70
W_HEURISTIC = 0.15
W_THREAT    = 0.15

DECIDER_LABEL = {
    "feedback": "Your correction", "blocklist": "Threat-intel blocklist", "allowlist": "Trusted-domain allowlist",
    "lookalike": "Lookalike check", "fusion": "Combined risk score", "ml": "ML model",
}

def build_trace(*, final_label, decider, fb, feedback_conflict, threat_flag, matched_lists, trusted, host,
                lookalike, lookalike_detail, weak_benign_override, fused, ml_label, ml_confidence,
                heuristic_score, triggered_rules):
    """
    Model-independent account of HOW the verdict was reached: one row per detection layer with what it
    found and whether it decided the verdict, agreed with it, or was overruled.
    status: decided | agrees | overruled | no_signal
    """
    threat = final_label != "benign"

    def stance(points_to_threat):
        return "agrees" if points_to_threat == threat else "overruled"

    steps = []
    if fb:
        where = {"url": "this exact page", "host": "this site", "domain": "this whole domain"}[fb["scope"]]
        steps.append(("feedback", "Your correction", "decided", f"You marked {where} as {'safe' if fb['correct_label'] == 'benign' else fb['correct_label']}."))
    elif feedback_conflict:
        steps.append(("feedback", "Your correction", "overruled", "You marked this safe, but it is on a threat blocklist, so the blocklist verdict was kept."))
    else:
        steps.append(("feedback", "Your correction", "no_signal", "No correction saved for this URL, site or domain."))

    if threat_flag:
        status = "decided" if decider == "blocklist" else "agrees"
        steps.append(("blocklist", "Threat-intel blocklist", status, "Domain found on: " + ", ".join(matched_lists) + "."))
    else:
        steps.append(("blocklist", "Threat-intel blocklist", "no_signal", "Not on the URLhaus or OpenPhish blocklists."))

    if trusted:
        steps.append(("allowlist", "Trusted-domain allowlist", "decided" if decider == "allowlist" else "agrees",
                      f"{base_domain(host)} is a top-ranked site with no threat history."))
    else:
        steps.append(("allowlist", "Trusted-domain allowlist", "no_signal", "Domain is not on the trusted list, or its trust was revoked."))

    if lookalike:
        steps.append(("lookalike", "Lookalike check", "decided" if decider == "lookalike" else "agrees", lookalike_detail + "."))
    else:
        steps.append(("lookalike", "Lookalike check", "no_signal", "Does not imitate a well-known brand or site."))

    if triggered_rules:
        names = ", ".join(d.lower() for _, _, d in triggered_rules[:3]) + (f" and {len(triggered_rules) - 3} more" if len(triggered_rules) > 3 else "")
        steps.append(("heuristic", "Heuristic rules", stance(heuristic_score >= 0.2), f"Score {heuristic_score:.2f}: {names}."))
    else:
        steps.append(("heuristic", "Heuristic rules", "no_signal", "No rule fired."))

    ml_threat = ml_label != "benign"
    steps.append(("ml", "ML model", "decided" if decider == "ml" else stance(ml_threat),
                  f"Predicted {ml_label} ({ml_confidence * 100:.0f}%) from the URL's structure."))

    if weak_benign_override:
        steps.append(("fusion", "Combined risk score", "decided", f"The model leaned benign, but the combined risk of {fused:.2f} is high enough to reclassify it."))

    return [{"id": i, "title": t, "status": st, "detail": d} for i, t, st, d in steps]

# Developer/community platforms where organisations legitimately use their own brand as a subdomain
# (microsoft.github.io, apple.stackexchange.com); excluded from the brand-in-subdomain rule.
BRAND_SUBDOMAIN_OK = {"github.io", "gitlab.io", "readthedocs.io", "stackexchange.com"}

def brand_in_subdomain(host):
    """
    A well-known brand name used as a whole word in the SUBDOMAIN of a domain that is not that brand's
    (google.abc.com, login.paypal.evil.com). Whole-word matching, so 'groups' is not 'ups'.
    """
    base = base_domain(host)
    if base in BRAND_SUBDOMAIN_OK or not host.endswith(base):
        return None
    sub = host[: -len(base)].rstrip(".")
    if not sub:
        return None
    tokens = set(re.split(r"[.\-_]", _brand_fold(sub)))
    for b in sorted(BRANDS):
        if b in tokens and not re.search(rf"(^|\.){b}\.((com|org|net)|[a-z]{{2}}|(co|com|org|gov|ac)\.[a-z]{{2}})$", base):
            return b
    return None

def normalize_for_analysis(url):
    """
    Match the dataset's URL normalisation (see auto_update.normalize_url): a bare host's lone trailing
    slash is dropped. Browsers always report https://example.com/ with the slash, and a model trained on
    slash-less threat URLs must not treat that slash as a signal.
    """
    url = url.strip()
    try:
        p = urlparse(url)
        if p.path == "/" and not (p.params or p.query or p.fragment):
            return url[: -1] if url.endswith("/") else url
    except ValueError:
        pass
    return url

def analyze(url, use_feedback=True):
    url = normalize_for_analysis(url)
    load_model()
    feats = extract_features(url)
    X = pd.DataFrame([feats])[FEATURE_COLS]
    proba = _model.predict_proba(X)[0]
    classes = list(_encoder.classes_)
    ml_label = classes[proba.argmax()]
    ml_confidence = round(float(proba.max()),4)
    benign_idx = classes.index("benign")
    ml_score = round(1.0 - float(proba[benign_idx]),4)
    heuristic_score, triggered_rules = score_url(url)
    ti_score, threat_flag, matched_lists = lookup(url)
    fused = round(W_ML*ml_score + W_HEURISTIC*heuristic_score + W_THREAT*ti_score, 4)
    if threat_flag:
        fused = max(fused, 0.75)

    # Override: if a domain is confirmed in a threat intel blocklist but the ML
    # model still predicted benign, trust the blocklist (ground truth) over the
    # statistical prediction. Without this, threat_intel and heuristic layers
    # only ever influenced risk_level/score display, never the actual
    # classification used for accuracy/FPR/FNR evaluation.
    final_label = ml_label
    decider = "ml"     # which layer decided the final verdict; shown to the user in the decision trace
    if threat_flag and ml_label == "benign":
        decider = "blocklist"
        if matched_lists and "urlhaus" in [m.lower() for m in matched_lists]:
            final_label = "malware"
        else:
            final_label = "phishing"

    # Trusted registered domain (top-ranked site never seen in threat data) and
    # not on any blocklist: a URL-string model can't out-vote that, so call it benign.
    host = urlparse(url).netloc.lower().split(":")[0]
    brand_sub = brand_in_subdomain(host)
    trusted = (USE_ALLOWLIST and not threat_flag and not feats["is_domain_ip"]
               and is_trusted_host(host) and not brand_sub)    # a brand name in the subdomain revokes the trust
    if trusted:
        decider = "allowlist"
        final_label = "benign"
        fused = min(fused, TRUSTED_SCORE_CAP)
    # Brand name hidden behind look-alike characters (amaz0n-update.tk, paypa1-login.com): deliberate obfuscation,
    # never seen on legitimate domains in the dataset.
    obfuscated = next((b for b in BRANDS if b in _brand_fold(host) and b not in host), None)

    lookalike = None
    if not trusted and not threat_flag and not feats["is_domain_ip"]:
        targets, folded = load_lookalike_targets()
        lookalike = find_lookalike(base_domain(host), targets, folded)
    weak_benign_override = False
    if lookalike:
        # Typosquat / confusable of a top site (rnicrosoft.com, g00gle.com, google.coms):
        # the URL string alone looks like an ordinary short domain, so don't let the ML score decide.
        target, kind = lookalike
        decider = "lookalike"
        if final_label == "benign":
            final_label = "phishing"
        fused = max(fused, LOOKALIKE_SCORE[kind])
    elif brand_sub and not threat_flag:
        decider = "lookalike"
        if final_label == "benign":
            final_label = "phishing"
        fused = max(fused, LOOKALIKE_SCORE["subdomain"])
        lookalike = (f"{brand_sub}.com", "subdomain")
    elif obfuscated and not trusted and not threat_flag:
        decider = "lookalike"
        if final_label == "benign":
            final_label = "phishing"
        fused = max(fused, LOOKALIKE_SCORE["typo"])
        lookalike = (f"{obfuscated}.com", "confusable")
    elif final_label == "benign" and fused >= FUSED_OVERRIDE:
        # Weak "benign" from the model but heuristics/threat intel disagree.
        decider = "fusion"
        weak_benign_override = True
        threat_classes = [c for c in classes if c != "benign"]
        final_label = max(threat_classes, key=lambda c: proba[classes.index(c)])

    lookalike_detail = None
    if lookalike:
        shown_domain = base_domain(host)
        lookalike_detail = describe_lookalike(shown_domain, lookalike[0], lookalike[1])

    # The user's own correction (feedback.py) beats every statistical layer. The one thing it cannot
    # beat is a threat-intel blocklist hit on a "this is safe" correction; that conflict is surfaced.
    fb = None
    feedback_conflict = False
    if use_feedback and USE_FEEDBACK:
        try:
            import feedback
            fb = feedback.lookup(url, base_domain(host))
        except Exception:
            fb = None
    if fb:
        if fb["correct_label"] == "benign" and threat_flag:
            feedback_conflict = True
            fb = None
        elif fb["correct_label"] == "benign":
            decider = "feedback"
            final_label = "benign"
            fused = min(fused, 0.05)
            lookalike = None
        else:
            decider = "feedback"
            final_label = fb["correct_label"]
            fused = max(fused, 0.85)
            trusted = False
            lookalike = None

    # Confidence in the FINAL verdict: the model's own probability when it agrees, otherwise the
    # fused risk (non-benign overrides) or its complement (trusted/benign overrides).
    if fb:
        confidence = 1.0   # the user's explicit decision
    elif final_label == ml_label:
        confidence = ml_confidence
    elif final_label == "benign":
        confidence = round(1.0 - fused, 4)
    else:
        confidence = round(max(fused, float(proba[classes.index(final_label)])), 4)

    trace = build_trace(
        final_label=final_label, decider=decider, fb=fb, feedback_conflict=feedback_conflict,
        threat_flag=threat_flag, matched_lists=matched_lists, trusted=trusted, host=host,
        lookalike=lookalike, lookalike_detail=lookalike_detail, weak_benign_override=weak_benign_override,
        fused=fused, ml_label=ml_label, ml_confidence=ml_confidence,
        heuristic_score=heuristic_score, triggered_rules=triggered_rules,
    )

    level = risk_level(fused)
    # A non-benign verdict must never display as safe/low in the UI.
    if final_label != "benign" and level in ("safe", "low"):
        level = "medium"
    return {
        "url":        url,
        "prediction": final_label,
        "risk_level": level,
        "score":      fused,
        "confidence": confidence,
        "lookalike_score": LOOKALIKE_SCORE[lookalike[1]] if lookalike else 0.0,
        "trusted_domain": trusted,
        "feedback": {k: fb[k] for k in ("id", "correct_label", "scope", "kind", "note", "created_at")} if fb else None,
        "feedback_conflict": feedback_conflict,
        "lookalike": {"target": lookalike[0], "kind": lookalike[1], "detail": lookalike_detail} if lookalike else None,
        "decided_by": decider,
        "trace": trace,
        "ml": {
            "drivers":       ml_drivers(X, classes),
            "label":         ml_label,
            "confidence":    ml_confidence,
            "score":         ml_score,
            "probabilities": dict(zip(classes,[round(float(p),4) for p in proba]))
        },
        "heuristic": {
            "score":           heuristic_score,
            "triggered_rules": [(n,d) for n,_,d in triggered_rules]
        },
        "threat_intel": {
            "score":         ti_score,
            "flag":          threat_flag,
            "matched_lists": matched_lists
        }
    }

if __name__ == "__main__":
    load_blocklists()
    for url in ["https://www.google.com","https://en.wikipedia.org","https://bankofengland.co.uk","http://paypal-secure-login.xyz/verify/account","http://amaz0n-update.tk/signin"]:
        r = analyze(url)
        print(f"{url[:60]:<60} {r['prediction']:<10} {r['risk_level']:<10} {r['score']}")