import joblib
import pandas as pd
from urllib.parse import urlparse
import re
import math

from heuristic_scorer import score_url, risk_level
from threat_intel import lookup, load_blocklists

_model = None
_encoder = None

def load_model():
    global _model, _encoder
    if _model is None:
        _model   = joblib.load("models/best_model.pkl")
        _encoder = joblib.load("models/label_encoder.pkl")

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
        detected_brand = next((b for b in BRANDS if b in domain), None)
        is_imp = 0
        if detected_brand:
            is_real = domain in (f"{detected_brand}.com",f"{detected_brand}.org",f"www.{detected_brand}.com")
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

W_ML        = 0.70
W_HEURISTIC = 0.15
W_THREAT    = 0.15

def analyze(url):
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
    level = risk_level(fused)
    return {
        "url":        url,
        "prediction": ml_label,
        "risk_level": level,
        "score":      fused,
        "ml": {
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