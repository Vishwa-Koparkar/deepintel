import pandas as pd
import joblib

FEATURE_COLS = [
    "url_length","path_length","num_subdomains","num_digits",
    "num_hyphens_domain","is_https","is_domain_ip","has_shortener",
    "has_suspicious_keywords","is_brand_impersonation","has_at_symbol",
    "has_double_slash","has_encoded_chars","num_query_params",
    "domain_entropy","tld_category"
]

test = pd.read_csv("data/test.csv")
le  = joblib.load("models/label_encoder.pkl")
model = joblib.load("models/best_model.pkl")

X = test[FEATURE_COLS]
y_true = test["label"]
y_pred = le.inverse_transform(model.predict(X))

# Find false positives: actual=benign, predicted=malicious
fp_mask = (y_true == "benign") & (y_pred != "benign")
fp = test[fp_mask].copy()
fp["predicted"] = y_pred[fp_mask]

print(f"False positives: {len(fp)} benign URLs flagged as malicious")
print(f"\nSample false positives:")
print(fp[["url","predicted"]].head(20).to_string(index=False))

print(f"\nFeature averages — false positives vs true benign:")
true_benign = test[y_true == "benign"]
print(pd.DataFrame({
    "true_benign": true_benign[FEATURE_COLS].mean().round(3),
    "false_positives": fp[FEATURE_COLS].mean().round(3),
}).to_string())