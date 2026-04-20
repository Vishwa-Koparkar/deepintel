import pandas as pd
import joblib
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, accuracy_score
from xgboost import XGBClassifier

FEATURE_COLS = [
    "url_length","path_length","num_subdomains","num_digits",
    "num_hyphens_domain","is_https","is_domain_ip","has_shortener",
    "has_suspicious_keywords","is_brand_impersonation","has_at_symbol",
    "has_double_slash","has_encoded_chars","num_query_params",
    "domain_entropy","tld_category",
    "is_safe_country_tld","domain_word_len","has_safe_extension","digit_ratio"
]

train = pd.read_csv("data/train.csv")
val   = pd.read_csv("data/val.csv")

le = joblib.load("models/label_encoder.pkl")
X_train = train[FEATURE_COLS]
X_val   = val[FEATURE_COLS]
y_train = le.transform(train["label"])
y_val   = le.transform(val["label"])

print("Training tuned XGBoost with 20 features...")
model = XGBClassifier(
    n_estimators=400,
    max_depth=8,
    learning_rate=0.05,
    subsample=0.8,
    colsample_bytree=0.8,
    min_child_weight=3,
    gamma=0.1,
    use_label_encoder=False,
    eval_metric="mlogloss",
    random_state=42,
    n_jobs=-1,
    early_stopping_rounds=20,
    verbosity=0,
)
model.fit(X_train, y_train, eval_set=[(X_val, y_val)], verbose=False)

preds = model.predict(X_val)
acc = accuracy_score(y_val, preds)
print(f"\nAccuracy: {acc*100:.2f}%")
print(classification_report(y_val, preds, target_names=le.classes_))

joblib.dump(model, "models/best_model.pkl")
print("Saved as models/best_model.pkl")