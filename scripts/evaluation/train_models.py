import pandas as pd
import numpy as np
import joblib
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from xgboost import XGBClassifier
from sklearn.preprocessing import LabelEncoder

TRAIN_FILE = "data/train.csv"
VAL_FILE   = "data/val.csv"

FEATURE_COLS = [
    "url_length", "path_length", "num_subdomains", "num_digits",
    "num_hyphens_domain", "is_https", "is_domain_ip", "has_shortener",
    "has_suspicious_keywords", "is_brand_impersonation", "has_at_symbol",
    "has_double_slash", "has_encoded_chars", "num_query_params",
    "domain_entropy", "tld_category"
]

os.makedirs("models", exist_ok=True)

# Load data
train = pd.read_csv(TRAIN_FILE)
val   = pd.read_csv(VAL_FILE)

# split data into x and y [x = features, y = labels]
X_train = train[FEATURE_COLS]
X_val   = val[FEATURE_COLS]

# Encode labels
le = LabelEncoder()
y_train = le.fit_transform(train["label"])
y_val   = le.transform(val["label"])
joblib.dump(le, "models/label_encoder.pkl")
print(f"Classes: {list(le.classes_)}\n")

def evaluate(name, model, X_val, y_val, le):
    preds = model.predict(X_val)
    acc = accuracy_score(y_val, preds)
    print(f"{'='*40}")
    print(f"  {name}")
    print(f"{'='*40}")
    print(f"  Accuracy: {acc*100:.2f}%")
    print(classification_report(y_val, preds, target_names=le.classes_))
    return acc

# --- Model A: Random Forest ---
print("Training Random Forest...")
rf = RandomForestClassifier(n_estimators=200, max_depth=20, random_state=42, n_jobs=-1)
rf.fit(X_train, y_train)
joblib.dump(rf, "models/random_forest.pkl")
rf_acc = evaluate("Random Forest", rf, X_val, y_val, le)

# --- Model B: XGBoost ---
print("Training XGBoost...")
xgb = XGBClassifier(n_estimators=200, max_depth=6, learning_rate=0.1,
                     use_label_encoder=False, eval_metric="mlogloss",
                     random_state=42, n_jobs=-1)
xgb.fit(X_train, y_train)
joblib.dump(xgb, "models/xgboost.pkl")
xgb_acc = evaluate("XGBoost", xgb, X_val, y_val, le)

# --- Select best model ---
print("\n" + "="*40)
if xgb_acc >= rf_acc:
    best_name = "XGBoost"
    best_model = xgb
else:
    best_name = "Random Forest"
    best_model = rf

print(f"  Best model: {best_name} (val accuracy: {max(rf_acc, xgb_acc)*100:.2f}%)")
joblib.dump(best_model, "models/best_model.pkl")

# Save which model won
with open("models/best_model_name.txt", "w") as f:
    f.write(best_name)

print(f"  Saved to models/best_model.pkl")