import os
import shutil
import sys

import joblib
import pandas as pd
from sklearn.metrics import classification_report, accuracy_score
from xgboost import XGBClassifier

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

FEATURE_COLS = [
    "url_length","path_length","num_subdomains","num_digits",
    "num_hyphens_domain","is_https","is_domain_ip","has_shortener",
    "has_suspicious_keywords","is_brand_impersonation","has_at_symbol",
    "has_double_slash","has_encoded_chars","num_query_params",
    "domain_entropy","tld_category",
    "is_safe_country_tld","domain_word_len","has_safe_extension","digit_ratio"
]

MODEL_PATH = "models/best_model.pkl"
BACKUP_PATH = "models/best_model.prev.pkl"
MAX_ACC_DROP = 0.01   # refuse to replace the live model if val accuracy falls by more than this


def accuracy_on(model, X, y):
    return accuracy_score(y, model.predict(X)) if len(y) else None


train = pd.read_csv("data/train.csv")
val   = pd.read_csv("data/val.csv")

le = joblib.load("models/label_encoder.pkl")
X_train = train[FEATURE_COLS]
X_val   = val[FEATURE_COLS]
y_train = le.transform(train["label"])
y_val   = le.transform(val["label"])
# Rows the user corrected (see feedback.py) carry a higher weight; everything else is 1
w_train = train["weight"].fillna(1.0) if "weight" in train.columns else None

# Corrections the user reported; they are only ever in train, so measure them separately
fb = train[train["source"] == "user_feedback"] if "source" in train.columns else train.iloc[0:0]
X_fb, y_fb = fb[FEATURE_COLS], le.transform(fb["label"]) if len(fb) else []

old_model = joblib.load(MODEL_PATH) if os.path.exists(MODEL_PATH) else None
old_acc = accuracy_on(old_model, X_val, y_val) if old_model is not None else None
old_fb  = accuracy_on(old_model, X_fb, y_fb) if old_model is not None and len(fb) else None

print(f"Training tuned XGBoost with 20 features on {len(train)} rows ({len(fb)} user corrections)...")
model = XGBClassifier(
    n_estimators=400,
    max_depth=6,           # reduce from 8
    learning_rate=0.05,
    subsample=0.8,
    colsample_bytree=0.8,
    min_child_weight=5,    # increase from 3
    gamma=0.2,             # increase from 0.1
    reg_lambda=1.5,        # add L2 regularization
    early_stopping_rounds=20,
    eval_metric="mlogloss"
)
model.fit(X_train, y_train, sample_weight=w_train, eval_set=[(X_val, y_val)], verbose=False)

preds = model.predict(X_val)
acc = accuracy_score(y_val, preds)
print(f"\nAccuracy: {acc*100:.2f}%")
print(classification_report(y_val, preds, target_names=le.classes_))

new_fb = accuracy_on(model, X_fb, y_fb) if len(fb) else None
if len(fb):
    print(f"Your corrections classified correctly: {old_fb*100 if old_fb is not None else float('nan'):.1f}% -> {new_fb*100:.1f}%  ({len(fb)} URLs)")

# Never silently ship a worse model
if old_acc is not None and acc < old_acc - MAX_ACC_DROP:
    print(f"\nNOT saved: validation accuracy {acc*100:.2f}% is more than {MAX_ACC_DROP*100:.0f} points below the current model ({old_acc*100:.2f}%).")
    print("Current model kept. Inspect data/train.csv and rerun.")
    sys.exit(2)

if old_model is not None:
    shutil.copy2(MODEL_PATH, BACKUP_PATH)
joblib.dump(model, MODEL_PATH)
print(f"Saved as {MODEL_PATH}" + (f" (previous model backed up to {BACKUP_PATH})" if old_model is not None else ""))

# Mark user corrections as learned
try:
    import feedback
    feedback.mark_trained()
except Exception as e:
    print(f"(could not mark feedback as trained: {e})")
