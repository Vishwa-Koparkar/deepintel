import pandas as pd
from sklearn.model_selection import train_test_split

INPUT_FILE = "data/dataset_features.csv"

df = pd.read_csv(INPUT_FILE)

# Extract domain for leak prevention
from urllib.parse import urlparse
df["domain"] = df["url"].apply(lambda u: urlparse(u).netloc.lower().split(":")[0])

# Split by domain to prevent same domain appearing in train and test
domains = df["domain"].unique()
train_domains, temp_domains = train_test_split(domains, test_size=0.30, random_state=42)
val_domains, test_domains = train_test_split(temp_domains, test_size=0.50, random_state=42)

train = df[df["domain"].isin(train_domains)].drop(columns=["domain"])
val   = df[df["domain"].isin(val_domains)].drop(columns=["domain"])
test  = df[df["domain"].isin(test_domains)].drop(columns=["domain"])

train.to_csv("data/train.csv", index=False)
val.to_csv("data/val.csv", index=False)
test.to_csv("data/test.csv", index=False)

print(f"Train: {len(train)} rows  ({len(train)/len(df)*100:.1f}%)")
print(f"Val:   {len(val)} rows  ({len(val)/len(df)*100:.1f}%)")
print(f"Test:  {len(test)} rows  ({len(test)/len(df)*100:.1f}%)")

print("\nTrain class distribution:")
print(train["label"].value_counts())
print("\nVal class distribution:")
print(val["label"].value_counts())
print("\nTest class distribution:")
print(test["label"].value_counts())