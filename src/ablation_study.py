import pandas as pd
import numpy as np
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import f1_score
from xgboost import XGBClassifier

df = pd.read_csv("data/dataset_master.csv").dropna().reset_index(drop=True)
groups = df["session_id"]

le_crypto = LabelEncoder()
y_crypto = pd.Series(le_crypto.fit_transform(df["label_crypto"].astype(str)))

# Feature Subsets
ablation_sets = {
    "1. Full Feature Set": [
        "mean_len", "std_len", "max_len", "q10_len", "q50_len", "q90_len",
        "mean_iat", "std_iat", "mean_entropy", "min_entropy", "std_entropy"
    ],
    "2. No Entropy Family": [
        "mean_len", "std_len", "max_len", "q10_len", "q50_len", "q90_len",
        "mean_iat", "std_iat"
    ],
    "3. No Packet Lengths": [
        "mean_iat", "std_iat", "mean_entropy", "min_entropy", "std_entropy"
    ],
    "4. No IAT (Timing)": [
        "mean_len", "std_len", "max_len", "q10_len", "q50_len", "q90_len",
        "mean_entropy", "min_entropy", "std_entropy"
    ],
    "5. Entropy Only": [
        "mean_entropy", "min_entropy", "std_entropy"
    ]
}

print("=" * 75)
print("FEATURE ABLATION STUDY: CIPHER SUITE CLASSIFICATION (XGBoost)")
print("=" * 75)

results = []
sgkf = StratifiedGroupKFold(n_splits=3)

for name, feats in ablation_sets.items():
    X_sub = df[feats]
    scores = []
    
    for train_idx, test_idx in sgkf.split(X_sub, y_crypto, groups):
        X_train, X_test = X_sub.iloc[train_idx], X_sub.iloc[test_idx]
        y_train, y_test = y_crypto.iloc[train_idx], y_crypto.iloc[test_idx]
        
        clf = XGBClassifier(n_estimators=100, random_state=42, eval_metric="mlogloss")
        clf.fit(X_train, y_train)
        scores.append(f1_score(y_test, clf.predict(X_test), average="macro"))
        
    mean_f1 = np.mean(scores)
    std_f1 = np.std(scores)
    results.append({"Configuration": name, "Features Used": len(feats), "Macro F1": mean_f1, "Std Dev": std_f1})

res_df = pd.DataFrame(results)
print(res_df.to_string(index=False))

res_df.to_csv("data/ablation_results.csv", index=False)
print("\n[+] Saved ablation results to data/ablation_results.csv")
