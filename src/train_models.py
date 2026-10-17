import joblib
import pandas as pd
import numpy as np
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import f1_score
from xgboost import XGBClassifier

df = pd.read_csv("data/dataset_master.csv").dropna().reset_index(drop=True)

feature_cols = [
    "mean_len", "std_len", "max_len", "q10_len", "q50_len", "q90_len",
    "mean_iat", "std_iat",
    "mean_entropy", "min_entropy", "std_entropy"
]

X = df[feature_cols]
groups = df["session_id"]

print("=" * 70)
print(f"[*] Total Samples: {len(df):,} | Independent Sessions: {df['session_id'].nunique()}")
print("=" * 70)

# Task 1: Mode Classification (Tunnel vs Transport)
le_mode = LabelEncoder()
y_mode = pd.Series(le_mode.fit_transform(df["label_mode"].astype(str)))

sgkf = StratifiedGroupKFold(n_splits=5)
rf_m, xgb_m, mlp_m = [], [], []

scaler = StandardScaler()
X_scaled = pd.DataFrame(scaler.fit_transform(X), columns=feature_cols)

for train_idx, test_idx in sgkf.split(X, y_mode, groups):
    X_tr, X_te = X.iloc[train_idx], X.iloc[test_idx]
    y_tr, y_te = y_mode.iloc[train_idx], y_mode.iloc[test_idx]
    X_tr_sc, X_te_sc = X_scaled.iloc[train_idx], X_scaled.iloc[test_idx]

    # Random Forest
    rf = RandomForestClassifier(n_estimators=100, random_state=42)
    rf.fit(X_tr, y_tr)
    rf_m.append(f1_score(y_te, rf.predict(X_te), average="macro"))

    # XGBoost
    xgb = XGBClassifier(n_estimators=100, random_state=42, eval_metric="logloss")
    xgb.fit(X_tr, y_tr)
    xgb_m.append(f1_score(y_te, xgb.predict(X_te), average="macro"))

    # MLP Baseline
    mlp = MLPClassifier(hidden_layer_sizes=(64, 32), max_iter=300, random_state=42)
    mlp.fit(X_tr_sc, y_tr)
    mlp_m.append(f1_score(y_te, mlp.predict(X_te_sc), average="macro"))

print("\n[+] TASK 1: MODE CLASSIFICATION BENCHMARK (Macro F1)")
print(f"    - XGBoost Classifier : {np.mean(xgb_m):.4f} (+/- {np.std(xgb_m):.4f})")
print(f"    - Random Forest      : {np.mean(rf_m):.4f} (+/- {np.std(rf_m):.4f})")
print(f"    - MLP Neural Baseline: {np.mean(mlp_m):.4f} (+/- {np.std(mlp_m):.4f})")

# Task 2: Cipher Family Classification
le_crypto = LabelEncoder()
y_crypto = pd.Series(le_crypto.fit_transform(df["label_crypto"].astype(str)))

rf_c, xgb_c, mlp_c = [], [], []
for train_idx, test_idx in sgkf.split(X, y_crypto, groups):
    X_tr, X_te = X.iloc[train_idx], X.iloc[test_idx]
    y_tr, y_te = y_crypto.iloc[train_idx], y_crypto.iloc[test_idx]
    X_tr_sc, X_te_sc = X_scaled.iloc[train_idx], X_scaled.iloc[test_idx]

    rf = RandomForestClassifier(n_estimators=100, random_state=42)
    rf.fit(X_tr, y_tr)
    rf_c.append(f1_score(y_te, rf.predict(X_te), average="macro"))

    xgb = XGBClassifier(n_estimators=100, random_state=42, eval_metric="mlogloss")
    xgb.fit(X_tr, y_tr)
    xgb_c.append(f1_score(y_te, xgb.predict(X_te), average="macro"))

    mlp = MLPClassifier(hidden_layer_sizes=(64, 32), max_iter=300, random_state=42)
    mlp.fit(X_tr_sc, y_tr)
    mlp_c.append(f1_score(y_te, mlp.predict(X_te_sc), average="macro"))

print("\n[+] TASK 2: CIPHER SUITE CLASSIFICATION BENCHMARK (Macro F1)")
print(f"    - XGBoost Classifier : {np.mean(xgb_c):.4f} (+/- {np.std(xgb_c):.4f})")
print(f"    - Random Forest      : {np.mean(rf_c):.4f} (+/- {np.std(rf_c):.4f})")
print(f"    - MLP Neural Baseline: {np.mean(mlp_c):.4f} (+/- {np.std(mlp_c):.4f})")

# Serialize final models
final_mode = XGBClassifier(n_estimators=100, random_state=42, eval_metric="logloss").fit(X, y_mode)
final_crypto = XGBClassifier(n_estimators=100, random_state=42, eval_metric="mlogloss").fit(X, y_crypto)

joblib.dump(final_mode, "models/xgb_mode_classifier.pkl")
joblib.dump(final_crypto, "models/xgb_crypto_classifier.pkl")
joblib.dump(le_mode, "models/le_mode.pkl")
joblib.dump(le_crypto, "models/le_crypto.pkl")
joblib.dump(scaler, "models/scaler.pkl")

print("\n[+] Serialized production models and scalers to models/")
