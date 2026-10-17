import os
import sys
import glob
import math
import time
import joblib
import numpy as np
import pandas as pd
from collections import Counter
from scapy.all import rdpcap, IP, UDP
from scapy.layers.ipsec import ESP
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import f1_score
from xgboost import XGBClassifier
import shap
import matplotlib.pyplot as plt

print("=" * 78)
print("   AI-POWERED IPSEC PROTOCOL ANALYZER — MASTER EXECUTION & EVALUATION")
print("=" * 78)

# -------------------------------------------------------------------------
# 1. Feature Extraction Helpers
# -------------------------------------------------------------------------
def calculate_shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())

def extract_window_features(pcap_path, window_size=25, step=12):
    filename = os.path.basename(pcap_path)
    session_id = filename.replace(".pcap", "")
    fn = filename.lower()

    if "scenario_a" in fn:
        label_mode, label_crypto = "tunnel", "AEAD_GCM"
    elif "scenario_b1" in fn:
        label_mode, label_crypto = "transport", "CBC"
    elif "scenario_b2" in fn:
        label_mode, label_crypto = "tunnel", "CBC"
    elif "scenario_c" in fn:
        label_mode, label_crypto = "tunnel", "NULL"
    elif "scenario_d" in fn:
        label_mode, label_crypto = "tunnel", "3DES_LEGACY"
    else:
        return []

    try:
        packets = rdpcap(pcap_path)
    except Exception:
        return []

    esp_packets = [p for p in packets if IP in p and (p[IP].proto == 50 or ESP in p)]
    if len(esp_packets) < window_size:
        return []

    rows = []
    for i in range(0, len(esp_packets) - window_size + 1, step):
        chunk = esp_packets[i:i + window_size]
        lengths = [len(p) for p in chunk]
        times = [float(p.time) for p in chunk]
        iats = np.diff(times) if len(times) > 1 else [0.0]
        entropies = [calculate_shannon_entropy(bytes(p[IP].payload)) for p in chunk]

        rows.append({
            "session_id": session_id,
            "mean_len": float(np.mean(lengths)),
            "std_len": float(np.std(lengths)),
            "max_len": float(np.max(lengths)),
            "q10_len": float(np.percentile(lengths, 10)),
            "q50_len": float(np.percentile(lengths, 50)),
            "q90_len": float(np.percentile(lengths, 90)),
            "mean_iat": float(np.mean(iats)),
            "std_iat": float(np.std(iats)),
            "mean_entropy": float(np.mean(entropies)),
            "min_entropy": float(np.min(entropies)),
            "std_entropy": float(np.std(entropies)),
            "label_mode": label_mode,
            "label_crypto": label_crypto
        })
    return rows

# -------------------------------------------------------------------------
# 2. Dataset Ingestion / Verification
# -------------------------------------------------------------------------
feature_cols = [
    "mean_len", "std_len", "max_len", "q10_len", "q50_len", "q90_len",
    "mean_iat", "std_iat",
    "mean_entropy", "min_entropy", "std_entropy"
]

if not os.path.exists("data/dataset_master.csv"):
    os.makedirs("data", exist_ok=True)
    pcap_files = sorted(glob.glob("captures/*.pcap"))
    print(f"[*] Extracting features from {len(pcap_files)} PCAPs...")
    records = []
    for f in pcap_files:
        records.extend(extract_window_features(f))
    df = pd.DataFrame(records)
    df.to_csv("data/dataset_master.csv", index=False)
else:
    df = pd.read_csv("data/dataset_master.csv").dropna()

print(f"[+] Active Dataset Samples: {len(df):,} | Independent Sessions: {df['session_id'].nunique()}")

X = df[feature_cols]
groups = df["session_id"]
le_mode = LabelEncoder()
y_mode = pd.Series(le_mode.fit_transform(df["label_mode"].astype(str)))

le_crypto = LabelEncoder()
y_crypto = pd.Series(le_crypto.fit_transform(df["label_crypto"].astype(str)))

scaler = StandardScaler()
X_scaled = pd.DataFrame(scaler.fit_transform(X), columns=feature_cols)

# -------------------------------------------------------------------------
# 3. Model Benchmark (Finding 5: XGBoost vs RF vs MLP)
# -------------------------------------------------------------------------
print("\n" + "=" * 78)
print("1. MODEL BENCHMARKING WITH SESSION GROUPING (StratifiedGroupKFold)")
print("=" * 78)

sgkf = StratifiedGroupKFold(n_splits=5)
xgb_m_scores, rf_m_scores, mlp_m_scores = [], [], []
xgb_c_scores, rf_c_scores, mlp_c_scores = [], [], []

for train_idx, test_idx in sgkf.split(X, y_crypto, groups):
    X_tr, X_te = X.iloc[train_idx], X.iloc[test_idx]
    X_tr_sc, X_te_sc = X_scaled.iloc[train_idx], X_scaled.iloc[test_idx]
    
    # Mode splits
    ym_tr, ym_te = y_mode.iloc[train_idx], y_mode.iloc[test_idx]
    xgb_m = XGBClassifier(n_estimators=100, random_state=42, eval_metric="logloss").fit(X_tr, ym_tr)
    rf_m = RandomForestClassifier(n_estimators=100, random_state=42).fit(X_tr, ym_tr)
    mlp_m = MLPClassifier(hidden_layer_sizes=(64, 32), max_iter=300, random_state=42).fit(X_tr_sc, ym_tr)

    xgb_m_scores.append(f1_score(ym_te, xgb_m.predict(X_te), average="macro"))
    rf_m_scores.append(f1_score(ym_te, rf_m.predict(X_te), average="macro"))
    mlp_m_scores.append(f1_score(ym_te, mlp_m.predict(X_te_sc), average="macro"))

    # Cipher splits
    yc_tr, yc_te = y_crypto.iloc[train_idx], y_crypto.iloc[test_idx]
    xgb_c = XGBClassifier(n_estimators=100, random_state=42, eval_metric="mlogloss").fit(X_tr, yc_tr)
    rf_c = RandomForestClassifier(n_estimators=100, random_state=42).fit(X_tr, yc_tr)
    mlp_c = MLPClassifier(hidden_layer_sizes=(64, 32), max_iter=300, random_state=42).fit(X_tr_sc, yc_tr)

    xgb_c_scores.append(f1_score(yc_te, xgb_c.predict(X_te), average="macro"))
    rf_c_scores.append(f1_score(yc_te, rf_c.predict(X_te), average="macro"))
    mlp_c_scores.append(f1_score(yc_te, mlp_c.predict(X_te_sc), average="macro"))

print("Mode Classification Macro F1:")
print(f"  - XGBoost       : {np.mean(xgb_m_scores):.4f} (+/- {np.std(xgb_m_scores):.4f})")
print(f"  - Random Forest : {np.mean(rf_m_scores):.4f} (+/- {np.std(rf_m_scores):.4f})")
print(f"  - MLP Baseline  : {np.mean(mlp_m_scores):.4f} (+/- {np.std(mlp_m_scores):.4f})")

print("\nCipher Suite Classification Macro F1:")
print(f"  - XGBoost       : {np.mean(xgb_c_scores):.4f} (+/- {np.std(xgb_c_scores):.4f})")
print(f"  - Random Forest : {np.mean(rf_c_scores):.4f} (+/- {np.std(rf_c_scores):.4f})")
print(f"  - MLP Baseline  : {np.mean(mlp_c_scores):.4f} (+/- {np.std(mlp_c_scores):.4f})")

# Serialize production models
os.makedirs("models", exist_ok=True)
final_mode = XGBClassifier(n_estimators=100, random_state=42, eval_metric="logloss").fit(X, y_mode)
final_crypto = XGBClassifier(n_estimators=100, random_state=42, eval_metric="mlogloss").fit(X, y_crypto)
joblib.dump(final_mode, "models/xgb_mode_classifier.pkl")
joblib.dump(final_crypto, "models/xgb_crypto_classifier.pkl")
joblib.dump(le_mode, "models/le_mode.pkl")
joblib.dump(le_crypto, "models/le_crypto.pkl")

# -------------------------------------------------------------------------
# 4. Feature Ablation Study (Finding 6 & 9)
# -------------------------------------------------------------------------
print("\n" + "=" * 78)
print("2. SYSTEMATIC FEATURE ABLATION STUDY")
print("=" * 78)

ablation_configs = {
    "1. Full Feature Set": feature_cols,
    "2. No Entropy Family": [c for c in feature_cols if "entropy" not in c],
    "3. No Packet Lengths": [c for c in feature_cols if "len" not in c],
    "4. No IAT (Timing)": [c for c in feature_cols if "iat" not in c],
    "5. Entropy Only": [c for c in feature_cols if "entropy" in c]
}

ablation_rows = []
for name, cols in ablation_configs.items():
    scores = []
    for tr_idx, te_idx in sgkf.split(X[cols], y_crypto, groups):
        clf = XGBClassifier(n_estimators=100, random_state=42, eval_metric="mlogloss")
        clf.fit(X[cols].iloc[tr_idx], y_crypto.iloc[tr_idx])
        scores.append(f1_score(y_crypto.iloc[te_idx], clf.predict(X[cols].iloc[te_idx]), average="macro"))
    ablation_rows.append({
        "Configuration": name,
        "Features Used": len(cols),
        "Macro F1": np.mean(scores),
        "Std Dev": np.std(scores)
    })

ablation_df = pd.DataFrame(ablation_rows)
ablation_df.to_csv("data/ablation_results.csv", index=False)
print(ablation_df.to_string(index=False))

# -------------------------------------------------------------------------
# 5. TreeSHAP Feature Attribution (Finding 7 & 8)
# -------------------------------------------------------------------------
print("\n" + "=" * 78)
print("3. TREESHAP EXPLAINABILITY ATTRIBUTION")
print("=" * 78)

X_sample = X.sample(n=min(500, len(X)), random_state=42)
explainer = shap.TreeExplainer(final_crypto)
shap_vals = explainer.shap_values(X_sample)

if isinstance(shap_vals, list):
    mean_abs_shap = np.mean([np.abs(s).mean(axis=0) for s in shap_vals], axis=0)
elif isinstance(shap_vals, np.ndarray) and shap_vals.ndim == 3:
    mean_abs_shap = np.abs(shap_vals).mean(axis=(0, 2))
else:
    mean_abs_shap = np.abs(shap_vals).mean(axis=0)

shap_df = pd.DataFrame({
    "Feature": feature_cols,
    "SHAP_Importance": np.array(mean_abs_shap).flatten()
}).sort_values(by="SHAP_Importance", ascending=False)
print(shap_df.to_string(index=False))

os.makedirs("figures", exist_ok=True)
plt.figure(figsize=(10, 6))
if isinstance(shap_vals, np.ndarray) and shap_vals.ndim == 3:
    shap.summary_plot(shap_vals[:, :, 0], X_sample, show=False)
else:
    shap.summary_plot(shap_vals, X_sample, show=False)
plt.tight_layout()
plt.savefig("figures/shap_summary.png", dpi=300)
print("[+] Figures saved: figures/shap_summary.png")

# -------------------------------------------------------------------------
# 6. Stateless Anomaly Engine (Finding 8)
# -------------------------------------------------------------------------
print("\n" + "=" * 78)
print("4. STATELESS ANOMALY DETECTION ENGINE (Isolation Forest)")
print("=" * 78)

base_df = df[df["session_id"].str.contains("scenario_A1", case=False)][feature_cols]
if len(base_df) > 0:
    iso = IsolationForest(contamination=0.05, random_state=42).fit(base_df)
    sim_replay = base_df.copy().iloc[:30]
    sim_replay["mean_iat"] = 0.00001
    sim_replay["std_iat"] = 0.0
    sim_replay["std_len"] = 0.0

    t95 = np.percentile(-iso.score_samples(base_df), 95)
    r_scores = -iso.score_samples(sim_replay)
    det_rate = (np.sum(r_scores > t95) / len(sim_replay)) * 100
    print(f"  - Compliant Baseline Samples  : {len(base_df)}")
    print(f"  - 95th Percentile Anomaly Cut : {t95:.4f}")
    print(f"  - Replay Attack Flagging Rate : {det_rate:.1f}%")
    joblib.dump(iso, "models/isolation_forest_anomaly.pkl")
else:
    print("  [WARN] Scenario A1 baseline not found in dataset for anomaly training.")

# -------------------------------------------------------------------------
# 7. Wire-Speed Runtime Benchmark (Finding 11)
# -------------------------------------------------------------------------
print("\n" + "=" * 78)
print("5. COMPUTATIONAL PROFILING & WIRE-SPEED THROUGHPUT")
print("=" * 78)

dummy_payload = np.random.randint(0, 256, size=1400, dtype=np.uint8).tobytes()
t0 = time.time()
n_trials = 10000
for _ in range(n_trials):
    _ = calculate_shannon_entropy(dummy_payload)
elapsed = time.time() - t0
pps = n_trials / elapsed

dummy_features = X.iloc[[0]]
t0 = time.time()
for _ in range(2000):
    _ = final_crypto.predict(dummy_features)
latency_ms = ((time.time() - t0) / 2000) * 1000

print(f"  - Byte Shannon Entropy Throughput : {pps:,.0f} Packets/Second (PPS)")
print(f"  - ML Decision Latency per Window  : {latency_ms:.4f} ms")
print("=" * 78)
print("[+] FULL EVALUATION RUN COMPLETED SUCCESSFULLY.")
print("=" * 78)
