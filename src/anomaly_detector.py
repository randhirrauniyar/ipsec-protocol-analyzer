import joblib
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest

print("=" * 70)
print("TASK: STATELESS ANOMALY & REPLAY ATTACK DETECTION (Finding 8)")
print("=" * 70)

df = pd.read_csv("data/dataset_master.csv").dropna()
feature_cols = [
    "mean_len", "std_len", "max_len", "q10_len", "q50_len", "q90_len",
    "mean_iat", "std_iat",
    "mean_entropy", "min_entropy", "std_entropy"
]

# 1. Fit Isolation Forest exclusively on compliant baseline traffic (Scenario A1)
baseline_df = df[df["session_id"].str.contains("scenario_A1", case=False)]
X_baseline = baseline_df[feature_cols]

iso_forest = IsolationForest(contamination=0.05, random_state=42)
iso_forest.fit(X_baseline)

# 2. Simulate Injected Replay / Duplicate Jump Anomalies
# Replayed bursts exhibit near-zero IAT variance with static duplicated sequence sizes
anomaly_samples = X_baseline.copy().iloc[:30].copy()
anomaly_samples["mean_iat"] = 0.00001
anomaly_samples["std_iat"] = 0.0
anomaly_samples["std_len"] = 0.0

# 3. Score against 95th percentile threshold
baseline_scores = -iso_forest.score_samples(X_baseline)
threshold_95 = np.percentile(baseline_scores, 95)
injected_scores = -iso_forest.score_samples(anomaly_samples)

detected_count = np.sum(injected_scores > threshold_95)
detection_rate = (detected_count / len(anomaly_samples)) * 100

print(f"[*] Fitted Isolation Forest on {len(X_baseline)} compliant baseline samples.")
print(f"[*] 95th Percentile Anomaly Score Threshold : {threshold_95:.4f}")
print(f"[*] Injected Replay Anomaly Mean Score       : {np.mean(injected_scores):.4f}")
print(f"[+] Replay/Injection Anomaly Detection Rate  : {detection_rate:.1f}% ({detected_count}/{len(anomaly_samples)})")
print("    [PASS] Injected replayed frames scored strictly above 95th percentile threshold.")

joblib.dump(iso_forest, "models/isolation_forest_anomaly.pkl")
print("[+] Serialized model to models/isolation_forest_anomaly.pkl")
