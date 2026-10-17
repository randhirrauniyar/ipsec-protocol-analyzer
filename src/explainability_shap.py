import joblib
import pandas as pd
import numpy as np
import shap
import matplotlib.pyplot as plt
import os

# 1. Load dataset and model
df = pd.read_csv("data/dataset_master.csv").dropna()
feature_cols = [
    "mean_len", "std_len", "max_len", "q10_len", "q50_len", "q90_len",
    "mean_iat", "std_iat",
    "mean_entropy", "min_entropy", "std_entropy"
]

X = df[feature_cols]
model_crypto = joblib.load("models/xgb_crypto_classifier.pkl")

# Subsample up to 500 samples for high-speed explainability calculation
sample_size = min(500, len(X))
X_sample = X.sample(n=sample_size, random_state=42)

print(f"[*] Computing TreeSHAP on {sample_size} representative samples...")
explainer = shap.TreeExplainer(model_crypto)
shap_values = explainer.shap_values(X_sample)

# 2. Reshape multi-class SHAP dimensions cleanly to 1D
if isinstance(shap_values, list):
    # Older SHAP multi-class format: list of (N, P)
    mean_abs_shap = np.mean([np.abs(sv).mean(axis=0) for sv in shap_values], axis=0)
elif isinstance(shap_values, np.ndarray) and shap_values.ndim == 3:
    # Modern SHAP format: (N, P, C) -> average over samples (axis 0) and classes (axis 2)
    mean_abs_shap = np.abs(shap_values).mean(axis=(0, 2))
else:
    # Binary format: (N, P)
    mean_abs_shap = np.abs(shap_values).mean(axis=0)

mean_abs_shap = np.array(mean_abs_shap).flatten()

feature_ranking = pd.DataFrame({
    "Feature": feature_cols,
    "SHAP_Importance": mean_abs_shap
}).sort_values(by="SHAP_Importance", ascending=False)

print("\n[+] Top Features Ranked by Mean Absolute SHAP Value:")
print(feature_ranking.to_string(index=False))

# 3. Render and save summary plot
os.makedirs("figures", exist_ok=True)
plt.figure(figsize=(10, 6))

if isinstance(shap_values, np.ndarray) and shap_values.ndim == 3:
    # Use class 0 for clear beeswarm plotting
    shap.summary_plot(shap_values[:, :, 0], X_sample, show=False)
else:
    shap.summary_plot(shap_values, X_sample, show=False)

plt.title("TreeSHAP Feature Importance (IPsec Cipher Classification)", fontsize=12)
plt.tight_layout()
plt.savefig("figures/shap_summary.png", dpi=300)
print("\n[+] Saved SHAP summary plot to figures/shap_summary.png")
