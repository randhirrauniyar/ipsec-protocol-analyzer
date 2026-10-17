import os
import glob
import pandas as pd

print("=" * 65)
print("       SUPERVISORY MILESTONE VALIDATION AUDIT")
print("=" * 65)

# 1. PCAP Captures
pcaps = glob.glob("captures/*.pcap")
print(f"[x] PCAP Captures Generated  : {len(pcaps)} files")

# 2. Master Dataset
df = pd.read_csv("data/dataset_master.csv")
print(f"[x] Master Dataset Volume    : {len(df):,} windowed samples")
sessions = df["session_id"].nunique()
print(f"[x] Independent Sessions     : {sessions}")

# 3. Serialized Models
models = glob.glob("models/*.pkl")
print(f"[x] Serialized Models (.pkl) : {len(models)} artifacts")
for m in sorted(models):
    print(f"    - {os.path.basename(m)}")

# 4. Tables and Figures
f_scenarios = os.path.exists("data/scenarios.csv")
f_ablation = os.path.exists("data/ablation_results.csv")
f_shap = os.path.exists("figures/shap_summary.png")

print(f"[x] Scenarios Registry       : {f_scenarios}")
print(f"[x] Ablation Table           : {f_ablation}")
print(f"[x] SHAP Visualization Plot  : {f_shap}")
print("=" * 65)
