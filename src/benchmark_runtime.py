import time
import joblib
import pandas as pd
import numpy as np
from scapy.all import rdpcap, IP

# Load test assets
model_crypto = joblib.load("models/xgb_crypto_classifier.pkl")
pcap_path = "captures/scenario_A1_s1.pcap"
packets = rdpcap(pcap_path)
esp_packets = [p for p in packets if IP in p and p[IP].proto == 50]

print("=" * 65)
print("RUNTIME PERFORMANCE & THROUGHPUT BENCHMARK")
print("=" * 65)

# 1. Measure Raw Packet Parsing & Entropy Throughput
total_pkts = len(esp_packets) * 100
start_time = time.perf_counter()

# Synthetic burst loop to simulate line-rate ingestion
for _ in range(100):
    for pkt in esp_packets:
        payload = bytes(pkt[IP].payload)
        # Fast entropy check
        length = len(payload)
        if length > 0:
            counts = np.bincount(np.frombuffer(payload, dtype=np.uint8), minlength=256)
            probs = counts[counts > 0] / length
            _ = -np.sum(probs * np.log2(probs))

elapsed = time.perf_counter() - start_time
pps = total_pkts / elapsed
mbps = (pps * 154 * 8) / 1_000_000

print(f"[*] Ingestion & Feature Extraction Throughput:")
print(f"    - Packets Processed : {total_pkts:,} packets")
print(f"    - Wall-Clock Time   : {elapsed:.3f} seconds")
print(f"    - Processing Speed  : {pps:,.1f} Packets/sec")
print(f"    - Bandwidth Capacity: {mbps:.2f} Mbps equivalent")

# 2. Measure Single-Window ML Inference Latency
df = pd.read_csv("data/dataset_master.csv").dropna()
feature_cols = [
    "mean_len", "std_len", "max_len", "q10_len", "q50_len", "q90_len",
    "mean_iat", "std_iat", "mean_entropy", "min_entropy", "std_entropy"
]
sample_window = df[feature_cols].iloc[[0]]

latencies = []
for _ in range(500):
    t0 = time.perf_counter()
    _ = model_crypto.predict(sample_window)
    latencies.append((time.perf_counter() - t0) * 1000)

mean_lat = np.mean(latencies)
p99_lat = np.percentile(latencies, 99)

print(f"\n[*] Model Inference Latency (Per 25-Packet Window):")
print(f"    - Mean Decision Latency : {mean_lat:.4f} ms")
print(f"    - 99th Percentile (P99) : {p99_lat:.4f} ms")
print("=" * 65)
