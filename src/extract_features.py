import os
import glob
import math
import numpy as np
import pandas as pd
from collections import Counter
from scapy.all import rdpcap, IP
from scapy.layers.ipsec import ESP

def calculate_shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    counts = Counter(data)
    for count in counts.values():
        p_x = count / length
        entropy -= p_x * math.log2(p_x)
    return entropy

def extract_features_from_pcap(pcap_path, window_size=25):
    filename = os.path.basename(pcap_path)
    session_id = filename.replace(".pcap", "")
    fn_lower = filename.lower()

    # Ground truth mapping across all 6 scenario profiles
    if "scenario_a1" in fn_lower or "scenario_a2" in fn_lower:
        label_mode = "tunnel"
        label_crypto = "AEAD_GCM"
    elif "scenario_b1" in fn_lower:
        label_mode = "transport"
        label_crypto = "CBC"
    elif "scenario_b2" in fn_lower:
        label_mode = "tunnel"
        label_crypto = "CBC"
    elif "scenario_c" in fn_lower:
        label_mode = "tunnel"
        label_crypto = "NULL"
    elif "scenario_d" in fn_lower:
        label_mode = "tunnel"
        label_crypto = "3DES_LEGACY"
    else:
        return []

    try:
        packets = rdpcap(pcap_path)
    except Exception as e:
        print(f"[!] Error reading {pcap_path}: {e}")
        return []

    esp_packets = [pkt for pkt in packets if IP in pkt and (pkt[IP].proto == 50 or ESP in pkt)]
    if len(esp_packets) < window_size:
        return []

    records = []
    # 50% overlap sliding window
    step = max(1, window_size // 2)
    for i in range(0, len(esp_packets) - window_size + 1, step):
        chunk = esp_packets[i:i + window_size]

        lengths = [len(p) for p in chunk]
        times = [float(p.time) for p in chunk]
        iats = np.diff(times) if len(times) > 1 else [0.0]

        entropies = [calculate_shannon_entropy(bytes(p[IP].payload)) for p in chunk]

        records.append({
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
    return records

def main():
    pcap_files = sorted(glob.glob("captures/*.pcap"))
    print(f"[*] Processing {len(pcap_files)} PCAP files across 6 scenarios...")

    all_records = []
    total_packets = 0
    scenarios_catalog = []

    for pcap in pcap_files:
        pkts = rdpcap(pcap)
        total_packets += len(pkts)
        records = extract_features_from_pcap(pcap, window_size=25)
        all_records.extend(records)
        scenarios_catalog.append({
            "pcap_file": os.path.basename(pcap),
            "total_packets": len(pkts),
            "windowed_samples": len(records)
        })

    pd.DataFrame(scenarios_catalog).to_csv("data/scenarios.csv", index=False)
    df = pd.DataFrame(all_records)
    df.to_csv("data/dataset_master.csv", index=False)

    print("=" * 65)
    print(f"[+] Total Ingested Packets : {total_packets:,}")
    print(f"[+] Total Windowed Samples  : {len(df):,}")
    print(f"[+] Saved Scenarios Registry: data/scenarios.csv")
    print(f"[+] Saved Master Dataset    : data/dataset_master.csv")
    print("=" * 65)
    print("\nSamples per Class:")
    print(df.groupby(["label_mode", "label_crypto"]).size())

if __name__ == "__main__":
    main()
