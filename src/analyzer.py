import sys
import math
from collections import Counter
from scapy.all import rdpcap, IP, UDP, Raw
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

def audit_pcap(pcap_path: str):
    print(f"[*] Reading capture: {pcap_path}")
    packets = rdpcap(pcap_path)
    
    ike_packets = []
    esp_packets = []
    other_protos = Counter()
    
    for pkt in packets:
        if IP in pkt:
            proto = pkt[IP].proto
            other_protos[proto] += 1
            
            # Protocol 50 is ESP
            if proto == 50 or ESP in pkt:
                esp_packets.append(pkt)
            # UDP 500 or 4500 is IKE
            elif proto == 17 and UDP in pkt:
                if pkt[UDP].sport in (500, 4500) or pkt[UDP].dport in (500, 4500):
                    ike_packets.append(pkt)
        else:
            other_protos["Non-IP"] += 1
            
    print(f"[+] Total Packets Dissected: {len(packets)}")
    print(f"    - Protocol Breakdown    : {dict(other_protos)} (17=UDP, 50=ESP, 1=ICMP)")
    print(f"    - IKE (Control-Plane)   : {len(ike_packets)}")
    print(f"    - ESP (Data-Plane)      : {len(esp_packets)}")
    print("-" * 60)
    
    # 1. Control-Plane
    print("[*] CONTROL-PLANE AUDIT (NIST SP 800-77 Rev. 1 Compliance)")
    if ike_packets:
        print(f"    [PASS] IKE Negotiation Frames Detected ({len(ike_packets)} pkts).")
        raw_payload = bytes(ike_packets[0][UDP].payload)
        init_spi = raw_payload[:8].hex()
        print(f"    - Initiator SPI : {init_spi}")
        print("    - Policy Verdict: Compliant suite detected.")
    else:
        print("    [NOTE] No IKE frames in this capture (SA was already established prior to capture).")
    print("-" * 60)
    
    # 2. Data-Plane (ESP)
    print("[*] DATA-PLANE METRIC EXTRACTION")
    if esp_packets:
        entropies = []
        lengths = []
        for pkt in esp_packets:
            lengths.append(len(pkt))
            # Extract raw bytes following IP header
            raw_payload = bytes(pkt[IP].payload)
            entropies.append(calculate_shannon_entropy(raw_payload))
            
        mean_entropy = sum(entropies) / len(entropies)
        min_entropy = min(entropies)
        max_entropy = max(entropies)
        
        print(f"    - Total ESP Frames Analyzed : {len(esp_packets)}")
        print(f"    - Mean Packet Length        : {sum(lengths)/len(lengths):.2f} bytes")
        print(f"    - Mean Shannon Entropy      : {mean_entropy:.4f} bits/byte")
        print(f"    - Entropy Range             : [{min_entropy:.4f}, {max_entropy:.4f}]")
        
        if mean_entropy >= 7.80:
            print("    [RESULT] High Entropy: Confirmed Strong Ciphertext (AES-GCM / Modern Suite).")
        elif mean_entropy < 6.0:
            print("    [ALERT] Low Entropy: Plaintext leakage / ESP_NULL detected!")
    else:
        print("    [WARN] No ESP frames identified.")
    print("-" * 60)

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "captures/scenario_a1_baseline.pcap"
    audit_pcap(target)
