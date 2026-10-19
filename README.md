# AI-Powered IPsec Protocol Analyzer

[![Python 3.14 (64-bit)](https://img.shields.io/badge/python-3.14-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Compliance](https://img.shields.io/badge/NIST-SP%20800--77%20Rev.%201-green.svg)](#control-plane-compliance)

An automated dual-plane security auditing and assessment platform for IPsec Virtual Private Networks (VPNs). It combines deterministic IKEv2 control-plane compliance checks with zero-decryption statistical machine learning (XGBoost, Random Forest, Isolation Forest, TreeSHAP) to audit host security policies, classify encapsulated ESP traffic, and identify cryptographic misconfigurations.

> **Scope Note:** Designed as an AI-assisted security assessment tool to help identify risky VPN patterns, misconfigurations, and plaintext leaks—not as an automated certification authority.

---

## Key Features

- **Host-Centric System Audit (`--audit-host`):** Inspects the host OS directly (Windows NetTCPIP/Firewall IPsec rules and active SAs, or Linux kernel XFRM states via `ip xfrm state/policy`) to audit active VPN configurations without needing PCAP files.
- **Control-Plane Auditing (IKEv2):** Parses unencrypted `IKE_SA_INIT` handshakes to flag deprecated cryptographic algorithms (3DES, MD5, Diffie-Hellman groups < 14) against NIST SP 800-77 Rev. 1 guidelines.
- **Data-Plane Zero-Decryption Inference (ESP):** Classifies tunnel encapsulation mode (Tunnel vs. Transport) and cryptographic suite family (AEAD-GCM vs. CBC vs. Plaintext) purely from packet size quantiles, entropy distributions, and inter-arrival timing.
- **Live Interface Sniffing (`--live`):** Sniffs real-time network adapters (Wi-Fi/Ethernet) for active IPsec traffic (UDP 500, 4500, Protocol 50 ESP) and feeds frames into the inference engine.
- **Stateless Anomaly & Leak Detection:** Flags `ESP_NULL` plaintext leakage via Shannon entropy drop-offs (< 5.0 bits/byte) and catches sequence anomalies or replay bursts using an Isolation Forest baseline.
- **Leakage-Free Cross-Validation:** Validated using `StratifiedGroupKFold` across 30 independent session boundaries to eliminate intra-flow temporal data leakage.
- **Wire-Speed Feasibility:** Sub-millisecond window inference latency (< 0.05 ms) on commodity hardware.

---

## Quick Start

### 1. Clone & Set Up Environment

```bash
git clone [https://github.com/randhirrauniyar/ipsec-protocol-analyzer.git](https://github.com/randhirrauniyar/ipsec-protocol-analyzer.git)
cd ipsec-protocol-analyzer