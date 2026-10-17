# AI-Powered IPsec Protocol Analyzer

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Compliance](https://img.shields.io/badge/NIST-SP%20800--77%20Rev.%201-green.svg)](#control-plane-compliance)

An automated dual-plane security auditing platform for IPsec Virtual Private Networks (VPNs). It combines deterministic IKEv2 control-plane compliance checks with zero-decryption statistical machine learning (XGBoost, TreeSHAP, Isolation Forest) to classify encapsulated ESP traffic and detect cryptographic misconfigurations.

---

## Key Features

- **Control-Plane Auditing (IKEv2):** Deterministically parses unencrypted \IKE_SA_INIT\ handshakes to flag deprecated cryptographic algorithms (3DES, MD5, Diffie-Hellman groups < 14) against NIST SP 800-77 Rev. 1 guidelines.
- **Data-Plane Zero-Decryption Inference (ESP):** Classifies tunnel encapsulation mode (Tunnel vs. Transport) and cryptographic suite family (AEAD-GCM vs. CBC vs. Plaintext) purely from packet size quantiles, entropy distributions, and inter-arrival timing.
- **Stateless Anomaly & Leak Detection:** Identifies \ESP_NULL\ plaintext leakage via Shannon entropy drop-offs (< 5.0 bits/byte) and catches sequence anomalies or replay bursts using an Isolation Forest baseline.
- **Leakage-Free Cross-Validation:** Uses \StratifiedGroupKFold\ across 30 independent session boundaries to eliminate intra-flow temporal data leakage.
- **Wire-Speed Feasibility:** Sub-millisecond window inference latency (< 0.05 ms) and high packet parsing throughput on commodity hardware.

---

## Quick Start

### 1. Clone & Set Up Environment

\\\ash
git clone https://github.com/randhirrauniyar/ipsec-protocol-analyzer.git
cd ipsec-protocol-analyzer
\\\

**On Linux / macOS:**
\\\ash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
\\\

**On Windows (PowerShell):**
\\\powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
\\\

---

## Usage

### Run Live Zero-Decryption Scanner on a PCAP

Analyze a compliant enterprise VPN session (AES-GCM):
\\\ash
python src/ipsec_scanner.py captures/scenario_A1_s1.pcap
\\\

Analyze an insecure \ESP_NULL\ misconfiguration (plaintext leak):
\\\ash
python src/ipsec_scanner.py captures/scenario_C_s1.pcap
\\\

### Reproduce Empirical Findings & Benchmarks

Verify all 11 empirical findings reported in the evaluation:
\\\ash
python verify_11_findings.py
\\\

Run full model retraining, feature ablation, and TreeSHAP attribution:
\\\ash
python run_complete_evaluation.py
\\\

---

## Repository Structure

\\\	ext
+-- captures/               # Pre-recorded multi-scenario PCAP datasets
+-- data/                   # Extracted tabular feature sets and ablation logs
+-- figures/                # TreeSHAP summary plots and evaluation curves
+-- models/                 # Pre-trained models (XGBoost, Isolation Forest, scalers)
+-- scripts/                # strongSwan testbed orchestration scripts
+-- src/
¦   +-- ipsec_scanner.py    # Zero-decryption PCAP analysis CLI tool
¦   +-- extract_features.py # Windowed feature extraction engine
¦   +-- train_models.py     # Cross-validated training pipeline
¦   +-- anomaly_detector.py # Isolation Forest replay detection engine
¦   +-- explainability_shap.py # TreeSHAP attribution generator
+-- verify_11_findings.py   # Empirical verification test suite
+-- run_complete_evaluation.py # End-to-end benchmark pipeline
+-- requirements.txt        # Cross-platform dependencies
\\\

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
