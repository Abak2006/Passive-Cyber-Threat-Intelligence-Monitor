# AEGIS — AI-Powered Passive Cyber Threat Intelligence

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests Passing](https://img.shields.io/badge/tests-50%2F50%20passing-brightgreen.svg)]()
[![Enclave Security](https://img.shields.io/badge/mode-unidirectional%20passive-success.svg)]()

> **AEGIS: AI-Powered Passive Cyber Threat Intelligence Platform**  
> An autonomous, explainable Intrusion Detection and Threat Intelligence system designed for critical-infrastructure networks monitored via physical hardware data diodes and optical taps.

---

## 1. Problem Statement

In critical-infrastructure networks (defense enclaves, industrial control systems, energy grids, and air traffic control), network isolation is the first line of defense. High-security environments require an AI-based detection system capable of monitoring IP traffic mirrored across a **unidirectional data diode** or **passive optical splitter**.

Because the monitoring enclave has **NO transmission path** back to the production network:
1. Traffic is strictly **read-only**.
2. The monitoring engine **cannot send packets**, probe hosts, complete handshakes, or transmit TCP resets.
3. The monitoring engine **cannot issue firewall / blocking commands** (passive IDS / Threat Intelligence, **NOT an IPS**).
4. The system **must not decrypt TLS or QUIC payloads** (metadata and flow dynamics only).
5. The system must process traffic **incrementally in near-real-time** rather than in batch post-processing.
6. The system must produce **structured, explainable alerts** with confidence ratings and forensic evidence.

---

## 2. Why Unidirectional Monitoring Matters

Traditional network security appliances (firewalls, active scanners, inline IPS) operate bidirectionally. If a monitoring tool is compromised, an adversary can pivot through its management interface into the core production network.

In a **unidirectional architecture**, a hardware data diode (such as a fiber-optic cable with the transmit photodiode physically removed on the receiving end) creates an absolute physical law of one-way data travel:

```text
       PRODUCTION NETWORK                       MONITORING ENCLAVE
  ┌───────────────────────────┐             ┌─────────────────────────┐
  │ Core Switches & Servers   │             │ AEGIS Threat Intelligence│
  │ (High Security OT/Gov)    │             │ (Isolated Enclave)      │
  └─────────────┬─────────────┘             └────────────▲────────────┘
                │                                        │
                │ [Passive Optical Splitter]             │
                └───────────────────►────────────────────┘
                          Physical One-Way Fiber
                          (Tx -> Rx ONLY)
                          NO RETURN PATH POSSIBLE
```

Because the enclave cannot talk back, threat detection must rely entirely on **passive metadata extraction**, **stateful flow dynamics**, and **explainable statistical/AI models**.

---

## 3. Logical Architecture

```text
                  TRAFFIC SOURCE (PCAP / Passive Tap)
                                   │
                                   ▼ [One-Way Passive Ingress]
                      ┌──────────────────────────┐
                      │    Read-Only Ingest      │
                      │ (Streaming PCAP Reader)  │
                      └────────────┬─────────────┘
                                   │
                                   ▼
                      ┌──────────────────────────┐
                      │ Stateful Flow Assembler  │
                      │ (Sliding-Window Manager) │
                      └────────────┬─────────────┘
                                   │
                                   ▼
                      ┌──────────────────────────┐
                      │  Passive Feature Engine  │
                      │ Flow / DNS / TLS / Timing│
                      └────────────┬─────────────┘
                                   │
       ┌───────────────────────────┼───────────────────────────┐
       ▼                           ▼                           ▼
 ┌───────────┐               ┌───────────┐               ┌───────────┐
 │   DDoS    │               │  Botnet   │               │    DGA    │
 │ Detector  │               │ Beaconing │               │ Classifier│
 └─────┬─────┘               └─────┬─────┘               └─────┬─────┘
       │                           │                           │
       ▼                           ▼                           ▼
 ┌───────────┐               ┌───────────┐               ┌───────────┐
 │DNS Tunnel │               │ Encrypted │               │ Recon &   │
 │ Detector  │               │  Traffic  │               │ Port Scan │
 └─────┬─────┘               └─────┬─────┘               └─────┬─────┘
       │                           │                           │
       └───────────────────────────┼───────────────────────────┘
                                   ▼
                             ┌───────────┐
                             │Exfiltrate │
                             │ Detector  │
                             └─────┬─────┘
                                   │
                                   ▼
                      ┌──────────────────────────┐
                      │   Threat Fusion Engine   │
                      │ Multi-vector correlation │
                      │ & Confidence/Severity map│
                      └────────────┬─────────────┘
                                   │
                      ┌──────────────────────────┐
                      │  Standard Alert Emitter  │
                      └────────────┬─────────────┘
                                   │
                   ┌───────────────┴───────────────┐
                   ▼                               ▼
            ┌───────────────┐               ┌─────────────┐
            │ SQLite (WAL)  │               │ FastAPI REST│
            │ Alert/Metrics │               │ API Server  │
            └───────┬───────┘               └──────┬──────┘
                    └───────────────┬──────────────┘
                                    ▼
                        ┌───────────────────────┐
                        │  Streamlit Dashboard  │
                        │ Real-Time Threat SOC  │
                        └───────────────────────┘
```

---

## 4. Threats That Are Detected

| Category | Detected Threats | Key Signals & Methodology |
| :--- | :--- | :--- |
| **A. Volumetric & Protocol DDoS** | SYN floods, UDP floods, amplification, spoofed-source floods | `syn_rate`, `udp_rate`, `source_entropy`, `syn_ack_ratio`, Random Forest classifier |
| **B. Botnet C2 Beaconing** | Periodic heartbeats, polling loops, jittered implants | Inter-Arrival Time (IAT), $CV < 0.25$, autocorrelation, jitter tolerance |
| **C. DGA Domain Detection** | Algorithmic pseudo-random domains (e.g. `x7k29a8d91.com`) | Shannon entropy, length, digit ratio, consonant clusters, Random Forest lexical model |
| **D. DNS Tunnelling** | Data exfiltration over DNS, covert command channels | Subdomain length $> 24$, subdomain entropy $> 3.75$, query frequency, TXT record ratio |
| **E. Suspicious Encrypted Traffic** | C2 implants & malware in TLS/QUIC (**NO DECRYPTION**) | JA3/JA4 representation, SPLT (Sequence of Packet Lengths and Times), outbound/inbound ratio |
| **F. Recon & Port Scanning** | Horizontal scans, vertical scans, broad sweeps | Unique destination hosts/ports, SYN-only flows, connection rate, destination entropy |
| **G. Data Exfiltration** | Large unauthorized outbound transfers, bulk dumps | Outbound/inbound ratio $> 6.0$, sustained upload rate, Isolation Forest anomaly model |

---

## 5. Feature Engineering Catalog

- **Flow Dynamics**: Duration, packets/sec, bytes/sec, forward/backward bytes, TCP flag ratios (`syn_ack_ratio`, `is_syn_only`).
- **Timing & Dispersion**: Mean IAT, standard deviation of IAT, Coefficient of Variation ($CV = \sigma / \mu$), lag-1 autocorrelation periodicity score.
- **DNS Lexical & Structural**: Shannon entropy, domain length, digit/vowel/consonant ratios, max consonant cluster, subdomain entropy, record types.
- **TLS/QUIC Passive Metadata**: Unencrypted Client Hello parsing (JA3 MD5 hash, JA4 string representation, cipher suite count, extension count, SNI presence/length) and SPLT early packet statistics.
- **Distribution Entropy**: Categorical Shannon entropy across source IPs (spoofed DDoS detection) and destination ports (scan detection).

---

## 6. Machine Learning Models & Training

The prototype uses a **hybrid architecture** combining deterministic statistical rules and machine learning:
1. **DDoS Protocol Classifier**: Random Forest (`n_estimators=100`, `max_depth=8`) trained on flow rates and flag ratios.
2. **DGA Lexical Classifier**: Random Forest (`n_estimators=120`, `max_depth=10`) trained on lexical n-gram and entropy metrics.
3. **Encrypted Anomaly Classifier**: Random Forest (`n_estimators=100`, `max_depth=8`) trained on SPLT metrics and metadata.
4. **Exfiltration Anomaly Detector**: Isolation Forest (`contamination=0.08`) trained on flow byte distributions.

### Training Command:
```bash
python -m training.train --detector all
```

---

## 7. Dataset Setup & Strategy

The repository **does not require downloading massive datasets** to run:
- **Instant Out-of-the-Box Demo**: `training/generate_synthetic.py` deterministically creates realistic training sets and a complete multi-threat PCAP (`data/sample/demo.pcap`) in seconds.
- **Public Dataset Adapters**: Pre-built adapters in `training/dataset_adapters/` support:
  - `CIC-IDS2017` & `CIC-DDoS2019`
  - `BoT-IoT`
  - `CIC-Bell-DNS2021` & DGA feeds

---

## 8. Incremental Streaming & Replay Engine

Rather than batch-processing completed PCAP files, the engine processes traffic incrementally:
```text
Packet arrives -> Assemble flow -> Update sliding windows -> Run detectors -> Fuse threats -> Emit alert
```

### Replay Commands:
```bash
# Replay sample PCAP in real time (1x speed):
python -m app.replay --pcap data/sample/demo.pcap --speed 1.0

# Replay at 5x accelerated speed:
python -m app.replay --pcap data/sample/demo.pcap --speed 5.0

# Replay at maximum possible throughput:
python -m app.replay --pcap data/sample/demo.pcap --speed 0.0
```

---

## 9. Standard Alert Schema

Every emitted alert adheres to the strict AEGIS JSON schema:

```json
{
  "timestamp": "2026-09-15T18:20:15Z",
  "flow_id": "TCP:10.0.0.15:42123<->10.0.0.50:80",
  "src_ip": "10.0.0.15",
  "src_port": 42123,
  "dst_ip": "10.0.0.50",
  "dst_port": 80,
  "protocol": "TCP",
  "threat_class": "SYN_FLOOD",
  "severity": "CRITICAL",
  "confidence": 0.9712,
  "detector": "ddos_detector",
  "evidence": {
    "syn_rate": 82400.0,
    "unique_sources": 18231,
    "source_entropy": 13.2,
    "syn_ack_ratio": 240.5
  }
}
```

### Multi-Detector Composite Threat Alerts:
When correlated signals coincide, the Threat Fusion Engine synthesizes composite threats:
- `SUSPICIOUS_ENCRYPTED_TRAFFIC` + `DATA_EXFILTRATION` $\rightarrow$ `POSSIBLE_ENCRYPTED_EXFILTRATION`
- `DGA_DOMAIN_DETECTION` + `BOTNET_C2_BEACONING` $\rightarrow$ `BOTNET_C2_INFRASTRUCTURE`

---

## 10. Dashboard

The interactive Streamlit dashboard provides:
- **Live KPI Cards**: Total flows processed, current flows/second, total alerts, critical and high threat counts.
- **Real-Time Traffic Graph**: Plotly timeline of ingestion and flow processing rates.
- **Threat Distribution Chart**: Donut chart categorizing alerts across all 7 threat classes.
- **Alert Log Table**: Filterable by severity tier (CRITICAL, HIGH, MEDIUM, LOW) and threat category.
- **Forensic Evidence Inspector**: Drill-down view displaying the full structured evidence dictionary and 5-tuple for any selected alert.

```bash
streamlit run dashboard/streamlit_app.py
```

---

## 11. Security Constraints & Passivity Verification

The prototype includes an automated codebase test (`tests/test_passive_guarantee.py`) proving:
- **Zero active socket transmissions** (`no send`, `sendto`, `sendall`, `scapy.send`, `scapy.srp`).
- **Zero active network probing** (`no ping`, `traceroute`, `nmap`).
- **Zero automated firewall rules / blocking** (`no iptables`, `nftables`, `netsh`).
- **Zero payload decryption** (`no private key parsing`, `no SSL key logging`).

---

## 12. Measured Throughput Benchmarking

Execute the benchmark suite:
```bash
# Single benchmark run:
python -m app.benchmark --pcap data/sample/demo.pcap --duration 10

# Multi-speed sweep (1x, 2x, 5x, 10x, max):
python -m app.benchmark --sweep --duration 3
```

### Actual Measured Results (Replay Rate Sweep on Host):
```text
==============================================================================
                   AEGIS REPLAY RATE SWEEP SUMMARY
==============================================================================
Rate       | Pkts/s       | Flows/s      | P50 (ms)   | P95 (ms)   | RSS (MB)  
------------------------------------------------------------------------------
1.0x       | 13.7         | 12.8         | 25.081     | 42.737     | 194.7     
2.0x       | 16.1         | 14.4         | 11.041     | 20.655     | 196.6     
5.0x       | 24.9         | 17.1         | 19.733     | 40.059     | 198.4     
10.0x      | 43.1         | 17.1         | 11.705     | 27.484     | 199.8     
max (raw)  | 88.1         | 35.9         | 22.033     | 54.419     | 201.7     
==============================================================================
```
*Full technical details and methodology available in [docs/upgrade_report.md](docs/upgrade_report.md).*

---

## 13. Quickstart & Demo Walkthrough

### 1. Installation
```bash
# Clone the repository
git clone https://github.com/Abak2006/Passive-Cyber-Threat-Intelligence-Monitor.git
cd Passive-Cyber-Threat-Intelligence-Monitor

# Install Python requirements
pip install -r requirements.txt
```

### 2. Setup Models & Datasets
```bash
# One-step generation of synthetic datasets, demo PCAP, and trained models:
python -m training.generate_synthetic
python -m training.train --detector all
```

### 3. Run Automated Tests
```bash
python -m pytest tests/ -v
```

### 4. Run the Live Demo
**Windows:**
```cmd
scripts\run_demo.bat
```
**Linux / macOS:**
```bash
chmod +x scripts/*.sh
./scripts/run_demo.sh
```

---

## 14. Real-World Limitations

1. **Passive Observation Boundary**: Cannot drop packets inline or reset connections; alerts must be consumed by external security teams or out-of-band automation.
2. **Encrypted Payload Opacity**: When attackers use custom padding and randomized timing jitter, passive statistical inference becomes probabilistic rather than deterministic.
3. **Fingerprint Collisions**: JA3/JA4 hashes are not proof of malware; common development runtimes or browsers share identical fingerprints, requiring behavioral corroboration.
4. **Buffer Sizing**: In Gigabit/10G physical diode taps, hardware NIC buffer overruns can drop frames if not coupled with kernel bypass (DPDK / AF_XDP).

---

## 15. Future Work

- **DPDK / AF_XDP Kernel Bypass Driver**: Ingestion speeds $> 1,000,000$ packets/sec on 10 Gbps fiber diodes.
- **QUIC Connection ID Tracking**: Enhancing UDP/443 QUIC handshake state tracking.
- **PostgreSQL / TimescaleDB Integration**: Production database adapter for archiving billions of flow records.
- **Kafka / ZeroMQ Broker Ingest**: Distributed streaming pipeline across multiple passive capture probes.
