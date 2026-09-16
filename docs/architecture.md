# System Architecture: NTRO Passive Cyber Threat Detection Engine

## 1. Operational Context & Hardware Data Diode Model

In critical-infrastructure networks (defense enclaves, power grids, government communication hubs), security and forensic isolation dictate that internal operational technology (OT) or classified networks must never accept inbound network connections from monitoring systems.

To satisfy this mandate, network traffic is replicated via a **hardware optical splitter (fiber tap)** or **unidirectional hardware data diode** into an isolated monitoring enclave:

```text
  [Production Network Core Switch]
                 │ (Tx / Rx Normal Operations)
                 ▼
         ┌───────────────┐
         │  PASSIVE TAP  │ (Physical Beam Splitter)
         └───────┬───────┘
                 │
                 │ One-way optical signal (Physical Diode)
                 │ [Tx photodiode → Rx photodetector only]
                 ▼
 ┌────────────────────────────────────────────────────────┐
 │            MONITORING ENCLAVE (READ-ONLY)              │
 │                                                        │
 │   Network Interface Card (NIC) in Promiscuous Mode     │
 │   * Transmit pin (Tx) physically disconnected / absent │
 │   * Inbound packets read asynchronously                │
 │   * ZERO return packets, ZERO resets, ZERO ARP replies │
 └────────────────────────────────────────────────────────┘
```

---

## 2. Ingestion Pipeline & Session Assembler

The software pipeline mirrors this physical passivity:

```text
   PCAP / Live Interface Ingest (PcapReader)
                      │
                      ▼
        Canonical 5-Tuple Normalizer
        (Protocol, Min IP:Port <-> Max IP:Port)
                      │
                      ▼
           Stateful Sliding Windows
  ┌───────────────────┼───────────────────┐
  ▼                   ▼                   ▼
Flow Assembler    Host Rate Windows   Domain Windows
(Duration, SPLT)  (SYN & Scan Track)  (DNS Apex Track)
```

1. **Incremental Streaming Ingestion (`app/ingest/pcap_reader.py`)**:
   - Packets are consumed incrementally.
   - Packets are never batched into memory-intensive global arrays, maintaining constant $O(1)$ memory consumption.
2. **Stateful Sliding-Window Flow Assembler (`app/ingest/flow_stream.py`)**:
   - Groups packets by bidirectional canonical flow identifier.
   - Calculates duration, forward vs backward packets, forward vs backward bytes, TCP flags (SYN, ACK, FIN, RST), and inter-packet arrival times.
   - Manages active flow state with configurable timeouts and immediate teardown upon FIN/RST.

---

## 3. Passive Feature Extraction Layer

- **Flow Feature Extractor (`app/features/flow_features.py`)**:
  Calculates rates (pkts/sec, bytes/sec), directional ratios (outbound/inbound), flag ratios (SYN/ACK), and packet size statistics.
- **Timing & Periodicity Extractor (`app/features/timing_features.py`)**:
  Computes consecutive Inter-Arrival Times (IAT), mean $\mu$, standard deviation $\sigma$, Coefficient of Variation ($CV = \sigma / \mu$), and lag-1 autocorrelation for beaconing detection.
- **DNS Feature Extractor (`app/features/dns_features.py`)**:
  Computes Shannon entropy, digit ratio, vowel-to-consonant distribution, consonant clustering, subdomain length, and query type distributions without payload inspection.
- **TLS/QUIC Passive Extractor (`app/features/tls_features.py`)**:
  Extracts unencrypted Client Hello metadata: JA3 hash, JA4 abstraction, TLS record version, cipher suite count, extension count, and Sequence of Packet Lengths and Times (SPLT).

---

## 4. Threat Detectors & Threat Fusion Engine

Seven specialized threat detectors process flow features and sliding-window context:
1. `DDoSDetector`
2. `BeaconingDetector`
3. `DGADetector`
4. `DNSTunnelDetector`
5. `EncryptedTrafficDetector`
6. `ReconDetector`
7. `ExfiltrationDetector`

All detectors produce normalized `DetectionResult` objects.
The **Threat Fusion Engine (`app/fusion/threat_fusion.py`)** correlates multi-vector attacks (e.g. `SUSPICIOUS_ENCRYPTED_TRAFFIC` + `DATA_EXFILTRATION` $\rightarrow$ `POSSIBLE_ENCRYPTED_EXFILTRATION`), boosts confidence, enforces severity mappings, and throttles duplicate alerts.

---

## 5. Persistence, API, and Dashboard

- **SQLite with WAL Mode (`app/storage/database.py`)**:
  High concurrency database engine allowing simultaneous stream writes from the replay engine and real-time read queries from the dashboard and REST API.
- **FastAPI Backend (`app/api/main.py`)**:
  Exposes REST endpoints for alert feeds, system throughput metrics, and health checks.
- **Streamlit Dashboard (`dashboard/streamlit_app.py`)**:
  Interactive analyst workstation with real-time KPI metrics, throughput timeseries graphs, threat distributions, alert tables, and an evidence drill-down inspector.
