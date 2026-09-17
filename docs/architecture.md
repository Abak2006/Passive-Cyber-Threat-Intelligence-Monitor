# System Architecture: AEGIS Passive Cyber Threat Intelligence Platform

## 1. Operational Context & Hardware Data Diode Model

In critical-infrastructure networks (defense enclaves, power grids, nuclear facilities, government communication hubs), security and forensic isolation dictate that internal operational technology (OT) or classified networks must never accept inbound network connections from monitoring systems.

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

### Hardware Data Diode vs. Software Adapter Boundary

It is vital to maintain engineering clarity regarding the hardware-software boundary:
- **Physical Hardware Data Diode**: A hardware-enforced appliance utilizing unidirectional physical transmission (e.g. an LED or laser transmitter coupled to a photodiode receiver with no reverse optical fiber). Physical physics prevents any electrical or optical signal from flowing back. Software cannot manufacture or simulate physical diode physics.
- **Software Receive Adapter (`DataDiodeFeedSource`)**: Operates on the receiving side within the isolated monitoring enclave. The software binds strictly to the host's passive ingest interface (or raw socket stream) in receive-only mode. It contains **zero transmission methods** (`send`, `sendto`, `sendp`, `connect`), zero probing logic, and zero firewall reconfiguration routines.

---

## 2. Ingestion Pipeline & Passive Input Sources

AEGIS implements a unified `PassiveInputSource` hierarchy (`app/ingest/sources.py`) providing polymorphic packet streaming while enforcing passive guarantees across all input types:

```text
                     PassiveInputSource (Base Interface)
                                      │
         ┌────────────────────────────┼────────────────────────────┐
         ▼                            ▼                            ▼
  PcapReplaySource          SyntheticStreamSource        DataDiodeFeedSource
(Timestamp-paced PCAP)     (In-Memory Attack Engine)    (Receive-Only NIC Tap)
```

1. **`PcapReplaySource`**:
   - Replays captured PCAP traces using recorded packet arrival deltas.
   - Supports configurable speed multipliers (`1x`, `2x`, `5x`, `10x`, and unthrottled `max`).
   - Packets are yielded incrementally via generators to maintain an $O(1)$ memory footprint.
2. **`SyntheticStreamSource`**:
   - Generates deterministic, multi-vector attack traffic in-memory (DDoS floods, C2 beaconing, DGA lookups, data exfiltration bursts, benign web browsing) without external disk dependencies.
   - Used for continuous CI testing, demo streams, and offline simulation.
3. **`DataDiodeFeedSource`**:
   - Connects to a physical or loopback receive-only network interface in the monitoring enclave.
   - Enforces unidirectional constraints at the class level: zero write sockets, zero broadcast ARP/ICMP packets, and strictly read-only packet sniffing.

---

## 3. Stateful Sliding-Window Flow Assembler

Packets from any active source pass through the **Flow Stream Assembler (`app/ingest/flow_stream.py`)**:

```text
       Packet Stream (PacketEvent)
                   │
                   ▼
      Canonical 5-Tuple Normalizer
      (Protocol, Min IP:Port <-> Max IP:Port)
                   │
                   ▼
         Stateful Sliding Windows
 ┌─────────────────┼─────────────────┐
 ▼                 ▼                 ▼
Flow Assembler  Host Rate Windows  Domain Windows
(Duration, SPLT)(SYN/UDP/Entropy)  (DNS Apex Track)
```

- **Unidirectional Flow Reconstruction**:
  - In unidirectional taps observing only egress or ingress, flow records must not fabricate unobserved reverse traffic.
  - Directionality is tracked via observed initiator (`src_ip:src_port` $\rightarrow$ `dst_ip:dst_port`). Forward and backward packet counts and byte volumes are recorded strictly when observed.
- **State Management**:
  - Manages active flows using a hash table bounded by `max_active_flows` (default 50,000) to prevent memory exhaustion during volumetric attacks.
  - Active flow timeout (default 15.0s) and immediate retirement on TCP FIN/RST.

---

## 4. Passive Feature Extraction Layer

Features are extracted passively without payload decryption or active endpoint interaction:

- **Flow & Volumetric Extractor (`app/features/flow_features.py`)**:
  Computes packet/byte rates, forward/backward volume ratios, mean/variance packet sizes, and TCP flag asymmetries (`syn_ack_ratio`, `is_syn_only`).
- **Timing & Periodicity Extractor (`app/features/timing_features.py`)**:
  Calculates consecutive Inter-Arrival Times (IAT), mean $\mu$, standard deviation $\sigma$, Coefficient of Variation ($CV = \sigma / \mu$), and lag-1 autocorrelation for beaconing detection.
- **DNS Feature Extractor (`app/features/dns_features.py`)**:
  Computes lexical Shannon entropy, digit ratio, vowel-to-consonant ratios, consonant clusters, and subdomain lengths.
  - **`DNSRollingStats`**: Sliding-window tracking of query type distributions (A, AAAA, TXT, CNAME, NULL ratios) and subdomain entropy over a 60-second window per apex domain.
- **TLS & QUIC Passive Extractor (`app/features/tls_features.py`, `app/features/quic_features.py`)**:
  - **TLS**: Extracts unencrypted Client Hello metadata: JA3 hash, JA4 fingerprint string, TLS record version, cipher suite counts, extension counts, SNI presence, and early packet size sequences (SPLT).
  - **QUIC (RFC 9000)**: Decodes long/short packet headers, version numbers, packet type counters (Initial, 0-RTT, Handshake, Retry), and connection ID lengths strictly from unencrypted transport framing. ZERO payload decryption is attempted.
- **Entropy & Distribution Extractor (`app/features/entropy.py`)**:
  Computes Shannon entropy $H(X) = -\sum p(x) \log_2 p(x)$, Herfindahl-Hirschman concentration index (HHI), and top-item dominance across source IPs, destination IPs, and destination ports.

---

## 5. Threat Detectors & Threat Fusion Engine

Seven specialized threat detectors evaluate flow and sliding-window features in parallel:

1. **`DDoSDetector` (`app/detectors/ddos.py`)**:
   - Specialized detection for TCP SYN floods, UDP floods, UDP amplification/reflection (ports 53, 123, 1900, 11211, 389), and spoofed-source floods using source-IP entropy.
2. **`BeaconingDetector` (`app/detectors/beaconing.py`)**:
   - Analyzes IAT dispersion ($CV < 0.25$), autocorrelation, and destination rarity to identify scheduled C2 polling heartbeats.
3. **`DGADetector` (`app/detectors/dga.py`)**:
   - Supervised Random Forest lexical model and entropy thresholds detecting algorithmically generated rendezvous domains.
4. **`DNSTunnelDetector` (`app/detectors/dns_tunnel.py`)**:
   - Detects covert channels through excessive subdomain length, high label entropy, abnormal TXT/NULL query ratios, and high query frequency per apex domain.
5. **`EncryptedTrafficDetector` (`app/detectors/encrypted.py`)**:
   - Behavioral analysis of encrypted sessions (TLS JA3/JA4 fingerprints, QUIC Initial/Handshake framing, SPLT variance, high outbound ratio) without payload decryption.
6. **`ReconDetector` (`app/detectors/recon.py`)**:
   - Identifies horizontal network sweeps, vertical port scans, and high ratios of short SYN-only connection probes.
7. **`ExfiltrationDetector` (`app/detectors/exfiltration.py`)**:
   - Detects bulk outbound data transfers using asymmetric byte ratios ($> 6.0$), sustained transfer rates ($> 2$ MB/s), and Isolation Forest volumetric anomaly scoring.

### Explainable Threat Fusion Engine (`app/fusion/threat_fusion.py`)

Individual detector findings are synthesized by the Threat Fusion Engine:
- **Multi-Vector Corroboration**: Correlates co-occurring indicators within a configurable sliding window (default 25.0s). For example, `SUSPICIOUS_ENCRYPTED_TRAFFIC` + `DATA_EXFILTRATION` fuses into `POSSIBLE_ENCRYPTED_EXFILTRATION` with boosted confidence.
- **Fallback Categorization**:
  - `UNKNOWN_ANOMALY`: Generated when statistical or ML anomaly models trigger without matching specific deterministic signatures, prompting analyst investigation.
  - `INSUFFICIENT_EVIDENCE`: Assigned when an anomaly score is elevated but packet counts or flow duration fall below the minimum threshold for confident classification.
- **Deduplication & Throttling**: Deduplicates repeated alerts on `(src_ip, dst_ip, threat_class)` to eliminate alert fatigue.

---

## 6. Persistence, API, and Dashboard

- **Buffered SQLite Storage with WAL Mode (`app/storage/database.py`)**:
  - SQLite configured with Write-Ahead Logging (`PRAGMA journal_mode=WAL`) and synchronous normal mode for concurrent read/write operations.
  - Implements buffered streaming batch insertion (`queue_flow`, `queue_alert`, `flush_buffers`) to maintain low detection latency under high packet rates.
  - Records input source attribution (`pcap_replay`, `synthetic_stream`, `data_diode_feed`) for forensic traceability.
- **FastAPI Backend (`app/api/main.py`)**:
  - Exposes REST endpoints for alert feeds, system throughput metrics, active input source configuration, and health checks.
- **Streamlit Analyst Dashboard (`dashboard/streamlit_app.py`)**:
  - Real-time command center featuring:
    - Active Input Source banner and selector (`PCAP Replay`, `Synthetic Stream`, `Data-Diode Feed`).
    - Active Detector status indicator strip (7/7 detectors active).
    - Tab 1: Live Monitoring & Threat Triage (real-time KPIs, throughput timeseries, threat distribution charts, searchable alert feed, and full forensic evidence inspector).
    - Tab 2: Measured Benchmarks & Telemetry (empirical hardware specs, throughput sweep graphs across speeds, latency percentile cards, and live benchmark execution).
