# Threat Models & Detection Methodologies

This document defines the 7 cyber threat categories analyzed by the NTRO passive detection engine.

---

## 1. Volumetric / Protocol DDoS
- **Attack Types**: SYN floods, UDP floods, DNS/NTP reflection, spoofed-source floods.
- **Passive Indicators**:
  - `syn_rate`: Excessive SYN packets directed at single host/port.
  - `syn_ack_ratio`: Extreme asymmetry where SYN $\gg$ ACK (unanswered half-open connection attempts).
  - `source_entropy`: High Shannon entropy across source IP addresses indicates random IP spoofing; low entropy indicates direct single-host flooding.
  - `unique_sources`: Sudden surge in distinct client endpoints in sliding window.
- **Explainable Evidence Output**:
  ```json
  {
    "syn_rate": 82400.0,
    "unique_sources": 18231,
    "source_entropy": 13.2,
    "syn_ack_ratio": 240.5
  }
  ```

---

## 2. Botnet C2 Beaconing
- **Attack Types**: Periodic polling loops, infected implant heartbeats (Cobalt Strike, Sliver, Trickbot, Emotet).
- **Passive Indicators**:
  - Inter-Arrival Times (IAT) sequence: Differences between consecutive connection start timestamps.
  - Coefficient of Variation ($CV = \sigma / \mu$): Highly periodic beaconing exhibits $CV < 0.25$.
  - Autocorrelation: High correlation between successive time intervals.
  - Jitter tolerance: Implants introducing random jitter (e.g. $\pm 20\%$) still maintain bounded variance and high periodicity scores.
- **Explainable Evidence Output**:
  ```json
  {
    "mean_inter_arrival_sec": 300.2,
    "std_inter_arrival_sec": 12.1,
    "coefficient_of_variation": 0.0403,
    "periodicity_score": 0.94,
    "connection_count": 8
  }
  ```

---

## 3. DGA (Domain Generation Algorithm) Detection
- **Attack Types**: Malware using algorithmic domains for dynamic C2 rendezvous to bypass static DNS blacklists.
- **Passive Indicators**:
  - High Shannon entropy in domain string (> 3.5 bits/char).
  - High digit ratio and low vowel-to-consonant ratio.
  - Long consonant clusters (e.g. `x7k29a8d91b4mz09.biz`).
  - Supervised Random Forest lexical model output probability.
- **Explainable Evidence Output**:
  ```json
  {
    "domain": "x7k29a8d91b4mz09.biz",
    "domain_entropy": 3.8842,
    "domain_length": 20,
    "digit_ratio": 0.4737,
    "vowel_ratio": 0.1053,
    "ml_probability": 0.9820
  }
  ```

---

## 4. DNS Tunnelling & Covert Channels
- **Attack Types**: Data exfiltration and remote command channels tunneled inside DNS queries (Iodine, DNScapy, Cobalt Strike DNS beacons).
- **Passive Indicators**:
  - Subdomain length $> 24$ characters (chunking base64/hex data into labels).
  - High subdomain entropy ($> 3.75$ bits/char).
  - High query frequency to a single apex domain with many unique pseudo-random subdomains.
  - Unusually frequent TXT or NULL record queries.
- **Explainable Evidence Output**:
  ```json
  {
    "suspicious_query": "a8f93e2b109c4d87e65fa31298c.tunnel.exfil.org",
    "subdomain_length": 27,
    "subdomain_entropy": 4.1250,
    "unique_subdomain_count": 18,
    "query_frequency": 6.5
  }
  ```

---

## 5. Malware in Encrypted TLS/QUIC Traffic
- **Constraint**: STRICTLY ZERO PAYLOAD DECRYPTION.
- **Passive Indicators**:
  - Handshake metadata: JA3 MD5 hash matched against catalog of known C2 frameworks (Cobalt Strike, Metasploit, AsyncRAT).
  - Absence of Server Name Indication (SNI) for TLS over port 443.
  - SPLT (Sequence of Packet Lengths and Times): Mean packet length and variance. Uniform small packet bursts (e.g. 50–200 bytes) indicate heartbeat command polling.
  - Directional byte ratios and connection periodicity.
- **Explainable Evidence Output**:
  ```json
  {
    "suspicious_tls_fingerprint": true,
    "ja3_hash": "e7d705a3286e19ea42f587b344ee6865",
    "periodicity_score": 0.94,
    "packet_size_anomaly": 0.87,
    "outbound_inbound_ratio": 14.2,
    "inspection_note": "Passive metadata and behavioral flow dynamics only. Zero payload decryption performed."
  }
  ```

---

## 6. Reconnaissance & Port Scanning
- **Attack Types**:
  - Horizontal scans: Attacker probes 1 port across multiple targets.
  - Vertical scans: Attacker probes multiple ports on 1 target.
  - Broad scans: Multi-host, multi-port sweeps.
- **Passive Indicators**:
  - Unique destination IPs contacted in sliding window.
  - Unique destination ports contacted in sliding window.
  - High connection rate of short-lived or SYN-only probes without completed handshakes.
  - Destination IP entropy.
- **Explainable Evidence Output**:
  ```json
  {
    "unique_destination_hosts": 42,
    "unique_destination_ports": 87,
    "connections_per_second": 31.5,
    "destination_entropy": 4.82,
    "is_short_flow": true
  }
  ```

---

## 7. Data Exfiltration
- **Attack Types**: Unauthorized bulk exfiltration, database dumps, or sustained trickle uploads.
- **Passive Indicators**:
  - High outbound/inbound byte ratio ($> 6.0:1$).
  - High sustained outbound transfer rate (bytes/sec) over duration.
  - Flow byte volume exceeds baseline thresholds ($> 3$ MB in single flow).
  - Isolation Forest anomaly score on flow volume and directionality.
- **Explainable Evidence Output**:
  ```json
  {
    "inbound_bytes": 1024,
    "outbound_bytes": 35000000,
    "outbound_inbound_ratio": 3417.9,
    "outbound_rate_bytes_per_sec": 8245000.0,
    "flow_duration_sec": 4.25
  }
  ```
