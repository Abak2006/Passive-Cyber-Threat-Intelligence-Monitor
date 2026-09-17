# Dataset Strategy & Setup Instructions

## 1. Zero Heavy Downloads Guarantee
To ensure the prototype can be evaluated immediately without downloading gigabyte-scale files, a synthetic dataset and test PCAP generator is provided:

```bash
# Generates training CSVs and data/sample/demo.pcap in seconds:
python -m training.generate_synthetic
```

The generated `data/sample/demo.pcap` contains 722 packets covering:
- **Benign background traffic**: Standard HTTP, DNS, TLS 1.2/1.3 browsing
- **Volumetric SYN Flood**: High packet arrival rate with ACK deficit
- **Botnet C2 Beaconing**: Periodic heartbeats with low jitter (CV < 0.05)
- **DGA Domain Queries**: High-entropy pseudo-random algorithmic domain lookups
- **DNS Tunnelling**: High-entropy long subdomains & TXT records to `tunnel.exfil.org`
- **Suspicious Encrypted Traffic**: Cobalt Strike JA3 & SPLT packet length profile
- **Reconnaissance**: Vertical port scan and horizontal subnet sweeps
- **Bulk Data Exfiltration**: `10.0.0.22` → `203.0.113.80:443` (~503 KB asymmetric transfer)
- **Slow-and-Low Data Exfiltration**: `10.0.0.23` → `203.0.113.90:443` (staged ~9.6 KB chunks with interval jitter, persistent drop destination, and strong cumulative volume/asymmetry)
- **Legitimate Periodic Traffic**: `10.0.0.45` → `198.51.100.20:443` (periodic balanced duplex transactions proving periodicity alone does NOT trigger exfiltration alerts)

> [!NOTE]
> **Synthetic Disclosures**: `data/sample/demo.pcap` is a synthetic laboratory evaluation artifact constructed via Scapy to provide repeatable, deterministically reproducible multi-threat scenarios without requiring gigabytes of packet downloads or exposing real credentials.


---

## 2. Using Public Cybersecurity Datasets

The repository includes adapters in `training/dataset_adapters/` to load and train against standard public research datasets:

### A. CIC-IDS2017 & CIC-DDoS2019
- **Source**: Canadian Institute for Cybersecurity
- **Usage**:
  ```python
  from training.dataset_adapters.cic_ids import CICIDSAdapter
  adapter = CICIDSAdapter("path/to/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")
  X, y = adapter.load_and_transform()
  ```

### B. BoT-IoT Dataset
- **Source**: UNSW Canberra Cyber
- **Usage**:
  ```python
  from training.dataset_adapters.bot_iot import BoTIoTAdapter
  adapter = BoTIoTAdapter("path/to/Entire_Dataset.csv")
  X, y = adapter.load_and_transform()
  ```

### C. CIC-Bell-DNS2021 & DGA Feeds
- **Source**: Netlab 360 DGA Feed / Tranco Top 1M / CIC-Bell-DNS2021
- **Usage**:
  ```python
  from training.dataset_adapters.dns_adapter import DNSDatasetAdapter
  adapter = DNSDatasetAdapter("path/to/dga_feed.csv")
  X, y = adapter.load_and_transform()
  ```
