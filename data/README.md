# Dataset Strategy & Setup Instructions

## 1. Zero Heavy Downloads Guarantee
To ensure the prototype can be evaluated immediately without downloading gigabyte-scale files, a synthetic dataset and test PCAP generator is provided:

```bash
# Generates training CSVs and data/sample/demo.pcap in seconds:
python -m training.generate_synthetic
```

The generated `data/sample/demo.pcap` contains:
- Benign background traffic (HTTP, DNS, TLS 1.2/1.3)
- Volumetric SYN Flood
- Botnet C2 Beaconing (periodic heartbeats with low jitter)
- DGA Domain Queries
- DNS Tunnelling (high entropy long subdomains & TXT records)
- Suspicious Encrypted Traffic (Cobalt Strike JA3 & SPLT anomalies)
- Vertical and Horizontal Port Scanning
- Data Exfiltration (asymmetric high-volume upload)

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
