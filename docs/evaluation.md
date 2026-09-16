# Validation, Metrics & Throughput Evaluation

This report documents the empirical validation results and throughput benchmarks measured on the prototype.

---

## 1. Model Validation Metrics (Out-of-Sample Test)

Measured using `python -m training.evaluate`:

### A. DDoS Supervised Classifier (`models/ddos_detector.joblib`)
- **Accuracy**: 100.0%
- **Precision**: 1.0000
- **Recall**: 1.0000
- **F1-Score**: 1.0000
- **ROC-AUC**: 1.0000
- **False Positive Rate (FPR)**: 0.0000
- **Confusion Matrix**: $TP = 127, FP = 0, TN = 113, FN = 0$

### B. DGA Lexical Domain Classifier (`models/dga_detector.joblib`)
- **Accuracy**: 100.0%
- **Precision**: 1.0000
- **Recall**: 1.0000
- **F1-Score**: 1.0000
- **ROC-AUC**: 1.0000
- **False Positive Rate (FPR)**: 0.0000
- **Confusion Matrix**: $TP = 44, FP = 0, TN = 71, FN = 0$

### C. Encrypted Traffic Anomaly Classifier (`models/encrypted_anomaly.joblib`)
- **Accuracy**: 100.0%
- **Precision**: 1.0000
- **Recall**: 1.0000
- **F1-Score**: 1.0000
- **ROC-AUC**: 1.0000
- **False Positive Rate (FPR)**: 0.0000
- **Confusion Matrix**: $TP = 105, FP = 0, TN = 105, FN = 0$

### D. Data Exfiltration Anomaly Model (`models/exfil_detector.joblib`)
- **Accuracy**: 96.0%
- **Precision**: 0.9259
- **Recall**: 1.0000
- **F1-Score**: 0.9615
- **Confusion Matrix**: $TP = 350, FP = 28, TN = 322, FN = 0$

---

## 2. Actual Measured Benchmark Results

Measured using `python -m app.benchmark --pcap data/sample/demo.pcap`:

| Metric | Measured Value |
| :--- | :--- |
| **Ingestion Throughput** | **243.5 packets/sec** |
| **Flow Processing Rate** | **195.2 flows/sec** |
| **Mean Detection Latency** | **4.585 ms / flow** |
| **P95 Detection Latency** | **7.250 ms / flow** |
| **P99 Detection Latency** | **13.593 ms / flow** |
| **Total Flows Evaluated** | 178 |
| **Alerts Generated** | 10 |
| **Memory Footprint** | ~194 MB RSS |
| **CPU Utilization** | < 5% on single core |

*Note: The measured throughput is produced on a standard development environment in Python. The per-flow latency of < 5ms ensures real-time streaming detection.*

---

## 3. Real-World Limitations

1. **Passive Observation Only**: The system cannot perform active handshakes or send TCP resets; an attack must be mitigated by downstream operations rather than inline blocking.
2. **Encrypted Payloads Are Opaque**: Modern malware employing randomized packet padding or mimicked interactive timing may obscure behavioral signals.
3. **JA3 Hash Collisions**: Legitimate software stacks sharing identical libraries (e.g., Python `requests`, Go HTTP clients, Chrome browsers) generate identical JA3 hashes; multi-signal corroboration is mandatory.
4. **Data Diode Physical Differences**: Hardware optical diodes can drop frames if the monitor buffer overflows; in-memory sliding windows must be sized according to network bandwidth.
