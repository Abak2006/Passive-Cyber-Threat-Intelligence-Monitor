# Machine Learning Methodology & Training Principles: AEGIS Platform

## 1. Hybrid Detection Philosophy

Cyber threats in unidirectional IP traffic cannot all be addressed by a single model type. AEGIS adopts a **hybrid detection architecture** combining supervised machine learning, unsupervised anomaly detection, and deterministic statistical dispersion metrics:

1. **Supervised Random Forest Classifiers**:
   - Deployed for detection tasks with well-defined feature boundaries and rich lexical or flow telemetry:
     - **DGA Domain Detection**: `RandomForestClassifier(n_estimators=120, max_depth=10)`
     - **DDoS Protocol Classifier**: `RandomForestClassifier(n_estimators=100, max_depth=8)`
     - **Encrypted Traffic Anomaly**: `RandomForestClassifier(n_estimators=100, max_depth=8)`
2. **Unsupervised Anomaly Detection (Isolation Forest)**:
   - Deployed where novel attack variants or zero-day exfiltration patterns diverge unpredictably from baseline distributions:
     - **Data Exfiltration**: `IsolationForest(contamination=0.08)`
3. **Statistical Dispersion & Autocorrelation Rules**:
   - Deployed where deterministic mathematical properties (e.g. strict periodicity in botnet heartbeats or port scan fan-out) provide higher precision and lower latency than opaque deep learning models:
     - **Botnet C2 Beaconing**: Coefficient of Variation ($CV < 0.25$), lag-1 autocorrelation, and destination rarity.
     - **Reconnaissance**: Sliding-window fan-out thresholds and SYN-only ratios.
     - **DNS Tunnelling**: Subdomain entropy, label lengths, and rolling TXT/NULL record distribution ratios.

---

## 2. Prevention of Data Leakage & Evaluation Rigor

Data leakage in network intrusion detection leads to artificially inflated validation metrics:
- **No Identical Session Leakage**: Packets from the exact same TCP connection or attack burst are never split across train and test partitions.
- **Stratified K-Fold Holdout Cross-Validation**:
  - Evaluation partitions preserve class balance across train and test sets using deterministic random states (`random_state=42`).
- **Preprocessing Isolation**: All normalization scalers, feature encoders, and n-gram lexical dictionaries are fit strictly on training folds and evaluated out-of-sample on unseen test partitions.
- **PR-AUC Prioritization**: Because passive monitoring enclaves experience extreme class imbalance (vast majority of traffic is benign background telemetry), models are evaluated and tuned based on **Precision-Recall Area Under Curve (PR-AUC)** and F1-score rather than raw accuracy or ROC-AUC alone.

---

## 3. Dataset Transparency & Enterprise Ingestion

- **Synthetic Baseline vs. Production Data**:
  - The models provided out-of-the-box are trained on reproducible synthetic baseline datasets (`data/synthetic_train/`), clearly labeled as simulated training data.
  - When evaluating on enterprise corpora (e.g. CIC-IDS2017, Bot-IoT), datasets must be ingested via the platform's adapters in `training/dataset_adapters/`.
- **Unidirectional Constraint Enforcement (`unidirectional_only=True`)**:
  - Standard intrusion datasets often contain bidirectional flow features (e.g. `Bwd Packet Length Mean`, `Flow IAT Mean`, server TCP window advertisements).
  - In a unidirectional passive monitoring enclave (hardware data diode tap), reverse-flow packets may be completely unobservable if the tap only mirrors egress or ingress.
  - The dataset adapters strictly drop or zero out all reverse-direction features when `unidirectional_only=True` is enabled, guaranteeing that models do not learn dependencies on telemetry that cannot physically exist in the target enclave.

---

## 4. False Positive Mitigation

Critical infrastructure monitoring demands high precision to prevent alert fatigue:
- **Corroborated TLS/QUIC Fingerprinting**: A repeated JA3 hash (e.g. from Python `requests` or an administrative tool) never triggers an alert in isolation. Alerts require corroborating behavioral anomalies (uniform small packet lengths, high outbound/inbound byte asymmetry, or periodic beaconing).
- **Explainable Fallback Categorization**: When ML anomaly models trigger on anomalous flow characteristics without matching specific attack signatures, the Threat Fusion Engine classifies the event as `UNKNOWN_ANOMALY` rather than fabricating a high-confidence threat label. Sessions with insufficient flow observations are marked as `INSUFFICIENT_EVIDENCE`.
- **Alert Throttling & Deduplication**: The Threat Fusion Engine deduplicates identical alerts on `(src_ip, dst_ip, threat_class)` within configurable time windows to eliminate alert storms.
