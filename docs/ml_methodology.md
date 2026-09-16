# Machine Learning Methodology & Training Principles

## 1. Hybrid Detection Philosophy

Cyber threats in unidirectional IP traffic cannot all be addressed by a single model type. In alignment with NTRO requirements, our engine adopts a **hybrid model architecture**:

1. **Supervised Random Forest Classifiers**:
   - Deployed for tasks with clear decision boundaries and rich lexical or flow metrics:
     - **DGA Domain Detection**: `RandomForestClassifier(n_estimators=120, max_depth=10)`
     - **DDoS Protocol Classifier**: `RandomForestClassifier(n_estimators=100, max_depth=8)`
     - **Encrypted Traffic Anomaly**: `RandomForestClassifier(n_estimators=100, max_depth=8)`
2. **Unsupervised Anomaly Detection (Isolation Forest)**:
   - Deployed where attack variants diverge unpredictably from normal traffic:
     - **Data Exfiltration**: `IsolationForest(contamination=0.08)`
3. **Statistical Dispersion & Autocorrelation Rules**:
   - Deployed where deterministic mathematical properties (e.g. strict periodicity in botnet heartbeats or port scan fan-out) provide higher precision and lower latency than opaque neural networks:
     - **Botnet C2 Beaconing**: Coefficient of Variation ($CV < 0.25$) + Autocorrelation.
     - **Reconnaissance**: Sliding-window fan-out thresholds.
     - **DNS Tunnelling**: Subdomain entropy and label length thresholds.

---

## 2. Prevention of Data Leakage

Data leakage in network intrusion detection leads to artificially inflated validation metrics:
- **No Identical Session Leakage**: Packets from the exact same TCP connection or attack burst are never split across train and test partitions.
- **Deterministic Random State**: Random seeds (`random_state=42`) ensure reproducible fold splits.
- **Preprocessing Isolation**: All normalization, scalers, and dictionary lookups are computed strictly on the training partition and evaluated out-of-sample.

---

## 3. False Positive Mitigation

Critical infrastructure monitoring must minimize false alarms:
- **TLS Fingerprints are NOT Verdicts**: A repeated JA3 hash (e.g., from Chrome or a VPN client) never triggers a threat on its own. It requires corroborating behavioral anomalies (uniform small packet lengths, high outbound/inbound ratios, or beaconing periodicity).
- **Rate-Based Threshold Baselines**: Large backups or legitimate downloads are distinguished from exfiltration by checking directional ratios and baseline behavior.
- **Alert Throttling**: The Threat Fusion Engine deduplicates identical alerts on `(src_ip, dst_ip, threat_class)` within configurable time windows to prevent alert storms.
