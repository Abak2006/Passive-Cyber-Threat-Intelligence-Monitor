# Feature Dictionary & Extraction Reference: AEGIS Platform

Comprehensive reference of all passive network features extracted by the AEGIS detection engine. All features are computed strictly out-of-band without active probing, connection handshakes, or payload decryption.

---

## 1. Flow & Volumetric Features (`app/features/flow_features.py`)

| Feature | Type | Description |
| :--- | :--- | :--- |
| `duration` | Float | Flow lifespan in seconds ($\Delta t = t_{last} - t_{first}$) |
| `total_packets` | Integer | Total packets observed across forward and backward directions |
| `total_bytes` | Integer | Total bytes observed across both directions |
| `packets_per_sec` | Float | Average packet ingestion rate ($\text{pkts} / \text{duration}$) |
| `bytes_per_sec` | Float | Average byte throughput ($\text{bytes} / \text{duration}$) |
| `forward_packets` | Integer | Packets sent from flow initiator to responder |
| `backward_packets` | Integer | Packets sent from responder to initiator |
| `forward_bytes` | Integer | Volume in bytes sent by initiator |
| `backward_bytes` | Integer | Volume in bytes sent by responder |
| `outbound_inbound_byte_ratio` | Float | Ratio: $\text{forward\_bytes} / (\text{backward\_bytes} + 1)$ |
| `mean_packet_size` | Float | Mean length of packets in bytes |
| `std_packet_size` | Float | Standard deviation of packet lengths |
| `syn_count` | Integer | TCP SYN flags observed |
| `ack_count` | Integer | TCP ACK flags observed |
| `syn_ack_ratio` | Float | Ratio: $\text{syn\_count} / (\text{ack\_count} + 1)$ |
| `is_short_flow` | Boolean | True if duration $< 0.5$s and total packets $\le 3$ |
| `is_syn_only` | Boolean | True if SYN $> 0$ and ACK $== 0$ (scanning / flood probe) |

---

## 2. Timing & Periodicity Features (`app/features/timing_features.py`)

| Feature | Type | Description |
| :--- | :--- | :--- |
| `iats` | List[Float] | Inter-arrival times between consecutive packet timestamps |
| `mean_iat` | Float | Average interval between connections/packets ($\mu$) |
| `std_iat` | Float | Standard deviation of intervals ($\sigma$) |
| `coefficient_of_variation` | Float | Dispersion: $CV = \sigma / \mu$. Lower value ($< 0.25$) indicates strict regularity |
| `periodicity_score` | Float | Normalized [0.0, 1.0] score capturing periodicity and autocorrelation |

---

## 3. DNS Lexical & Rolling Distribution Features (`app/features/dns_features.py`)

### A. Static Lexical Metrics (Per Query)
| Feature | Type | Description |
| :--- | :--- | :--- |
| `domain` | String | Normalized queried domain string (lowercase, stripped) |
| `length` | Integer | Total character count of domain |
| `entropy` | Float | Shannon entropy in bits/symbol: $-\sum p(x) \log_2 p(x)$ |
| `digit_ratio` | Float | Proportion of numeric characters |
| `vowel_ratio` | Float | Proportion of vowels ($a, e, i, o, u$) |
| `consonant_ratio` | Float | Proportion of consonants |
| `unique_char_ratio` | Float | Number of unique characters divided by total length |
| `num_labels` | Integer | Count of dot-separated labels (e.g. `sub.example.com` = 3) |
| `longest_label_len` | Integer | Character length of longest label |
| `subdomain_length` | Integer | Length of subdomain prefix before registered apex |
| `subdomain_entropy` | Float | Shannon entropy of subdomain label |
| `max_consonant_cluster` | Integer | Longest run of consecutive consonants |
| `is_txt_record` | Integer | 1 if query type is TXT, 0 otherwise |

### B. Sliding-Window Record Type & Anomaly Metrics (`DNSRollingStats`)
Computed over a 60-second sliding window per registered apex domain:
| Feature | Type | Description |
| :--- | :--- | :--- |
| `rolling_query_count` | Integer | Total DNS queries observed for this apex in window |
| `txt_record_ratio` | Float | Ratio of TXT queries: $\text{count(TXT)} / \text{total\_queries}$ |
| `null_record_ratio` | Float | Ratio of NULL queries: $\text{count(NULL)} / \text{total\_queries}$ |
| `cname_record_ratio` | Float | Ratio of CNAME queries: $\text{count(CNAME)} / \text{total\_queries}$ |
| `rolling_subdomain_entropy` | Float | Average Shannon entropy across subdomains in window |
| `unique_subdomains_count` | Integer | Cardinality of distinct subdomains queried under apex |

---

## 4. Passive TLS & QUIC Metadata (`app/features/tls_features.py`, `app/features/quic_features.py`)

> [!NOTE]
> All TLS and QUIC features are extracted exclusively from unencrypted protocol framing (Client Hello, packet headers). Zero payload decryption is performed.

### A. TLS Metadata (TCP Port 443 / 8443)
| Feature | Type | Description |
| :--- | :--- | :--- |
| `ja3_string` | String | Raw string: `SSLVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats` |
| `ja3_hash` | String | MD5 hash of `ja3_string` matched against known C2 signatures |
| `ja4_fingerprint` | String | JA4 abstraction: `t13d[ciphers][extensions]_[ciphers_hash]_[extensions_hash]` |
| `tls_version` | String | Handshake TLS protocol version (e.g. `0x0303` for TLS 1.2, `0x0304` for TLS 1.3) |
| `ciphers_count` | Integer | Total non-GREASE cipher suites offered |
| `extensions_count` | Integer | Total non-GREASE TLS extensions offered |
| `has_sni` | Boolean | True if Server Name Indication extension is present in Client Hello |
| `splt_mean_length` | Float | Mean length of early packet burst (Sequence of Packet Lengths and Times) |
| `splt_length_variance` | Float | Variance of early packet lengths |
| `early_packet_lengths` | List[Int] | Sequence of first 10 packet lengths (SPLT prefix) |

### B. QUIC Transport Framing (RFC 9000 / UDP Port 443)
| Feature | Type | Description |
| :--- | :--- | :--- |
| `is_quic` | Boolean | True if packet matches RFC 9000 header structure |
| `quic_version` | String | Hexadecimal version string (e.g. `0x00000001` for RFC 9000, `0xff00001d` for draft-29) |
| `quic_long_header_count` | Integer | Count of packets with Long Header format (handshake establishment) |
| `quic_short_header_count` | Integer | Count of packets with Short Header 1-RTT format (data transfer) |
| `quic_initial_count` | Integer | Count of Initial packets observed |
| `quic_retry_count` | Integer | Count of Retry packets observed |
| `quic_handshake_count` | Integer | Count of Handshake packets observed |
| `quic_scid_length` | Integer | Source Connection ID byte length |
| `quic_dcid_length` | Integer | Destination Connection ID byte length |

---

## 5. Entropy & Distribution Metrics (`app/features/entropy.py`)

Measures categorical diversity and concentration across network flows in a sliding window:

| Feature | Type | Description |
| :--- | :--- | :--- |
| `source_ip_entropy` | Float | Shannon entropy across source IPs: $-\sum p(x) \log_2 p(x)$. High value indicates IP spoofing. |
| `destination_ip_entropy`| Float | Shannon entropy across destination IPs. High value indicates horizontal network sweep. |
| `destination_port_entropy`| Float | Shannon entropy across destination ports. High value indicates vertical port scan. |
| `herfindahl_index` | Float | Herfindahl-Hirschman Index (HHI) $\sum p(x)^2 \in [0.0, 1.0]$. Low value confirms dispersed spoofing; high value indicates concentrated target. |
| `top_item_pct` | Float | Percentage of total traffic attributed to the single most frequent address/port. |

---

## 6. Data Exfiltration Features (`app/detectors/exfiltration.py`)

### A. Bulk Volumetric & Rate Features
Passive volumetric, rate, and directional asymmetry features evaluated for outbound bulk transfers:

| Feature | Type | Description |
| :--- | :--- | :--- |
| `bytes_out` | Integer | Total bytes transferred in forward direction ($\text{src} \rightarrow \text{dst}$) |
| `bytes_in` | Integer | Total bytes transferred in backward direction ($\text{dst} \rightarrow \text{src}$) |
| `out_in_ratio` | Float | Safe directional ratio: $\text{bytes\_out} / \max(1, \text{bytes\_in})$. High value indicates extreme asymmetry |
| `outbound_rate_bytes_per_sec` | Float | Sustained outbound throughput: $\text{bytes\_out} / \text{duration}$ |
| `duration_sec` | Float | Active flow duration over which the transfer occurred |
| `destination_frequency` | Integer | Cardinality of sessions to the external destination in active observation window |
| `ratio_threshold_configured` | Float | Configured prototype threshold for volumetric asymmetry (default $6.0\times$) |
| `ml_anomaly_detected` | Boolean | True if unsupervised Isolation Forest scores flow outside benign baseline distribution |

### B. Stateful Multi-Window Slow-and-Low Features
Features computed across sliding temporal windows (60s, 300s, 900s, 3600s) to detect low-and-slow data exfiltration staged over time:

| Feature | Type | Description |
| :--- | :--- | :--- |
| `window_seconds` | Integer | Active temporal aggregation window in seconds (60, 300, 900, or 3600) |
| `transfer_count` | Integer | Number of discrete outbound flows initiated by the source within the window |
| `cumulative_outbound_bytes` | Integer | Total outbound payload bytes staged across all flows in the window |
| `cumulative_inbound_bytes` | Integer | Total inbound acknowledgment payload bytes across the window |
| `outbound_inbound_ratio` | Float | Multi-flow cumulative ratio $\sum B_{out} / \max(1, \sum B_{in})$ with zero-inbound bounds |
| `average_transfer_bytes` | Float | Mean outbound transfer size across active flows |
| `min_transfer_bytes` / `max_transfer_bytes` | Integer | Minimum and maximum transfer sizes observed in the window |
| `mean_interarrival_seconds` | Float | Mean inter-arrival time (IAT) between staged transfers |
| `iat_cv` | Float | Coefficient of variation ($CV = \sigma / \mu$) of inter-arrival times. Values $< 0.50$ indicate consistent automated staging |
| `destination_persistence` | Float | Fraction of total transfers directed to the single dominant destination $[0.0, 1.0]$ |
| `dominant_destination` | String | External endpoint (`IP:Port`) receiving the majority of staged transfers |
| `unique_destinations` | Integer | Count of distinct destinations contacted by the internal host in the window |
| `slow_exfiltration_score` | Float | Normalized composite score $[0.0, 1.0]$ synthesizing volume, asymmetry, persistence, timing regularity, and frequency |


