# Feature Dictionary & Extraction Reference

Comprehensive reference of all passive network features extracted by the engine.

---

## 1. Flow & Volumetric Features (`app/features/flow_features.py`)

| Feature | Type | Description |
| :--- | :--- | :--- |
| `duration` | Float | Flow lifespan in seconds ($\Delta t = t_{last} - t_{first}$) |
| `total_packets` | Integer | Total packets observed across forward and backward directions |
| `total_bytes` | Integer | Total bytes observed |
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

## 3. DNS Lexical Features (`app/features/dns_features.py`)

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

---

## 4. Passive TLS/QUIC Metadata (`app/features/tls_features.py`)

| Feature | Type | Description |
| :--- | :--- | :--- |
| `ja3_string` | String | Raw string: `SSLVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats` |
| `ja3_hash` | String | MD5 hash of `ja3_string` |
| `ja4_fingerprint` | String | Clean JA4 abstraction: `t13d[ciphers][extensions]_[hash]` |
| `tls_version` | String | Handshake TLS protocol version (e.g. `0x0303` for TLS 1.2) |
| `ciphers_count` | Integer | Total non-GREASE cipher suites offered |
| `extensions_count` | Integer | Total non-GREASE TLS extensions offered |
| `has_sni` | Boolean | True if Server Name Indication extension is present |
| `splt_mean_length` | Float | Mean length of early packet burst |
| `splt_length_variance` | Float | Variance of early packet lengths |
| `early_packet_lengths` | List[Int] | Sequence of first 10 packet lengths (SPLT prefix) |

---

## 5. Entropy & Distribution Metrics (`app/features/entropy.py`)

| Feature | Type | Description |
| :--- | :--- | :--- |
| `source_entropy` | Float | Shannon entropy across observed source IPs targeting destination |
| `destination_entropy` | Float | Shannon entropy across destination ports or IPs targeted by source |
