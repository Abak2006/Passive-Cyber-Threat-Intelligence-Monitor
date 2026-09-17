"""
Unit Tests for Feature Extraction Modules.
Verifies numerical correctness of entropy, timing, flow, DNS, and TLS metadata extraction.
"""

import pytest
from app.features.entropy import shannon_entropy, distribution_entropy
from app.features.timing_features import compute_timing_stats, calculate_iats
from app.features.flow_features import FlowFeatureExtractor
from app.features.dns_features import DNSFeatureExtractor
from app.features.tls_features import TLSFeatureExtractor


def test_shannon_entropy():
    # Repetitive string has low entropy
    assert shannon_entropy("aaaaaaaaaa") == 0.0
    # Balanced string has higher entropy
    h_balanced = shannon_entropy("abcdefgh")
    assert h_balanced > 2.5
    # Empty string returns 0.0
    assert shannon_entropy("") == 0.0


def test_distribution_entropy():
    # Single IP has 0 entropy
    assert distribution_entropy(["10.0.0.1"] * 20) == 0.0
    # Diverse random IPs have high entropy
    diverse_ips = [f"172.16.1.{i}" for i in range(50)]
    assert distribution_entropy(diverse_ips) > 5.0


def test_timing_features_periodicity():
    # Perfectly periodic intervals (e.g. beaconing every 2.0 seconds)
    periodic_ts = [10.0, 12.0, 14.0, 16.0, 18.0, 20.0]
    mean_iat, std_iat, cv, periodicity = compute_timing_stats(periodic_ts)

    assert mean_iat == 2.0
    assert std_iat == 0.0
    assert cv == 0.0
    assert periodicity >= 0.90

    # Highly irregular / Poisson distributed timestamps
    irregular_ts = [1.0, 1.2, 5.8, 6.1, 14.9, 15.0, 42.1]
    _, _, cv_irreg, periodicity_irreg = compute_timing_stats(irregular_ts)
    assert cv_irreg > 0.80
    assert periodicity_irreg < 0.40


def test_flow_feature_extractor():
    raw_flow = {
        "flow_id": "TCP:10.0.0.1:1234<->10.0.0.2:80",
        "src_ip": "10.0.0.1",
        "src_port": 1234,
        "dst_ip": "10.0.0.2",
        "dst_port": 80,
        "protocol": "TCP",
        "duration": 2.0,
        "forward_packets": 10,
        "backward_packets": 10,
        "forward_bytes": 1000,
        "backward_bytes": 1000,
        "packet_lengths": [100] * 20,
        "syn_count": 1,
        "ack_count": 19,
    }
    feats = FlowFeatureExtractor.extract_features(raw_flow)
    assert feats["total_packets"] == 20
    assert feats["total_bytes"] == 2000
    assert feats["packets_per_sec"] == 10.0
    assert feats["mean_packet_size"] == 100.0
    assert feats["outbound_inbound_byte_ratio"] == pytest.approx(1.0, rel=0.05)


def test_dns_lexical_extractor():
    # Benign domain
    benign_lex = DNSFeatureExtractor.extract_lexical_features("google.com")
    assert benign_lex["entropy"] < 3.2
    assert benign_lex["digit_ratio"] == 0.0

    # DGA domain
    dga_lex = DNSFeatureExtractor.extract_lexical_features("x7k29a8d91b4mz09.biz")
    assert dga_lex["entropy"] > 3.4
    assert dga_lex["digit_ratio"] > 0.25
    assert dga_lex["max_consonant_cluster"] >= 2


def test_tls_feature_extractor_no_decryption():
    # Construct a valid TLS 1.2 Client Hello payload bytes
    payload = bytearray()
    payload.extend(b"\x16\x03\x01\x00\x45")  # Handshake record
    payload.extend(b"\x01\x00\x00\x41")      # Client Hello
    payload.extend(b"\x03\x03")              # TLS 1.2
    payload.extend(b"\x00" * 32)             # Random
    payload.extend(b"\x00")                  # Session ID
    payload.extend(b"\x00\x04\xc0\x2f\xc0\x30") # 2 ciphers
    payload.extend(b"\x01\x00")              # Compression
    payload.extend(b"\x00\x1a")              # Extensions len
    payload.extend(b"\x00\x00\x00\x09\x00\x07\x00\x00\x04test") # SNI "test"
    payload.extend(b"\x00\x0a\x00\x04\x00\x02\x00\x1d") # Supported group 29
    payload.extend(b"\x00\x0b\x00\x01\x00") # Point format

    res = TLSFeatureExtractor.parse_client_hello(bytes(payload))
    assert res is not None
    assert "ja3_hash" in res
    assert len(res["ja3_hash"]) == 32
    assert res["has_sni"] is True
    assert res["ciphers_count"] == 2


def test_ip_and_port_entropy_metrics():
    from app.features.entropy import (
        source_ip_entropy,
        destination_ip_entropy,
        destination_port_entropy,
        calculate_distribution_metrics,
    )

    # 1. Concentrated source (all from same IP)
    single_src = [{"src_ip": "192.168.1.100", "dst_ip": "10.0.0.1", "dst_port": 80}] * 50
    assert source_ip_entropy(single_src) == 0.0

    # 2. Spoofed / Distributed sources (50 distinct IPs)
    distributed_src = [
        {"src_ip": f"172.16.0.{i}", "dst_ip": "10.0.0.1", "dst_port": 80}
        for i in range(50)
    ]
    assert source_ip_entropy(distributed_src) > 5.0

    # 3. Port scan (single destination IP, diverse destination ports)
    port_scan = [
        {"src_ip": "192.168.1.5", "dst_ip": "10.0.0.50", "dst_port": p}
        for p in range(1, 65)
    ]
    assert destination_ip_entropy(port_scan) == 0.0
    assert destination_port_entropy(port_scan) > 5.5

    # 4. Distribution metrics
    metrics = calculate_distribution_metrics(distributed_src, key="src_ip")
    assert metrics["unique_count"] == 50
    assert metrics["entropy"] > 5.0
    assert metrics["herfindahl_index"] < 0.05
    assert metrics["top_1_ratio"] == pytest.approx(0.02, rel=0.1)


def test_dns_rolling_stats_record_type_distribution():
    from app.features.dns_features import DNSRollingStats

    stats = DNSRollingStats(window_size=20)
    # Record standard A records
    for _ in range(15):
        stats.record_query("api.example.com", record_type=1)

    # Record anomalous TXT records (record_type=16)
    for _ in range(5):
        stats.record_query("payload.tunnel.example.com", record_type=16)

    dist = stats.get_distribution()
    assert dist["total_queries"] == 20
    assert dist["txt_ratio"] == 0.25
    assert dist["null_ratio"] == 0.0
    assert "A" in dist["record_types"]
    assert "TXT" in dist["record_types"]


def test_quic_feature_extractor_no_decryption():
    from app.features.quic_features import QUICFeatureExtractor

    # 1. Non-QUIC UDP packet
    regular_udp = b"\x00\x01\x02\x03\x04"
    assert QUICFeatureExtractor.is_quic_packet(regular_udp, 1234, 80) is False

    # 2. Simulated QUIC Initial Long Header packet (RFC 9000: header_form=1, fixed_bit=1, type=0x00 Initial, version 1)
    # First byte: 0xc0 (1100 0000 -> Long header, fixed bit 1, Initial packet)
    quic_initial = bytearray([0xc0, 0x00, 0x00, 0x00, 0x01])  # Version 1 (0x00000001)
    quic_initial.extend(b"\x08")  # DCID len 8
    quic_initial.extend(b"\x11\x22\x33\x44\x55\x66\x77\x88")  # DCID
    quic_initial.extend(b"\x00")  # SCID len 0
    quic_initial.extend(b"\x00" * 1200)  # Padded Initial packet payload

    quic_bytes = bytes(quic_initial)
    assert QUICFeatureExtractor.is_quic_packet(quic_bytes, 50000, 443) is True

    parsed = QUICFeatureExtractor.parse_quic_packet(quic_bytes, 50000, 443)
    assert parsed is not None
    assert parsed["is_quic"] is True
    assert parsed["header_type"] == "long"
    assert parsed["is_initial"] is True
    assert parsed["version"] == "0x00000001"
    assert parsed["version_name"] == "QUIC-v1 (RFC 9000)"
    assert parsed["length"] >= 1200
    assert "inspection_note" in parsed

