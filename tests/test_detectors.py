"""
Unit Tests for Specialized Cyber Threat Detectors.
Validates detection logic, confidence ratings, and evidence structures for all 7 threat categories.
"""

import numpy as np
import pytest
from app.detectors.ddos import DDoSDetector
from app.detectors.beaconing import BeaconingDetector
from app.detectors.dga import DGADetector
from app.detectors.dns_tunnel import DNSTunnelDetector
from app.detectors.encrypted import EncryptedTrafficDetector
from app.detectors.recon import ReconDetector
from app.detectors.exfiltration import ExfiltrationDetector


def test_ddos_detector():
    det = DDoSDetector(syn_rate_threshold=50.0)
    flow = {
        "flow_id": "TCP:1.2.3.4:1000<->10.0.0.50:80",
        "src_ip": "1.2.3.4",
        "src_port": 1000,
        "dst_ip": "10.0.0.50",
        "dst_port": 80,
        "protocol": "TCP",
        "duration": 1.0,
        "syn_count": 80,
        "ack_count": 0,
        "syn_ack_ratio": 80.0,
        "packets_per_sec": 80.0,
    }
    res = det.predict(flow, context={"syn_rate": 80.0, "unique_sources": 1})
    assert res is not None
    assert res.threat_class == "SYN_FLOOD"
    assert res.confidence >= 0.80
    assert "syn_rate" in res.evidence


def test_beaconing_detector():
    det = BeaconingDetector(min_connections=4, cv_threshold=0.25)
    flow = {
        "flow_id": "TCP:10.0.0.15:49152<->198.51.100.44:8443",
        "src_ip": "10.0.0.15",
        "src_port": 49152,
        "dst_ip": "198.51.100.44",
        "dst_port": 8443,
        "protocol": "TCP",
        "duration": 5.0,
        "timestamps": [1.0, 2.0, 3.0, 4.0, 5.0, 6.0],
    }
    res = det.predict(flow, context={"connection_timestamps": [10.0, 11.0, 12.0, 13.0, 14.0]})
    assert res is not None
    assert res.threat_class == "BOTNET_C2_BEACONING"
    assert res.confidence >= 0.70
    assert "coefficient_of_variation" in res.evidence
    assert res.evidence["coefficient_of_variation"] < 0.25


def test_dga_detector():
    det = DGADetector(entropy_threshold=3.5, length_threshold=15)
    flow = {
        "flow_id": "UDP:10.0.0.20:53123<->8.8.8.8:53",
        "src_ip": "10.0.0.20",
        "src_port": 53123,
        "dst_ip": "8.8.8.8",
        "dst_port": 53,
        "protocol": "UDP",
        "dns_queries": ["x7k29a8d91b4mz09.biz"],
    }
    res = det.predict(flow)
    assert res is not None
    assert res.threat_class == "DGA_DOMAIN_DETECTION"
    assert res.confidence >= 0.70
    assert res.evidence["domain_entropy"] > 3.4


def test_dns_tunnel_detector():
    det = DNSTunnelDetector(subdomain_len_threshold=20, subdomain_entropy_threshold=3.5)
    flow = {
        "flow_id": "UDP:10.0.0.25:54000<->8.8.4.4:53",
        "src_ip": "10.0.0.25",
        "src_port": 54000,
        "dst_ip": "8.8.4.4",
        "dst_port": 53,
        "protocol": "UDP",
        "dns_queries": ["a8f93e2b109c4d87e65fa31298c.tunnel.exfil.org"],
    }
    ctx = {
        "dns_tunnel_context": {
            "query_count": 8,
            "unique_subdomains": 8,
            "query_rate": 6.0,
            "queries": ["a8f93e2b109c4d87e65fa31298c.tunnel.exfil.org"] * 8,
        }
    }
    res = det.predict(flow, context=ctx)
    assert res is not None
    assert res.threat_class == "DNS_TUNNELLING"
    assert res.confidence >= 0.70
    assert "subdomain_entropy" in res.evidence


def test_encrypted_traffic_detector():
    det = EncryptedTrafficDetector()
    flow = {
        "flow_id": "TCP:10.0.0.30:51234<->203.0.113.99:443",
        "src_ip": "10.0.0.30",
        "src_port": 51234,
        "dst_ip": "203.0.113.99",
        "dst_port": 443,
        "protocol": "TCP",
        "outbound_inbound_byte_ratio": 12.0,
        "forward_bytes": 6000,
        "backward_bytes": 500,
        "packet_lengths": [100, 110, 105, 108, 102, 105], # Low variance
        "timestamps": [1.0, 2.0, 3.0, 4.0, 5.0, 6.0],     # Periodic
        "tls_metadata": {
            "ja3_hash": "e7d705a3286e19ea42f587b344ee6865", # Cobalt strike
            "ja4_fingerprint": "t12i030300_e7d705a3286e",
            "has_sni": False,
            "ciphers_count": 3
        }
    }
    res = det.predict(flow)
    assert res is not None
    assert res.threat_class == "SUSPICIOUS_ENCRYPTED_TRAFFIC"
    assert res.evidence["suspicious_tls_fingerprint"] is True
    assert "inspection_note" in res.evidence


def test_recon_detector():
    det = ReconDetector(vertical_threshold=6)
    flow = {
        "flow_id": "TCP:10.0.0.88:50000<->10.0.0.50:80",
        "src_ip": "10.0.0.88",
        "src_port": 50000,
        "dst_ip": "10.0.0.50",
        "dst_port": 80,
        "protocol": "TCP",
        "is_short_flow": True,
    }
    scan_ctx = {
        "unique_dst_ips": 1,
        "unique_dst_ports": 12,
        "connections_per_sec": 8.0,
        "raw_dst_ips": ["10.0.0.50"],
        "raw_dst_ports": list(range(12)),
    }
    res = det.predict(flow, context={"scan_context": scan_ctx})
    assert res is not None
    assert res.threat_class == "PORT_SCAN_VERTICAL"
    assert res.confidence >= 0.85


def test_exfiltration_detector():
    """Basic exfiltration detection verification."""
    det = ExfiltrationDetector(ratio_threshold=5.0, min_outbound_bytes=200_000)
    flow = {
        "flow_id": "TCP:10.0.0.22:44890<->203.0.113.80:443",
        "src_ip": "10.0.0.22",
        "src_port": 44890,
        "dst_ip": "203.0.113.80",
        "dst_port": 443,
        "protocol": "TCP",
        "forward_bytes": 5_000_000,
        "backward_bytes": 50_000,
        "outbound_inbound_byte_ratio": 100.0,
        "duration": 2.0,
    }
    res = det.predict(flow)
    assert res is not None
    assert res.threat_class == "DATA_EXFILTRATION"
    assert res.confidence >= 0.80
    assert res.evidence["outbound_inbound_ratio"] == 100.0


def test_exfiltration_strongly_asymmetric_alert():
    """Test strongly asymmetric outbound traffic (500 KB out, 5 KB in -> ratio 100x)."""
    det = ExfiltrationDetector(ratio_threshold=6.0, min_outbound_bytes=200_000)
    flow = {
        "flow_id": "TCP:10.0.0.22:44890<->203.0.113.80:443",
        "src_ip": "10.0.0.22",
        "src_port": 44890,
        "dst_ip": "203.0.113.80",
        "dst_port": 443,
        "protocol": "TCP",
        "forward_bytes": 500_000,
        "backward_bytes": 5_000,
        "outbound_inbound_byte_ratio": 100.0,
        "duration": 3.0,
    }
    res = det.predict(flow)
    assert res is not None
    assert res.threat_class == "DATA_EXFILTRATION"
    assert res.confidence >= 0.70
    assert res.evidence["bytes_out"] == 500_000
    assert res.evidence["bytes_in"] == 5_000
    assert res.evidence["out_in_ratio"] == 100.0


def test_exfiltration_normal_traffic_no_alert():
    """Test normal everyday web/API traffic does not trigger exfiltration."""
    det = ExfiltrationDetector(ratio_threshold=6.0, min_outbound_bytes=200_000)
    normal_flows = [
        # Small web browsing flow (mostly download)
        {"forward_bytes": 1_200, "backward_bytes": 18_000, "duration": 2.5},
        # Small upload under baseline (e.g. POST request 8 KB)
        {"forward_bytes": 8_000, "backward_bytes": 1_500, "duration": 1.0},
        # Balanced API transaction
        {"forward_bytes": 45_000, "backward_bytes": 35_000, "duration": 1.5},
    ]
    for flow in normal_flows:
        res = det.predict(flow)
        assert res is None, f"Normal flow unexpectedly flagged: {flow}"


def test_exfiltration_sustained_high_rate():
    """Test sustained high outbound rate triggers exfiltration signal."""
    det = ExfiltrationDetector(sustained_rate_threshold_bps=1_000_000.0, min_duration=1.0)
    flow = {
        "flow_id": "TCP:10.0.0.22:44890<->203.0.113.80:443",
        "src_ip": "10.0.0.22",
        "src_port": 44890,
        "dst_ip": "203.0.113.80",
        "dst_port": 443,
        "protocol": "TCP",
        "forward_bytes": 3_500_000,
        "backward_bytes": 200_000,
        "duration": 2.0,
    }
    res = det.predict(flow)
    assert res is not None
    assert res.threat_class == "DATA_EXFILTRATION"
    assert res.evidence["outbound_rate_bytes_per_sec"] >= 1_000_000.0
    assert "sustained threshold" in res.evidence["threat_diagnosis"]


def test_exfiltration_large_burst():
    """Test large outbound burst triggers exfiltration signal."""
    det = ExfiltrationDetector(burst_threshold_bytes=2_000_000)
    flow = {
        "flow_id": "TCP:10.0.0.22:44890<->203.0.113.80:443",
        "src_ip": "10.0.0.22",
        "src_port": 44890,
        "dst_ip": "203.0.113.80",
        "dst_port": 443,
        "protocol": "TCP",
        "forward_bytes": 2_500_000,
        "backward_bytes": 100_000,
        "duration": 4.0,
    }
    res = det.predict(flow)
    assert res is not None
    assert res.threat_class == "DATA_EXFILTRATION"
    assert "burst threshold" in res.evidence["threat_diagnosis"]


def test_exfiltration_zero_inbound_bytes_safe():
    """Test zero inbound bytes handles division safely without crashing."""
    det = ExfiltrationDetector(ratio_threshold=6.0, min_outbound_bytes=200_000)
    flow = {
        "flow_id": "TCP:10.0.0.22:44890<->203.0.113.80:443",
        "src_ip": "10.0.0.22",
        "src_port": 44890,
        "dst_ip": "203.0.113.80",
        "dst_port": 443,
        "protocol": "TCP",
        "forward_bytes": 350_000,
        "backward_bytes": 0,
        "duration": 2.0,
    }
    res = det.predict(flow)
    assert res is not None
    assert res.threat_class == "DATA_EXFILTRATION"
    assert res.evidence["bytes_in"] == 0
    assert not np.isnan(res.evidence["out_in_ratio"])
    assert not np.isinf(res.evidence["out_in_ratio"])
    assert res.evidence["out_in_ratio"] > 0


def test_exfiltration_legitimate_high_volume_balanced_no_alert():
    """Test legitimate high-volume balanced flow is not classified as exfiltration."""
    det = ExfiltrationDetector(
        ratio_threshold=6.0,
        min_outbound_bytes=200_000,
        sustained_rate_threshold_bps=2_000_000.0,
        burst_threshold_bytes=5_000_000
    )
    # Balanced duplex transfer: e.g. 1.2 MB out, 1.0 MB in (ratio = 1.2x)
    legitimate_flow = {
        "forward_bytes": 1_200_000,
        "backward_bytes": 1_000_000,
        "duration": 5.0,
    }
    res = det.predict(legitimate_flow)
    assert res is None, "Legitimate balanced flow was falsely classified as exfiltration"


def test_exfiltration_slow_and_low_repeated_transfers():
    """Test slow-and-low exfiltration: small repeated transfers accumulate and alert."""
    det = ExfiltrationDetector(
        slow_exfil_enabled=True,
        slow_min_transfers=4,
        slow_min_cumulative_bytes=35_000,
        slow_windows=[60.0, 300.0],
    )
    det.reset_state()

    alerts = []
    for i in range(5):
        flow = {
            "flow_id": f"TCP:10.0.0.23:{50000+i}<->203.0.113.90:443",
            "src_ip": "10.0.0.23",
            "src_port": 50000 + i,
            "dst_ip": "203.0.113.90",
            "dst_port": 443,
            "protocol": "TCP",
            "forward_bytes": 10_000,
            "backward_bytes": 100,
            "duration": 1.0,
            "start_time": 100.0 + i * 12.0,
            "end_time": 101.0 + i * 12.0,
        }
        res = det.predict(flow)
        if res:
            alerts.append(res)

    assert len(alerts) >= 1
    alert = alerts[-1]
    assert alert.threat_class == "DATA_EXFILTRATION"
    assert alert.evidence["subtype"] == "SLOW_AND_LOW"
    assert alert.evidence["transfer_count"] >= 4
    assert alert.evidence["cumulative_outbound_bytes"] >= 35_000
    assert alert.evidence["destination_persistence"] == 1.0
    assert alert.evidence["iat_cv"] <= 0.50
    assert alert.confidence >= 0.70
    assert alert.evidence["slow_exfiltration_score"] >= 0.65


def test_exfiltration_periodic_benign_traffic_no_alert():
    """Test that periodic traffic alone does NOT trigger slow-and-low exfiltration."""
    det = ExfiltrationDetector(
        slow_exfil_enabled=True,
        slow_min_transfers=4,
        slow_min_cumulative_bytes=35_000,
        slow_windows=[60.0, 300.0],
    )
    det.reset_state()

    for i in range(6):
        flow = {
            "flow_id": f"TCP:10.0.0.45:{51000+i}<->198.51.100.20:443",
            "src_ip": "10.0.0.45",
            "src_port": 51000 + i,
            "dst_ip": "198.51.100.20",
            "dst_port": 443,
            "protocol": "TCP",
            "forward_bytes": 8_000,
            "backward_bytes": 8_000,
            "duration": 1.0,
            "start_time": 200.0 + i * 10.0,
            "end_time": 201.0 + i * 10.0,
        }
        res = det.predict(flow)
        assert res is None, f"Balanced periodic traffic unexpectedly triggered alert at step {i}"


def test_exfiltration_destination_persistence_increases():
    """Test destination persistence metric across multiple repeated transfers."""
    det = ExfiltrationDetector(slow_exfil_enabled=True)
    det.reset_state()

    for i in range(5):
        flow = {
            "flow_id": f"TCP:10.0.0.50:{52000+i}<->203.0.113.77:443",
            "src_ip": "10.0.0.50",
            "src_port": 52000 + i,
            "dst_ip": "203.0.113.77",
            "dst_port": 443,
            "protocol": "TCP",
            "forward_bytes": 8_000,
            "backward_bytes": 200,
            "duration": 1.0,
            "start_time": 300.0 + i * 10.0,
            "end_time": 301.0 + i * 10.0,
        }
        det.predict(flow)

    from app.features.timing_features import calculate_destination_persistence
    history = list(det.source_history["10.0.0.50"])
    pers = calculate_destination_persistence(history)
    assert pers["dominant_dst_ip"] == "203.0.113.77"
    assert pers["persistence_ratio"] == 1.0
    assert pers["unique_dst_count"] == 1


def test_exfiltration_irregular_small_transfers_no_alert():
    """Test small irregular transfers below threshold do not trigger exfiltration."""
    det = ExfiltrationDetector(
        slow_exfil_enabled=True,
        slow_min_transfers=4,
        slow_min_cumulative_bytes=35_000
    )
    det.reset_state()

    for i in range(3):
        flow = {
            "flow_id": f"TCP:10.0.0.60:{53000+i}<->203.0.113.88:443",
            "src_ip": "10.0.0.60",
            "src_port": 53000 + i,
            "dst_ip": "203.0.113.88",
            "dst_port": 443,
            "protocol": "TCP",
            "forward_bytes": 5_000,
            "backward_bytes": 50,
            "duration": 1.0,
            "start_time": 400.0 + i * 20.0,
            "end_time": 401.0 + i * 20.0,
        }
        res = det.predict(flow)
        assert res is None


def test_exfiltration_rolling_window_expiration():
    """Test that events older than the sliding window expire from rolling calculations."""
    from app.features.timing_features import calculate_rolling_transfer_statistics

    transfers = [
        {"timestamp": 10.0, "forward_bytes": 10_000, "backward_bytes": 100},
        {"timestamp": 20.0, "forward_bytes": 10_000, "backward_bytes": 100},
        {"timestamp": 30.0, "forward_bytes": 10_000, "backward_bytes": 100},
        {"timestamp": 120.0, "forward_bytes": 10_000, "backward_bytes": 100},
    ]

    stats = calculate_rolling_transfer_statistics(transfers, window_sec=60.0, current_time=120.0)
    assert stats["transfer_count"] == 1
    assert stats["cumulative_outbound_bytes"] == 10_000

    stats_300 = calculate_rolling_transfer_statistics(transfers, window_sec=300.0, current_time=120.0)
    assert stats_300["transfer_count"] == 4
    assert stats_300["cumulative_outbound_bytes"] == 40_000


def test_exfiltration_multiple_destinations_dispersion_no_alert():
    """Test transfers distributed across many random destinations do not trigger slow-and-low alert."""
    det = ExfiltrationDetector(
        slow_exfil_enabled=True,
        slow_min_transfers=4,
        slow_min_cumulative_bytes=35_000,
        slow_persistence_threshold=0.75
    )
    det.reset_state()

    for i in range(6):
        flow = {
            "flow_id": f"TCP:10.0.0.70:{54000+i}<->203.0.113.{i+1}:443",
            "src_ip": "10.0.0.70",
            "src_port": 54000 + i,
            "dst_ip": f"203.0.113.{i+1}",
            "dst_port": 443,
            "protocol": "TCP",
            "forward_bytes": 10_000,
            "backward_bytes": 100,
            "duration": 1.0,
            "start_time": 500.0 + i * 10.0,
            "end_time": 501.0 + i * 10.0,
        }
        res = det.predict(flow)
        assert res is None, f"Dispersed multi-destination flow unexpectedly alerted: {flow}"


def test_exfiltration_long_duration_multi_window():
    """Test longer rolling window captures slow behavior that short window misses."""
    det = ExfiltrationDetector(
        slow_exfil_enabled=True,
        slow_windows=[60.0, 900.0],
        slow_min_transfers=4,
        slow_min_cumulative_bytes=35_000,
    )
    det.reset_state()

    alerts = []
    for i in range(4):
        flow = {
            "flow_id": f"TCP:10.0.0.80:{55000+i}<->203.0.113.66:443",
            "src_ip": "10.0.0.80",
            "src_port": 55000 + i,
            "dst_ip": "203.0.113.66",
            "dst_port": 443,
            "protocol": "TCP",
            "forward_bytes": 10_000,
            "backward_bytes": 100,
            "duration": 1.0,
            "start_time": 1000.0 + i * 120.0,
            "end_time": 1001.0 + i * 120.0,
        }
        res = det.predict(flow)
        if res:
            alerts.append(res)

    assert len(alerts) >= 1
    alert = alerts[-1]
    assert alert.evidence["window_seconds"] == 900
    assert alert.evidence["transfer_count"] == 4


def test_exfiltration_stateful_zero_inbound_safe():
    """Test stateful rolling detector handles 0 inbound bytes safely."""
    det = ExfiltrationDetector(
        slow_exfil_enabled=True,
        slow_min_transfers=4,
        slow_min_cumulative_bytes=35_000,
    )
    det.reset_state()

    for i in range(4):
        flow = {
            "flow_id": f"TCP:10.0.0.90:{56000+i}<->203.0.113.55:443",
            "src_ip": "10.0.0.90",
            "src_port": 56000 + i,
            "dst_ip": "203.0.113.55",
            "dst_port": 443,
            "protocol": "TCP",
            "forward_bytes": 10_000,
            "backward_bytes": 0,
            "duration": 1.0,
            "start_time": 2000.0 + i * 10.0,
            "end_time": 2001.0 + i * 10.0,
        }
        res = det.predict(flow)

    assert res is not None
    assert not np.isnan(res.evidence["outbound_inbound_ratio"])
    assert not np.isinf(res.evidence["outbound_inbound_ratio"])
    assert res.evidence["outbound_inbound_ratio"] > 0



def test_udp_flood_detection():
    det = DDoSDetector(udp_rate_threshold=100.0)
    flow = {
        "flow_id": "UDP:198.51.100.10:45000<->10.0.0.100:9999",
        "src_ip": "198.51.100.10",
        "src_port": 45000,
        "dst_ip": "10.0.0.100",
        "dst_port": 9999,
        "protocol": "UDP",
        "duration": 1.0,
        "packets_per_sec": 250.0,
        "total_packets": 250,
    }
    res = det.predict(flow)
    assert res is not None
    assert res.threat_class == "UDP_FLOOD"
    assert res.confidence >= 0.85
    assert res.evidence["udp_packet_rate"] == 250.0


def test_udp_amplification_reflection_detection():
    det = DDoSDetector()
    # NTP reflection from port 123 with high packet size
    flow = {
        "flow_id": "UDP:203.0.113.50:123<->10.0.0.5:43210",
        "src_ip": "203.0.113.50",
        "src_port": 123,  # NTP
        "dst_ip": "10.0.0.5",
        "dst_port": 43210,
        "protocol": "UDP",
        "duration": 1.0,
        "packets_per_sec": 80.0,
        "mean_packet_size": 480.0,
    }
    res = det.predict(flow)
    assert res is not None
    assert res.threat_class == "AMPLIFICATION_REFLECTION_DDOS"
    assert res.confidence >= 0.85
    assert res.evidence["amplification_service"] == "NTP"


def test_spoofed_ddos_detection():
    det = DDoSDetector()
    flow = {
        "flow_id": "UDP:10.0.0.1:0<->10.0.0.50:80",
        "src_ip": "10.0.0.1",
        "src_port": 0,
        "dst_ip": "10.0.0.50",
        "dst_port": 80,
        "protocol": "UDP",
        "packets_per_sec": 60.0,
    }
    context = {
        "source_entropy": 5.2,
        "unique_sources": 250,
    }
    res = det.predict(flow, context=context)
    assert res is not None
    assert res.threat_class == "SPOOFED_SOURCE_DDOS"
    assert res.evidence["source_ip_entropy"] == 5.2


def test_quic_encrypted_traffic_detection():
    det = EncryptedTrafficDetector()
    flow = {
        "flow_id": "UDP:10.0.0.40:51234<->198.51.100.80:443",
        "src_ip": "10.0.0.40",
        "src_port": 51234,
        "dst_ip": "198.51.100.80",
        "dst_port": 443,
        "protocol": "UDP",
        "duration": 4.0,
        "timestamps": [1.0, 2.0, 3.0, 4.0],
        "packet_lengths": [1200, 1200, 1200, 1200],  # Constant payload size
        "quic_metadata": {
            "has_quic": True,
            "version": "0x00000001",
            "is_initial": True,
            "header_types": ["long"],
        },
    }
    res = det.predict(flow)
    assert res is not None
    assert res.threat_class == "SUSPICIOUS_ENCRYPTED_TRAFFIC"
    assert res.evidence["is_quic"] is True

