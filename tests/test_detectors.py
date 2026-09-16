"""
Unit Tests for Specialized Cyber Threat Detectors.
Validates detection logic, confidence ratings, and evidence structures for all 7 threat categories.
"""

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
    det = ExfiltrationDetector(ratio_threshold=5.0)
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
