"""
Unit Tests for Threat Fusion Engine.
Tests multi-detector composite rules and sliding-window alert deduplication.
"""

import time
from app.alerts.schema import DetectionResult, SeverityLevel
from app.fusion.threat_fusion import ThreatFusionEngine


def test_fusion_encrypted_exfiltration():
    fusion = ThreatFusionEngine()
    flow = {
        "flow_id": "TCP:10.0.0.30:50000<->203.0.113.99:443",
        "src_ip": "10.0.0.30",
        "src_port": 50000,
        "dst_ip": "203.0.113.99",
        "dst_port": 443,
        "protocol": "TCP",
        "end_time": time.time(),
    }
    det1 = DetectionResult(
        threat_class="SUSPICIOUS_ENCRYPTED_TRAFFIC",
        confidence=0.91,
        severity=SeverityLevel.HIGH,
        detector="encrypted_traffic_detector",
        evidence={"periodicity_score": 0.94},
        flow_id=flow["flow_id"],
        src_ip=flow["src_ip"],
        src_port=flow["src_port"],
        dst_ip=flow["dst_ip"],
        dst_port=flow["dst_port"],
        protocol="TCP",
    )
    det2 = DetectionResult(
        threat_class="DATA_EXFILTRATION",
        confidence=0.96,
        severity=SeverityLevel.CRITICAL,
        detector="exfiltration_detector",
        evidence={"outbound_inbound_ratio": 45.0},
        flow_id=flow["flow_id"],
        src_ip=flow["src_ip"],
        src_port=flow["src_port"],
        dst_ip=flow["dst_ip"],
        dst_port=flow["dst_port"],
        protocol="TCP",
    )

    fused = fusion.fuse([det1, det2], flow)
    assert len(fused) == 1
    alert = fused[0]
    assert alert.threat_class == "POSSIBLE_ENCRYPTED_EXFILTRATION"
    assert alert.severity == SeverityLevel.CRITICAL
    assert alert.confidence >= 0.96
    assert "encrypted_traffic_signals" in alert.evidence


def test_fusion_dga_and_beaconing():
    fusion = ThreatFusionEngine()
    flow = {
        "flow_id": "TCP:10.0.0.15:49152<->198.51.100.44:8443",
        "src_ip": "10.0.0.15",
        "src_port": 49152,
        "dst_ip": "198.51.100.44",
        "dst_port": 8443,
        "protocol": "TCP",
        "end_time": time.time(),
    }
    det1 = DetectionResult(
        threat_class="DGA_DOMAIN_DETECTION",
        confidence=0.90,
        severity=SeverityLevel.HIGH,
        detector="dga_detector",
        evidence={"domain": "x7k29a8d91b4mz09.biz"},
    )
    det2 = DetectionResult(
        threat_class="BOTNET_C2_BEACONING",
        confidence=0.88,
        severity=SeverityLevel.HIGH,
        detector="beaconing_detector",
        evidence={"cv": 0.04},
    )

    fused = fusion.fuse([det1, det2], flow)
    assert len(fused) == 1
    assert fused[0].threat_class == "BOTNET_C2_INFRASTRUCTURE"
    assert fused[0].severity == SeverityLevel.CRITICAL


def test_alert_deduplication():
    fusion = ThreatFusionEngine(dedup_window_sec=10.0)
    now = time.time()
    flow = {
        "flow_id": "TCP:10.0.0.1:100<->10.0.0.2:80",
        "src_ip": "10.0.0.1",
        "src_port": 100,
        "dst_ip": "10.0.0.2",
        "dst_port": 80,
        "protocol": "TCP",
        "end_time": now,
    }
    det = DetectionResult(
        threat_class="SYN_FLOOD",
        confidence=0.95,
        severity=SeverityLevel.CRITICAL,
        detector="ddos_detector",
    )

    # First emission allowed
    res1 = fusion.fuse([det], flow)
    assert len(res1) == 1

    # Immediate second emission within 10s window throttled
    flow["end_time"] = now + 1.0
    res2 = fusion.fuse([det], flow)
    assert len(res2) == 0

    # After dedup window expires, allowed again
    flow["end_time"] = now + 11.0
    res3 = fusion.fuse([det], flow)
    assert len(res3) == 1
