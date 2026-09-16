"""
Unit Tests for Standard Alert Schema and Storage Layer.
"""

from pathlib import Path
import pytest
from app.alerts.schema import StandardAlert, SeverityLevel, FlowRecord
from app.storage.database import ThreatDatabase


def test_standard_alert_schema():
    alert = StandardAlert(
        flow_id="TCP:10.0.0.1:1234<->10.0.0.2:80",
        src_ip="10.0.0.1",
        src_port=1234,
        dst_ip="10.0.0.2",
        dst_port=80,
        protocol="TCP",
        threat_class="SYN_FLOOD",
        severity=SeverityLevel.CRITICAL,
        confidence=0.97123,
        detector="ddos_detector",
        evidence={"syn_rate": 82400, "unique_sources": 18231}
    )
    assert alert.confidence == 0.9712
    d = alert.to_dict()
    assert d["threat_class"] == "SYN_FLOOD"
    assert d["evidence"]["syn_rate"] == 82400


def test_database_crud(tmp_path):
    db_file = tmp_path / "test_threats.db"
    db = ThreatDatabase(str(db_file))

    alert = StandardAlert(
        flow_id="TCP:1.1.1.1:100<->2.2.2.2:443",
        src_ip="1.1.1.1",
        src_port=100,
        dst_ip="2.2.2.2",
        dst_port=443,
        protocol="TCP",
        threat_class="PORT_SCAN_VERTICAL",
        severity=SeverityLevel.HIGH,
        confidence=0.91,
        detector="recon_detector",
        evidence={"unique_ports": 45}
    )

    row_id = db.insert_alert(alert)
    assert row_id > 0

    recent = db.get_recent_alerts(limit=10)
    assert len(recent) == 1
    assert recent[0]["threat_class"] == "PORT_SCAN_VERTICAL"
    assert recent[0]["evidence"]["unique_ports"] == 45

    counts = db.get_alert_counts_by_severity()
    assert counts["HIGH"] == 1
    assert counts["CRITICAL"] == 0

    # Flow insert
    flow = FlowRecord(
        flow_id="TCP:1.1.1.1:100<->2.2.2.2:443",
        start_time=100.0,
        end_time=102.0,
        src_ip="1.1.1.1",
        src_port=100,
        dst_ip="2.2.2.2",
        dst_port=443,
        protocol="TCP",
        packet_count=10,
        byte_count=1500,
        duration_sec=2.0,
        forward_packets=5,
        backward_packets=5,
        forward_bytes=750,
        backward_bytes=750,
    )
    db.insert_flow(flow)

    stats = db.get_system_stats()
    assert stats["total_flows"] == 1
    assert stats["total_alerts"] == 1
