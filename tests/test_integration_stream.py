"""
End-to-end Integration Test for AEGIS Streaming Ingestion and Threat Detection.
Tests complete pipeline:
PassiveInputSource (PCAP Replay / Synthetic / Data Diode) -> FlowStreamManager -> FlowFeatureExtractor -> AlertPipeline -> ThreatDatabase
Verifies source provenance preservation (synthetic_stream -> synthetic_stream, data_diode -> data_diode).
"""

from pathlib import Path
import pytest

from app.alerts.generator import AlertPipeline
from app.features.flow_features import FlowFeatureExtractor
from app.ingest.flow_stream import FlowStreamManager
from app.ingest.replay import PCAPReplayEngine
from app.ingest.sources import DataDiodeFeedSource, PacketEvent, PcapReplaySource, SyntheticStreamSource
from app.storage.database import ThreatDatabase


def test_full_pipeline_with_synthetic_stream(tmp_path):
    test_db_path = str(tmp_path / "test_aegis_integration.db")
    db = ThreatDatabase(test_db_path)

    pipeline = AlertPipeline(db=db)
    flow_manager = FlowStreamManager(flow_timeout_sec=1.0, sliding_window_sec=1.0)
    source = SyntheticStreamSource(count=150, interval_sec=0.0)

    alerts_captured = []
    pipeline.subscribe(lambda alert: alerts_captured.append(alert))

    for event in source.stream_events():
        pkt_dict = event.to_dict()
        active_flow, expired_flows = flow_manager.process_packet(pkt_dict)

        for flow_dict in expired_flows:
            features = FlowFeatureExtractor.extract_features(flow_dict)
            if flow_dict.get("dns_queries"):
                features["dns_queries"] = flow_dict["dns_queries"]
            if flow_dict.get("tls_metadata"):
                features["tls_metadata"] = flow_dict["tls_metadata"]
            features["timestamps"] = flow_dict.get("timestamps", [])
            features["packet_lengths"] = flow_dict.get("packet_lengths", [])

            pipeline.process_flow(features)

    # Flush remaining flows
    remaining = flow_manager.flush_all()
    for flow_dict in remaining:
        features = FlowFeatureExtractor.extract_features(flow_dict)
        pipeline.process_flow(features)

    # Force database commit of any buffered items
    db.flush_buffers()

    # Verify database contents and source provenance
    flows = db.get_flows(limit=100)
    alerts = db.get_alerts(limit=100)

    assert len(flows) > 0
    assert all(f.get("input_source") == "synthetic_stream" for f in flows)

    if alerts:
        for alert in alerts:
            assert alert.get("input_source") == "synthetic_stream"
            assert "threat_class" in alert
            assert "severity" in alert
            assert alert.get("confidence", 0.0) > 0.0


def test_source_provenance_data_diode_regression(tmp_path):
    """Regression test ensuring data_diode provenance is preserved all the way to StandardAlert and DB."""
    test_db_path = str(tmp_path / "test_diode_integration.db")
    db = ThreatDatabase(test_db_path)
    pipeline = AlertPipeline(db=db)
    flow_manager = FlowStreamManager(flow_timeout_sec=0.5, sliding_window_sec=1.0)

    queue = []
    source = DataDiodeFeedSource(queue_buffer=queue)

    # Append synthetic SYN flood packets to diode queue
    for i in range(40):
        ev = PacketEvent(
            timestamp=1000.0 + i * 0.01,
            length=64,
            src_ip="192.168.1.55",
            src_port=40000,
            dst_ip="10.0.0.99",
            dst_port=80,
            protocol="TCP",
            is_syn=True,
            is_ack=False,
            input_source="data_diode",
        )
        queue.append(ev)

    for event in source.stream_events():
        pkt_dict = event.to_dict()
        active_flow, expired_flows = flow_manager.process_packet(pkt_dict)
        for flow_dict in expired_flows:
            features = FlowFeatureExtractor.extract_features(flow_dict)
            pipeline.process_flow(features)

    remaining = flow_manager.flush_all()
    for flow_dict in remaining:
        features = FlowFeatureExtractor.extract_features(flow_dict)
        pipeline.process_flow(features)

    db.flush_buffers()
    alerts = db.get_alerts(limit=10)
    assert len(alerts) > 0
    for a in alerts:
        assert a.get("input_source") == "data_diode"


def test_full_pipeline_with_pcap_replay(tmp_path):
    """
    End-to-end integration test exercising:
    PCAP -> Replay -> Flow Assembly -> Feature Extraction -> Detectors -> Threat Fusion -> Alerts & DB.
    Validates that the exfiltration scenario in demo.pcap correctly triggers DATA_EXFILTRATION with forensic evidence.
    """
    pcap_path = "data/sample/demo.pcap"
    if not Path(pcap_path).exists():
        pytest.skip(f"PCAP {pcap_path} not found.")

    test_db_path = str(tmp_path / "test_pcap_integration.db")
    db = ThreatDatabase(test_db_path)

    engine = PCAPReplayEngine(
        pcap_path=pcap_path,
        speed=0.0,
        flow_timeout=2.0,
        sliding_window=2.0,
        db_path=test_db_path
    )
    engine.run()

    # Query flows and alerts from database
    flows = db.get_flows(limit=500)
    alerts = db.get_alerts(limit=500)

    assert len(flows) > 0, "No flows recorded from PCAP"
    assert any(f.get("input_source") == "pcap_replay" for f in flows)

    assert len(alerts) > 0, "No alerts generated from PCAP replay"
    alert_classes = {a["threat_class"] for a in alerts}

    # Verify DATA_EXFILTRATION is generated from actual flow features
    assert "DATA_EXFILTRATION" in alert_classes, (
        f"DATA_EXFILTRATION alert missing from demo PCAP replay. Alerts generated: {alert_classes}"
    )

    # Verify both BULK and SLOW_AND_LOW exfiltration alerts are generated
    exfil_alerts = [a for a in alerts if a["threat_class"] == "DATA_EXFILTRATION"]
    assert len(exfil_alerts) >= 2, f"Expected at least 2 exfiltration alerts, got {len(exfil_alerts)}"

    # 1. Bulk exfiltration verification (10.0.0.22 -> 203.0.113.80:443)
    bulk_alerts = [a for a in exfil_alerts if a["src_ip"] == "10.0.0.22" and a["dst_ip"] == "203.0.113.80"]
    assert len(bulk_alerts) >= 1, "Missing bulk exfiltration alert for 10.0.0.22"
    bulk_alert = bulk_alerts[0]
    assert bulk_alert["dst_port"] == 443
    assert bulk_alert["evidence"].get("subtype") in ("BULK", "COMPOSITE_EXFILTRATION")
    assert bulk_alert["evidence"]["bytes_out"] >= 200_000
    assert bulk_alert["evidence"]["out_in_ratio"] >= 6.0
    assert bulk_alert["evidence"]["duration_sec"] > 0

    # 2. Slow-and-low exfiltration verification (10.0.0.23 -> 203.0.113.90:443)
    slow_alerts = [a for a in exfil_alerts if a["src_ip"] == "10.0.0.23" and a["dst_ip"] == "203.0.113.90"]
    assert len(slow_alerts) >= 1, "Missing slow-and-low exfiltration alert for 10.0.0.23"
    slow_alert = slow_alerts[0]
    assert slow_alert["dst_port"] == 443
    assert slow_alert["evidence"].get("subtype") == "SLOW_AND_LOW"
    assert slow_alert["evidence"]["transfer_count"] >= 4
    assert slow_alert["evidence"]["cumulative_outbound_bytes"] >= 35_000
    assert slow_alert["evidence"]["destination_persistence"] >= 0.75
    assert slow_alert["evidence"]["iat_cv"] <= 0.50
    assert slow_alert["evidence"]["slow_exfiltration_score"] >= 0.65

    # 3. Anti-False-Positive: 10.0.0.45 (balanced benign periodic traffic) must have zero exfiltration alerts
    benign_exfil = [a for a in exfil_alerts if a["src_ip"] == "10.0.0.45"]
    assert len(benign_exfil) == 0, f"False positive: benign periodic traffic alerted as exfiltration: {benign_exfil}"

    # Also verify other attack classes in demo PCAP are preserved and detected
    expected_attacks = {"DGA_DOMAIN_DETECTION", "PORT_SCAN_HORIZONTAL", "BOTNET_C2_BEACONING"}
    assert expected_attacks.issubset(alert_classes), (
        f"Missing expected attack classes in demo PCAP. Found: {alert_classes}"
    )

