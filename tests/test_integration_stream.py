"""
End-to-end Integration Test for AEGIS Streaming Ingestion and Threat Detection.
Tests complete pipeline:
PassiveInputSource (PCAP Replay / Synthetic) -> FlowStreamManager -> FlowFeatureExtractor -> AlertPipeline -> ThreatDatabase
"""

from pathlib import Path
import pytest

from app.alerts.generator import AlertPipeline
from app.features.flow_features import FlowFeatureExtractor
from app.ingest.flow_stream import FlowStreamManager
from app.ingest.sources import PcapReplaySource, SyntheticStreamSource
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
            features["input_source"] = flow_dict.get("source_type", "synthetic_stream")

            pipeline.process_flow(features)

    # Flush remaining flows
    remaining = flow_manager.flush_all()
    for flow_dict in remaining:
        features = FlowFeatureExtractor.extract_features(flow_dict)
        features["input_source"] = flow_dict.get("source_type", "synthetic_stream")
        pipeline.process_flow(features)

    # Force database commit of any buffered items
    db.flush_buffers()

    # Verify database contents
    flows = db.get_flows(limit=100)
    alerts = db.get_alerts(limit=100)

    assert len(flows) > 0
    assert any(f.get("input_source") == "synthetic_stream" for f in flows)

    if alerts:
        for alert in alerts:
            assert alert.get("input_source") == "synthetic_stream"
            assert "threat_class" in alert
            assert "severity" in alert
            assert alert.get("confidence", 0.0) > 0.0


def test_full_pipeline_with_pcap_replay(tmp_path):
    pcap_path = "data/sample/demo.pcap"
    if not Path(pcap_path).exists():
        pytest.skip(f"PCAP {pcap_path} not found.")

    test_db_path = str(tmp_path / "test_pcap_integration.db")
    db = ThreatDatabase(test_db_path)

    pipeline = AlertPipeline(db=db)
    flow_manager = FlowStreamManager(flow_timeout_sec=2.0, sliding_window_sec=2.0)
    source = PcapReplaySource(pcap_path=pcap_path, speed=0.0)

    alert_count = 0
    pipeline.subscribe(lambda a: None)

    for event in source.stream_events():
        pkt_dict = event.to_dict()
        active_flow, expired_flows = flow_manager.process_packet(pkt_dict)

        for flow_dict in expired_flows:
            features = FlowFeatureExtractor.extract_features(flow_dict)
            features["input_source"] = flow_dict.get("source_type", "pcap_replay")
            pipeline.process_flow(features)

    remaining = flow_manager.flush_all()
    for flow_dict in remaining:
        features = FlowFeatureExtractor.extract_features(flow_dict)
        features["input_source"] = flow_dict.get("source_type", "pcap_replay")
        pipeline.process_flow(features)

    db.flush_buffers()
    flows = db.get_flows(limit=50)
    assert len(flows) > 0
    assert any(f.get("input_source") == "pcap_replay" for f in flows)
