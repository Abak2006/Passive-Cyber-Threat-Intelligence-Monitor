"""
Alert Generation Pipeline Coordinator.
Executes specialized detectors, delegates to ThreatFusionEngine,
and dispatches structured alerts to database and logging subscribers.
"""

import logging
import time
from typing import Any, Callable, Dict, List, Optional

from app.alerts.schema import StandardAlert, DetectionResult
from app.config import Config, get_config
from app.detectors.ddos import DDoSDetector
from app.detectors.beaconing import BeaconingDetector
from app.detectors.dga import DGADetector
from app.detectors.dns_tunnel import DNSTunnelDetector
from app.detectors.encrypted import EncryptedTrafficDetector
from app.detectors.recon import ReconDetector
from app.detectors.exfiltration import ExfiltrationDetector
from app.fusion.threat_fusion import ThreatFusionEngine
from app.storage.database import ThreatDatabase

logger = logging.getLogger(__name__)


class AlertPipeline:
    def __init__(self, config: Optional[Config] = None, db: Optional[ThreatDatabase] = None):
        self.cfg = config or get_config()
        self.db = db or ThreatDatabase(self.cfg.database_path)

        # Initialize detectors
        self.detectors = [
            DDoSDetector(
                syn_rate_threshold=self.cfg.get("detectors.ddos.syn_rate_threshold", 50.0),
                udp_rate_threshold=self.cfg.get("detectors.ddos.udp_rate_threshold", 80.0),
                model_path=self.cfg.get("detectors.ddos.model_path", "models/ddos_detector.joblib")
            ),
            BeaconingDetector(
                min_connections=self.cfg.get("detectors.beaconing.min_connections", 4),
                cv_threshold=self.cfg.get("detectors.beaconing.cv_threshold", 0.25),
                periodicity_threshold=self.cfg.get("detectors.beaconing.periodicity_score_threshold", 0.70)
            ),
            DGADetector(
                entropy_threshold=self.cfg.get("detectors.dga.entropy_threshold", 3.6),
                length_threshold=self.cfg.get("detectors.dga.length_threshold", 15),
                model_path=self.cfg.get("detectors.dga.model_path", "models/dga_detector.joblib")
            ),
            DNSTunnelDetector(
                subdomain_len_threshold=self.cfg.get("detectors.dns_tunnel.subdomain_length_threshold", 24),
                subdomain_entropy_threshold=self.cfg.get("detectors.dns_tunnel.subdomain_entropy_threshold", 3.75),
                query_frequency_threshold=self.cfg.get("detectors.dns_tunnel.query_frequency_threshold", 5.0)
            ),
            EncryptedTrafficDetector(
                outbound_ratio_threshold=self.cfg.get("detectors.encrypted.outbound_inbound_ratio_threshold", 7.0),
                periodicity_threshold=self.cfg.get("detectors.encrypted.periodicity_threshold", 0.70),
                model_path=self.cfg.get("detectors.encrypted.model_path", "models/encrypted_anomaly.joblib")
            ),
            ReconDetector(
                horizontal_threshold=self.cfg.get("detectors.recon.horizontal_scan_threshold", 8),
                vertical_threshold=self.cfg.get("detectors.recon.vertical_scan_threshold", 8)
            ),
            ExfiltrationDetector(
                ratio_threshold=self.cfg.get("detectors.exfiltration.outbound_inbound_byte_ratio", 6.0),
                sustained_rate_threshold_bps=self.cfg.get("detectors.exfiltration.sustained_outbound_rate_bps", 1_500_000.0),
                model_path=self.cfg.get("detectors.exfiltration.model_path", "models/exfil_detector.joblib")
            ),
        ]

        self.fusion_engine = ThreatFusionEngine(
            correlation_window_sec=self.cfg.get("fusion.correlation_window_sec", 25.0),
            confidence_boost=self.cfg.get("fusion.confidence_boost_multi_detector", 0.08)
        )

        self.subscribers: List[Callable[[StandardAlert], None]] = []

    def subscribe(self, callback: Callable[[StandardAlert], None]):
        self.subscribers.append(callback)

    def process_flow(
        self,
        flow_features: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> List[StandardAlert]:
        """
        Runs all detectors, executes fusion, persists alerts, and dispatches to subscribers.
        """
        detections: List[DetectionResult] = []
        for det in self.detectors:
            try:
                res = det.predict(flow_features, context)
                if res:
                    detections.append(res)
            except Exception as e:
                logger.error(f"Error in detector {det.name}: {e}")

        # Run Threat Fusion
        alerts = self.fusion_engine.fuse(detections, flow_features)

        # Persist flow summary record
        if flow_features.get("flow_id") and hasattr(self.db, "queue_flow"):
            try:
                from app.alerts.schema import FlowRecord
                flow_rec = FlowRecord(
                    flow_id=flow_features["flow_id"],
                    start_time=flow_features.get("start_time", time.time()),
                    end_time=flow_features.get("end_time", time.time()),
                    src_ip=flow_features.get("src_ip", "0.0.0.0"),
                    src_port=flow_features.get("src_port", 0),
                    dst_ip=flow_features.get("dst_ip", "0.0.0.0"),
                    dst_port=flow_features.get("dst_port", 0),
                    protocol=flow_features.get("protocol", "TCP"),
                    packet_count=flow_features.get("total_packets", 0),
                    byte_count=flow_features.get("total_bytes", 0),
                    duration_sec=round(flow_features.get("duration", 0.0), 4),
                    forward_packets=flow_features.get("forward_packets", 0),
                    backward_packets=flow_features.get("backward_packets", 0),
                    forward_bytes=flow_features.get("forward_bytes", 0),
                    backward_bytes=flow_features.get("backward_bytes", 0),
                    input_source=flow_features.get("input_source", "pcap_replay"),
                )
                self.db.queue_flow(flow_rec)
            except Exception as e:
                logger.error(f"Database error saving flow: {e}")

        # Persist and notify alerts
        for alert in alerts:
            try:
                self.db.insert_alert(alert)
            except Exception as e:
                logger.error(f"Database error saving alert: {e}")

            for sub in self.subscribers:
                try:
                    sub(alert)
                except Exception as e:
                    logger.error(f"Error in alert subscriber: {e}")

        return alerts
