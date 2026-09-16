"""
Threat Fusion Engine.
Correlates outputs from individual detectors, applies multi-vector behavioral rules,
synthesizes composite threat assessments, and generates structured StandardAlerts.
"""

from collections import defaultdict
from datetime import datetime, timezone
import time
from typing import Any, Dict, List, Optional, Tuple

from app.alerts.schema import DetectionResult, SeverityLevel, StandardAlert


class ThreatFusionEngine:
    """
    Synthesizes and correlates multi-detector outputs into unified, explainable threat alerts.
    Also handles sliding-window alert deduplication to prevent alert storms.
    """

    def __init__(
        self,
        correlation_window_sec: float = 25.0,
        confidence_boost: float = 0.08,
        dedup_window_sec: float = 15.0
    ):
        self.correlation_window_sec = correlation_window_sec
        self.confidence_boost = confidence_boost
        self.dedup_window_sec = dedup_window_sec

        # Deduplication cache: (src_ip, dst_ip, threat_class) -> last_alert_time
        self._dedup_cache: Dict[Tuple[str, str, str], float] = {}

    def fuse(
        self,
        detections: List[DetectionResult],
        flow_features: Dict[str, Any]
    ) -> List[StandardAlert]:
        """
        Receives raw detection candidates for a flow/context.
        Emits synthesized StandardAlert objects.
        """
        if not detections:
            return []

        now_ts = flow_features.get("end_time") or time.time()
        now_iso = datetime.now(timezone.utc).isoformat()

        # Group detections by target/flow
        det_map = {d.detector: d for d in detections}
        threat_classes = set(d.threat_class for d in detections)

        final_alerts: List[StandardAlert] = []

        # Multi-detector Composite Rule 1: Encrypted Traffic + Data Exfiltration
        if (
            "encrypted_traffic_detector" in det_map and
            "exfiltration_detector" in det_map
        ):
            enc = det_map["encrypted_traffic_detector"]
            exf = det_map["exfiltration_detector"]
            fused_conf = min(0.99, max(enc.confidence, exf.confidence) + self.confidence_boost)

            combined_evidence = {
                "fusion_summary": "Correlated high-volume outbound asymmetric transfer inside encrypted session with suspicious metadata",
                "encrypted_traffic_signals": enc.evidence,
                "exfiltration_signals": exf.evidence,
            }

            alert = StandardAlert(
                timestamp=now_iso,
                flow_id=flow_features.get("flow_id", "unknown"),
                src_ip=flow_features.get("src_ip", "0.0.0.0"),
                src_port=flow_features.get("src_port", 0),
                dst_ip=flow_features.get("dst_ip", "0.0.0.0"),
                dst_port=flow_features.get("dst_port", 0),
                protocol=flow_features.get("protocol", "TCP"),
                threat_class="POSSIBLE_ENCRYPTED_EXFILTRATION",
                severity=SeverityLevel.CRITICAL,
                confidence=round(fused_conf, 4),
                detector="fusion_engine (encrypted + exfiltration)",
                evidence=combined_evidence,
            )
            if self._should_emit(alert, now_ts):
                final_alerts.append(alert)
            return final_alerts

        # Multi-detector Composite Rule 2: DGA + C2 Beaconing
        if (
            "dga_detector" in det_map and
            "beaconing_detector" in det_map
        ):
            dga = det_map["dga_detector"]
            bcn = det_map["beaconing_detector"]
            fused_conf = min(0.99, max(dga.confidence, bcn.confidence) + self.confidence_boost)

            combined_evidence = {
                "fusion_summary": "Periodic automated beaconing correlated with algorithmic pseudo-random DGA domain query",
                "dga_signals": dga.evidence,
                "beaconing_signals": bcn.evidence,
            }

            alert = StandardAlert(
                timestamp=now_iso,
                flow_id=flow_features.get("flow_id", "unknown"),
                src_ip=flow_features.get("src_ip", "0.0.0.0"),
                src_port=flow_features.get("src_port", 0),
                dst_ip=flow_features.get("dst_ip", "0.0.0.0"),
                dst_port=flow_features.get("dst_port", 0),
                protocol=flow_features.get("protocol", "TCP"),
                threat_class="BOTNET_C2_INFRASTRUCTURE",
                severity=SeverityLevel.CRITICAL,
                confidence=round(fused_conf, 4),
                detector="fusion_engine (dga + beaconing)",
                evidence=combined_evidence,
            )
            if self._should_emit(alert, now_ts):
                final_alerts.append(alert)
            return final_alerts

        # Multi-detector Composite Rule 3: Recon + Exfiltration
        if (
            "recon_detector" in det_map and
            "exfiltration_detector" in det_map
        ):
            rcn = det_map["recon_detector"]
            exf = det_map["exfiltration_detector"]
            fused_conf = min(0.98, max(rcn.confidence, exf.confidence) + self.confidence_boost)

            alert = StandardAlert(
                timestamp=now_iso,
                flow_id=flow_features.get("flow_id", "unknown"),
                src_ip=flow_features.get("src_ip", "0.0.0.0"),
                src_port=flow_features.get("src_port", 0),
                dst_ip=flow_features.get("dst_ip", "0.0.0.0"),
                dst_port=flow_features.get("dst_port", 0),
                protocol=flow_features.get("protocol", "TCP"),
                threat_class="TARGETED_RECON_AND_EXFILTRATION",
                severity=SeverityLevel.CRITICAL,
                confidence=round(fused_conf, 4),
                detector="fusion_engine (recon + exfiltration)",
                evidence={"recon_signals": rcn.evidence, "exfiltration_signals": exf.evidence},
            )
            if self._should_emit(alert, now_ts):
                final_alerts.append(alert)
            return final_alerts

        # Standard / Single Detector alert forwarding
        for det in detections:
            alert = StandardAlert(
                timestamp=now_iso,
                flow_id=flow_features.get("flow_id", "unknown"),
                src_ip=flow_features.get("src_ip", "0.0.0.0"),
                src_port=flow_features.get("src_port", 0),
                dst_ip=flow_features.get("dst_ip", "0.0.0.0"),
                dst_port=flow_features.get("dst_port", 0),
                protocol=flow_features.get("protocol", "TCP"),
                threat_class=det.threat_class,
                severity=det.severity,
                confidence=round(det.confidence, 4),
                detector=det.detector,
                evidence=det.evidence,
            )
            if self._should_emit(alert, now_ts):
                final_alerts.append(alert)

        return final_alerts

    def _should_emit(self, alert: StandardAlert, current_time: float) -> bool:
        """Deduplicates repetitive alerts on identical endpoints within sliding window."""
        key = (alert.src_ip, alert.dst_ip, alert.threat_class)
        last_time = self._dedup_cache.get(key, 0.0)
        if current_time - last_time < self.dedup_window_sec:
            return False
        self._dedup_cache[key] = current_time
        return True
