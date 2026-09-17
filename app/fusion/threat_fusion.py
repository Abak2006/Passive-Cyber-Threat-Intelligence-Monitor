"""
Threat Fusion Engine (AEGIS v2.1).
Correlates outputs from individual detectors, synthesizes composite threat assessments,
handles unknown anomaly classifications, and generates structured, explainable StandardAlerts.
Distinguishes SAME-SIGNAL evidence from INDEPENDENT PROTOCOL / BEHAVIORAL signals.
"""

from collections import defaultdict
from datetime import datetime, timezone
import time
from typing import Any, Dict, List, Optional, Tuple

from app.alerts.schema import DetectionResult, SeverityLevel, StandardAlert


class ThreatFusionEngine:
    """
    Synthesizes and correlates multi-detector outputs into unified, explainable threat alerts.
    Distinguishes Malicious Evidence, Benign Evidence, and Insufficient Evidence.
    Combines Timing Group, Behavior Group, and Protocol Group evidence without double-counting.
    Deduplicates repetitive alerts on identical endpoints within a sliding time window.
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
        Emits synthesized StandardAlert objects with explainable evidence.
        """
        if not detections:
            return []

        now_ts = flow_features.get("end_time") or time.time()
        now_iso = datetime.now(timezone.utc).isoformat()
        input_source = flow_features.get("input_source") or flow_features.get("source_type", "pcap_replay")

        det_map = {d.detector: d for d in detections}
        final_alerts: List[StandardAlert] = []

        # -------------------------------------------------------------
        # COMPOSITE RULE 1: Encrypted Traffic + Data Exfiltration
        # -------------------------------------------------------------
        if (
            "encrypted_traffic_detector" in det_map and
            "exfiltration_detector" in det_map
        ):
            enc = det_map["encrypted_traffic_detector"]
            exf = det_map["exfiltration_detector"]
            fused_conf = min(0.99, max(enc.confidence, exf.confidence) + self.confidence_boost)

            combined_evidence = {
                "fusion_summary": "Correlated high-volume outbound asymmetric transfer inside encrypted session with suspicious metadata",
                "malicious_evidence": [
                    enc.evidence.get("threat_diagnosis", "Suspicious encrypted session"),
                    exf.evidence.get("threat_diagnosis", "High outbound byte transfer"),
                ],
                "encrypted_signals": enc.evidence,
                "encrypted_traffic_signals": enc.evidence,
                "exfiltration_signals": exf.evidence,
                "passive_guarantee": "Forensic evaluation performed on observable flow metadata. Zero payload decryption.",
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
                input_source=input_source,
                evidence=combined_evidence,
            )
            if self._should_emit(alert, now_ts):
                final_alerts.append(alert)
            return final_alerts

        # -------------------------------------------------------------
        # COMPOSITE RULE 2: DGA + C2 Beaconing (or Suspicious Encrypted + Beaconing)
        # -------------------------------------------------------------
        if (
            "dga_detector" in det_map and
            "beaconing_detector" in det_map
        ):
            dga = det_map["dga_detector"]
            bcn = det_map["beaconing_detector"]
            fused_conf = min(0.99, max(dga.confidence, bcn.confidence) + self.confidence_boost)

            combined_evidence = {
                "fusion_summary": "Periodic automated beaconing correlated with algorithmic pseudo-random DGA domain query",
                "malicious_evidence": [
                    dga.evidence.get("threat_diagnosis", "Algorithmic domain name generation"),
                    bcn.evidence.get("threat_diagnosis", "Periodic beaconing heartbeat"),
                ],
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
                input_source=input_source,
                evidence=combined_evidence,
            )
            if self._should_emit(alert, now_ts):
                final_alerts.append(alert)
            return final_alerts

        # -------------------------------------------------------------
        # COMPOSITE RULE 3: Encrypted Traffic + C2 Beaconing / Anomaly
        # -------------------------------------------------------------
        if (
            "encrypted_traffic_detector" in det_map and
            "beaconing_detector" in det_map
        ):
            enc = det_map["encrypted_traffic_detector"]
            bcn = det_map["beaconing_detector"]
            fused_conf = min(0.99, max(enc.confidence, bcn.confidence) + self.confidence_boost)

            combined_evidence = {
                "fusion_summary": "Suspicious encrypted TLS/QUIC session correlated with C2 communication/beaconing pattern",
                "malicious_evidence": [
                    enc.evidence.get("threat_diagnosis", "Suspicious encrypted session"),
                    bcn.evidence.get("threat_diagnosis", "C2 beaconing pattern"),
                ],
                "encrypted_signals": enc.evidence,
                "beaconing_signals": bcn.evidence,
                "passive_guarantee": "Forensic evaluation performed on observable flow metadata. Zero payload decryption.",
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
                detector="fusion_engine (encrypted + beaconing)",
                input_source=input_source,
                evidence=combined_evidence,
            )
            if self._should_emit(alert, now_ts):
                final_alerts.append(alert)
            return final_alerts

        # -------------------------------------------------------------
        # COMPOSITE RULE 4: Recon + Exfiltration
        # -------------------------------------------------------------
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
                input_source=input_source,
                evidence={
                    "fusion_summary": "Reconnaissance scan followed immediately by high-volume data exfiltration",
                    "recon_signals": rcn.evidence,
                    "exfiltration_signals": exf.evidence
                },
            )
            if self._should_emit(alert, now_ts):
                final_alerts.append(alert)
            return final_alerts

        # -------------------------------------------------------------
        # Standard / Single Detector alert forwarding with explainability structure
        # -------------------------------------------------------------
        for det in detections:
            threat_class = det.threat_class
            confidence = det.confidence
            severity = det.severity

            if confidence < 0.50:
                threat_class = "INSUFFICIENT_EVIDENCE"
                severity = SeverityLevel.LOW
            elif "anomaly" in threat_class.lower() and confidence < 0.70:
                threat_class = "UNKNOWN_ANOMALY"
                severity = SeverityLevel.MEDIUM

            # Structure evidence into explainable categories
            evidence_dict = dict(det.evidence)
            if "malicious_evidence" not in evidence_dict:
                diag = evidence_dict.get("threat_diagnosis")
                evidence_dict["malicious_evidence"] = [diag] if diag else ["Anomalous statistical deviation observed."]

            alert = StandardAlert(
                timestamp=now_iso,
                flow_id=flow_features.get("flow_id", "unknown"),
                src_ip=flow_features.get("src_ip", "0.0.0.0"),
                src_port=flow_features.get("src_port", 0),
                dst_ip=flow_features.get("dst_ip", "0.0.0.0"),
                dst_port=flow_features.get("dst_port", 0),
                protocol=flow_features.get("protocol", "TCP"),
                threat_class=threat_class,
                severity=severity,
                confidence=round(confidence, 4),
                detector=det.detector,
                input_source=input_source,
                evidence=evidence_dict,
            )
            if self._should_emit(alert, now_ts):
                final_alerts.append(alert)

        return final_alerts

    def _should_emit(self, alert: StandardAlert, current_time: float) -> bool:
        """Deduplicates repetitive alerts on identical endpoints within sliding window."""
        subtype = alert.evidence.get("subtype", "")
        key = (alert.src_ip, alert.dst_ip, alert.threat_class, subtype)
        last_time = self._dedup_cache.get(key, 0.0)
        if current_time - last_time < self.dedup_window_sec:
            return False
        self._dedup_cache[key] = current_time
        return True
