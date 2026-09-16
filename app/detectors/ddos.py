"""
Volumetric & Protocol DDoS Threat Detector.
Identifies SYN Floods, UDP Floods, Amplification, and Spoofed-Source Floods.
Combines statistical rate/entropy thresholds with ML classifier.
"""

from pathlib import Path
from typing import Any, Dict, Optional
import joblib
import numpy as np

from app.alerts.schema import DetectionResult, SeverityLevel
from app.detectors.base import BaseDetector
from app.features.entropy import distribution_entropy


class DDoSDetector(BaseDetector):
    def __init__(
        self,
        syn_rate_threshold: float = 50.0,
        udp_rate_threshold: float = 80.0,
        source_entropy_threshold: float = 3.0,
        model_path: Optional[str] = "models/ddos_detector.joblib"
    ):
        super().__init__(name="ddos_detector")
        self.syn_rate_threshold = syn_rate_threshold
        self.udp_rate_threshold = udp_rate_threshold
        self.source_entropy_threshold = source_entropy_threshold
        self.model_path = model_path
        self.model = None

        if self.model_path and Path(self.model_path).exists():
            try:
                self.model = joblib.load(self.model_path)
            except Exception:
                self.model = None

    def predict(
        self,
        flow_features: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> Optional[DetectionResult]:
        ctx = context or {}
        syn_rate = ctx.get("syn_rate", 0.0)
        udp_rate = ctx.get("udp_rate", 0.0)
        unique_sources = ctx.get("unique_sources", 1)
        source_ips = ctx.get("source_ips", [])

        # In-flow metrics as fallback if no sliding-window context
        flow_syn = flow_features.get("syn_count", 0)
        flow_duration = max(0.01, flow_features.get("duration", 1.0))
        flow_protocol = flow_features.get("protocol", "TCP")
        packets_per_sec = flow_features.get("packets_per_sec", 0.0)
        syn_ack_ratio = flow_features.get("syn_ack_ratio", 1.0)
        avg_pkt_size = flow_features.get("mean_packet_size", 0.0)

        if syn_rate == 0.0 and flow_syn > 0:
            syn_rate = round(flow_syn / flow_duration, 2)
        if udp_rate == 0.0 and flow_protocol == "UDP":
            udp_rate = packets_per_sec

        src_entropy = distribution_entropy(source_ips) if len(source_ips) > 1 else 0.0

        # Detection logic
        is_syn_flood = (syn_rate >= self.syn_rate_threshold and syn_ack_ratio > 3.0) or (flow_syn > 30 and flow_features.get("ack_count", 0) == 0)
        is_udp_flood = (udp_rate >= self.udp_rate_threshold and flow_protocol == "UDP")
        is_spoofed = (is_syn_flood or is_udp_flood) and (unique_sources > 10 or src_entropy >= self.source_entropy_threshold)

        if not (is_syn_flood or is_udp_flood):
            # Evaluate ML model if loaded
            if self.model is not None:
                try:
                    feat_vec = np.array([[
                        packets_per_sec,
                        flow_features.get("bytes_per_sec", 0.0),
                        flow_syn,
                        flow_features.get("ack_count", 0),
                        syn_ack_ratio,
                        avg_pkt_size
                    ]])
                    prob = float(self.model.predict_proba(feat_vec)[0, 1])
                    if prob >= 0.75:
                        threat_type = "PROTOCOL_DDOS_ATTACK"
                        sev = self.calculate_severity(prob, impact_multiplier=1.1)
                        return DetectionResult(
                            threat_class=threat_type,
                            confidence=round(prob, 4),
                            severity=sev,
                            detector=self.name,
                            evidence={
                                "ml_anomaly_score": round(prob, 4),
                                "packets_per_sec": packets_per_sec,
                                "syn_rate": syn_rate,
                                "syn_ack_ratio": syn_ack_ratio,
                                "unique_sources": unique_sources,
                            },
                            flow_id=flow_features.get("flow_id"),
                            src_ip=flow_features.get("src_ip"),
                            src_port=flow_features.get("src_port"),
                            dst_ip=flow_features.get("dst_ip"),
                            dst_port=flow_features.get("dst_port"),
                            protocol=flow_protocol,
                        )
                except Exception:
                    pass
            return None

        # Determine specific threat class
        if is_spoofed:
            threat_class = "SPOOFED_SOURCE_DDOS"
            confidence = min(0.99, 0.85 + 0.05 * min(3.0, src_entropy))
            severity = SeverityLevel.CRITICAL
        elif is_syn_flood:
            threat_class = "SYN_FLOOD"
            confidence = min(0.98, 0.80 + (syn_rate / (self.syn_rate_threshold * 4)))
            severity = SeverityLevel.CRITICAL if syn_rate > self.syn_rate_threshold * 2 else SeverityLevel.HIGH
        else:
            threat_class = "UDP_FLOOD"
            confidence = min(0.95, 0.75 + (udp_rate / (self.udp_rate_threshold * 4)))
            severity = SeverityLevel.HIGH

        evidence = {
            "syn_rate": round(syn_rate, 2),
            "udp_rate": round(udp_rate, 2),
            "unique_sources": unique_sources,
            "source_entropy": round(src_entropy, 2),
            "syn_ack_ratio": round(syn_ack_ratio, 2),
            "avg_packet_size": round(avg_pkt_size, 2),
            "packets_per_sec": round(packets_per_sec, 2),
        }

        return DetectionResult(
            threat_class=threat_class,
            confidence=round(confidence, 4),
            severity=severity,
            detector=self.name,
            evidence=evidence,
            flow_id=flow_features.get("flow_id"),
            src_ip=flow_features.get("src_ip"),
            src_port=flow_features.get("src_port"),
            dst_ip=flow_features.get("dst_ip"),
            dst_port=flow_features.get("dst_port"),
            protocol=flow_protocol,
        )
