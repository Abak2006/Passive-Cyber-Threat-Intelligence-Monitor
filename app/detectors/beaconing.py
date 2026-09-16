"""
Botnet C2 Beaconing Detector.
Detects periodic heartbeats and polling loops to command-and-control servers.
Uses statistical dispersion (Coefficient of Variation), autocorrelation, and jitter tolerance.
"""

from typing import Any, Dict, List, Optional
import numpy as np

from app.alerts.schema import DetectionResult, SeverityLevel
from app.detectors.base import BaseDetector
from app.features.timing_features import compute_timing_stats


class BeaconingDetector(BaseDetector):
    def __init__(
        self,
        min_connections: int = 4,
        cv_threshold: float = 0.25,
        periodicity_threshold: float = 0.70
    ):
        super().__init__(name="beaconing_detector")
        self.min_connections = min_connections
        self.cv_threshold = cv_threshold
        self.periodicity_threshold = periodicity_threshold

    def predict(
        self,
        flow_features: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> Optional[DetectionResult]:
        ctx = context or {}
        # Timestamps can come from connection history between host pair or packet timestamps in flow
        host_timestamps = ctx.get("connection_timestamps", [])
        if len(host_timestamps) < self.min_connections:
            # Fallback to packet timestamps inside the flow
            host_timestamps = flow_features.get("timestamps", [])

        if len(host_timestamps) < self.min_connections:
            return None

        mean_iat, std_iat, cv, periodicity = compute_timing_stats(host_timestamps)

        # High periodicity indicator: low CV and sufficient connections
        is_periodic = (cv <= self.cv_threshold and periodicity >= self.periodicity_threshold)

        # Even with moderate jitter (e.g. CV up to 0.35), if autocorrelation is high, flag it
        if not is_periodic and cv <= 0.35 and periodicity >= 0.65 and len(host_timestamps) >= 6:
            is_periodic = True

        if not is_periodic:
            return None

        # Calculate confidence based on periodicity and number of repeated connections
        sample_boost = min(0.15, (len(host_timestamps) - self.min_connections) * 0.02)
        confidence = min(0.96, periodicity + sample_boost)

        severity = self.calculate_severity(confidence, impact_multiplier=1.0)

        evidence = {
            "mean_inter_arrival_sec": round(mean_iat, 2),
            "std_inter_arrival_sec": round(std_iat, 2),
            "coefficient_of_variation": round(cv, 4),
            "periodicity_score": round(periodicity, 4),
            "connection_count": len(host_timestamps),
            "flow_duration": flow_features.get("duration", 0.0),
            "destination_concentration": round(ctx.get("dst_concentration", 1.0), 2),
        }

        return DetectionResult(
            threat_class="BOTNET_C2_BEACONING",
            confidence=round(confidence, 4),
            severity=severity,
            detector=self.name,
            evidence=evidence,
            flow_id=flow_features.get("flow_id"),
            src_ip=flow_features.get("src_ip"),
            src_port=flow_features.get("src_port"),
            dst_ip=flow_features.get("dst_ip"),
            dst_port=flow_features.get("dst_port"),
            protocol=flow_features.get("protocol", "TCP"),
        )
