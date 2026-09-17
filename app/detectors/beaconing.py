"""
Botnet C2 Beaconing Detector.
Detects periodic heartbeats and automated polling loops to command-and-control servers.
Uses statistical dispersion (Coefficient of Variation), lag-1 autocorrelation, jitter tolerance,
and destination persistence/rarity to prevent false alarms from benign periodic applications.
"""

from typing import Any, Dict, List, Optional
import numpy as np

from app.alerts.schema import DetectionResult, SeverityLevel
from app.detectors.base import BaseDetector
from app.features.timing_features import compute_timing_stats, calculate_iats

COMMON_BENIGN_DESTINATIONS = {
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9"
}


class BeaconingDetector(BaseDetector):
    def __init__(
        self,
        min_connections: int = 4,
        cv_threshold: float = 0.25,
        periodicity_threshold: float = 0.70,
        require_destination_rarity: bool = True
    ):
        super().__init__(name="beaconing_detector")
        self.min_connections = min_connections
        self.cv_threshold = cv_threshold
        self.periodicity_threshold = periodicity_threshold
        self.require_destination_rarity = require_destination_rarity

    def predict(
        self,
        flow_features: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> Optional[DetectionResult]:
        ctx = context or {}
        # Timestamps can come from connection history between host pair or packet timestamps in flow
        host_timestamps = ctx.get("connection_timestamps", [])
        if len(host_timestamps) < self.min_connections:
            host_timestamps = flow_features.get("timestamps", [])

        if len(host_timestamps) < self.min_connections:
            return None

        mean_iat, std_iat, cv, periodicity = compute_timing_stats(host_timestamps)
        iats = calculate_iats(host_timestamps)

        # Continuous packet streaming (mean_iat < 0.5s) represents bulk stream transmission, not periodic beacon check-ins
        if mean_iat < 0.5:
            return None

        # High periodicity indicator: low CV and sufficient connections
        is_periodic = (cv <= self.cv_threshold and periodicity >= self.periodicity_threshold)

        # Moderate jitter (e.g. CV up to 0.35 with 10-20% random sleep jitter) with high autocorrelation
        if not is_periodic and cv <= 0.35 and periodicity >= 0.65 and len(host_timestamps) >= 6:
            is_periodic = True

        if not is_periodic:
            return None

        dst_ip = str(flow_features.get("dst_ip", ""))
        dst_concentration = float(ctx.get("dst_concentration", 1.0))

        # Filter out common benign public resolvers if not correlated with suspicious signals
        if dst_ip in COMMON_BENIGN_DESTINATIONS and cv > 0.10:
            return None

        # Sample IAT pattern description (e.g., "60.1s, 59.8s, 60.4s")
        recent_iats = [f"{iat:.1f}s" for iat in iats[-5:]] if iats else []
        pattern_summary = ", ".join(recent_iats)

        # Corroborate with TLS or QUIC metadata if available
        tls_meta = flow_features.get("tls_metadata") or {}
        quic_meta = flow_features.get("quic_metadata") or {}
        has_suspicious_meta = bool(tls_meta.get("ja3_hash") or quic_meta.get("quic_detected"))

        # Calculate confidence
        sample_boost = min(0.12, (len(host_timestamps) - self.min_connections) * 0.02)
        confidence = min(0.97, periodicity + sample_boost)
        if has_suspicious_meta:
            confidence = min(0.99, confidence + 0.05)

        severity = self.calculate_severity(confidence, impact_multiplier=1.0)
        if len(host_timestamps) >= 12 and cv < 0.15:
            severity = SeverityLevel.CRITICAL

        evidence = {
            "threat_diagnosis": f"Strictly periodic communication pattern detected (Mean IAT: {mean_iat:.2f}s, CV: {cv:.4f}).",
            "recent_iat_pattern": pattern_summary,
            "mean_inter_arrival_sec": round(mean_iat, 2),
            "std_inter_arrival_sec": round(std_iat, 2),
            "coefficient_of_variation": round(cv, 4),
            "periodicity_score": round(periodicity, 4),
            "observed_connection_count": len(host_timestamps),
            "destination_concentration": round(dst_concentration, 2),
            "destination_rarity_confirmed": (dst_ip not in COMMON_BENIGN_DESTINATIONS),
            "flow_duration_sec": flow_features.get("duration", 0.0),
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
            dst_ip=dst_ip,
            dst_port=flow_features.get("dst_port"),
            protocol=flow_features.get("protocol", "TCP"),
        )
