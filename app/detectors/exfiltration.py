"""
Data Exfiltration Threat Detector.
Identifies anomalous outbound data transfers, asymmetric high-volume uploads,
and covert transfer bursts relative to normal traffic baselines.
"""

from pathlib import Path
from typing import Any, Dict, Optional
import joblib
import numpy as np

from app.alerts.schema import DetectionResult, SeverityLevel
from app.detectors.base import BaseDetector


class ExfiltrationDetector(BaseDetector):
    def __init__(
        self,
        ratio_threshold: float = 6.0,
        sustained_rate_threshold_bps: float = 1_500_000.0,
        burst_threshold_bytes: int = 3_000_000,
        model_path: Optional[str] = "models/exfil_detector.joblib"
    ):
        super().__init__(name="exfiltration_detector")
        self.ratio_threshold = ratio_threshold
        self.sustained_rate_threshold_bps = sustained_rate_threshold_bps
        self.burst_threshold_bytes = burst_threshold_bytes
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
        fwd_bytes = flow_features.get("forward_bytes", 0)
        bwd_bytes = flow_features.get("backward_bytes", 0)
        duration = max(0.001, flow_features.get("duration", 1.0))
        ratio = flow_features.get("outbound_inbound_byte_ratio", 1.0)
        byte_rate = fwd_bytes / duration

        # Baseline filters: Ignore tiny transfers (e.g. DNS queries or single HTTP requests)
        if fwd_bytes < 50_000:
            return None

        # Exfiltration heuristics:
        # 1. Extreme asymmetry: Outbound >> Inbound by factor of ratio_threshold AND significant bytes
        is_asymmetric_bulk = (ratio >= self.ratio_threshold and fwd_bytes >= 200_000)

        # 2. Sustained high-rate upload
        is_high_rate = (byte_rate >= self.sustained_rate_threshold_bps and duration >= 1.0)

        # 3. Burst upload
        is_burst = (fwd_bytes >= self.burst_threshold_bytes and ratio >= 3.0)

        is_exfil = is_asymmetric_bulk or is_high_rate or is_burst

        ml_anomaly = False
        ml_score = 0.0
        if self.model is not None:
            try:
                vec = np.array([[fwd_bytes, bwd_bytes, ratio, byte_rate, duration]])
                # Isolation forest outputs -1 for anomaly, 1 for inlier
                pred = self.model.predict(vec)[0]
                if hasattr(self.model, "score_samples"):
                    score = -float(self.model.score_samples(vec)[0])
                    ml_score = score
                    if pred == -1 or score > 0.65:
                        ml_anomaly = True
            except Exception:
                pass

        if not (is_exfil or ml_anomaly):
            return None

        # Confidence calculation
        if is_asymmetric_bulk and is_high_rate:
            confidence = min(0.97, 0.85 + (ratio / 50.0))
            severity = SeverityLevel.CRITICAL
        elif is_asymmetric_bulk or is_burst:
            confidence = min(0.92, 0.78 + (ratio / 80.0))
            severity = SeverityLevel.HIGH if fwd_bytes < 5_000_000 else SeverityLevel.CRITICAL
        else:
            confidence = 0.82
            severity = SeverityLevel.MEDIUM

        evidence = {
            "inbound_bytes": bwd_bytes,
            "outbound_bytes": fwd_bytes,
            "outbound_inbound_ratio": round(ratio, 2),
            "outbound_rate_bytes_per_sec": round(byte_rate, 2),
            "flow_duration_sec": round(duration, 2),
            "is_asymmetric_bulk": is_asymmetric_bulk,
            "ml_anomaly_detected": ml_anomaly,
            "ml_anomaly_score": round(ml_score, 4) if ml_score > 0 else None,
        }

        return DetectionResult(
            threat_class="DATA_EXFILTRATION",
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
