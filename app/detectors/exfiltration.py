"""
Data Exfiltration Threat Detector.
Identifies anomalous outbound bulk transfers, asymmetric upload volume,
and sustained high-rate transfers relative to configured baselines.
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
        min_bytes_threshold: int = 50_000,
        model_path: Optional[str] = "models/exfil_detector.joblib"
    ):
        super().__init__(name="exfiltration_detector")
        self.ratio_threshold = ratio_threshold
        self.sustained_rate_threshold_bps = sustained_rate_threshold_bps
        self.burst_threshold_bytes = burst_threshold_bytes
        self.min_bytes_threshold = min_bytes_threshold
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
        fwd_bytes = flow_features.get("forward_bytes", 0)
        bwd_bytes = flow_features.get("backward_bytes", 0)
        duration = max(0.001, flow_features.get("duration", 1.0))
        ratio = flow_features.get("outbound_inbound_byte_ratio", 1.0)
        byte_rate = fwd_bytes / duration

        # Baseline filter: Ignore tiny transactions (e.g. DNS lookups, keep-alive probes)
        if fwd_bytes < self.min_bytes_threshold:
            return None

        # Exfiltration heuristics:
        # 1. Asymmetric bulk upload: Outbound >> Inbound by factor of ratio_threshold
        is_asymmetric_bulk = (ratio >= self.ratio_threshold and fwd_bytes >= 200_000)

        # 2. Sustained high-rate upload
        is_high_rate = (byte_rate >= self.sustained_rate_threshold_bps and duration >= 1.0)

        # 3. Burst transfer
        is_burst = (fwd_bytes >= self.burst_threshold_bytes and ratio >= 3.0)

        destination_frequency = ctx.get("dst_frequency", 1)

        is_exfil = is_asymmetric_bulk or is_high_rate or is_burst

        ml_anomaly = False
        ml_score = 0.0
        if self.model is not None:
            try:
                vec = np.array([[fwd_bytes, bwd_bytes, ratio, byte_rate, duration]])
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

        # Determine severity and confidence
        reasons = []
        if is_asymmetric_bulk:
            reasons.append(f"Upload ratio ({ratio:.2f}x) exceeds asymmetry threshold ({self.ratio_threshold}x)")
        if is_high_rate:
            reasons.append(f"Outbound transfer rate ({byte_rate/1024/1024:.2f} MB/s) exceeds sustained threshold ({self.sustained_rate_threshold_bps/1024/1024:.2f} MB/s)")
        if is_burst:
            reasons.append(f"Volume ({fwd_bytes/1024/1024:.2f} MB) exceeds burst threshold ({self.burst_threshold_bytes/1024/1024:.2f} MB)")
        if ml_anomaly:
            reasons.append(f"Unsupervised Isolation Forest anomaly score ({ml_score:.3f}) exceeds threshold")

        if is_asymmetric_bulk and is_high_rate:
            confidence = min(0.98, 0.85 + (ratio / 50.0))
            severity = SeverityLevel.CRITICAL
        elif is_asymmetric_bulk or is_burst:
            confidence = min(0.92, 0.78 + (ratio / 80.0))
            severity = SeverityLevel.HIGH if fwd_bytes < 5_000_000 else SeverityLevel.CRITICAL
        else:
            confidence = 0.80
            severity = SeverityLevel.MEDIUM

        evidence = {
            "threat_diagnosis": "; ".join(reasons),
            "bytes_out": fwd_bytes,
            "bytes_in": bwd_bytes,
            "out_in_ratio": round(ratio, 2),
            "outbound_inbound_ratio": round(ratio, 2),
            "outbound_rate_bytes_per_sec": round(byte_rate, 2),
            "sustained_duration_sec": round(duration, 2),
            "destination_frequency": destination_frequency,
            "ratio_threshold_configured": self.ratio_threshold,
            "ml_anomaly_detected": ml_anomaly,
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
