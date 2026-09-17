"""
Botnet C2 Beaconing Detector (AEGIS v2.1).
Detects periodic heartbeats, jittered polling loops, low-and-slow C2, and automated check-ins.
Constructs an explicit, grouped BeaconEvidence structure (Timing Group, Protocol Group, Behavior Group).
Prevents double-counting correlated timing metrics, distinguishes timing quality from attack intent,
and safely routes ambiguous anomalies to UNKNOWN_ANOMALY or INSUFFICIENT_EVIDENCE.
"""

from typing import Any, Dict, List, Optional
import numpy as np

from app.alerts.schema import DetectionResult, SeverityLevel
from app.detectors.base import BaseDetector
from app.features.timing_features import (
    compute_advanced_timing_stats,
    calculate_iats,
)

COMMON_BENIGN_DESTINATIONS = {
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9"
}


class BeaconingDetector(BaseDetector):
    def __init__(
        self,
        min_connections: int = 4,
        cv_threshold: float = 0.25,
        periodicity_threshold: float = 0.65,
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
        # Timestamps can come from host-pair connection history across sliding window or packet timestamps in flow
        host_timestamps = ctx.get("connection_timestamps", [])
        if len(host_timestamps) < self.min_connections:
            host_timestamps = flow_features.get("timestamps", [])

        # Check for insufficient observations
        if len(host_timestamps) < self.min_connections:
            return None

        # -------------------------------------------------------------
        # 1. GROUP 1: TIMING EVIDENCE (Consolidated, No Double-Counting)
        # -------------------------------------------------------------
        timing_stats = compute_advanced_timing_stats(host_timestamps)
        mean_iat = timing_stats["mean_iat"]
        std_iat = timing_stats["std_iat"]
        cv = timing_stats["cv"]
        periodicity = timing_stats["periodicity_score"]
        lag1_corr = timing_stats["lag1_autocorr"]
        best_lag = timing_stats["best_lag"]
        best_corr = timing_stats["best_autocorr"]
        spectral = timing_stats["spectral_periodicity"]
        jitter_mag = timing_stats["jitter_magnitude"]
        jitter_score = timing_stats["jitter_score"]
        iat_entropy = timing_stats["iat_entropy"]
        timing_quality = timing_stats["timing_evidence_quality"]
        iats = calculate_iats(host_timestamps)

        # -------------------------------------------------------------
        # 2. GROUP 2: BEHAVIOR & DESTINATION PERSISTENCE EVIDENCE
        # -------------------------------------------------------------
        dst_ip = str(flow_features.get("dst_ip", ""))
        dst_concentration = float(ctx.get("dst_concentration", 1.0))
        dst_count = int(ctx.get("destination_count", 1))
        is_known_public_resolver = dst_ip in COMMON_BENIGN_DESTINATIONS

        # Low-and-slow & destination persistence analysis:
        # High persistence means host repeatedly contacts the SAME external endpoint over time
        sample_persistence_factor = min(1.0, len(host_timestamps) / 10.0)
        dst_persistence_score = (dst_concentration * 0.70 + sample_persistence_factor * 0.30)
        dst_rarity_score = 0.15 if is_known_public_resolver else (0.85 if dst_count <= 2 else 0.45)

        # -------------------------------------------------------------
        # 3. GROUP 3: INDEPENDENT PROTOCOL EVIDENCE (TLS / QUIC / DNS)
        # -------------------------------------------------------------
        tls_meta = flow_features.get("tls_metadata") or {}
        quic_meta = flow_features.get("quic_metadata") or {}
        dns_queries = flow_features.get("dns_queries") or []

        has_suspicious_ja3 = bool(tls_meta.get("ja3_hash"))
        has_suspicious_quic = bool(quic_meta.get("quic_detected"))
        has_dga_domain = False
        if dns_queries:
            # Check domain characteristics if present in flow context
            first_q = str(dns_queries[0]).lower()
            if len(first_q) > 12 and any(c.isdigit() for c in first_q):
                has_dga_domain = True

        protocol_evidence_score = 0.0
        if has_suspicious_ja3:
            protocol_evidence_score += 0.50
        if has_suspicious_quic:
            protocol_evidence_score += 0.30
        if has_dga_domain:
            protocol_evidence_score += 0.40
        protocol_evidence_score = min(1.0, protocol_evidence_score)

        # Enforce require_destination_rarity parameter
        if self.require_destination_rarity and is_known_public_resolver:
            # Common public resolvers (e.g. 8.8.8.8) are legitimate periodic poll targets.
            # Require external suspicious metadata (e.g. JA3 hash, suspicious QUIC) to flag as C2.
            if protocol_evidence_score < 0.30:
                return None

        # -------------------------------------------------------------
        # 4. PERIODICITY CLASSIFICATION & COMPOSITE CONFIDENCE
        # -------------------------------------------------------------
        is_strict_beacon = (cv <= self.cv_threshold and periodicity >= self.periodicity_threshold)
        is_jittered_beacon = (
            cv <= 0.45 and
            (best_corr >= 0.50 or spectral >= 0.50 or periodicity >= 0.55) and
            len(host_timestamps) >= 5
        )
        is_structured_beacon = (
            best_corr >= 0.65 and
            len(host_timestamps) >= 6 and
            periodicity >= 0.50
        )
        is_low_and_slow_persistent = (
            mean_iat >= 30.0 and
            dst_persistence_score >= 0.75 and
            (cv <= 0.40 or periodicity >= 0.50) and
            len(host_timestamps) >= 4
        )

        has_timing_beacon_signal = (
            is_strict_beacon or
            is_jittered_beacon or
            is_structured_beacon or
            is_low_and_slow_persistent
        )

        # If timing evidence is degraded (e.g. random jitter) but protocol / persistence evidence is strong:
        has_fused_anomaly_signal = (
            protocol_evidence_score >= 0.40 and
            dst_persistence_score >= 0.60 and
            len(host_timestamps) >= 4
        )

        if not has_timing_beacon_signal and not has_fused_anomaly_signal:
            return None

        # Determine threat class: if timing is degraded/random but other signals exist -> UNKNOWN_ANOMALY
        if not has_timing_beacon_signal and has_fused_anomaly_signal:
            threat_class = "UNKNOWN_ANOMALY"
            confidence = 0.65 + 0.20 * protocol_evidence_score + 0.10 * dst_persistence_score
        else:
            threat_class = "BOTNET_C2_BEACONING"
            # Group-level fusion (preventing double counting of timing metrics)
            timing_group_score = periodicity * 0.70 + (1.0 - min(1.0, cv)) * 0.30
            behavior_group_score = dst_persistence_score * 0.60 + dst_rarity_score * 0.40
            protocol_group_score = protocol_evidence_score

            base_confidence = (
                timing_group_score * 0.60 +
                behavior_group_score * 0.25 +
                protocol_group_score * 0.15
            )

            # Sample longevity boost
            sample_boost = min(0.10, (len(host_timestamps) - self.min_connections) * 0.015)
            confidence = base_confidence + sample_boost

            # Attenuate if jitter is high and autocorrelation is low
            if jitter_score > 0.40 and best_corr < 0.40:
                confidence *= 0.85

        confidence = float(np.clip(round(confidence, 4), 0.50, 0.98))
        severity = self.calculate_severity(confidence, impact_multiplier=1.0)
        if len(host_timestamps) >= 12 and cv < 0.15 and threat_class == "BOTNET_C2_BEACONING":
            severity = SeverityLevel.CRITICAL

        recent_iats = [f"{iat:.1f}s" for iat in iats[-5:]] if iats else []
        pattern_summary = ", ".join(recent_iats)

        # -------------------------------------------------------------
        # 5. STRUCTURED BEACON EVIDENCE VECTOR (GROUPED & EXPLAINABLE)
        # -------------------------------------------------------------
        evidence = {
            "threat_diagnosis": f"C2 communication pattern detected (Mean IAT: {mean_iat:.2f}s, CV: {cv:.4f}, Best Lag: {best_lag}, Autocorr: {best_corr:.2f}, Timing Quality: {timing_quality:.2f}).",
            "recent_iat_pattern": pattern_summary,
            "evidence_groups": {
                "timing_group": {
                    "mean_inter_arrival_sec": round(mean_iat, 2),
                    "std_inter_arrival_sec": round(std_iat, 2),
                    "coefficient_of_variation": round(cv, 4),
                    "periodicity_score": round(periodicity, 4),
                    "lag1_autocorrelation": round(lag1_corr, 4),
                    "best_lag": best_lag,
                    "best_autocorrelation": round(best_corr, 4),
                    "spectral_periodicity": round(spectral, 4),
                    "jitter_magnitude": round(jitter_mag, 4),
                    "jitter_score": round(jitter_score, 4),
                    "iat_entropy": round(iat_entropy, 4),
                    "timing_evidence_quality": round(timing_quality, 4),
                },
                "behavior_group": {
                    "observed_connection_count": len(host_timestamps),
                    "destination_concentration": round(dst_concentration, 2),
                    "destination_persistence_score": round(dst_persistence_score, 2),
                    "destination_rarity_score": round(dst_rarity_score, 2),
                    "destination_rarity_confirmed": (not is_known_public_resolver),
                },
                "protocol_group": {
                    "protocol_evidence_score": round(protocol_evidence_score, 2),
                    "has_suspicious_ja3": has_suspicious_ja3,
                    "has_suspicious_quic": has_suspicious_quic,
                    "has_dga_domain": has_dga_domain,
                }
            },
            # Flat attributes for backward compatibility with existing tests
            "mean_inter_arrival_sec": round(mean_iat, 2),
            "std_inter_arrival_sec": round(std_iat, 2),
            "coefficient_of_variation": round(cv, 4),
            "periodicity_score": round(periodicity, 4),
            "lag1_autocorrelation": round(lag1_corr, 4),
            "best_lag": best_lag,
            "best_autocorrelation": round(best_corr, 4),
            "spectral_periodicity": round(spectral, 4),
            "jitter_magnitude": round(jitter_mag, 4),
            "jitter_score": round(jitter_score, 4),
            "iat_entropy": round(iat_entropy, 4),
            "timing_evidence_quality": round(timing_quality, 4),
            "observed_connection_count": len(host_timestamps),
            "destination_concentration": round(dst_concentration, 2),
            "destination_persistence_score": round(dst_persistence_score, 2),
            "destination_rarity_score": round(dst_rarity_score, 2),
            "destination_rarity_confirmed": (not is_known_public_resolver),
            "flow_duration_sec": flow_features.get("duration", 0.0),
        }

        return DetectionResult(
            threat_class=threat_class,
            confidence=confidence,
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
