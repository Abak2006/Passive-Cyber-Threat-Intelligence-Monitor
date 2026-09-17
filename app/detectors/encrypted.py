"""
Suspicious Encrypted TLS & QUIC Traffic Detector.
STRICT REQUIREMENT: NO payload decryption. Passive metadata and behavioral heuristics only.
Combines observable TLS/QUIC handshake fingerprinting (JA3/JA4, QUIC Long Header) with timing periodicity,
packet-size sequence anomalies (SPLT), and directional byte ratios.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional, Set
import joblib
import numpy as np

from app.alerts.schema import DetectionResult, SeverityLevel
from app.detectors.base import BaseDetector
from app.features.quic_features import QUICFeatureExtractor
from app.features.tls_features import TLSFeatureExtractor
from app.features.timing_features import compute_timing_stats

# Curated catalog of known C2 / Malware Framework JA3 hashes
KNOWN_SUSPICIOUS_JA3: Set[str] = {
    "e7d705a3286e19ea42f587b344ee6865",  # Cobalt Strike HTTPS default
    "6734f37431670b3ab4292b8faae04f7b",  # Metasploit reverse_https
    "06a2082260ff2a1aa07949826a0c0a5e",  # Trickbot banker
    "72a589da586844d7f0818ce684948eea",  # Emotet TLS
    "b32309a26951912be7dba376398abc3b",  # AsyncRAT
    "a0e9f5d64349fb13191bc781f81f42e1",  # Sliver C2
    "51c64c77e60f3980eea90869b68c58a8",  # Havoc C2 framework
}


class EncryptedTrafficDetector(BaseDetector):
    def __init__(
        self,
        outbound_ratio_threshold: float = 7.0,
        periodicity_threshold: float = 0.70,
        quic_enabled: bool = True,
        model_path: Optional[str] = "models/encrypted_anomaly.joblib"
    ):
        super().__init__(name="encrypted_traffic_detector")
        self.outbound_ratio_threshold = outbound_ratio_threshold
        self.periodicity_threshold = periodicity_threshold
        self.quic_enabled = quic_enabled
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
        protocol = flow_features.get("protocol", "TCP").upper()
        dst_port = flow_features.get("dst_port", 0)
        src_port = flow_features.get("src_port", 0)

        tls_meta = flow_features.get("tls_metadata") or {}
        quic_meta = flow_features.get("quic_metadata") or {}

        is_tls_candidate = (protocol == "TCP" and (dst_port in (443, 8443, 4433, 9443) or src_port in (443, 8443) or bool(tls_meta)))
        is_quic_candidate = (self.quic_enabled and protocol == "UDP" and (dst_port in (443, 8443, 4433) or src_port in (443, 8443) or bool(quic_meta)))

        if not is_tls_candidate and not is_quic_candidate:
            return None

        # Timing & Behavioral features
        timestamps = flow_features.get("timestamps", [])
        mean_iat, _, cv, periodicity = compute_timing_stats(timestamps) if len(timestamps) >= 3 else (0.0, 0.0, 1.0, 0.0)

        outbound_ratio = flow_features.get("outbound_inbound_byte_ratio", 1.0)
        packet_lengths = flow_features.get("packet_lengths", [])

        splt = TLSFeatureExtractor.extract_behavioral_features(
            packet_lengths=packet_lengths,
            timestamps=timestamps,
            forward_bytes=flow_features.get("forward_bytes", 0),
            backward_bytes=flow_features.get("backward_bytes", 0)
        )
        mean_len = splt["splt_mean_length"]
        len_var = splt["splt_length_variance"]

        suspicious_behavior_count = 0
        evidence_signals: List[str] = []

        # Behavioral Anomaly Checks
        # 1. Periodic automated intervals (C2 check-in polling requires meaningful inter-checkin interval >= 0.5s)
        if periodicity >= self.periodicity_threshold and mean_iat >= 0.5:
            suspicious_behavior_count += 1
            evidence_signals.append(f"Periodic interval score {periodicity:.2f} (CV: {cv:.4f})")

        # 2. Uniform small packet payload anomaly (C2 heartbeat characteristic)
        if 40 <= mean_len <= 350 and len_var < 1500.0 and len(packet_lengths) >= 5:
            suspicious_behavior_count += 1
            evidence_signals.append(f"Uniform payload size profile (Mean: {mean_len:.1f}B, Var: {len_var:.1f})")

        # 3. Directional byte volume asymmetry
        if outbound_ratio >= self.outbound_ratio_threshold:
            suspicious_behavior_count += 1
            evidence_signals.append(f"Asymmetric outbound volume ratio ({outbound_ratio:.2f}x)")

        # Protocol-specific inspections
        ja3_hash = ""
        ja4_fp = "unavailable"
        tls_version = "unknown"
        suspicious_ja3 = False
        quic_telemetry: Optional[Dict[str, Any]] = None

        if is_tls_candidate:
            ja3_hash = tls_meta.get("ja3_hash", "")
            ja4_fp = tls_meta.get("ja4_fingerprint", "t_unknown")
            tls_version = tls_meta.get("tls_version", "unknown")
            has_sni = tls_meta.get("has_sni", False)
            suspicious_ja3 = ja3_hash in KNOWN_SUSPICIOUS_JA3

            if suspicious_ja3:
                evidence_signals.append(f"Observed JA3 signature ({ja3_hash}) matches known adversary framework catalog")

            # Direct IP TLS without SNI (requires actual observed TLS Client Hello)
            if bool(tls_meta) and not has_sni and len(packet_lengths) >= 4 and dst_port == 443:
                suspicious_behavior_count += 1
                evidence_signals.append("Direct IP TLS handshake without Server Name Indication (SNI)")

        elif is_quic_candidate:
            # QUIC passive extraction
            quic_telemetry = QUICFeatureExtractor.extract_quic_flow_features(flow_features)
            quic_version = quic_meta.get("version") or quic_telemetry.get("quic_version")
            if quic_version:
                tls_version = quic_version
            if quic_meta.get("is_initial") or quic_telemetry.get("quic_initial_seen"):
                evidence_signals.append("Observed QUIC Initial handshake packet exchange")
                suspicious_behavior_count += 1

            if len_var < 50.0 and len(packet_lengths) >= 4:
                suspicious_behavior_count += 1
                evidence_signals.append("Fixed-length padded QUIC datagram sequence")

            # Extreme packet variance or asymmetry in UDP 443
            if outbound_ratio > 3.0 and len(packet_lengths) >= 4:
                suspicious_behavior_count += 1
                evidence_signals.append(f"Anomalous UDP 443 upload volume ratio ({outbound_ratio:.2f}x)")

        is_suspicious = False
        confidence = 0.0

        if suspicious_ja3 and suspicious_behavior_count >= 1:
            is_suspicious = True
            confidence = min(0.96, 0.80 + 0.05 * suspicious_behavior_count)
        elif suspicious_behavior_count >= 2:
            is_suspicious = True
            confidence = min(0.92, 0.65 + 0.09 * suspicious_behavior_count)
        elif self.model is not None and is_tls_candidate:
            try:
                vec = np.array([[
                    mean_len,
                    len_var,
                    outbound_ratio,
                    periodicity,
                    1.0 if suspicious_ja3 else 0.0,
                    1.0 if tls_meta.get("has_sni", False) else 0.0
                ]])
                prob = float(self.model.predict_proba(vec)[0, 1])
                if prob >= 0.75:
                    is_suspicious = True
                    confidence = prob
                    evidence_signals.append(f"ML behavioral model anomaly score: {prob:.4f}")
            except Exception:
                pass

        if not is_suspicious:
            return None

        severity = self.calculate_severity(confidence, impact_multiplier=1.0)

        evidence = {
            "threat_diagnosis": "; ".join(evidence_signals) if evidence_signals else "Anomalous encrypted session behavior detected.",
            "encrypted_transport": "QUIC" if is_quic_candidate else "TLS",
            "is_quic": is_quic_candidate,
            "suspicious_tls_fingerprint": suspicious_ja3,
            "ja3": ja3_hash if ja3_hash else None,
            "ja4": ja4_fp,
            "tls_version": tls_version,
            "destination_port": dst_port,
            "periodicity_score": round(periodicity, 4),
            "packet_size_variance": round(len_var, 2),
            "splt_mean_length": mean_len,
            "outbound_inbound_ratio": round(outbound_ratio, 2),
            "inspection_note": "Passive observable transport and handshake metadata only. Zero payload decryption performed.",
        }

        if quic_telemetry and quic_telemetry.get("quic_detected"):
            evidence["quic_telemetry"] = quic_telemetry

        return DetectionResult(
            threat_class="SUSPICIOUS_ENCRYPTED_TRAFFIC",
            confidence=round(confidence, 4),
            severity=severity,
            detector=self.name,
            evidence=evidence,
            flow_id=flow_features.get("flow_id"),
            src_ip=flow_features.get("src_ip"),
            src_port=src_port,
            dst_ip=flow_features.get("dst_ip"),
            dst_port=dst_port,
            protocol=protocol,
        )
