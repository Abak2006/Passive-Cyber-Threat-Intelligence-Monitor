"""
Suspicious Encrypted TLS/QUIC Traffic Detector.
STRICT REQUIREMENT: NO payload decryption. Passive metadata and behavioral heuristics only.
Combines TLS handshake fingerprinting (JA3/JA4 representation) with timing periodicity,
packet-size sequence anomalies (SPLT), and directional byte ratios.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional, Set
import joblib
import numpy as np

from app.alerts.schema import DetectionResult, SeverityLevel
from app.detectors.base import BaseDetector
from app.features.tls_features import TLSFeatureExtractor
from app.features.timing_features import compute_timing_stats


# Curated catalog of known C2 / Malware Framework JA3 hashes (Cobalt Strike, Metasploit, etc.)
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
        model_path: Optional[str] = "models/encrypted_anomaly.joblib"
    ):
        super().__init__(name="encrypted_traffic_detector")
        self.outbound_ratio_threshold = outbound_ratio_threshold
        self.periodicity_threshold = periodicity_threshold
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
        # Only evaluate TLS/QUIC flows (typically port 443, 8443, or flows having tls_metadata)
        dst_port = flow_features.get("dst_port", 0)
        src_port = flow_features.get("src_port", 0)
        tls_meta = flow_features.get("tls_metadata") or {}

        is_tls_port = (dst_port in (443, 8443, 4433, 9443) or src_port in (443, 8443))
        if not is_tls_port and not tls_meta:
            return None

        # 1. TLS Metadata Features (JA3 / JA4 representation)
        ja3_hash = tls_meta.get("ja3_hash", "")
        ja4_fp = tls_meta.get("ja4_fingerprint", "t_unknown")
        suspicious_ja3 = ja3_hash in KNOWN_SUSPICIOUS_JA3
        ciphers_count = tls_meta.get("ciphers_count", 0)
        has_sni = tls_meta.get("has_sni", False)

        # 2. Behavioral & Timing Features
        timestamps = flow_features.get("timestamps", [])
        _, _, cv, periodicity = compute_timing_stats(timestamps) if len(timestamps) >= 3 else (0.0, 0.0, 1.0, 0.0)

        # 3. SPLT & Directional Volume Features
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

        # Packet size anomaly: C2 polling typically uses uniform small payloads
        # e.g., low variance in packet size and small mean length
        packet_size_anomaly = 0.0
        if 40 <= mean_len <= 350 and len_var < 1500.0:
            packet_size_anomaly = 0.85
        elif outbound_ratio > self.outbound_ratio_threshold:
            packet_size_anomaly = 0.80

        # Multi-signal corroboration: Never classify as malware on JA3 alone!
        # Must have behavioral anomaly (periodicity, packet size anomaly, or extreme ratio)
        suspicious_behavior_count = 0
        if periodicity >= self.periodicity_threshold:
            suspicious_behavior_count += 1
        if packet_size_anomaly >= 0.70:
            suspicious_behavior_count += 1
        if outbound_ratio >= self.outbound_ratio_threshold:
            suspicious_behavior_count += 1
        if not has_sni and is_tls_port and len(packet_lengths) > 4:
            # Direct IP TLS connection without SNI is common in malware
            suspicious_behavior_count += 1

        is_suspicious = False
        confidence = 0.0

        if suspicious_ja3 and suspicious_behavior_count >= 1:
            # Known fingerprint corroborated by behavioral anomaly
            is_suspicious = True
            confidence = min(0.96, 0.80 + 0.05 * suspicious_behavior_count)
        elif suspicious_behavior_count >= 2:
            # Strong behavioral signals even if JA3 is not in static blacklist
            is_suspicious = True
            confidence = min(0.91, 0.65 + 0.10 * suspicious_behavior_count)
        elif self.model is not None:
            try:
                vec = np.array([[
                    mean_len,
                    len_var,
                    outbound_ratio,
                    periodicity,
                    1.0 if suspicious_ja3 else 0.0,
                    1.0 if has_sni else 0.0
                ]])
                prob = float(self.model.predict_proba(vec)[0, 1])
                if prob >= 0.75:
                    is_suspicious = True
                    confidence = prob
            except Exception:
                pass

        if not is_suspicious:
            return None

        severity = self.calculate_severity(confidence, impact_multiplier=1.0)

        evidence = {
            "suspicious_tls_fingerprint": suspicious_ja3,
            "ja3_hash": ja3_hash if ja3_hash else "unavailable_passive",
            "ja4_fingerprint": ja4_fp,
            "periodicity_score": round(periodicity, 4),
            "packet_size_anomaly": round(packet_size_anomaly, 4),
            "outbound_inbound_ratio": round(outbound_ratio, 4),
            "has_sni": has_sni,
            "splt_mean_length": mean_len,
            "inspection_note": "Passive metadata and behavioral flow dynamics only. Zero payload decryption performed.",
        }

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
            protocol=flow_features.get("protocol", "TCP"),
        )
