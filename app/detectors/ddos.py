"""
Volumetric & Protocol DDoS Threat Detector.
Identifies SYN Floods, UDP Floods, UDP Amplification/Reflection, and Spoofed-Source Flooding.
Combines statistical rate/entropy thresholds with ML classifier and objective, explainable evidence.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional
import joblib
import numpy as np

from app.alerts.schema import DetectionResult, SeverityLevel
from app.detectors.base import BaseDetector
from app.features.entropy import distribution_entropy, source_ip_entropy, calculate_distribution_metrics


class DDoSDetector(BaseDetector):
    def __init__(
        self,
        syn_rate_threshold: float = 50.0,
        udp_rate_threshold: float = 80.0,
        amplification_ratio_threshold: float = 10.0,
        amplification_min_bytes: int = 50000,
        source_entropy_threshold: float = 3.0,
        destination_concentration_threshold: float = 0.8,
        model_path: Optional[str] = "models/ddos_detector.joblib"
    ):
        super().__init__(name="ddos_detector")
        self.syn_rate_threshold = syn_rate_threshold
        self.udp_rate_threshold = udp_rate_threshold
        self.amplification_ratio_threshold = amplification_ratio_threshold
        self.amplification_min_bytes = amplification_min_bytes
        self.source_entropy_threshold = source_entropy_threshold
        self.destination_concentration_threshold = destination_concentration_threshold
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
        source_ips: List[str] = ctx.get("source_ips", [])
        dst_concentration = ctx.get("dst_concentration", 1.0)

        # In-flow metrics as fallback if no external sliding-window context
        flow_syn = flow_features.get("syn_count", 0)
        flow_ack = flow_features.get("ack_count", 0)
        flow_duration = max(0.01, flow_features.get("duration", 1.0))
        flow_protocol = flow_features.get("protocol", "TCP")
        packets_per_sec = flow_features.get("packets_per_sec", 0.0)
        bytes_per_sec = flow_features.get("bytes_per_sec", 0.0)
        syn_ack_ratio = flow_features.get("syn_ack_ratio", 1.0)
        avg_pkt_size = flow_features.get("mean_packet_size", 0.0)
        forward_bytes = flow_features.get("forward_bytes", 0)
        backward_bytes = flow_features.get("backward_bytes", 0)

        if syn_rate == 0.0 and flow_syn > 0:
            syn_rate = round(flow_syn / flow_duration, 2)
        if udp_rate == 0.0 and flow_protocol == "UDP":
            udp_rate = packets_per_sec

        # Source IP entropy & distribution analysis
        src_entropy = ctx.get("source_entropy", 0.0)
        src_concentration = ctx.get("source_concentration", 1.0)
        if source_ips:
            src_metrics = calculate_distribution_metrics(source_ips)
            src_entropy = src_metrics["entropy"]
            src_concentration = src_metrics["concentration"]
            unique_sources = max(unique_sources, src_metrics["unique_count"])
        elif src_entropy >= self.source_entropy_threshold and "source_concentration" not in ctx:
            src_concentration = 0.1

        # Specialized attack determinations:
        # A. SYN Flood
        is_syn_flood = (
            (syn_rate >= self.syn_rate_threshold and syn_ack_ratio > 3.0) or
            (flow_syn > 25 and flow_ack == 0)
        )

        # B. UDP Flood
        is_udp_flood = (udp_rate >= self.udp_rate_threshold and flow_protocol == "UDP") or (packets_per_sec >= self.udp_rate_threshold and flow_protocol == "UDP")

        # C. UDP Amplification / Reflection
        is_amplification = False
        amp_ratio = 0.0
        amp_service = None
        known_amp_ports = {123: "NTP", 53: "DNS", 1900: "SSDP", 11211: "Memcached", 389: "CLDAP", 161: "SNMP"}
        src_p = flow_features.get("src_port", 0)

        if flow_protocol == "UDP":
            req_b = max(1, min(forward_bytes, backward_bytes))
            resp_b = max(forward_bytes, backward_bytes)
            amp_ratio = round(resp_b / req_b, 2)
            if amp_ratio >= self.amplification_ratio_threshold and resp_b >= self.amplification_min_bytes:
                is_amplification = True
                amp_service = known_amp_ports.get(src_p, "UDP-Service")
            elif src_p in known_amp_ports and (avg_pkt_size >= 350.0 or amp_ratio >= 5.0) and (packets_per_sec >= 40.0 or udp_rate >= 40.0):
                is_amplification = True
                amp_service = known_amp_ports[src_p]

        # D. Spoofed-Source Flooding:
        is_spoofed = (
            (is_syn_flood or is_udp_flood or packets_per_sec >= 40.0) and
            (unique_sources >= 8 or src_entropy >= self.source_entropy_threshold) and
            src_concentration < 0.35
        )

        threat_class = None
        confidence = 0.0
        severity = SeverityLevel.MEDIUM
        reason = ""

        if is_amplification:
            threat_class = "AMPLIFICATION_REFLECTION_DDOS"
            confidence = min(0.97, 0.85 + min(0.10, amp_ratio / 50.0))
            severity = SeverityLevel.CRITICAL
            reason = f"High asymmetric UDP volume consistent with {amp_service or 'reflection'} amplification attack."
        elif is_spoofed:
            threat_class = "SPOOFED_SOURCE_DDOS"
            confidence = min(0.99, 0.85 + 0.04 * min(3.0, src_entropy))
            severity = SeverityLevel.CRITICAL
            reason = "High source diversity combined with abnormal traffic rate and protocol behavior increases spoofed DDoS suspicion."
        elif is_syn_flood:
            threat_class = "SYN_FLOOD"
            confidence = min(0.98, 0.80 + (syn_rate / (self.syn_rate_threshold * 4)))
            severity = SeverityLevel.CRITICAL if syn_rate > self.syn_rate_threshold * 2 else SeverityLevel.HIGH
            reason = f"Elevated SYN arrival rate ({syn_rate:.1f} pkts/s) with severe ACK deficit (SYN/ACK ratio {syn_ack_ratio:.2f})."
        elif is_udp_flood:
            threat_class = "UDP_FLOOD"
            confidence = min(0.95, 0.75 + (udp_rate / (self.udp_rate_threshold * 4)))
            severity = SeverityLevel.HIGH
            reason = f"Volumetric UDP datagram flood exceeding threshold ({udp_rate:.1f} pkts/s)."
        else:
            # Fallback to ML classifier if available
            if self.model is not None:
                try:
                    feat_vec = np.array([[
                        packets_per_sec,
                        bytes_per_sec,
                        flow_syn,
                        flow_ack,
                        syn_ack_ratio,
                        avg_pkt_size
                    ]])
                    prob = float(self.model.predict_proba(feat_vec)[0, 1])
                    if prob >= 0.75:
                        threat_class = "PROTOCOL_DDOS_ATTACK"
                        confidence = prob
                        severity = self.calculate_severity(prob, impact_multiplier=1.1)
                        reason = "Supervised classifier flagged anomalous volumetric flag and packet rate profile."
                except Exception:
                    pass

        if not threat_class:
            return None

        evidence = {
            "threat_diagnosis": reason,
            "syn_rate": round(syn_rate, 2),
            "syn_rate_pkts_per_sec": round(syn_rate, 2),
            "udp_rate": round(udp_rate, 2),
            "udp_packet_rate": round(udp_rate, 2),
            "unique_source_count": unique_sources,
            "source_ip_entropy": round(src_entropy, 2),
            "source_concentration_hhi": round(src_concentration, 4),
            "destination_concentration": round(dst_concentration, 2),
            "syn_ack_ratio": round(syn_ack_ratio, 2),
            "packets_per_sec": round(packets_per_sec, 2),
            "bytes_per_sec": round(bytes_per_sec, 2),
            "avg_packet_size_bytes": round(avg_pkt_size, 2),
        }

        if is_amplification:
            evidence["amplification_ratio"] = amp_ratio
            evidence["amplification_service"] = amp_service or "UDP"

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
