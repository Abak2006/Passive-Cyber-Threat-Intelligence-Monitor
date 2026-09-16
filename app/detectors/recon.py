"""
Reconnaissance & Port Scanning Threat Detector.
Identifies Horizontal Scans, Vertical Scans, and Broad Reconnaissance.
Evaluates destination host fan-out, port diversity, short flow durations, and SYN-only attempts.
"""

from typing import Any, Dict, List, Optional
from app.alerts.schema import DetectionResult, SeverityLevel
from app.detectors.base import BaseDetector
from app.features.entropy import distribution_entropy


class ReconDetector(BaseDetector):
    def __init__(
        self,
        horizontal_threshold: int = 8,
        vertical_threshold: int = 8,
        connections_per_sec_threshold: float = 5.0
    ):
        super().__init__(name="recon_detector")
        self.horizontal_threshold = horizontal_threshold
        self.vertical_threshold = vertical_threshold
        self.connections_per_sec_threshold = connections_per_sec_threshold

    def predict(
        self,
        flow_features: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> Optional[DetectionResult]:
        ctx = context or {}
        scan_ctx = ctx.get("scan_context", {})

        unique_dst_ips = scan_ctx.get("unique_dst_ips", 1)
        unique_dst_ports = scan_ctx.get("unique_dst_ports", 1)
        conn_rate = scan_ctx.get("connections_per_sec", 0.0)
        raw_dst_ips = scan_ctx.get("raw_dst_ips", [])

        dst_entropy = distribution_entropy(raw_dst_ips) if len(raw_dst_ips) > 1 else 0.0

        is_short = flow_features.get("is_short_flow", False)
        is_syn_only = flow_features.get("is_syn_only", False)

        is_vertical = unique_dst_ports >= self.vertical_threshold
        is_horizontal = unique_dst_ips >= self.horizontal_threshold
        is_broad = is_vertical and is_horizontal

        if not (is_vertical or is_horizontal):
            # Check in-flow indicator: if single flow was an immediate SYN-only probe with zero payload
            if is_syn_only and flow_features.get("total_packets", 0) <= 2:
                # Could be a single probe, but alert requires network pattern or high connection rate
                if conn_rate < self.connections_per_sec_threshold:
                    return None
                is_vertical = True
            else:
                return None

        if is_broad:
            threat_class = "BROAD_RECONNAISSANCE"
            base_conf = 0.94
            sev = SeverityLevel.CRITICAL
        elif is_vertical:
            threat_class = "PORT_SCAN_VERTICAL"
            base_conf = 0.91
            sev = SeverityLevel.HIGH
        else:
            threat_class = "PORT_SCAN_HORIZONTAL"
            base_conf = 0.90
            sev = SeverityLevel.HIGH

        # Confidence adjustment based on speed & entropy
        entropy_boost = min(0.05, dst_entropy * 0.02)
        confidence = min(0.98, base_conf + entropy_boost)

        evidence = {
            "unique_destination_hosts": unique_dst_ips,
            "unique_destination_ports": unique_dst_ports,
            "connections_per_second": round(conn_rate, 2),
            "destination_entropy": round(dst_entropy, 2),
            "is_short_flow": is_short,
            "is_syn_only_probe": is_syn_only,
        }

        return DetectionResult(
            threat_class=threat_class,
            confidence=round(confidence, 4),
            severity=sev,
            detector=self.name,
            evidence=evidence,
            flow_id=flow_features.get("flow_id"),
            src_ip=flow_features.get("src_ip"),
            src_port=flow_features.get("src_port"),
            dst_ip=flow_features.get("dst_ip"),
            dst_port=flow_features.get("dst_port"),
            protocol=flow_features.get("protocol", "TCP"),
        )
