"""
DNS Tunnelling & Exfiltration Threat Detector.
Detects covert channels, base32/base64 encoded payloads in subdomains, and DNS data exfiltration.
Inspects passive DNS query metadata, subdomain entropy, query frequency, and record-type distributions (e.g. TXT/NULL ratio spikes).
"""

from typing import Any, Dict, List, Optional
from app.alerts.schema import DetectionResult, SeverityLevel
from app.detectors.base import BaseDetector
from app.features.dns_features import DNSFeatureExtractor


class DNSTunnelDetector(BaseDetector):
    def __init__(
        self,
        subdomain_len_threshold: int = 24,
        subdomain_entropy_threshold: float = 3.75,
        query_frequency_threshold: float = 8.0,
        txt_ratio_threshold: float = 0.40,
        null_ratio_threshold: float = 0.10,
        unique_subdomains_threshold: int = 8
    ):
        super().__init__(name="dns_tunnel_detector")
        self.subdomain_len_threshold = subdomain_len_threshold
        self.subdomain_entropy_threshold = subdomain_entropy_threshold
        self.query_frequency_threshold = query_frequency_threshold
        self.txt_ratio_threshold = txt_ratio_threshold
        self.null_ratio_threshold = null_ratio_threshold
        self.unique_subdomains_threshold = unique_subdomains_threshold

    def predict(
        self,
        flow_features: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> Optional[DetectionResult]:
        ctx = context or {}
        queries: List[str] = flow_features.get("dns_queries", [])

        # Check sliding-window context if available
        apex_context = ctx.get("dns_tunnel_context", {})
        rolling_metrics = ctx.get("dns_rolling_metrics", {})
        unique_subdomains = apex_context.get("unique_subdomains", len(queries))
        query_rate = apex_context.get("query_rate", 0.0)

        all_queries = queries if queries else apex_context.get("queries", [])
        if not all_queries and not rolling_metrics:
            return None

        suspicious_query = None
        max_sub_entropy = 0.0
        max_sub_len = 0

        for q in all_queries:
            lex = DNSFeatureExtractor.extract_lexical_features(q)
            sub_len = lex["subdomain_length"]
            sub_ent = lex["subdomain_entropy"]

            if sub_len > max_sub_len:
                max_sub_len = sub_len
            if sub_ent > max_sub_entropy:
                max_sub_entropy = sub_ent
                suspicious_query = q

        # Record-type concentration anomalies
        txt_ratio = rolling_metrics.get("txt_ratio", 0.0)
        null_ratio = rolling_metrics.get("null_ratio", 0.0)

        # In-flow record check if available
        dns_type_name = str(flow_features.get("dns_type_name", "")).upper()
        if dns_type_name == "TXT" and not txt_ratio:
            txt_ratio = 1.0
        elif dns_type_name == "NULL" and not null_ratio:
            null_ratio = 1.0

        # Tunnel signals
        has_long_subdomain = (max_sub_len >= self.subdomain_len_threshold)
        has_high_entropy = (max_sub_entropy >= self.subdomain_entropy_threshold)
        has_high_volume = (
            unique_subdomains >= self.unique_subdomains_threshold or
            query_rate >= self.query_frequency_threshold
        )
        has_txt_anomaly = (txt_ratio >= self.txt_ratio_threshold and (has_high_entropy or max_sub_len > 15))
        has_null_anomaly = (null_ratio >= self.null_ratio_threshold)

        # Combined tunnel determination
        is_tunnel = (
            (has_long_subdomain and has_high_entropy) or
            (has_high_entropy and has_high_volume) or
            has_txt_anomaly or
            has_null_anomaly
        )

        if not is_tunnel:
            return None

        # Confidence calculation
        score = 0.0
        if has_long_subdomain:
            score += 0.30
        if has_high_entropy:
            score += 0.35
        if has_high_volume:
            score += 0.15
        if has_txt_anomaly:
            score += 0.25
        if has_null_anomaly:
            score += 0.30

        confidence = min(0.98, max(0.70, score))
        is_critical = (has_long_subdomain and has_high_entropy and (has_high_volume or has_txt_anomaly))
        severity = SeverityLevel.CRITICAL if is_critical else SeverityLevel.HIGH

        reasons = []
        if has_long_subdomain:
            reasons.append(f"Subdomain length {max_sub_len} chars exceeds threshold {self.subdomain_len_threshold}")
        if has_high_entropy:
            reasons.append(f"Subdomain Shannon entropy {max_sub_entropy:.2f} indicates encoded binary payload")
        if has_txt_anomaly:
            reasons.append(f"Abnormal TXT query concentration ({txt_ratio*100:.1f}%)")
        if has_null_anomaly:
            reasons.append(f"Unusual NULL record queries detected ({null_ratio*100:.1f}%)")
        if has_high_volume:
            reasons.append(f"High query volume ({unique_subdomains} unique subdomains, {query_rate:.1f} q/s)")

        evidence = {
            "threat_diagnosis": "; ".join(reasons),
            "suspicious_query": suspicious_query,
            "subdomain_length": max_sub_len,
            "subdomain_entropy": round(max_sub_entropy, 4),
            "unique_subdomain_count": unique_subdomains,
            "query_frequency": round(query_rate, 2),
            "txt_query_ratio": round(txt_ratio, 4),
            "null_query_ratio": round(null_ratio, 4),
            "is_encoded_subdomain": bool(has_high_entropy and has_long_subdomain),
        }

        return DetectionResult(
            threat_class="DNS_TUNNELLING",
            confidence=round(confidence, 4),
            severity=severity,
            detector=self.name,
            evidence=evidence,
            flow_id=flow_features.get("flow_id"),
            src_ip=flow_features.get("src_ip"),
            src_port=flow_features.get("src_port"),
            dst_ip=flow_features.get("dst_ip"),
            dst_port=flow_features.get("dst_port"),
            protocol=flow_features.get("protocol", "UDP"),
        )
