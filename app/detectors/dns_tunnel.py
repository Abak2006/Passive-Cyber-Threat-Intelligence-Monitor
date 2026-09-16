"""
DNS Tunnelling & Exfiltration Threat Detector.
Detects covert channels, encoded payloads in subdomains, and DNS data exfiltration.
Inspects passive DNS query metadata (subdomain entropy, length, frequency, TXT records).
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
        query_frequency_threshold: float = 5.0,
        unique_subdomains_threshold: int = 6
    ):
        super().__init__(name="dns_tunnel_detector")
        self.subdomain_len_threshold = subdomain_len_threshold
        self.subdomain_entropy_threshold = subdomain_entropy_threshold
        self.query_frequency_threshold = query_frequency_threshold
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
        unique_subdomains = apex_context.get("unique_subdomains", len(queries))
        query_rate = apex_context.get("query_rate", 0.0)

        if not queries and not apex_context.get("queries"):
            return None

        all_queries = queries if queries else apex_context.get("queries", [])

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

        # Tunnel signals
        has_long_subdomain = max_sub_len >= self.subdomain_len_threshold
        has_high_entropy = max_sub_entropy >= self.subdomain_entropy_threshold
        has_high_volume = (unique_subdomains >= self.unique_subdomains_threshold or
                           query_rate >= self.query_frequency_threshold)

        # Combined check
        is_tunnel = (has_long_subdomain and has_high_entropy) or (has_high_entropy and has_high_volume)

        if not is_tunnel:
            return None

        # Confidence calculation
        score = 0.0
        if has_long_subdomain:
            score += 0.35
        if has_high_entropy:
            score += 0.40
        if has_high_volume:
            score += 0.20

        confidence = min(0.97, max(0.70, score))
        severity = SeverityLevel.CRITICAL if (has_long_subdomain and has_high_entropy and has_high_volume) else SeverityLevel.HIGH

        evidence = {
            "suspicious_query": suspicious_query,
            "subdomain_length": max_sub_len,
            "subdomain_entropy": round(max_sub_entropy, 4),
            "unique_subdomain_count": unique_subdomains,
            "query_frequency": round(query_rate, 2),
            "is_encoded_subdomain": has_high_entropy and has_long_subdomain,
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
