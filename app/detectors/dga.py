"""
DGA (Domain Generation Algorithm) Detector.
Detects algorithmic pseudo-random domains using lexical feature extraction,
Shannon entropy, and supervised ML classification.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import joblib
import numpy as np

from app.alerts.schema import DetectionResult, SeverityLevel
from app.detectors.base import BaseDetector
from app.features.dns_features import DNSFeatureExtractor


class DGADetector(BaseDetector):
    def __init__(
        self,
        entropy_threshold: float = 3.6,
        length_threshold: int = 15,
        model_path: Optional[str] = "models/dga_detector.joblib"
    ):
        super().__init__(name="dga_detector")
        self.entropy_threshold = entropy_threshold
        self.length_threshold = length_threshold
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
        # Collect domains from flow DNS queries or SNI
        domains_to_check: List[str] = []
        if flow_features.get("dns_queries"):
            domains_to_check.extend(flow_features["dns_queries"])

        # Check SNI if present in TLS metadata
        tls_meta = flow_features.get("tls_metadata") or {}
        if tls_meta.get("sni"):
            domains_to_check.append(tls_meta["sni"])

        if not domains_to_check:
            return None

        # Analyze the most suspicious domain in the flow
        highest_score = 0.0
        most_suspicious_domain = None
        best_evidence = {}

        for dom in set(domains_to_check):
            lex = DNSFeatureExtractor.extract_lexical_features(dom)
            score, evidence = self._evaluate_domain(dom, lex)
            if score > highest_score:
                highest_score = score
                most_suspicious_domain = dom
                best_evidence = evidence

        if highest_score < 0.70:
            return None

        severity = self.calculate_severity(highest_score, impact_multiplier=1.0)

        return DetectionResult(
            threat_class="DGA_DOMAIN_DETECTION",
            confidence=round(highest_score, 4),
            severity=severity,
            detector=self.name,
            evidence=best_evidence,
            flow_id=flow_features.get("flow_id"),
            src_ip=flow_features.get("src_ip"),
            src_port=flow_features.get("src_port"),
            dst_ip=flow_features.get("dst_ip"),
            dst_port=flow_features.get("dst_port"),
            protocol=flow_features.get("protocol", "UDP"),
        )

    def _evaluate_domain(self, domain: str, lex: Dict[str, Any]) -> Tuple[float, Dict[str, Any]]:
        """Evaluates domain using ML model if present, or lexical scoring heuristic."""
        entropy = lex["entropy"]
        length = lex["length"]
        digit_ratio = lex["digit_ratio"]
        vowel_ratio = lex["vowel_ratio"]
        consonant_cluster = lex["max_consonant_cluster"]

        ml_prob = None
        if self.model is not None:
            try:
                # Features: [length, entropy, digit_ratio, vowel_ratio, consonant_ratio, unique_char_ratio, max_consonant_cluster]
                vec = np.array([[
                    length,
                    entropy,
                    digit_ratio,
                    vowel_ratio,
                    lex["consonant_ratio"],
                    lex["unique_char_ratio"],
                    consonant_cluster
                ]])
                ml_prob = float(self.model.predict_proba(vec)[0, 1])
            except Exception:
                ml_prob = None

        if ml_prob is not None:
            confidence = ml_prob
        else:
            # Rule-based lexical heuristic
            score = 0.0
            if entropy >= self.entropy_threshold:
                score += 0.35
            if length >= self.length_threshold:
                score += 0.25
            if digit_ratio >= 0.20:
                score += 0.20
            if vowel_ratio < 0.18:
                score += 0.15
            if consonant_cluster >= 5:
                score += 0.15
            confidence = min(0.98, score)

        evidence = {
            "domain": domain,
            "domain_entropy": round(entropy, 4),
            "domain_length": length,
            "digit_ratio": round(digit_ratio, 4),
            "vowel_ratio": round(vowel_ratio, 4),
            "consonant_cluster_len": consonant_cluster,
            "ml_probability": round(ml_prob, 4) if ml_prob is not None else None,
        }

        return confidence, evidence
