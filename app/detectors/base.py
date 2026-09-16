"""
Base Detector Interface.
All specialized threat detectors implement this contract for explainable, structured detection.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

from app.alerts.schema import DetectionResult, SeverityLevel


class BaseDetector(ABC):
    """Abstract Base Class for all specialized cyber threat detectors."""

    def __init__(self, name: str, enabled: bool = True):
        self.name = name
        self.enabled = enabled

    @abstractmethod
    def predict(
        self,
        flow_features: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> Optional[DetectionResult]:
        """
        Evaluate flow features and context.
        Returns a structured DetectionResult if a threat is identified, else None.
        """
        pass

    def calculate_severity(self, confidence: float, impact_multiplier: float = 1.0) -> SeverityLevel:
        """
        Configurable mapping from confidence & impact to standard severity tiers.
        """
        effective_score = min(1.0, confidence * impact_multiplier)
        if effective_score >= 0.90:
            return SeverityLevel.CRITICAL
        elif effective_score >= 0.70:
            return SeverityLevel.HIGH
        elif effective_score >= 0.50:
            return SeverityLevel.MEDIUM
        return SeverityLevel.LOW
