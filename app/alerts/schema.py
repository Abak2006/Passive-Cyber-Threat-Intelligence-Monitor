"""
Standard Alert & Detection Schema for NTRO Passive Threat Intelligence.
Strictly defines structured alert outputs, severity ratings, and evidence dictionaries.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field, field_validator


class SeverityLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DetectionResult(BaseModel):
    """Output from an individual specialized detector before fusion."""
    threat_class: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    severity: SeverityLevel
    detector: str
    evidence: Dict[str, Any] = Field(default_factory=dict)
    flow_id: Optional[str] = None
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    timestamp: Optional[str] = None


class StandardAlert(BaseModel):
    """
    Standard Alert Schema required by NTRO specifications.
    Every emitted alert must strictly follow this structure.
    """
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    flow_id: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    threat_class: str
    severity: SeverityLevel
    confidence: float = Field(..., ge=0.0, le=1.0)
    detector: str
    evidence: Dict[str, Any]

    @field_validator("confidence")
    @classmethod
    def round_confidence(cls, v: float) -> float:
        return round(float(v), 4)

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


class FlowRecord(BaseModel):
    """Summary of a network flow extracted passively from raw packets."""
    flow_id: str
    start_time: float
    end_time: float
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    packet_count: int
    byte_count: int
    duration_sec: float
    forward_packets: int
    backward_packets: int
    forward_bytes: int
    backward_bytes: int
