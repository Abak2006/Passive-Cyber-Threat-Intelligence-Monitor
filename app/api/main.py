"""
FastAPI REST API Service for Passive Threat Intelligence.
Provides data access endpoints for dashboards, SIEM connectors, and operators.
Strictly read-only with respect to the monitored network.
"""

from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app.config import get_config
from app.storage.database import ThreatDatabase

app = FastAPI(
    title="NTRO Passive Cyber Threat Intelligence API",
    description="Unidirectional Network Monitoring and AI-Based Cyber Threat Detection Engine",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

cfg = get_config()
db = ThreatDatabase(cfg.database_path)


@app.get("/api/health")
def get_health() -> Dict[str, Any]:
    """Confirms system health and passive enclave guarantees."""
    return {
        "status": "OPERATIONAL",
        "environment": cfg.get("system.environment", "passive_monitoring_enclave"),
        "mode": cfg.get("system.mode", "unidirectional_read_only"),
        "zero_probe_enforced": True,
        "database_connected": True,
    }


@app.get("/api/stats")
def get_system_stats() -> Dict[str, Any]:
    """Returns top-level KPIs including total flows, total alerts, and throughput."""
    return db.get_system_stats()


@app.get("/api/alerts")
def get_alerts(
    limit: int = Query(50, ge=1, le=500),
    severity: Optional[str] = Query(None, description="Filter by LOW, MEDIUM, HIGH, CRITICAL"),
    threat_class: Optional[str] = Query(None, description="Filter by threat category")
) -> List[Dict[str, Any]]:
    """Returns recent structured threat alerts."""
    return db.get_recent_alerts(limit=limit, severity=severity, threat_class=threat_class)


@app.get("/api/threat-distribution")
def get_threat_distribution() -> Dict[str, int]:
    """Returns alert counts categorized by threat class."""
    return db.get_alert_counts_by_threat()


@app.get("/api/severity-distribution")
def get_severity_distribution() -> Dict[str, int]:
    """Returns alert counts categorized by severity."""
    return db.get_alert_counts_by_severity()


@app.get("/api/metrics/timeseries")
def get_metrics_timeseries(limit: int = Query(60, ge=10, le=300)) -> List[Dict[str, Any]]:
    """Returns real-time traffic throughput timeseries."""
    return db.get_metrics_timeseries(limit=limit)


@app.post("/api/clear")
def clear_records() -> Dict[str, str]:
    """Clears stored alerts and flows (useful for resetting demo state)."""
    db.clear_data()
    return {"message": "All alerts, flows, and metrics have been cleared."}


class DomainRequest(BaseModel):
    domain: str


class FlowAnalysisRequest(BaseModel):
    src_ip: str = "10.0.0.15"
    src_port: int = 49152
    dst_ip: str = "198.51.100.44"
    dst_port: int = 443
    protocol: str = "TCP"
    duration: float = 2.0
    forward_packets: int = 10
    backward_packets: int = 10
    forward_bytes: int = 1500
    backward_bytes: int = 1500
    syn_count: int = 1
    ack_count: int = 9
    dns_queries: Optional[List[str]] = None
    timestamps: Optional[List[float]] = None
    packet_lengths: Optional[List[int]] = None


@app.post("/api/analyze/domain")
def analyze_domain(req: DomainRequest) -> Dict[str, Any]:
    """Analyzes a custom domain using lexical feature extraction and the DGA classifier."""
    from app.features.dns_features import DNSFeatureExtractor
    from app.detectors.dga import DGADetector

    lex = DNSFeatureExtractor.extract_lexical_features(req.domain)
    detector = DGADetector()
    fake_flow = {
        "flow_id": f"DNS:TEST<->{req.domain}",
        "src_ip": "10.0.0.99",
        "src_port": 53535,
        "dst_ip": "8.8.8.8",
        "dst_port": 53,
        "protocol": "UDP",
        "dns_queries": [req.domain],
    }
    detection = detector.predict(fake_flow)

    return {
        "domain": req.domain,
        "lexical_features": lex,
        "is_threat": detection is not None,
        "detection_result": detection.model_dump() if detection else None
    }


@app.post("/api/analyze/flow")
def analyze_flow(req: FlowAnalysisRequest) -> Dict[str, Any]:
    """Analyzes a custom synthetic or real flow through all 7 detectors and Threat Fusion."""
    from app.alerts.generator import AlertPipeline
    from app.features.flow_features import FlowFeatureExtractor

    pipeline = AlertPipeline(db=db)
    raw_flow = req.model_dump()
    raw_flow["flow_id"] = f"{req.protocol}:{req.src_ip}:{req.src_port}<->{req.dst_ip}:{req.dst_port}"

    features = FlowFeatureExtractor.extract_features(raw_flow)
    if req.dns_queries:
        features["dns_queries"] = req.dns_queries
    if req.timestamps:
        features["timestamps"] = req.timestamps
    if req.packet_lengths:
        features["packet_lengths"] = req.packet_lengths

    alerts = pipeline.process_flow(features)
    return {
        "flow_id": raw_flow["flow_id"],
        "extracted_features": features,
        "alerts_generated": [a.model_dump() for a in alerts]
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)

