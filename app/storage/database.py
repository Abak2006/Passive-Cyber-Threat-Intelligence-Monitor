"""
SQLite Database Layer with WAL Mode for High Concurrency.
Stores alerts, network flow summaries, and real-time throughput metrics.
Includes streaming batch commit buffering and input_source provenance tracking.
"""

import json
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
import logging

from app.alerts.schema import StandardAlert, FlowRecord, SeverityLevel

logger = logging.getLogger(__name__)


class ThreatDatabase:
    def __init__(self, db_path: str = "data/threats.db", batch_buffer_size: int = 50):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.batch_buffer_size = batch_buffer_size
        self._alert_buffer: List[StandardAlert] = []
        self._flow_buffer: List[FlowRecord] = []
        self._last_flush_time = time.time()
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            str(self.db_path),
            timeout=30.0,
            check_same_thread=False
        )
        conn.row_factory = sqlite3.Row
        # Enable WAL mode for high concurrency
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            # Alerts table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    flow_id TEXT NOT NULL,
                    src_ip TEXT NOT NULL,
                    src_port INTEGER NOT NULL,
                    dst_ip TEXT NOT NULL,
                    dst_port INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    threat_class TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    detector TEXT NOT NULL,
                    input_source TEXT DEFAULT 'pcap_replay',
                    evidence_json TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(timestamp);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_threat ON alerts(threat_class);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_sev ON alerts(severity);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_flow ON alerts(flow_id);")

            # Check if input_source column exists in existing DBs
            cursor.execute("PRAGMA table_info(alerts);")
            alert_cols = [c[1] for c in cursor.fetchall()]
            if "input_source" not in alert_cols:
                cursor.execute("ALTER TABLE alerts ADD COLUMN input_source TEXT DEFAULT 'pcap_replay';")

            # Flows table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS flows (
                    flow_id TEXT PRIMARY KEY,
                    start_time REAL NOT NULL,
                    end_time REAL NOT NULL,
                    src_ip TEXT NOT NULL,
                    src_port INTEGER NOT NULL,
                    dst_ip TEXT NOT NULL,
                    dst_port INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    packet_count INTEGER NOT NULL,
                    byte_count INTEGER NOT NULL,
                    duration_sec REAL NOT NULL,
                    forward_packets INTEGER NOT NULL,
                    backward_packets INTEGER NOT NULL,
                    forward_bytes INTEGER NOT NULL,
                    backward_bytes INTEGER NOT NULL,
                    input_source TEXT DEFAULT 'pcap_replay',
                    recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_flows_end ON flows(end_time);")

            cursor.execute("PRAGMA table_info(flows);")
            flow_cols = [c[1] for c in cursor.fetchall()]
            if "input_source" not in flow_cols:
                cursor.execute("ALTER TABLE flows ADD COLUMN input_source TEXT DEFAULT 'pcap_replay';")

            # System metrics timeline table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    flows_per_sec REAL NOT NULL,
                    packets_per_sec REAL NOT NULL,
                    bytes_per_sec REAL NOT NULL,
                    active_flows INTEGER NOT NULL,
                    total_alerts INTEGER NOT NULL,
                    critical_alerts INTEGER NOT NULL
                );
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_metrics_ts ON metrics(timestamp);")
            conn.commit()

    def insert_alert(self, alert: StandardAlert) -> int:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO alerts (
                    timestamp, flow_id, src_ip, src_port, dst_ip, dst_port,
                    protocol, threat_class, severity, confidence, detector, input_source, evidence_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert.timestamp,
                alert.flow_id,
                alert.src_ip,
                alert.src_port,
                alert.dst_ip,
                alert.dst_port,
                alert.protocol,
                alert.threat_class,
                alert.severity.value if isinstance(alert.severity, SeverityLevel) else str(alert.severity),
                float(alert.confidence),
                alert.detector,
                getattr(alert, "input_source", "pcap_replay"),
                json.dumps(alert.evidence)
            ))
            conn.commit()
            return cursor.lastrowid

    def insert_alerts(self, alerts: List[StandardAlert]):
        if not alerts:
            return
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.executemany("""
                INSERT INTO alerts (
                    timestamp, flow_id, src_ip, src_port, dst_ip, dst_port,
                    protocol, threat_class, severity, confidence, detector, input_source, evidence_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, [
                (
                    a.timestamp,
                    a.flow_id,
                    a.src_ip,
                    a.src_port,
                    a.dst_ip,
                    a.dst_port,
                    a.protocol,
                    a.threat_class,
                    a.severity.value if isinstance(a.severity, SeverityLevel) else str(a.severity),
                    float(a.confidence),
                    a.detector,
                    getattr(a, "input_source", "pcap_replay"),
                    json.dumps(a.evidence)
                ) for a in alerts
            ])
            conn.commit()

    def insert_flow(self, flow: FlowRecord):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO flows (
                    flow_id, start_time, end_time, src_ip, src_port, dst_ip, dst_port,
                    protocol, packet_count, byte_count, duration_sec,
                    forward_packets, backward_packets, forward_bytes, backward_bytes, input_source
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                flow.flow_id,
                flow.start_time,
                flow.end_time,
                flow.src_ip,
                flow.src_port,
                flow.dst_ip,
                flow.dst_port,
                flow.protocol,
                flow.packet_count,
                flow.byte_count,
                flow.duration_sec,
                flow.forward_packets,
                flow.backward_packets,
                flow.forward_bytes,
                flow.backward_bytes,
                getattr(flow, "input_source", "pcap_replay")
            ))
            conn.commit()

    def queue_alert(self, alert: StandardAlert):
        """Buffers alerts for streaming batch persistence."""
        self._alert_buffer.append(alert)
        if len(self._alert_buffer) >= self.batch_buffer_size or (time.time() - self._last_flush_time) > 2.0:
            self.flush_buffers()

    def queue_flow(self, flow: FlowRecord):
        """Buffers flows for streaming batch persistence."""
        self._flow_buffer.append(flow)
        if len(self._flow_buffer) >= self.batch_buffer_size or (time.time() - self._last_flush_time) > 2.0:
            self.flush_buffers()

    def flush_buffers(self):
        """Flushes buffered alerts and flows in a single transaction."""
        if self._alert_buffer:
            to_insert = self._alert_buffer[:]
            self._alert_buffer.clear()
            self.insert_alerts(to_insert)

        if self._flow_buffer:
            to_insert = self._flow_buffer[:]
            self._flow_buffer.clear()
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.executemany("""
                    INSERT OR REPLACE INTO flows (
                        flow_id, start_time, end_time, src_ip, src_port, dst_ip, dst_port,
                        protocol, packet_count, byte_count, duration_sec,
                        forward_packets, backward_packets, forward_bytes, backward_bytes, input_source
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, [
                    (
                        f.flow_id, f.start_time, f.end_time, f.src_ip, f.src_port, f.dst_ip, f.dst_port,
                        f.protocol, f.packet_count, f.byte_count, f.duration_sec,
                        f.forward_packets, f.backward_packets, f.forward_bytes, f.backward_bytes,
                        getattr(f, "input_source", "pcap_replay")
                    ) for f in to_insert
                ])
                conn.commit()

        self._last_flush_time = time.time()

    def record_metrics(
        self,
        flows_per_sec: float,
        packets_per_sec: float,
        bytes_per_sec: float,
        active_flows: int,
        total_alerts: int,
        critical_alerts: int,
        timestamp: Optional[str] = None
    ):
        ts = timestamp or datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO metrics (
                    timestamp, flows_per_sec, packets_per_sec, bytes_per_sec,
                    active_flows, total_alerts, critical_alerts
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                ts, flows_per_sec, packets_per_sec, bytes_per_sec,
                active_flows, total_alerts, critical_alerts
            ))
            conn.commit()

    def get_recent_alerts(
        self,
        limit: int = 50,
        severity: Optional[str] = None,
        threat_class: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        self.flush_buffers()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            query = "SELECT * FROM alerts"
            params = []
            conditions = []
            if severity:
                conditions.append("severity = ?")
                params.append(severity.upper())
            if threat_class:
                conditions.append("threat_class = ?")
                params.append(threat_class)
            if conditions:
                query += " WHERE " + " AND ".join(conditions)
            query += " ORDER BY id DESC LIMIT ?"
            params.append(limit)

            cursor.execute(query, params)
            rows = cursor.fetchall()
            results = []
            for r in rows:
                item = dict(r)
                item["evidence"] = json.loads(item["evidence_json"])
                del item["evidence_json"]
                results.append(item)
            return results

    def get_alerts(
        self,
        limit: int = 50,
        severity: Optional[str] = None,
        threat_class: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Convenience alias for get_recent_alerts."""
        return self.get_recent_alerts(limit=limit, severity=severity, threat_class=threat_class)

    def get_flows(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieves recently recorded network flows."""
        self.flush_buffers()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM flows ORDER BY end_time DESC LIMIT ?", (limit,))
            rows = cursor.fetchall()
            return [dict(r) for r in rows]

    def get_alert_counts_by_severity(self) -> Dict[str, int]:
        self.flush_buffers()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT severity, COUNT(*) as count FROM alerts GROUP BY severity")
            rows = cursor.fetchall()
            counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
            for r in rows:
                sev = r["severity"].upper()
                if sev in counts:
                    counts[sev] = r["count"]
            return counts

    def get_alert_counts_by_threat(self) -> Dict[str, int]:
        self.flush_buffers()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT threat_class, COUNT(*) as count FROM alerts GROUP BY threat_class ORDER BY count DESC")
            rows = cursor.fetchall()
            return {r["threat_class"]: r["count"] for r in rows}

    def get_metrics_timeseries(self, limit: int = 60) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM metrics ORDER BY id DESC LIMIT ?",
                (limit,)
            )
            rows = cursor.fetchall()
            return [dict(r) for r in reversed(rows)]

    def get_system_stats(self) -> Dict[str, Any]:
        self.flush_buffers()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) as total_flows, SUM(byte_count) as total_bytes FROM flows")
            flow_res = cursor.fetchone()
            total_flows = flow_res["total_flows"] or 0
            total_bytes = flow_res["total_bytes"] or 0

            cursor.execute("SELECT COUNT(*) as total_alerts FROM alerts")
            total_alerts = cursor.fetchone()["total_alerts"] or 0

            sev_counts = self.get_alert_counts_by_severity()

            # Latest throughput metric
            cursor.execute("SELECT flows_per_sec, packets_per_sec, bytes_per_sec FROM metrics ORDER BY id DESC LIMIT 1")
            latest_metric = cursor.fetchone()
            fps = latest_metric["flows_per_sec"] if latest_metric else 0.0
            pps = latest_metric["packets_per_sec"] if latest_metric else 0.0

            return {
                "total_flows": total_flows,
                "total_bytes": total_bytes,
                "total_alerts": total_alerts,
                "critical_alerts": sev_counts.get("CRITICAL", 0),
                "high_alerts": sev_counts.get("HIGH", 0),
                "medium_alerts": sev_counts.get("MEDIUM", 0),
                "low_alerts": sev_counts.get("LOW", 0),
                "current_flows_per_sec": fps,
                "current_packets_per_sec": pps,
            }

    def clear_data(self):
        self._alert_buffer.clear()
        self._flow_buffer.clear()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM alerts;")
            cursor.execute("DELETE FROM flows;")
            cursor.execute("DELETE FROM metrics;")
            conn.commit()
