"""
Passive Streaming PCAP Replay Simulator.
Replays packet capture files incrementally at configurable speeds, simulating a live passive network tap.
Guarantees unidirectional read-only operation with zero transmission or active packet injection.
"""

import argparse
import logging
import sys
import time
from pathlib import Path
from typing import Optional

from app.alerts.generator import AlertPipeline
from app.config import get_config
from app.features.flow_features import FlowFeatureExtractor
from app.ingest.flow_stream import FlowStreamManager
from app.ingest.pcap_reader import StreamingPCAPReader
from app.storage.database import ThreatDatabase

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("replay_engine")


class PCAPReplayEngine:
    def __init__(
        self,
        pcap_path: str,
        speed: float = 1.0,
        flow_timeout: float = 10.0,
        sliding_window: float = 10.0,
        db_path: str = "data/threats.db"
    ):
        self.pcap_path = pcap_path
        self.speed = max(0.0, float(speed))
        self.db = ThreatDatabase(db_path)
        self.pipeline = AlertPipeline(db=self.db)
        self.flow_manager = FlowStreamManager(
            flow_timeout_sec=flow_timeout,
            sliding_window_sec=sliding_window
        )

        # Performance tracking
        self.total_packets = 0
        self.total_flows_processed = 0
        self.total_alerts_emitted = 0
        self.start_wall_time = 0.0

        # Subscribe pipeline logger
        self.pipeline.subscribe(self._on_alert)

    def _on_alert(self, alert):
        self.total_alerts_emitted += 1
        print(f"\n[ALERT] [{alert.severity.value}] {alert.threat_class} (Confidence: {alert.confidence:.2f})")
        print(f"        Flow: {alert.src_ip}:{alert.src_port} -> {alert.dst_ip}:{alert.dst_port} ({alert.protocol})")
        print(f"        Detector: {alert.detector}")
        for k, v in list(alert.evidence.items())[:4]:
            print(f"        Evidence: {k} = {v}")

    def run(self, max_packets: Optional[int] = None, loop: bool = False):
        """Execute the incremental streaming replay."""
        print("=" * 65)
        print("   NTRO PASSIVE CYBER THREAT DETECTOR - REPLAY INGEST")
        print("   Security: UNIDIRECTIONAL ENCLAVE (STRICTLY PASSIVE)")
        print(f"   PCAP: {self.pcap_path} | Speed: {self.speed}x")
        print("=" * 65)

        self.start_wall_time = time.time()
        last_metric_time = self.start_wall_time
        packets_since_metric = 0
        bytes_since_metric = 0
        flows_since_metric = 0

        while True:
            reader = StreamingPCAPReader(self.pcap_path)
            prev_packet_time = None

            for packet in reader.stream_packets():
                self.total_packets += 1
                packets_since_metric += 1
                bytes_since_metric += packet["length"]

                # Timing simulation
                pkt_time = packet["timestamp"]
                if self.speed > 0.0 and prev_packet_time is not None:
                    delta = (pkt_time - prev_packet_time) / self.speed
                    if 0.0001 < delta < 2.0:  # Cap large gaps
                        time.sleep(delta)
                prev_packet_time = pkt_time

                # Ingest into flow manager
                active_flow, expired_flows = self.flow_manager.process_packet(packet)

                # Process any expired flows that completed
                for exp in expired_flows:
                    self._evaluate_flow(exp)
                    self.total_flows_processed += 1
                    flows_since_metric += 1

                # Periodically evaluate active flow for real-time detections (e.g. active attacks)
                if active_flow["total_packets"] in (5, 15, 30, 60, 100) or active_flow.get("is_syn_only"):
                    self._evaluate_flow(active_flow)

                # Record throughput metrics to DB every 1.0 wall-clock seconds
                wall_now = time.time()
                elapsed = wall_now - last_metric_time
                if elapsed >= 1.0:
                    fps = round(flows_since_metric / elapsed, 2)
                    pps = round(packets_since_metric / elapsed, 2)
                    bps = round(bytes_since_metric / elapsed, 2)

                    sev_counts = self.db.get_alert_counts_by_severity()
                    self.db.record_metrics(
                        flows_per_sec=fps,
                        packets_per_sec=pps,
                        bytes_per_sec=bps,
                        active_flows=len(self.flow_manager.active_flows),
                        total_alerts=self.total_alerts_emitted,
                        critical_alerts=sev_counts.get("CRITICAL", 0)
                    )

                    last_metric_time = wall_now
                    packets_since_metric = 0
                    bytes_since_metric = 0
                    flows_since_metric = 0

                if max_packets and self.total_packets >= max_packets:
                    break

            # Flush any remaining active flows at PCAP conclusion
            remaining = self.flow_manager.flush_all()
            for rem in remaining:
                self._evaluate_flow(rem)
                self.total_flows_processed += 1

            if not loop or (max_packets and self.total_packets >= max_packets):
                break

        total_elapsed = max(0.001, time.time() - self.start_wall_time)
        print("\n" + "=" * 65)
        print("   REPLAY COMPLETED")
        print(f"   Total Packets:   {self.total_packets:,}")
        print(f"   Total Flows:     {self.total_flows_processed:,}")
        print(f"   Total Alerts:    {self.total_alerts_emitted:,}")
        print(f"   Elapsed Time:    {total_elapsed:.2f} s")
        print(f"   Avg Throughput:  {self.total_flows_processed / total_elapsed:,.1f} flows/sec")
        print("=" * 65)

    def _evaluate_flow(self, flow_dict):
        features = FlowFeatureExtractor.extract_features(flow_dict)
        if flow_dict.get("dns_queries"):
            features["dns_queries"] = flow_dict["dns_queries"]
        if flow_dict.get("tls_metadata"):
            features["tls_metadata"] = flow_dict["tls_metadata"]
        features["timestamps"] = flow_dict.get("timestamps", [])
        features["packet_lengths"] = flow_dict.get("packet_lengths", [])

        # Build context
        dst_ip = flow_dict.get("dst_ip", "")
        src_ip = flow_dict.get("src_ip", "")

        context = {
            "syn_rate": self.flow_manager.get_destination_ddos_context(dst_ip).get("syn_rate", 0.0),
            "udp_rate": self.flow_manager.get_destination_ddos_context(dst_ip).get("udp_rate", 0.0),
            "unique_sources": self.flow_manager.get_destination_ddos_context(dst_ip).get("unique_sources", 1),
            "source_ips": self.flow_manager.get_destination_ddos_context(dst_ip).get("source_ips", []),
            "scan_context": self.flow_manager.get_source_scan_context(src_ip),
            "connection_timestamps": self.flow_manager.get_host_pair_connection_times(src_ip, dst_ip),
        }

        # Check apex domain for DNS queries
        dns_queries = flow_dict.get("dns_queries", [])
        if dns_queries:
            first_q = dns_queries[0]
            parts = first_q.split(".")
            apex = ".".join(parts[-2:]) if len(parts) >= 2 else first_q
            context["dns_tunnel_context"] = self.flow_manager.get_dns_tunnel_context(apex)

        # Run pipeline
        self.pipeline.process_flow(features, context)

        # Persist flow summary record
        try:
            flow_rec = FlowFeatureExtractor.extract_features(flow_dict)
            from app.alerts.schema import FlowRecord
            record = FlowRecord(
                flow_id=flow_dict["flow_id"],
                start_time=flow_dict.get("start_time", 0.0),
                end_time=flow_dict.get("end_time", 0.0),
                src_ip=flow_dict.get("src_ip", "0.0.0.0"),
                src_port=flow_dict.get("src_port", 0),
                dst_ip=flow_dict.get("dst_ip", "0.0.0.0"),
                dst_port=flow_dict.get("dst_port", 0),
                protocol=flow_dict.get("protocol", "TCP"),
                packet_count=flow_dict.get("total_packets", 0),
                byte_count=flow_dict.get("total_bytes", 0),
                duration_sec=round(flow_dict.get("duration", 0.0), 4),
                forward_packets=flow_dict.get("forward_packets", 0),
                backward_packets=flow_dict.get("backward_packets", 0),
                forward_bytes=flow_dict.get("forward_bytes", 0),
                backward_bytes=flow_dict.get("backward_bytes", 0),
            )
            self.db.insert_flow(record)
        except Exception:
            pass


def main():
    parser = argparse.ArgumentParser(description="Passive Streaming PCAP Replay Simulator")
    parser.add_argument("--pcap", type=str, default="data/sample/demo.pcap", help="Path to input PCAP")
    parser.add_argument("--speed", type=float, default=1.0, help="Replay speed multiplier (0.0 = max throughput)")
    parser.add_argument("--max-packets", type=int, default=None, help="Stop after N packets")
    parser.add_argument("--loop", action="store_true", help="Loop PCAP indefinitely for live demo")
    parser.add_argument("--clear-db", action="store_true", help="Clear historical alerts and flows before starting")

    args = parser.parse_args()

    cfg = get_config()
    db_path = cfg.database_path

    if args.clear_db:
        db = ThreatDatabase(db_path)
        db.clear_data()
        print("[*] Cleared existing database records.")

    pcap_path = Path(args.pcap)
    if not pcap_path.exists():
        print(f"[-] PCAP file not found at {pcap_path}.")
        print("[*] Hint: run 'python -m training.generate_synthetic' first to build the sample PCAP.")
        sys.exit(1)

    engine = PCAPReplayEngine(
        pcap_path=str(pcap_path),
        speed=args.speed,
        db_path=db_path
    )
    try:
        engine.run(max_packets=args.max_packets, loop=args.loop)
    except KeyboardInterrupt:
        print("\n[*] Replay stopped by user.")


if __name__ == "__main__":
    main()
