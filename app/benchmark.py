"""
Throughput and Latency Benchmarking Suite.
Measures real performance under continuous packet streaming:
- Total flows processed
- Flows/second throughput
- Packets/second ingestion rate
- Mean, P95, P99 detection latency
- Alerts generated
- CPU and Memory utilization via psutil
"""

import argparse
from pathlib import Path
import sys
import time
from typing import List
import numpy as np
import psutil

from app.alerts.generator import AlertPipeline
from app.features.flow_features import FlowFeatureExtractor
from app.ingest.flow_stream import FlowStreamManager
from app.ingest.pcap_reader import StreamingPCAPReader
from app.storage.database import ThreatDatabase


def run_benchmark(pcap_path: str, duration: int = 60, max_packets: int = None):
    print("=" * 65)
    print("      NTRO UNIDIRECTIONAL THREAT DETECTION - BENCHMARK")
    print(f"      Target PCAP: {pcap_path}")
    print(f"      Max Duration: {duration}s")
    print("=" * 65)

    proc = psutil.Process()
    initial_mem_mb = proc.memory_info().rss / (1024 * 1024)

    # In-memory temporary database for benchmark to isolate pure detection throughput
    db = ThreatDatabase("data/benchmark_test.db")
    db.clear_data()

    pipeline = AlertPipeline(db=db)
    flow_manager = FlowStreamManager(flow_timeout_sec=5.0, sliding_window_sec=5.0)

    reader = StreamingPCAPReader(pcap_path)

    total_packets = 0
    total_flows = 0
    total_alerts = 0
    latencies: List[float] = []

    def alert_tracker(alert):
        nonlocal total_alerts
        total_alerts += 1

    pipeline.subscribe(alert_tracker)

    start_time = time.perf_counter()
    stop_time = start_time + duration

    for packet in reader.stream_packets():
        total_packets += 1
        now = time.perf_counter()
        if now >= stop_time:
            break

        active_flow, expired_flows = flow_manager.process_packet(packet)

        for flow_dict in expired_flows:
            t0 = time.perf_counter()
            features = FlowFeatureExtractor.extract_features(flow_dict)
            if flow_dict.get("dns_queries"):
                features["dns_queries"] = flow_dict["dns_queries"]
            if flow_dict.get("tls_metadata"):
                features["tls_metadata"] = flow_dict["tls_metadata"]
            features["timestamps"] = flow_dict.get("timestamps", [])
            features["packet_lengths"] = flow_dict.get("packet_lengths", [])

            pipeline.process_flow(features)
            t1 = time.perf_counter()
            latencies.append((t1 - t0) * 1000.0)  # ms
            total_flows += 1

        if active_flow["total_packets"] in (5, 15, 30):
            t0 = time.perf_counter()
            features = FlowFeatureExtractor.extract_features(active_flow)
            pipeline.process_flow(features)
            t1 = time.perf_counter()
            latencies.append((t1 - t0) * 1000.0)

        if max_packets and total_packets >= max_packets:
            break

    # Flush remaining
    remaining = flow_manager.flush_all()
    for flow_dict in remaining:
        t0 = time.perf_counter()
        features = FlowFeatureExtractor.extract_features(flow_dict)
        pipeline.process_flow(features)
        t1 = time.perf_counter()
        latencies.append((t1 - t0) * 1000.0)
        total_flows += 1

    end_time = time.perf_counter()
    elapsed_total = max(0.0001, end_time - start_time)

    final_mem_mb = proc.memory_info().rss / (1024 * 1024)
    cpu_percent = proc.cpu_percent(interval=0.1)

    # Compute latency statistics
    if latencies:
        arr_lat = np.array(latencies)
        mean_lat = float(np.mean(arr_lat))
        p95_lat = float(np.percentile(arr_lat, 95))
        p99_lat = float(np.percentile(arr_lat, 99))
        max_lat = float(np.max(arr_lat))
    else:
        mean_lat = p95_lat = p99_lat = max_lat = 0.0

    fps = total_flows / elapsed_total
    pps = total_packets / elapsed_total

    print("\n" + "=" * 65)
    print("              ACTUAL MEASURED BENCHMARK RESULTS")
    print("=" * 65)
    print(f"  Test Duration:              {elapsed_total:.2f} seconds")
    print(f"  Total Packets Processed:    {total_packets:,}")
    print(f"  Total Flows Evaluated:      {total_flows:,}")
    print(f"  Alerts Generated:           {total_alerts:,}")
    print("-" * 65)
    print(f"  Ingestion Throughput:       {pps:,.1f} packets/sec")
    print(f"  Flow Processing Rate:       {fps:,.1f} flows/sec")
    print("-" * 65)
    print(f"  Mean Detection Latency:     {mean_lat:.3f} ms / flow")
    print(f"  P95 Detection Latency:      {p95_lat:.3f} ms / flow")
    print(f"  P99 Detection Latency:      {p99_lat:.3f} ms / flow")
    print(f"  Max Latency:                {max_lat:.3f} ms / flow")
    print("-" * 65)
    print(f"  Initial Memory:             {initial_mem_mb:.1f} MB")
    print(f"  Final Memory:               {final_mem_mb:.1f} MB (Delta: {final_mem_mb - initial_mem_mb:+.1f} MB)")
    print(f"  CPU Utilization:            {cpu_percent:.1f}%")
    print("=" * 65)

    # Cleanup benchmark DB
    try:
        Path("data/benchmark_test.db").unlink(missing_ok=True)
    except Exception:
        pass


def main():
    parser = argparse.ArgumentParser(description="NTRO Threat Detection Throughput Benchmark")
    parser.add_argument("--pcap", type=str, default="data/sample/demo.pcap", help="PCAP path")
    parser.add_argument("--duration", type=int, default=60, help="Benchmark duration in seconds")
    parser.add_argument("--max-packets", type=int, default=None, help="Max packets to benchmark")
    args = parser.parse_args()

    pcap_path = Path(args.pcap)
    if not pcap_path.exists():
        print(f"[-] PCAP {pcap_path} not found.")
        sys.exit(1)

    run_benchmark(str(pcap_path), duration=args.duration, max_packets=args.max_packets)


if __name__ == "__main__":
    main()
