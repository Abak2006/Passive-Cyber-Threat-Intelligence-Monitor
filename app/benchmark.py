"""
AEGIS Throughput and Latency Benchmarking Suite.
Measures real performance under continuous packet streaming:
- Total packets and flows processed
- Packets/second ingestion throughput
- Flows/second evaluation rate
- Alerts generated and alerts/second
- Detection latency percentiles: Mean, P50 (median), P95, P99, Max
- CPU and RSS Memory utilization (Initial, Peak, Final, Delta) via psutil
- Multi-speed sweeps (1x, 2x, 5x, 10x, max)
- JSON export for UI telemetry and reproducible reporting
"""

import argparse
import json
from pathlib import Path
import platform
import sys
import time
from typing import Any, Dict, List, Optional
import numpy as np
import psutil

from app.alerts.generator import AlertPipeline
from app.features.flow_features import FlowFeatureExtractor
from app.ingest.flow_stream import FlowStreamManager
from app.ingest.pcap_reader import StreamingPCAPReader
from app.ingest.sources import PcapReplaySource, SyntheticStreamSource
from app.storage.database import ThreatDatabase


def run_single_benchmark(
    pcap_path: Optional[str] = None,
    speed: float = 0.0,
    duration: float = 30.0,
    max_packets: Optional[int] = None,
    loop: bool = True,
    use_synthetic: bool = False,
    synthetic_count: int = 5000,
    db_path: str = "data/benchmark_test.db",
) -> Dict[str, Any]:
    """
    Executes a single benchmark run and returns measured performance metrics.
    speed=0.0 denotes maximum unthrottled throughput.
    """
    proc = psutil.Process()
    initial_mem_mb = proc.memory_info().rss / (1024 * 1024)
    peak_mem_mb = initial_mem_mb

    db = ThreatDatabase(db_path)
    db.clear_data()

    pipeline = AlertPipeline(db=db)
    flow_manager = FlowStreamManager(flow_timeout_sec=5.0, sliding_window_sec=5.0)

    total_alerts = 0

    def alert_tracker(alert):
        nonlocal total_alerts
        total_alerts += 1

    pipeline.subscribe(alert_tracker)

    total_packets = 0
    total_flows = 0
    latencies_ms: List[float] = []

    # Configure packet generator
    def packet_generator():
        if use_synthetic:
            source = SyntheticStreamSource(count=synthetic_count, interval_sec=0.0)
            for event in source.stream_events():
                yield event.to_dict()
        else:
            if not pcap_path or not Path(pcap_path).exists():
                raise FileNotFoundError(f"PCAP file not found: {pcap_path}")
            
            while True:
                reader = StreamingPCAPReader(pcap_path)
                packet_count_in_pass = 0
                prev_time = None
                for pkt in reader.stream_packets():
                    packet_count_in_pass += 1
                    if speed > 0.0 and prev_time is not None:
                        delta = (pkt["timestamp"] - prev_time) / speed
                        if 0.0001 < delta < 0.5:
                            time.sleep(delta)
                    prev_time = pkt["timestamp"]
                    yield pkt
                
                # If not looping or no packets found, terminate generator
                if not loop or packet_count_in_pass == 0:
                    break

    start_time = time.perf_counter()
    stop_time = start_time + duration

    for packet in packet_generator():
        total_packets += 1
        now = time.perf_counter()
        if now >= stop_time:
            break

        active_flow, expired_flows = flow_manager.process_packet(packet)

        # Process expired flows
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
            latencies_ms.append((t1 - t0) * 1000.0)
            total_flows += 1

        # Checkpoint active flows periodically for early detection
        if active_flow.get("total_packets") in (5, 15, 30):
            t0 = time.perf_counter()
            features = FlowFeatureExtractor.extract_features(active_flow)
            pipeline.process_flow(features)
            t1 = time.perf_counter()
            latencies_ms.append((t1 - t0) * 1000.0)

        # Sample memory periodically to capture peak
        if total_packets % 250 == 0:
            current_mem = proc.memory_info().rss / (1024 * 1024)
            if current_mem > peak_mem_mb:
                peak_mem_mb = current_mem

        if max_packets and total_packets >= max_packets:
            break

    # Flush any remaining flows
    remaining = flow_manager.flush_all()
    for flow_dict in remaining:
        t0 = time.perf_counter()
        features = FlowFeatureExtractor.extract_features(flow_dict)
        pipeline.process_flow(features)
        t1 = time.perf_counter()
        latencies_ms.append((t1 - t0) * 1000.0)
        total_flows += 1

    end_time = time.perf_counter()
    elapsed = max(0.0001, end_time - start_time)

    final_mem_mb = proc.memory_info().rss / (1024 * 1024)
    peak_mem_mb = max(peak_mem_mb, final_mem_mb)
    cpu_percent = proc.cpu_percent(interval=0.05)

    if latencies_ms:
        arr = np.array(latencies_ms)
        mean_lat = float(np.mean(arr))
        p50_lat = float(np.percentile(arr, 50))
        p95_lat = float(np.percentile(arr, 95))
        p99_lat = float(np.percentile(arr, 99))
        max_lat = float(np.max(arr))
    else:
        mean_lat = p50_lat = p95_lat = p99_lat = max_lat = 0.0

    pps = total_packets / elapsed
    fps = total_flows / elapsed
    aps = total_alerts / elapsed

    result = {
        "speed_setting": "max (unthrottled)" if speed <= 0.0 else f"{speed}x",
        "speed_factor": speed,
        "duration_sec": round(elapsed, 3),
        "total_packets": total_packets,
        "total_flows": total_flows,
        "total_alerts": total_alerts,
        "packets_per_sec": round(pps, 1),
        "flows_per_sec": round(fps, 1),
        "alerts_per_sec": round(aps, 2),
        "latency_mean_ms": round(mean_lat, 3),
        "latency_p50_ms": round(p50_lat, 3),
        "latency_p95_ms": round(p95_lat, 3),
        "latency_p99_ms": round(p99_lat, 3),
        "latency_max_ms": round(max_lat, 3),
        "initial_memory_mb": round(initial_mem_mb, 1),
        "peak_memory_mb": round(peak_mem_mb, 1),
        "final_memory_mb": round(final_mem_mb, 1),
        "memory_delta_mb": round(final_mem_mb - initial_mem_mb, 1),
        "cpu_percent": round(cpu_percent, 1),
    }

    # Cleanup temporary test DB
    try:
        Path(db_path).unlink(missing_ok=True)
    except Exception:
        pass

    return result


def print_single_result(res: Dict[str, Any]):
    print("\n" + "=" * 68)
    print(f"      AEGIS BENCHMARK RUN [{res['speed_setting'].upper()}]")
    print("=" * 68)
    print(f"  Test Duration:              {res['duration_sec']:.2f} seconds")
    print(f"  Total Packets Ingested:     {res['total_packets']:,}")
    print(f"  Total Flows Evaluated:      {res['total_flows']:,}")
    print(f"  Alerts Generated:           {res['total_alerts']:,}")
    print("-" * 68)
    print(f"  Ingestion Throughput:       {res['packets_per_sec']:,.1f} packets/sec")
    print(f"  Flow Evaluation Rate:       {res['flows_per_sec']:,.1f} flows/sec")
    print(f"  Alert Generation Rate:      {res['alerts_per_sec']:,.2f} alerts/sec")
    print("-" * 68)
    print(f"  Latency P50 (Median):       {res['latency_p50_ms']:.3f} ms / flow")
    print(f"  Latency Mean:               {res['latency_mean_ms']:.3f} ms / flow")
    print(f"  Latency P95:                {res['latency_p95_ms']:.3f} ms / flow")
    print(f"  Latency P99:                {res['latency_p99_ms']:.3f} ms / flow")
    print(f"  Latency Max:                {res['latency_max_ms']:.3f} ms / flow")
    print("-" * 68)
    print(f"  Initial Memory (RSS):       {res['initial_memory_mb']:.1f} MB")
    print(f"  Peak Memory (RSS):          {res['peak_memory_mb']:.1f} MB")
    print(f"  Final Memory (RSS):         {res['final_memory_mb']:.1f} MB (Delta: {res['memory_delta_mb']:+.1f} MB)")
    print(f"  CPU Utilization:            {res['cpu_percent']:.1f}%")
    print("=" * 68)


def run_sweep_benchmark(
    pcap_path: str,
    duration_per_speed: float = 5.0,
    speeds: Optional[List[float]] = None,
    output_json: Optional[str] = "data/benchmark_results.json",
) -> List[Dict[str, Any]]:
    if speeds is None:
        speeds = [1.0, 2.0, 5.0, 10.0, 0.0]

    print("=" * 72)
    print("      AEGIS PASSIVE THREAT INTELLIGENCE - MULTI-SPEED SWEEP")
    print(f"      Target PCAP: {pcap_path}")
    print(f"      Speeds to evaluate: {[('max' if s == 0 else f'{s}x') for s in speeds]}")
    print("=" * 72)

    results = []
    for s in speeds:
        label = "max (unthrottled)" if s == 0.0 else f"{s}x"
        print(f"\n[*] Running benchmark at rate: {label} for {duration_per_speed}s...")
        res = run_single_benchmark(
            pcap_path=pcap_path,
            speed=s,
            duration=duration_per_speed,
            loop=True,
        )
        print_single_result(res)
        results.append(res)

    # Print summary table
    print("\n" + "=" * 78)
    print("                   AEGIS REPLAY RATE SWEEP SUMMARY")
    print("=" * 78)
    header = f"{'Rate':<10} | {'Pkts/s':<12} | {'Flows/s':<12} | {'P50 (ms)':<10} | {'P95 (ms)':<10} | {'RSS (MB)':<10}"
    print(header)
    print("-" * 78)
    for r in results:
        line = (
            f"{r['speed_setting']:<10} | "
            f"{r['packets_per_sec']:<12,.1f} | "
            f"{r['flows_per_sec']:<12,.1f} | "
            f"{r['latency_p50_ms']:<10.3f} | "
            f"{r['latency_p95_ms']:<10.3f} | "
            f"{r['final_memory_mb']:<10.1f}"
        )
        print(line)
    print("=" * 78)

    if output_json:
        save_data = {
            "platform": {
                "system": platform.system(),
                "release": platform.release(),
                "machine": platform.machine(),
                "python_version": platform.python_version(),
                "cpu_count": psutil.cpu_count(logical=True),
            },
            "pcap_source": pcap_path,
            "timestamp": time.time(),
            "runs": results,
        }
        out_path = Path(output_json)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w") as f:
            json.dump(save_data, f, indent=2)
        print(f"[+] Benchmark results saved to {output_json}")

    return results


def main():
    parser = argparse.ArgumentParser(description="AEGIS Passive Threat Detection Benchmark Suite")
    parser.add_argument("--pcap", type=str, default="data/sample/demo.pcap", help="PCAP path")
    parser.add_argument("--duration", type=float, default=10.0, help="Benchmark duration in seconds")
    parser.add_argument("--speed", type=float, default=0.0, help="Speed multiplier (0.0 = max rate)")
    parser.add_argument("--max-packets", type=int, default=None, help="Max packets to benchmark")
    parser.add_argument("--loop", action="store_true", default=True, help="Loop over PCAP until duration completes")
    parser.add_argument("--no-loop", action="store_false", dest="loop", help="Do not loop over PCAP")
    parser.add_argument("--sweep", action="store_true", help="Execute multi-speed sweep (1x, 2x, 5x, 10x, max)")
    parser.add_argument("--synthetic", action="store_true", help="Benchmark using synthetic packet stream")
    parser.add_argument("--output-json", type=str, default="data/benchmark_results.json", help="Path to save JSON benchmark summary")
    args = parser.parse_args()

    if args.sweep:
        run_sweep_benchmark(
            pcap_path=args.pcap,
            duration_per_speed=args.duration if args.duration < 15 else 5.0,
            output_json=args.output_json,
        )
    else:
        res = run_single_benchmark(
            pcap_path=args.pcap,
            speed=args.speed,
            duration=args.duration,
            max_packets=args.max_packets,
            loop=args.loop,
            use_synthetic=args.synthetic,
        )
        print_single_result(res)

        if args.output_json:
            save_data = {
                "platform": {
                    "system": platform.system(),
                    "release": platform.release(),
                    "machine": platform.machine(),
                    "python_version": platform.python_version(),
                    "cpu_count": psutil.cpu_count(logical=True),
                },
                "pcap_source": args.pcap if not args.synthetic else "synthetic_stream",
                "timestamp": time.time(),
                "runs": [res],
            }
            out_path = Path(args.output_json)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            with open(out_path, "w") as f:
                json.dump(save_data, f, indent=2)
            print(f"[+] Benchmark results saved to {args.output_json}")


if __name__ == "__main__":
    main()
