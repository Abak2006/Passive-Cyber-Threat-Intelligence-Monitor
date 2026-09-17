"""
Data Exfiltration Threat Detector.
Identifies anomalous outbound bulk transfers, asymmetric upload volume,
sustained high-rate transfers, and stateful multi-window slow-and-low exfiltration.
"""

from collections import defaultdict, deque
from pathlib import Path
import time
from typing import Any, Dict, List, Optional
import joblib
import numpy as np

from app.alerts.schema import DetectionResult, SeverityLevel
from app.detectors.base import BaseDetector
from app.features.timing_features import (
    calculate_destination_persistence,
    calculate_iat_statistics,
    calculate_rolling_transfer_statistics,
)


class ExfiltrationDetector(BaseDetector):
    """
    Passive Data Exfiltration Threat Detector.
    Evaluates multi-signal volumetric, rate, and temporal telemetry to detect outbound data theft:
    1. Bulk Exfiltration:
       - Asymmetric byte ratio (Outbound >> Inbound)
       - Sustained high-rate upload (outbound bytes/sec)
       - Large burst volume
       - Destination persistence / frequency
       - Unsupervised Isolation Forest anomaly score
    2. Stateful Slow-and-Low Exfiltration:
       - Rolling time windows (60s, 300s, 900s, 3600s)
       - Bounded state tracking across multiple flows
       - Low-and-slow cumulative outbound volume aggregation
       - Inter-arrival time (IAT) analysis and coefficient of variation (CV)
       - Destination persistence (dominant destination concentration)
       - Guarding against false positives on legitimate periodic traffic
    """

    def __init__(
        self,
        ratio_threshold: float = 6.0,
        min_outbound_bytes: int = 200_000,
        sustained_rate_threshold_bps: float = 1_000_000.0,
        burst_threshold_bytes: int = 2_000_000,
        min_duration: float = 0.5,
        min_bytes_baseline: int = 1_000,
        min_bytes_threshold: Optional[int] = None,
        model_path: Optional[str] = "models/exfil_detector.joblib",
        # Slow-and-low configuration options:
        slow_exfil_enabled: bool = True,
        slow_windows: Optional[List[float]] = None,
        slow_min_transfers: int = 4,
        slow_min_cumulative_bytes: int = 35_000,
        slow_max_cv: float = 0.50,
        slow_persistence_threshold: float = 0.75,
        slow_asymmetric_ratio_threshold: float = 3.5,
        slow_score_threshold: float = 0.65,
        slow_weights: Optional[Dict[str, float]] = None,
        max_history_per_source: int = 1000,
    ):
        super().__init__(name="exfiltration_detector")
        self.ratio_threshold = ratio_threshold
        self.min_outbound_bytes = min_outbound_bytes
        self.sustained_rate_threshold_bps = sustained_rate_threshold_bps
        self.burst_threshold_bytes = burst_threshold_bytes
        self.min_duration = min_duration
        self.min_bytes_baseline = min_bytes_threshold if min_bytes_threshold is not None else min_bytes_baseline
        self.model_path = model_path
        self.model = None

        if self.model_path and Path(self.model_path).exists():
            try:
                self.model = joblib.load(self.model_path)
            except Exception:
                self.model = None

        # Slow-and-low parameters
        self.slow_exfil_enabled = slow_exfil_enabled
        self.slow_windows = slow_windows if slow_windows is not None else [60.0, 300.0, 900.0, 3600.0]
        self.slow_min_transfers = slow_min_transfers
        self.slow_min_cumulative_bytes = slow_min_cumulative_bytes
        self.slow_max_cv = slow_max_cv
        self.slow_persistence_threshold = slow_persistence_threshold
        self.slow_asymmetric_ratio_threshold = slow_asymmetric_ratio_threshold
        self.slow_score_threshold = slow_score_threshold
        self.slow_weights = slow_weights if slow_weights is not None else {
            "volume": 0.25,
            "asymmetry": 0.25,
            "persistence": 0.20,
            "timing": 0.15,
            "frequency": 0.15,
        }
        self.max_history_per_source = max_history_per_source

        # Bounded temporal rolling state: src_ip -> deque of transfer dicts
        self.source_history: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=self.max_history_per_source)
        )

    def reset_state(self):
        """Clears all in-memory rolling state (useful for tests and stream isolation)."""
        self.source_history.clear()

    def predict(
        self,
        flow_features: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> Optional[DetectionResult]:
        ctx = context or {}
        src_ip = flow_features.get("src_ip", "")
        dst_ip = flow_features.get("dst_ip", "")
        dst_port = int(flow_features.get("dst_port", 0))
        fwd_bytes = int(flow_features.get("forward_bytes", 0))
        bwd_bytes = int(flow_features.get("backward_bytes", 0))
        duration = max(0.001, float(flow_features.get("duration", 1.0)))

        # Timestamp resolution
        ts = flow_features.get("end_time") or flow_features.get("start_time")
        if not ts:
            timestamps = flow_features.get("timestamps", [])
            ts = max(timestamps) if timestamps else ctx.get("timestamp", time.time())
        ts = float(ts)

        # Update stateful rolling history for source IP if outbound bytes meet baseline filter
        if self.slow_exfil_enabled and src_ip and fwd_bytes >= self.min_bytes_baseline:
            flow_id = flow_features.get("flow_id", "")
            history_deque = self.source_history[src_ip]

            # Check if this exact flow_id is already present in recent history
            existing_record = None
            if flow_id:
                for r in reversed(history_deque):
                    if r.get("flow_id") == flow_id:
                        existing_record = r
                        break

            if existing_record is not None:
                existing_record["forward_bytes"] = fwd_bytes
                existing_record["backward_bytes"] = bwd_bytes
                existing_record["timestamp"] = ts
                existing_record["duration"] = duration
            else:
                transfer_record = {
                    "flow_id": flow_id,
                    "timestamp": ts,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "forward_bytes": fwd_bytes,
                    "backward_bytes": bwd_bytes,
                    "duration": duration,
                }
                history_deque.append(transfer_record)

            # Evict entries older than max(windows) to guarantee bounded memory
            max_window = max(self.slow_windows) if self.slow_windows else 3600.0
            cutoff = ts - max_window
            while history_deque and history_deque[0]["timestamp"] < cutoff:
                history_deque.popleft()

        # =========================================================================
        # PATH 1: EVALUATE SINGLE-FLOW BULK EXFILTRATION
        # =========================================================================
        # Safe ratio calculation avoiding division by zero, NaN, or Inf
        if bwd_bytes <= 0:
            ratio = float(min(10000.0, fwd_bytes)) if fwd_bytes > 0 else 1.0
        else:
            ratio = float(fwd_bytes) / float(bwd_bytes)

        if np.isnan(ratio) or np.isinf(ratio):
            ratio = 1.0

        byte_rate = float(fwd_bytes) / duration
        destination_frequency = ctx.get("dst_frequency", 1)

        is_asymmetric_bulk = (ratio >= self.ratio_threshold and fwd_bytes >= self.min_outbound_bytes)
        is_high_rate = (byte_rate >= self.sustained_rate_threshold_bps and duration >= self.min_duration and ratio >= 2.0 and fwd_bytes >= 50_000)
        is_burst = (fwd_bytes >= self.burst_threshold_bytes and ratio >= 2.0)

        ml_anomaly = False
        ml_score = 0.0
        if self.model is not None and fwd_bytes >= self.min_outbound_bytes:
            try:
                vec = np.array([[fwd_bytes, bwd_bytes, ratio, byte_rate, duration]])
                pred = self.model.predict(vec)[0]
                if hasattr(self.model, "score_samples"):
                    score = -float(self.model.score_samples(vec)[0])
                    ml_score = score
                    if pred == -1 or score > 0.65:
                        ml_anomaly = True
            except Exception:
                pass

        is_bulk = is_asymmetric_bulk or is_high_rate or is_burst or (ml_anomaly and ratio >= 2.0 and fwd_bytes >= self.min_outbound_bytes)

        bulk_result = None
        if is_bulk:
            reasons = []
            if is_asymmetric_bulk:
                reasons.append(f"Upload ratio ({ratio:.2f}x) exceeds asymmetry threshold ({self.ratio_threshold}x) with {fwd_bytes/1024:.1f} KB transferred")
            if is_high_rate:
                reasons.append(f"Outbound transfer rate ({byte_rate/1024/1024:.2f} MB/s) exceeds sustained threshold ({self.sustained_rate_threshold_bps/1024/1024:.2f} MB/s)")
            if is_burst:
                reasons.append(f"Volume ({fwd_bytes/1024/1024:.2f} MB) exceeds burst threshold ({self.burst_threshold_bytes/1024/1024:.2f} MB)")
            if ml_anomaly:
                reasons.append(f"Unsupervised Isolation Forest anomaly score ({ml_score:.3f}) exceeds threshold")
            if destination_frequency > 1:
                reasons.append(f"Destination contacted repeatedly ({destination_frequency} flows in window)")

            base_confidence = 0.65
            asym_score = min(0.12, 0.04 + 0.03 * float(np.log10(max(1.0, ratio / self.ratio_threshold) + 1.0))) if ratio >= self.ratio_threshold else 0.0
            vol_score = min(0.10, (fwd_bytes / 2_000_000.0) * 0.10)
            rate_score = min(0.08, (byte_rate / self.sustained_rate_threshold_bps) * 0.08) if byte_rate >= (self.sustained_rate_threshold_bps * 0.5) else 0.0
            persist_score = 0.05 if destination_frequency > 1 else 0.0
            ml_contrib = 0.06 if ml_anomaly else 0.0

            raw_confidence = base_confidence + asym_score + vol_score + rate_score + persist_score + ml_contrib
            bulk_confidence = round(min(0.98, max(0.50, raw_confidence)), 4)

            if bulk_confidence >= 0.88 or (is_asymmetric_bulk and is_high_rate) or fwd_bytes >= 2_000_000:
                bulk_severity = SeverityLevel.CRITICAL
            elif is_asymmetric_bulk or is_burst or bulk_confidence >= 0.75:
                bulk_severity = SeverityLevel.HIGH
            else:
                bulk_severity = SeverityLevel.MEDIUM

            bulk_evidence = {
                "subtype": "BULK",
                "threat_subtype": "BULK",
                "threat_diagnosis": "; ".join(reasons),
                "bytes_out": fwd_bytes,
                "bytes_in": bwd_bytes,
                "out_in_ratio": round(ratio, 2),
                "outbound_inbound_ratio": round(ratio, 2),
                "outbound_rate_bytes_per_sec": round(byte_rate, 2),
                "duration_sec": round(duration, 2),
                "sustained_duration_sec": round(duration, 2),
                "destination_frequency": destination_frequency,
                "ratio_threshold_configured": self.ratio_threshold,
                "ml_anomaly_detected": ml_anomaly,
                "malicious_evidence": reasons,
            }
            bulk_result = {
                "confidence": bulk_confidence,
                "severity": bulk_severity,
                "evidence": bulk_evidence,
            }

        # =========================================================================
        # PATH 2: EVALUATE STATEFUL MULTI-WINDOW SLOW-AND-LOW EXFILTRATION
        # =========================================================================
        slow_result = None
        if self.slow_exfil_enabled and src_ip in self.source_history:
            history_list = list(self.source_history[src_ip])
            best_window_match = None
            highest_slow_score = -1.0

            # Evaluate each configured rolling window
            for win_sec in sorted(self.slow_windows):
                stats = calculate_rolling_transfer_statistics(history_list, win_sec, ts)
                t_count = stats["transfer_count"]
                cum_fwd = stats["cumulative_outbound_bytes"]
                cum_bwd = stats["cumulative_inbound_bytes"]
                cum_ratio = stats["outbound_inbound_ratio"]

                # Gate: Must meet minimum transfer count and minimum cumulative outbound bytes
                if t_count < self.slow_min_transfers or cum_fwd < self.slow_min_cumulative_bytes:
                    continue

                active_transfers = stats["active_transfers"]
                persistence_stats = calculate_destination_persistence(active_transfers)
                pers_ratio = persistence_stats["persistence_ratio"]
                dom_dst = persistence_stats["dominant_dst_ip"]

                # Extract IAT timing for transfers to the dominant destination (or all if dominant)
                dom_ts = [t["timestamp"] for t in active_transfers if t.get("dst_ip") == dom_dst]
                if len(dom_ts) < 2:
                    dom_ts = [t["timestamp"] for t in active_transfers]
                iat_stats = calculate_iat_statistics(dom_ts)
                iat_cv = iat_stats["cv"]
                mean_iat = iat_stats["mean_iat"]

                # -----------------------------------------------------------------
                # STRICT ANTI-FALSE-POSITIVE GUARDS:
                # 1. Balanced duplex (cum_ratio < 2.0) is normal bidirectional traffic.
                # 2. Multi-destination dispersion (pers_ratio < 0.50) is normal browsing.
                # 3. Periodicity alone NEVER triggers exfiltration.
                # -----------------------------------------------------------------
                if cum_ratio < 2.0 or pers_ratio < 0.50:
                    continue

                # Normalized Component Scores [0.0, 1.0]
                # 1. Volume score
                s_vol = min(1.0, cum_fwd / float(self.slow_min_cumulative_bytes * 2.5))

                # 2. Asymmetry score
                s_asym = min(1.0, max(0.0, (cum_ratio - 1.0) / float(self.slow_asymmetric_ratio_threshold - 1.0)))

                # 3. Destination persistence score
                s_pers = min(1.0, max(0.0, (pers_ratio - 0.50) / 0.50))

                # 4. Timing consistency / Periodicity score
                # Low CV indicates steady, automated staging intervals
                if iat_cv <= self.slow_max_cv:
                    s_timing = max(0.25, 1.0 - (iat_cv / (self.slow_max_cv * 1.5)))
                else:
                    s_timing = max(0.05, 0.40 - 0.20 * min(2.0, (iat_cv - self.slow_max_cv)))

                # 5. Frequency score
                s_freq = min(1.0, t_count / float(self.slow_min_transfers * 2.0))

                w = self.slow_weights
                slow_score = (
                    w.get("volume", 0.25) * s_vol +
                    w.get("asymmetry", 0.25) * s_asym +
                    w.get("persistence", 0.20) * s_pers +
                    w.get("timing", 0.15) * s_timing +
                    w.get("frequency", 0.15) * s_freq
                )

                # Penalize heavily if asymmetry or persistence is weak
                if cum_ratio < 2.5 or pers_ratio < self.slow_persistence_threshold:
                    slow_score *= 0.65

                if slow_score >= self.slow_score_threshold and slow_score > highest_slow_score:
                    highest_slow_score = slow_score
                    best_window_match = {
                        "window_sec": win_sec,
                        "stats": stats,
                        "persistence": persistence_stats,
                        "iat_stats": iat_stats,
                        "score": round(slow_score, 4),
                    }

            if best_window_match is not None:
                bw = best_window_match
                b_stats = bw["stats"]
                b_pers = bw["persistence"]
                b_iat = bw["iat_stats"]
                score = bw["score"]

                slow_conf = round(min(0.96, max(0.65, 0.55 + 0.40 * score)), 4)
                if b_stats["cumulative_outbound_bytes"] >= 150_000 or slow_conf >= 0.88:
                    slow_sev = SeverityLevel.CRITICAL
                elif b_stats["cumulative_outbound_bytes"] >= 50_000 or slow_conf >= 0.75:
                    slow_sev = SeverityLevel.HIGH
                else:
                    slow_sev = SeverityLevel.MEDIUM

                diag = (
                    f"Slow-and-low exfiltration pattern identified across {int(bw['window_sec'])}s window: "
                    f"{b_stats['transfer_count']} transfers totaling {b_stats['cumulative_outbound_bytes']:,} bytes "
                    f"outbound (asymmetry: {b_stats['outbound_inbound_ratio']:.1f}x, destination persistence: "
                    f"{b_pers['persistence_ratio']*100:.0f}% to {b_pers['dominant_dst_ip']}, "
                    f"IAT CV: {b_iat['cv']:.2f}, score: {score:.2f})."
                )
                malicious_reasons = [
                    f"Temporal aggregation: {b_stats['transfer_count']} low-volume transfers staged over {b_stats['duration_sec']:.1f}s",
                    f"High destination persistence ({b_pers['persistence_ratio']*100:.0f}%) to {b_pers['dominant_dst_ip']}:{b_pers['dominant_dst_port']}",
                    f"Cumulative outbound/inbound byte asymmetry of {b_stats['outbound_inbound_ratio']:.1f}x",
                    f"Consistent inter-arrival timing interval (CV={b_iat['cv']:.2f}, mean={b_iat['mean_iat']:.1f}s)",
                ]

                slow_evidence = {
                    "subtype": "SLOW_AND_LOW",
                    "threat_subtype": "SLOW_AND_LOW",
                    "window_seconds": int(bw["window_sec"]),
                    "transfer_count": b_stats["transfer_count"],
                    "cumulative_outbound_bytes": b_stats["cumulative_outbound_bytes"],
                    "cumulative_inbound_bytes": b_stats["cumulative_inbound_bytes"],
                    "average_transfer_bytes": b_stats["avg_outbound_bytes"],
                    "min_transfer_bytes": b_stats["min_outbound_bytes"],
                    "max_transfer_bytes": b_stats["max_outbound_bytes"],
                    "mean_interarrival_seconds": b_iat["mean_iat"],
                    "iat_cv": b_iat["cv"],
                    "destination_persistence": b_pers["persistence_ratio"],
                    "dominant_destination": f"{b_pers['dominant_dst_ip']}:{b_pers['dominant_dst_port']}",
                    "unique_destinations": b_pers["unique_dst_count"],
                    "outbound_inbound_ratio": b_stats["outbound_inbound_ratio"],
                    "out_in_ratio": b_stats["outbound_inbound_ratio"],
                    "bytes_out": b_stats["cumulative_outbound_bytes"],
                    "bytes_in": b_stats["cumulative_inbound_bytes"],
                    "duration_seconds": b_stats["duration_sec"],
                    "duration_sec": b_stats["duration_sec"],
                    "slow_exfiltration_score": score,
                    "threat_diagnosis": diag,
                    "malicious_evidence": malicious_reasons,
                }
                slow_result = {
                    "confidence": slow_conf,
                    "severity": slow_sev,
                    "evidence": slow_evidence,
                    "target_dst_ip": b_pers["dominant_dst_ip"],
                    "target_dst_port": b_pers["dominant_dst_port"],
                }

        # =========================================================================
        # SYNTHESIS & FINAL EMISSION
        # =========================================================================
        if not bulk_result and not slow_result:
            return None

        # Case A: Both bulk and slow-and-low match
        if bulk_result and slow_result:
            fused_conf = min(0.98, max(bulk_result["confidence"], slow_result["confidence"]) + 0.04)
            fused_sev = SeverityLevel.CRITICAL if (bulk_result["severity"] == SeverityLevel.CRITICAL or slow_result["severity"] == SeverityLevel.CRITICAL) else SeverityLevel.HIGH
            combined_evidence = dict(bulk_result["evidence"])
            combined_evidence["subtype"] = "COMPOSITE_EXFILTRATION"
            combined_evidence["threat_subtype"] = "COMPOSITE_EXFILTRATION"
            combined_evidence["slow_and_low_metrics"] = slow_result["evidence"]
            combined_evidence["threat_diagnosis"] += f" | {slow_result['evidence']['threat_diagnosis']}"
            combined_evidence["malicious_evidence"].extend(slow_result["evidence"]["malicious_evidence"])

            return DetectionResult(
                threat_class="DATA_EXFILTRATION",
                confidence=round(fused_conf, 4),
                severity=fused_sev,
                detector=self.name,
                evidence=combined_evidence,
                flow_id=flow_features.get("flow_id"),
                src_ip=src_ip,
                src_port=flow_features.get("src_port"),
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=flow_features.get("protocol", "TCP"),
            )

        # Case B: Bulk exfiltration match
        if bulk_result:
            return DetectionResult(
                threat_class="DATA_EXFILTRATION",
                confidence=bulk_result["confidence"],
                severity=bulk_result["severity"],
                detector=self.name,
                evidence=bulk_result["evidence"],
                flow_id=flow_features.get("flow_id"),
                src_ip=src_ip,
                src_port=flow_features.get("src_port"),
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=flow_features.get("protocol", "TCP"),
            )

        # Case C: Slow-and-low exfiltration match
        if slow_result:
            target_dst = slow_result.get("target_dst_ip") or dst_ip
            target_port = slow_result.get("target_dst_port") or dst_port
            return DetectionResult(
                threat_class="DATA_EXFILTRATION",
                confidence=slow_result["confidence"],
                severity=slow_result["severity"],
                detector=self.name,
                evidence=slow_result["evidence"],
                flow_id=flow_features.get("flow_id"),
                src_ip=src_ip,
                src_port=flow_features.get("src_port"),
                dst_ip=target_dst,
                dst_port=target_port,
                protocol=flow_features.get("protocol", "TCP"),
            )

        return None
