"""
Timing & Inter-Arrival Time (IAT) Analysis for Periodicity and Beaconing Detection.
Evaluates regular intervals characteristic of Botnet C2 communication, polling loops, and automated scripts.
"""

from typing import List, Tuple
import numpy as np


def calculate_iats(timestamps: List[float]) -> List[float]:
    """Calculate inter-arrival times (differences between consecutive packet/connection timestamps)."""
    if len(timestamps) < 2:
        return []
    sorted_ts = sorted(timestamps)
    return [round(sorted_ts[i] - sorted_ts[i - 1], 6) for i in range(1, len(sorted_ts))]


def compute_timing_stats(timestamps: List[float]) -> Tuple[float, float, float, float]:
    """
    Computes (mean_iat, std_iat, coefficient_of_variation, periodicity_score).
    - CV = std / mean: When CV is very low (< 0.25), intervals are highly regular.
    - Periodicity score is normalized [0.0, 1.0].
    """
    iats = calculate_iats(timestamps)
    if not iats:
        return 0.0, 0.0, 0.0, 0.0

    arr = np.array(iats, dtype=np.float64)
    mean_iat = float(np.mean(arr))
    std_iat = float(np.std(arr))

    # Coefficient of variation (CV = std / mean)
    cv = (std_iat / mean_iat) if mean_iat > 1e-6 else 0.0

    # Periodicity scoring based on interval consistency and low dispersion
    # CV close to 0 -> high periodicity score (~1.0); CV > 1.0 -> low periodicity score (~0.0)
    # Jitter-tolerant scoring:
    if cv < 0.05:
        periodicity = 0.98
    elif cv < 0.15:
        periodicity = 0.90
    elif cv < 0.30:
        periodicity = 0.75
    elif cv < 0.50:
        periodicity = 0.50
    elif cv < 1.0:
        periodicity = 0.25
    else:
        periodicity = 0.05

    # Autocorrelation boost if sufficient samples
    if len(iats) >= 5 and std_iat > 1e-6:
        s1, s2 = arr[:-1], arr[1:]
        if np.std(s1) > 1e-6 and np.std(s2) > 1e-6:
            lag1_corr = np.corrcoef(s1, s2)[0, 1]
            if not np.isnan(lag1_corr) and lag1_corr > 0.6:
                periodicity = min(1.0, periodicity + 0.15)

    return round(mean_iat, 4), round(std_iat, 4), round(cv, 4), round(periodicity, 4)


def calculate_iat_statistics(timestamps: List[float]) -> dict:
    """
    Computes detailed IAT statistics: mean_iat, std_iat, cv, min_iat, max_iat, iat_count.
    Handles mean=0 and single/empty timestamp lists safely.
    """
    iats = calculate_iats(timestamps)
    if not iats:
        return {
            "mean_iat": 0.0,
            "std_iat": 0.0,
            "cv": 0.0,
            "min_iat": 0.0,
            "max_iat": 0.0,
            "iat_count": 0,
        }
    arr = np.array(iats, dtype=np.float64)
    mean_iat = float(np.mean(arr))
    std_iat = float(np.std(arr))
    cv = (std_iat / mean_iat) if mean_iat > 1e-6 else 0.0
    return {
        "mean_iat": round(mean_iat, 4),
        "std_iat": round(std_iat, 4),
        "cv": round(cv, 4),
        "min_iat": round(float(np.min(arr)), 4),
        "max_iat": round(float(np.max(arr)), 4),
        "iat_count": len(iats),
    }


def calculate_destination_persistence(transfers: List[dict]) -> dict:
    """
    Analyzes destination focus across a list of transfers:
    - unique_dst_count: number of distinct destination IPs
    - dominant_dst_ip: most frequently contacted destination IP
    - dominant_dst_port: most frequent destination port
    - persistence_ratio: fraction of transfers destined to the dominant IP [0.0, 1.0]
    - dominant_dst_count: number of transfers to dominant IP
    - total_transfers: total transfers evaluated
    """
    if not transfers:
        return {
            "unique_dst_count": 0,
            "dominant_dst_ip": "",
            "dominant_dst_port": 0,
            "persistence_ratio": 0.0,
            "dominant_dst_count": 0,
            "total_transfers": 0,
        }
    dst_counts = {}
    dst_port_counts = {}
    for t in transfers:
        dst = t.get("dst_ip", "")
        port = t.get("dst_port", 0)
        dst_counts[dst] = dst_counts.get(dst, 0) + 1
        dst_port_counts[(dst, port)] = dst_port_counts.get((dst, port), 0) + 1

    dominant_dst, dom_count = max(dst_counts.items(), key=lambda x: x[1])
    (dom_ip, dom_port), _ = max(dst_port_counts.items(), key=lambda x: x[1])
    total = len(transfers)
    ratio = dom_count / float(total) if total > 0 else 0.0

    return {
        "unique_dst_count": len(dst_counts),
        "dominant_dst_ip": dominant_dst,
        "dominant_dst_port": dom_port,
        "persistence_ratio": round(ratio, 4),
        "dominant_dst_count": dom_count,
        "total_transfers": total,
    }


def calculate_rolling_transfer_statistics(
    transfers: List[dict],
    window_sec: float,
    current_time: float
) -> dict:
    """
    Calculates windowed transfer statistics for a given sliding window [current_time - window_sec, current_time].
    Computes cumulative outbound/inbound bytes, safe ratios, sizes (avg, min, max), rate, and active duration.
    """
    cutoff = current_time - window_sec
    active = [t for t in transfers if t.get("timestamp", 0.0) >= cutoff]
    if not active:
        return {
            "window_sec": window_sec,
            "transfer_count": 0,
            "cumulative_outbound_bytes": 0,
            "cumulative_inbound_bytes": 0,
            "outbound_inbound_ratio": 0.0,
            "avg_outbound_bytes": 0.0,
            "min_outbound_bytes": 0,
            "max_outbound_bytes": 0,
            "bytes_per_sec": 0.0,
            "duration_sec": 0.0,
            "active_transfers": [],
        }

    fwd_bytes_list = [int(t.get("forward_bytes", t.get("fwd_bytes", 0))) for t in active]
    bwd_bytes_list = [int(t.get("backward_bytes", t.get("bwd_bytes", 0))) for t in active]
    timestamps = [float(t.get("timestamp", 0.0)) for t in active]

    total_fwd = sum(fwd_bytes_list)
    total_bwd = sum(bwd_bytes_list)

    # Safe ratio calculation avoiding division by zero, NaN, or Inf
    if total_bwd <= 0:
        ratio = float(min(10000.0, total_fwd)) if total_fwd > 0 else 1.0
    else:
        ratio = float(total_fwd) / float(total_bwd)
    if np.isnan(ratio) or np.isinf(ratio):
        ratio = 1.0

    min_ts = min(timestamps)
    max_ts = max(timestamps)
    duration = max(0.001, max_ts - min_ts)
    rate = total_fwd / duration if duration > 0 else 0.0

    return {
        "window_sec": window_sec,
        "transfer_count": len(active),
        "cumulative_outbound_bytes": total_fwd,
        "cumulative_inbound_bytes": total_bwd,
        "outbound_inbound_ratio": round(ratio, 2),
        "avg_outbound_bytes": round(float(np.mean(fwd_bytes_list)), 2) if fwd_bytes_list else 0.0,
        "min_outbound_bytes": int(np.min(fwd_bytes_list)) if fwd_bytes_list else 0,
        "max_outbound_bytes": int(np.max(fwd_bytes_list)) if fwd_bytes_list else 0,
        "bytes_per_sec": round(rate, 2),
        "duration_sec": round(duration, 2),
        "active_transfers": active,
    }

