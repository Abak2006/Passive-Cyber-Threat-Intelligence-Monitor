"""
Timing & Inter-Arrival Time (IAT) Analysis for Periodicity and Beaconing Detection.
Evaluates regular intervals characteristic of Botnet C2 communication, polling loops, and automated scripts.
Includes multi-lag autocorrelation, spectral periodicity (NumPy FFT), jitter analysis, entropy metrics,
and explicit timing evidence quality assessment to support multi-signal threat fusion.
"""

from typing import Any, Dict, List, Tuple
import math
import numpy as np


def calculate_iats(timestamps: List[float]) -> List[float]:
    """Calculate inter-arrival times (differences between consecutive packet/connection timestamps)."""
    if len(timestamps) < 2:
        return []
    sorted_ts = sorted(timestamps)
    return [round(sorted_ts[i] - sorted_ts[i - 1], 6) for i in range(1, len(sorted_ts))]


def compute_autocorrelation(iats: List[float], lag: int = 1) -> float:
    """
    Computes Pearson autocorrelation coefficient at a specified lag.
    Safely handles zero-variance and short sequence edge cases without NaN/inf.
    """
    if len(iats) <= lag or lag < 1:
        return 0.0

    arr = np.array(iats, dtype=np.float64)
    s1 = arr[:-lag]
    s2 = arr[lag:]

    std1 = float(np.std(s1))
    std2 = float(np.std(s2))

    # If IATs are perfectly constant (zero variance), autocorrelation is perfectly 1.0
    if std1 < 1e-7 and std2 < 1e-7:
        return 1.0
    if std1 < 1e-7 or std2 < 1e-7:
        return 0.0

    corr = float(np.corrcoef(s1, s2)[0, 1])
    if math.isnan(corr) or math.isinf(corr):
        return 0.0
    return float(np.clip(corr, -1.0, 1.0))


def compute_multi_lag_autocorrelation(iats: List[float], max_lag: int = 5) -> Tuple[int, float, Dict[int, float]]:
    """
    Inspects small bounded lag range (1 to min(max_lag, len(iats)//2)) to find the best periodicity lag.
    Returns (best_lag, best_corr, lag_correlations_dict).
    """
    if len(iats) < 3:
        return 1, 0.0, {}

    effective_max_lag = min(max_lag, max(1, len(iats) - 2), max(1, len(iats) // 2))
    lag_corrs: Dict[int, float] = {}
    best_lag = 1
    best_corr = -1.0

    for lag in range(1, effective_max_lag + 1):
        corr = compute_autocorrelation(iats, lag=lag)
        lag_corrs[lag] = round(corr, 4)
        if corr > best_corr:
            best_corr = corr
            best_lag = lag

    return best_lag, round(max(0.0, best_corr), 4), lag_corrs


def compute_spectral_periodicity(iats: List[float]) -> float:
    """
    Computes lightweight spectral periodicity measure using NumPy FFT.
    Calculates the ratio of peak harmonic power to total non-DC power.
    Bounded in [0.0, 1.0].
    """
    if len(iats) < 6:
        return 0.0

    arr = np.array(iats, dtype=np.float64)
    # Zero-center to remove DC component
    centered = arr - np.mean(arr)
    if np.std(centered) < 1e-7:
        # Perfectly constant IAT is trivially 100% periodic
        return 1.0

    fft_vals = np.fft.rfft(centered)
    power_spectrum = np.abs(fft_vals) ** 2

    # Exclude DC bin (index 0)
    non_dc_power = power_spectrum[1:]
    total_power = float(np.sum(non_dc_power))

    if total_power < 1e-9:
        return 0.0

    peak_power = float(np.max(non_dc_power))
    # Normalized spectral concentration: peak_power / total_power
    spectral_score = peak_power / total_power
    if math.isnan(spectral_score) or math.isinf(spectral_score):
        return 0.0
    return float(np.clip(round(spectral_score, 4), 0.0, 1.0))


def compute_jitter_metrics(iats: List[float]) -> Tuple[float, float]:
    """
    Computes (jitter_magnitude, jitter_score).
    - jitter_magnitude: mean absolute consecutive difference (MACD) / mean_iat
    - jitter_score: normalized in [0.0, 1.0], where 0.0 is zero jitter and 1.0 is extreme jitter.
    """
    if len(iats) < 2:
        return 0.0, 0.0

    arr = np.array(iats, dtype=np.float64)
    mean_iat = float(np.mean(arr))
    if mean_iat < 1e-6:
        return 0.0, 0.0

    diffs = np.abs(np.diff(arr))
    macd = float(np.mean(diffs))
    jitter_mag = macd / mean_iat
    jitter_score = float(np.clip(jitter_mag, 0.0, 1.0))

    return round(jitter_mag, 4), round(jitter_score, 4)


def compute_iat_entropy(iats: List[float], bins: int = 5) -> float:
    """
    Computes Shannon entropy of the IAT histogram normalized to [0.0, 1.0].
    Low entropy indicates concentrated/deterministic intervals.
    """
    if len(iats) < 3:
        return 0.0

    arr = np.array(iats, dtype=np.float64)
    if np.std(arr) < 1e-7:
        return 0.0

    effective_bins = min(bins, len(iats))
    counts, _ = np.histogram(arr, bins=effective_bins)
    total = np.sum(counts)
    if total == 0:
        return 0.0

    probs = counts[counts > 0] / total
    ent = -np.sum(probs * np.log2(probs))
    max_ent = math.log2(effective_bins) if effective_bins > 1 else 1.0
    norm_ent = ent / max_ent if max_ent > 0 else 0.0

    return float(np.clip(round(norm_ent, 4), 0.0, 1.0))


def compute_timing_evidence_quality(
    sample_count: int,
    cv: float,
    jitter_score: float,
    best_autocorr: float
) -> float:
    """
    Interpretable metric in [0.0, 1.0] reflecting whether timing observations are
    sufficient, coherent, and informative.
    - High quality (0.75 - 1.0): Sufficient observations with clear timing structure (periodic or structured).
    - Medium quality (0.45 - 0.74): Moderate jitter where timing retained partial signal.
    - Low quality (0.10 - 0.44): Strong randomized jitter / extreme dispersion where timing is non-informative.
    - Insufficient quality (0.0): Too few samples (< 4).
    """
    if sample_count < 4:
        return 0.0

    sample_factor = min(1.0, sample_count / 8.0)

    # If autocorrelation is high, timing is structured despite CV
    if best_autocorr >= 0.70:
        base_quality = 0.85
    elif cv < 0.15:
        base_quality = 0.95
    elif cv < 0.30:
        base_quality = 0.75
    elif cv < 0.50:
        base_quality = 0.50
    else:
        # High CV with low autocorrelation means timing signal is degraded
        base_quality = max(0.10, 0.40 - (0.5 * jitter_score))

    quality = base_quality * sample_factor
    return float(np.clip(round(quality, 4), 0.0, 1.0))


def compute_composite_periodicity_score(
    cv: float,
    best_autocorr: float,
    spectral_score: float,
    jitter_score: float,
    sample_count: int
) -> float:
    """
    Computes bounded composite periodicity score in [0.0, 1.0].
    Combines:
    - CV evidence (lower CV -> higher score)
    - Multi-lag Autocorrelation evidence (higher -> higher score)
    - Spectral FFT peak concentration (higher -> higher score)
    - Jitter tolerance penalty (attenuates score under high random jitter)
    """
    # 1. CV Component (0.0 to 1.0)
    cv_component = math.exp(-3.0 * max(0.0, cv))

    # 2. Autocorrelation Component (0.0 to 1.0)
    corr_component = max(0.0, best_autocorr)

    # 3. Spectral Component (0.0 to 1.0)
    spec_component = max(0.0, spectral_score)

    # Weighted blend depending on sample size
    if sample_count >= 8:
        raw_score = 0.45 * cv_component + 0.35 * corr_component + 0.20 * spec_component
    elif sample_count >= 4:
        raw_score = 0.60 * cv_component + 0.40 * corr_component
    else:
        raw_score = cv_component

    # Attenuate by jitter score when jitter is high
    jitter_attenuation = 1.0 - (0.35 * max(0.0, jitter_score - 0.25))
    final_score = raw_score * max(0.1, jitter_attenuation)

    return float(np.clip(round(final_score, 4), 0.0, 1.0))


def compute_advanced_timing_stats(timestamps: List[float]) -> Dict[str, Any]:
    """
    Comprehensive multi-feature timing analysis for adversarially robust beacon detection.
    Returns bounded metrics dictionary with zero NaN/inf values.
    """
    iats = calculate_iats(timestamps)
    if not iats:
        return {
            "mean_iat": 0.0,
            "std_iat": 0.0,
            "cv": 0.0,
            "lag1_autocorr": 0.0,
            "best_lag": 1,
            "best_autocorr": 0.0,
            "lag_correlations": {},
            "spectral_periodicity": 0.0,
            "jitter_magnitude": 0.0,
            "jitter_score": 0.0,
            "iat_entropy": 0.0,
            "periodicity_score": 0.0,
            "timing_evidence_quality": 0.0,
            "sample_count": len(timestamps),
            "iat_count": 0,
        }

    arr = np.array(iats, dtype=np.float64)
    mean_iat = float(np.mean(arr))
    std_iat = float(np.std(arr))

    # Handle zero variance / constant IAT
    if std_iat < 1e-7:
        cv = 0.0
    elif mean_iat > 1e-7:
        cv = std_iat / mean_iat
    else:
        cv = 0.0

    lag1_corr = compute_autocorrelation(iats, lag=1)
    best_lag, best_corr, lag_corrs = compute_multi_lag_autocorrelation(iats, max_lag=5)
    spectral = compute_spectral_periodicity(iats)
    jitter_mag, jitter_score = compute_jitter_metrics(iats)
    iat_ent = compute_iat_entropy(iats)

    periodicity = compute_composite_periodicity_score(
        cv=cv,
        best_autocorr=best_corr,
        spectral_score=spectral,
        jitter_score=jitter_score,
        sample_count=len(timestamps)
    )

    timing_quality = compute_timing_evidence_quality(
        sample_count=len(timestamps),
        cv=cv,
        jitter_score=jitter_score,
        best_autocorr=best_corr
    )

    return {
        "mean_iat": round(mean_iat, 4),
        "std_iat": round(std_iat, 4),
        "cv": round(cv, 4),
        "min_iat": round(float(np.min(arr)), 4),
        "max_iat": round(float(np.max(arr)), 4),
        "lag1_autocorr": round(lag1_corr, 4),
        "best_lag": best_lag,
        "best_autocorr": round(best_corr, 4),
        "lag_correlations": lag_corrs,
        "spectral_periodicity": round(spectral, 4),
        "jitter_magnitude": round(jitter_mag, 4),
        "jitter_score": round(jitter_score, 4),
        "iat_entropy": round(iat_ent, 4),
        "periodicity_score": round(periodicity, 4),
        "timing_evidence_quality": timing_quality,
        "sample_count": len(timestamps),
        "iat_count": len(iats),
    }


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


def compute_timing_stats(timestamps: List[float]) -> Tuple[float, float, float, float]:
    """
    Legacy API compatible wrapper returning (mean_iat, std_iat, cv, periodicity_score).
    """
    stats = compute_advanced_timing_stats(timestamps)
    return stats["mean_iat"], stats["std_iat"], stats["cv"], stats["periodicity_score"]


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
