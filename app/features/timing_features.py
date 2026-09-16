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
