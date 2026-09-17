"""
Entropy and Statistical Distribution Utilities for Passive Network Telemetry.
Calculates Shannon entropy for string lexical analysis and network distribution analysis
(Source IPs, Destination Ports, Destination IPs, etc.).
"""

from collections import Counter, defaultdict
import math
from typing import Any, Dict, Iterable, List, Optional, Union


def shannon_entropy(data: Union[str, bytes]) -> float:
    """
    Calculate Shannon entropy of a string or byte sequence in bits per symbol.
    H(X) = - sum(p(x) * log2(p(x)))
    Higher entropy indicates greater randomness (e.g., encrypted/compressed data or DGA domains).
    """
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def distribution_entropy(items: Iterable[Any]) -> float:
    """
    Calculate the entropy of a categorical distribution.
    Useful for detecting port scans (high port entropy) or spoofed DDoS (high source IP entropy).
    """
    items_list = list(items)
    if not items_list:
        return 0.0
    total = len(items_list)
    counts = Counter(items_list)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def source_ip_entropy(
    source_ips: Iterable[Any],
    weights: Optional[Iterable[float]] = None
) -> float:
    """
    Computes Shannon entropy of source IP addresses across an observation window.
    Supports weighted packet counts per source IP: H(X) = - sum(p(x) * log2(p(x))).
    High source diversity with elevated packet rates increases DDoS suspicion.
    """
    raw_ips = list(source_ips)
    if not raw_ips:
        return 0.0

    # Extract if dict items were provided
    ips = [
        item.get("src_ip", item.get("ip", str(item))) if isinstance(item, dict) else str(item)
        for item in raw_ips
    ]

    if weights is None:
        return distribution_entropy(ips)

    w_list = list(weights)
    if len(w_list) != len(ips):
        return distribution_entropy(ips)

    # Aggregate weights per IP
    ip_weights: Dict[str, float] = defaultdict(float)
    for ip, w in zip(ips, w_list):
        ip_weights[ip] += max(0.0, float(w))

    total_weight = sum(ip_weights.values())
    if total_weight <= 0.0:
        return 0.0

    entropy = 0.0
    for w in ip_weights.values():
        if w > 0:
            p = w / total_weight
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def destination_ip_entropy(
    dest_ips: Iterable[Any],
    weights: Optional[Iterable[float]] = None
) -> float:
    """Computes Shannon entropy of destination IP address distributions."""
    raw = list(dest_ips)
    ips = [
        item.get("dst_ip", item.get("ip", str(item))) if isinstance(item, dict) else str(item)
        for item in raw
    ]
    return source_ip_entropy(ips, weights=weights)


def destination_port_entropy(
    dest_ports: Iterable[Any],
    weights: Optional[Iterable[float]] = None
) -> float:
    """Computes Shannon entropy of destination port distributions."""
    raw = list(dest_ports)
    ports = [
        str(item.get("dst_port", item.get("port", str(item)))) if isinstance(item, dict) else str(item)
        for item in raw
    ]
    return source_ip_entropy(ports, weights=weights)


def calculate_distribution_metrics(
    items: Iterable[Any],
    weights: Optional[Iterable[float]] = None,
    key: Optional[str] = None
) -> Dict[str, Any]:
    """
    Calculates detailed distribution and concentration metrics across a network feature set:
    - unique_count
    - entropy
    - concentration (Herfindahl-Hirschman index sum(p_i^2))
    - top_item_percentage
    - top_5_percentage
    """
    raw_list = list(items)
    if not raw_list:
        return {
            "unique_count": 0,
            "entropy": 0.0,
            "concentration": 0.0,
            "herfindahl_index": 0.0,
            "top_1_ratio": 0.0,
            "top_item_percentage": 0.0,
            "top_5_percentage": 0.0,
        }

    if key:
        item_list = [
            it.get(key, str(it)) if isinstance(it, dict) else str(it)
            for it in raw_list
        ]
    else:
        item_list = [
            it.get("src_ip", str(it)) if isinstance(it, dict) else it
            for it in raw_list
        ]

    if weights is None:
        counts = Counter(item_list)
        total = float(len(item_list))
        freqs = [c / total for c in counts.values()]
    else:
        w_list = list(weights)
        agg: Dict[Any, float] = defaultdict(float)
        for it, w in zip(item_list, w_list):
            agg[it] += max(0.0, float(w))
        total = sum(agg.values())
        if total <= 0.0:
            return {
                "unique_count": len(agg),
                "entropy": 0.0,
                "concentration": 0.0,
                "herfindahl_index": 0.0,
                "top_1_ratio": 0.0,
                "top_item_percentage": 0.0,
                "top_5_percentage": 0.0,
            }
        freqs = [w / total for w in agg.values()]

    freqs.sort(reverse=True)
    entropy = -sum(p * math.log2(p) for p in freqs if p > 0)
    concentration = sum(p * p for p in freqs)
    top_1 = freqs[0] if freqs else 0.0
    top_5 = sum(freqs[:5]) if len(freqs) >= 5 else sum(freqs)

    return {
        "unique_count": len(freqs),
        "entropy": round(entropy, 4),
        "concentration": round(concentration, 4),
        "herfindahl_index": round(concentration, 4),
        "top_1_ratio": round(top_1, 4),
        "top_item_percentage": round(top_1 * 100.0, 2),
        "top_5_percentage": round(top_5 * 100.0, 2),
    }
