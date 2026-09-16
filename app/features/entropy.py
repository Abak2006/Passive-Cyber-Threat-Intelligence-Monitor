"""
Entropy calculation utilities for string lexical analysis and network distribution analysis.
"""

import math
from collections import Counter
from typing import Any, Dict, Iterable, List, Union


def shannon_entropy(data: Union[str, bytes]) -> float:
    """
    Calculate Shannon entropy of a string or byte sequence in bits per symbol.
    H(X) = - sum(p(x) * log2(p(x)))
    Higher entropy indicates more randomness (e.g., encrypted/compressed data or DGA domains).
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
    Calculate the entropy of a categorical distribution (e.g., unique source IPs or ports).
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
