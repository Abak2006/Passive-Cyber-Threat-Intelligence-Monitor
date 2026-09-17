"""
DNS Passive Metadata Feature Extraction & Rolling Anomaly Engine.
Extracts lexical, structural, and query distribution features without inspecting private payloads.
Tracks rolling DNS record-type distributions (A, AAAA, TXT, CNAME, NULL) to detect covert channels.
"""

from collections import Counter, deque
import re
import time
from typing import Any, Dict, List, Optional, Tuple, Union
import numpy as np
from app.features.entropy import shannon_entropy

VOWELS = set("aeiou")
CONSONANTS = set("bcdfghjklmnpqrstvwxyz")

DNS_TYPE_MAP: Dict[int, str] = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    10: "NULL",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    255: "ANY",
}

DNS_NAME_TO_TYPE: Dict[str, int] = {v: k for k, v in DNS_TYPE_MAP.items()}


def normalize_dns_type(qtype: Union[int, str, None]) -> Tuple[int, str]:
    """Resolves DNS query type to (numeric_code, standard_name)."""
    if qtype is None:
        return 1, "A"
    if isinstance(qtype, int):
        name = DNS_TYPE_MAP.get(qtype, f"TYPE{qtype}")
        return qtype, name
    qstr = str(qtype).upper().strip()
    if qstr.isdigit():
        code = int(qstr)
        return code, DNS_TYPE_MAP.get(code, f"TYPE{code}")
    code = DNS_NAME_TO_TYPE.get(qstr, 0)
    return code, qstr


class DNSFeatureExtractor:
    """Extracts lexical and structural features for DGA detection and DNS Tunnelling detection."""

    @staticmethod
    def extract_lexical_features(domain: str) -> Dict[str, Any]:
        """
        Extracts structural and statistical lexical features from a domain name.
        Example: 'x7k29a8d91.tunnel.example.com' or 'google.com'
        """
        clean_domain = str(domain).lower().strip().rstrip(".")
        if not clean_domain:
            return {
                "domain": "",
                "length": 0,
                "entropy": 0.0,
                "digit_ratio": 0.0,
                "vowel_ratio": 0.0,
                "consonant_ratio": 0.0,
                "unique_char_ratio": 0.0,
                "num_labels": 0,
                "domain_depth": 0,
                "longest_label_len": 0,
                "subdomain_length": 0,
                "subdomain_entropy": 0.0,
                "max_consonant_cluster": 0,
            }

        labels = clean_domain.split(".")
        num_labels = len(labels)
        domain_depth = num_labels
        longest_label = max(labels, key=len) if labels else ""
        longest_label_len = len(longest_label)

        # Separate apex/TLD from subdomains
        if num_labels > 2:
            subdomain = ".".join(labels[:-2])
            subdomain_len = len(subdomain)
            sub_entropy = shannon_entropy(subdomain)
        else:
            subdomain = ""
            subdomain_len = 0
            sub_entropy = 0.0

        chars_only = clean_domain.replace(".", "").replace("-", "")
        total_chars = max(1, len(chars_only))

        digits = sum(1 for c in chars_only if c.isdigit())
        vowels = sum(1 for c in chars_only if c in VOWELS)
        consonants = sum(1 for c in chars_only if c in CONSONANTS)
        unique_chars = len(set(chars_only))

        consonant_clusters = re.findall(r"[bcdfghjklmnpqrstvwxyz]+", clean_domain)
        max_consonant_cluster = max([len(c) for c in consonant_clusters], default=0)

        entropy = shannon_entropy(clean_domain)

        return {
            "domain": clean_domain,
            "length": len(clean_domain),
            "entropy": round(entropy, 4),
            "digit_ratio": round(digits / total_chars, 4),
            "vowel_ratio": round(vowels / total_chars, 4),
            "consonant_ratio": round(consonants / total_chars, 4),
            "unique_char_ratio": round(unique_chars / total_chars, 4),
            "num_labels": num_labels,
            "domain_depth": domain_depth,
            "longest_label_len": longest_label_len,
            "subdomain_length": subdomain_len,
            "subdomain_entropy": round(sub_entropy, 4),
            "max_consonant_cluster": max_consonant_cluster,
        }

    @staticmethod
    def extract_dns_query_features(
        query_name: str,
        query_type: Union[int, str] = "A",
        response_code: int = 0
    ) -> Dict[str, Any]:
        """
        Extracts features from an observed passive DNS query event.
        """
        lexical = DNSFeatureExtractor.extract_lexical_features(query_name)
        type_code, type_name = normalize_dns_type(query_type)

        is_txt = 1 if type_name == "TXT" else 0
        is_null = 1 if type_name == "NULL" else 0
        is_cname = 1 if type_name == "CNAME" else 0
        is_any = 1 if type_name == "ANY" else 0

        # NXDOMAIN in standard DNS is RCODE 3
        is_nxdomain = 1 if response_code == 3 else 0

        features = {
            **lexical,
            "query_type_code": type_code,
            "query_type_name": type_name,
            "is_txt_query": is_txt,
            "is_null_query": is_null,
            "is_cname_query": is_cname,
            "is_any_query": is_any,
            "response_code": response_code,
            "is_nxdomain": is_nxdomain,
        }
        return features


class DNSRollingStats:
    """
    Sliding-window statistical analyzer for passive DNS query streams.
    Tracks record-type concentrations, query frequencies, and subdomain distributions per host/apex.
    """

    def __init__(self, window_sec: float = 30.0, window_size: Optional[int] = None):
        self.window_sec = window_sec
        self.window_size = window_size
        self.history: deque = deque()  # (timestamp, query_name, type_name, response_code)

    def record_query(
        self,
        query_name: str,
        query_type: Union[int, str] = "A",
        timestamp: Optional[float] = None,
        response_code: int = 0,
        record_type: Optional[Union[int, str]] = None
    ):
        ts = timestamp or time.time()
        effective_type = record_type if record_type is not None else query_type
        _, type_name = normalize_dns_type(effective_type)
        self.history.append((ts, query_name, type_name, response_code))
        self._prune(ts)

    def _prune(self, current_time: float):
        if self.window_size is not None and len(self.history) > self.window_size:
            while len(self.history) > self.window_size:
                self.history.popleft()
        cutoff = current_time - self.window_sec
        while self.history and self.history[0][0] < cutoff and (self.window_size is None or len(self.history) > self.window_size):
            self.history.popleft()

    def get_distribution(self, current_time: Optional[float] = None) -> Dict[str, Any]:
        """Convenience alias for get_rolling_metrics."""
        return self.get_rolling_metrics(current_time=current_time)

    def get_rolling_metrics(self, current_time: Optional[float] = None) -> Dict[str, Any]:
        now = current_time or time.time()
        self._prune(now)

        total = len(self.history)
        if total == 0:
            return {
                "total_queries": 0,
                "unique_queries": 0,
                "query_rate": 0.0,
                "record_type_distribution": {},
                "record_types": [],
                "txt_ratio": 0.0,
                "null_ratio": 0.0,
                "cname_ratio": 0.0,
                "a_aaaa_ratio": 0.0,
                "nxdomain_ratio": 0.0,
                "mean_subdomain_entropy": 0.0,
                "max_subdomain_entropy": 0.0,
                "max_subdomain_length": 0,
            }

        duration = max(0.5, self.window_sec)
        query_rate = total / duration

        query_names = [item[1] for item in self.history]
        type_names = [item[2] for item in self.history]
        rcodes = [item[3] for item in self.history]

        unique_queries = len(set(query_names))
        type_counts = Counter(type_names)

        dist = {k: round(v / total, 4) for k, v in type_counts.items()}
        txt_ratio = dist.get("TXT", 0.0)
        null_ratio = dist.get("NULL", 0.0)
        cname_ratio = dist.get("CNAME", 0.0)
        a_count = type_counts.get("A", 0)
        aaaa_count = type_counts.get("AAAA", 0)
        a_aaaa_ratio = round((a_count + aaaa_count) / total, 4)

        nxdomain_count = sum(1 for r in rcodes if r == 3)
        nxdomain_ratio = round(nxdomain_count / total, 4)

        sub_entropies = []
        sub_lens = []
        for q in query_names:
            lex = DNSFeatureExtractor.extract_lexical_features(q)
            if lex["subdomain_length"] > 0:
                sub_entropies.append(lex["subdomain_entropy"])
                sub_lens.append(lex["subdomain_length"])

        return {
            "total_queries": total,
            "unique_queries": unique_queries,
            "query_rate": round(query_rate, 2),
            "record_type_distribution": dist,
            "record_types": list(type_counts.keys()),
            "txt_ratio": txt_ratio,
            "null_ratio": null_ratio,
            "cname_ratio": cname_ratio,
            "a_aaaa_ratio": a_aaaa_ratio,
            "nxdomain_ratio": nxdomain_ratio,
            "mean_subdomain_entropy": round(float(np.mean(sub_entropies)), 4) if sub_entropies else 0.0,
            "max_subdomain_entropy": round(float(np.max(sub_entropies)), 4) if sub_entropies else 0.0,
            "max_subdomain_length": max(sub_lens) if sub_lens else 0,
        }
