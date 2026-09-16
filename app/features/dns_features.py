"""
DNS Passive Metadata Feature Extraction.
Extracts lexical, structural, and query distribution features without inspecting private payloads.
"""

import re
from typing import Any, Dict, List, Optional
from app.features.entropy import shannon_entropy

VOWELS = set("aeiou")
CONSONANTS = set("bcdfghjklmnpqrstvwxyz")


class DNSFeatureExtractor:
    """Extracts features for DGA detection and DNS Tunnelling detection."""

    @staticmethod
    def extract_lexical_features(domain: str) -> Dict[str, Any]:
        """
        Extracts structural and statistical lexical features from a domain name.
        Example domain: 'x7k29a8d91.malicious.net' or 'google.com'
        """
        clean_domain = domain.lower().strip().rstrip(".")
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
                "longest_label_len": 0,
                "subdomain_length": 0,
                "subdomain_entropy": 0.0,
                "max_consonant_cluster": 0,
            }

        labels = clean_domain.split(".")
        num_labels = len(labels)
        longest_label = max(labels, key=len) if labels else ""
        longest_label_len = len(longest_label)

        # Separate apex/TLD from subdomains if possible
        # e.g. 'c2beacon.sub1.example.com' -> subdomain = 'c2beacon.sub1'
        if num_labels > 2:
            subdomain = ".".join(labels[:-2])
            subdomain_len = len(subdomain)
            sub_entropy = shannon_entropy(subdomain)
        else:
            subdomain = ""
            subdomain_len = 0
            sub_entropy = 0.0

        # Entire domain statistics (excluding dots)
        chars_only = clean_domain.replace(".", "").replace("-", "")
        total_chars = max(1, len(chars_only))

        digits = sum(1 for c in chars_only if c.isdigit())
        vowels = sum(1 for c in chars_only if c in VOWELS)
        consonants = sum(1 for c in chars_only if c in CONSONANTS)
        unique_chars = len(set(chars_only))

        # Max consecutive consonants (consonant cluster)
        consonant_clusters = re.findall(r'[bcdfghjklmnpqrstvwxyz]+', clean_domain)
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
            "longest_label_len": longest_label_len,
            "subdomain_length": subdomain_len,
            "subdomain_entropy": round(sub_entropy, 4),
            "max_consonant_cluster": max_consonant_cluster,
        }

    @staticmethod
    def extract_dns_query_features(
        query_name: str,
        query_type: str = "A",
        response_code: int = 0
    ) -> Dict[str, Any]:
        """
        Extracts features from an observed passive DNS query event.
        Does not require access to DNS internal resolver state.
        """
        lexical = DNSFeatureExtractor.extract_lexical_features(query_name)
        qtype_upper = str(query_type).upper()

        is_txt = 1 if qtype_upper in ("TXT", "16") else 0
        is_null = 1 if qtype_upper in ("NULL", "10") else 0
        is_any = 1 if qtype_upper in ("ANY", "255") else 0

        features = {
            **lexical,
            "query_type": qtype_upper,
            "is_txt_record": is_txt,
            "is_null_record": is_null,
            "is_any_record": is_any,
            "response_code": response_code,
        }
        return features
