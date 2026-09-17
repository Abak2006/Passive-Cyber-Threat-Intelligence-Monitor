"""
Adapter for DNS datasets (e.g. CIC-Bell-DNS2021, DGA feeds, Alexa/Tranco top domains).
Extracts lexical features for training the DGA supervised model.
"""

from typing import Optional, Tuple
import pandas as pd
import numpy as np

from app.features.dns_features import DNSFeatureExtractor
from training.dataset_adapters.base_adapter import BaseDatasetAdapter


class DNSDatasetAdapter(BaseDatasetAdapter):
    """
    Adapter for DNS datasets (e.g. CIC-Bell-DNS2021, DGA feeds, Alexa/Tranco top domains).
    Extracts lexical features for training the DGA supervised model from passively
    observed query strings without active DNS resolution or server probing.
    """

    def __init__(self, dataset_path: str, unidirectional_only: bool = True):
        super().__init__(dataset_path=dataset_path, unidirectional_only=unidirectional_only)

    def load_and_transform(self, max_samples: Optional[int] = None) -> Tuple[pd.DataFrame, pd.Series]:
        if not self.dataset_path.exists():
            raise FileNotFoundError(f"DNS dataset not found at {self.dataset_path}")

        df = pd.read_csv(self.dataset_path, nrows=max_samples)
        domain_col = "domain" if "domain" in df.columns else df.columns[0]
        label_col = "label" if "label" in df.columns else df.columns[-1]

        y = df[label_col].apply(lambda x: 1 if str(x).lower() in ("1", "dga", "malicious") else 0)

        rows = []
        for dom in df[domain_col]:
            lex = DNSFeatureExtractor.extract_lexical_features(str(dom))
            rows.append({
                "length": lex["length"],
                "entropy": lex["entropy"],
                "digit_ratio": lex["digit_ratio"],
                "vowel_ratio": lex["vowel_ratio"],
                "consonant_ratio": lex["consonant_ratio"],
                "unique_char_ratio": lex["unique_char_ratio"],
                "max_consonant_cluster": lex["max_consonant_cluster"],
            })

        X = pd.DataFrame(rows)
        return X, y
