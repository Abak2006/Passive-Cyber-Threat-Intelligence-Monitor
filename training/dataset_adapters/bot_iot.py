"""
Adapter for BoT-IoT dataset.
Maps BoT-IoT flow statistics into standard features.
"""

from typing import Optional, Tuple
import pandas as pd
import numpy as np

from training.dataset_adapters.base_adapter import BaseDatasetAdapter


class BoTIoTAdapter(BaseDatasetAdapter):
    """
    Adapter for BoT-IoT dataset.
    Maps BoT-IoT flow statistics into standard features with strict
    unidirectional passive monitoring awareness.
    """

    def __init__(self, dataset_path: str, unidirectional_only: bool = True):
        super().__init__(dataset_path=dataset_path, unidirectional_only=unidirectional_only)

    def load_and_transform(self, max_samples: Optional[int] = None) -> Tuple[pd.DataFrame, pd.Series]:
        if not self.dataset_path.exists():
            raise FileNotFoundError(f"BoT-IoT dataset not found at {self.dataset_path}")

        df = pd.read_csv(self.dataset_path, nrows=max_samples, low_memory=False)
        label_col = "attack" if "attack" in df.columns else "category"
        y = df[label_col].apply(lambda x: 0 if str(x) in ("0", "Normal") else 1)

        dur = df.get("dur", 1.0).replace(0, 0.001)

        X = pd.DataFrame()
        if self.unidirectional_only:
            # When unidirectional, prefer source-only packets and bytes (spkts, sbytes)
            pkts = df.get("spkts", df.get("pkts", 1)).replace(0, 1)
            bytes_tot = df.get("sbytes", df.get("bytes", 64))
            X["packets_per_sec"] = (pkts / dur).replace([np.inf, -np.inf], 0).fillna(0)
            X["bytes_per_sec"] = (bytes_tot / dur).replace([np.inf, -np.inf], 0).fillna(0)
            X["syn_count"] = df.get("syn", 0)
            # In unidirectional egress tap, server-side ACKs are unobserved
            X["ack_count"] = df.get("ack", 0) if "ack" in df.columns else 0
            X["syn_ack_ratio"] = (X["syn_count"] / (X["ack_count"] + 1)).fillna(0)
            X["mean_packet_size"] = (bytes_tot / pkts).replace([np.inf, -np.inf], 0).fillna(0)
        else:
            pkts = df.get("pkts", 1).replace(0, 1)
            bytes_tot = df.get("bytes", 64)
            X["packets_per_sec"] = (pkts / dur).replace([np.inf, -np.inf], 0).fillna(0)
            X["bytes_per_sec"] = (bytes_tot / dur).replace([np.inf, -np.inf], 0).fillna(0)
            X["syn_count"] = df.get("syn", 0)
            X["ack_count"] = df.get("ack", 0)
            X["syn_ack_ratio"] = (X["syn_count"] / (X["ack_count"] + 1)).fillna(0)
            X["mean_packet_size"] = (bytes_tot / pkts).replace([np.inf, -np.inf], 0).fillna(0)

        return X, y
