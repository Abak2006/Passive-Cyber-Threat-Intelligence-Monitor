"""
Adapter for BoT-IoT dataset.
Maps BoT-IoT flow statistics into standard features.
"""

from typing import Optional, Tuple
import pandas as pd
import numpy as np

from training.dataset_adapters.base_adapter import BaseDatasetAdapter


class BoTIoTAdapter(BaseDatasetAdapter):
    def load_and_transform(self, max_samples: Optional[int] = None) -> Tuple[pd.DataFrame, pd.Series]:
        if not self.dataset_path.exists():
            raise FileNotFoundError(f"BoT-IoT dataset not found at {self.dataset_path}")

        df = pd.read_csv(self.dataset_path, nrows=max_samples, low_memory=False)
        label_col = "attack" if "attack" in df.columns else "category"
        y = df[label_col].apply(lambda x: 0 if str(x) in ("0", "Normal") else 1)

        dur = df.get("dur", 1.0).replace(0, 0.001)
        pkts = df.get("pkts", 1)
        bytes_tot = df.get("bytes", 64)

        X = pd.DataFrame()
        X["packets_per_sec"] = (pkts / dur).replace([np.inf, -np.inf], 0)
        X["bytes_per_sec"] = (bytes_tot / dur).replace([np.inf, -np.inf], 0)
        X["syn_count"] = df.get("syn", 0)
        X["ack_count"] = df.get("ack", 0)
        X["syn_ack_ratio"] = (X["syn_count"] / (X["ack_count"] + 1))
        X["mean_packet_size"] = (bytes_tot / pkts).replace([np.inf, -np.inf], 0)

        return X, y
