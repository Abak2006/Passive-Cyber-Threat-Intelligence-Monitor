"""
Adapter for CIC-IDS2017 and CIC-DDoS2019 datasets.
Maps raw CICFlowMeter columns into normalized flow features.
"""

from typing import Optional, Tuple
import pandas as pd
import numpy as np

from training.dataset_adapters.base_adapter import BaseDatasetAdapter


class CICIDSAdapter(BaseDatasetAdapter):
    def load_and_transform(self, max_samples: Optional[int] = None) -> Tuple[pd.DataFrame, pd.Series]:
        if not self.dataset_path.exists():
            raise FileNotFoundError(f"CIC dataset not found at {self.dataset_path}")

        df = pd.read_csv(self.dataset_path, nrows=max_samples, low_memory=False)
        # Strip whitespace from column headers (common CICFlowMeter issue)
        df.columns = df.columns.str.strip()

        # Target label column
        label_col = "Label" if "Label" in df.columns else df.columns[-1]
        y = df[label_col].apply(lambda x: 0 if str(x).upper() == "BENIGN" else 1)

        # Standardized feature mapping
        X = pd.DataFrame()
        X["packets_per_sec"] = df.get("Flow Packets/s", df.get("Flow Pkts/s", 0)).fillna(0).replace([np.inf, -np.inf], 0)
        X["bytes_per_sec"] = df.get("Flow Bytes/s", df.get("Flow Byts/s", 0)).fillna(0).replace([np.inf, -np.inf], 0)
        X["syn_count"] = df.get("SYN Flag Count", 0).fillna(0)
        X["ack_count"] = df.get("ACK Flag Count", 0).fillna(0)
        X["syn_ack_ratio"] = (X["syn_count"] / (X["ack_count"] + 1)).fillna(0)
        X["mean_packet_size"] = df.get("Packet Length Mean", df.get("Average Packet Size", 0)).fillna(0)

        return X, y
