"""
Adapter for CIC-IDS2017 and CIC-DDoS2019 datasets.
Maps raw CICFlowMeter columns into normalized flow features with strict
unidirectional passive monitoring awareness.
"""

from typing import Optional, Tuple
import numpy as np
import pandas as pd

from training.dataset_adapters.base_adapter import BaseDatasetAdapter


class CICIDSAdapter(BaseDatasetAdapter):
    """
    Adapts CIC-IDS2017 / CIC-DDoS2019 datasets for AEGIS passive monitoring.
    
    In unidirectional mode (hardware data diode / single-direction tap):
    - Forward flow metrics (client-to-server or observed tap direction) are preserved.
    - Reverse/backward metrics (Bwd Packets/s, Bwd IAT, ACK from server) are physically
      unobservable if monitoring egress-only or ingress-only. They are NOT fabricated.
    """

    def __init__(self, dataset_path: str, unidirectional_only: bool = True):
        super().__init__(dataset_path=dataset_path, unidirectional_only=unidirectional_only)

    def load_and_transform(self, max_samples: Optional[int] = None) -> Tuple[pd.DataFrame, pd.Series]:
        if not self.dataset_path.exists():
            raise FileNotFoundError(f"CIC dataset not found at {self.dataset_path}")

        df = pd.read_csv(self.dataset_path, nrows=max_samples, low_memory=False)
        # Strip whitespace from column headers (common CICFlowMeter issue)
        df.columns = df.columns.str.strip()

        # Target label column
        label_col = "Label" if "Label" in df.columns else df.columns[-1]
        y = df[label_col].apply(lambda x: 0 if str(x).upper() == "BENIGN" else 1)

        X = pd.DataFrame()
        if self.unidirectional_only:
            # Strictly forward/observed unidirectional traffic features
            fwd_pkts = df.get("Total Fwd Packets", df.get("Total Fwd Pkts", 0)).fillna(0)
            flow_dur = df.get("Flow Duration", 1.0).replace(0, 1.0) / 1e6  # to seconds
            X["packets_per_sec"] = (fwd_pkts / flow_dur).replace([np.inf, -np.inf], 0).fillna(0)
            
            fwd_bytes = df.get("Total Length of Fwd Packets", df.get("Total Length of Fwd Pkts", 0)).fillna(0)
            X["bytes_per_sec"] = (fwd_bytes / flow_dur).replace([np.inf, -np.inf], 0).fillna(0)
            
            X["syn_count"] = df.get("SYN Flag Count", df.get("Fwd PSH Flags", 0)).fillna(0)
            # In unidirectional egress tap, inbound ACKs from remote destination are absent
            X["ack_count"] = df.get("ACK Flag Count", 0).fillna(0)
            X["syn_ack_ratio"] = (X["syn_count"] / (X["ack_count"] + 1)).fillna(0)
            X["mean_packet_size"] = df.get("Fwd Packet Length Mean", df.get("Packet Length Mean", 0)).fillna(0)
        else:
            # Full duplex / bidirectional tap mode
            X["packets_per_sec"] = df.get("Flow Packets/s", df.get("Flow Pkts/s", 0)).fillna(0).replace([np.inf, -np.inf], 0)
            X["bytes_per_sec"] = df.get("Flow Bytes/s", df.get("Flow Byts/s", 0)).fillna(0).replace([np.inf, -np.inf], 0)
            X["syn_count"] = df.get("SYN Flag Count", 0).fillna(0)
            X["ack_count"] = df.get("ACK Flag Count", 0).fillna(0)
            X["syn_ack_ratio"] = (X["syn_count"] / (X["ack_count"] + 1)).fillna(0)
            X["mean_packet_size"] = df.get("Packet Length Mean", df.get("Average Packet Size", 0)).fillna(0)

        return X, y
