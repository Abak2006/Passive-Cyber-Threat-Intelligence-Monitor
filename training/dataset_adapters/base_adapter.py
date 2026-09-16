"""
Base Dataset Adapter Interface.
Defines common interface for adapting public cybersecurity datasets
(e.g., CIC-IDS2017, BoT-IoT, CIC-Bell-DNS2021) into normalized feature vectors.
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Tuple, Optional
import pandas as pd
import numpy as np


class BaseDatasetAdapter(ABC):
    def __init__(self, dataset_path: str):
        self.dataset_path = Path(dataset_path)

    @abstractmethod
    def load_and_transform(self, max_samples: Optional[int] = None) -> Tuple[pd.DataFrame, pd.Series]:
        """
        Loads dataset CSV and returns:
        - X (pd.DataFrame): standardized feature matrix
        - y (pd.Series): binary or multi-class label (1 = malicious, 0 = benign)
        """
        pass
