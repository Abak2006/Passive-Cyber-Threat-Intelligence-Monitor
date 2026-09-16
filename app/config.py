"""
Configuration Loader for NTRO Cyber Threat Detection System.
Loads YAML settings with environment variable overrides and safe defaults.
"""

from pathlib import Path
from typing import Any, Dict, List
import yaml


class Config:
    def __init__(self, config_path: str = None):
        if config_path is None:
            # Default to configs/config.yaml relative to project root
            base_dir = Path(__file__).resolve().parent.parent
            default_path = base_dir / "configs" / "config.yaml"
            if default_path.exists():
                config_path = str(default_path)
            else:
                config_path = "configs/config.yaml"

        self.config_path = Path(config_path)
        self._raw_data = self._load()

    def _load(self) -> Dict[str, Any]:
        if not self.config_path.exists():
            return self._get_fallback_defaults()
        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
                return data or {}
        except Exception:
            return self._get_fallback_defaults()

    def get(self, key_path: str, default: Any = None) -> Any:
        keys = key_path.split(".")
        val = self._raw_data
        for k in keys:
            if isinstance(val, dict) and k in val:
                val = val[k]
            else:
                return default
        return val

    @property
    def system(self) -> Dict[str, Any]:
        return self._raw_data.get("system", {})

    @property
    def database_path(self) -> str:
        return self.get("system.database_path", "data/threats.db")

    @property
    def ingest(self) -> Dict[str, Any]:
        return self._raw_data.get("ingest", {})

    @property
    def detectors(self) -> Dict[str, Any]:
        return self._raw_data.get("detectors", {})

    @property
    def fusion(self) -> Dict[str, Any]:
        return self._raw_data.get("fusion", {})

    @staticmethod
    def _get_fallback_defaults() -> Dict[str, Any]:
        return {
            "system": {
                "environment": "passive_monitoring_enclave",
                "mode": "unidirectional_read_only",
                "zero_probe_enforced": True,
                "database_path": "data/threats.db",
                "log_level": "INFO",
            },
            "ingest": {
                "flow_timeout_sec": 15.0,
                "sliding_window_sec": 10.0,
                "sample_pcap_path": "data/sample/demo.pcap",
            },
            "detectors": {
                "ddos": {"enabled": True, "syn_rate_threshold": 50.0},
                "beaconing": {"enabled": True, "cv_threshold": 0.25},
                "dga": {"enabled": True, "entropy_threshold": 3.6},
                "dns_tunnel": {"enabled": True, "subdomain_entropy_threshold": 3.75},
                "encrypted": {"enabled": True, "outbound_inbound_ratio_threshold": 7.0},
                "recon": {"enabled": True, "vertical_scan_threshold": 8},
                "exfiltration": {"enabled": True, "outbound_inbound_byte_ratio": 6.0},
            },
            "fusion": {
                "correlation_window_sec": 25.0,
                "confidence_boost_multi_detector": 0.12,
            },
        }


# Singleton instance
_instance = None


def get_config(config_path: str = None) -> Config:
    global _instance
    if _instance is None or config_path is not None:
        _instance = Config(config_path)
    return _instance
