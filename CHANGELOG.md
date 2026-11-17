# Changelog

## 1.1.0

- **Incident-scoped alert deduplication.** The fusion engine now identifies incidents by victim (DDoS), by scanner (scans) or by unordered host pair (everything else) instead of by `(src, dst)`. A spoofed-source flood no longer produces one alert per forged source, and the two directions of one C2 conversation no longer alert twice. Demo PCAP: 109 → 17 alerts. The dedup cache is now pruned so it cannot grow without bound.
- **Packaging and `aegis` CLI.** `pyproject.toml` makes the project pip-installable and adds the `aegis` command with `replay`, `benchmark`, `train`, `serve` and `dashboard` subcommands.
- **CI.** GitHub Actions runs ruff, pytest and a demo-PCAP smoke test on Python 3.9, 3.11 and 3.13.
- **Cleanup.** Removed unused imports and variables, and a dict literal with duplicated keys in `flow_features.py` (behaviour unchanged: the later keys already won).
