"""
Adversarial Beacon Benchmark Suite (AEGIS v2.2 Red-Team Validation).
Comprehensive evaluation of timing evasion, low-and-slow C2, randomized jitter,
benign hard negatives, adversarial escalation, and multi-signal threat fusion across
38 distinct benchmark scenarios (A through AL):

Part 1: Original AEGIS v2.1 Scenarios (A - T):
  Timing-Only Baseline Scenarios:
    A. Perfect periodic beacon (0% jitter)
    B. 10% jitter (mild random jitter)
    C. 20% jitter (moderate random jitter)
    D. 40% jitter (heavy random jitter)
    E. Structured / correlated jitter (e.g. alternating delays / lag-2 periodicity)
    F. Random jitter (uniform wide spread timing)
    G. Legitimate periodic polling (e.g. NTP/DNS to benign public infrastructure)
    H. Legitimate high-frequency traffic (bursty Poisson web browsing)
    I. Beacon + repeated destination (C2 persistence)
    J. Beacon + suspicious DNS behavior (DGA / tunnel domain)
    K. Beacon + suspicious TLS/QUIC metadata (Cobalt Strike JA3 / QUIC)

  Low-and-Slow Accumulation Scenarios:
    L. Low-and-slow beacon (60s intervals, steady persistence)
    M. Low-and-slow beacon + 20% jitter (60s intervals with jitter)
    N. Low-and-slow beacon + high repeated destination concentration
    O. Low-and-slow beacon + suspicious DNS context
    P. Low-and-slow beacon + suspicious TLS JA3 context

  Randomized Jitter + Independent Signal Fusion Scenarios:
    Q. Randomized jitter + DGA domain query
    R. Randomized jitter + Suspicious TLS JA3 fingerprint
    S. Randomized jitter + High destination persistence
    T. Randomized jitter + DGA + Suspicious TLS (Full Multi-Signal)

Part 2: Benign Hard Negatives (U - AD):
  Periodic, low-CV, high-persistence, and structured benign traffic deliberately
  resembling C2 timing without attack payloads or suspicious protocol indicators:
    U. Legitimate periodic REST API polling (cloud endpoint, standard HTTPS)
    V. Legitimate DNS recursive resolver cache refresh (regular 30s intervals)
    W. Legitimate NTP network time synchronization client (UDP 123, 64s poll)
    X. Legitimate load-balancer TCP health check probe (5s interval, low variance)
    Y. Legitimate database connection pool keepalive (TCP 3306/5432, 15s interval)
    Z. Legitimate cloud telemetry agent check-in (AWS/Azure endpoint, 30s interval)
    AA. Legitimate TLS persistent keepalive (valid SNI, standard browser ciphers)
    AB. Legitimate HTTP/3 QUIC connection (UDP 443, standard CDN, variable packet sizes)
    AC. Legitimate low-and-slow business application (infrequent 90s batch check-in)
    AD. Legitimate variable-jitter client polling (exponential backoff 5s-25s)

Part 3: Adversarial Escalation & Boundary Mapping (AE - AL):
  Progressively evasive attacker strategies to empirically map detection limits:
    AE. 60% randomized timing jitter
    AF. 80% randomized timing jitter
    AG. 100% randomized timing jitter (complete interval entropy)
    AH. Rapid destination IP rotation (attacker rotates IPs every connection)
    AI. Progressive period drift (intervals linearly drifting from 10s to 45s)
    AJ. Randomized jitter + destination IP rotation
    AK. Randomized jitter + progressive period drift
    AL. Low-and-slow (60s) + destination IP rotation

Features:
- Pure observable features provided to detector (zero label leakage)
- Continuous threat score tracking for all trials for ROC-AUC / PR-AUC calculation
- Confidence distribution percentiles (mean, median, std, min, max, P25, P75, P95)
- Outcome states: Detected, Partially Detected, Unknown Anomaly, Insufficient Evidence, Missed
- Threshold sensitivity analysis (0.50, 0.60, 0.70, 0.80, 0.90)
- Multi-seed cross validation (--seed, --seeds) with mean +/- std statistics
"""

import argparse
import json
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional, Tuple
import numpy as np
from sklearn.metrics import average_precision_score, precision_recall_curve, roc_auc_score

from app.detectors.beaconing import BeaconingDetector
from app.detectors.dga import DGADetector
from app.detectors.encrypted import EncryptedTrafficDetector
from app.features.timing_features import compute_advanced_timing_stats
from app.fusion.threat_fusion import ThreatFusionEngine


def generate_scenario_timestamps(
    scenario_type: str,
    base_interval: float = 10.0,
    count: int = 15,
    seed: int = 42
) -> Tuple[List[float], Dict[str, Any]]:
    """
    Generates timestamps and metadata context for a given scenario.
    Returns (timestamps, meta_dict).
    NOTE: Generator metadata (is_attack, label, scenario) is used strictly by the
    evaluation harness for ground truth and is NEVER passed into feature extractors or detectors.
    """
    rng = np.random.RandomState(seed)
    start_time = 100.0

    # -------------------------------------------------------------
    # 1. ORIGINAL AEGIS v2.1 SCENARIOS (A - T)
    # -------------------------------------------------------------
    if scenario_type == "A_PERFECT_PERIODIC":
        iats = [base_interval] * (count - 1)
        meta = {"dst_ip": "198.51.100.22", "dst_port": 8443, "is_attack": True, "label": "A. Beacon (0% Jitter)"}

    elif scenario_type == "B_JITTER_10":
        iats = [base_interval * (1.0 + rng.uniform(-0.10, 0.10)) for _ in range(count - 1)]
        meta = {"dst_ip": "198.51.100.23", "dst_port": 8443, "is_attack": True, "label": "B. Beacon (10% Jitter)"}

    elif scenario_type == "C_JITTER_20":
        iats = [base_interval * (1.0 + rng.uniform(-0.20, 0.20)) for _ in range(count - 1)]
        meta = {"dst_ip": "198.51.100.24", "dst_port": 8443, "is_attack": True, "label": "C. Beacon (20% Jitter)"}

    elif scenario_type == "D_JITTER_40":
        iats = [base_interval * (1.0 + rng.uniform(-0.40, 0.40)) for _ in range(count - 1)]
        meta = {"dst_ip": "198.51.100.25", "dst_port": 8443, "is_attack": True, "label": "D. Beacon (40% Jitter)"}

    elif scenario_type == "E_STRUCTURED_JITTER":
        iats = [8.0 if i % 2 == 0 else 14.0 for i in range(count - 1)]
        meta = {"dst_ip": "198.51.100.26", "dst_port": 8443, "is_attack": True, "label": "E. Structured Jitter (Lag-2)"}

    elif scenario_type == "F_RANDOM_JITTER":
        iats = list(rng.exponential(scale=base_interval, size=count - 1) + 1.0)
        meta = {"dst_ip": "198.51.100.27", "dst_port": 8443, "is_attack": True, "label": "F. Heavy Random Dispersion"}

    elif scenario_type == "G_LEGITIMATE_PERIODIC_POLL":
        iats = [base_interval * (1.0 + rng.uniform(-0.05, 0.05)) for _ in range(count - 1)]
        meta = {"dst_ip": "8.8.8.8", "dst_port": 53, "is_attack": False, "label": "G. Benign DNS Poll (8.8.8.8)"}

    elif scenario_type == "H_LEGITIMATE_BURSTY_WEB":
        iats = [0.05, 0.02, 0.1, 0.03, 5.0, 0.04, 0.02, 0.08, 12.0, 0.05, 0.02, 0.06, 0.04, 8.0]
        meta = {
            "dst_ip": "142.250.190.46",
            "dst_port": 443,
            "forward_bytes": 2000,
            "backward_bytes": 15000,
            "dst_concentration": 0.15,
            "destination_count": 15,
            "packet_lengths": [100, 1400, 1400, 1400, 80, 1400, 1400, 1400, 80],
            "tls_metadata": {"has_sni": True, "tls_version": "0x0304"},
            "is_attack": False,
            "label": "H. Benign Bursty Web Traffic"
        }

    elif scenario_type == "I_BEACON_REPEATED_DEST":
        iats = [base_interval * (1.0 + rng.uniform(-0.15, 0.15)) for _ in range(count - 1)]
        meta = {
            "dst_ip": "198.51.100.99",
            "dst_port": 443,
            "dst_concentration": 0.95,
            "destination_count": 1,
            "is_attack": True,
            "label": "I. Beacon + Dest Persistence"
        }

    elif scenario_type == "J_BEACON_SUSPICIOUS_DNS":
        iats = [base_interval * (1.0 + rng.uniform(-0.15, 0.15)) for _ in range(count - 1)]
        meta = {
            "dst_ip": "198.51.100.77",
            "dst_port": 53,
            "dns_queries": ["x9k2zq8w110mnv.cc"],
            "is_attack": True,
            "label": "J. Beacon + DGA Domain"
        }

    elif scenario_type == "K_BEACON_SUSPICIOUS_TLS":
        iats = [base_interval * (1.0 + rng.uniform(-0.15, 0.15)) for _ in range(count - 1)]
        meta = {
            "dst_ip": "198.51.100.88",
            "dst_port": 443,
            "tls_metadata": {
                "ja3_hash": "e7d705a3286e19ea42f587b344ee6865",
                "ja4_fingerprint": "t12i030300_e7d705a3286e",
                "has_sni": False,
            },
            "is_attack": True,
            "label": "K. Beacon + JA3 Fingerprint"
        }

    elif scenario_type == "L_LOW_AND_SLOW_BEACON":
        iats = [60.0] * (count - 1)
        meta = {
            "dst_ip": "198.51.100.31",
            "dst_port": 443,
            "dst_concentration": 0.90,
            "destination_count": 1,
            "is_attack": True,
            "label": "L. Low-and-Slow (60s interval)"
        }

    elif scenario_type == "M_LOW_AND_SLOW_BEACON_JITTER":
        iats = [60.0 * (1.0 + rng.uniform(-0.20, 0.20)) for _ in range(count - 1)]
        meta = {
            "dst_ip": "198.51.100.32",
            "dst_port": 443,
            "dst_concentration": 0.85,
            "destination_count": 1,
            "is_attack": True,
            "label": "M. Low-and-Slow + 20% Jitter"
        }

    elif scenario_type == "N_LOW_AND_SLOW_BEACON_REPEATED_DEST":
        iats = [60.0 * (1.0 + rng.uniform(-0.25, 0.25)) for _ in range(count - 1)]
        meta = {
            "dst_ip": "198.51.100.33",
            "dst_port": 443,
            "dst_concentration": 1.0,
            "destination_count": 1,
            "is_attack": True,
            "label": "N. Low-and-Slow + Max Dest Concentration"
        }

    elif scenario_type == "O_LOW_AND_SLOW_BEACON_SUSPICIOUS_DNS":
        iats = [60.0 * (1.0 + rng.uniform(-0.20, 0.20)) for _ in range(count - 1)]
        meta = {
            "dst_ip": "198.51.100.34",
            "dst_port": 53,
            "dns_queries": ["c2-slow-heartbeat-node99.biz"],
            "dst_concentration": 0.90,
            "is_attack": True,
            "label": "O. Low-and-Slow + DGA Context"
        }

    elif scenario_type == "P_LOW_AND_SLOW_BEACON_SUSPICIOUS_TLS":
        iats = [60.0 * (1.0 + rng.uniform(-0.20, 0.20)) for _ in range(count - 1)]
        meta = {
            "dst_ip": "198.51.100.35",
            "dst_port": 443,
            "tls_metadata": {
                "ja3_hash": "e7d705a3286e19ea42f587b344ee6865",
                "has_sni": False,
            },
            "dst_concentration": 0.90,
            "is_attack": True,
            "label": "P. Low-and-Slow + JA3 Fingerprint"
        }

    elif scenario_type == "Q_RANDOM_JITTER_PLUS_DGA":
        iats = list(rng.exponential(scale=base_interval, size=count - 1) + 1.0)
        meta = {
            "dst_ip": "198.51.100.41",
            "dst_port": 53,
            "dns_queries": ["x9k2zq8w110mnv.cc"],
            "dst_concentration": 0.85,
            "is_attack": True,
            "label": "Q. Random Jitter + DGA Domain"
        }

    elif scenario_type == "R_RANDOM_JITTER_PLUS_SUSPICIOUS_TLS":
        iats = list(rng.exponential(scale=base_interval, size=count - 1) + 1.0)
        meta = {
            "dst_ip": "198.51.100.42",
            "dst_port": 443,
            "tls_metadata": {
                "ja3_hash": "e7d705a3286e19ea42f587b344ee6865",
                "has_sni": False,
                "ciphers_count": 3,
            },
            "packet_lengths": [120, 125, 122, 128, 121, 124],
            "dst_concentration": 0.85,
            "is_attack": True,
            "label": "R. Random Jitter + JA3 Metadata"
        }

    elif scenario_type == "S_RANDOM_JITTER_PLUS_DESTINATION_PERSISTENCE":
        iats = list(rng.exponential(scale=base_interval, size=count - 1) + 1.0)
        meta = {
            "dst_ip": "198.51.100.43",
            "dst_port": 443,
            "dst_concentration": 0.98,
            "destination_count": 1,
            "is_attack": True,
            "label": "S. Random Jitter + Max Persistence"
        }

    elif scenario_type == "T_RANDOM_JITTER_PLUS_DGA_PLUS_TLS":
        iats = list(rng.exponential(scale=base_interval, size=count - 1) + 1.0)
        meta = {
            "dst_ip": "198.51.100.44",
            "dst_port": 443,
            "dns_queries": ["x9k2zq8w110mnv.cc"],
            "tls_metadata": {
                "ja3_hash": "e7d705a3286e19ea42f587b344ee6865",
                "has_sni": False,
            },
            "dst_concentration": 0.95,
            "is_attack": True,
            "label": "T. Random Jitter + DGA + JA3"
        }

    # -------------------------------------------------------------
    # 2. BENIGN HARD NEGATIVES (U - AD)
    # -------------------------------------------------------------
    elif scenario_type == "U_LEGITIMATE_PERIODIC_API_POLLING":
        # Rest API polling every 10s with +/-2% timer variance to internal enterprise service
        iats = [base_interval * (1.0 + rng.uniform(-0.02, 0.02)) for _ in range(count - 1)]
        meta = {
            "dst_ip": "10.100.5.50",
            "dst_port": 443,
            "tls_metadata": {
                "ja3_hash": "cd08e31494f9531f560d64c695473da9",  # Standard Python/Requests TLS
                "has_sni": True,
                "server_name": "api.internal.corp",
                "ciphers_count": 18,
            },
            "packet_lengths": [180, 850, 180, 860, 180, 850],
            "forward_bytes": 1200,
            "backward_bytes": 8000,
            "dst_concentration": 0.90,
            "destination_count": 3,
            "is_attack": False,
            "label": "U. Benign API Polling (api.internal.corp)"
        }

    elif scenario_type == "V_LEGITIMATE_DNS_CACHE_REFRESH":
        # Recursive resolver cache refresh every 30s
        iats = [30.0 * (1.0 + rng.uniform(-0.03, 0.03)) for _ in range(count - 1)]
        meta = {
            "dst_ip": "1.1.1.1",  # Cloudflare public resolver
            "dst_port": 53,
            "dns_queries": ["auth.microsoft.com"],
            "dst_concentration": 0.85,
            "destination_count": 2,
            "is_attack": False,
            "label": "V. Benign DNS Cache Refresh (1.1.1.1)"
        }

    elif scenario_type == "W_LEGITIMATE_NTP_CLIENT":
        # NTP time sync every 64s
        iats = [64.0 * (1.0 + rng.uniform(-0.01, 0.01)) for _ in range(count - 1)]
        meta = {
            "dst_ip": "192.168.1.1",  # Internal NTP server / Gateway
            "dst_port": 123,
            "protocol": "UDP",
            "forward_bytes": 48 * count,
            "backward_bytes": 48 * count,
            "dst_concentration": 0.95,
            "destination_count": 1,
            "is_attack": False,
            "label": "W. Benign NTP Client (UDP 123)"
        }

    elif scenario_type == "X_LEGITIMATE_HEALTH_CHECK":
        # Load balancer HTTP health check probe every 5s
        iats = [5.0 * (1.0 + rng.uniform(-0.01, 0.01)) for _ in range(count - 1)]
        meta = {
            "dst_ip": "10.0.10.20",
            "dst_port": 80,
            "forward_bytes": 150 * count,
            "backward_bytes": 220 * count,
            "dst_concentration": 0.92,
            "destination_count": 2,
            "is_attack": False,
            "label": "X. Benign Health Check (Port 80)"
        }

    elif scenario_type == "Y_LEGITIMATE_DATABASE_HEARTBEAT":
        # Database pool keepalive query every 15s
        iats = [15.0 * (1.0 + rng.uniform(-0.02, 0.02)) for _ in range(count - 1)]
        meta = {
            "dst_ip": "10.0.50.5",
            "dst_port": 5432,  # PostgreSQL
            "forward_bytes": 80 * count,
            "backward_bytes": 80 * count,
            "dst_concentration": 0.95,
            "destination_count": 1,
            "is_attack": False,
            "label": "Y. Benign DB Heartbeat (TCP 5432)"
        }

    elif scenario_type == "Z_LEGITIMATE_CLOUD_SERVICE_POLLING":
        # AWS SSM / CloudWatch agent telemetry push every 30s
        iats = [30.0 * (1.0 + rng.uniform(-0.04, 0.04)) for _ in range(count - 1)]
        meta = {
            "dst_ip": "52.94.76.1",  # AWS IP
            "dst_port": 443,
            "tls_metadata": {
                "ja3_hash": "b32309a26951912be7dba376398abc11",  # Generic TLS agent
                "has_sni": True,
                "server_name": "monitoring.us-east-1.amazonaws.com",
                "ciphers_count": 22,
            },
            "forward_bytes": 4500,
            "backward_bytes": 1200,
            "dst_concentration": 0.88,
            "destination_count": 3,
            "is_attack": False,
            "label": "Z. Benign Cloud Polling (AWS CloudWatch)"
        }

    elif scenario_type == "AA_LEGITIMATE_TLS_KEEPALIVE":
        # Browser persistent keepalive to CDN
        iats = [20.0 * (1.0 + rng.uniform(-0.05, 0.05)) for _ in range(count - 1)]
        meta = {
            "dst_ip": "104.16.132.229",  # Cloudflare CDN
            "dst_port": 443,
            "tls_metadata": {
                "ja3_hash": "771d4e55331c5369712331a4e3f229f2",  # Standard Chrome JA3
                "has_sni": True,
                "server_name": "static.cloudflare.com",
                "ciphers_count": 16,
            },
            "forward_bytes": 500,
            "backward_bytes": 3500,
            "dst_concentration": 0.70,
            "destination_count": 5,
            "is_attack": False,
            "label": "AA. Benign TLS Keepalive (Chrome CDN)"
        }

    elif scenario_type == "AB_LEGITIMATE_QUIC_CONNECTIONS":
        # Legitimate Google HTTP/3 QUIC stream
        iats = [12.0 * (1.0 + rng.uniform(-0.08, 0.08)) for _ in range(count - 1)]
        meta = {
            "dst_ip": "142.250.190.78",
            "dst_port": 443,
            "protocol": "UDP",
            "quic_metadata": {
                "quic_detected": True,
                "version": "0x00000001",
                "is_initial": False,
            },
            "packet_lengths": [1200, 1350, 450, 1280, 800, 1420],  # Variable packet lengths
            "forward_bytes": 1200,
            "backward_bytes": 18000,
            "dst_concentration": 0.65,
            "destination_count": 6,
            "is_attack": False,
            "label": "AB. Benign QUIC Traffic (Google HTTP/3)"
        }

    elif scenario_type == "AC_LEGITIMATE_LOW_AND_SLOW_APPLICATION":
        # Legitimate ERP sync batch query every 90s
        iats = [90.0 * (1.0 + rng.uniform(-0.02, 0.02)) for _ in range(count - 1)]
        meta = {
            "dst_ip": "10.20.30.40",
            "dst_port": 443,
            "tls_metadata": {
                "ja3_hash": "84c8a2b535d8d47b744d0ec36f2f9b1c",
                "has_sni": True,
                "server_name": "erp-sync.corp.local",
                "ciphers_count": 15,
            },
            "forward_bytes": 8000,
            "backward_bytes": 25000,
            "dst_concentration": 0.92,
            "destination_count": 2,
            "is_attack": False,
            "label": "AC. Benign Low & Slow (ERP Sync 90s)"
        }

    elif scenario_type == "AD_LEGITIMATE_VARIABLE_JITTER_POLLING":
        # Mobile app push notification poll with exponential jitter (5s - 25s)
        iats = list(rng.uniform(5.0, 25.0, size=count - 1))
        meta = {
            "dst_ip": "17.57.144.80",  # Apple Push Gateway
            "dst_port": 5223,
            "tls_metadata": {
                "ja3_hash": "4a71d2b8344e45d6a89c891f1a5b8e99",
                "has_sni": True,
                "server_name": "courier.push.apple.com",
            },
            "forward_bytes": 350,
            "backward_bytes": 450,
            "dst_concentration": 0.85,
            "destination_count": 3,
            "is_attack": False,
            "label": "AD. Benign Variable Jitter Polling (APNs)"
        }

    # -------------------------------------------------------------
    # 3. ADVERSARIAL ESCALATION & BOUNDARY MAPPING (AE - AL)
    # -------------------------------------------------------------
    elif scenario_type == "AE_RANDOMIZED_JITTER_60":
        # 60% random jitter on base 10s interval
        iats = [base_interval * (1.0 + rng.uniform(-0.60, 0.60)) for _ in range(count - 1)]
        meta = {"dst_ip": "198.51.100.101", "dst_port": 8443, "is_attack": True, "label": "AE. Beacon (60% Jitter)"}

    elif scenario_type == "AF_RANDOMIZED_JITTER_80":
        # 80% random jitter on base 10s interval
        iats = [base_interval * (1.0 + rng.uniform(-0.80, 0.80)) for _ in range(count - 1)]
        meta = {"dst_ip": "198.51.100.102", "dst_port": 8443, "is_attack": True, "label": "AF. Beacon (80% Jitter)"}

    elif scenario_type == "AG_RANDOMIZED_JITTER_100":
        # 100% random jitter (range 0.1s to 20s)
        iats = [base_interval * (1.0 + rng.uniform(-0.95, 1.05)) for _ in range(count - 1)]
        meta = {"dst_ip": "198.51.100.103", "dst_port": 8443, "is_attack": True, "label": "AG. Beacon (100% Jitter)"}

    elif scenario_type == "AH_DESTINATION_ROTATION":
        # Periodic 10s interval, but attacker rotates destination IP per connection
        iats = [base_interval] * (count - 1)
        rot_idx = rng.randint(1, 250)
        meta = {
            "dst_ip": f"198.51.100.{rot_idx}",
            "dst_port": 8443,
            "dst_concentration": 0.20,  # Rotates destinations, so persistence per IP is low
            "destination_count": 10,
            "is_attack": True,
            "label": "AH. Destination IP Rotation (10 IPs)"
        }

    elif scenario_type == "AI_PERIOD_DRIFT":
        # Period drift: starts at 10s and increases by 2.5s every interval (10, 12.5, 15, 17.5, ...)
        iats = [base_interval + 2.5 * i for i in range(count - 1)]
        meta = {
            "dst_ip": "198.51.100.105",
            "dst_port": 8443,
            "dst_concentration": 0.95,
            "destination_count": 1,
            "is_attack": True,
            "label": "AI. Period Drift (10s -> 45s)"
        }

    elif scenario_type == "AJ_JITTER_PLUS_DESTINATION_ROTATION":
        # 30% jitter + destination rotation
        iats = [base_interval * (1.0 + rng.uniform(-0.30, 0.30)) for _ in range(count - 1)]
        rot_idx = rng.randint(1, 250)
        meta = {
            "dst_ip": f"198.51.100.{rot_idx}",
            "dst_port": 8443,
            "dst_concentration": 0.25,
            "destination_count": 8,
            "is_attack": True,
            "label": "AJ. 30% Jitter + Dest Rotation"
        }

    elif scenario_type == "AK_JITTER_PLUS_PERIOD_DRIFT":
        # Period drift (10s -> 40s) + 20% random jitter on top
        iats = [(base_interval + 2.0 * i) * (1.0 + rng.uniform(-0.20, 0.20)) for i in range(count - 1)]
        meta = {
            "dst_ip": "198.51.100.107",
            "dst_port": 8443,
            "dst_concentration": 0.90,
            "destination_count": 1,
            "is_attack": True,
            "label": "AK. Jitter + Period Drift"
        }

    elif scenario_type == "AL_LOW_AND_SLOW_PLUS_DESTINATION_ROTATION":
        # 60s interval + rotating destinations (Fast Flux C2)
        iats = [60.0 * (1.0 + rng.uniform(-0.15, 0.15)) for _ in range(count - 1)]
        rot_idx = rng.randint(1, 250)
        meta = {
            "dst_ip": f"198.51.100.{rot_idx}",
            "dst_port": 443,
            "dst_concentration": 0.30,
            "destination_count": 6,
            "is_attack": True,
            "label": "AL. Low-and-Slow + Dest Rotation"
        }

    else:
        raise ValueError(f"Unknown scenario: {scenario_type}")

    timestamps = [start_time]
    for iat in iats:
        timestamps.append(timestamps[-1] + float(iat))

    return timestamps, meta


def run_benchmark_for_seed(
    seed: int = 42,
    num_trials_per_scenario: int = 50,
    decision_threshold: float = 0.60
) -> Dict[str, Any]:
    """
    Runs evaluation for a single seed across all 38 scenarios.
    Calculates per-scenario confidence statistics (mean, median, std, min, max, P25, P75, P95),
    outcome state classifications, continuous scores for ROC/PR AUC, and threshold sensitivity.
    """
    scenarios = [
        # Part 1: Original Scenarios (A-T)
        "A_PERFECT_PERIODIC",
        "B_JITTER_10",
        "C_JITTER_20",
        "D_JITTER_40",
        "E_STRUCTURED_JITTER",
        "F_RANDOM_JITTER",
        "G_LEGITIMATE_PERIODIC_POLL",
        "H_LEGITIMATE_BURSTY_WEB",
        "I_BEACON_REPEATED_DEST",
        "J_BEACON_SUSPICIOUS_DNS",
        "K_BEACON_SUSPICIOUS_TLS",
        "L_LOW_AND_SLOW_BEACON",
        "M_LOW_AND_SLOW_BEACON_JITTER",
        "N_LOW_AND_SLOW_BEACON_REPEATED_DEST",
        "O_LOW_AND_SLOW_BEACON_SUSPICIOUS_DNS",
        "P_LOW_AND_SLOW_BEACON_SUSPICIOUS_TLS",
        "Q_RANDOM_JITTER_PLUS_DGA",
        "R_RANDOM_JITTER_PLUS_SUSPICIOUS_TLS",
        "S_RANDOM_JITTER_PLUS_DESTINATION_PERSISTENCE",
        "T_RANDOM_JITTER_PLUS_DGA_PLUS_TLS",
        # Part 2: Benign Hard Negatives (U-AD)
        "U_LEGITIMATE_PERIODIC_API_POLLING",
        "V_LEGITIMATE_DNS_CACHE_REFRESH",
        "W_LEGITIMATE_NTP_CLIENT",
        "X_LEGITIMATE_HEALTH_CHECK",
        "Y_LEGITIMATE_DATABASE_HEARTBEAT",
        "Z_LEGITIMATE_CLOUD_SERVICE_POLLING",
        "AA_LEGITIMATE_TLS_KEEPALIVE",
        "AB_LEGITIMATE_QUIC_CONNECTIONS",
        "AC_LEGITIMATE_LOW_AND_SLOW_APPLICATION",
        "AD_LEGITIMATE_VARIABLE_JITTER_POLLING",
        # Part 3: Adversarial Escalation (AE-AL)
        "AE_RANDOMIZED_JITTER_60",
        "AF_RANDOMIZED_JITTER_80",
        "AG_RANDOMIZED_JITTER_100",
        "AH_DESTINATION_ROTATION",
        "AI_PERIOD_DRIFT",
        "AJ_JITTER_PLUS_DESTINATION_ROTATION",
        "AK_JITTER_PLUS_PERIOD_DRIFT",
        "AL_LOW_AND_SLOW_PLUS_DESTINATION_ROTATION",
    ]

    beacon_det = BeaconingDetector(require_destination_rarity=True)
    dga_det = DGADetector()
    enc_det = EncryptedTrafficDetector()
    fusion_engine = ThreatFusionEngine(dedup_window_sec=0.0)

    scenario_results: Dict[str, Any] = {}

    all_y_true: List[int] = []
    all_y_score: List[float] = []

    total_tp = 0
    total_fp = 0
    total_tn = 0
    total_fn = 0

    false_positive_investigations: List[Dict[str, Any]] = []

    for scen in scenarios:
        timing_detected_count = 0
        fused_detected_count = 0
        unknown_anomaly_count = 0
        insufficient_evidence_count = 0

        timing_confidences: List[float] = []
        fused_confidences: List[float] = []
        timing_qualities: List[float] = []
        protocol_scores: List[float] = []
        behavior_scores: List[float] = []

        is_attack_scenario = True
        label = scen

        for trial in range(num_trials_per_scenario):
            # Deterministic trial seed derived from master seed
            trial_seed = seed * 1000 + trial
            ts, meta = generate_scenario_timestamps(scen, seed=trial_seed)
            is_attack_scenario = meta.get("is_attack", True)
            label = meta.get("label", scen)

            # Construct observable features dictionary (strictly isolated from ground truth)
            flow_features = {
                "flow_id": f"TEST:{scen}:{seed}:{trial}",
                "src_ip": "10.0.0.15",
                "src_port": 50000 + (trial % 10000),
                "dst_ip": meta.get("dst_ip", "198.51.100.1"),
                "dst_port": meta.get("dst_port", 8443),
                "protocol": meta.get("protocol", "TCP"),
                "duration": ts[-1] - ts[0],
                "timestamps": ts,
                "packet_lengths": meta.get("packet_lengths", [100] * len(ts)),
                "forward_bytes": meta.get("forward_bytes", 5000),
                "backward_bytes": meta.get("backward_bytes", 1000),
                "tls_metadata": meta.get("tls_metadata", {}),
                "quic_metadata": meta.get("quic_metadata", {}),
                "dns_queries": meta.get("dns_queries", []),
                "input_source": "synthetic_stream",
            }

            ctx = {
                "connection_timestamps": ts,
                "dst_concentration": meta.get("dst_concentration", 1.0),
                "destination_count": meta.get("destination_count", 1),
            }

            # 1. Evaluate Timing-Only Detector
            timing_res = beacon_det.predict(flow_features, context=ctx)
            if timing_res is not None and timing_res.threat_class == "BOTNET_C2_BEACONING":
                timing_detected_count += 1
                timing_confidences.append(timing_res.confidence)
                t_qual = timing_res.evidence.get("timing_evidence_quality", 0.5)
                p_score = timing_res.evidence.get("evidence_groups", {}).get("protocol_group", {}).get("protocol_evidence_score", 0.0)
                b_score = timing_res.evidence.get("destination_persistence_score", 0.5)
            else:
                timing_confidences.append(0.0)
                timing_stats = compute_advanced_timing_stats(ts)
                t_qual = timing_stats["timing_evidence_quality"]
                p_score = 0.5 if (meta.get("tls_metadata") or meta.get("dns_queries") or meta.get("quic_metadata")) else 0.0
                b_score = meta.get("dst_concentration", 0.5)

            timing_qualities.append(t_qual)
            protocol_scores.append(p_score)
            behavior_scores.append(b_score)

            # 2. Evaluate All Detectors for Full-Fusion Pipeline
            candidate_detections = []
            if timing_res:
                candidate_detections.append(timing_res)

            dga_res = dga_det.predict(flow_features, context=ctx)
            if dga_res:
                candidate_detections.append(dga_res)

            enc_res = enc_det.predict(flow_features, context=ctx)
            if enc_res:
                candidate_detections.append(enc_res)

            fused_alerts = fusion_engine.fuse(candidate_detections, flow_features)

            # Extract continuous score for ROC-AUC / PR-AUC
            if fused_alerts:
                trial_score = float(fused_alerts[0].confidence)
                alert_threat_class = fused_alerts[0].threat_class
            elif timing_res:
                trial_score = float(timing_res.confidence)
                alert_threat_class = timing_res.threat_class
            else:
                trial_score = 0.0
                alert_threat_class = "NONE"

            fused_confidences.append(trial_score)

            # Ground truth binary: 1 = Attack, 0 = Benign
            all_y_true.append(1 if is_attack_scenario else 0)
            all_y_score.append(trial_score)

            # Binary decision based on decision_threshold
            is_detected = (trial_score >= decision_threshold)

            if alert_threat_class == "UNKNOWN_ANOMALY":
                unknown_anomaly_count += 1
            elif alert_threat_class == "INSUFFICIENT_EVIDENCE":
                insufficient_evidence_count += 1

            if is_detected:
                fused_detected_count += 1
                if is_attack_scenario:
                    total_tp += 1
                else:
                    total_fp += 1
                    # Record False Positive forensic telemetry
                    if len(false_positive_investigations) < 10:
                        false_positive_investigations.append({
                            "scenario": scen,
                            "label": label,
                            "trial": trial,
                            "confidence": round(trial_score, 4),
                            "threat_class": alert_threat_class,
                            "timing_quality": round(t_qual, 4),
                            "protocol_score": round(p_score, 4),
                            "behavior_score": round(b_score, 4),
                            "root_cause_analysis": "Periodic interval or concentration overlap with benign keepalive profile.",
                        })
            else:
                if is_attack_scenario:
                    total_fn += 1
                else:
                    total_tn += 1

        t_det_rate = timing_detected_count / num_trials_per_scenario
        f_det_rate = fused_detected_count / num_trials_per_scenario

        # Statistical confidence distribution calculation
        fused_np = np.array(fused_confidences)
        timing_np = np.array(timing_confidences)

        # Classify scenario outcome state
        if f_det_rate >= 0.80:
            outcome_state = "Detected"
        elif f_det_rate >= 0.20:
            outcome_state = "Partially Detected"
        elif unknown_anomaly_count > (num_trials_per_scenario // 3):
            outcome_state = "Unknown Anomaly"
        elif insufficient_evidence_count > (num_trials_per_scenario // 3):
            outcome_state = "Insufficient Evidence"
        else:
            outcome_state = "Missed"

        scenario_results[scen] = {
            "scenario": scen,
            "label": label,
            "is_attack": is_attack_scenario,
            "sample_count": num_trials_per_scenario,
            "outcome_state": outcome_state,
            "timing_detected_count": timing_detected_count,
            "timing_detection_rate": round(t_det_rate, 4),
            "timing_mean_confidence": round(float(np.mean(timing_np)), 4),
            "timing_median_confidence": round(float(np.median(timing_np)), 4),
            "timing_evidence_quality": round(float(np.mean(timing_qualities)), 4),
            "fused_detected_count": fused_detected_count,
            "fused_detection_rate": round(f_det_rate, 4),
            "fused_mean_confidence": round(float(np.mean(fused_np)), 4),
            "fused_median_confidence": round(float(np.median(fused_np)), 4),
            "fused_std_confidence": round(float(np.std(fused_np)), 4),
            "fused_min_confidence": round(float(np.min(fused_np)), 4),
            "fused_max_confidence": round(float(np.max(fused_np)), 4),
            "fused_p25_confidence": round(float(np.percentile(fused_np, 25)), 4),
            "fused_p75_confidence": round(float(np.percentile(fused_np, 75)), 4),
            "fused_p95_confidence": round(float(np.percentile(fused_np, 95)), 4),
            "protocol_evidence_score": round(float(np.mean(protocol_scores)), 4),
            "behavior_evidence_score": round(float(np.mean(behavior_scores)), 4),
            "false_positive_rate": round(f_det_rate, 4) if not is_attack_scenario else 0.0,
            "recall": round(f_det_rate, 4) if is_attack_scenario else 0.0,
        }

    # Confusion matrix metrics
    total_positives = total_tp + total_fn
    total_negatives = total_tn + total_fp
    precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0.0
    recall = total_tp / total_positives if total_positives > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    fpr = total_fp / total_negatives if total_negatives > 0 else 0.0

    # ROC-AUC and PR-AUC calculation across all continuous trial scores
    try:
        roc_auc = float(roc_auc_score(all_y_true, all_y_score))
    except Exception:
        roc_auc = 0.0

    try:
        pr_auc = float(average_precision_score(all_y_true, all_y_score))
    except Exception:
        pr_auc = 0.0

    # Threshold sensitivity evaluation across [0.50, 0.60, 0.70, 0.80, 0.90]
    threshold_sweep: List[Dict[str, Any]] = []
    for th in [0.50, 0.60, 0.70, 0.80, 0.90]:
        th_tp = sum(1 for yt, ys in zip(all_y_true, all_y_score) if yt == 1 and ys >= th)
        th_fp = sum(1 for yt, ys in zip(all_y_true, all_y_score) if yt == 0 and ys >= th)
        th_tn = sum(1 for yt, ys in zip(all_y_true, all_y_score) if yt == 0 and ys < th)
        th_fn = sum(1 for yt, ys in zip(all_y_true, all_y_score) if yt == 1 and ys < th)

        th_prec = th_tp / (th_tp + th_fp) if (th_tp + th_fp) > 0 else 0.0
        th_rec = th_tp / (th_tp + th_fn) if (th_tp + th_fn) > 0 else 0.0
        th_f1 = 2 * (th_prec * th_rec) / (th_prec + th_rec) if (th_prec + th_rec) > 0 else 0.0
        th_fpr = th_fp / (th_fp + th_tn) if (th_fp + th_tn) > 0 else 0.0

        threshold_sweep.append({
            "threshold": th,
            "precision": round(th_prec, 4),
            "recall": round(th_rec, 4),
            "f1_score": round(th_f1, 4),
            "fpr": round(th_fpr, 4),
            "tp": th_tp,
            "fp": th_fp,
            "tn": th_tn,
            "fn": th_fn,
        })

    # Grouped comparisons:
    # 1. Pure Timing Evasion (A-F)
    pure_timing_recal = [v["timing_detection_rate"] for k, v in scenario_results.items() if k in ("A_PERFECT_PERIODIC", "B_JITTER_10", "C_JITTER_20", "D_JITTER_40", "E_STRUCTURED_JITTER", "F_RANDOM_JITTER")]
    # 2. Low-and-Slow (L-P)
    low_slow_recal = [v["fused_detection_rate"] for k, v in scenario_results.items() if k.startswith("L_") or k.startswith("M_") or k.startswith("N_") or k.startswith("O_") or k.startswith("P_")]
    # 3. Randomized Jitter + Independent Signals (Q-T)
    random_plus_indep_recal = [v["fused_detection_rate"] for k, v in scenario_results.items() if k.startswith("Q_") or k.startswith("R_") or k.startswith("S_") or k.startswith("T_")]
    # 4. Benign Hard Negatives (U-AD)
    benign_hard_neg_fpr = [v["false_positive_rate"] for k, v in scenario_results.items() if k in (
        "U_LEGITIMATE_PERIODIC_API_POLLING", "V_LEGITIMATE_DNS_CACHE_REFRESH", "W_LEGITIMATE_NTP_CLIENT",
        "X_LEGITIMATE_HEALTH_CHECK", "Y_LEGITIMATE_DATABASE_HEARTBEAT", "Z_LEGITIMATE_CLOUD_SERVICE_POLLING",
        "AA_LEGITIMATE_TLS_KEEPALIVE", "AB_LEGITIMATE_QUIC_CONNECTIONS", "AC_LEGITIMATE_LOW_AND_SLOW_APPLICATION",
        "AD_LEGITIMATE_VARIABLE_JITTER_POLLING"
    )]
    # 5. Adversarial Escalation (AE-AL)
    adv_escalation_recal = [v["fused_detection_rate"] for k, v in scenario_results.items() if k.startswith("AE_") or k.startswith("AF_") or k.startswith("AG_") or k.startswith("AH_") or k.startswith("AI_") or k.startswith("AJ_") or k.startswith("AK_") or k.startswith("AL_")]

    grouped_summary = {
        "pure_timing_mean_recall": round(float(np.mean(pure_timing_recal)), 4),
        "low_and_slow_fused_mean_recall": round(float(np.mean(low_slow_recal)), 4),
        "random_jitter_plus_independent_signals_mean_recall": round(float(np.mean(random_plus_indep_recal)), 4),
        "benign_hard_negatives_mean_fpr": round(float(np.mean(benign_hard_neg_fpr)), 4),
        "adversarial_escalation_mean_recall": round(float(np.mean(adv_escalation_recal)), 4),
    }

    return {
        "seed": seed,
        "scenarios": scenario_results,
        "confusion_matrix": {
            "TP": total_tp,
            "FP": total_fp,
            "TN": total_tn,
            "FN": total_fn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4),
            "fpr": round(fpr, 4),
            "roc_auc": round(roc_auc, 4),
            "pr_auc": round(pr_auc, 4),
        },
        "grouped_summary": grouped_summary,
        "threshold_sensitivity": threshold_sweep,
        "false_positive_investigations": false_positive_investigations,
    }


def run_cross_seed_benchmark(
    seeds: List[int],
    num_trials_per_scenario: int = 50,
    decision_threshold: float = 0.60
) -> Dict[str, Any]:
    """
    Executes benchmark across multiple seeds and compiles cross-seed mean and std metrics.
    """
    seed_runs: List[Dict[str, Any]] = []

    recalls: List[float] = []
    precisions: List[float] = []
    f1s: List[float] = []
    fprs: List[float] = []
    roc_aucs: List[float] = []
    pr_aucs: List[float] = []

    pure_timing_recalls: List[float] = []
    low_slow_recalls: List[float] = []
    random_plus_indep_recalls: List[float] = []
    benign_fprs: List[float] = []
    adv_escalation_recalls: List[float] = []

    for s in seeds:
        res = run_benchmark_for_seed(
            seed=s,
            num_trials_per_scenario=num_trials_per_scenario,
            decision_threshold=decision_threshold
        )
        seed_runs.append(res)
        cm = res["confusion_matrix"]
        grp = res["grouped_summary"]

        recalls.append(cm["recall"])
        precisions.append(cm["precision"])
        f1s.append(cm["f1_score"])
        fprs.append(cm["fpr"])
        roc_aucs.append(cm["roc_auc"])
        pr_aucs.append(cm["pr_auc"])

        pure_timing_recalls.append(grp["pure_timing_mean_recall"])
        low_slow_recalls.append(grp["low_and_slow_fused_mean_recall"])
        random_plus_indep_recalls.append(grp["random_jitter_plus_independent_signals_mean_recall"])
        benign_fprs.append(grp["benign_hard_negatives_mean_fpr"])
        adv_escalation_recalls.append(grp["adversarial_escalation_mean_recall"])

    cross_seed_stats = {
        "seeds_evaluated": seeds,
        "recall_mean": round(float(np.mean(recalls)), 4),
        "recall_std": round(float(np.std(recalls)), 4),
        "precision_mean": round(float(np.mean(precisions)), 4),
        "precision_std": round(float(np.std(precisions)), 4),
        "f1_mean": round(float(np.mean(f1s)), 4),
        "f1_std": round(float(np.std(f1s)), 4),
        "fpr_mean": round(float(np.mean(fprs)), 4),
        "fpr_std": round(float(np.std(fprs)), 4),
        "roc_auc_mean": round(float(np.mean(roc_aucs)), 4),
        "roc_auc_std": round(float(np.std(roc_aucs)), 4),
        "pr_auc_mean": round(float(np.mean(pr_aucs)), 4),
        "pr_auc_std": round(float(np.std(pr_aucs)), 4),
        "grouped_stats": {
            "pure_timing_recall_mean": round(float(np.mean(pure_timing_recalls)), 4),
            "pure_timing_recall_std": round(float(np.std(pure_timing_recalls)), 4),
            "low_slow_recall_mean": round(float(np.mean(low_slow_recalls)), 4),
            "low_slow_recall_std": round(float(np.std(low_slow_recalls)), 4),
            "random_plus_indep_recall_mean": round(float(np.mean(random_plus_indep_recalls)), 4),
            "random_plus_indep_recall_std": round(float(np.std(random_plus_indep_recalls)), 4),
            "benign_hard_neg_fpr_mean": round(float(np.mean(benign_fprs)), 4),
            "benign_hard_neg_fpr_std": round(float(np.std(benign_fprs)), 4),
            "adv_escalation_recall_mean": round(float(np.mean(adv_escalation_recalls)), 4),
            "adv_escalation_recall_std": round(float(np.std(adv_escalation_recalls)), 4),
        }
    }

    # Primary baseline run is the first seed (e.g. seed 42)
    primary_run = seed_runs[0]
    primary_run["cross_seed_summary"] = cross_seed_stats
    primary_run["all_seed_runs"] = [{
        "seed": r["seed"],
        "recall": r["confusion_matrix"]["recall"],
        "precision": r["confusion_matrix"]["precision"],
        "f1": r["confusion_matrix"]["f1_score"],
        "fpr": r["confusion_matrix"]["fpr"],
        "roc_auc": r["confusion_matrix"]["roc_auc"],
        "pr_auc": r["confusion_matrix"]["pr_auc"],
    } for r in seed_runs]

    return primary_run


def main():
    parser = argparse.ArgumentParser(description="AEGIS v2.2 Red-Team Adversarial Validation Suite")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for single-seed run")
    parser.add_argument("--seeds", type=int, nargs="+", default=None, help="List of seeds for multi-seed validation (e.g. 42 123 999 2026 777)")
    parser.add_argument("--trials", type=int, default=50, help="Number of trials per scenario (default: 50)")
    parser.add_argument("--threshold", type=float, default=0.60, help="Classification decision threshold (default: 0.60)")
    parser.add_argument("--export", type=str, default="data/adversarial_beacon_results.json", help="Export path for JSON telemetry")

    args = parser.parse_args()

    print("=" * 96)
    print("   AEGIS v2.2 RED-TEAM VALIDATION & EMPIRICAL BOUNDARY BENCHMARK")
    print("   Evaluating Label Isolation, Benign Hard Negatives, & Adversarial Escalation (38 Scenarios)")
    print("=" * 96)

    if args.seeds:
        eval_seeds = args.seeds
        print(f"[*] Running multi-seed cross validation across seeds: {eval_seeds}")
        results = run_cross_seed_benchmark(seeds=eval_seeds, num_trials_per_scenario=args.trials, decision_threshold=args.threshold)
    else:
        print(f"[*] Running benchmark with single seed: {args.seed}")
        results = run_benchmark_for_seed(seed=args.seed, num_trials_per_scenario=args.trials, decision_threshold=args.threshold)

    scens = results["scenarios"]
    cm = results["confusion_matrix"]
    grp = results["grouped_summary"]
    th_sweep = results["threshold_sensitivity"]

    print(f"\n{'Scenario':<42} | {'Type':<6} | {'Outcome':<18} | {'Timing':<7} | {'Fused':<7} | {'P50 Conf':<8} | {'P95 Conf':<8}")
    print("-" * 110)
    for k, v in scens.items():
        stype = "ATTACK" if v["is_attack"] else "BENIGN"
        print(f"{v['label'][:42]:<42} | {stype:<6} | {v['outcome_state']:<18} | {v['timing_detection_rate']*100:>6.1f}% | {v['fused_detection_rate']*100:>6.1f}% | {v['fused_median_confidence']:>8.4f} | {v['fused_p95_confidence']:>8.4f}")

    print("\n" + "=" * 96)
    print("   OVERALL CONFUSION MATRIX & ROC/PR EVALUATION (FULL FUSION PIPELINE)")
    print("=" * 96)
    print(f"  True Positives (TP):  {cm['TP']:<5} | False Positives (FP): {cm['FP']}")
    print(f"  True Negatives (TN):  {cm['TN']:<5} | False Negatives (FN): {cm['FN']}")
    print(f"  Precision:            {cm['precision']:.4f}")
    print(f"  Recall (Sensitivity): {cm['recall']:.4f}")
    print(f"  F1-Score:             {cm['f1_score']:.4f}")
    print(f"  False Positive Rate:  {cm['fpr']:.4f}")
    print(f"  ROC-AUC:              {cm['roc_auc']:.4f}")
    print(f"  PR-AUC (Avg Prec):    {cm['pr_auc']:.4f}")

    print("\n" + "=" * 96)
    print("   GROUPED ARCHITECTURAL SUBSET BREAKDOWN")
    print("=" * 96)
    print(f"  1. Pure Timing Baseline Scenarios (A-F) Timing Recall:         {grp['pure_timing_mean_recall']*100:.1f}%")
    print(f"  2. Low-and-Slow Persistent C2 Scenarios (L-P) Fused Recall:    {grp['low_and_slow_fused_mean_recall']*100:.1f}%")
    print(f"  3. Random Jitter + Independent Signals (Q-T) Fused Recall:     {grp['random_jitter_plus_independent_signals_mean_recall']*100:.1f}%")
    print(f"  4. Benign Hard Negatives (U-AD) False Positive Rate:           {grp['benign_hard_negatives_mean_fpr']*100:.1f}%")
    print(f"  5. Adversarial Escalation & Evasion (AE-AL) Fused Recall:      {grp['adversarial_escalation_mean_recall']*100:.1f}%")

    if "cross_seed_summary" in results:
        cs = results["cross_seed_summary"]
        print("\n" + "=" * 96)
        print("   CROSS-SEED VALIDATION SUMMARY (MEAN +/- STD)")
        print("=" * 96)
        print(f"  - Recall:    {cs['recall_mean']:.4f} +/- {cs['recall_std']:.4f}")
        print(f"  - Precision: {cs['precision_mean']:.4f} +/- {cs['precision_std']:.4f}")
        print(f"  - F1-Score:  {cs['f1_mean']:.4f} +/- {cs['f1_std']:.4f}")
        print(f"  - FPR:       {cs['fpr_mean']:.4f} +/- {cs['fpr_std']:.4f}")
        print(f"  - ROC-AUC:   {cs['roc_auc_mean']:.4f} +/- {cs['roc_auc_std']:.4f}")
        print(f"  - PR-AUC:    {cs['pr_auc_mean']:.4f} +/- {cs['pr_auc_std']:.4f}")

    print("\n" + "=" * 96)
    print("   CLASSIFICATION THRESHOLD SENSITIVITY SWEEP")
    print("=" * 96)
    print(f"  {'Threshold':<10} | {'Precision':<11} | {'Recall':<10} | {'F1-Score':<10} | {'FPR':<10} | {'TP':<5} | {'FP':<5}")
    print("  " + "-" * 75)
    for sw in th_sweep:
        print(f"  {sw['threshold']:<10.2f} | {sw['precision']:<11.4f} | {sw['recall']:<10.4f} | {sw['f1_score']:<10.4f} | {sw['fpr']:<10.4f} | {sw['tp']:<5} | {sw['fp']:<5}")
    print("=" * 96)

    out_path = Path(args.export)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n[+] Comprehensive telemetry successfully exported to {out_path}")


if __name__ == "__main__":
    main()
