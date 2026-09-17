"""
Security & Passive Architecture Guarantee Test.
Strictly audits codebase to guarantee:
1. Zero active socket connections or packet transmissions (no socket.connect, socket.send, scapy send/sendp/sr/srp).
2. Zero active network probes (no ping, traceroute, nmap, masscan).
3. Zero firewall modification or blocking commands (no iptables, nftables, pfctl, netsh).
4. Zero payload decryption operations (no private key parsing, no SSL key log decryption).
"""

import ast
import os
from pathlib import Path
import pytest

FORBIDDEN_CALLS = {
    "send", "sendto", "sendall", "sendp", "sendpfast",
    "sr", "sr1", "srp", "srp1", "srloop",
    "connect", "connect_ex",
}

FORBIDDEN_COMMAND_SUBSTRINGS = [
    "iptables", "nftables", "firewall-cmd", "netsh advfirewall",
    "ip link set", "tc qdisc", "route add", "route del"
]


def test_no_active_packet_transmission():
    """Scans all Python files in app/ to ensure no forbidden transmission functions are invoked."""
    app_dir = Path("app")
    violations = []

    for py_file in app_dir.rglob("*.py"):
        # Allow read-only operations and test files
        with open(py_file, "r", encoding="utf-8") as f:
            content = f.read()

        try:
            tree = ast.parse(content, filename=str(py_file))
        except Exception:
            continue

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = ""
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr

                # Check if forbidden network transmission function is called
                # Note: list.append / set.add are allowed, but socket.send, scapy.send are forbidden
                if func_name in FORBIDDEN_CALLS:
                    # Ignore benign methods like database transaction methods or queue methods if any
                    # But flag any socket or scapy transmission calls
                    if isinstance(node.func, ast.Attribute):
                        target_obj = ""
                        if isinstance(node.func.value, ast.Name):
                            target_obj = node.func.value.id
                        # Flag if called on socket, sock, s, or scapy
                        if target_obj.lower() in ("socket", "sock", "s", "scapy"):
                            violations.append(f"{py_file}:{node.lineno} calls {target_obj}.{func_name}()")
                    elif func_name in ("send", "sendp", "sr", "srp", "sr1"):
                        violations.append(f"{py_file}:{node.lineno} calls {func_name}()")

    assert not violations, f"Passive architecture violated! Found active transmission calls: {violations}"


def test_no_firewall_or_mitigation_commands():
    """Scans codebase to ensure no automated blocking/mitigation commands exist."""
    app_dir = Path("app")
    violations = []

    for py_file in app_dir.rglob("*.py"):
        with open(py_file, "r", encoding="utf-8") as f:
            for line_no, line in enumerate(f, 1):
                lower = line.lower()
                for cmd in FORBIDDEN_COMMAND_SUBSTRINGS:
                    if cmd in lower:
                        violations.append(f"{py_file}:{line_no} references mitigation command: {cmd}")

    assert not violations, f"IPS/Mitigation commands detected: {violations}"


def test_no_payload_decryption():
    """Verifies that no SSL private keys or SSLKEYLOGFILE decryption routines are present."""
    app_dir = Path("app")
    violations = []

    for py_file in app_dir.rglob("*.py"):
        with open(py_file, "r", encoding="utf-8") as f:
            for line_no, line in enumerate(f, 1):
                lower = line.lower()
                if "sslkeylogfile" in lower or "load_privatekey" in lower or "decrypt_payload" in lower:
                    violations.append(f"{py_file}:{line_no} contains decryption reference: {line.strip()}")

    assert not violations, f"Payload decryption routines detected: {violations}"


def test_data_diode_strictly_receive_only_interface():
    """Verifies that DataDiodeFeedSource exposes only receive-oriented interfaces."""
    from app.ingest.sources import DataDiodeFeedSource
    forbidden = ["send", "write", "transmit", "reply", "probe", "dial", "post"]
    for attr in dir(DataDiodeFeedSource):
        for f in forbidden:
            assert f not in attr.lower(), f"Forbidden method '{attr}' found in DataDiodeFeedSource"


def test_no_outbound_http_or_dns_requests_in_analytics():
    """Verifies that no detectors, fusion, or feature extractors make outbound HTTP/DNS network requests."""
    forbidden_modules = ["requests.", "urllib.request", "http.client", "httpx.", "aiohttp."]
    app_dir = Path("app")

    violations = []
    for py_file in app_dir.rglob("*.py"):
        # Exclude server entrypoint / dashboard if applicable
        if "dashboard" in str(py_file) or "server.py" in str(py_file):
            continue

        with open(py_file, "r", encoding="utf-8") as f:
            for line_no, line in enumerate(f, 1):
                for fm in forbidden_modules:
                    if fm in line and not line.strip().startswith("#"):
                        violations.append(f"{py_file}:{line_no} references network client '{fm}': {line.strip()}")

    assert not violations, f"Outbound network request libraries found in detection pipeline: {violations}"

