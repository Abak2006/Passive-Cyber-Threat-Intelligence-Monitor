"""
Passive QUIC Metadata and Behavioral Feature Extraction.
STRICT REQUIREMENT: Absolutely NO payload decryption or key interception.
Passively inspects observable UDP transport metadata, unencrypted QUIC Long Headers,
versions, connection IDs, and packet inter-arrival dynamics.
"""

import struct
from typing import Any, Dict, List, Optional, Tuple
import numpy as np

from app.features.timing_features import calculate_iats

KNOWN_QUIC_VERSIONS: Dict[int, str] = {
    0x00000001: "QUIC-v1 (RFC 9000)",
    0x6B3343CF: "QUIC-v2 (RFC 9369)",
    0x00000000: "Version Negotiation",
    0x51303530: "gQUIC Q050",
    0x51303436: "gQUIC Q046",
    0x51303433: "gQUIC Q043",
    0xFF00001D: "draft-29",
}


class QUICFeatureExtractor:
    """
    Passively inspects observable QUIC header fields and flow dynamics without decrypting payloads.
    Returns None for any fields that cannot be reliably extracted from passive observation.
    """

    @staticmethod
    def is_quic_packet(payload: bytes, src_port: int = 0, dst_port: int = 0) -> bool:
        """Determines whether a UDP packet likely carries QUIC transport framing."""
        if dst_port not in (443, 8443, 4433) and src_port not in (443, 8443, 4433):
            return False
        parsed = QUICFeatureExtractor.parse_quic_packet_header(payload)
        return parsed is not None

    @staticmethod
    def parse_quic_packet(payload: bytes, src_port: int = 0, dst_port: int = 0) -> Optional[Dict[str, Any]]:
        """Parses QUIC header and formats standardized packet dictionary."""
        header = QUICFeatureExtractor.parse_quic_packet_header(payload)
        if not header:
            return None
        return {
            "is_quic": True,
            "header_type": header["header_form"],
            "is_initial": header.get("is_initial", False),
            "version": f"0x{header['quic_version_raw']:08x}" if header.get("quic_version_raw") is not None else None,
            "version_name": header.get("quic_version"),
            "length": len(payload),
            "packet_type": header.get("packet_type"),
            "inspection_note": "Passive observable QUIC header fields only. Zero payload decryption performed.",
        }

    @staticmethod
    def parse_quic_packet_header(payload: bytes) -> Optional[Dict[str, Any]]:
        """
        Passively parse observable QUIC header fields from raw UDP payload bytes.
        Does not attempt payload decryption.
        """
        if not payload or len(payload) < 5:
            return None

        first_byte = payload[0]
        # Bit 7 (0x80) indicates Long Header (1) or Short Header (0)
        is_long_header = bool(first_byte & 0x80)
        # Bit 6 (0x40) is the Fixed Bit, must be 1 in standard QUIC
        fixed_bit = bool(first_byte & 0x40)

        if not fixed_bit and not is_long_header:
            return None

        if is_long_header:
            # Long Header format: [Header Byte (1), Version (4), DCIL (1), DCID, SCIL (1), SCID, ...]
            if len(payload) < 7:
                return None

            version_raw = struct.unpack("!I", payload[1:5])[0]
            version_name = KNOWN_QUIC_VERSIONS.get(version_raw, f"0x{version_raw:08x}")

            # Long packet types (Bits 4-5 in RFC 9000):
            # 0x00: Initial, 0x01: 0-RTT, 0x02: Handshake, 0x03: Retry
            packet_type_bits = (first_byte >> 4) & 0x03
            packet_type_names = {0: "Initial", 1: "0-RTT", 2: "Handshake", 3: "Retry"}
            packet_type = packet_type_names.get(packet_type_bits, "Unknown-Long")

            dcil = payload[5]
            offset = 6 + dcil
            scil = 0
            if offset < len(payload):
                scil = payload[offset]

            return {
                "header_form": "long",
                "quic_version": version_name,
                "quic_version_raw": version_raw,
                "packet_type": packet_type,
                "is_initial": (packet_type == "Initial"),
                "dcid_length": dcil,
                "scid_length": scil,
            }
        else:
            # Short Header (1-RTT application data)
            # All application payloads are encrypted; only header flags observable
            spin_bit = bool(first_byte & 0x20)
            key_phase = bool(first_byte & 0x04)
            return {
                "header_form": "short",
                "quic_version": None,  # Short headers do not carry version field
                "packet_type": "1-RTT (Encrypted Data)",
                "is_initial": False,
                "spin_bit": spin_bit,
                "key_phase": key_phase,
            }

    @staticmethod
    def extract_quic_flow_features(flow_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Synthesizes passive QUIC telemetry from flow state and packet samples.
        """
        protocol = flow_dict.get("protocol", "")
        dst_port = flow_dict.get("dst_port", 0)
        src_port = flow_dict.get("src_port", 0)
        is_quic_port = (protocol == "UDP" and (dst_port in (443, 8443, 4433) or src_port in (443, 8443, 4433)))

        packet_lengths = flow_dict.get("packet_lengths", [])
        timestamps = flow_dict.get("timestamps", [])
        forward_bytes = flow_dict.get("forward_bytes", 0)
        backward_bytes = flow_dict.get("backward_bytes", 0)
        total_bytes = forward_bytes + backward_bytes
        packet_count = len(packet_lengths)
        duration = max(0.0001, flow_dict.get("duration", 0.0))

        # Check for any parsed header metadata
        quic_meta = flow_dict.get("quic_metadata") or {}
        quic_version = quic_meta.get("quic_version")
        is_initial_seen = quic_meta.get("is_initial", False)

        quic_detected = is_quic_port or (quic_version is not None) or is_initial_seen

        mean_iat = None
        if len(timestamps) >= 2:
            iats = calculate_iats(timestamps)
            if iats:
                mean_iat = round(float(np.mean(iats)), 4)

        packet_size_mean = None
        packet_size_var = None
        if packet_lengths:
            packet_size_mean = round(float(np.mean(packet_lengths)), 2)
            packet_size_var = round(float(np.var(packet_lengths)), 2)

        return {
            "quic_detected": quic_detected,
            "quic_version": quic_version,
            "quic_initial_seen": is_initial_seen,
            "quic_packet_count": packet_count,
            "quic_bytes": total_bytes,
            "quic_duration": round(duration, 4),
            "quic_mean_iat": mean_iat,
            "quic_packet_size_mean": packet_size_mean,
            "quic_packet_size_variance": packet_size_var,
        }
