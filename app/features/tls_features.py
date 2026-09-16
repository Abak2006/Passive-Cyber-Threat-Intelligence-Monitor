"""
Passive TLS/QUIC Metadata & Behavioral Feature Extraction.
STRICT REQUIREMENT: Absolutely NO payload decryption or key interception.
Extracts only unencrypted handshake headers (JA3/JA4 representation), cipher distributions,
and Sequence of Packet Lengths and Times (SPLT).
"""

import hashlib
import struct
from typing import Any, Dict, List, Optional, Tuple


# Standard GREASE values to filter out of JA3
GREASE_VALUES = {
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
    0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA
}


class TLSFeatureExtractor:
    """
    Extracts observable metadata from TLS Client Hello packets and early flow behavior.
    Operates in passive one-way mode; does not perform any MITM or decryption.
    """

    @staticmethod
    def parse_client_hello(payload: bytes) -> Optional[Dict[str, Any]]:
        """
        Passively parse TLS Client Hello handshake fields from raw bytes.
        Returns JA3 parameters and metadata if valid Client Hello, else None.
        """
        if not payload or len(payload) < 43:
            return None

        try:
            # TLS Record Header: [ContentType (1), Version (2), Length (2)]
            content_type, rec_ver_major, rec_ver_minor, rec_len = struct.unpack("!BBHH", payload[:6])
            if content_type != 22:  # 22 = Handshake
                return None

            # Handshake Header: [HandshakeType (1), Length (3)]
            hs_type = payload[5]
            if hs_type != 1:  # 1 = Client Hello
                return None

            idx = 9  # Start of Client Hello body
            # Handshake Version (2 bytes)
            if idx + 2 > len(payload):
                return None
            hs_version = struct.unpack("!H", payload[idx:idx + 2])[0]
            idx += 2

            # Random (32 bytes)
            idx += 32
            if idx > len(payload):
                return None

            # Session ID Length (1 byte)
            sess_id_len = payload[idx]
            idx += 1 + sess_id_len
            if idx + 2 > len(payload):
                return None

            # Cipher Suites Length (2 bytes)
            ciphers_len = struct.unpack("!H", payload[idx:idx + 2])[0]
            idx += 2
            if idx + ciphers_len > len(payload):
                return None

            ciphers = []
            for i in range(0, ciphers_len, 2):
                cipher_val = struct.unpack("!H", payload[idx + i:idx + i + 2])[0]
                if cipher_val not in GREASE_VALUES:
                    ciphers.append(cipher_val)
            idx += ciphers_len

            # Compression Methods Length (1 byte)
            if idx >= len(payload):
                return None
            comp_len = payload[idx]
            idx += 1 + comp_len

            # Extensions Length (2 bytes)
            if idx + 2 > len(payload):
                return None
            exts_len = struct.unpack("!H", payload[idx:idx + 2])[0]
            idx += 2

            extensions = []
            elliptic_curves = []
            ec_point_formats = []
            sni_present = False
            sni_len = 0
            alpn_present = False

            end_ext = min(len(payload), idx + exts_len)
            while idx + 4 <= end_ext:
                ext_type, ext_data_len = struct.unpack("!HH", payload[idx:idx + 4])
                idx += 4
                if ext_type not in GREASE_VALUES:
                    extensions.append(ext_type)

                ext_data = payload[idx:idx + ext_data_len]
                if ext_type == 0:  # SNI
                    sni_present = True
                    sni_len = ext_data_len
                elif ext_type == 10:  # Supported Groups (Elliptic Curves)
                    if len(ext_data) >= 2:
                        curves_len = struct.unpack("!H", ext_data[:2])[0]
                        for c in range(2, min(len(ext_data), 2 + curves_len), 2):
                            curve_val = struct.unpack("!H", ext_data[c:c + 2])[0]
                            if curve_val not in GREASE_VALUES:
                                elliptic_curves.append(curve_val)
                elif ext_type == 11:  # EC Point Formats
                    if len(ext_data) >= 1:
                        point_formats_len = ext_data[0]
                        for p in range(1, min(len(ext_data), 1 + point_formats_len)):
                            ec_point_formats.append(ext_data[p])
                elif ext_type == 16:  # ALPN
                    alpn_present = True

                idx += ext_data_len

            # Build standard JA3 string:
            # SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat
            ja3_str = (
                f"{hs_version},"
                f"{'-'.join(map(str, ciphers))},"
                f"{'-'.join(map(str, extensions))},"
                f"{'-'.join(map(str, elliptic_curves))},"
                f"{'-'.join(map(str, ec_point_formats))}"
            )
            ja3_hash = hashlib.md5(ja3_str.encode("utf-8")).hexdigest()

            # JA4 abstraction placeholder: e.g. "t13d080500_hash"
            ver_str = "t13" if hs_version == 0x0304 else "t12"
            sni_flag = "d" if sni_present else "i"
            ja4_str = f"{ver_str}{sni_flag}{len(ciphers):02d}{len(extensions):02d}00_{ja3_hash[:12]}"

            return {
                "ja3_string": ja3_str,
                "ja3_hash": ja3_hash,
                "ja4_fingerprint": ja4_str,
                "tls_version": hex(hs_version),
                "ciphers_count": len(ciphers),
                "extensions_count": len(extensions),
                "has_sni": sni_present,
                "sni_length": sni_len,
                "has_alpn": alpn_present,
            }
        except Exception:
            return None

    @staticmethod
    def extract_behavioral_features(
        packet_lengths: List[int],
        timestamps: List[float],
        forward_bytes: int,
        backward_bytes: int
    ) -> Dict[str, Any]:
        """
        Extracts SPLT (Sequence of Packet Lengths and Times) and flow behavioral characteristics
        for encrypted traffic where payload contents cannot be observed.
        """
        import numpy as np

        if not packet_lengths:
            return {
                "splt_mean_length": 0.0,
                "splt_std_length": 0.0,
                "splt_length_variance": 0.0,
                "early_packet_lengths": [],
                "outbound_inbound_ratio": 0.0,
            }

        arr_lens = np.array(packet_lengths, dtype=np.float64)
        mean_len = float(np.mean(arr_lens))
        std_len = float(np.std(arr_lens))
        var_len = float(np.var(arr_lens))

        out_in_ratio = float(forward_bytes) / float(backward_bytes + 1)
        early_lengths = packet_lengths[:10]  # First 10 packet lengths (SPLT prefix)

        return {
            "splt_mean_length": round(mean_len, 2),
            "splt_std_length": round(std_len, 2),
            "splt_length_variance": round(var_len, 2),
            "early_packet_lengths": early_lengths,
            "outbound_inbound_ratio": round(out_in_ratio, 4),
        }
