"""
Passive Streaming PCAP Reader.
Reads packets incrementally without loading full capture into memory.
Guarantees zero packet transmission or active injection into the monitored network.
"""

from pathlib import Path
from typing import Any, Dict, Generator, Optional
import logging

from scapy.all import PcapReader, IP, IPv6, TCP, UDP, DNS, Raw

logger = logging.getLogger(__name__)

TCP_FLAGS_MAP = {
    0x01: "FIN",
    0x02: "SYN",
    0x04: "RST",
    0x08: "PSH",
    0x10: "ACK",
    0x20: "URG",
}


class StreamingPCAPReader:
    """Incremental streaming PCAP packet source."""

    def __init__(self, pcap_path: str):
        self.pcap_path = Path(pcap_path)
        if not self.pcap_path.exists():
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    def stream_packets(self) -> Generator[Dict[str, Any], None, None]:
        """
        Yields parsed packet metadata dictionary packet by packet.
        Memory footprint remains constant regardless of PCAP file size.
        """
        reader = None
        try:
            reader = PcapReader(str(self.pcap_path))
            for pkt in reader:
                parsed = self._parse_packet(pkt)
                if parsed:
                    yield parsed
        except Exception as e:
            logger.error(f"Error reading PCAP {self.pcap_path}: {e}")
            raise
        finally:
            if reader:
                try:
                    reader.close()
                except Exception:
                    pass

    def _parse_packet(self, pkt) -> Optional[Dict[str, Any]]:
        """Extracts 5-tuple, protocol flags, and payload references."""
        ts = float(pkt.time)
        pkt_len = len(pkt)

        src_ip = None
        dst_ip = None
        protocol = "OTHER"

        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
        elif IPv6 in pkt:
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst
        else:
            return None

        src_port = 0
        dst_port = 0
        flags = []
        is_syn = False
        is_ack = False
        is_fin = False
        is_rst = False
        payload_bytes = b""

        if TCP in pkt:
            protocol = "TCP"
            src_port = int(pkt[TCP].sport)
            dst_port = int(pkt[TCP].dport)
            raw_flags = int(pkt[TCP].flags)
            is_syn = bool(raw_flags & 0x02)
            is_ack = bool(raw_flags & 0x10)
            is_fin = bool(raw_flags & 0x01)
            is_rst = bool(raw_flags & 0x04)
            if Raw in pkt:
                payload_bytes = bytes(pkt[Raw].load)
        elif UDP in pkt:
            protocol = "UDP"
            src_port = int(pkt[UDP].sport)
            dst_port = int(pkt[UDP].dport)
            if Raw in pkt:
                payload_bytes = bytes(pkt[Raw].load)

        # Check DNS layer if present
        dns_query = None
        dns_type = None
        if DNS in pkt:
            try:
                if pkt[DNS].qd and pkt[DNS].qd.qname:
                    dns_query = pkt[DNS].qd.qname.decode("utf-8", errors="ignore").rstrip(".")
                    dns_type = pkt[DNS].qd.qtype
            except Exception:
                pass

        return {
            "timestamp": ts,
            "length": pkt_len,
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "protocol": protocol,
            "is_syn": is_syn,
            "is_ack": is_ack,
            "is_fin": is_fin,
            "is_rst": is_rst,
            "payload_bytes": payload_bytes,
            "dns_query": dns_query,
            "dns_type": dns_type,
        }
