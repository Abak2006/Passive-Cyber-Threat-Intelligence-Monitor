"""
AEGIS Passive Input Source Abstraction Layer.
Defines unified, strictly receive-only input source interfaces for unidirectional network monitoring.
Guarantees zero packet transmission, zero active probing, and zero reverse communication paths.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
import logging
from pathlib import Path
import time
from typing import Any, Dict, Generator, List, Optional

from app.ingest.pcap_reader import StreamingPCAPReader

logger = logging.getLogger(__name__)


@dataclass
class PacketEvent:
    """
    Standardized immutable packet-level event representation across all input sources.
    Consumed by FlowStreamManager and downstream detection engines.
    """
    timestamp: float
    length: int
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    is_syn: bool = False
    is_ack: bool = False
    is_fin: bool = False
    is_rst: bool = False
    payload_bytes: bytes = field(default=b"", repr=False)
    dns_query: Optional[str] = None
    dns_type: Optional[int] = None
    input_source: str = "pcap_replay"

    def __init__(
        self,
        timestamp: float,
        length: int,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        protocol: str,
        is_syn: bool = False,
        is_ack: bool = False,
        is_fin: bool = False,
        is_rst: bool = False,
        payload_bytes: bytes = b"",
        dns_query: Optional[str] = None,
        dns_type: Optional[int] = None,
        input_source: Optional[str] = None,
        source_type: Optional[str] = None,
    ):
        self.timestamp = timestamp
        self.length = length
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.protocol = protocol
        self.is_syn = is_syn
        self.is_ack = is_ack
        self.is_fin = is_fin
        self.is_rst = is_rst
        self.payload_bytes = payload_bytes
        self.dns_query = dns_query
        self.dns_type = dns_type
        self.input_source = input_source or source_type or "pcap_replay"

    @property
    def source_type(self) -> str:
        """Backward compatibility alias for input_source."""
        return self.input_source

    @source_type.setter
    def source_type(self, value: str) -> None:
        self.input_source = value

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary matching flow stream manager expectation."""
        return {
            "timestamp": self.timestamp,
            "length": self.length,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "is_syn": self.is_syn,
            "is_ack": self.is_ack,
            "is_fin": self.is_fin,
            "is_rst": self.is_rst,
            "payload_bytes": self.payload_bytes,
            "dns_query": self.dns_query,
            "dns_type": self.dns_type,
            "input_source": self.input_source,
            "source_type": self.input_source,
        }


class PassiveInputSource(ABC):
    """
    Abstract Base Class for all passive input sources.
    Enforces strictly read-only, receive-only streaming ingestion.
    """

    def __init__(self, input_source: Optional[str] = None, source_type: Optional[str] = None):
        self.input_source = input_source or source_type or "pcap_replay"

    @property
    def source_type(self) -> str:
        """Backward compatibility alias for input_source."""
        return self.input_source

    @source_type.setter
    def source_type(self, value: str) -> None:
        self.input_source = value

    @abstractmethod
    def stream_events(self) -> Generator[PacketEvent, None, None]:
        """Yields PacketEvent objects sequentially. Must never write or transmit to network."""
        pass


class PcapReplaySource(PassiveInputSource):
    """
    Timestamp-aware streaming PCAP replay input source.
    Paces packet delivery according to captured packet timestamps and speed multiplier.
    """

    def __init__(self, pcap_path: str, speed: float = 1.0, realtime: bool = False):
        super().__init__(input_source="pcap_replay")
        self.pcap_path = Path(pcap_path)
        if not self.pcap_path.exists():
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

        if realtime:
            self.speed = 1.0
        else:
            self.speed = max(0.0, float(speed))

    def stream_events(self) -> Generator[PacketEvent, None, None]:
        reader = StreamingPCAPReader(str(self.pcap_path))
        prev_packet_time: Optional[float] = None

        for pkt_dict in reader.stream_packets():
            pkt_time = pkt_dict["timestamp"]

            # Realtime or speed-scaled pacing
            if self.speed > 0.0 and prev_packet_time is not None:
                delta = (pkt_time - prev_packet_time) / self.speed
                if 0.0001 < delta < 2.0:  # Cap excessive idle intervals
                    time.sleep(delta)
            prev_packet_time = pkt_time

            yield PacketEvent(
                timestamp=pkt_dict["timestamp"],
                length=pkt_dict["length"],
                src_ip=pkt_dict["src_ip"],
                src_port=pkt_dict["src_port"],
                dst_ip=pkt_dict["dst_ip"],
                dst_port=pkt_dict["dst_port"],
                protocol=pkt_dict["protocol"],
                is_syn=pkt_dict.get("is_syn", False),
                is_ack=pkt_dict.get("is_ack", False),
                is_fin=pkt_dict.get("is_fin", False),
                is_rst=pkt_dict.get("is_rst", False),
                payload_bytes=pkt_dict.get("payload_bytes", b""),
                dns_query=pkt_dict.get("dns_query"),
                dns_type=pkt_dict.get("dns_type"),
                input_source=self.input_source,
            )


class SyntheticStreamSource(PassiveInputSource):
    """
    In-memory synthetic telemetry stream generator for live demonstrations and testing.
    Generates controlled attack and benign flow events without requiring disk PCAP files.
    """

    def __init__(self, count: int = 100, interval_sec: float = 0.01):
        super().__init__(input_source="synthetic_stream")
        self.count = count
        self.interval_sec = interval_sec

    def stream_events(self) -> Generator[PacketEvent, None, None]:
        base_time = time.time()
        for i in range(self.count):
            t = base_time + i * self.interval_sec
            # Alternate between benign web session and periodic heartbeat
            if i % 10 == 0:
                # Periodic C2-like heartbeat
                yield PacketEvent(
                    timestamp=t,
                    length=120,
                    src_ip="10.0.0.55",
                    src_port=49800,
                    dst_ip="198.51.100.99",
                    dst_port=443,
                    protocol="TCP",
                    is_syn=False,
                    is_ack=True,
                    input_source=self.input_source,
                )
            else:
                # Normal web traffic
                yield PacketEvent(
                    timestamp=t,
                    length=500 + (i % 200),
                    src_ip="10.0.0.12",
                    src_port=52000 + (i % 10),
                    dst_ip="93.184.216.34",
                    dst_port=80,
                    protocol="TCP",
                    is_syn=(i % 5 == 0),
                    is_ack=True,
                    input_source=self.input_source,
                )
            if self.interval_sec > 0:
                time.sleep(self.interval_sec)


class DataDiodeFeedSource(PassiveInputSource):
    """
    Receive-Only Hardware Data Diode Ingestion Adapter.
    Represents the boundary interface receiving unidirectional traffic from a physical data diode.
    
    ARCHITECTURAL GUARANTEE:
    This adapter is strictly RECEIVE-ONLY. It exposes NO send(), transmit(), reply(),
    probe(), or reverse-channel methods. Physical enforcement occurs at the diode optical layer;
    this adapter enforces software-level receive-only semantics.
    """

    def __init__(
        self,
        queue_buffer: Optional[List[PacketEvent]] = None,
        listen_address: Optional[str] = None,
        listen_port: Optional[int] = None
    ):
        super().__init__(input_source="data_diode")
        # Correctly preserve caller's buffer reference when an empty list is passed
        self._buffer: List[PacketEvent] = queue_buffer if queue_buffer is not None else []
        self.listen_address = listen_address
        self.listen_port = listen_port

    def receive(self) -> Generator[PacketEvent, None, None]:
        """
        Yields packets incoming from the physical diode receive buffer.
        Zero capability to transmit packets back into the source network.
        """
        while self._buffer:
            yield self._buffer.pop(0)

    def stream_events(self) -> Generator[PacketEvent, None, None]:
        """Delegates strictly to receive()."""
        yield from self.receive()

    def ingest_diode_frame(self, frame: PacketEvent) -> None:
        """Internal enqueue hook from the physical NIC receive ring buffer."""
        frame.input_source = self.input_source
        self._buffer.append(frame)


class NetFlowSource(PassiveInputSource):
    """Receive-only collector interface for passive NetFlow v5/v9 datagrams."""

    def __init__(self):
        super().__init__(input_source="netflow")

    def stream_events(self) -> Generator[PacketEvent, None, None]:
        # Receive-only collector stub ready for enterprise telemetry ingestion
        return
        yield  # type: ignore


class IPFIXSource(PassiveInputSource):
    """Receive-only collector interface for passive IPFIX export streams."""

    def __init__(self):
        super().__init__(input_source="ipfix")

    def stream_events(self) -> Generator[PacketEvent, None, None]:
        return
        yield  # type: ignore


class SFlowSource(PassiveInputSource):
    """Receive-only collector interface for passive sFlow packet-sampling datagrams."""

    def __init__(self):
        super().__init__(input_source="sflow")

    def stream_events(self) -> Generator[PacketEvent, None, None]:
        return
        yield  # type: ignore
