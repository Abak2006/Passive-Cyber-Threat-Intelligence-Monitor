"""
Stateful Sliding-Window Flow Assembler and Session Stream Manager.
Aggregates packet streams into bidirectional flows without retaining full payloads.
"""

from collections import defaultdict, deque
import time
from typing import Any, Dict, Generator, List, Optional, Set, Tuple

from app.alerts.schema import FlowRecord
from app.features.tls_features import TLSFeatureExtractor


def canonical_flow_id(src_ip: str, src_port: int, dst_ip: str, dst_port: int, protocol: str) -> str:
    """Deterministic bidirectional flow identifier."""
    if (src_ip, src_port) <= (dst_ip, dst_port):
        return f"{protocol}:{src_ip}:{src_port}<->{dst_ip}:{dst_port}"
    return f"{protocol}:{dst_ip}:{dst_port}<->{src_ip}:{src_port}"


class FlowState:
    """Internal state tracking a single bidirectional flow."""

    def __init__(self, packet: Dict[str, Any]):
        self.flow_id = canonical_flow_id(
            packet["src_ip"], packet["src_port"],
            packet["dst_ip"], packet["dst_port"],
            packet["protocol"]
        )
        self.init_src_ip = packet["src_ip"]
        self.init_src_port = packet["src_port"]
        self.init_dst_ip = packet["dst_ip"]
        self.init_dst_port = packet["dst_port"]
        self.protocol = packet["protocol"]

        self.start_time = packet["timestamp"]
        self.last_time = packet["timestamp"]

        self.forward_packets = 0
        self.backward_packets = 0
        self.forward_bytes = 0
        self.backward_bytes = 0

        self.timestamps: List[float] = []
        self.packet_lengths: List[int] = []

        self.syn_count = 0
        self.ack_count = 0
        self.fin_count = 0
        self.rst_count = 0

        # Protocol metadata
        self.dns_queries: List[str] = []
        self.tls_metadata: Optional[Dict[str, Any]] = None

        self.add_packet(packet)

    def add_packet(self, packet: Dict[str, Any]):
        ts = packet["timestamp"]
        length = packet["length"]
        self.last_time = max(self.last_time, ts)
        self.timestamps.append(ts)
        self.packet_lengths.append(length)

        # Direction check
        if packet["src_ip"] == self.init_src_ip and packet["src_port"] == self.init_src_port:
            self.forward_packets += 1
            self.forward_bytes += length
        else:
            self.backward_packets += 1
            self.backward_bytes += length

        if packet.get("is_syn"):
            self.syn_count += 1
        if packet.get("is_ack"):
            self.ack_count += 1
        if packet.get("is_fin"):
            self.fin_count += 1
        if packet.get("is_rst"):
            self.rst_count += 1

        if packet.get("dns_query"):
            self.dns_queries.append(packet["dns_query"])

        # Passive TLS parsing on initial handshake
        if not self.tls_metadata and packet.get("payload_bytes"):
            tls_meta = TLSFeatureExtractor.parse_client_hello(packet["payload_bytes"])
            if tls_meta:
                self.tls_metadata = tls_meta

    @property
    def duration(self) -> float:
        return max(0.0001, self.last_time - self.start_time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "flow_id": self.flow_id,
            "src_ip": self.init_src_ip,
            "src_port": self.init_src_port,
            "dst_ip": self.init_dst_ip,
            "dst_port": self.init_dst_port,
            "protocol": self.protocol,
            "start_time": self.start_time,
            "end_time": self.last_time,
            "duration": self.duration,
            "forward_packets": self.forward_packets,
            "backward_packets": self.backward_packets,
            "forward_bytes": self.forward_bytes,
            "backward_bytes": self.backward_bytes,
            "total_packets": self.forward_packets + self.backward_packets,
            "total_bytes": self.forward_bytes + self.backward_bytes,
            "timestamps": self.timestamps,
            "packet_lengths": self.packet_lengths,
            "syn_count": self.syn_count,
            "ack_count": self.ack_count,
            "fin_count": self.fin_count,
            "rst_count": self.rst_count,
            "dns_queries": self.dns_queries,
            "tls_metadata": self.tls_metadata,
        }

    def to_flow_record(self) -> FlowRecord:
        return FlowRecord(
            flow_id=self.flow_id,
            start_time=self.start_time,
            end_time=self.last_time,
            src_ip=self.init_src_ip,
            src_port=self.init_src_port,
            dst_ip=self.init_dst_ip,
            dst_port=self.init_dst_port,
            protocol=self.protocol,
            packet_count=self.forward_packets + self.backward_packets,
            byte_count=self.forward_bytes + self.backward_bytes,
            duration_sec=round(self.duration, 4),
            forward_packets=self.forward_packets,
            backward_packets=self.backward_packets,
            forward_bytes=self.forward_bytes,
            backward_bytes=self.backward_bytes,
        )


class FlowStreamManager:
    """
    Manages active flows and sliding time-window network state.
    Emits completed or expired flows incrementally.
    """

    def __init__(self, flow_timeout_sec: float = 15.0, sliding_window_sec: float = 10.0):
        self.flow_timeout_sec = flow_timeout_sec
        self.sliding_window_sec = sliding_window_sec
        self.active_flows: Dict[str, FlowState] = {}
        self.current_time: float = 0.0

        # Global sliding window stats for network-wide threat correlation
        # Destination -> deque of (timestamp, src_ip, is_syn)
        self.dest_syn_window = defaultdict(deque)
        # Source -> deque of (timestamp, dst_ip, dst_port, is_syn)
        self.src_scan_window = defaultdict(deque)
        # Apex domain -> deque of (timestamp, full_subdomain)
        self.dns_tunnel_window = defaultdict(deque)
        # (src_ip, dst_ip) -> deque of connection start timestamps (for C2 beaconing)
        self.host_pair_connections = defaultdict(deque)

    def process_packet(self, packet: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Process incoming packet. Returns:
        - active flow state snapshot
        - list of expired flow states ready for final evaluation
        """
        ts = packet["timestamp"]
        self.current_time = max(self.current_time, ts)

        flow_id = canonical_flow_id(
            packet["src_ip"], packet["src_port"],
            packet["dst_ip"], packet["dst_port"],
            packet["protocol"]
        )

        # Update sliding window structures
        self._update_sliding_windows(packet)

        if flow_id in self.active_flows:
            flow = self.active_flows[flow_id]
            flow.add_packet(packet)
        else:
            flow = FlowState(packet)
            self.active_flows[flow_id] = flow
            # Track connection initiation for beaconing
            self.host_pair_connections[(packet["src_ip"], packet["dst_ip"])].append(ts)

        expired_flows = []
        # Early expiration on TCP teardown (FIN/RST)
        if packet.get("is_fin") or packet.get("is_rst"):
            expired = self.active_flows.pop(flow_id, None)
            if expired:
                expired_flows.append(expired.to_dict())

        # Check periodic timeout expiration
        expired_flows.extend(self._check_timeouts(self.current_time))

        return flow.to_dict(), expired_flows

    def _update_sliding_windows(self, packet: Dict[str, Any]):
        ts = packet["timestamp"]
        cutoff = ts - self.sliding_window_sec

        # 1. Destination DDoS tracker
        dst = packet["dst_ip"]
        self.dest_syn_window[dst].append((ts, packet["src_ip"], packet.get("is_syn", False), packet["protocol"]))
        while self.dest_syn_window[dst] and self.dest_syn_window[dst][0][0] < cutoff:
            self.dest_syn_window[dst].popleft()

        # 2. Source Recon / Scan tracker
        src = packet["src_ip"]
        self.src_scan_window[src].append((ts, packet["dst_ip"], packet["dst_port"], packet.get("is_syn", False)))
        while self.src_scan_window[src] and self.src_scan_window[src][0][0] < cutoff:
            self.src_scan_window[src].popleft()

        # 3. DNS Tunnel tracker
        if packet.get("dns_query"):
            domain = packet["dns_query"].lower()
            parts = domain.split(".")
            apex = ".".join(parts[-2:]) if len(parts) >= 2 else domain
            self.dns_tunnel_window[apex].append((ts, domain))
            while self.dns_tunnel_window[apex] and self.dns_tunnel_window[apex][0][0] < cutoff:
                self.dns_tunnel_window[apex].popleft()

    def _check_timeouts(self, now: float) -> List[Dict[str, Any]]:
        expired = []
        timeout_cutoff = now - self.flow_timeout_sec
        to_delete = []

        for flow_id, flow in self.active_flows.items():
            if flow.last_time < timeout_cutoff:
                to_delete.append(flow_id)
                expired.append(flow.to_dict())

        for fid in to_delete:
            del self.active_flows[fid]

        return expired

    def flush_all(self) -> List[Dict[str, Any]]:
        """Flush and return all remaining active flows at end of stream."""
        remaining = [f.to_dict() for f in self.active_flows.values()]
        self.active_flows.clear()
        return remaining

    def get_destination_ddos_context(self, dst_ip: str) -> Dict[str, Any]:
        """Provides sliding-window DDoS context for a given destination."""
        window = self.dest_syn_window.get(dst_ip, [])
        if not window:
            return {"syn_rate": 0.0, "udp_rate": 0.0, "packet_rate": 0.0, "unique_sources": 0, "source_ips": []}

        syn_count = sum(1 for item in window if item[2])
        udp_count = sum(1 for item in window if item[3] == "UDP")
        unique_srcs = list(set(item[1] for item in window))
        duration = max(0.1, self.sliding_window_sec)

        return {
            "syn_rate": round(syn_count / duration, 2),
            "udp_rate": round(udp_count / duration, 2),
            "packet_rate": round(len(window) / duration, 2),
            "unique_sources": len(unique_srcs),
            "source_ips": unique_srcs,
        }

    def get_source_scan_context(self, src_ip: str) -> Dict[str, Any]:
        """Provides sliding-window Recon/Scan context for a given source."""
        window = self.src_scan_window.get(src_ip, [])
        if not window:
            return {"unique_dst_ips": 0, "unique_dst_ports": 0, "connections_per_sec": 0.0}

        dst_ips = set(item[1] for item in window)
        dst_ports = set(item[2] for item in window)
        duration = max(0.1, self.sliding_window_sec)

        return {
            "unique_dst_ips": len(dst_ips),
            "unique_dst_ports": len(dst_ports),
            "connections_per_sec": round(len(window) / duration, 2),
            "raw_dst_ips": list(dst_ips),
            "raw_dst_ports": list(dst_ports),
        }

    def get_dns_tunnel_context(self, apex_domain: str) -> Dict[str, Any]:
        """Provides sliding-window DNS query statistics for an apex domain."""
        window = self.dns_tunnel_window.get(apex_domain, [])
        if not window:
            return {"query_count": 0, "unique_subdomains": 0, "query_rate": 0.0, "queries": []}

        queries = [item[1] for item in window]
        unique_subdomains = set(queries)
        duration = max(0.1, self.sliding_window_sec)

        return {
            "query_count": len(queries),
            "unique_subdomains": len(unique_subdomains),
            "query_rate": round(len(queries) / duration, 2),
            "queries": queries,
        }

    def get_host_pair_connection_times(self, src_ip: str, dst_ip: str) -> List[float]:
        """Returns recorded connection timestamps between a host pair for beaconing analysis."""
        deque_ts = self.host_pair_connections.get((src_ip, dst_ip), [])
        return list(deque_ts)
