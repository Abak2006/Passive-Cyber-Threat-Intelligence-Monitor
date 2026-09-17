"""
Passive Flow Feature Extraction Engine.
Aggregates bidirectional packet statistics, rate metrics, and packet length distributions.
"""

from typing import Any, Dict, List, Optional
import numpy as np


class FlowFeatureExtractor:
    """Extracts statistical and behavioral features from an individual flow."""

    @staticmethod
    def extract_features(flow_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Takes raw flow aggregation dictionary and returns normalized flow features.
        """
        duration = max(0.0001, flow_dict.get("duration", 0.0))
        fwd_pkts = flow_dict.get("forward_packets", 0)
        bwd_pkts = flow_dict.get("backward_packets", 0)
        total_pkts = fwd_pkts + bwd_pkts

        fwd_bytes = flow_dict.get("forward_bytes", 0)
        bwd_bytes = flow_dict.get("backward_bytes", 0)
        total_bytes = fwd_bytes + bwd_bytes

        pkt_lengths = flow_dict.get("packet_lengths", [])
        if pkt_lengths:
            arr_lens = np.array(pkt_lengths, dtype=np.float64)
            mean_pkt_len = float(np.mean(arr_lens))
            std_pkt_len = float(np.std(arr_lens))
            min_pkt_len = float(np.min(arr_lens))
            max_pkt_len = float(np.max(arr_lens))
        else:
            mean_pkt_len = std_pkt_len = min_pkt_len = max_pkt_len = 0.0

        # TCP flags
        syn_count = flow_dict.get("syn_count", 0)
        ack_count = flow_dict.get("ack_count", 0)
        rst_count = flow_dict.get("rst_count", 0)
        fin_count = flow_dict.get("fin_count", 0)

        # Directional ratios
        out_in_byte_ratio = float(fwd_bytes) / float(bwd_bytes + 1)
        out_in_pkt_ratio = float(fwd_pkts) / float(bwd_pkts + 1)
        syn_ack_ratio = float(syn_count) / float(ack_count + 1)

        features = {
            "flow_id": flow_dict.get("flow_id", ""),
            "src_ip": flow_dict.get("src_ip", ""),
            "src_port": flow_dict.get("src_port", 0),
            "dst_ip": flow_dict.get("dst_ip", ""),
            "dst_port": flow_dict.get("dst_port", 0),
            "protocol": flow_dict.get("protocol", "TCP"),
            "input_source": flow_dict.get("input_source", flow_dict.get("source_type", "pcap_replay")),
            "source_type": flow_dict.get("source_type", flow_dict.get("input_source", "pcap_replay")),
            "start_time": flow_dict.get("start_time", 0.0),
            "end_time": flow_dict.get("end_time", flow_dict.get("last_time", 0.0)),
            "duration": round(duration, 4),
            "total_packets": total_pkts,
            "total_bytes": total_bytes,
            "packets_per_sec": round(total_pkts / duration, 2),
            "bytes_per_sec": round(total_bytes / duration, 2),
            "forward_packets": fwd_pkts,
            "backward_packets": bwd_pkts,
            "forward_bytes": fwd_bytes,
            "backward_bytes": bwd_bytes,
            "outbound_inbound_byte_ratio": round(out_in_byte_ratio, 4),
            "outbound_inbound_pkt_ratio": round(out_in_pkt_ratio, 4),
            "mean_packet_size": round(mean_pkt_len, 2),
            "std_packet_size": round(std_pkt_len, 2),
            "min_packet_size": round(min_pkt_len, 2),
            "max_packet_size": round(max_pkt_len, 2),
            "syn_count": syn_count,
            "ack_count": ack_count,
            "rst_count": rst_count,
            "fin_count": fin_count,
            "syn_ack_ratio": round(syn_ack_ratio, 4),
            "is_short_flow": duration < 0.5 and total_pkts <= 3,
            "is_syn_only": syn_count > 0 and ack_count == 0,
        }

        return features
