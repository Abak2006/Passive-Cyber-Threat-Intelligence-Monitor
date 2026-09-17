"""
Unit Tests for AEGIS Passive Input Sources.
Verifies strictly passive behavior, receive-only interfaces, and streaming mechanics.
"""

from pathlib import Path
import pytest

from app.ingest.sources import (
    DataDiodeFeedSource,
    PassiveInputSource,
    PacketEvent,
    PcapReplaySource,
    SyntheticStreamSource,
)


def test_data_diode_feed_source_passive_contract():
    """
    CRITICAL SECURITY INVARIANT:
    DataDiodeFeedSource represents an endpoint receiving data across an optical hardware diode.
    It must NEVER implement or expose any transmission, sending, or active probing methods.
    """
    forbidden_method_substrings = [
        "send", "transmit", "reply", "probe", "write", "connect", "push", "upload"
    ]

    source_attrs = dir(DataDiodeFeedSource)
    for attr in source_attrs:
        attr_lower = attr.lower()
        for forbidden in forbidden_method_substrings:
            assert forbidden not in attr_lower, (
                f"DataDiodeFeedSource violates passive diode guarantee by exposing: {attr}"
            )

    source = DataDiodeFeedSource(listen_address="127.0.0.1", listen_port=9999)
    assert source.source_type == "data_diode_feed"
    assert hasattr(source, "stream_events")


def test_packet_event_structure():
    event = PacketEvent(
        timestamp=1000.0,
        length=1400,
        src_ip="192.168.1.10",
        src_port=54321,
        dst_ip="10.0.0.1",
        dst_port=443,
        protocol="TCP",
        is_syn=True,
        is_ack=False,
        payload_bytes=b"\x16\x03\x01",
        source_type="pcap_replay",
    )
    d = event.to_dict()
    assert d["src_ip"] == "192.168.1.10"
    assert d["dst_port"] == 443
    assert d["is_syn"] is True
    assert d["source_type"] == "pcap_replay"
    assert d["length"] == 1400


def test_synthetic_stream_source():
    count = 50
    source = SyntheticStreamSource(count=count, interval_sec=0.0)
    assert source.source_type == "synthetic_stream"

    events = list(source.stream_events())
    assert len(events) == count

    for ev in events:
        assert isinstance(ev, PacketEvent)
        assert ev.source_type == "synthetic_stream"
        assert ev.src_ip is not None
        assert ev.dst_ip is not None
        assert ev.length > 0


def test_pcap_replay_source():
    pcap_path = "data/sample/demo.pcap"
    if not Path(pcap_path).exists():
        pytest.skip(f"Sample PCAP {pcap_path} not present")

    source = PcapReplaySource(pcap_path=pcap_path, speed=0.0)
    assert source.source_type == "pcap_replay"

    events = []
    for ev in source.stream_events():
        events.append(ev)
        if len(events) >= 20:
            break

    assert len(events) == 20
    assert all(isinstance(e, PacketEvent) for e in events)
    assert all(e.source_type == "pcap_replay" for e in events)
