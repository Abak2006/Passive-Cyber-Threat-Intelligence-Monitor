"""
Unit Tests for AEGIS Passive Input Sources.
Verifies strictly passive behavior, receive-only interfaces, streaming mechanics,
canonical input_source provenance, and DataDiodeFeedSource buffer preservation.
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
    assert source.input_source == "data_diode"
    assert source.source_type == "data_diode"
    assert hasattr(source, "stream_events")


def test_data_diode_buffer_reference_integrity():
    """
    Regression Test (Phase 2):
    1. Create an empty list as queue_buffer.
    2. Pass it to DataDiodeFeedSource.
    3. Append a PacketEvent to the original list.
    4. Verify the source sees the event (buffer reference not replaced with a fresh []).
    """
    external_buffer = []
    source = DataDiodeFeedSource(queue_buffer=external_buffer)

    # Append to caller's original list
    ev = PacketEvent(
        timestamp=100.0,
        length=64,
        src_ip="10.0.0.1",
        src_port=1234,
        dst_ip="10.0.0.2",
        dst_port=80,
        protocol="TCP",
        input_source="data_diode"
    )
    external_buffer.append(ev)

    # Verify source streams the appended event
    streamed = list(source.stream_events())
    assert len(streamed) == 1
    assert streamed[0].src_ip == "10.0.0.1"
    assert streamed[0].input_source == "data_diode"


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
        input_source="pcap_replay",
    )
    d = event.to_dict()
    assert d["src_ip"] == "192.168.1.10"
    assert d["dst_port"] == 443
    assert d["is_syn"] is True
    assert d["input_source"] == "pcap_replay"
    assert d["source_type"] == "pcap_replay"
    assert d["length"] == 1400


def test_synthetic_stream_source():
    count = 50
    source = SyntheticStreamSource(count=count, interval_sec=0.0)
    assert source.input_source == "synthetic_stream"
    assert source.source_type == "synthetic_stream"

    events = list(source.stream_events())
    assert len(events) == count

    for ev in events:
        assert isinstance(ev, PacketEvent)
        assert ev.input_source == "synthetic_stream"
        assert ev.source_type == "synthetic_stream"
        assert ev.src_ip is not None
        assert ev.dst_ip is not None
        assert ev.length > 0


def test_pcap_replay_source():
    pcap_path = "data/sample/demo.pcap"
    if not Path(pcap_path).exists():
        pytest.skip(f"Sample PCAP {pcap_path} not present")

    source = PcapReplaySource(pcap_path=pcap_path, speed=0.0)
    assert source.input_source == "pcap_replay"
    assert source.source_type == "pcap_replay"

    events = []
    for ev in source.stream_events():
        events.append(ev)
        if len(events) >= 20:
            break

    assert len(events) == 20
    assert all(isinstance(e, PacketEvent) for e in events)
    assert all(e.input_source == "pcap_replay" for e in events)
    assert all(e.source_type == "pcap_replay" for e in events)
