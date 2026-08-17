"""End-to-end engine tests: background consumer thread, bounded history,
packet lookup and numbering."""
import time

from conftest import build

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether


def _make_engine(history=1000):
    from yaragon.engine import AnalysisEngine
    from yaragon.utils.config import Config
    cfg = Config()
    cfg.packet_history_limit = history
    return AnalysisEngine(cfg)


def _traffic():
    pkts = []
    for i in range(50):
        pkts.append(build(Ether() / IP(src="192.168.1.20", dst="1.2.3.4") /
                          TCP(sport=40000 + i, dport=80, flags="S", seq=i)))
        pkts.append(build(Ether() / IP(src="192.168.1.20", dst="8.8.8.8") /
                          UDP(sport=5000, dport=53) /
                          DNS(rd=1, qd=DNSQR(qname="example.com"))))
    return pkts


def test_engine_processes_and_counts():
    engine = _make_engine()
    engine.start()
    try:
        for p in _traffic():
            engine.enqueue(p)
        deadline = time.time() + 5
        while engine.total < 100 and time.time() < deadline:
            time.sleep(0.05)
        assert engine.total == 100
        # packets are classified and retrievable by number
        protocols = {r.protocol for r in engine.history()}
        assert "TCP" in protocols and "DNS" in protocols
        assert engine.get_packet(1) is not None
        assert engine.get_packet(1).raw != b""       # raw kept for inspector
    finally:
        engine.stop()


def test_bounded_history():
    engine = _make_engine(history=30)
    engine.start()
    try:
        for p in _traffic():
            engine.enqueue(p)
        time.sleep(1.0)
        # history is bounded to 30 even though 100 packets flowed through
        assert len(engine.history()) <= 30
    finally:
        engine.stop()


def _feed(engine, pkts):
    """Drive packets through the consumer path deterministically (no thread)."""
    for p in pkts:
        engine._process(p)


def test_numbering_is_monotonic_and_unique():
    engine = _make_engine()
    _feed(engine, _traffic())               # 100 packets
    numbers = [r.number for r in engine.history()]
    assert numbers == list(range(1, 101))   # 1..100, in order, no gaps
    assert len(set(numbers)) == len(numbers)
    assert engine.total == 100


def test_clear_resets_history_and_numbering():
    engine = _make_engine()
    _feed(engine, _traffic())
    assert engine.total == 100 and engine.history()
    engine.clear()
    assert engine.history() == []
    assert engine.total == 0
    assert engine.get_packet(1) is None
    assert engine.drain_new() == []
    # numbering restarts at 1 after a clear
    _feed(engine, _traffic()[:3])
    assert [r.number for r in engine.history()] == [1, 2, 3]


def test_get_packet_none_after_eviction():
    engine = _make_engine(history=30)
    _feed(engine, _traffic())               # 100 packets, keep last 30
    assert len(engine.history()) == 30
    assert engine.total == 100
    assert engine.get_packet(1) is None     # evicted
    assert engine.get_packet(100) is not None  # still resident
    # numbering stays monotonic across eviction
    assert engine.history()[-1].number == 100


def test_malformed_frame_does_not_break_numbering():
    """A frame that fails to parse is dropped without consuming a number."""
    engine = _make_engine()

    class Boom:
        # stand-in for a frame whose parse raises inside _consume
        pass
    good = _traffic()[:2]
    engine._process(good[0])
    try:
        engine._process(Boom())             # parser will raise
    except Exception:
        pass
    engine._process(good[1])
    # the failed frame consumed no number -> [1, 2], no gap
    assert [r.number for r in engine.history()] == [1, 2]


def test_load_records_replaces_history():
    """Opening a .pcap loads records into history, preserving their numbers."""
    from yaragon.analysis.packet_parser import PacketParser
    engine = _make_engine()
    _feed(engine, _traffic())               # live capture first
    assert engine.total == 100

    parser = PacketParser()
    loaded = []
    for i in range(5):
        rec = parser.parse(build(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") /
                                 TCP(sport=1000 + i, dport=80)))
        rec.number = i + 1
        loaded.append(rec)
    engine.load_records(loaded)

    assert engine.total == 5
    assert [r.number for r in engine.history()] == [1, 2, 3, 4, 5]
    assert engine.get_packet(3) is loaded[2]
    assert engine.get_packet(100) is None   # previous capture replaced


def test_load_records_over_limit_keeps_history_tail():
    """Opening a .pcap larger than the history limit keeps only the retained
    tail in history(); total is the highest resident number so a later live
    packet never gets a number that precedes a record still in history."""
    from yaragon.analysis.packet_parser import PacketParser
    engine = _make_engine(history=20)
    parser = PacketParser()
    loaded = []
    for i in range(100):
        rec = parser.parse(build(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") /
                                 TCP(sport=1000 + i, dport=80)))
        rec.number = i + 1
        loaded.append(rec)
    engine.load_records(loaded)

    hist = engine.history()
    assert len(hist) == 20                       # bounded tail only
    assert [r.number for r in hist] == list(range(81, 101))
    assert engine.total == 100                   # highest resident number
    # continuing a live capture numbers strictly after the resident tail
    engine._process(build(Ether() / IP(src="9.9.9.9", dst="8.8.8.8") /
                          TCP(sport=1, dport=2)))
    assert engine.history()[-1].number == 101


def test_load_records_over_limit_index_stays_consistent():
    """The lookup index must not outgrow the bounded history, and get_packet()
    must never return a record that history() has evicted - the invariant that
    _process() carefully maintains for live capture."""
    from yaragon.analysis.packet_parser import PacketParser
    engine = _make_engine(history=20)
    parser = PacketParser()
    loaded = []
    for i in range(100):
        rec = parser.parse(build(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") /
                                 TCP(sport=1000 + i, dport=80)))
        rec.number = i + 1
        loaded.append(rec)
    engine.load_records(loaded)

    # index bounded to the resident history
    assert len(engine._index) == len(engine.history())
    # an evicted number must not resolve to a stale record
    assert engine.get_packet(1) is None
    # and every resolvable record is actually in history
    assert engine.get_packet(100) in engine.history()
