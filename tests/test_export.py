"""pcap export tests: verify a real, reopenable capture file is produced and
that packet bytes and timestamps are preserved."""
from conftest import build
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether

from yaragon.analysis.packet_parser import PacketParser
from yaragon.storage.exporter import export_pcap, import_pcap


def _records(n=10):
    parser = PacketParser()
    out = []
    for i in range(n):
        pkt = (Ether() / IP(src="10.0.0.5", dst="10.0.0.9")
               / TCP(sport=1000 + i, dport=80))
        rec = parser.parse(build(pkt), i + 1)
        rec.timestamp = 1_700_000_000.0 + i     # deterministic capture time
        out.append(rec)
    return out


def test_export_writes_reopenable_pcap(tmp_path):
    from scapy.utils import rdpcap

    recs = _records(10)
    out = tmp_path / "capture.pcap"
    written = export_pcap(recs, str(out))

    assert written == 10
    assert out.exists() and out.stat().st_size > 0

    read_back = rdpcap(str(out))
    assert len(read_back) == 10
    # bytes preserved exactly
    assert bytes(read_back[0]) == recs[0].raw
    # timestamps preserved
    assert abs(float(read_back[0].time) - recs[0].timestamp) < 1e-6
    assert abs(float(read_back[9].time) - recs[9].timestamp) < 1e-6


def test_export_skips_records_without_raw_bytes(tmp_path):
    recs = _records(3)
    recs[1].raw = b""                    # simulate a record with no bytes
    out = tmp_path / "partial.pcap"
    assert export_pcap(recs, str(out)) == 2


def test_export_empty_is_graceful(tmp_path):
    from scapy.utils import rdpcap

    out = tmp_path / "empty.pcap"
    assert export_pcap([], str(out)) == 0
    assert out.exists()
    assert len(rdpcap(str(out))) == 0


def test_export_preserves_udp_packet_fields(tmp_path):
    from scapy.utils import rdpcap

    parser = PacketParser()
    pkt = Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / UDP(sport=5353, dport=53)
    rec = parser.parse(build(pkt), 1)
    out = tmp_path / "udp.pcap"
    export_pcap([rec], str(out))

    got = rdpcap(str(out))[0]
    assert got.haslayer(UDP)
    assert got[UDP].sport == 5353
    assert got[UDP].dport == 53


def test_import_pcap_roundtrip(tmp_path):
    """A .pcap written by export_pcap re-imports with matching count, protocols
    and monotonic numbers 1..N (item 3: Open .pcap)."""
    recs = _records(10)
    out = tmp_path / "roundtrip.pcap"
    export_pcap(recs, str(out))

    imported = import_pcap(str(out))
    assert len(imported) == len(recs)
    assert [r.number for r in imported] == list(range(1, len(recs) + 1))
    assert [r.protocol for r in imported] == [r.protocol for r in recs]
    # capture time is preserved from the pcap frame
    assert abs(imported[0].timestamp - recs[0].timestamp) < 1e-6


def test_import_pcap_of_empty_file_is_empty(tmp_path):
    """Round-trip of a zero-packet capture: export produces a valid file and
    import reads back zero records without raising."""
    out = tmp_path / "empty.pcap"
    export_pcap([], str(out))
    assert import_pcap(str(out)) == []


def test_import_pcap_skips_unparseable_frames(tmp_path, monkeypatch):
    """One frame that fails to parse must be skipped, not abort the whole open -
    mirroring the live engine. Surviving frames keep gap-free 1..N numbering."""
    recs = _records(5)
    out = tmp_path / "mixed.pcap"
    export_pcap(recs, str(out))

    real_parse = PacketParser.parse
    calls = {"n": 0}

    def flaky_parse(self, pkt, number=0, build_tree=True):
        calls["n"] += 1
        if calls["n"] == 3:                 # blow up on the third frame only
            raise ValueError("boom")
        return real_parse(self, pkt, number, build_tree)

    # import_pcap does a local `from ...packet_parser import PacketParser`, so it
    # resolves the same class object - patching the class attribute takes effect.
    monkeypatch.setattr(PacketParser, "parse", flaky_parse)
    imported = import_pcap(str(out))
    assert len(imported) == 4                # 5 frames, 1 skipped
    assert [r.number for r in imported] == [1, 2, 3, 4]   # renumbered, no gap


def test_export_roundtrip_large_capture_is_lossless(tmp_path):
    """A bounded-large capture (2000 frames) round-trips with every frame's bytes
    and packet number preserved 1..N - no truncation or reordering."""
    recs = _records(2000)
    out = tmp_path / "large.pcap"
    assert export_pcap(recs, str(out)) == 2000

    imported = import_pcap(str(out))
    assert len(imported) == 2000
    assert [r.number for r in imported] == list(range(1, 2001))
    # spot-check byte-exact fidelity at both ends and the middle
    for i in (0, 999, 1999):
        assert imported[i].raw == recs[i].raw


def test_import_pcap_truncates_at_frame_cap(tmp_path):
    """A12: a file with more frames than the cap yields exactly `max_frames`
    records via the streaming reader (not OOM), numbered gap-free 1..cap."""
    recs = _records(50)
    out = tmp_path / "big.pcap"
    export_pcap(recs, str(out))

    imported = import_pcap(str(out), max_frames=10)
    assert len(imported) == 10
    assert [r.number for r in imported] == list(range(1, 11))
    # the retained frames are the first ten, byte-exact
    assert imported[0].raw == recs[0].raw
    assert imported[9].raw == recs[9].raw


def test_export_from_engine_history_is_bounded(tmp_path):
    """End-to-end: only the packets still in the bounded history carry raw bytes
    and can be exported. This pins the documented behaviour that an export of a
    capture larger than the history limit contains just the retained tail."""
    from scapy.utils import rdpcap
    from yaragon.engine import AnalysisEngine
    from yaragon.utils.config import Config

    cfg = Config()
    cfg.packet_history_limit = 20
    engine = AnalysisEngine(cfg)
    for i in range(100):
        pkt = Ether() / IP(src="10.0.0.5", dst="10.0.0.9") / TCP(sport=1000 + i, dport=80)
        engine._process(build(pkt))

    assert engine.total == 100
    records = engine.history()
    assert len(records) == 20                       # bounded tail only

    out = tmp_path / "engine.pcap"
    written = export_pcap(records, str(out))
    assert written == 20
    assert len(rdpcap(str(out))) == 20
