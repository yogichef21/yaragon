"""The engine is the authoritative history; investigation queries run over ALL of
it, not the smaller display window. These lock the read-only query API and the
review's W-D fix (search must not silently miss packets held in history).
"""
import os

os.environ["QT_QPA_PLATFORM"] = "offscreen"

from conftest import build
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from PySide6.QtWidgets import QApplication

from yaragon.engine import AnalysisEngine
from yaragon.utils.config import Config

_app = QApplication.instance() or QApplication([])


def _rec(parser, src, dst, dport, num):
    pkt = Ether() / IP(src=src, dst=dst) / TCP(sport=40000, dport=dport, flags="PA")
    r = parser.parse(build(pkt), num)
    r.number = num
    return r


def test_engine_conversations_over_history(parser):
    eng = AnalysisEngine(Config())
    recs = [_rec(parser, "10.0.0.2", "10.0.0.1", 80, i + 1) for i in range(4)]
    recs += [_rec(parser, "10.0.0.3", "10.0.0.1", 443, i + 5) for i in range(6)]
    eng.load_records(recs)
    convs = eng.conversations()
    assert len(convs) == 2
    assert convs[0].packets == 6           # heaviest first


def test_engine_conversation_packets_both_directions(parser):
    eng = AnalysisEngine(Config())
    recs = [_rec(parser, "10.0.0.2", "10.0.0.1", 80, 1),
            _rec(parser, "10.0.0.1", "10.0.0.2", 40000, 2)]
    eng.load_records(recs)
    pkts = eng.conversation_packets("10.0.0.2", "10.0.0.1")
    assert len(pkts) == 2


def test_engine_target_intel_over_history(parser):
    eng = AnalysisEngine(Config())
    recs = [_rec(parser, "10.0.0.2", "10.0.0.1", 80, 1)]
    eng.load_records(recs)
    intel = eng.target_intel("10.0.0.2")
    assert intel.packets == 1
    assert "10.0.0.1" in intel.peers


def test_search_finds_packets_beyond_the_old_display_window(parser):
    """W-D regression: a record held in the authoritative history must be found
    even though it is far past the old 5000-row display cap."""
    cfg = Config()
    cfg.packet_history_limit = 6000
    eng = AnalysisEngine(cfg)
    recs = [_rec(parser, "10.0.0.2", "10.0.0.9", 80, i + 1) for i in range(5500)]
    # one needle near the front, well past a 5000-row display window from the end
    recs[10] = _rec(parser, "10.0.0.2", "10.0.0.42", 8443, 11)
    eng.load_records(recs)
    pkts = eng.conversation_packets("10.0.0.2", "10.0.0.42")
    assert len(pkts) == 1
    assert pkts[0].dst_ip == "10.0.0.42"


def test_l2_only_conversation_is_followable(parser):
    """A flow keyed on MAC (IP-less L2 frame) is both listed AND followable -
    the aggregate and follow paths share one endpoint identity (no dead rows)."""
    from scapy.layers.l2 import Ether
    from scapy.packet import Raw
    eng = AnalysisEngine(Config())
    pkt = Ether(src="02:00:00:00:00:aa", dst="02:00:00:00:00:bb") / Raw(load=b"\x00\x01")
    rec = parser.parse(build(pkt), 1)
    rec.number = 1
    eng.load_records([rec])
    convs = eng.conversations()
    assert convs                                  # the L2 flow is listed
    c = convs[0]
    pkts = eng.conversation_packets(c.a, c.b)     # ...and can be opened
    assert len(pkts) == 1


def test_traffic_table_cap_matches_history_limit():
    """The display model must hold the full authoritative history so a filter over
    the table cannot miss a packet the engine still holds (W-D)."""
    from yaragon.gui.main_window import MainWindow
    cfg = Config()
    mw = MainWindow(cfg)
    try:
        assert mw.traffic.model._rows.maxlen == cfg.packet_history_limit
    finally:
        mw.close()
