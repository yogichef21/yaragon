"""Lazy decoded tree: the live path parses the cheap summary (protocol / info /
meta / ports) for every packet but does NOT build the heavy nested inspector
tree - that is built on demand from the frame bytes when a packet is selected.
This keeps a large history cheap without losing any inspector detail.
"""
from conftest import build
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from yaragon.analysis.packet_parser import PacketParser, detail_tree_from_raw


def _http(parser):
    pkt = (Ether() / IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=40000, dport=80,
                                                              flags="PA")
           / Raw(load=b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
    return pkt


def test_build_tree_false_skips_tree_but_keeps_summary(parser):
    pkt = _http(parser)
    rec = PacketParser().parse(build(pkt), build_tree=False)
    assert rec.detail_tree == []          # heavy tree not retained
    assert rec.protocol == "HTTP"         # cheap summary still extracted
    assert rec.src_port == 40000
    assert "http" in rec.meta             # metadata still available


def test_default_still_builds_tree(parser):
    """Default behaviour is unchanged - every existing caller/test still gets the
    full decoded tree."""
    rec = PacketParser().parse(build(_http(parser)))
    assert rec.detail_tree                # non-empty


def test_tree_rebuilds_from_raw_on_demand(parser):
    pkt = build(_http(parser))
    lazy = PacketParser().parse(pkt, build_tree=False)
    eager = PacketParser().parse(pkt)     # full tree
    rebuilt = detail_tree_from_raw(lazy.raw)
    # the on-demand tree matches the eagerly-built one
    assert rebuilt == eager.detail_tree
    assert rebuilt   # non-empty
