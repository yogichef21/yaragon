"""Conversation aggregation: turn a flat packet history into per-endpoint-pair
flows (the SELECT-what-to-investigate step). Pure and Qt-free.
"""
from conftest import build
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether

from yaragon.analysis.conversations import build_conversations


def _tcp(parser, src, dst, sport, dport, n):
    out = []
    for i in range(n):
        pkt = Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport,
                                                   flags="PA", seq=i + 1)
        out.append(parser.parse(build(pkt)))
    return out


def test_two_directions_collapse_into_one_conversation(parser):
    recs = _tcp(parser, "10.0.0.2", "10.0.0.1", 40000, 80, 6)
    recs += _tcp(parser, "10.0.0.1", "10.0.0.2", 80, 40000, 4)
    convs = build_conversations(recs)
    assert len(convs) == 1
    c = convs[0]
    assert {c.a, c.b} == {"10.0.0.1", "10.0.0.2"}
    assert c.packets == 10
    assert c.a_to_b + c.b_to_a == 10
    assert "TCP" in c.protocols
    assert 80 in c.ports


def test_distinct_pairs_are_separate_conversations(parser):
    recs = _tcp(parser, "10.0.0.2", "10.0.0.1", 40000, 80, 3)
    recs += _tcp(parser, "10.0.0.3", "10.0.0.1", 40001, 443, 5)
    convs = build_conversations(recs)
    assert len(convs) == 2
    by_pkts = sorted(convs, key=lambda c: c.packets)
    assert by_pkts[0].packets == 3
    assert by_pkts[1].packets == 5


def test_conversations_sorted_by_packets_desc(parser):
    recs = _tcp(parser, "10.0.0.2", "10.0.0.1", 40000, 80, 2)
    recs += _tcp(parser, "10.0.0.3", "10.0.0.1", 40001, 443, 9)
    convs = build_conversations(recs)
    assert convs[0].packets == 9      # heaviest flow first (triage order)
    assert convs[-1].packets == 2


def test_bytes_and_duration_are_tracked(parser):
    recs = _tcp(parser, "10.0.0.2", "10.0.0.1", 40000, 80, 3)
    for r, ts in zip(recs, (100.0, 101.0, 102.5)):
        r.timestamp = ts
    convs = build_conversations(recs)
    c = convs[0]
    assert c.bytes > 0
    assert c.duration == 2.5


def test_udp_and_endpoints_without_ip_are_handled(parser):
    recs = [parser.parse(build(Ether() / IP(src="10.0.0.2", dst="10.0.0.1") /
                                UDP(sport=5353, dport=5353)))]
    convs = build_conversations(recs)
    assert len(convs) == 1
    assert "UDP" in convs[0].protocols
