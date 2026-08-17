"""Core parser tests: Ethernet, IPv4, IPv6, UDP, ICMP, ICMPv6 and the record
data model."""
from conftest import build

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import ICMPv6EchoRequest, IPv6
from scapy.layers.l2 import Ether


def test_ethernet_fields(parser):
    pkt = build(Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02") /
                IP(src="10.0.0.1", dst="10.0.0.2") / UDP())
    rec = parser.parse(pkt, 1)
    assert rec.src_mac == "aa:bb:cc:dd:ee:01"
    assert rec.dst_mac == "aa:bb:cc:dd:ee:02"
    assert rec.ethertype == 0x0800


def test_ipv4_fields(parser):
    pkt = build(Ether() / IP(src="192.168.1.10", dst="192.168.1.20", ttl=64) / UDP())
    rec = parser.parse(pkt, 2)
    assert rec.ip_version == 4
    assert rec.src_ip == "192.168.1.10"
    assert rec.dst_ip == "192.168.1.20"
    assert rec.ttl == 64


def test_ipv6_fields(parser):
    pkt = build(Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2") / UDP())
    rec = parser.parse(pkt, 3)
    assert rec.ip_version == 6
    assert rec.src_ip == "2001:db8::1"


def test_icmp(parser):
    pkt = build(Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / ICMP(type=8))
    rec = parser.parse(pkt, 4)
    assert rec.protocol == "ICMP"
    assert "Echo Request" in rec.info


def test_icmpv6(parser):
    pkt = build(Ether() / IPv6(src="fe80::1", dst="fe80::2") / ICMPv6EchoRequest())
    rec = parser.parse(pkt, 5)
    assert rec.protocol == "ICMPv6"


def test_udp_ports(parser):
    pkt = build(Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / UDP(sport=1234, dport=5678))
    rec = parser.parse(pkt, 6)
    assert rec.src_port == 1234 and rec.dst_port == 5678


def test_raw_bytes_captured_for_inspector(parser):
    pkt = build(Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / UDP(sport=1, dport=2))
    rec = parser.parse(pkt)
    assert isinstance(rec.raw, bytes) and len(rec.raw) == rec.length


def test_hexdump_helper():
    from yaragon.analysis.model import hexdump
    data = bytes(range(0, 32))
    dump = hexdump(data)
    assert "00000000" in dump                 # offset column
    assert "00 01 02 03" in dump               # hex column
    assert hexdump(b"") == "(no bytes captured)"


def test_tcp_flags_string(parser):
    pkt = build(Ether() / IP(src="1.1.1.1", dst="2.2.2.2") /
                TCP(sport=1, dport=2, flags="SA"))
    rec = parser.parse(pkt, 1)
    assert rec.tcp_flags == "SA"                 # displayed exactly as decoded
    assert rec.protocol == "TCP"


def test_payload_len_strips_ethernet_padding(parser):
    # A bare SYN is smaller than the 60-byte Ethernet minimum, so the wire frame
    # carries padding. The parser must not count that padding as TCP payload.
    pkt = build(Ether() / IP(src="1.1.1.1", dst="2.2.2.2") /
                TCP(sport=1, dport=2, flags="S"))
    rec = parser.parse(pkt, 1)
    assert rec.tcp_payload_len == 0


def test_malformed_frames_do_not_crash(parser):
    # Any frame scapy manages to dissect (even partially) must yield a record,
    # never raise, so one odd packet can't take down the capture pipeline.
    candidates = [
        bytes(Ether()),                                 # header only, no payload
        b"\x00" * 14,                                   # all-zero L2 header
        bytes(Ether() / IP()),                          # IP with no L4
        bytes(Ether() / IP(proto=6)) + b"\x00\x02",     # claims TCP, garbage L4
        bytes(Ether() / IP() / TCP())[:34],             # truncated (IP header only)
    ]
    tested = 0
    for raw in candidates:
        try:
            pkt = Ether(raw)
        except Exception:
            continue          # scapy rejected these bytes at dissect time
        tested += 1
        rec = parser.parse(pkt, tested)                 # must not raise
        assert rec is not None and isinstance(rec.raw, bytes)
    assert tested > 0
