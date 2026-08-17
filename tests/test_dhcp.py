"""DHCP parsing tests."""
from conftest import build

from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether


def test_dhcp_discover(parser):
    pkt = build(Ether(dst="ff:ff:ff:ff:ff:ff") /
                IP(src="0.0.0.0", dst="255.255.255.255") /
                UDP(sport=68, dport=67) /
                BOOTP(chaddr=b"\x11\x22\x33\x44\x55\x66") /
                DHCP(options=[("message-type", "discover"), "end"]))
    rec = parser.parse(pkt, 1)
    assert rec.protocol == "DHCP"
    assert rec.meta["dhcp"]["message_type"] == "DISCOVER"
    assert rec.meta["dhcp"]["client_mac"].startswith("11:22:33")


def test_dhcp_ack_with_options(parser):
    pkt = build(Ether() / IP(src="192.168.1.1", dst="192.168.1.20") /
                UDP(sport=67, dport=68) /
                BOOTP(yiaddr="192.168.1.20", chaddr=b"\xaa\xbb\xcc\xdd\xee\xff") /
                DHCP(options=[("message-type", "ack"),
                              ("server_id", "192.168.1.1"),
                              ("router", "192.168.1.1"),
                              ("lease_time", 86400), "end"]))
    rec = parser.parse(pkt, 2)
    d = rec.meta["dhcp"]
    assert d["message_type"] == "ACK"
    assert d["assigned_ip"] == "192.168.1.20"
    assert d["lease_time"] == 86400


def test_dhcp_hostname_and_vendor(parser):
    # Options 12 (host name) and 60 (vendor class) carry free, passive host
    # identity - surfaced in meta["dhcp"] (item 12).
    pkt = build(Ether(dst="ff:ff:ff:ff:ff:ff") /
                IP(src="0.0.0.0", dst="255.255.255.255") /
                UDP(sport=68, dport=67) /
                BOOTP(chaddr=b"\x11\x22\x33\x44\x55\x66") /
                DHCP(options=[("message-type", "request"),
                              ("hostname", b"Johns-iPhone"),
                              ("vendor_class_id", b"android-dhcp-13"), "end"]))
    rec = parser.parse(pkt, 3)
    d = rec.meta["dhcp"]
    assert d["hostname"] == "Johns-iPhone"
    assert d["vendor_class_id"] == "android-dhcp-13"
