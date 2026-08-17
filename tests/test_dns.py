"""DNS parsing tests."""
from conftest import build

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether


def test_dns_query(parser):
    pkt = build(Ether() / IP(src="192.168.1.20", dst="8.8.8.8") /
                UDP(sport=5353, dport=53) /
                DNS(rd=1, qd=DNSQR(qname="example.com", qtype="A")))
    rec = parser.parse(pkt, 1)
    assert rec.protocol == "DNS"
    assert rec.meta["dns"]["query"] == "example.com"
    assert rec.meta["dns"]["qtype"] == "A"
    assert rec.meta["dns"]["is_response"] is False


def test_dns_response_a(parser):
    pkt = build(Ether() / IP(src="8.8.8.8", dst="192.168.1.20") /
                UDP(sport=53, dport=5353) /
                DNS(qr=1, qd=DNSQR(qname="example.com"),
                    an=DNSRR(rrname="example.com", type="A",
                             rdata="93.184.216.34", ttl=300)))
    rec = parser.parse(pkt, 2)
    dns = rec.meta["dns"]
    assert dns["is_response"] is True
    assert dns["answers"][0]["data"] == "93.184.216.34"
    assert dns["answers"][0]["type"] == "A"
    assert dns["answers"][0]["ttl"] == 300


def test_dns_aaaa(parser):
    pkt = build(Ether() / IP(src="8.8.8.8", dst="192.168.1.20") /
                UDP(sport=53, dport=5353) /
                DNS(qr=1, qd=DNSQR(qname="ipv6.example.com", qtype="AAAA"),
                    an=DNSRR(rrname="ipv6.example.com", type="AAAA",
                             rdata="2606:2800:220:1::1", ttl=60)))
    rec = parser.parse(pkt, 3)
    assert rec.meta["dns"]["answers"][0]["type"] == "AAAA"


def test_dns_nxdomain(parser):
    pkt = build(Ether() / IP(src="8.8.8.8", dst="192.168.1.20") /
                UDP(sport=53, dport=5353) /
                DNS(qr=1, rcode=3, qd=DNSQR(qname="nope.invalid")))
    rec = parser.parse(pkt, 4)
    assert rec.meta["dns"]["rcode"] == 3
    assert rec.meta["dns"]["rcode_name"] == "NXDOMAIN"
