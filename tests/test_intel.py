"""Target Intelligence: roll up what Yaragon already parsed about one host -
names it resolved, SNI/HTTP hosts it contacted, DHCP identity, protocols, peers.
Pure aggregation over existing metadata; no new capture or exposure.
"""
from conftest import build
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from yaragon.analysis.intel import build_target_intel
from yaragon.analysis.model import PacketRecord


def _dns_query(parser, host="10.0.0.2", name="example.com"):
    pkt = (Ether() / IP(src=host, dst="8.8.8.8") / UDP(sport=5000, dport=53)
           / DNS(rd=1, qd=DNSQR(qname=name)))
    return parser.parse(build(pkt))


def _http_get(parser, host="10.0.0.2"):
    pkt = (Ether() / IP(src=host, dst="10.0.0.1") / TCP(sport=40000, dport=80, flags="PA")
           / Raw(load=b"GET /a HTTP/1.1\r\nHost: site.example\r\nUser-Agent: curl/8\r\n\r\n"))
    return parser.parse(build(pkt))


def _tls_with_sni(host="10.0.0.2", peer="93.184.216.34", sni="api.example.com"):
    # Build the record directly with the metadata the TLS parser would produce;
    # crafting exact ClientHello bytes is covered by the TLS parser's own tests.
    rec = PacketRecord(src_ip=host, dst_ip=peer, protocol="TLS", length=200)
    rec.src_port, rec.dst_port = 40001, 443
    rec.meta["tls"] = {"handshake_type": "ClientHello", "sni": sni}
    return rec


def test_rolls_up_names_sni_http_and_peers(parser):
    host = "10.0.0.2"
    recs = [_dns_query(parser, host, "example.com"),
            _http_get(parser, host),
            _tls_with_sni(host=host, peer="93.184.216.34", sni="api.example.com")]
    intel = build_target_intel(recs, host)
    assert "example.com" in intel.names_resolved
    assert "site.example" in intel.http_hosts
    assert "curl/8" in intel.user_agents
    assert "api.example.com" in intel.sni
    assert {"DNS", "HTTP", "TLS"} <= intel.protocols
    assert "8.8.8.8" in intel.peers and "10.0.0.1" in intel.peers


def test_peers_have_packet_counts(parser):
    host = "10.0.0.2"
    recs = [_http_get(parser, host), _http_get(parser, host)]
    intel = build_target_intel(recs, host)
    assert intel.peers["10.0.0.1"] == 2


def test_dhcp_identity_is_captured(parser):
    host = "10.0.0.55"
    rec = PacketRecord(src_ip=host, dst_ip="10.0.0.1", protocol="DHCP", length=300)
    rec.meta["dhcp"] = {"hostname": "alices-laptop", "vendor_class_id": "MSFT 5.0",
                        "assigned_ip": host}
    intel = build_target_intel([rec], host)
    assert intel.dhcp_hostname == "alices-laptop"
    assert intel.dhcp_vendor == "MSFT 5.0"


def test_unrelated_host_traffic_is_ignored(parser):
    recs = [_http_get(parser, "10.0.0.9")]     # different host
    intel = build_target_intel(recs, "10.0.0.2")
    assert intel.packets == 0
    assert not intel.http_hosts
