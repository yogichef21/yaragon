"""OSI layer mapping tests - accurate, packet-driven, no forced mappings."""
from conftest import build

from scapy.layers.inet import ICMP, IP, TCP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw

from yaragon.analysis.osi import layer_for, layer_title


def test_layer_titles():
    assert layer_title(2) == "Layer 2 · Data Link"
    assert layer_title(3) == "Layer 3 · Network"
    assert layer_title(4) == "Layer 4 · Transport"
    assert layer_title(7) == "Layer 7 · Application"
    assert layer_title(None) == "Other"


def test_core_layer_mapping():
    assert layer_for("Ethernet II")[0] == 2
    assert layer_for("Internet Protocol Version 4")[0] == 3
    assert layer_for("Internet Protocol Version 6")[0] == 3
    assert layer_for("Transmission Control Protocol")[0] == 4
    assert layer_for("User Datagram Protocol")[0] == 4
    assert layer_for("Domain Name System")[0] == 7
    assert layer_for("Hypertext Transfer Protocol")[0] == 7


def test_nuanced_protocols_carry_notes():
    # These deliberately do not map to one clean layer and must explain why.
    for label in ("ARP", "Transport Layer Security",
                  "Internet Control Message Protocol"):
        layer, note = layer_for(label)
        assert layer is not None
        assert note and len(note) > 10


def test_unknown_label_is_other():
    assert layer_for("Nonexistent Protocol") == (None, None)


def test_http_packet_maps_to_expected_layers(parser):
    payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    pkt = build(Ether() / IP(src="10.0.0.2", dst="10.0.0.1") /
                TCP(sport=40000, dport=80, flags="PA", seq=1) / Raw(load=payload))
    rec = parser.parse(pkt, 1)
    layers = {layer_for(label)[0] for label, _, _ in rec.detail_tree}
    assert {2, 3, 4, 7}.issubset(layers)   # Ethernet, IPv4, TCP, HTTP


def test_arp_packet_is_layer2_only(parser):
    pkt = build(Ether(dst="ff:ff:ff:ff:ff:ff") /
                ARP(op=1, psrc="10.0.0.2", pdst="10.0.0.1", hwsrc="11:22:33:44:55:66"))
    rec = parser.parse(pkt, 1)
    layers = {layer_for(label)[0] for label, _, _ in rec.detail_tree}
    assert layers == {2}


def test_icmp_maps_to_network_layer(parser):
    pkt = build(Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / ICMP(type=8))
    rec = parser.parse(pkt, 1)
    labels = {label for label, _, _ in rec.detail_tree}
    assert "Internet Control Message Protocol" in labels
    assert layer_for("Internet Control Message Protocol")[0] == 3
