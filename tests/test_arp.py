"""ARP parsing tests."""
from conftest import build

from scapy.layers.l2 import ARP, Ether


def _arp(op, psrc, pdst, hwsrc):
    return build(Ether(dst="ff:ff:ff:ff:ff:ff") /
                 ARP(op=op, psrc=psrc, pdst=pdst, hwsrc=hwsrc))


def test_arp_request(parser):
    rec = parser.parse(_arp(1, "192.168.1.20", "192.168.1.1", "11:22:33:44:55:66"), 1)
    assert rec.protocol == "ARP"
    assert rec.meta["arp"]["op"] == 1
    assert "Who has 192.168.1.1" in rec.info


def test_arp_reply(parser):
    rec = parser.parse(_arp(2, "192.168.1.1", "192.168.1.20", "aa:bb:cc:dd:ee:ff"), 2)
    assert rec.meta["arp"]["op"] == 2
    assert rec.meta["arp"]["sender_mac"] == "aa:bb:cc:dd:ee:ff"


def test_arp_fields_complete(parser):
    rec = parser.parse(_arp(1, "192.168.1.20", "192.168.1.1", "11:22:33:44:55:66"), 3)
    arp = rec.meta["arp"]
    assert arp["sender_ip"] == "192.168.1.20"
    assert arp["target_ip"] == "192.168.1.1"
    assert arp["sender_mac"] == "11:22:33:44:55:66"
