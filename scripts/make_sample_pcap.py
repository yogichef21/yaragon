#!/usr/bin/env python3
"""Generate the bundled sample capture (assets/samples/yaragon-sample.pcap).

A tiny, benign, synthetic capture that demonstrates Yaragon's inspector, search,
filtering, conversations and follow-stream on first run WITHOUT needing a live
MITM. It is clearly labelled as sample data in the UI. Contains DNS, a TCP
handshake, an HTTP request/response and a TLS ClientHello (with SNI).

Reproducible: re-run to regenerate. No real hosts, credentials, or secrets.
"""
from __future__ import annotations

import os
import struct

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

CLIENT = "10.0.0.5"
DNSSRV = "10.0.0.1"
WEB = "93.184.216.34"
CMAC = "02:00:00:00:00:05"
GMAC = "02:00:00:00:00:01"


def _client_hello(sni: str) -> bytes:
    """Build a minimal, valid TLS 1.2 ClientHello record carrying one SNI."""
    name = sni.encode()
    server_name = b"\x00" + struct.pack(">H", len(name)) + name      # type + len + host
    sni_list = struct.pack(">H", len(server_name)) + server_name
    sni_ext = b"\x00\x00" + struct.pack(">H", len(sni_list)) + sni_list
    exts = sni_ext
    body = (
        b"\x03\x03"                       # client version TLS 1.2
        + b"\x00" * 32                    # random
        + b"\x00"                         # session id len
        + struct.pack(">H", 2) + b"\x13\x01"   # cipher suites (TLS_AES_128_GCM_SHA256)
        + b"\x01\x00"                     # compression: 1 method, null
        + struct.pack(">H", len(exts)) + exts
    )
    handshake = b"\x01" + struct.pack(">I", len(body))[1:] + body     # type + 3-byte len
    record = b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake
    return record


def build():
    pkts = []

    # DNS query + response
    pkts.append(Ether(src=CMAC, dst=GMAC) / IP(src=CLIENT, dst=DNSSRV)
                / UDP(sport=51000, dport=53) / DNS(rd=1, qd=DNSQR(qname="example.com")))
    pkts.append(Ether(src=GMAC, dst=CMAC) / IP(src=DNSSRV, dst=CLIENT)
                / UDP(sport=53, dport=51000)
                / DNS(id=0, qr=1, qd=DNSQR(qname="example.com"),
                      an=DNSRR(rrname="example.com", ttl=300, rdata=WEB)))

    # TCP handshake to the web host (port 80)
    pkts.append(Ether(src=CMAC, dst=GMAC) / IP(src=CLIENT, dst=WEB)
                / TCP(sport=44001, dport=80, flags="S", seq=1000))
    pkts.append(Ether(src=GMAC, dst=CMAC) / IP(src=WEB, dst=CLIENT)
                / TCP(sport=80, dport=44001, flags="SA", seq=5000, ack=1001))
    pkts.append(Ether(src=CMAC, dst=GMAC) / IP(src=CLIENT, dst=WEB)
                / TCP(sport=44001, dport=80, flags="A", seq=1001, ack=5001))

    # HTTP request + response
    pkts.append(Ether(src=CMAC, dst=GMAC) / IP(src=CLIENT, dst=WEB)
                / TCP(sport=44001, dport=80, flags="PA", seq=1001, ack=5001)
                / Raw(load=b"GET / HTTP/1.1\r\nHost: example.com\r\n"
                            b"User-Agent: Yaragon-Sample/1.0\r\nAccept: */*\r\n\r\n"))
    pkts.append(Ether(src=GMAC, dst=CMAC) / IP(src=WEB, dst=CLIENT)
                / TCP(sport=80, dport=44001, flags="PA", seq=5001, ack=1100)
                / Raw(load=b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
                            b"Content-Length: 13\r\n\r\nhello, world!"))

    # TLS ClientHello (with SNI) to the web host (port 443)
    pkts.append(Ether(src=CMAC, dst=GMAC) / IP(src=CLIENT, dst=WEB)
                / TCP(sport=44002, dport=443, flags="PA", seq=2000, ack=9000)
                / Raw(load=_client_hello("secure.example.com")))

    # A couple of ARP frames to show the layer the MITM abuses
    from scapy.layers.l2 import ARP
    pkts.append(Ether(src=CMAC, dst="ff:ff:ff:ff:ff:ff")
                / ARP(op=1, psrc=CLIENT, pdst=DNSSRV, hwsrc=CMAC))
    pkts.append(Ether(src=GMAC, dst=CMAC)
                / ARP(op=2, psrc=DNSSRV, pdst=CLIENT, hwsrc=GMAC, hwdst=CMAC))

    return pkts


def main():
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out_dir = os.path.join(here, "assets", "samples")
    os.makedirs(out_dir, exist_ok=True)
    out = os.path.join(out_dir, "yaragon-sample.pcap")
    pkts = build()
    # Serialise then re-read each frame so lengths/checksums are populated as on
    # the wire (matches how a live capture presents frames).
    built = [Ether(bytes(p)) for p in pkts]
    for i, p in enumerate(built):
        p.time = 1_700_000_000.0 + i * 0.05
    wrpcap(out, built)
    print(f"wrote {len(built)} packets to {out}")


if __name__ == "__main__":
    main()
