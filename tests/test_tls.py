"""TLS metadata parsing tests (no decryption)."""
import struct

from conftest import build
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw


def _client_hello_bytes(sni=b"example.com"):
    ext_sni = (b"\x00\x00" + struct.pack(">H", len(sni) + 5) +
               struct.pack(">H", len(sni) + 3) + b"\x00" +
               struct.pack(">H", len(sni)) + sni)
    body = (b"\x03\x03" + b"\x00" * 32 + b"\x00" +           # version + random + sid
            struct.pack(">H", 2) + b"\x13\x01" +             # cipher suites
            b"\x01\x00" +                                    # compression
            struct.pack(">H", len(ext_sni)) + ext_sni)       # extensions
    hs = b"\x01" + struct.pack(">I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs


def _tls_pkt(payload):
    return build(Ether() / IP(src="192.168.1.20", dst="1.2.3.4") /
                 TCP(sport=44001, dport=443, flags="PA", seq=1) / Raw(load=payload))


def test_tls_client_hello_sni(parser):
    rec = parser.parse(_tls_pkt(_client_hello_bytes(b"secure.example.org")), 1)
    assert rec.protocol == "TLS"
    tls = rec.meta["tls"]
    assert tls["handshake_type"] == "ClientHello"
    assert tls["sni"] == "secure.example.org"
    assert tls["record_version"] == "TLS 1.0"


def test_tls_application_data_encrypted(parser):
    # content type 23 = Application Data => must be labelled ENCRYPTED, no decrypt
    payload = b"\x17\x03\x03" + struct.pack(">H", 32) + b"\x00" * 32
    rec = parser.parse(_tls_pkt(payload), 2)
    assert rec.meta["tls"]["encrypted"] is True
    assert "ENCRYPTED" in rec.info


def test_tls_cipher_suites_listed(parser):
    rec = parser.parse(_tls_pkt(_client_hello_bytes()), 3)
    assert "TLS_AES_128_GCM_SHA256" in rec.meta["tls"]["cipher_suites"]
