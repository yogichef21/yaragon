"""Follow Stream reassembly: reconstruct a conversation's application payload by
direction, from the captured bytes. TLS/encrypted spans stay labelled ENCRYPTED
and are never rendered as content - no decryption, ever.
"""
from conftest import build
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from yaragon.analysis.stream import reassemble


def _http_req(parser, src="10.0.0.2", dst="10.0.0.1"):
    pkt = (Ether() / IP(src=src, dst=dst) / TCP(sport=40000, dport=80, flags="PA")
           / Raw(load=b"GET / HTTP/1.1\r\nHost: example\r\n\r\n"))
    return parser.parse(build(pkt))


def _http_resp(parser, src="10.0.0.1", dst="10.0.0.2"):
    pkt = (Ether() / IP(src=src, dst=dst) / TCP(sport=80, dport=40000, flags="PA")
           / Raw(load=b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"))
    return parser.parse(build(pkt))


def _tls_appdata(parser, src="10.0.0.2", dst="10.0.0.1"):
    body = bytes([0x17, 0x03, 0x03, 0x00, 0x05]) + b"abcde"  # TLS AppData record
    pkt = (Ether() / IP(src=src, dst=dst) / TCP(sport=40001, dport=443, flags="PA")
           / Raw(load=body))
    return parser.parse(build(pkt))


def test_reassembles_both_directions_with_payload(parser):
    recs = [_http_req(parser), _http_resp(parser)]
    segs = reassemble(recs, "10.0.0.2", "10.0.0.1")
    assert len(segs) == 2
    req = segs[0]
    assert req.src == "10.0.0.2" and req.dst == "10.0.0.1"
    assert b"GET / HTTP/1.1" in req.data
    assert req.encrypted is False
    resp = segs[1]
    assert b"200 OK" in resp.data


def test_only_the_selected_pair_is_included(parser):
    recs = [_http_req(parser),
            _http_req(parser, src="10.9.9.9", dst="10.0.0.1")]  # different pair
    segs = reassemble(recs, "10.0.0.2", "10.0.0.1")
    assert len(segs) == 1
    assert segs[0].src == "10.0.0.2"


def test_encrypted_tls_is_flagged_not_decrypted(parser):
    segs = reassemble([_tls_appdata(parser)], "10.0.0.2", "10.0.0.1")
    assert len(segs) == 1
    assert segs[0].encrypted is True
    # The raw ciphertext length is known, but it is never presented as plaintext.
    assert segs[0].protocol == "TLS"


def test_reassemble_orders_each_direction_by_seq(parser):
    """A direction captured out of sequence order is reassembled in seq order,
    so the transcript reads correctly under reordering/retransmit."""
    later = (Ether() / IP(src="10.0.0.2", dst="10.0.0.1")
             / TCP(sport=40000, dport=80, flags="PA", seq=200) / Raw(load=b"second"))
    earlier = (Ether() / IP(src="10.0.0.2", dst="10.0.0.1")
               / TCP(sport=40000, dport=80, flags="PA", seq=100) / Raw(load=b"first"))
    # captured later-seq first, earlier-seq second
    recs = [parser.parse(build(later)), parser.parse(build(earlier))]
    segs = reassemble(recs, "10.0.0.2", "10.0.0.1")
    assert [s.data for s in segs] == [b"first", b"second"]


def test_retransmitted_segment_is_deduped(parser):
    """A retransmit (same direction re-sending the same TCP seq) is a duplicate on
    the wire, not new content - it appears once in the transcript."""
    pkt = (Ether() / IP(src="10.0.0.2", dst="10.0.0.1")
           / TCP(sport=40000, dport=80, flags="PA", seq=100) / Raw(load=b"hello"))
    r1 = parser.parse(build(pkt))
    r2 = parser.parse(build(pkt))          # identical retransmit
    segs = reassemble([r1, r2], "10.0.0.2", "10.0.0.1")
    assert len(segs) == 1
    assert segs[0].data == b"hello"


def test_pure_acks_without_payload_are_skipped(parser):
    ack = parser.parse(build(Ether() / IP(src="10.0.0.2", dst="10.0.0.1")
                             / TCP(sport=40000, dport=80, flags="A")))
    segs = reassemble([ack], "10.0.0.2", "10.0.0.1")
    assert segs == []
