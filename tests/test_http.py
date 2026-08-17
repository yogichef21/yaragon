"""HTTP metadata parsing tests (safe metadata only)."""
from conftest import build

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw


def _http(payload, sport=44000, dport=80):
    return build(Ether() / IP(src="192.168.1.20", dst="1.2.3.4") /
                 TCP(sport=sport, dport=dport, flags="PA", seq=1) / Raw(load=payload))


def test_http_request(parser):
    payload = (b"GET /index.html?q=1 HTTP/1.1\r\nHost: example.com\r\n"
               b"User-Agent: curl/8.0\r\nAccept: */*\r\n\r\n")
    rec = parser.parse(_http(payload), 1)
    assert rec.protocol == "HTTP"
    http = rec.meta["http"]
    assert http["method"] == "GET"
    assert http["host"] == "example.com"
    assert http["path"] == "/index.html"
    assert http["user_agent"] == "curl/8.0"


def test_http_response(parser):
    payload = (b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
               b"Content-Length: 1256\r\nServer: nginx\r\n\r\n")
    rec = parser.parse(_http(payload, sport=80, dport=44000), 2)
    http = rec.meta["http"]
    assert http["kind"] == "response"
    assert http["status"] == "200"
    assert http["content_type"] == "text/html"


def test_http_does_not_capture_auth(parser):
    # Authorization / Cookie headers must NOT be surfaced (privacy by design).
    payload = (b"GET / HTTP/1.1\r\nHost: x\r\nAuthorization: Basic c2VjcmV0\r\n"
               b"Cookie: session=abc\r\n\r\n")
    rec = parser.parse(_http(payload), 3)
    headers = rec.meta["http"]["headers"]
    assert "authorization" not in headers
    assert "cookie" not in headers


def test_http_post(parser):
    payload = b"POST /login HTTP/1.1\r\nHost: site\r\nContent-Length: 20\r\n\r\n"
    rec = parser.parse(_http(payload), 4)
    assert rec.meta["http"]["method"] == "POST"


def test_http_decoded_tree_omits_query_string(parser):
    # SEC-4 (item 13): the curated Decoded tree shows the query-free Path only -
    # never the full URI, which can carry credentials in its query string.
    payload = b"GET /a?token=secret HTTP/1.1\r\nHost: x\r\n\r\n"
    rec = parser.parse(_http(payload), 5)

    flat = []

    def walk(node):
        label, value, children = node
        flat.append((label, value))
        for c in children:
            walk(c)

    for node in rec.detail_tree:
        walk(node)

    labels = [lbl for lbl, _ in flat]
    assert "Path" in labels
    assert "URI" not in labels
    assert all("token=secret" not in str(v) for _, v in flat)
    # the query-free path is what the tree surfaces
    assert rec.meta["http"]["path"] == "/a"
