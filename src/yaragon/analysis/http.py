"""Plaintext HTTP metadata extraction.

We extract *safe* protocol metadata only: method, host, path, status, version,
content-type/length and User-Agent. We deliberately do NOT parse request bodies,
Authorization headers, Cookie headers or any credential-bearing fields.
"""
from __future__ import annotations

from typing import List, Optional

from .model import DetailNode, PacketRecord

HTTP_METHODS = (b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS",
                b"PATCH", b"TRACE", b"CONNECT")

# Headers we will surface. Everything else is ignored (privacy by design).
SAFE_HEADERS = {
    "host", "user-agent", "content-type", "content-length", "server",
    "location", "referer", "accept", "connection",
}


def looks_like_http(payload: bytes, sport: Optional[int], dport: Optional[int]) -> bool:
    if not payload:
        return False
    if payload[:8].upper().startswith(b"HTTP/"):
        return True
    for m in HTTP_METHODS:
        if payload.startswith(m + b" "):
            return True
    return dport == 80 or sport == 80


def _parse_headers(lines: List[bytes]) -> dict:
    headers = {}
    for line in lines:
        if b":" not in line:
            continue
        k, _, v = line.partition(b":")
        key = k.decode("latin-1", "replace").strip().lower()
        if key in SAFE_HEADERS:
            headers[key] = v.decode("latin-1", "replace").strip()
    return headers


def parse_http(payload: bytes, rec: PacketRecord, tree: List[DetailNode]) -> None:
    rec.protocol = "HTTP"
    try:
        head = payload.split(b"\r\n\r\n", 1)[0]
        lines = head.split(b"\r\n")
    except Exception:
        rec.info = "HTTP (unparsed)"
        return

    if not lines:
        rec.info = "HTTP"
        return

    start = lines[0]
    headers = _parse_headers(lines[1:])
    http = {"headers": headers}

    if start.upper().startswith(b"HTTP/"):
        # Response
        parts = start.split(b" ", 2)
        version = parts[0].decode("latin-1", "replace") if parts else "HTTP"
        status = parts[1].decode("latin-1", "replace") if len(parts) > 1 else ""
        reason = parts[2].decode("latin-1", "replace") if len(parts) > 2 else ""
        http.update({
            "kind": "response", "version": version, "status": status,
            "reason": reason,
            "content_type": headers.get("content-type", ""),
            "content_length": headers.get("content-length", ""),
            "server": headers.get("server", ""),
        })
        rec.info = f"HTTP {status} {reason} ({headers.get('content-type', '')})".strip()
        children = [
            ("HTTP Version", version, []),
            ("Status Code", status, []),
            ("Reason", reason, []),
            ("Content-Type", headers.get("content-type", ""), []),
            ("Content-Length", headers.get("content-length", ""), []),
            ("Server", headers.get("server", ""), []),
        ]
    else:
        # Request
        parts = start.split(b" ")
        method = parts[0].decode("latin-1", "replace") if parts else ""
        uri = parts[1].decode("latin-1", "replace") if len(parts) > 1 else ""
        version = parts[2].decode("latin-1", "replace") if len(parts) > 2 else ""
        path = uri.split("?", 1)[0]
        http.update({
            "kind": "request", "method": method, "uri": uri, "path": path,
            "version": version, "host": headers.get("host", ""),
            "user_agent": headers.get("user-agent", ""),
            "content_type": headers.get("content-type", ""),
            "content_length": headers.get("content-length", ""),
        })
        rec.info = f"{method} {headers.get('host', '')}{path}".strip()
        children = [
            ("Method", method, []),
            ("Host", headers.get("host", ""), []),
            # Only the query-free Path is surfaced in the curated Decoded view;
            # the full URI (which can carry credentials in its query string) is
            # kept in meta but never shown here. The raw bytes remain in Hex/
            # ASCII/Raw and the exported .pcap, as with any analyzer.
            ("Path", path, []),
            ("HTTP Version", version, []),
            ("User-Agent", headers.get("user-agent", ""), []),
            ("Content-Type", headers.get("content-type", ""), []),
            ("Content-Length", headers.get("content-length", ""), []),
        ]

    rec.meta["http"] = http
    tree.append(("Hypertext Transfer Protocol", http.get("kind", "http"), children))
