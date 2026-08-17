"""Structured internal representation of a captured packet.

Every captured frame is normalised into a :class:`PacketRecord`. This is the
single object that flows from the capture worker through the analysis engine
into the GUI.

The full frame bytes are kept in ``raw`` (in memory only, bounded by the
packet-history limit) so the inspector can show Hex/ASCII/Raw and so the capture
can be exported to ``.pcap``. The curated *Decoded* view is credential-free by
design - the HTTP parser drops ``Authorization``/``Cookie`` headers and shows
only the query-free path. The full plaintext on the wire is still present in the
Hex/ASCII/Raw views and in any exported ``.pcap``, exactly as with any analyzer.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

# A node in the collapsible inspector tree: (label, value, [children])
DetailNode = Tuple[str, str, List["DetailNode"]]


@dataclass
class PacketRecord:
    # Identity / timing
    number: int = 0
    timestamp: float = 0.0
    length: int = 0

    # Link layer
    src_mac: str = ""
    dst_mac: str = ""
    ethertype: Optional[int] = None

    # Network layer
    src_ip: str = ""
    dst_ip: str = ""
    ip_version: Optional[int] = None
    ttl: Optional[int] = None
    ip_proto: Optional[int] = None

    # Transport layer
    src_port: Optional[int] = None
    dst_port: Optional[int] = None

    # TCP specifics
    tcp_flags: str = ""
    tcp_seq: Optional[int] = None
    tcp_ack: Optional[int] = None
    tcp_window: Optional[int] = None
    tcp_payload_len: int = 0

    # High-level classification (ARP, TCP, UDP, DNS, HTTP, TLS, ICMP, DHCP, ...)
    protocol: str = "OTHER"
    info: str = ""

    # Per-protocol structured extras (dns={...}, http={...}, tls={...}, ...)
    meta: Dict[str, Any] = field(default_factory=dict)

    # Fully-built inspector tree (lazy; built by the parser on demand)
    detail_tree: List[DetailNode] = field(default_factory=list)

    # Full frame bytes, kept in-memory only for the inspector's Hex/ASCII/Raw
    # views and for .pcap export. Bounded by the packet-history limit.
    raw: bytes = b""

    # ---- convenience ------------------------------------------------------
    @property
    def src_socket(self) -> str:
        if self.src_port is not None:
            return f"{self.src_ip}:{self.src_port}"
        return self.src_ip or self.src_mac

    @property
    def dst_socket(self) -> str:
        if self.dst_port is not None:
            return f"{self.dst_ip}:{self.dst_port}"
        return self.dst_ip or self.dst_mac


def hexdump(data: bytes, width: int = 16) -> str:
    """Classic offset / hex / ASCII hexdump of raw bytes."""
    if not data:
        return "(no bytes captured)"
    lines = []
    for off in range(0, len(data), width):
        chunk = data[off:off + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        hex_part = f"{hex_part:<{width * 3 - 1}}"
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{off:08x}  {hex_part}  {ascii_part}")
    return "\n".join(lines)


def ascii_view(data: bytes) -> str:
    """Printable-ASCII rendering of raw bytes (non-printables shown as '.')."""
    if not data:
        return "(no bytes captured)"
    return "".join(chr(b) if 32 <= b < 127 else "." for b in data)
