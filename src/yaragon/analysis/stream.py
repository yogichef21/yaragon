"""Follow Stream: reconstruct a conversation's application-layer payload.

Given the captured records of one endpoint pair, this returns the payload-bearing
segments in capture order, tagged with direction. Payload bytes are re-extracted
on demand from the frame's ``raw`` (nothing extra is stored during capture).

Posture: encrypted spans (TLS Application Data) are flagged ``encrypted`` and
their bytes are NEVER presented as plaintext - Yaragon does not decrypt TLS. This
reads bytes already captured; it adds no new exposure over a Wireshark "Follow
Stream" on the same pcap.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from .conversations import endpoints
from .model import PacketRecord
from .packet_parser import l4_payload


@dataclass
class StreamSegment:
    src: str
    dst: str
    data: bytes
    protocol: str
    encrypted: bool = False
    seq: Optional[int] = None


def _payload(rec: PacketRecord) -> bytes:
    """Re-extract the transport payload from the frame bytes (on demand)."""
    if not rec.raw:
        return b""
    try:
        from scapy.layers.inet import TCP, UDP
        from scapy.layers.l2 import Ether
        pkt = Ether(rec.raw)
        if pkt.haslayer(TCP):
            return l4_payload(pkt[TCP])
        if pkt.haslayer(UDP):
            return l4_payload(pkt[UDP])
    except Exception:
        return b""
    return b""


def reassemble(records: List[PacketRecord], a: str, b: str) -> List[StreamSegment]:
    """Return the payload-bearing segments of the {a, b} conversation, tagged by
    direction. Each direction is ordered by TCP sequence number (fixing captured
    reordering / retransmits) while the A/B interleaving from the capture is
    preserved, so the transcript reads as the exchange happened. Empty (pure-ACK /
    no-payload) records are skipped.

    Uses the shared endpoint identity so a conversation keyed on MAC (IP-less L2)
    resolves the same way it was listed.
    """
    pair = frozenset((a, b))
    # Collect payload segments with their capture position and direction.
    collected = []
    for i, rec in enumerate(records):
        if frozenset(endpoints(rec)) != pair:
            continue
        data = _payload(rec)
        if not data:
            continue
        e1, e2 = endpoints(rec)
        encrypted = bool(rec.protocol == "TLS"
                         and rec.meta.get("tls", {}).get("encrypted"))
        seg = StreamSegment(src=e1, dst=e2, data=data, protocol=rec.protocol,
                            encrypted=encrypted, seq=rec.tcp_seq)
        collected.append((i, seg))
    if not collected:
        return []
    # Drop retransmits: the same direction re-sending the same TCP sequence is a
    # duplicate on the wire, not new content - keep the first occurrence.
    seen = set()
    unique = []
    for i, seg in collected:
        if seg.seq is not None:
            key = (seg.src, seg.seq)
            if key in seen:
                continue
            seen.add(key)
        unique.append((i, seg))
    collected = unique
    # Per-direction queues ordered by seq (None-seq keeps capture order); then
    # re-emit following the original direction rhythm so bytes within a direction
    # are seq-ordered without losing the request/response interleave.
    from collections import deque
    dirs = {}
    for i, seg in collected:
        dirs.setdefault(seg.src, []).append((i, seg))
    for src in dirs:
        dirs[src] = deque(sorted(dirs[src],
                                 key=lambda t: (t[1].seq if t[1].seq is not None
                                                else t[0])))
    out: List[StreamSegment] = []
    for i, seg in collected:                 # walk original order for the rhythm
        out.append(dirs[seg.src].popleft()[1])
    return out
