"""Aggregate a flat packet history into conversations (flows).

A *conversation* is all traffic between one unordered pair of endpoints - the
natural unit for triaging a noisy MITM capture: "1,000 packets" becomes "these 7
flows", ranked by volume, each openable into a Follow-Stream view.

Pure and Qt-free so it is unit-testable headlessly. It only reads fields the
parser already produced (endpoints, protocol, length, ports, timestamp); it adds
no new capture, decryption, or exposure.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple

from .model import PacketRecord


def endpoints(rec: PacketRecord) -> Tuple[str, str]:
    """The two endpoints of a record - IP where present, else MAC. This is the
    single identity function every follow/aggregate path shares, so a flow listed
    in Conversations can always be opened (no IP-vs-MAC key mismatch)."""
    a = rec.src_ip or rec.src_mac
    b = rec.dst_ip or rec.dst_mac
    return a, b


@dataclass
class Conversation:
    a: str                                   # the two endpoints, sorted for a
    b: str                                   # stable identity of the pair
    packets: int = 0
    bytes: int = 0
    a_to_b: int = 0                          # packets from a to b
    b_to_a: int = 0                          # packets from b to a
    protocols: Set[str] = field(default_factory=set)
    ports: Set[int] = field(default_factory=set)
    first_ts: float = 0.0
    last_ts: float = 0.0

    @property
    def duration(self) -> float:
        if not self.first_ts or not self.last_ts:
            return 0.0
        return round(self.last_ts - self.first_ts, 3)

    @property
    def pair(self) -> Tuple[str, str]:
        return (self.a, self.b)


def build_conversations(records: List[PacketRecord]) -> List[Conversation]:
    """Group *records* by unordered endpoint pair and summarise each flow.

    Returned sorted by packet count descending (heaviest flow first - the triage
    order an operator wants). Records with no resolvable endpoints are skipped.
    """
    convs: Dict[frozenset, Conversation] = {}
    for rec in records:
        a, b = endpoints(rec)
        if not a or not b:
            continue
        key = frozenset((a, b))
        # Stable endpoint labels: sort so 'a' is deterministic regardless of
        # which direction was seen first.
        lo, hi = sorted((a, b))
        conv = convs.get(key)
        if conv is None:
            conv = Conversation(a=lo, b=hi, first_ts=rec.timestamp or 0.0)
            convs[key] = conv
        conv.packets += 1
        conv.bytes += int(rec.length or 0)
        if a == conv.a:
            conv.a_to_b += 1
        else:
            conv.b_to_a += 1
        if rec.protocol:
            conv.protocols.add(rec.protocol)
        for p in (rec.src_port, rec.dst_port):
            if p:
                conv.ports.add(int(p))
        ts = rec.timestamp or 0.0
        if ts:
            if not conv.first_ts or ts < conv.first_ts:
                conv.first_ts = ts
            if ts > conv.last_ts:
                conv.last_ts = ts
    return sorted(convs.values(), key=lambda c: c.packets, reverse=True)
