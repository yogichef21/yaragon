"""Map observed protocols to OSI layers for the packet inspector.

The mapping is intentionally honest: several real-world protocols do not sit on
exactly one OSI layer, so those carry a short note explaining the nuance rather
than being forced into a single box. We never invent layer information that is
not present in the packet.
"""
from __future__ import annotations

from typing import Optional, Tuple

LAYER_NAMES = {
    1: "Physical",
    2: "Data Link",
    3: "Network",
    4: "Transport",
    5: "Session",
    6: "Presentation",
    7: "Application",
}

# protocol node label (as produced by the parser) -> (layer, optional note)
_MAP = {
    "Frame": (1, "Capture metadata. A capture cannot record the physical "
                 "layer itself, so this describes the frame as seen by the NIC."),
    "Ethernet II": (2, None),
    "ARP": (2, "ARP bridges layers 2 and 3 - it resolves layer-3 addresses "
               "to layer-2 (MAC) addresses."),
    "Internet Protocol Version 4": (3, None),
    "Internet Protocol Version 6": (3, None),
    "Internet Control Message Protocol": (3, "ICMP is a control protocol "
                                             "carried inside IP; usually placed at layer 3."),
    "Internet Control Message Protocol v6": (3, "ICMPv6 is carried inside "
                                                "IPv6; usually placed at layer 3."),
    "Transmission Control Protocol": (4, None),
    "User Datagram Protocol": (4, None),
    "Transport Layer Security": (6, "TLS spans the session/presentation "
                                    "boundary. Real stacks don't map it to a single OSI "
                                    "layer; only the unencrypted handshake metadata is shown."),
    "Domain Name System": (7, None),
    "Hypertext Transfer Protocol": (7, None),
    "Dynamic Host Configuration Protocol": (7, None),
}


def layer_for(protocol_label: str) -> Tuple[Optional[int], Optional[str]]:
    """Return (osi_layer, note). Unknown labels fall through to (None, None)."""
    return _MAP.get(protocol_label, (None, None))


def layer_title(layer: Optional[int]) -> str:
    if layer is None:
        return "Other"
    return f"Layer {layer} · {LAYER_NAMES.get(layer, '?')}"
