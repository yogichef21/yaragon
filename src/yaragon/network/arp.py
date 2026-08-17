"""ARP helpers: resolve a MAC for an IP, and read the system neighbour cache."""
from __future__ import annotations

from typing import Dict, Optional

from ..platform import get_platform
from ..utils.logging import get_logger

log = get_logger("arp")


def resolve_mac(ip: str, iface: str, timeout: float = 2.0) -> Optional[str]:
    """Resolve the MAC address for *ip* on *iface* via an ARP request.

    Requires raw-socket privileges; returns None on failure or timeout.
    """
    try:
        from scapy.all import ARP, Ether, srp
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
            timeout=timeout, iface=iface, verbose=0,
        )
        for _, resp in ans:
            return resp.hwsrc
    except PermissionError:
        log.warning("resolve_mac needs raw-socket privileges")
    except Exception as exc:  # pragma: no cover
        log.debug("resolve_mac failed for %s: %s", ip, exc)
    return None


def neighbour_cache() -> Dict[str, str]:
    """Return ip -> mac from the OS neighbour/ARP cache (no privileges needed)."""
    return get_platform().neighbour_cache()
