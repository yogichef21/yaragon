"""Lab-local host discovery via ARP sweep.

Sweeps the CIDR of the selected interface with ARP requests and reports live
hosts with IP, MAC, resolved hostname and inferred role (gateway / this host /
client). Falls back to the kernel neighbour cache when raw-socket privileges
are unavailable so the UI still shows *something*. Vendor fingerprinting is left
to DHCP option 60 at investigation time (analysis/dhcp.py), which is accurate;
a tiny built-in OUI table could not be.
"""
from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from typing import Callable, List, Optional

from ..utils.logging import get_logger
from . import arp as arp_helper
from .interfaces import InterfaceInfo, default_gateway

log = get_logger("discovery")


@dataclass
class Host:
    ip: str
    mac: str = ""
    hostname: str = ""
    status: str = "up"
    role: str = "client"


def _hostname(ip: str, timeout: float = 0.3) -> str:
    """Best-effort reverse DNS with a short timeout so a subnet full of hosts
    without PTR records cannot stall the whole scan on slow resolver lookups."""
    old = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""
    finally:
        socket.setdefaulttimeout(old)


def discover_hosts(
    iface: InterfaceInfo,
    timeout: float = 2.0,
    progress: Optional[Callable[[int, int], None]] = None,
    max_hosts: int = 512,
) -> List[Host]:
    """ARP-sweep the interface subnet. Requires raw-socket privileges for the
    active sweep; otherwise returns hosts from the neighbour cache."""
    gw = default_gateway()
    hosts: List[Host] = []
    seen = set()

    cidr = iface.cidr
    active_ok = False
    if cidr:
        try:
            from scapy.all import ARP, Ether, srp

            net = ipaddress.IPv4Network(cidr, strict=False)
            targets = [str(h) for h in net.hosts()][:max_hosts]
            total = len(targets)
            done = 0
            # send in chunks to keep memory bounded and allow progress reporting
            chunk = 64
            for i in range(0, total, chunk):
                batch = targets[i:i + chunk]
                ans, _ = srp(
                    Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=batch),
                    timeout=timeout, iface=iface.name, verbose=0,
                )
                for _, resp in ans:
                    ip = resp.psrc
                    if ip in seen:
                        continue
                    seen.add(ip)
                    hosts.append(_build_host(ip, resp.hwsrc, iface, gw))
                done += len(batch)
                if progress:
                    progress(min(done, total), total)
                active_ok = True
        except PermissionError:
            log.warning("ARP sweep needs raw-socket privileges; using neigh cache")
        except Exception as exc:
            log.debug("ARP sweep error: %s", exc)

    if not active_ok:
        for ip, mac in arp_helper.neighbour_cache().items():
            if ip in seen:
                continue
            seen.add(ip)
            hosts.append(_build_host(ip, mac, iface, gw))

    # ensure this host and the gateway are represented
    if iface.ipv4 and iface.ipv4 not in seen:
        hosts.append(_build_host(iface.ipv4, iface.mac, iface, gw))
    hosts.sort(key=lambda h: tuple(int(p) for p in h.ip.split(".")) if h.ip.count(".") == 3 else (0,))
    return hosts


def _build_host(ip: str, mac: str, iface: InterfaceInfo, gw: Optional[str]) -> Host:
    role = "client"
    if gw and ip == gw:
        role = "gateway"
    elif ip == iface.ipv4:
        role = "this host (Yaragon)"
    return Host(
        ip=ip, mac=mac or "", hostname=_hostname(ip), status="up", role=role,
    )
