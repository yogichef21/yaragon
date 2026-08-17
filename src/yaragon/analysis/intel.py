"""Target Intelligence: a per-host rollup of metadata Yaragon already parsed.

Turns scattered rows into a profile of one asset: the MACs it uses, the names it
resolved (DNS), the servers it reached (TLS SNI, HTTP Host), its User-Agents, its
DHCP identity, the protocols it spoke and the peers it talked to (with counts).

Pure and Qt-free. It only reads ``rec.meta`` the parser produced - it performs no
new capture, no decryption, and adds no exposure beyond what the inspector
already shows per packet.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Set

from .model import PacketRecord


@dataclass
class TargetIntel:
    ip: str
    packets: int = 0
    macs: Set[str] = field(default_factory=set)
    protocols: Set[str] = field(default_factory=set)
    names_resolved: Set[str] = field(default_factory=set)  # DNS queries it sent
    sni: Set[str] = field(default_factory=set)             # TLS server names
    http_hosts: Set[str] = field(default_factory=set)      # HTTP Host headers
    user_agents: Set[str] = field(default_factory=set)
    dhcp_hostname: str = ""
    dhcp_vendor: str = ""
    peers: Dict[str, int] = field(default_factory=dict)    # peer ip -> packets


def build_target_intel(records: List[PacketRecord], host_ip: str) -> TargetIntel:
    """Aggregate everything already known about *host_ip* from *records*."""
    intel = TargetIntel(ip=host_ip)
    for rec in records:
        is_src = rec.src_ip == host_ip
        is_dst = rec.dst_ip == host_ip
        if not (is_src or is_dst):
            continue
        intel.packets += 1
        if rec.protocol:
            intel.protocols.add(rec.protocol)
        # MAC(s) this host uses, and the peer on the other side (with a count).
        if is_src:
            if rec.src_mac:
                intel.macs.add(rec.src_mac)
            if rec.dst_ip:
                intel.peers[rec.dst_ip] = intel.peers.get(rec.dst_ip, 0) + 1
        else:
            if rec.dst_mac:
                intel.macs.add(rec.dst_mac)
            if rec.src_ip:
                intel.peers[rec.src_ip] = intel.peers.get(rec.src_ip, 0) + 1

        dns = rec.meta.get("dns")
        if dns and not dns.get("is_response") and dns.get("query") and is_src:
            intel.names_resolved.add(dns["query"])

        tls = rec.meta.get("tls")
        if tls and tls.get("sni"):
            intel.sni.add(tls["sni"])

        http = rec.meta.get("http")
        if http and http.get("kind") == "request" and is_src:
            if http.get("host"):
                intel.http_hosts.add(http["host"])
            if http.get("user_agent"):
                intel.user_agents.add(http["user_agent"])

        dhcp = rec.meta.get("dhcp")
        if dhcp:
            if dhcp.get("hostname") and not intel.dhcp_hostname:
                intel.dhcp_hostname = dhcp["hostname"]
            if dhcp.get("vendor_class_id") and not intel.dhcp_vendor:
                intel.dhcp_vendor = dhcp["vendor_class_id"]
    return intel
