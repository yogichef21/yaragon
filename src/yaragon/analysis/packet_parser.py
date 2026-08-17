"""Turn raw scapy packets into normalised :class:`PacketRecord` objects.

Covers the full protocol set required by the lab:
Ethernet, ARP, IPv4, IPv6, TCP, UDP, ICMP, ICMPv6, DNS, DHCP, HTTP, TLS.

Only observable protocol metadata is extracted. We never decrypt TLS and never
harvest credentials - encrypted payloads are labelled ENCRYPTED and left alone.
"""
from __future__ import annotations

from typing import List

from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNS
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import (
    ICMPv6DestUnreach,
    ICMPv6EchoReply,
    ICMPv6EchoRequest,
    ICMPv6ND_NA,
    ICMPv6ND_NS,
    ICMPv6TimeExceeded,
    IPv6,
)
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet

from . import dhcp as dhcp_mod
from . import dns as dns_mod
from . import http as http_mod
from . import tls as tls_mod
from .model import DetailNode, PacketRecord

TCP_FLAG_ORDER = [
    ("F", 0x01, "FIN"),
    ("S", 0x02, "SYN"),
    ("R", 0x04, "RST"),
    ("P", 0x08, "PSH"),
    ("A", 0x10, "ACK"),
    ("U", 0x20, "URG"),
    ("E", 0x40, "ECE"),
    ("C", 0x80, "CWR"),
]

ETHERTYPES = {
    0x0800: "IPv4",
    0x0806: "ARP",
    0x86DD: "IPv6",
    0x8100: "802.1Q VLAN",
}

IP_PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6", 2: "IGMP"}

ARP_OPS = {1: "who-has (request)", 2: "is-at (reply)"}

ICMP_TYPES = {
    0: "Echo Reply",
    3: "Destination Unreachable",
    5: "Redirect",
    8: "Echo Request",
    11: "Time Exceeded",
}


def l4_payload(layer) -> bytes:
    """Return a transport layer's real payload, excluding any trailing Ethernet
    padding scapy attaches to short frames (so payload lengths stay accurate)."""
    from scapy.packet import NoPayload, Padding

    payload = layer.payload
    if isinstance(payload, (NoPayload, Padding)) or not payload:
        return b""
    data = bytes(payload)
    pad = payload.getlayer(Padding)
    if pad is not None:
        pad_len = len(bytes(pad))
        if pad_len:
            data = data[:-pad_len]
    return data


def tcp_flags_str(flags_int: int) -> str:
    out = []
    for short, bit, _ in TCP_FLAG_ORDER:
        if flags_int & bit:
            out.append(short)
    return "".join(out)


def tcp_flags_expand(flags_int: int) -> str:
    names = [name for _, bit, name in TCP_FLAG_ORDER if flags_int & bit]
    return ", ".join(names) if names else "(none)"


class PacketParser:
    """Stateless parser (thread-safe): call :meth:`parse` per frame."""

    def parse(self, pkt: Packet, number: int = 0) -> PacketRecord:
        rec = PacketRecord(number=number)
        try:
            rec.timestamp = float(pkt.time)
        except Exception:
            rec.timestamp = 0.0
        try:
            rec.length = len(pkt)
        except Exception:
            rec.length = 0
        try:
            # Full frame bytes for the inspector's Hex/ASCII/Raw views.
            # In-memory only (bounded history); not persisted or exported.
            rec.raw = bytes(pkt)
        except Exception:
            rec.raw = b""

        tree: List[DetailNode] = []

        # ---- Link layer --------------------------------------------------
        if pkt.haslayer(Ether):
            eth = pkt[Ether]
            rec.src_mac = eth.src
            rec.dst_mac = eth.dst
            rec.ethertype = int(eth.type) if eth.type is not None else None
            names = ETHERTYPES.get(rec.ethertype, f"0x{rec.ethertype:04x}" if rec.ethertype else "")
            tree.append((
                "Ethernet II", f"{eth.src} → {eth.dst}", [
                    ("Source MAC", eth.src, []),
                    ("Destination MAC", eth.dst, []),
                    ("EtherType", f"0x{rec.ethertype:04x} ({names})" if rec.ethertype else "", []),
                ],
            ))

        # ---- ARP ---------------------------------------------------------
        if pkt.haslayer(ARP):
            self._parse_arp(pkt[ARP], rec, tree)
            rec.detail_tree = tree
            return rec

        # ---- Network layer ----------------------------------------------
        ip_layer = None
        if pkt.haslayer(IP):
            ip_layer = pkt[IP]
            self._parse_ipv4(ip_layer, rec, tree)
        elif pkt.haslayer(IPv6):
            ip_layer = pkt[IPv6]
            self._parse_ipv6(ip_layer, rec, tree)

        # ---- Transport / L4 ---------------------------------------------
        if pkt.haslayer(TCP):
            self._parse_tcp(pkt, pkt[TCP], rec, tree)
        elif pkt.haslayer(UDP):
            self._parse_udp(pkt, pkt[UDP], rec, tree)
        elif pkt.haslayer(ICMP):
            self._parse_icmp(pkt[ICMP], rec, tree)
        elif self._parse_icmpv6(pkt, rec, tree):
            pass
        elif ip_layer is None and pkt.haslayer(Ether):
            rec.protocol = ETHERTYPES.get(rec.ethertype, "OTHER")
            rec.info = rec.info or f"Ethernet frame (type 0x{rec.ethertype:04x})" if rec.ethertype else "Ethernet frame"

        if not rec.info:
            rec.info = f"{rec.protocol} {rec.src_socket} → {rec.dst_socket}"

        rec.detail_tree = tree
        return rec

    # ------------------------------------------------------------------ ARP
    def _parse_arp(self, arp: ARP, rec: PacketRecord, tree: List[DetailNode]) -> None:
        rec.protocol = "ARP"
        rec.src_ip = arp.psrc
        rec.dst_ip = arp.pdst
        op = ARP_OPS.get(int(arp.op), str(arp.op))
        rec.meta["arp"] = {
            "op": int(arp.op),
            "op_name": op,
            "sender_ip": arp.psrc,
            "sender_mac": arp.hwsrc,
            "target_ip": arp.pdst,
            "target_mac": arp.hwdst,
        }
        if int(arp.op) == 1:
            rec.info = f"Who has {arp.pdst}? Tell {arp.psrc}"
        else:
            rec.info = f"{arp.psrc} is at {arp.hwsrc}"
        tree.append((
            "ARP", op, [
                ("Operation", f"{arp.op} ({op})", []),
                ("Sender IP", arp.psrc, []),
                ("Sender MAC", arp.hwsrc, []),
                ("Target IP", arp.pdst, []),
                ("Target MAC", arp.hwdst, []),
            ],
        ))

    # ----------------------------------------------------------------- IPv4
    def _parse_ipv4(self, ip: IP, rec: PacketRecord, tree: List[DetailNode]) -> None:
        rec.ip_version = 4
        rec.src_ip = ip.src
        rec.dst_ip = ip.dst
        rec.ttl = int(ip.ttl)
        rec.ip_proto = int(ip.proto)
        rec.protocol = IP_PROTOCOLS.get(rec.ip_proto, f"IPv4/{rec.ip_proto}")
        flags = str(ip.flags) if ip.flags is not None else ""
        ihl = int(ip.ihl) if ip.ihl is not None else None
        ip_id = int(ip.id) if ip.id is not None else 0
        tos = int(getattr(ip, "tos", 0) or 0)
        tree.append((
            "Internet Protocol Version 4", f"{ip.src} → {ip.dst}", [
                ("Version", "4", []),
                ("Header Length", f"{ihl * 4} bytes ({ihl})" if ihl is not None else "computed", []),
                ("DSCP", str(tos >> 2), []),
                ("ECN", str(tos & 0x03), []),
                ("Total Length", str(ip.len) if ip.len is not None else "computed", []),
                ("Identification", f"0x{ip_id:04x} ({ip_id})", []),
                ("Flags", flags or "(none)", []),
                ("Fragment Offset", str(int(ip.frag or 0)), []),
                ("TTL", str(ip.ttl), []),
                ("Protocol", f"{ip.proto} ({IP_PROTOCOLS.get(rec.ip_proto, '?')})", []),
                ("Header Checksum", f"0x{int(ip.chksum or 0):04x}", []),
                ("Source IP", ip.src, []),
                ("Destination IP", ip.dst, []),
            ],
        ))

    # ----------------------------------------------------------------- IPv6
    def _parse_ipv6(self, ip: IPv6, rec: PacketRecord, tree: List[DetailNode]) -> None:
        rec.ip_version = 6
        rec.src_ip = ip.src
        rec.dst_ip = ip.dst
        rec.ttl = int(ip.hlim)
        rec.ip_proto = int(ip.nh)
        rec.protocol = IP_PROTOCOLS.get(rec.ip_proto, f"IPv6/{rec.ip_proto}")
        tree.append((
            "Internet Protocol Version 6", f"{ip.src} → {ip.dst}", [
                ("Version", "6", []),
                ("Traffic Class", str(getattr(ip, "tc", 0)), []),
                ("Flow Label", str(getattr(ip, "fl", 0)), []),
                ("Payload Length", str(ip.plen) if ip.plen is not None else "computed", []),
                ("Next Header", f"{ip.nh} ({IP_PROTOCOLS.get(rec.ip_proto, '?')})", []),
                ("Hop Limit", str(ip.hlim), []),
                ("Source", ip.src, []),
                ("Destination", ip.dst, []),
            ],
        ))

    # ------------------------------------------------------------------ TCP
    def _parse_tcp(self, pkt, tcp: TCP, rec: PacketRecord, tree) -> None:
        rec.src_port = int(tcp.sport)
        rec.dst_port = int(tcp.dport)
        flags_int = int(tcp.flags)
        rec.tcp_flags = tcp_flags_str(flags_int)
        rec.tcp_seq = int(tcp.seq)
        rec.tcp_ack = int(tcp.ack)
        rec.tcp_window = int(tcp.window)

        payload = l4_payload(tcp)
        rec.tcp_payload_len = len(payload)

        # Application-layer classification
        classified = False
        if http_mod.looks_like_http(payload, rec.src_port, rec.dst_port):
            http_mod.parse_http(payload, rec, tree)
            classified = True
        elif tls_mod.looks_like_tls(payload, rec.src_port, rec.dst_port):
            tls_mod.parse_tls(payload, rec, tree)
            classified = True

        if not classified:
            rec.protocol = "TCP"
            rec.info = (
                f"{rec.src_port} → {rec.dst_port} [{tcp_flags_expand(flags_int)}] "
                f"Seq={rec.tcp_seq} Ack={rec.tcp_ack} Win={rec.tcp_window} "
                f"Len={rec.tcp_payload_len}"
            )

        tree.append((
            "Transmission Control Protocol",
            f"{rec.src_port} → {rec.dst_port} [{rec.tcp_flags}] len={rec.tcp_payload_len}",
            [
                ("Source Port", str(rec.src_port), []),
                ("Destination Port", str(rec.dst_port), []),
                ("Sequence Number", str(rec.tcp_seq), []),
                ("Acknowledgment Number", str(rec.tcp_ack), []),
                ("Header Length", f"{tcp.dataofs * 4} bytes ({tcp.dataofs})" if tcp.dataofs else "computed", []),
                ("Flags", f"{rec.tcp_flags} ({tcp_flags_expand(flags_int)})", [
                    ("FIN", str(bool(flags_int & 0x01)), []),
                    ("SYN", str(bool(flags_int & 0x02)), []),
                    ("RST", str(bool(flags_int & 0x04)), []),
                    ("PSH", str(bool(flags_int & 0x08)), []),
                    ("ACK", str(bool(flags_int & 0x10)), []),
                    ("URG", str(bool(flags_int & 0x20)), []),
                    ("ECE", str(bool(flags_int & 0x40)), []),
                    ("CWR", str(bool(flags_int & 0x80)), []),
                ]),
                ("Window Size", str(rec.tcp_window), []),
                ("Checksum", f"0x{int(tcp.chksum or 0):04x}", []),
                ("Urgent Pointer", str(tcp.urgptr), []),
                ("Payload Length", str(rec.tcp_payload_len), []),
            ],
        ))

    # ------------------------------------------------------------------ UDP
    def _parse_udp(self, pkt, udp: UDP, rec: PacketRecord, tree) -> None:
        rec.src_port = int(udp.sport)
        rec.dst_port = int(udp.dport)
        rec.protocol = "UDP"

        # DNS?
        if pkt.haslayer(DNS):
            dns_mod.parse_dns(pkt[DNS], rec, tree)
        # DHCP?
        elif pkt.haslayer(DHCP) or pkt.haslayer(BOOTP):
            dhcp_mod.parse_dhcp(pkt, rec, tree)
        else:
            ulen = int(udp.len) if udp.len is not None else "?"
            rec.info = f"{rec.src_port} → {rec.dst_port}  Len={ulen}"

        tree.append((
            "User Datagram Protocol",
            f"{rec.src_port} → {rec.dst_port}", [
                ("Source Port", str(rec.src_port), []),
                ("Destination Port", str(rec.dst_port), []),
                ("Length", str(int(udp.len)) if udp.len is not None else "computed", []),
                ("Checksum", f"0x{int(udp.chksum or 0):04x}", []),
            ],
        ))

    # ----------------------------------------------------------------- ICMP
    def _parse_icmp(self, icmp: ICMP, rec: PacketRecord, tree) -> None:
        rec.protocol = "ICMP"
        t = int(icmp.type)
        c = int(icmp.code)
        tname = ICMP_TYPES.get(t, str(t))
        rec.meta["icmp"] = {"type": t, "code": c, "type_name": tname,
                            "id": int(getattr(icmp, "id", 0) or 0),
                            "seq": int(getattr(icmp, "seq", 0) or 0)}
        rec.info = f"{tname} (type={t}, code={c})"
        tree.append((
            "Internet Control Message Protocol", tname, [
                ("Type", f"{t} ({tname})", []),
                ("Code", str(c), []),
                ("Checksum", f"0x{int(icmp.chksum or 0):04x}", []),
                ("Identifier", str(getattr(icmp, "id", "")), []),
                ("Sequence", str(getattr(icmp, "seq", "")), []),
            ],
        ))

    # --------------------------------------------------------------- ICMPv6
    def _parse_icmpv6(self, pkt, rec: PacketRecord, tree) -> bool:
        mapping = [
            (ICMPv6EchoRequest, "Echo Request"),
            (ICMPv6EchoReply, "Echo Reply"),
            (ICMPv6DestUnreach, "Destination Unreachable"),
            (ICMPv6TimeExceeded, "Time Exceeded"),
            (ICMPv6ND_NS, "Neighbor Solicitation"),
            (ICMPv6ND_NA, "Neighbor Advertisement"),
        ]
        for layer, name in mapping:
            if pkt.haslayer(layer):
                rec.protocol = "ICMPv6"
                l = pkt[layer]
                t = int(getattr(l, "type", 0) or 0)
                c = int(getattr(l, "code", 0) or 0)
                rec.meta["icmpv6"] = {"type": t, "code": c, "type_name": name}
                rec.info = f"{name} (type={t}, code={c})"
                tree.append((
                    "Internet Control Message Protocol v6", name, [
                        ("Type", f"{t} ({name})", []),
                        ("Code", str(c), []),
                    ],
                ))
                return True
        return False
