"""DHCP parsing - DISCOVER / OFFER / REQUEST / ACK / NAK / DECLINE / RELEASE.

Extracts the client MAC, assigned/requested IP, DHCP server, gateway (router),
DNS servers and lease time where present.
"""
from __future__ import annotations

from typing import List

from scapy.layers.dhcp import BOOTP, DHCP

from .model import DetailNode, PacketRecord

DHCP_MSG_TYPES = {
    1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE",
    5: "ACK", 6: "NAK", 7: "RELEASE", 8: "INFORM",
}


def _mac_from_chaddr(chaddr: bytes) -> str:
    try:
        return ":".join(f"{b:02x}" for b in chaddr[:6])
    except Exception:
        return ""


def _text(val) -> str:
    """Decode a DHCP option value that may be bytes (e.g. hostname, vendor)."""
    if isinstance(val, bytes):
        return val.decode("utf-8", "replace")
    return str(val)


def parse_dhcp(pkt, rec: PacketRecord, tree: List[DetailNode]) -> None:
    rec.protocol = "DHCP"
    info = {}

    if pkt.haslayer(BOOTP):
        bootp = pkt[BOOTP]
        info["client_mac"] = _mac_from_chaddr(bytes(bootp.chaddr))
        info["assigned_ip"] = bootp.yiaddr
        info["server_ip"] = bootp.siaddr
        info["client_ip"] = bootp.ciaddr
        info["transaction_id"] = f"0x{int(bootp.xid):08x}"

    msg_type = None
    if pkt.haslayer(DHCP):
        for opt in pkt[DHCP].options:
            if not isinstance(opt, tuple):
                continue
            key = opt[0]
            val = opt[1] if len(opt) > 1 else None
            if key == "message-type":
                msg_type = DHCP_MSG_TYPES.get(int(val), str(val))
            elif key == "server_id":
                info["dhcp_server"] = str(val)
            elif key == "router":
                info["gateway"] = str(val)
            elif key in ("name_server", "domain-name-server"):
                info["dns_servers"] = str(val)
            elif key == "lease_time":
                info["lease_time"] = int(val)
            elif key == "requested_addr":
                info["requested_ip"] = str(val)
            elif key == "subnet_mask":
                info["subnet_mask"] = str(val)
            elif key == "hostname":
                info["hostname"] = _text(val)
            elif key == "vendor_class_id":
                info["vendor_class_id"] = _text(val)

    info["message_type"] = msg_type or "?"
    rec.meta["dhcp"] = info
    rec.info = f"DHCP {info['message_type']}" + (
        f" - {info.get('assigned_ip')}" if info.get("assigned_ip") and info["assigned_ip"] != "0.0.0.0" else ""
    )

    children: List[DetailNode] = [
        ("Message Type", info["message_type"], []),
        ("Client MAC", info.get("client_mac", ""), []),
        ("Host Name", info.get("hostname", ""), []),
        ("Vendor Class", info.get("vendor_class_id", ""), []),
        ("Assigned IP", info.get("assigned_ip", ""), []),
        ("DHCP Server", info.get("dhcp_server", info.get("server_ip", "")), []),
        ("Gateway", info.get("gateway", ""), []),
        ("DNS Server", info.get("dns_servers", ""), []),
        ("Lease Time", str(info.get("lease_time", "")), []),
    ]
    tree.append(("Dynamic Host Configuration Protocol", info["message_type"], children))
