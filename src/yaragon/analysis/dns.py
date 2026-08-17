"""DNS parsing - queries, responses, common record types.

Extracts query name, type, response records, TTL and response code. Supports
A, AAAA, CNAME, MX, NS, TXT, PTR, SOA, SRV among others.
"""
from __future__ import annotations

from typing import List

from scapy.layers.dns import DNS

from .model import DetailNode, PacketRecord

DNS_TYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
    16: "TXT", 28: "AAAA", 33: "SRV", 35: "NAPTR", 43: "DS",
    46: "RRSIG", 48: "DNSKEY", 257: "CAA", 255: "ANY",
}

DNS_RCODES = {
    0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
    4: "NOTIMP", 5: "REFUSED",
}


def _decode(v) -> str:
    if isinstance(v, bytes):
        try:
            return v.decode("utf-8", "replace").rstrip(".")
        except Exception:
            return repr(v)
    return str(v).rstrip(".")


def _rdata(rr) -> str:
    try:
        data = rr.rdata
    except Exception:
        return ""
    if isinstance(data, list):
        return ", ".join(_decode(x) for x in data)
    return _decode(data)


def parse_dns(dns: DNS, rec: PacketRecord, tree: List[DetailNode]) -> None:
    rec.protocol = "DNS"
    is_response = int(dns.qr) == 1
    rcode = int(dns.rcode)
    qname = ""
    qtype = ""
    answers = []

    def _as_list(field):
        if field is None:
            return []
        if isinstance(field, (bytes, str)):
            return []
        try:
            return list(field)
        except TypeError:
            return [field]

    questions = _as_list(dns.qd)
    if questions:
        try:
            qname = _decode(questions[0].qname)
            qtype = DNS_TYPES.get(int(questions[0].qtype), str(questions[0].qtype))
        except Exception:
            pass

    if is_response:
        for rr in _as_list(dns.an):
            try:
                answers.append({
                    "name": _decode(rr.rrname),
                    "type": DNS_TYPES.get(int(rr.type), str(rr.type)),
                    "ttl": int(rr.ttl),
                    "data": _rdata(rr),
                })
            except Exception:
                continue

    rec.meta["dns"] = {
        "is_response": is_response,
        "id": int(dns.id),
        "query": qname,
        "qtype": qtype,
        "rcode": rcode,
        "rcode_name": DNS_RCODES.get(rcode, str(rcode)),
        "answers": answers,
    }

    if is_response:
        summary = ", ".join(f"{a['type']} {a['data']}" for a in answers) or "no records"
        rec.info = f"DNS response {qname} → {summary} [{DNS_RCODES.get(rcode, rcode)}]"
    else:
        rec.info = f"DNS query {qname} ({qtype})"

    children: List[DetailNode] = [
        ("Transaction ID", f"0x{int(dns.id):04x}", []),
        ("Type", "response" if is_response else "query", []),
        ("Response Code", DNS_RCODES.get(rcode, str(rcode)), []),
        ("Question", f"{qname} ({qtype})", []),
    ]
    for a in answers:
        children.append((
            "Answer", f"{a['name']} {a['type']} → {a['data']} (TTL {a['ttl']})", []
        ))
    tree.append(("Domain Name System", "response" if is_response else "query", children))
