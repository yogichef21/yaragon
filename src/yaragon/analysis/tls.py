"""TLS metadata analysis - NO decryption, ever.

We inspect only the observable, unencrypted portions of the TLS handshake:
record version, handshake type, ClientHello SNI/ALPN/version, ServerHello
chosen version and cipher suite. Application data records are labelled
ENCRYPTED and never touched. This is purely passive metadata analysis.
"""
from __future__ import annotations

import struct
from typing import List, Optional

from .model import DetailNode, PacketRecord

TLS_CONTENT_TYPES = {
    20: "ChangeCipherSpec", 21: "Alert", 22: "Handshake", 23: "Application Data",
}
TLS_VERSIONS = {
    0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1",
    0x0303: "TLS 1.2", 0x0304: "TLS 1.3",
}
HANDSHAKE_TYPES = {
    1: "ClientHello", 2: "ServerHello", 11: "Certificate",
    12: "ServerKeyExchange", 14: "ServerHelloDone", 16: "ClientKeyExchange",
}
# A small readable subset of the IANA cipher-suite registry.
CIPHER_SUITES = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0xC02B: "ECDHE-ECDSA-AES128-GCM-SHA256",
    0xC02F: "ECDHE-RSA-AES128-GCM-SHA256",
    0xC030: "ECDHE-RSA-AES256-GCM-SHA384",
    0xCCA8: "ECDHE-RSA-CHACHA20-POLY1305",
}


def looks_like_tls(payload: bytes, sport: Optional[int], dport: Optional[int]) -> bool:
    if len(payload) < 3:
        return False
    ct = payload[0]
    ver = (payload[1] << 8) | payload[2]
    if ct in TLS_CONTENT_TYPES and ver in TLS_VERSIONS:
        return True
    return dport == 443 or sport == 443


def _parse_client_hello(body: bytes, info: dict) -> None:
    try:
        pos = 0
        ver = struct.unpack(">H", body[pos:pos + 2])[0]
        info["hello_version"] = TLS_VERSIONS.get(ver, f"0x{ver:04x}")
        pos += 2 + 32  # version + random
        sid_len = body[pos]; pos += 1 + sid_len
        cs_len = struct.unpack(">H", body[pos:pos + 2])[0]; pos += 2
        suites = []
        for i in range(0, cs_len, 2):
            cs = struct.unpack(">H", body[pos + i:pos + i + 2])[0]
            suites.append(CIPHER_SUITES.get(cs, f"0x{cs:04x}"))
        info["cipher_suites"] = suites[:20]
        pos += cs_len
        comp_len = body[pos]; pos += 1 + comp_len
        if pos + 2 > len(body):
            return
        ext_total = struct.unpack(">H", body[pos:pos + 2])[0]; pos += 2
        end = pos + ext_total
        while pos + 4 <= end and pos + 4 <= len(body):
            etype, elen = struct.unpack(">HH", body[pos:pos + 4]); pos += 4
            edata = body[pos:pos + elen]; pos += elen
            if etype == 0x0000 and len(edata) >= 5:  # SNI
                name_len = struct.unpack(">H", edata[3:5])[0]
                info["sni"] = edata[5:5 + name_len].decode("latin-1", "replace")
            elif etype == 0x0010:  # ALPN
                protos = []
                p = 2
                while p < len(edata):
                    ln = edata[p]; p += 1
                    protos.append(edata[p:p + ln].decode("latin-1", "replace")); p += ln
                info["alpn"] = protos
    except Exception:
        pass


def _parse_server_hello(body: bytes, info: dict) -> None:
    try:
        ver = struct.unpack(">H", body[0:2])[0]
        info["hello_version"] = TLS_VERSIONS.get(ver, f"0x{ver:04x}")
        pos = 2 + 32
        sid_len = body[pos]; pos += 1 + sid_len
        cs = struct.unpack(">H", body[pos:pos + 2])[0]
        info["chosen_cipher"] = CIPHER_SUITES.get(cs, f"0x{cs:04x}")
    except Exception:
        pass


def parse_tls(payload: bytes, rec: PacketRecord, tree: List[DetailNode]) -> None:
    rec.protocol = "TLS"
    if len(payload) < 5:
        rec.info = "TLS record (truncated)"
        return

    ct = payload[0]
    ver = (payload[1] << 8) | payload[2]
    rec_len = struct.unpack(">H", payload[3:5])[0]
    ct_name = TLS_CONTENT_TYPES.get(ct, str(ct))
    ver_name = TLS_VERSIONS.get(ver, f"0x{ver:04x}")

    info = {
        "content_type": ct_name,
        "record_version": ver_name,
        "encrypted": ct == 23,
    }

    children: List[DetailNode] = [
        ("Content Type", f"{ct} ({ct_name})", []),
        ("Record Version", ver_name, []),
        ("Record Length", str(rec_len), []),
    ]

    if ct == 22 and len(payload) >= 6:  # Handshake
        hs_type = payload[5]
        hs_name = HANDSHAKE_TYPES.get(hs_type, str(hs_type))
        info["handshake_type"] = hs_name
        # Handshake body: the TLS record spans payload[5:5+rec_len]; the 4-byte
        # handshake header is payload[5:9], so the body ends at 5+rec_len (not
        # 9+rec_len, which would bleed into a following concatenated record).
        body = payload[9:5 + rec_len]
        if hs_type == 1:
            _parse_client_hello(body, info)
        elif hs_type == 2:
            _parse_server_hello(body, info)
        children.append(("Handshake Type", f"{hs_type} ({hs_name})", []))
        if info.get("hello_version"):
            children.append(("Hello Version", info["hello_version"], []))
        if info.get("sni"):
            children.append(("Server Name (SNI)", info["sni"], []))
        if info.get("alpn"):
            children.append(("ALPN", ", ".join(info["alpn"]), []))
        if info.get("chosen_cipher"):
            children.append(("Cipher Suite", info["chosen_cipher"], []))
        if info.get("cipher_suites"):
            children.append(("Offered Ciphers", f"{len(info['cipher_suites'])} suites",
                             [(c, "", []) for c in info["cipher_suites"]]))
        sni = f" SNI={info['sni']}" if info.get("sni") else ""
        rec.info = f"TLS {hs_name}{sni} [{ver_name}]"
    elif ct == 23:
        rec.info = f"TLS Application Data [ENCRYPTED, {rec_len} bytes]"
        children.append(("Payload", "ENCRYPTED (not decrypted)", []))
    else:
        rec.info = f"TLS {ct_name} [{ver_name}]"

    rec.meta["tls"] = info
    tree.append(("Transport Layer Security", ct_name, children))
