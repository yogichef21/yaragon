"""Target Intelligence dialog: a per-host profile built from metadata Yaragon
already parsed - names resolved, servers contacted (SNI/HTTP), User-Agents, DHCP
identity, protocols and top peers. Contextual and read-only; not a dashboard.
"""
from __future__ import annotations

from PySide6.QtWidgets import (QDialog, QHBoxLayout, QLabel, QPushButton,
                               QVBoxLayout)

from ..analysis.intel import TargetIntel
from .styles import FONT_MONO, PALETTE


def _join(values, limit: int = 12) -> str:
    vals = sorted(v for v in values if v)
    if not vals:
        return "-"
    shown = vals[:limit]
    extra = len(vals) - len(shown)
    return ", ".join(shown) + (f"  (+{extra} more)" if extra > 0 else "")


class TargetIntelDialog(QDialog):
    def __init__(self, intel: TargetIntel, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Target intelligence · {intel.ip}")
        self.resize(560, 520)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 16, 16, 16)
        lay.setSpacing(6)

        title = QLabel(intel.ip); title.setObjectName("H2")
        lay.addWidget(title)
        sub = QLabel(f"{intel.packets} packet(s) observed")
        sub.setObjectName("Dim")
        lay.addWidget(sub)

        top_peers = sorted(intel.peers.items(), key=lambda kv: kv[1], reverse=True)
        peers_str = _join([f"{ip} ({n})" for ip, n in top_peers]) if top_peers else "-"

        rows = [
            ("MAC address(es)", _join(intel.macs)),
            ("Protocols", _join(intel.protocols)),
            ("Names resolved (DNS)", _join(intel.names_resolved)),
            ("Servers (TLS SNI)", _join(intel.sni)),
            ("HTTP hosts", _join(intel.http_hosts)),
            ("User-Agents", _join(intel.user_agents)),
            ("DHCP hostname", intel.dhcp_hostname or "-"),
            ("DHCP vendor", intel.dhcp_vendor or "-"),
            ("Top peers", peers_str),
        ]
        for key, val in rows:
            k = QLabel(key.upper()); k.setObjectName("StripKey")
            v = QLabel(val); v.setWordWrap(True)
            v.setStyleSheet(f"font-family: {FONT_MONO}; color: {PALETTE['text']};")
            v.setTextInteractionFlags(v.textInteractionFlags().TextSelectableByMouse)
            lay.addWidget(k); lay.addWidget(v)

        lay.addStretch(1)
        btnrow = QHBoxLayout(); btnrow.addStretch(1)
        close = QPushButton("Close"); close.setObjectName("Ghost")
        close.clicked.connect(self.accept)
        btnrow.addWidget(close)
        lay.addLayout(btnrow)
