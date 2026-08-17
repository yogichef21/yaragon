"""Follow Stream dialog: the reassembled two-colour transcript of one
conversation. Client→server and server→client are tinted differently so the
exchange reads at a glance. Encrypted (TLS Application Data) spans are shown as a
labelled placeholder - never decrypted.
"""
from __future__ import annotations

import html
from typing import List

from PySide6.QtWidgets import (QDialog, QHBoxLayout, QLabel, QPushButton,
                               QTextEdit, QVBoxLayout)

from ..analysis.stream import StreamSegment
from .styles import FONT_MONO, PALETTE


class FollowStreamDialog(QDialog):
    def __init__(self, a: str, b: str, segments: List[StreamSegment], parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Follow stream · {a} ↔ {b}")
        self.resize(760, 560)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 16, 16, 16)
        lay.setSpacing(10)

        head = QLabel(f"{a}  ↔  {b}")
        head.setObjectName("H2")
        lay.addWidget(head)

        legend = QLabel(
            f"<span style='color:{PALETTE['accent']}'>■</span> {a} → {b}    "
            f"<span style='color:{PALETTE['ok']}'>■</span> {b} → {a}    "
            f"<span style='color:{PALETTE['text_dim']}'>{len(segments)} segment(s)</span>")
        lay.addWidget(legend)

        self.view = QTextEdit()
        self.view.setReadOnly(True)
        self.view.setLineWrapMode(QTextEdit.NoWrap)
        self.view.setStyleSheet(
            f"background: {PALETTE['bg']}; border: 1px solid {PALETTE['border_sub']};"
            f"font-family: {FONT_MONO}; font-size: 12px;")
        lay.addWidget(self.view, 1)

        self._render(a, segments)

        btnrow = QHBoxLayout(); btnrow.addStretch(1)
        close = QPushButton("Close"); close.setObjectName("Ghost")
        close.clicked.connect(self.accept)
        btnrow.addWidget(close)
        lay.addLayout(btnrow)

    def _render(self, a: str, segments: List[StreamSegment]) -> None:
        if not segments:
            self.view.setHtml(
                f"<span style='color:{PALETTE['muted']}'>No application-layer "
                f"payload in this conversation (only control packets).</span>")
            return
        blocks = []
        for seg in segments:
            color = PALETTE["accent"] if seg.src == a else PALETTE["ok"]
            if seg.encrypted:
                body = (f"<i>[{seg.protocol} ENCRYPTED · {len(seg.data)} bytes · "
                        f"not decrypted]</i>")
            else:
                text = seg.data.decode("latin-1", "replace")
                body = html.escape(text).replace("\n", "<br>")
            blocks.append(
                f"<div style='color:{color}; white-space:pre-wrap; "
                f"margin-bottom:8px'><b>{html.escape(seg.src)} → "
                f"{html.escape(seg.dst)}</b><br>{body}</div>")
        self.view.setHtml("".join(blocks))
