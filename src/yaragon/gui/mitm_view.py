"""MITM - validate, start and stop an ARP MITM session against selected targets.

For authorized security testing only. Targets are chosen on the Discover
screen and carried here; the gateway is auto-detected but editable.
"""
from __future__ import annotations

import html
from typing import List, Tuple

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (QHBoxLayout, QLabel, QLineEdit, QListWidget,
                               QPushButton, QTextEdit, QVBoxLayout, QWidget)

from .styles import FONT_MONO, PALETTE
from .widgets import Card, KeyValueRow, StatusPill


class MitmView(QWidget):
    validate_requested = Signal(list, str)   # target_ips, gateway_ip
    start_requested = Signal(list, str)
    stop_requested = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(24, 22, 24, 24)
        lay.setSpacing(14)

        header = QLabel("MITM"); header.setObjectName("H1")
        lay.addWidget(header)

        self.unsupported = QLabel("")
        self.unsupported.setWordWrap(True)
        self.unsupported.setStyleSheet(
            f"color: {PALETTE['text_dim']}; background: {PALETTE['panel_2']};"
            f"border: 1px solid {PALETTE['border']}; border-radius: 10px; padding: 12px;")
        self.unsupported.hide()
        lay.addWidget(self.unsupported)

        top = QHBoxLayout(); top.setSpacing(16)

        # targets
        tgt = Card("Targets")
        self.targets_list = QListWidget()
        self.targets_list.setStyleSheet(f"font-family: {FONT_MONO};")
        self.targets_list.setMinimumHeight(150)
        tgt.add(self.targets_list)
        self.targets_hint = QLabel("Select targets on the Discover screen.")
        self.targets_hint.setObjectName("Dim")
        tgt.add(self.targets_hint)
        top.addWidget(tgt, 2)

        # parameters + session controls
        right = Card("Session")
        self.kv_iface = KeyValueRow("Interface")
        right.add(self.kv_iface)
        grow = QHBoxLayout()
        gl = QLabel("Gateway"); gl.setObjectName("Dim")
        self.gateway_edit = QLineEdit(); self.gateway_edit.setPlaceholderText("auto-detected")
        grow.addWidget(gl); grow.addWidget(self.gateway_edit, 1)
        gw = QWidget(); gw.setLayout(grow); right.add(gw)
        self.kv_gwmac = KeyValueRow("Gateway MAC")
        right.add(self.kv_gwmac)

        prow = QHBoxLayout()
        pl = QLabel("Status"); pl.setObjectName("Dim")
        self.pill = StatusPill("INACTIVE", "off")
        prow.addWidget(pl); prow.addStretch(1); prow.addWidget(self.pill)
        pw = QWidget(); pw.setLayout(prow); right.add(pw)
        self.kv_duration = KeyValueRow("Active since")
        right.add(self.kv_duration)

        # Honest technique boundary, taught where it matters (RESEARCH-5): the
        # attack is ARP-based and IPv4-only. One sentence, never a tutorial panel.
        scope = QLabel("Intercepts IPv4 (ARP). IPv6/NDP traffic is not captured.")
        scope.setObjectName("Dim"); scope.setWordWrap(True)
        right.add(scope)

        self.validate_btn = QPushButton("Dry run"); self.validate_btn.setObjectName("Ghost")
        self.validate_btn.setToolTip(
            "Pre-flight reachability probe - sends no spoofed ARP")
        self.start_btn = QPushButton("Start MITM"); self.start_btn.setObjectName("Primary")
        self.start_btn.setEnabled(False)
        self.stop_btn = QPushButton("Stop MITM"); self.stop_btn.setObjectName("Danger")
        self.stop_btn.setEnabled(False)
        right.add(self.validate_btn); right.add(self.start_btn); right.add(self.stop_btn)
        top.addWidget(right, 1)
        lay.addLayout(top)

        logcard = Card("Activity")
        self.log = QTextEdit(); self.log.setReadOnly(True)
        self.log.setStyleSheet(
            f"background: {PALETTE['bg']}; font-family: {FONT_MONO}; font-size: 12px;")
        logcard.add(self.log)
        lay.addWidget(logcard, 1)

        self._targets: List[Tuple[str, str]] = []
        self._supported = True
        self._active = False
        self._probing = False

        self.validate_btn.clicked.connect(
            lambda: self.validate_requested.emit(self._target_ips(),
                                                 self.gateway_edit.text().strip()))
        self.start_btn.clicked.connect(
            lambda: self.start_requested.emit(self._target_ips(),
                                              self.gateway_edit.text().strip()))
        self.stop_btn.clicked.connect(self.stop_requested.emit)

    # ---- helpers -----------------------------------------------------
    def _target_ips(self) -> List[str]:
        return [ip for ip, _ in self._targets]

    def set_context(self, iface: str, gateway: str, gateway_mac: str = "") -> None:
        self.kv_iface.set_value(iface)
        self.kv_gwmac.set_value(gateway_mac)
        if gateway and not self.gateway_edit.text().strip():
            self.gateway_edit.setText(gateway)

    def _refresh_buttons(self) -> None:
        """Single source of truth for control enablement across targets /
        active / probing / platform-support state."""
        n = len(self._targets)
        can = self._supported and not self._active and not self._probing and n > 0
        self.start_btn.setEnabled(can)
        self.validate_btn.setEnabled(can)
        self.stop_btn.setEnabled(self._supported and self._active)
        self.validate_btn.setText("Probing…" if self._probing else "Dry run")

    def set_targets(self, targets: List[Tuple[str, str]]) -> None:
        self._targets = list(targets)
        self.targets_list.clear()
        for ip, mac in self._targets:
            self.targets_list.addItem(f"{ip:<16} {mac or ''}".rstrip())
        n = len(self._targets)
        self.targets_hint.setText(
            f"{n} target{'s' if n != 1 else ''} selected." if n
            else "Select targets on the Discover screen.")
        self._refresh_buttons()

    def set_probing(self, probing: bool) -> None:
        """Reflect the off-thread dry-run: disable the trigger and show an inline
        'Probing…' label while the reachability worker runs."""
        self._probing = probing
        self._refresh_buttons()

    def append_log(self, text: str, color: str = "text") -> None:
        # The log renders rich text, so escape the message: values interpolated
        # here (target IPs, error strings) must never be treated as markup.
        safe = html.escape(text)
        self.log.append(f"<span style='color:{PALETTE.get(color, PALETTE['text'])}'>{safe}</span>")

    def set_active(self, active: bool, since: str = "") -> None:
        self._active = active
        self.pill.set_state("ACTIVE" if active else "INACTIVE",
                            "warn" if active else "off")
        self._refresh_buttons()
        self.kv_duration.set_value(since or "-")

    def set_degraded(self) -> None:
        """Surface a running session that has stopped intercepting - the one
        place MITM shows danger (red). ACTIVE must never silently lie."""
        self.pill.set_state("DEGRADED", "danger")

    def set_platform_support(self, supported: bool, reason: str = "") -> None:
        self._supported = supported
        if supported:
            self.unsupported.hide()
            return
        self.unsupported.setText("⛔  " + reason)
        self.unsupported.show()
        for w in (self.start_btn, self.stop_btn, self.validate_btn, self.gateway_edit):
            w.setEnabled(False)
        self.pill.set_state("N/A", "off")
