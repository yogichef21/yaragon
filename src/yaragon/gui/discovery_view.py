"""Discover - interface detection and host discovery with multi-target selection.

Selection model (product intent): checkboxes are the single source of truth.
Click a row to toggle it, use the header "Select all" for the whole (filtered)
set, and a single contextual action - "Continue" - carries the selected targets
into the MITM screen. There are no redundant "select target" buttons or hints.
"""
from __future__ import annotations

from typing import List, Optional, Tuple

from PySide6.QtCore import QObject, Qt, QThread, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (QCheckBox, QComboBox, QHBoxLayout, QHeaderView,
                               QLabel, QLineEdit, QProgressBar, QPushButton,
                               QSizePolicy, QTableWidget, QTableWidgetItem,
                               QToolButton, QVBoxLayout, QWidget)

from ..network.discovery import Host, discover_hosts
from ..network.interfaces import (InterfaceInfo, default_interface,
                                   get_interface, list_interfaces)
from .styles import PALETTE
from .widgets import Card

# host table columns (0 = selection checkbox)
COLS = ["Select", "IP", "MAC", "Hostname", "Status", "Role"]


def _cell(val: str) -> QTableWidgetItem:
    """Build a table cell. A missing value renders as a dim, centered '-' so an
    empty cell reads as 'no value' rather than a broken or misaligned control."""
    if val:
        return QTableWidgetItem(val)
    item = QTableWidgetItem("-")
    item.setTextAlignment(Qt.AlignCenter)
    item.setForeground(QColor(PALETTE["muted"]))
    return item


class _DiscoveryWorker(QObject):
    finished = Signal(list)
    progress = Signal(int, int)
    error = Signal(str)

    def __init__(self, iface: InterfaceInfo):
        super().__init__()
        self.iface = iface

    def run(self):
        try:
            hosts = discover_hosts(self.iface, progress=lambda d, t: self.progress.emit(d, t))
            self.finished.emit(hosts)
        except Exception as exc:
            self.error.emit(str(exc))


class DiscoveryView(QWidget):
    interface_selected = Signal(str)
    targets_selected = Signal(list)      # list[(ip, mac)] - chosen MITM targets
    capture_only_requested = Signal()    # go straight to Investigate, no MITM

    def __init__(self, parent=None):
        super().__init__(parent)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(24, 22, 24, 24)
        lay.setSpacing(14)

        header = QLabel("Discover"); header.setObjectName("H1")
        lay.addWidget(header)
        sub = QLabel("Interfaces are detected automatically. Discover hosts, then "
                     "choose one or more targets.")
        sub.setObjectName("Dim"); sub.setWordWrap(True)
        lay.addWidget(sub)

        # ---- interfaces --------------------------------------------------
        # The screen's job is finding hosts, not being an interface reference.
        # So the combo + a one-line readout of the *selected* interface lead;
        # the full per-interface table hides behind a "Details" disclosure.
        ifcard = Card("Interfaces")
        bar = QHBoxLayout()
        self.iface_combo = QComboBox()
        self.refresh_btn = QPushButton("Re-scan interfaces")
        self.refresh_btn.setObjectName("Ghost")
        self.details_btn = QToolButton()
        self.details_btn.setText("Details")
        self.details_btn.setCheckable(True)
        self.details_btn.setArrowType(Qt.RightArrow)
        self.details_btn.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        self.details_btn.setToolTip("Show every detected interface")
        bar.addWidget(QLabel("Active interface:"))
        bar.addWidget(self.iface_combo, 1)
        bar.addWidget(self.details_btn)
        bar.addWidget(self.refresh_btn)
        w = QWidget(); w.setLayout(bar); ifcard.add(w)

        self.iface_readout = QLabel("-"); self.iface_readout.setObjectName("Mono")
        ifcard.add(self.iface_readout)

        self.iface_table = QTableWidget(0, 7)
        self.iface_table.setHorizontalHeaderLabels(
            ["Name", "Type", "Status", "IPv4", "IPv6", "MAC", "MTU"])
        self.iface_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.iface_table.verticalHeader().setVisible(False)
        self.iface_table.verticalHeader().setDefaultSectionSize(30)
        self.iface_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.iface_table.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.iface_table.setMaximumHeight(240)   # scrolls beyond this; never clips a row
        self.iface_table.hide()   # revealed only via the Details disclosure
        ifcard.add(self.iface_table)
        lay.addWidget(ifcard)

        # ---- hosts -------------------------------------------------------
        hostcard = Card("Hosts")
        top = QHBoxLayout()
        self.scan_btn = QPushButton("Discover Hosts"); self.scan_btn.setObjectName("Primary")
        self.host_search = QLineEdit()
        self.host_search.setPlaceholderText("Filter by IP, MAC, hostname or role…")
        self.host_search.setClearButtonEnabled(True)
        self.shown_lbl = QLabel(""); self.shown_lbl.setObjectName("Dim")
        self.progress = QProgressBar(); self.progress.setVisible(False); self.progress.setMaximumWidth(160)
        top.addWidget(self.scan_btn)
        top.addWidget(self.host_search, 1)
        top.addWidget(self.shown_lbl)
        top.addWidget(self.progress)
        tw = QWidget(); tw.setLayout(top); hostcard.add(tw)

        self.host_table = QTableWidget(0, len(COLS))
        self.host_table.setHorizontalHeaderLabels(COLS)
        hh = self.host_table.horizontalHeader()
        hh.setSectionResizeMode(QHeaderView.Stretch)
        hh.setSectionResizeMode(0, QHeaderView.Fixed)
        self.host_table.setColumnWidth(0, 66)
        self.host_table.verticalHeader().setVisible(False)
        self.host_table.verticalHeader().setDefaultSectionSize(30)
        self.host_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.host_table.setSelectionMode(QTableWidget.NoSelection)
        self.host_table.setShowGrid(False)
        # Fill the card and scroll internally, so a long host list never pushes
        # rows off the bottom of the window.
        self.host_table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.host_table.setMinimumHeight(260)
        self.host_table.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        hostcard.add(self.host_table)

        # dedicated, danger-coloured error line (never overwrites the selection
        # status label); cleared on a new scan.
        self.error_lbl = QLabel(""); self.error_lbl.setWordWrap(True)
        self.error_lbl.setStyleSheet(f"color: {PALETTE['danger']}; font-weight: 600;")
        self.error_lbl.hide()
        hostcard.add(self.error_lbl)

        # single contextual action area - un-ticking "Select all" is the way to
        # clear a selection; the count label communicates state.
        actions = QHBoxLayout()
        self.select_all = QCheckBox("Select all")
        self.selected_lbl = QLabel("No hosts discovered yet")
        self.selected_lbl.setObjectName("Dim")
        self.capture_only_btn = QPushButton("Capture only"); self.capture_only_btn.setObjectName("Ghost")
        self.capture_only_btn.setToolTip("Skip MITM - go to Investigate and passively "
                                         "capture on this interface")
        # One primary action, by phase: scan is primary until a target is picked,
        # then Continue takes over (see _update_counts). Start Ghost/disabled.
        self.continue_btn = QPushButton("Continue"); self.continue_btn.setObjectName("Ghost")
        self.continue_btn.setEnabled(False)
        actions.addWidget(self.select_all)
        actions.addWidget(self.selected_lbl)
        actions.addStretch(1)
        actions.addWidget(self.capture_only_btn)
        actions.addWidget(self.continue_btn)
        aw = QWidget(); aw.setLayout(actions); hostcard.add(aw)
        lay.addWidget(hostcard, 1)

        self._hosts: List[Host] = []
        self._thread: Optional[QThread] = None
        self._populating = False

        self.refresh_btn.clicked.connect(self.refresh_interfaces)
        self.details_btn.toggled.connect(self._toggle_details)
        self.iface_combo.currentIndexChanged.connect(self._emit_iface)
        self.scan_btn.clicked.connect(self.start_scan)
        self.host_search.textChanged.connect(self._filter_hosts)
        self.host_table.cellClicked.connect(self._on_cell_clicked)
        self.host_table.itemChanged.connect(self._on_item_changed)
        self.select_all.toggled.connect(self._toggle_select_all)
        self.continue_btn.clicked.connect(self._continue)
        self.capture_only_btn.clicked.connect(self.capture_only_requested.emit)

        self.refresh_interfaces()

    def _toggle_details(self, shown: bool) -> None:
        self.iface_table.setVisible(shown)
        self.details_btn.setArrowType(Qt.DownArrow if shown else Qt.RightArrow)

    def _set_primary(self, btn: QPushButton, primary: bool) -> None:
        """Swap a button between the filled-amber primary and the quiet ghost
        style, re-polishing so the QSS #Primary/#Ghost rule takes effect."""
        btn.setObjectName("Primary" if primary else "Ghost")
        btn.style().unpolish(btn); btn.style().polish(btn)

    # ---- interfaces --------------------------------------------------
    def refresh_interfaces(self) -> None:
        ifaces = list_interfaces()
        current = self.iface_combo.currentData()
        self.iface_combo.blockSignals(True)
        self.iface_combo.clear()
        self.iface_table.setRowCount(0)
        for iface in ifaces:
            label = iface.name + (f"  ({iface.display_name})"
                                  if iface.display_name and iface.display_name != iface.name else "")
            self.iface_combo.addItem(label, iface.name)
            r = self.iface_table.rowCount(); self.iface_table.insertRow(r)
            values = [iface.name, iface.display_name or iface.kind, iface.link_state,
                      iface.ipv4, iface.ipv6, iface.mac,
                      str(iface.mtu) if iface.mtu else ""]
            for c, val in enumerate(values):
                item = _cell(val)
                if c == 2 and val:
                    item.setForeground(QColor(PALETTE["ok"] if iface.is_up else PALETTE["muted"]))
                self.iface_table.setItem(r, c, item)
        names = [i.name for i in ifaces]
        target = current if current in names else default_interface()
        if target:
            idx = self.iface_combo.findData(target)
            if idx >= 0:
                self.iface_combo.setCurrentIndex(idx)
        self.iface_combo.blockSignals(False)
        self._emit_iface(self.iface_combo.currentIndex())

    def _emit_iface(self, _index: int) -> None:
        name = self.iface_combo.currentData()
        self.capture_only_btn.setEnabled(bool(name))
        iface = get_interface(name) if name else None
        if iface:
            state = "up" if iface.is_up else "down"
            self.iface_readout.setText(
                f"{iface.name} · {state} · {iface.ipv4 or 'no IPv4'}")
        else:
            self.iface_readout.setText("-")
        if name:
            self.interface_selected.emit(name)

    def selected_interface(self) -> Optional[InterfaceInfo]:
        return get_interface(self.iface_combo.currentData())

    # ---- scan --------------------------------------------------------
    def start_scan(self) -> None:
        iface = self.selected_interface()
        if not iface:
            return
        self.scan_btn.setEnabled(False)
        self.error_lbl.clear(); self.error_lbl.hide()
        self.progress.setVisible(True); self.progress.setRange(0, 0)
        self._thread = QThread()
        self._worker = _DiscoveryWorker(iface)
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.progress.connect(self._on_progress)
        self._worker.finished.connect(self._on_hosts)
        self._worker.error.connect(self._on_error)
        self._worker.finished.connect(self._thread.quit)
        self._worker.error.connect(self._thread.quit)
        self._thread.start()

    def _on_progress(self, done: int, total: int) -> None:
        self.progress.setRange(0, total); self.progress.setValue(done)

    def _on_error(self, msg: str) -> None:
        self.scan_btn.setEnabled(True); self.progress.setVisible(False)
        self.error_lbl.setText(f"Discovery failed: {msg}")
        self.error_lbl.show()

    def _on_hosts(self, hosts: List[Host]) -> None:
        self._hosts = hosts
        self.scan_btn.setEnabled(True)
        self.progress.setVisible(False)
        self.host_search.clear()
        self.select_all.blockSignals(True); self.select_all.setChecked(False)
        self.select_all.blockSignals(False)

        self._populating = True
        self.host_table.setRowCount(0)
        for h in hosts:
            r = self.host_table.rowCount(); self.host_table.insertRow(r)
            chk = QTableWidgetItem()
            chk.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled)
            chk.setCheckState(Qt.Unchecked)
            self.host_table.setItem(r, 0, chk)
            for c, val in enumerate([h.ip, h.mac, h.hostname, h.status, h.role], start=1):
                item = _cell(val)
                if c == 5 and "gateway" in h.role:
                    item.setForeground(QColor(PALETTE["accent"]))
                self.host_table.setItem(r, c, item)
        self._populating = False
        self._update_counts()

    # ---- selection ---------------------------------------------------
    def _on_cell_clicked(self, row: int, col: int) -> None:
        # Clicking anywhere except the checkbox itself toggles the row.
        if col == 0:
            return
        item = self.host_table.item(row, 0)
        if item:
            item.setCheckState(Qt.Unchecked if item.checkState() == Qt.Checked else Qt.Checked)

    def _on_item_changed(self, _item) -> None:
        if not self._populating:
            self._update_counts()

    def _toggle_select_all(self, checked: bool) -> None:
        state = Qt.Checked if checked else Qt.Unchecked
        self._populating = True
        for r in range(self.host_table.rowCount()):
            if not self.host_table.isRowHidden(r):
                self.host_table.item(r, 0).setCheckState(state)
        self._populating = False
        self._update_counts()

    def _selected(self) -> List[Tuple[str, str]]:
        out = []
        for r in range(self.host_table.rowCount()):
            item = self.host_table.item(r, 0)
            if item and item.checkState() == Qt.Checked and r < len(self._hosts):
                out.append((self._hosts[r].ip, self._hosts[r].mac))
        return out

    def _continue(self) -> None:
        sel = self._selected()
        if sel:
            self.targets_selected.emit(sel)

    # ---- filter / counts ---------------------------------------------
    def _filter_hosts(self, text: str) -> None:
        q = text.lower().strip()
        for r in range(self.host_table.rowCount()):
            if not q:
                self.host_table.setRowHidden(r, False)
                continue
            match = any(self.host_table.item(r, c) and q in self.host_table.item(r, c).text().lower()
                        for c in range(1, len(COLS)))
            self.host_table.setRowHidden(r, not match)
        self._update_counts()

    def _update_counts(self) -> None:
        total = self.host_table.rowCount()
        shown = sum(0 if self.host_table.isRowHidden(r) else 1 for r in range(total))
        selected = len(self._selected())
        self.shown_lbl.setText(f"{shown} of {total}" if total else "")
        if total == 0:
            self.selected_lbl.setText("No hosts discovered yet")
        elif selected == 0:
            self.selected_lbl.setText("Select one or more hosts")
        else:
            self.selected_lbl.setText(f"{selected} target{'s' if selected != 1 else ''} selected")
        self.selected_lbl.setStyleSheet(
            f"color: {PALETTE['primary'] if selected else PALETTE['text_dim']};")
        self.continue_btn.setEnabled(selected > 0)

        # One filled-amber primary at a time (BRAND): before a target is picked,
        # "Discover Hosts" is primary; once ≥1 is selected, Continue takes over
        # and scan demotes to a quiet "Re-scan".
        self._set_primary(self.continue_btn, selected > 0)
        self._set_primary(self.scan_btn, selected == 0)
        self.scan_btn.setText("Re-scan" if total else "Discover Hosts")
