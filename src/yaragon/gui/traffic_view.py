"""Traffic Monitor - the primary screen after MITM starts.

Layout: a slim, readable packet table on the left and an OSI/Hex/ASCII packet
inspector on the right. Protocol filtering is a row of one-click chips; below
them, dedicated Source IP / Destination IP boxes and a free-text search (which
also filters by port when given a bare number) narrow the table. Updates are
batched so the GUI never stalls under load.
"""
from __future__ import annotations

from collections import deque
from typing import List, Optional

from PySide6.QtCore import (QAbstractTableModel, QModelIndex, QSortFilterProxyModel,
                            Qt, Signal)
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (QApplication, QButtonGroup, QHBoxLayout,
                               QLabel, QLineEdit, QMenu, QPushButton, QSplitter,
                               QStackedWidget, QTableView, QVBoxLayout, QWidget)

from ..analysis.model import PacketRecord
from .packet_inspector import PacketInspector
from .styles import FONT_UI, PALETTE, PROTOCOL_COLORS
from .widgets import EmptyState

COLUMNS = ["#", "Time (s)", "Protocol", "Source", "Destination", "Length", "Info"]
CHIPS = ["All", "TCP", "UDP", "DNS", "HTTP", "TLS", "ARP", "ICMP", "DHCP"]
RIGHT_ALIGNED = {0, 5}  # numeric columns: # and Length


class TrafficModel(QAbstractTableModel):
    def __init__(self, limit: int = 5000, parent=None):
        super().__init__(parent)
        self._rows: deque = deque(maxlen=limit)
        # Epoch time of the session's first packet; the Time column is rendered
        # relative to it (seconds, ms precision) so timing is legible.
        self._t0: Optional[float] = None

    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent=QModelIndex()) -> int:
        return len(COLUMNS)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return COLUMNS[section]
        return None

    def data(self, index: QModelIndex, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        rec: PacketRecord = self._rows[index.row()]
        col = index.column()
        if role == Qt.DisplayRole:
            return [
                str(rec.number), self._rel_time(rec), rec.protocol,
                rec.src_socket, rec.dst_socket, str(rec.length), rec.info,
            ][col]
        if role == Qt.ForegroundRole and col == 2:
            return QColor(PROTOCOL_COLORS.get(rec.protocol, PALETTE["text"]))
        if role == Qt.TextAlignmentRole and col in RIGHT_ALIGNED:
            return int(Qt.AlignRight | Qt.AlignVCenter)
        return None

    def _rel_time(self, rec: PacketRecord) -> str:
        if self._t0 is None or not rec.timestamp:
            return ""
        return f"{rec.timestamp - self._t0:.3f}"

    def append_batch(self, records: List[PacketRecord]) -> None:
        if not records:
            return
        if self._t0 is None:
            # The session's first packet with a real timestamp anchors t0.
            for r in records:
                if r.timestamp:
                    self._t0 = r.timestamp
                    break
        over = len(self._rows) + len(records) - (self._rows.maxlen or 0)
        if over > 0:
            self.beginResetModel(); self._rows.extend(records); self.endResetModel()
        else:
            start = len(self._rows)
            self.beginInsertRows(QModelIndex(), start, start + len(records) - 1)
            self._rows.extend(records)
            self.endInsertRows()

    def record_at(self, row: int) -> Optional[PacketRecord]:
        return self._rows[row] if 0 <= row < len(self._rows) else None

    def clear(self) -> None:
        self.beginResetModel(); self._rows.clear(); self._t0 = None; self.endResetModel()


class TrafficProxy(QSortFilterProxyModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.proto = "All"
        self.text = ""
        self.src_ip = ""
        self.dst_ip = ""
        self.pair = None   # frozenset{A, B} - "follow conversation" both ways

    def set_proto(self, proto: str):
        self.proto = proto; self.invalidate()

    def set_pair(self, pair):
        """Follow one A<->B conversation: keep only packets whose endpoints are
        exactly {A, B}, in either direction. `pair` is (a, b) or None to clear."""
        self.pair = frozenset(pair) if pair else None
        self.invalidate()

    def set_text(self, text: str):
        self.text = text.lower().strip(); self.invalidate()

    def set_src_ip(self, text: str):
        self.src_ip = text.lower().strip(); self.invalidate()

    def set_dst_ip(self, text: str):
        self.dst_ip = text.lower().strip(); self.invalidate()

    def filterAcceptsRow(self, row: int, parent: QModelIndex) -> bool:
        model: TrafficModel = self.sourceModel()
        rec = model.record_at(row)
        if rec is None:
            return False
        if self.proto != "All" and rec.protocol != self.proto:
            return False
        if self.pair is not None and frozenset((rec.src_ip, rec.dst_ip)) != self.pair:
            return False
        if self.src_ip and self.src_ip not in rec.src_ip.lower():
            return False
        if self.dst_ip and self.dst_ip not in rec.dst_ip.lower():
            return False
        if self.text:
            # A bare number is a strict port filter - an exact match on either
            # port, with no substring fallthrough, so "80" does not also match
            # 10.0.0.80 or port 8080. Any other text is a substring search over
            # the endpoints/protocol/info.
            if self.text.isdigit():
                n = int(self.text)
                return rec.src_port == n or rec.dst_port == n
            hay = f"{rec.src_socket} {rec.dst_socket} {rec.protocol} {rec.info}".lower()
            if self.text not in hay:
                return False
        return True


class TrafficView(QWidget):
    start_requested = Signal()          # begin (or resume) packet capture
    pause_requested = Signal()          # pause capture, keeping captured packets
    stop_requested = Signal()           # stop the session, keeping captured packets
    clear_requested = Signal()          # clear displayed traffic from this session
    export_requested = Signal()         # save the capture to a .pcap file
    open_requested = Signal()           # open a saved .pcap for offline inspection

    def __init__(self, limit: int = 5000, parent=None):
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 22, 24, 24)
        root.setSpacing(12)

        head = QVBoxLayout(); head.setSpacing(2)
        h = QLabel("Investigate"); h.setObjectName("H1")
        self.subtitle = QLabel("Packets on the selected interface - controlled below.")
        self.subtitle.setObjectName("Dim")
        head.addWidget(h); head.addWidget(self.subtitle)
        root.addLayout(head)

        # row 1: the capture lifecycle as a contextual state machine -
        # Start/Resume · Pause · Stop on the left, with the capture-time BPF field
        # revealed only during setup; Clear · Export .pcap are contextual
        # session-data actions on the right (enabled only when packets exist).
        controls = QHBoxLayout(); controls.setSpacing(6)
        self.start_btn = QPushButton("Start"); self.start_btn.setObjectName("Primary")
        self.start_btn.setToolTip("Begin packet capture (resumes if paused)")
        self.pause_btn = QPushButton("Pause"); self.pause_btn.setObjectName("Ghost")
        self.pause_btn.setToolTip("Pause capture - captured packets are kept")
        self.stop_btn = QPushButton("Stop"); self.stop_btn.setObjectName("Danger")
        self.stop_btn.setToolTip("Stop the capture session - captured packets are kept")
        self.clear_btn = QPushButton("Clear"); self.clear_btn.setObjectName("Ghost")
        self.clear_btn.setToolTip("Clear the displayed traffic from this session")
        self.export_btn = QPushButton("Export .pcap")
        self.export_btn.setToolTip("Save the captured packets to a .pcap file "
                                   "(open in Wireshark, tcpdump, …)")

        # Capture-time BPF lives with Start (capture setup), not with the display
        # filters - it is applied on Start, not to already-captured rows.
        self.bpf_box = QWidget()
        bpf_l = QHBoxLayout(self.bpf_box); bpf_l.setContentsMargins(0, 0, 0, 0)
        bpf_l.setSpacing(6)
        bpf_lbl = QLabel("Capture filter (BPF)"); bpf_lbl.setObjectName("Dim")
        self.bpf_filter = QLineEdit()
        self.bpf_filter.setPlaceholderText("applied on Start, e.g. tcp port 80")
        self.bpf_filter.setClearButtonEnabled(True); self.bpf_filter.setFixedWidth(260)
        self.bpf_filter.setToolTip("Optional libpcap/BPF expression applied at capture "
                                   "time. Takes effect when you press Start.")
        bpf_l.addWidget(bpf_lbl); bpf_l.addWidget(self.bpf_filter)

        controls.addWidget(self.start_btn)
        controls.addWidget(self.pause_btn)
        controls.addWidget(self.stop_btn)
        controls.addSpacing(8)
        controls.addWidget(self.bpf_box)
        controls.addStretch(1)
        controls.addWidget(self.clear_btn)
        controls.addWidget(self.export_btn)
        root.addLayout(controls)

        # row 2: protocol filter chips
        bar = QHBoxLayout(); bar.setSpacing(6)
        self._chip_group = QButtonGroup(self); self._chip_group.setExclusive(True)
        for i, name in enumerate(CHIPS):
            chip = QPushButton(name); chip.setCheckable(True); chip.setObjectName("Chip")
            self._style_chip(chip, name)
            chip.clicked.connect(lambda _=False, n=name: self.proxy.set_proto(n))
            if name == "All":
                # "All" is the reset: it also clears a followed conversation.
                chip.clicked.connect(lambda _=False: self.proxy.set_pair(None))
            self._chip_group.addButton(chip, i)
            bar.addWidget(chip)
            if i == 0:
                chip.setChecked(True)
        bar.addStretch(1)
        root.addLayout(bar)

        # row 3: display filters that narrow the already-captured rows -
        # Source/Destination IP (also set by the right-click pivots) + a
        # free-text search (a bare number filters by port).
        filters = QHBoxLayout(); filters.setSpacing(6)
        self.src_filter = QLineEdit(); self.src_filter.setPlaceholderText("Source IP")
        self.src_filter.setClearButtonEnabled(True); self.src_filter.setFixedWidth(180)
        self.dst_filter = QLineEdit(); self.dst_filter.setPlaceholderText("Destination IP")
        self.dst_filter.setClearButtonEnabled(True); self.dst_filter.setFixedWidth(180)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search info · type a number to filter by port (e.g. 443)")
        self.search.setClearButtonEnabled(True)
        filters.addWidget(self.src_filter); filters.addWidget(self.dst_filter)
        filters.addWidget(self.search, 1)
        root.addLayout(filters)

        # Inline "filter matches nothing" line - without it, a filter that hides
        # every row just blanks the table, which reads as "the capture died".
        fe = QHBoxLayout(); fe.setSpacing(8)
        self.filter_empty_lbl = QLabel("No packets match this filter")
        self.filter_empty_lbl.setObjectName("Dim")
        self.clear_filters_btn = QPushButton("Clear filters")
        self.clear_filters_btn.setObjectName("Ghost")
        fe.addWidget(self.filter_empty_lbl)
        fe.addWidget(self.clear_filters_btn)
        fe.addStretch(1)
        self.filter_empty = QWidget(); self.filter_empty.setLayout(fe)
        self.filter_empty.hide()
        root.addWidget(self.filter_empty)

        # packet table (left)  |  inspector (right)
        split = QSplitter(Qt.Horizontal)
        self.model = TrafficModel(limit)
        self.proxy = TrafficProxy(); self.proxy.setSourceModel(self.model)
        self.table = QTableView(); self.table.setModel(self.proxy)
        self.table.setSelectionBehavior(QTableView.SelectRows)
        self.table.setSelectionMode(QTableView.SingleSelection)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        hh = self.table.horizontalHeader()
        hh.setStretchLastSection(True)
        for i, wdt in enumerate((60, 88, 78, 185, 185, 66)):
            self.table.setColumnWidth(i, wdt)

        # The table shares its pane with an empty state shown until the first
        # packet arrives (and again after Clear), so a fresh screen never reads
        # as a broken blank grid.
        self.table_stack = QStackedWidget()
        self._empty = EmptyState(
            "No packets yet",
            "Press Start to capture, or open a saved .pcap to inspect it offline.",
            icon="≣",
            action_text="Open .pcap…",
            on_action=self.open_requested.emit)
        self.table_stack.addWidget(self._empty)
        self.table_stack.addWidget(self.table)
        self.table_stack.setCurrentWidget(self._empty)
        split.addWidget(self.table_stack)

        self.inspector = PacketInspector(compact=True)
        split.addWidget(self.inspector)
        split.setStretchFactor(0, 3); split.setStretchFactor(1, 2)
        split.setSizes([780, 460])
        root.addWidget(split, 1)

        self.search.textChanged.connect(self.proxy.set_text)
        self.src_filter.textChanged.connect(self.proxy.set_src_ip)
        self.dst_filter.textChanged.connect(self.proxy.set_dst_ip)
        self.start_btn.clicked.connect(self.start_requested.emit)
        self.pause_btn.clicked.connect(self.pause_requested.emit)
        self.stop_btn.clicked.connect(self.stop_requested.emit)
        self.clear_btn.clicked.connect(self.clear_requested.emit)
        self.export_btn.clicked.connect(self.export_requested.emit)
        self.table.selectionModel().selectionChanged.connect(self._on_select)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._table_context_menu)
        self.clear_filters_btn.clicked.connect(self._clear_filters)
        for sig in (self.proxy.layoutChanged, self.proxy.modelReset,
                    self.proxy.rowsInserted, self.proxy.rowsRemoved):
            sig.connect(self._update_filter_empty)
        self._has_packets = False
        self._state = "idle"
        self.set_capture_state("idle")

    def set_has_packets(self, has: bool) -> None:
        """Gate the contextual Clear / Export actions: they only make sense once
        packets exist. Kept separate from the lifecycle state so either can
        change independently."""
        self._has_packets = has
        self._update_data_actions()

    def _update_data_actions(self) -> None:
        offline = self._state == "offline"
        self.clear_btn.setEnabled(offline or self._has_packets)
        self.export_btn.setEnabled(offline or self._has_packets)

    def set_capture_state(self, state: str) -> None:
        """Reflect the real capture state as a contextual control set (DESIGN
        §4.2).

        state is one of "idle", "capturing", "paused", "offline". Buttons are
        enabled only for valid transitions so rapid or repeated presses cannot
        drive an invalid lifecycle (e.g. a second Start spawning a duplicate
        sniffer). Exactly one filled-amber control (Start/Resume) is visible at
        a time.
        """
        self._state = state
        capturing = state == "capturing"
        paused = state == "paused"
        idle = state == "idle"
        offline = state == "offline"

        # Live lifecycle triplet is hidden entirely in offline (.pcap) sessions.
        for b in (self.start_btn, self.pause_btn, self.stop_btn):
            b.setVisible(not offline)
        self.start_btn.setEnabled(idle or paused)
        self.start_btn.setText("Resume" if paused else "Start")
        self.pause_btn.setEnabled(capturing)
        self.stop_btn.setEnabled(capturing or paused)

        # Capture-time BPF is only relevant in the setup (idle) context.
        self.bpf_box.setVisible(idle)

        # Contextual session-data actions.
        self.clear_btn.setText("Close file" if offline else "Clear")
        self._update_data_actions()

    def _style_chip(self, chip: QPushButton, name: str):
        color = PROTOCOL_COLORS.get(name, PALETTE["text_dim"])
        chip.setStyleSheet(
            f"QPushButton#Chip {{ background: transparent; color: {PALETTE['text_dim']};"
            f" border: 1px solid {PALETTE['border']}; border-radius: 13px;"
            f" padding: 4px 12px; font-family: {FONT_UI}; font-weight: 600; }}"
            f"QPushButton#Chip:hover {{ color: {PALETTE['text']}; border-color: {color}; }}"
            f"QPushButton#Chip:checked {{ color: #061024; background: {color};"
            f" border-color: {color}; }}")

    # ---- context -----------------------------------------------------
    def set_context(self, targets, gateway_ip: str, mitm_active: bool) -> None:
        # Honest and static: this subtitle never narrates live state (the status
        # pill and top strip own that). It only reflects an active MITM scope.
        targets = list(targets or [])
        n = len(targets)
        if mitm_active and n:
            tail = f"{n} target{'s' if n != 1 else ''}"
            self.subtitle.setText(f"Packets on the selected interface - MITM session · {tail}.")
        else:
            self.subtitle.setText("Packets on the selected interface - controlled below.")

    def capture_filter(self) -> str:
        """The capture-time BPF expression the operator typed (may be empty)."""
        return self.bpf_filter.text().strip()

    def _update_filter_empty(self, *args) -> None:
        active = self.is_filter_active()
        empty = self.proxy.rowCount() == 0 and self.model.rowCount() > 0
        self.filter_empty.setVisible(active and empty)

    def _clear_filters(self) -> None:
        """Reset every display filter (proto chip, IP boxes, search, followed
        conversation) so the full capture is visible again."""
        self.src_filter.clear()
        self.dst_filter.clear()
        self.search.clear()
        self.proxy.set_pair(None)
        self.proxy.set_proto("All")
        btn = self._chip_group.button(0)
        if btn is not None:
            btn.setChecked(True)
        self._update_filter_empty()

    def is_filter_active(self) -> bool:
        """True when any display filter (proto chip, src/dst IP, search) narrows
        the table below the full capture."""
        return (self.proxy.proto != "All" or bool(self.proxy.src_ip)
                or bool(self.proxy.dst_ip) or bool(self.proxy.text)
                or self.proxy.pair is not None)

    def visible_records(self) -> List[PacketRecord]:
        """The records currently accepted by the active filter, in table order."""
        out: List[PacketRecord] = []
        for row in range(self.proxy.rowCount()):
            src = self.proxy.mapToSource(self.proxy.index(row, 0))
            rec = self.model.record_at(src.row())
            if rec is not None:
                out.append(rec)
        return out

    def set_loaded_file(self, path: str, count: int) -> None:
        """Reflect that an offline .pcap is loaded (not a live capture)."""
        import os
        self.subtitle.setText(
            f"Offline - {count} packet(s) loaded from {os.path.basename(path)}.")

    # ---- packets -----------------------------------------------------
    def append_batch(self, records: List[PacketRecord]) -> None:
        if not records:
            return
        if self.table_stack.currentWidget() is not self.table:
            self.table_stack.setCurrentWidget(self.table)
        sb = self.table.verticalScrollBar()
        at_bottom = sb.value() >= sb.maximum() - 4
        self.model.append_batch(records)
        if not self._has_packets:
            self.set_has_packets(True)
        if at_bottom:
            self.table.scrollToBottom()

    # ---- context menu (pivot & copy) ---------------------------------
    def _table_context_menu(self, pos) -> None:
        idx = self.table.indexAt(pos)
        if not idx.isValid():
            return
        src_row = self.proxy.mapToSource(idx).row()
        cell = self.proxy.data(idx, Qt.DisplayRole)
        menu = self.build_row_menu(src_row, cell)
        if menu is not None:
            menu.exec(self.table.viewport().mapToGlobal(pos))

    def build_row_menu(self, src_row: int, cell_value=None) -> Optional[QMenu]:
        """Build the row context menu. Reuses the existing filter fields and the
        clipboard - no new filter engine. Exposed for headless testing."""
        rec = self.model.record_at(src_row)
        if rec is None:
            return None
        menu = QMenu(self)
        if cell_value:
            act = menu.addAction(f'Copy "{cell_value}"')
            act.triggered.connect(
                lambda _=False, v=str(cell_value): QApplication.clipboard().setText(v))
            menu.addSeparator()
        if rec.src_ip:
            a = menu.addAction(f"Filter by source IP  ({rec.src_ip})")
            a.triggered.connect(lambda _=False, ip=rec.src_ip: self.src_filter.setText(ip))
        if rec.dst_ip:
            a = menu.addAction(f"Filter by destination IP  ({rec.dst_ip})")
            a.triggered.connect(lambda _=False, ip=rec.dst_ip: self.dst_filter.setText(ip))
        port = rec.dst_port or rec.src_port
        if port:
            a = menu.addAction(f"Filter by port  ({port})")
            a.triggered.connect(lambda _=False, p=port: self.search.setText(str(p)))
        if rec.src_ip and rec.dst_ip and rec.src_ip != rec.dst_ip:
            menu.addSeparator()
            a = menu.addAction(
                f"Follow conversation  ({rec.src_ip} ↔ {rec.dst_ip})")
            a.triggered.connect(
                lambda _=False, s=rec.src_ip, d=rec.dst_ip: self.proxy.set_pair((s, d)))
        return menu

    def _on_select(self):
        idx = self.table.selectionModel().currentIndex()
        if not idx.isValid():
            return
        rec = self.model.record_at(self.proxy.mapToSource(idx).row())
        if rec:
            self.inspector.show_packet(rec)

    def clear(self):
        self.model.clear()
        self.table_stack.setCurrentWidget(self._empty)
        self.set_has_packets(False)
