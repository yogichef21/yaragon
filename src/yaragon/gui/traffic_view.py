"""Investigate - the heart screen where captured traffic is analysed.

Layout: a slim, sortable packet table on the left and a Decoded/Hex inspector on
the right. Protocol filtering is a row of MULTI-select chips; a free-text search
(a bare number filters by port), Source/Destination IP boxes and right-click
pivots narrow the table, with a live match count and an always-available clear.
A small keyboard set drives the loop (/ focus search, Esc clear, F follow, 1-9
chips). Conversations / Follow Stream / Target Intelligence open from here over
the full engine history. Updates are batched so the GUI never stalls under load.
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
        # Grow past the cap by evicting the oldest rows and inserting the new
        # ones (row remove/insert), never a full model reset - a long capture
        # would otherwise reset on every drain, losing selection and churning the
        # inspector. The rows are references to the engine's PacketRecords.
        maxlen = self._rows.maxlen
        incoming = len(records)
        cur = len(self._rows)
        if maxlen:
            total_after = min(cur + incoming, maxlen)
            evict = min(cur + incoming - total_after, cur)
        else:
            evict = 0
        if evict:
            self.beginRemoveRows(QModelIndex(), 0, evict - 1)
            for _ in range(evict):
                self._rows.popleft()
            self.endRemoveRows()
        # If one batch is larger than the whole table, only its tail survives -
        # insert exactly the rows that will remain so the row count stays honest.
        to_insert = records[-maxlen:] if (maxlen and incoming > maxlen) else records
        start = len(self._rows)
        self.beginInsertRows(QModelIndex(), start, start + len(to_insert) - 1)
        self._rows.extend(records)   # deque auto-trims to maxlen
        self.endInsertRows()

    def record_at(self, row: int) -> Optional[PacketRecord]:
        return self._rows[row] if 0 <= row < len(self._rows) else None

    def clear(self) -> None:
        self.beginResetModel(); self._rows.clear(); self._t0 = None; self.endResetModel()


class TrafficProxy(QSortFilterProxyModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.protos: set = set()   # empty = all protocols; else a union filter
        self.text = ""
        self.src_ip = ""
        self.dst_ip = ""
        self.pair = None   # frozenset{A, B} - "follow conversation" both ways

    def set_proto(self, proto: str):
        """Replace the protocol filter with a single protocol ('All'/'' = clear).
        Used programmatically; the chip UI uses toggle_proto for multi-select."""
        self.protos = set() if proto in ("All", "", None) else {proto}
        self.invalidate()

    def toggle_proto(self, proto: str):
        """Multi-select: add/remove one protocol from the union filter. 'All'
        clears the set so every protocol shows."""
        if proto in ("All", "", None):
            self.protos = set()
        elif proto in self.protos:
            self.protos.discard(proto)
        else:
            self.protos.add(proto)
        self.invalidate()

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

    def lessThan(self, left: QModelIndex, right: QModelIndex) -> bool:
        """Sort by the record's typed field for the clicked column, so numeric
        columns (# / Time / Length) sort numerically, not lexicographically."""
        model: TrafficModel = self.sourceModel()
        a = model.record_at(left.row())
        b = model.record_at(right.row())
        if a is None or b is None:
            return False
        col = left.column()
        if col == 0:
            return a.number < b.number
        if col == 1:
            return (a.timestamp or 0.0) < (b.timestamp or 0.0)
        if col == 2:
            return a.protocol < b.protocol
        if col == 3:
            return (a.src_ip, a.src_port or 0) < (b.src_ip, b.src_port or 0)
        if col == 4:
            return (a.dst_ip, a.dst_port or 0) < (b.dst_ip, b.dst_port or 0)
        if col == 5:
            return a.length < b.length
        if col == 6:
            return a.info < b.info
        return a.number < b.number

    def filterAcceptsRow(self, row: int, parent: QModelIndex) -> bool:
        model: TrafficModel = self.sourceModel()
        rec = model.record_at(row)
        if rec is None:
            return False
        if self.protos and rec.protocol not in self.protos:
            return False
        if self.pair is not None and frozenset(
                (rec.src_ip or rec.src_mac, rec.dst_ip or rec.dst_mac)) != self.pair:
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
    conversations_requested = Signal()  # open the flow-triage Conversations view
    follow_stream_requested = Signal(str, str)   # reassemble a flow (a, b)
    target_intel_requested = Signal(str)         # per-host intelligence rollup
    sample_requested = Signal()         # load the bundled sample capture

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
        self.conv_btn = QPushButton("Conversations"); self.conv_btn.setObjectName("Ghost")
        self.conv_btn.setToolTip("Triage the capture as endpoint-pair flows "
                                 "(packets, bytes, protocols) - open one to follow it")
        self.clear_btn = QPushButton("Clear packets")
        self.clear_btn.setObjectName("Ghost")
        self.clear_btn.setToolTip("Discard the captured packets from this session "
                                  "(distinct from clearing display filters)")
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
        controls.addWidget(self.conv_btn)
        controls.addWidget(self.clear_btn)
        controls.addWidget(self.export_btn)
        root.addLayout(controls)

        # row 2: protocol filter chips
        # Protocol chips are MULTI-select (view TCP + TLS + DNS together): the
        # group is non-exclusive and each chip toggles its protocol in the union.
        # "All" is the reset - it clears the union and any followed conversation.
        bar = QHBoxLayout(); bar.setSpacing(6)
        self._chip_group = QButtonGroup(self); self._chip_group.setExclusive(False)
        for i, name in enumerate(CHIPS):
            chip = QPushButton(name); chip.setCheckable(True); chip.setObjectName("Chip")
            self._style_chip(chip, name)
            chip.clicked.connect(lambda _=False, n=name: self._on_chip_clicked(n))
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
        # A dim match count ("shown / total") and an always-available clear so the
        # operator can always see how hard a filter bit and step back out of it.
        self.match_lbl = QLabel(""); self.match_lbl.setObjectName("Dim")
        self.clear_inline_btn = QPushButton("Clear (Esc)")
        self.clear_inline_btn.setObjectName("Ghost")
        self.clear_inline_btn.setToolTip("Clear all display filters")
        self.clear_inline_btn.hide()
        filters.addWidget(self.src_filter); filters.addWidget(self.dst_filter)
        filters.addWidget(self.search, 1)
        filters.addWidget(self.match_lbl)
        filters.addWidget(self.clear_inline_btn)
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
        # Range/extended selection so an operator can hand-pick a subset (e.g. to
        # export just those packets), not only whole filters.
        self.table.setSelectionMode(QTableView.ExtendedSelection)
        self.table.setSortingEnabled(True)   # click a header to sort (see lessThan)
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
            "Press Start to capture, load the sample to explore offline, or open "
            "a saved .pcap.",
            icon="≣",
            action_text="Load sample capture",
            on_action=self.sample_requested.emit,
            action2_text="Open .pcap…",
            on_action2=self.open_requested.emit)
        self.table_stack.addWidget(self._empty)
        self.table_stack.addWidget(self.table)
        self.table_stack.setCurrentWidget(self._empty)
        split.addWidget(self.table_stack)

        self.inspector = PacketInspector(compact=True)
        split.addWidget(self.inspector)
        split.setStretchFactor(0, 3); split.setStretchFactor(1, 2)
        split.setSizes([780, 460])
        root.addWidget(split, 1)

        # Debounce the free-text search: filtering re-scans the whole history, so
        # coalesce keystrokes into one pass (~150ms) instead of one per key.
        from PySide6.QtCore import QTimer
        self._search_timer = QTimer(self)
        self._search_timer.setSingleShot(True)
        self._search_timer.setInterval(150)
        self._search_timer.timeout.connect(
            lambda: self.proxy.set_text(self.search.text()))
        self.search.textChanged.connect(lambda _t: self._search_timer.start())
        self.src_filter.textChanged.connect(self.proxy.set_src_ip)
        self.dst_filter.textChanged.connect(self.proxy.set_dst_ip)
        self.start_btn.clicked.connect(self.start_requested.emit)
        self.pause_btn.clicked.connect(self.pause_requested.emit)
        self.stop_btn.clicked.connect(self.stop_requested.emit)
        self.clear_btn.clicked.connect(self.clear_requested.emit)
        self.export_btn.clicked.connect(self.export_requested.emit)
        self.conv_btn.clicked.connect(self.conversations_requested.emit)
        self.table.selectionModel().selectionChanged.connect(self._on_select)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._table_context_menu)
        self.clear_filters_btn.clicked.connect(self._clear_filters)
        self.clear_inline_btn.clicked.connect(self._clear_filters)
        for sig in (self.proxy.layoutChanged, self.proxy.modelReset,
                    self.proxy.rowsInserted, self.proxy.rowsRemoved):
            sig.connect(self._update_filter_empty)
            sig.connect(self._update_match_count)
        self._has_packets = False
        self._state = "idle"
        self._install_shortcuts()
        self.set_capture_state("idle")

    # ---- expert-operator layer --------------------------------------
    def _install_shortcuts(self) -> None:
        """A small, high-value keyboard set for the investigation loop.

        Single-key (printable) shortcuts are scoped to the packet TABLE
        (Qt.WidgetShortcut), so they only fire when the table has focus and can
        NEVER hijack typing in the search / IP fields (you can still type '/' in a
        path or a CIDR). Ctrl-modified shortcuts are window-wide since they can't
        collide with plain typing."""
        from PySide6.QtCore import Qt
        from PySide6.QtGui import QKeySequence, QShortcut

        def table_sc(seq, handler):
            s = QShortcut(QKeySequence(seq), self.table)
            s.setContext(Qt.WidgetShortcut)   # only when the table has focus
            s.activated.connect(handler)
            return s

        def win_sc(seq, handler):
            s = QShortcut(QKeySequence(seq), self)
            s.activated.connect(handler)
            return s

        win_sc("Ctrl+F", self._focus_search)   # jump to search from anywhere
        table_sc("/", self._focus_search)
        table_sc("Esc", self._clear_filters)
        table_sc("F", self.follow_selected)
        for i in range(1, len(CHIPS)):          # 1..8 -> protocol chips
            table_sc(str(i), lambda idx=i: self._toggle_chip_by_index(idx))
        table_sc("0", lambda: self._toggle_chip_by_index(0))   # 0 -> All (reset)

    def _typing_in_field(self) -> bool:
        w = QApplication.focusWidget()
        return isinstance(w, QLineEdit)

    def _focus_search(self) -> None:
        self.search.setFocus()
        self.search.selectAll()

    def _toggle_chip_by_index(self, idx: int) -> None:
        if self._typing_in_field():
            return
        btn = self._chip_group.button(idx)
        if btn is not None:
            btn.animateClick()

    def follow_selected(self) -> None:
        """Follow the conversation of the selected row (A ↔ B). Bound to 'F'."""
        if self._typing_in_field():
            return
        idx = self.table.selectionModel().currentIndex()
        if not idx.isValid():
            return
        rec = self.model.record_at(self.proxy.mapToSource(idx).row())
        if rec and rec.src_ip and rec.dst_ip and rec.src_ip != rec.dst_ip:
            self.proxy.set_pair((rec.src_ip, rec.dst_ip))

    def _on_chip_clicked(self, name: str) -> None:
        """Chip toggled: 'All' resets everything; a specific chip toggles its
        protocol in the union and unchecks 'All'."""
        all_btn = self._chip_group.button(0)
        if name == "All":
            self.proxy.toggle_proto("All")     # clear the union
            self.proxy.set_pair(None)
            for b in self._chip_group.buttons():
                b.setChecked(b is all_btn)
        else:
            self.proxy.toggle_proto(name)
            if all_btn is not None:
                all_btn.setChecked(not self.proxy.protos)

    def _update_match_count(self, *args) -> None:
        shown = self.proxy.rowCount()
        total = self.model.rowCount()
        active = self.is_filter_active()
        self.match_lbl.setText(f"{shown} / {total}" if active else "")
        self.clear_inline_btn.setVisible(active)

    def set_has_packets(self, has: bool) -> None:
        """Gate the contextual Clear / Export actions: they only make sense once
        packets exist. Kept separate from the lifecycle state so either can
        change independently."""
        self._has_packets = has
        self._update_data_actions()

    def _update_data_actions(self) -> None:
        offline = self._state == "offline"
        has = offline or self._has_packets
        self.clear_btn.setEnabled(has)
        self.export_btn.setEnabled(has)
        self.conv_btn.setEnabled(has)

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
        self.clear_btn.setText("Close file" if offline else "Clear packets")
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
        """Reset every display filter (proto chips, IP boxes, search, followed
        conversation) so the full capture is visible again."""
        self.src_filter.clear()
        self.dst_filter.clear()
        self.search.clear()
        self.proxy.set_pair(None)
        self.proxy.set_proto("All")            # clears the protocol union
        all_btn = self._chip_group.button(0)
        for b in self._chip_group.buttons():
            b.setChecked(b is all_btn)
        self._update_filter_empty()
        self._update_match_count()

    def is_filter_active(self) -> bool:
        """True when any display filter (proto chip, src/dst IP, search) narrows
        the table below the full capture."""
        return (bool(self.proxy.protos) or bool(self.proxy.src_ip)
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

    def set_sample_loaded(self, count: int) -> None:
        """Reflect that the bundled SAMPLE capture is loaded - clearly synthetic,
        never presented as live traffic."""
        self.subtitle.setText(
            f"SAMPLE CAPTURE - {count} synthetic packet(s) for learning "
            f"(not live traffic).")

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
        # Only auto-follow the tail in the natural capture order: unsorted, or
        # sorted ascending by '#'. Any other column - or '#' descending
        # (newest-first at the top) - means the tail is not at the bottom, so
        # don't yank the viewport.
        header = self.table.horizontalHeader()
        section = header.sortIndicatorSection()
        ascending = header.sortIndicatorOrder() == Qt.AscendingOrder
        natural_order = section == -1 or (section == 0 and ascending)
        if at_bottom and natural_order:
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
            a = menu.addAction(
                f"Follow stream  ({rec.src_ip} ↔ {rec.dst_ip})…")
            a.triggered.connect(
                lambda _=False, s=rec.src_ip, d=rec.dst_ip:
                self.follow_stream_requested.emit(s, d))
        if rec.src_ip or rec.dst_ip:
            menu.addSeparator()
            for ip in (rec.src_ip, rec.dst_ip):
                if ip:
                    a = menu.addAction(f"Target intelligence  ({ip})…")
                    a.triggered.connect(
                        lambda _=False, host=ip: self.target_intel_requested.emit(host))
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
