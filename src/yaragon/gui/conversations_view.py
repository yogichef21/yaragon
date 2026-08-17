"""Conversations dialog: flow-level triage of the capture. Turns a noisy packet
list into a ranked table of endpoint-pair flows (packets, bytes, protocols,
ports, duration). Double-click a flow to follow it in the packet table; a button
opens the reassembled stream. No live state, no dashboard - a focused picker.
"""
from __future__ import annotations

from typing import List

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (QAbstractItemView, QDialog, QHBoxLayout, QLabel,
                               QPushButton, QTableWidget, QTableWidgetItem,
                               QVBoxLayout)

from ..analysis.conversations import Conversation

_COLS = ["Endpoint A", "Endpoint B", "Packets", "Bytes", "A→B", "B→A",
         "Protocols", "Ports", "Duration (s)"]
_NUMERIC_COLS = {2, 3, 4, 5, 8}


class _Cell(QTableWidgetItem):
    """A table cell that sorts numerically when given a number, so the operator
    can re-rank flows by bytes / duration, not just packets."""

    def __init__(self, text: str, value=None):
        super().__init__(text)
        self._value = value

    def __lt__(self, other):
        # NB: do not call super().__lt__ - on a QTableWidgetItem override it
        # recurses back into this method. Compare values, else fall back to text.
        if isinstance(other, _Cell) and self._value is not None \
                and other._value is not None:
            return self._value < other._value
        return self.text() < other.text()


class ConversationsDialog(QDialog):
    # Emitted with (a, b) when the operator picks a flow to filter/follow.
    follow_requested = Signal(str, str)
    stream_requested = Signal(str, str)

    def __init__(self, conversations: List[Conversation], parent=None):
        super().__init__(parent)
        self.setWindowTitle("Conversations")
        self.resize(820, 520)
        self._convs = conversations
        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 16, 16, 16)
        lay.setSpacing(10)

        head = QLabel(f"{len(conversations)} conversation(s) · heaviest first")
        head.setObjectName("H2")
        lay.addWidget(head)

        self.table = QTableWidget(len(conversations), len(_COLS))
        self.table.setHorizontalHeaderLabels(_COLS)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)
        self._fill()
        self.table.setSortingEnabled(True)   # re-rank by bytes / duration / etc.
        self.table.doubleClicked.connect(self._on_double_click)
        lay.addWidget(self.table, 1)

        row = QHBoxLayout()
        hint = QLabel("Double-click to follow in the packet table.")
        hint.setObjectName("Dim")
        row.addWidget(hint); row.addStretch(1)
        self.stream_btn = QPushButton("Follow stream")
        self.stream_btn.setObjectName("Ghost")
        self.stream_btn.clicked.connect(self._emit_stream)
        follow = QPushButton("Follow in table"); follow.setObjectName("Primary")
        follow.clicked.connect(self._emit_follow)
        close = QPushButton("Close"); close.setObjectName("Ghost")
        close.clicked.connect(self.reject)
        row.addWidget(self.stream_btn); row.addWidget(follow); row.addWidget(close)
        lay.addLayout(row)

    def _fill(self) -> None:
        for r, c in enumerate(self._convs):
            cells = [(c.a, None), (c.b, None), (str(c.packets), c.packets),
                     (str(c.bytes), c.bytes), (str(c.a_to_b), c.a_to_b),
                     (str(c.b_to_a), c.b_to_a),
                     (" ".join(sorted(c.protocols)), None),
                     (" ".join(str(p) for p in sorted(c.ports)[:6]), None),
                     (f"{c.duration:.3f}", c.duration)]
            for col, (text, value) in enumerate(cells):
                item = _Cell(text, value)
                if col in _NUMERIC_COLS:
                    item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
                if col == 0:
                    # Carry the conversation on the row so selection survives a
                    # user re-sort (never index self._convs by view row).
                    item.setData(Qt.UserRole, c)
                self.table.setItem(r, col, item)
        self.table.resizeColumnsToContents()

    def _selected(self):
        row = self.table.currentRow()
        item = self.table.item(row, 0) if row >= 0 else None
        return item.data(Qt.UserRole) if item is not None else None

    def _on_double_click(self, _idx) -> None:
        self._emit_follow()

    def _emit_follow(self) -> None:
        c = self._selected()
        if c is not None:
            self.follow_requested.emit(c.a, c.b)
            self.accept()

    def _emit_stream(self) -> None:
        c = self._selected()
        if c is not None:
            self.stream_requested.emit(c.a, c.b)
