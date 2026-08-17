"""Packet Inspector.

Two views of the selected packet:
  * Decoded  - protocols grouped by OSI layer (collapsible), each field shown.
  * Hex      - offset / hex / ASCII-gutter dump of the full frame.

The Hex view already carries an ASCII gutter, so separate ASCII/Raw tabs would
only restate the same bytes in weaker forms; a right-click "Copy bytes as hex"
covers the one thing the old Raw tab was good for.

OSI grouping is honest: protocols that don't map cleanly to one layer carry a
short note. Nothing is invented - only what the parser observed is shown.

Usable full-page or, with ``compact=True``, docked beside the traffic table.
"""
from __future__ import annotations

import html
from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (QApplication, QLabel, QMenu, QPlainTextEdit,
                               QStackedWidget, QTabWidget, QTreeWidget,
                               QTreeWidgetItem, QVBoxLayout, QWidget)

from ..analysis.model import PacketRecord, hexdump
from ..analysis.osi import layer_for, layer_title
from .styles import FONT_MONO, PALETTE, PROTOCOL_COLORS
from .widgets import EmptyState


class PacketInspector(QWidget):
    def __init__(self, compact: bool = False, parent=None):
        super().__init__(parent)
        lay = QVBoxLayout(self)
        m = 12 if compact else 20
        lay.setContentsMargins(m, m, m, m)
        lay.setSpacing(10)

        header = QLabel("Packet Inspector")
        header.setObjectName("H2" if compact else "H1")
        lay.addWidget(header)

        self._stack = QStackedWidget()
        lay.addWidget(self._stack, 1)

        self._empty = EmptyState(
            "No packet selected",
            "Select a row in the traffic table to dissect it by OSI layer, "
            "or view its bytes.",
            icon="⧉")
        self._stack.addWidget(self._empty)

        detail = QWidget()
        dl = QVBoxLayout(detail); dl.setContentsMargins(0, 0, 0, 0); dl.setSpacing(8)
        self.summary = QLabel("")
        self.summary.setObjectName("Dim")
        self.summary.setWordWrap(True)
        dl.addWidget(self.summary)

        self.tabs = QTabWidget()
        # Decoded (OSI tree)
        self.tree = QTreeWidget()
        self.tree.setColumnCount(2)
        self.tree.setHeaderLabels(["Field", "Value"])
        self.tree.setColumnWidth(0, 260 if compact else 340)
        self.tree.setAlternatingRowColors(True)
        self.tree.header().setStretchLastSection(True)
        self.tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self._tree_context_menu)
        self.tabs.addTab(self.tree, "Decoded")

        self.hex_view = self._mono_text()
        self.hex_view.setContextMenuPolicy(Qt.CustomContextMenu)
        self.hex_view.customContextMenuRequested.connect(self._hex_context_menu)
        self.tabs.addTab(self.hex_view, "Hex")

        dl.addWidget(self.tabs, 1)
        self._stack.addWidget(detail)
        self._stack.setCurrentWidget(self._empty)
        self._rec: Optional[PacketRecord] = None

    def _hex_context_menu(self, pos) -> None:
        menu = self.build_hex_menu()
        if menu is not None:
            menu.exec(self.hex_view.viewport().mapToGlobal(pos))

    def build_hex_menu(self):
        """Context menu for the Hex view: 'Copy bytes as hex' - the contiguous
        frame-hex the retired Raw tab used to show. Exposed for headless tests."""
        if self._rec is None or not self._rec.raw:
            return None
        menu = QMenu(self)
        act = menu.addAction("Copy bytes as hex")
        act.triggered.connect(
            lambda _=False, h=self._rec.raw.hex(): QApplication.clipboard().setText(h))
        return menu

    def _tree_context_menu(self, pos) -> None:
        item = self.tree.itemAt(pos)
        menu = self.build_item_menu(item)
        if menu is not None:
            menu.exec(self.tree.viewport().mapToGlobal(pos))

    def build_item_menu(self, item: Optional[QTreeWidgetItem]):
        """Build the decoded-tree context menu ("Copy value"). Exposed for
        headless testing."""
        if item is None:
            return None
        value = item.text(1) or item.text(0)
        menu = QMenu(self)
        act = menu.addAction("Copy value")
        act.triggered.connect(
            lambda _=False, v=value: QApplication.clipboard().setText(v))
        return menu

    def _mono_text(self) -> QPlainTextEdit:
        w = QPlainTextEdit()
        w.setReadOnly(True)
        w.setLineWrapMode(QPlainTextEdit.NoWrap)
        w.setStyleSheet(
            f"background: {PALETTE['bg']}; color: {PALETTE['text']};"
            f"font-family: {FONT_MONO}; font-size: 12px; border: none;")
        return w

    def show_packet(self, rec: Optional[PacketRecord]) -> None:
        if rec is None:
            self._rec = None
            self._stack.setCurrentWidget(self._empty)
            return
        # rec.protocol / rec.info are attacker-controlled (DNS names, HTTP
        # request lines, ARP strings). The summary is rich text, so escape them -
        # a forensic tool must render on-wire bytes as literal text, never markup.
        proto = html.escape(rec.protocol)
        info = html.escape(rec.info)
        proto_color = PROTOCOL_COLORS.get(rec.protocol, PALETTE["text"])
        self.summary.setText(
            f"<b>#{rec.number}</b> · t={rec.timestamp:.6f} · {rec.length} B · "
            f"<span style='color:{proto_color}'>{proto}</span> · {info}")

        self._rec = rec
        self._build_decoded(rec)
        self.hex_view.setPlainText(hexdump(rec.raw))

        self._stack.setCurrentIndex(1)

    # ---- decoded / OSI tree -----------------------------------------
    def _build_decoded(self, rec: PacketRecord) -> None:
        self.tree.clear()
        nodes = [("Frame", f"#{rec.number}, {rec.length} bytes", [
            ("Capture Length", str(rec.length), []),
            ("Epoch Time", f"{rec.timestamp:.6f}", []),
            ("Protocol", rec.protocol, []),
        ])]
        nodes.extend(rec.detail_tree)

        buckets, order = {}, []
        for label, value, children in nodes:
            layer, note = layer_for(label)
            if layer not in buckets:
                buckets[layer] = []
                order.append(layer)
            buckets[layer].append(((label, value, children), note))

        for layer in sorted(order, key=lambda x: (x is None, x if x is not None else 99)):
            # Layer titles are a label treatment (dim + bold), not an amber
            # action - amber on every OSI group header is amber overuse.
            group = QTreeWidgetItem([layer_title(layer).upper(), ""])
            gf = group.font(0); gf.setBold(True); group.setFont(0, gf)
            group.setForeground(0, QBrush(QColor(PALETTE["text_dim"])))
            for (label, value, children), note in buckets[layer]:
                proto = self._build(label, value, children)
                pf = proto.font(0); pf.setBold(True); proto.setFont(0, pf)
                if note:
                    n = QTreeWidgetItem([" note", note])
                    n.setForeground(0, QBrush(QColor(PALETTE["muted"])))
                    n.setForeground(1, QBrush(QColor(PALETTE["text_dim"])))
                    nf = n.font(1); nf.setItalic(True); n.setFont(1, nf)
                    proto.insertChild(0, n)
                group.addChild(proto)
            self.tree.addTopLevelItem(group)
            group.setExpanded(True)
            for i in range(group.childCount()):
                group.child(i).setExpanded(True)

    def _build(self, label, value, children) -> QTreeWidgetItem:
        item = QTreeWidgetItem([str(label), str(value)])
        for c_label, c_value, c_children in children:
            item.addChild(self._build(c_label, c_value, c_children))
        return item
