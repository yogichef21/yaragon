"""The investigation surfaces (Conversations, Follow Stream, Target Intelligence)
construct headlessly, are driven by the pure analysis layer, and are wired to the
packet table via signals. They are dialogs (no new always-on chrome).
"""
import os

os.environ["QT_QPA_PLATFORM"] = "offscreen"

import pytest

pytest.importorskip("PySide6")

from conftest import build
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from PySide6.QtWidgets import QApplication

_app = QApplication.instance() or QApplication([])

from yaragon.analysis.conversations import build_conversations
from yaragon.analysis.intel import build_target_intel
from yaragon.analysis.stream import reassemble
from yaragon.gui.conversations_view import ConversationsDialog
from yaragon.gui.intel_view import TargetIntelDialog
from yaragon.gui.stream_view import FollowStreamDialog


def _http(parser, src="10.0.0.2", dst="10.0.0.1"):
    pkt = (Ether() / IP(src=src, dst=dst) / TCP(sport=40000, dport=80, flags="PA")
           / Raw(load=b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
    return parser.parse(build(pkt))


def test_conversations_dialog_emits_follow(parser):
    convs = build_conversations([_http(parser), _http(parser)])
    dlg = ConversationsDialog(convs)
    try:
        seen = []
        dlg.follow_requested.connect(lambda a, b: seen.append((a, b)))
        dlg.table.selectRow(0)
        dlg._emit_follow()
        assert seen == [("10.0.0.1", "10.0.0.2")]
    finally:
        dlg.deleteLater()


def test_follow_stream_dialog_renders_payload(parser):
    segs = reassemble([_http(parser)], "10.0.0.2", "10.0.0.1")
    dlg = FollowStreamDialog("10.0.0.2", "10.0.0.1", segs)
    try:
        assert "GET / HTTP/1.1" in dlg.view.toPlainText()
    finally:
        dlg.deleteLater()


def test_target_intel_dialog_constructs(parser):
    intel = build_target_intel([_http(parser)], "10.0.0.2")
    dlg = TargetIntelDialog(intel)
    try:
        assert dlg.windowTitle().endswith("10.0.0.2")
    finally:
        dlg.deleteLater()


def test_conversations_dialog_sorts_numerically(parser):
    """The Conversations table re-ranks by a numeric column (bytes) numerically,
    and selection resolves the right flow after the re-sort."""
    from PySide6.QtCore import Qt
    recs = [_http(parser, src="10.0.0.2", dst="10.0.0.1")]          # 1 flow
    recs += [_http(parser, src="10.0.0.3", dst="10.0.0.1")] * 3     # heavier flow
    dlg = ConversationsDialog(build_conversations(recs))
    try:
        dlg.table.sortItems(3, Qt.DescendingOrder)   # Bytes column, desc
        top = dlg.table.item(0, 0).data(Qt.UserRole)
        assert top.bytes == max(c.bytes for c in build_conversations(recs))
        dlg.table.selectRow(0)
        assert dlg._selected().bytes == top.bytes    # selection is sort-safe
    finally:
        dlg.deleteLater()


def test_dropped_frames_are_surfaced(parser, tmp_path, monkeypatch):
    """An incomplete capture is shown, never hidden: a non-zero drop count lights
    the dropped readout."""
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "c"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "d"))
    from yaragon.gui.main_window import MainWindow
    from yaragon.utils.config import Config

    class _Cap:
        is_paused = False
        dropped = 7
        captured = 100
    mw = MainWindow(Config())
    try:
        mw.capture = _Cap()
        mw._on_tick()
        assert not mw.dropped_lbl.isHidden()
        assert "7" in mw.dropped_lbl.text()
        mw.capture = None
        mw._on_tick()
        assert mw.dropped_lbl.isHidden()    # clears when no drops
    finally:
        mw.close()


def test_traffic_view_emits_investigation_signals(parser):
    from yaragon.gui.traffic_view import TrafficView
    view = TrafficView(limit=100)
    try:
        view.append_batch([_http(parser)])       # enables the data actions
        conv = []
        view.conversations_requested.connect(lambda: conv.append(True))
        view.conv_btn.click()
        assert conv == [True]

        # the row context menu offers Follow stream + Target intelligence
        menu = view.build_row_menu(0)
        labels = [a.text() for a in menu.actions()]
        assert any("Follow stream" in t for t in labels)
        assert any("Target intelligence" in t for t in labels)
    finally:
        view.deleteLater()
