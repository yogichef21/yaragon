"""Expert-operator layer: column sorting, multi-select protocol chips, an
always-available filter clear, and a match-count readout. These make the
filter -> isolate -> inspect loop fast without adding chrome.
"""
import os

os.environ["QT_QPA_PLATFORM"] = "offscreen"

import pytest

pytest.importorskip("PySide6")

from conftest import build
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

_app = QApplication.instance() or QApplication([])


def _tcp(parser, n, length_pad=0, num0=1):
    out = []
    for i in range(n):
        pkt = Ether() / IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=40000,
                                                                 dport=80, flags="PA")
        r = parser.parse(build(pkt), num0 + i)
        r.number = num0 + i
        r.length = 100 + length_pad + i     # ascending lengths
        out.append(r)
    return out


def _dns(parser):
    pkt = (Ether() / IP(src="10.0.0.2", dst="8.8.8.8") / UDP(sport=5000, dport=53)
           / DNS(rd=1, qd=DNSQR(qname="a.com")))
    return parser.parse(build(pkt))


def test_sorting_enabled_and_orders_by_length_desc(parser):
    from yaragon.gui.traffic_view import TrafficView
    view = TrafficView(limit=100)
    try:
        assert view.table.isSortingEnabled()
        view.append_batch(_tcp(parser, 5))       # lengths 100..104
        view.proxy.sort(5, Qt.DescendingOrder)    # Length column
        first = view.model.record_at(view.proxy.mapToSource(view.proxy.index(0, 0)).row())
        last = view.model.record_at(view.proxy.mapToSource(view.proxy.index(4, 0)).row())
        assert first.length == 104 and last.length == 100
        # sorting does not lose or corrupt records
        assert len(view.visible_records()) == 5
    finally:
        view.deleteLater()


def test_multi_select_protocol_union(parser):
    from yaragon.gui.traffic_view import TrafficView
    view = TrafficView(limit=100)
    try:
        recs = _tcp(parser, 3) + [_dns(parser)]
        view.append_batch(recs)
        view.proxy.toggle_proto("TCP")
        assert view.proxy.rowCount() == 3
        view.proxy.toggle_proto("DNS")            # union, not replace
        assert view.proxy.rowCount() == 4
        view.proxy.toggle_proto("TCP")            # untoggle TCP -> only DNS
        assert view.proxy.rowCount() == 1
    finally:
        view.deleteLater()


def test_clear_filters_resets_multi_select(parser):
    from yaragon.gui.traffic_view import TrafficView
    view = TrafficView(limit=100)
    try:
        view.append_batch(_tcp(parser, 3) + [_dns(parser)])
        view.proxy.toggle_proto("TCP")
        view.proxy.toggle_proto("DNS")
        view._clear_filters()
        assert view.proxy.rowCount() == 4
        assert not view.is_filter_active()
    finally:
        view.deleteLater()


def test_match_count_label_reflects_filter(parser):
    from yaragon.gui.traffic_view import TrafficView
    view = TrafficView(limit=100)
    try:
        view.append_batch(_tcp(parser, 3) + [_dns(parser)])
        view.proxy.set_proto("DNS")
        view._update_match_count()
        assert view.match_lbl.text() == "1 / 4"
    finally:
        view.deleteLater()


def test_follow_selected_row_sets_pair(parser):
    from yaragon.gui.traffic_view import TrafficView
    view = TrafficView(limit=100)
    try:
        view.append_batch(_tcp(parser, 3))
        view.table.selectRow(0)
        view.follow_selected()
        assert view.proxy.pair == frozenset(("10.0.0.2", "10.0.0.1"))
    finally:
        view.deleteLater()
