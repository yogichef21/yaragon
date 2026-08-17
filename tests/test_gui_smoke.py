"""Headless GUI smoke tests.

Runs under the Qt 'offscreen' platform so it works in CI with no display. We
exercise the widgets that back the hot path (batched traffic table + inspector)
rather than the full window; the full window is verified on a real display.
"""
import os

# Force headless rendering for tests regardless of any inherited setting
# (e.g. the Docker image pins QT_QPA_PLATFORM=xcb for the live GUI).
os.environ["QT_QPA_PLATFORM"] = "offscreen"

import pytest

pytest.importorskip("PySide6")

from conftest import build
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from PySide6.QtWidgets import QApplication

_app = QApplication.instance() or QApplication([])


def _records(parser, n=200):
    out = []
    for i in range(n):
        pkt = Ether() / IP(src="10.0.0.2", dst="10.0.0.1") / TCP(
            sport=40000 + i, dport=80, flags="S", seq=1000 + i)
        out.append(parser.parse(build(pkt), i + 1))
    return out


def test_traffic_table_batched_and_filtered(parser):
    from yaragon.gui.traffic_view import TrafficView
    view = TrafficView(limit=500)
    view.append_batch(_records(parser, 200))
    assert view.model.rowCount() == 200
    view.proxy.set_proto("UDP")
    assert view.proxy.rowCount() == 0        # no UDP among the TCP records
    view.proxy.set_proto("TCP")
    assert view.proxy.rowCount() == 200
    view.deleteLater()


def test_traffic_table_bounded(parser):
    from yaragon.gui.traffic_view import TrafficView
    view = TrafficView(limit=100)
    view.append_batch(_records(parser, 250))
    assert view.model.rowCount() <= 100      # bounded live table
    view.deleteLater()


def test_traffic_number_column(parser):
    """First column is the sequential packet number (rec.number)."""
    from PySide6.QtCore import Qt
    from yaragon.gui.traffic_view import COLUMNS, TrafficView
    assert COLUMNS[0] == "#"
    assert "Direction" not in COLUMNS
    view = TrafficView(limit=100)
    view.append_batch(_records(parser, 5))
    idx = view.model.index(0, 0)
    assert view.model.data(idx, Qt.DisplayRole) == "1"
    idx5 = view.model.index(4, 0)
    assert view.model.data(idx5, Qt.DisplayRole) == "5"
    view.deleteLater()


def test_traffic_ip_filtering(parser):
    """Source/Destination IP filters narrow the table without mutating data."""
    from yaragon.gui.traffic_view import TrafficView
    view = TrafficView(limit=500)
    recs = _records(parser, 20)          # all src 10.0.0.2 -> dst 10.0.0.1
    view.append_batch(recs)
    view.proxy.set_src_ip("10.0.0.2")
    assert view.proxy.rowCount() == 20
    view.proxy.set_src_ip("10.9.9.9")    # matches nothing
    assert view.proxy.rowCount() == 0
    view.proxy.set_src_ip("")            # cleared -> all rows back
    assert view.proxy.rowCount() == 20
    view.proxy.set_dst_ip("10.0.0.1")
    assert view.proxy.rowCount() == 20
    view.proxy.set_dst_ip("10.0.0.2")    # dst never matches src
    assert view.proxy.rowCount() == 0
    # underlying model data is untouched by filtering
    assert view.model.rowCount() == 20
    view.deleteLater()


def test_capture_controls_reflect_state():
    """The Start/Pause/Stop buttons enable only for valid transitions and Start
    doubles as Resume when paused - so rapid presses can't drive an invalid
    lifecycle."""
    from yaragon.gui.traffic_view import TrafficView
    view = TrafficView(limit=100)

    view.set_capture_state("idle")
    assert view.start_btn.isEnabled() and view.start_btn.text() == "Start"
    assert not view.pause_btn.isEnabled()
    assert not view.stop_btn.isEnabled()

    view.set_capture_state("capturing")
    assert not view.start_btn.isEnabled()
    assert view.pause_btn.isEnabled()
    assert view.stop_btn.isEnabled()

    view.set_capture_state("paused")
    assert view.start_btn.isEnabled() and view.start_btn.text() == "Resume"
    assert not view.pause_btn.isEnabled()
    assert view.stop_btn.isEnabled()
    view.deleteLater()


def test_investigate_contextual_state_machine(parser):
    """A6: the strip is a contextual state machine. start_over_btn is gone; BPF
    lives with Start (idle only); Clear/Export gate on packets; offline hides the
    live lifecycle and Clear becomes 'Close file'."""
    from yaragon.gui.traffic_view import TrafficView
    view = TrafficView(limit=100)
    assert not hasattr(view, "start_over_btn")
    assert not hasattr(view, "open_btn")

    # idle + no packets: BPF visible; Clear/Export disabled.
    view.set_capture_state("idle")
    assert view.bpf_box.isVisibleTo(view)
    assert not view.clear_btn.isEnabled()
    assert not view.export_btn.isEnabled()

    # packets arrive -> Clear/Export enabled.
    view.append_batch(_records(parser, 3))
    assert view.clear_btn.isEnabled() and view.export_btn.isEnabled()

    # capturing hides BPF; exactly Start is the primary (disabled while running).
    view.set_capture_state("capturing")
    assert not view.bpf_box.isVisibleTo(view)
    assert not view.start_btn.isEnabled()

    # offline: no live lifecycle, Clear becomes 'Close file', Export enabled.
    view.set_capture_state("offline")
    assert not view.start_btn.isVisibleTo(view)
    assert not view.pause_btn.isVisibleTo(view)
    assert not view.stop_btn.isVisibleTo(view)
    assert view.clear_btn.text() == "Close file"
    assert view.export_btn.isEnabled()
    view.deleteLater()


def test_investigate_title_is_investigate():
    from yaragon.gui.traffic_view import TrafficView
    view = TrafficView(limit=10)
    titles = [w.text() for w in view.findChildren(type(view.subtitle))
              if w.objectName() == "H1"]
    assert "Investigate" in titles
    view.deleteLater()


def test_clear_empties_the_table():
    from yaragon.gui.traffic_view import TrafficView
    from yaragon.analysis.packet_parser import PacketParser
    view = TrafficView(limit=100)
    view.append_batch(_records(PacketParser(), 10))
    assert view.model.rowCount() == 10
    view.clear()
    assert view.model.rowCount() == 0
    view.deleteLater()


def test_traffic_empty_state_toggles(parser):
    """Item 4: the packet pane shows an empty state until the first packet, the
    table after append_batch, and the empty state again after clear()."""
    from yaragon.gui.traffic_view import TrafficView
    view = TrafficView(limit=100)
    assert view.table_stack.currentWidget() is view._empty
    view.append_batch(_records(parser, 3))
    assert view.table_stack.currentWidget() is view.table
    view.clear()
    assert view.table_stack.currentWidget() is view._empty
    view.deleteLater()


def test_livedot_has_no_animation_timer():
    """Item 5: LiveDot is a static dot - no perpetual QTimer."""
    from yaragon.gui.widgets import LiveDot
    dot = LiveDot()
    assert not hasattr(dot, "_timer")
    assert not hasattr(dot, "_phase")
    dot.set_live(True); dot.set_live(False)     # must not raise
    dot.deleteLater()


def test_traffic_relative_time_column(parser):
    """Item 8: the Time column is seconds since the session's first packet."""
    from PySide6.QtCore import Qt
    from yaragon.gui.traffic_view import COLUMNS, TrafficView
    assert COLUMNS[1] == "Time (s)"
    view = TrafficView(limit=100)
    recs = _records(parser, 3)
    recs[0].timestamp = 1000.0
    recs[1].timestamp = 1000.5
    recs[2].timestamp = 1002.481
    view.append_batch(recs)
    col = 1
    assert view.model.data(view.model.index(0, col), Qt.DisplayRole) == "0.000"
    assert view.model.data(view.model.index(1, col), Qt.DisplayRole) == "0.500"
    assert view.model.data(view.model.index(2, col), Qt.DisplayRole) == "2.481"
    view.deleteLater()


def test_capture_filter_accessor():
    """Item 7: the BPF field value is exposed (trimmed) for capture start."""
    from yaragon.gui.traffic_view import TrafficView
    view = TrafficView(limit=100)
    assert view.capture_filter() == ""
    view.bpf_filter.setText("  tcp port 80  ")
    assert view.capture_filter() == "tcp port 80"
    view.deleteLater()


def test_visible_records_and_filter_active(parser):
    """Item 9: visible_records() returns exactly the filtered subset in order."""
    from yaragon.gui.traffic_view import TrafficView
    view = TrafficView(limit=500)
    view.append_batch(_records(parser, 10))     # all TCP, src 10.0.0.2
    assert view.is_filter_active() is False
    view.proxy.set_proto("TCP")
    assert view.is_filter_active() is True
    assert len(view.visible_records()) == 10
    view.proxy.set_src_ip("10.9.9.9")           # matches nothing
    assert view.visible_records() == []
    view.deleteLater()


def test_table_context_menu_sets_filter(parser):
    """Item 10: the row menu populates the proxy filters via the filter fields."""
    from yaragon.gui.traffic_view import TrafficView
    view = TrafficView(limit=100)
    view.append_batch(_records(parser, 3))       # src 10.0.0.2 -> dst 10.0.0.1:80
    menu = view.build_row_menu(0, "10.0.0.2")
    for a in menu.actions():
        if a.text().startswith("Filter by source IP"):
            a.trigger()
    assert view.proxy.src_ip == "10.0.0.2"
    view.deleteLater()


def test_follow_conversation_both_directions(parser):
    """A8: 'Follow conversation (A<->B)' keeps only packets between {A,B} in
    either direction - one predicate on the existing proxy."""
    from yaragon.gui.traffic_view import TrafficView
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether
    view = TrafficView(limit=100)
    recs = []
    # 3 A->B, 2 B->A, plus 4 unrelated C->D
    for i in range(3):
        recs.append(parser.parse(build(Ether() / IP(src="10.0.0.2", dst="10.0.0.1")
                                        / TCP(sport=1000 + i, dport=80)), i + 1))
    for i in range(2):
        recs.append(parser.parse(build(Ether() / IP(src="10.0.0.1", dst="10.0.0.2")
                                        / TCP(sport=80, dport=1000 + i)), 10 + i))
    for i in range(4):
        recs.append(parser.parse(build(Ether() / IP(src="10.0.0.9", dst="10.0.0.8")
                                        / TCP(sport=2000 + i, dport=53)), 20 + i))
    view.append_batch(recs)
    assert view.model.rowCount() == 9
    view.proxy.set_pair(("10.0.0.1", "10.0.0.2"))
    assert view.proxy.rowCount() == 5            # both directions of A<->B
    assert view.is_filter_active() is True
    view.proxy.set_pair(("10.0.0.2", "10.0.0.1"))   # unordered - same result
    assert view.proxy.rowCount() == 5
    view.proxy.set_pair(None)
    assert view.proxy.rowCount() == 9
    view.deleteLater()


def test_follow_conversation_menu_entry(parser):
    """A8: the row menu offers Follow conversation and wires the proxy pair."""
    from yaragon.gui.traffic_view import TrafficView
    view = TrafficView(limit=100)
    view.append_batch(_records(parser, 3))       # 10.0.0.2 -> 10.0.0.1
    menu = view.build_row_menu(0, "10.0.0.2")
    followed = [a for a in menu.actions() if a.text().startswith("Follow conversation")]
    assert len(followed) == 1
    followed[0].trigger()
    assert view.proxy.pair == frozenset(("10.0.0.2", "10.0.0.1"))
    view.deleteLater()


def test_tree_copy_value_to_clipboard(parser):
    """Item 10: the decoded-tree 'Copy value' puts the field value on clipboard."""
    from PySide6.QtWidgets import QApplication
    from yaragon.gui.packet_inspector import PacketInspector
    insp = PacketInspector(compact=True)
    rec = _records(parser, 1)[0]
    insp.show_packet(rec)
    item = insp.tree.topLevelItem(0).child(0)
    menu = insp.build_item_menu(item)
    menu.actions()[0].trigger()
    assert QApplication.clipboard().text() == (item.text(1) or item.text(0))
    insp.deleteLater()


def test_mitm_degraded_maps_to_danger_readout():
    """A13: the GUI maps a degraded session to the danger (DEGRADED) pill."""
    from yaragon.gui.mitm_view import MitmView
    view = MitmView()
    view.set_targets([("10.0.0.5", "aa:bb:cc:dd:ee:ff")])
    view.set_active(True, "12:00:00")
    view.set_degraded()
    assert view.pill.text() == "DEGRADED"
    view.deleteLater()


def test_discovery_one_primary_and_no_clear_button():
    """A7: never two #Primary at once; clear-selection button gone; the full
    interface table is hidden until the Details disclosure is toggled."""
    from PySide6.QtCore import Qt
    from yaragon.gui.discovery_view import DiscoveryView
    from yaragon.network.discovery import Host
    view = DiscoveryView()
    assert not hasattr(view, "clear_sel_btn")

    # interface table hidden by default, revealed by Details.
    assert not view.iface_table.isVisibleTo(view)
    view.details_btn.setChecked(True)
    assert view.iface_table.isVisibleTo(view)
    view.details_btn.setChecked(False)

    # populate two hosts and check the phase-based single primary.
    view._on_hosts([Host(ip="10.0.0.1", mac="aa"), Host(ip="10.0.0.2", mac="bb")])
    primaries = lambda: [b for b in (view.scan_btn, view.continue_btn)
                         if b.objectName() == "Primary"]
    # nothing selected -> scan is the only primary
    assert primaries() == [view.scan_btn]
    # select one host -> Continue becomes the only primary
    view.host_table.item(0, 0).setCheckState(Qt.Checked)
    assert primaries() == [view.continue_btn]
    view.deleteLater()


def test_discovery_capture_only_signal():
    """Item 11: the Capture-only action emits its signal."""
    from yaragon.gui.discovery_view import DiscoveryView
    view = DiscoveryView()
    fired = []
    view.capture_only_requested.connect(lambda: fired.append(True))
    view.capture_only_btn.setEnabled(True)
    view.capture_only_btn.click()
    assert fired == [True]
    view.deleteLater()


def test_append_batch_over_limit_preserves_order_and_relative_time(parser):
    """When a batch pushes the model past its row limit the reset path is taken;
    it must keep the retained tail in order and still anchor relative time to the
    session's first packet (t0), not to the tail's first row."""
    from PySide6.QtCore import Qt
    from yaragon.gui.traffic_view import TrafficView
    view = TrafficView(limit=10)
    recs = _records(parser, 25)
    for i, r in enumerate(recs):
        r.timestamp = 1000.0 + i          # 1000, 1001, ... deterministic
    view.append_batch(recs[:5])           # normal insert path
    view.append_batch(recs[5:])           # crosses the limit -> reset path
    assert view.model.rowCount() == 10    # bounded tail
    # tail is the last 10 records, still in ascending packet-number order
    first_num = int(view.model.data(view.model.index(0, 0), Qt.DisplayRole))
    last_num = int(view.model.data(view.model.index(9, 0), Qt.DisplayRole))
    assert (first_num, last_num) == (16, 25)
    # t0 stays the very first packet (ts=1000.0); row for ts=1015 -> "15.000"
    assert view.model.data(view.model.index(0, 1), Qt.DisplayRole) == "15.000"
    view.deleteLater()


def test_search_bare_number_matches_exact_port(parser):
    """A bare number in search accepts rows whose src/dst port matches exactly."""
    from yaragon.gui.traffic_view import TrafficView
    view = TrafficView(limit=100)
    view.append_batch(_records(parser, 5))     # all dst port 80
    view.proxy.set_text("80")
    assert view.proxy.rowCount() == 5
    view.proxy.set_text("9999")                # no such port / substring
    assert view.proxy.rowCount() == 0
    view.deleteLater()


def test_search_clearing_restores_all_rows(parser):
    from yaragon.gui.traffic_view import TrafficView
    view = TrafficView(limit=100)
    view.append_batch(_records(parser, 8))
    view.proxy.set_text("nonsense-token")
    assert view.proxy.rowCount() == 0
    view.proxy.set_text("")
    assert view.proxy.rowCount() == 8
    view.deleteLater()


def test_filter_empty_line_toggles(parser):
    """A9: filtering to a no-match set shows the inline line; Clear filters
    resets and hides it."""
    from yaragon.gui.traffic_view import TrafficView
    view = TrafficView(limit=100)
    view.append_batch(_records(parser, 5))          # all TCP
    assert not view.filter_empty.isVisibleTo(view)
    view.proxy.set_proto("UDP")                     # matches nothing
    view._update_filter_empty()
    assert view.filter_empty.isVisibleTo(view)
    view.clear_filters_btn.click()
    assert not view.filter_empty.isVisibleTo(view)
    assert view.proxy.protos == set()      # multi-select union cleared
    view.deleteLater()


def test_empty_state_ctas_fire(parser):
    """A9: the packet-table empty state offers first-run CTAs - Load sample
    (primary) and Open .pcap (secondary) - both clickable."""
    from yaragon.gui.traffic_view import TrafficView
    view = TrafficView(limit=100)
    sample = []; opened = []
    view.sample_requested.connect(lambda: sample.append(True))
    view.open_requested.connect(lambda: opened.append(True))
    view._empty.action_btn.click()
    view._empty.action2_btn.click()
    assert sample == [True]
    assert opened == [True]
    view.deleteLater()


def test_empty_state_error_variant():
    """A9: EmptyState(error=True) renders the danger variant with a retry."""
    from yaragon.gui.widgets import EmptyState
    fired = []
    es = EmptyState("Scan failed", "Check the interface", icon="!",
                    error=True, action_text="Retry", on_action=lambda: fired.append(1))
    es.action_btn.click()
    assert fired == [1]
    es.deleteLater()


def test_window_icon_constructible():
    """A9: the brand mark resolves and builds a non-null QIcon (app icon)."""
    from PySide6.QtGui import QIcon
    from yaragon.gui.widgets import brand_mark_path
    path = brand_mark_path()
    assert path is not None
    assert not QIcon(path).isNull()


def test_empty_batch_is_a_noop_and_keeps_empty_state(parser):
    from yaragon.gui.traffic_view import TrafficView
    view = TrafficView(limit=100)
    view.append_batch([])                       # must not switch away from empty state
    assert view.model.rowCount() == 0
    assert view.table_stack.currentWidget() is view._empty
    view.deleteLater()


def test_inspector_shows_and_clears(parser):
    from yaragon.gui.packet_inspector import PacketInspector
    insp = PacketInspector(compact=True)
    insp.show_packet(None)                # empty state, no crash
    rec = _records(parser, 1)[0]
    insp.show_packet(rec)
    assert insp.tree.topLevelItemCount() > 0
    insp.deleteLater()


def test_inspector_has_decoded_and_hex_only(parser):
    """A8: the inspector is trimmed to Decoded + Hex; ASCII/Raw are gone and
    'Copy bytes as hex' covers Raw's only real use."""
    from yaragon.gui.packet_inspector import PacketInspector
    insp = PacketInspector(compact=True)
    labels = [insp.tabs.tabText(i) for i in range(insp.tabs.count())]
    assert labels == ["Decoded", "Hex"]
    assert not hasattr(insp, "raw_view")
    assert not hasattr(insp, "ascii_view_w")
    rec = _records(parser, 1)[0]
    insp.show_packet(rec)
    assert "00000000" in insp.hex_view.toPlainText()      # hex dump populated
    # "Copy bytes as hex" puts the contiguous frame hex on the clipboard.
    menu = insp.build_hex_menu()
    menu.actions()[0].trigger()
    assert QApplication.clipboard().text() == rec.raw.hex()
    insp.deleteLater()


def test_inspector_summary_escapes_markup(parser):
    """A5: attacker-controlled protocol/info must render as literal text, not
    markup - the same class of bug already fixed in the MITM activity log."""
    from yaragon.gui.packet_inspector import PacketInspector
    insp = PacketInspector(compact=True)
    rec = _records(parser, 1)[0]
    rec.info = '<img src=x onerror=alert(1)>'
    rec.protocol = '<b>EVIL</b>'
    insp.show_packet(rec)
    text = insp.summary.text()
    assert "<img" not in text and "<b>EVIL</b>" not in text
    assert "&lt;img" in text and "&lt;b&gt;EVIL" in text
    insp.deleteLater()


def test_stage_rail_renders_states_and_emits():
    """A3: StageRail renders the four visual states from a supplied dict and
    emits stage_clicked (including for locked chips - the window gates)."""
    from yaragon.gui.widgets import StageRail
    from yaragon.gui.workflow import Stage, StageState
    rail = StageRail()
    rail.set_states({
        Stage.DISCOVER: StageState.DONE,
        Stage.MITM: StageState.LOCKED,
        Stage.INVESTIGATE: StageState.CURRENT,
    })
    assert rail.chip(Stage.DISCOVER).state() == "done"
    assert rail.chip(Stage.MITM).state() == "locked"
    assert rail.chip(Stage.INVESTIGATE).state() == "current"
    # exactly one current
    currents = [s for s in Stage if rail.state_of(s) == StageState.CURRENT]
    assert currents == [Stage.INVESTIGATE]
    fired = []
    rail.stage_clicked.connect(lambda s: fired.append(s))
    rail.chip(Stage.MITM).click()
    assert fired == [Stage.MITM]
    rail.deleteLater()


def test_no_sidebar_nav_labels_remain():
    """A3: the free sidebar / NAV_LABELS are gone; the rail replaces them."""
    import yaragon.gui.main_window as mw
    assert not hasattr(mw, "NAV_LABELS")
    src = open(mw.__file__).read()
    assert "_build_sidebar" not in src
    assert "Sidebar" not in src


def _flatten_tree(tree):
    """Collect (field-label, value) pairs from every row of the decoded tree."""
    out = []

    def walk(item):
        out.append((item.text(0).strip(), item.text(1)))
        for i in range(item.childCount()):
            walk(item.child(i))

    for i in range(tree.topLevelItemCount()):
        walk(tree.topLevelItem(i))
    return out


def test_inspector_values_match_the_actual_packet(parser):
    """The decoded tree must reflect the real packet bytes, not fabricated data."""
    from yaragon.gui.packet_inspector import PacketInspector
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether

    pkt = (Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66")
           / IP(src="192.168.1.50", dst="192.168.1.1")
           / TCP(sport=51000, dport=443, flags="PA", seq=42, ack=99))
    built = build(pkt)
    rec = parser.parse(built, 7)

    # Record-level fields match the wire.
    assert rec.number == 7
    assert rec.length == len(built)
    assert rec.raw == bytes(built)
    assert rec.src_mac == "aa:bb:cc:dd:ee:ff"
    assert rec.dst_mac == "11:22:33:44:55:66"
    assert rec.src_ip == "192.168.1.50"
    assert rec.dst_ip == "192.168.1.1"
    assert rec.src_port == 51000
    assert rec.dst_port == 443

    insp = PacketInspector(compact=True)
    insp.show_packet(rec)
    fields = dict(_flatten_tree(insp.tree))
    assert fields["Source MAC"] == "aa:bb:cc:dd:ee:ff"
    assert fields["Destination MAC"] == "11:22:33:44:55:66"
    assert fields["Source IP"] == "192.168.1.50"
    assert fields["Destination IP"] == "192.168.1.1"
    assert fields["Source Port"] == "51000"
    assert fields["Destination Port"] == "443"
    assert fields["Sequence Number"] == "42"
    assert fields["Acknowledgment Number"] == "99"
    insp.deleteLater()
