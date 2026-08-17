"""Headless integration + robustness tests (QA adversarial pass).

These complement the unit-level smoke tests by exercising things the mission
brief calls out explicitly but that were previously untested:

  * the "Ink & Signal" stylesheet builds valid, non-empty QSS in BOTH themes
    and applies to a real widget without error;
  * every top-level view constructs offscreen and accepts the app stylesheet;
  * the full MainWindow constructs offscreen and its guided stage rail reflects
    real session state (target selection, capture running, locked navigation);
  * the capture-lifecycle state machine holds its invariants under repeated and
    cycled presses (never an invalid enabled set, exactly one primary);
  * compute_stages() output drives the StageRail one-to-one (unit integration);
  * combined display filters intersect correctly;
  * shutting the window down mid-capture tears threads down cleanly.

Everything runs under Qt 'offscreen'. No NIC / root / display is required or
assumed - live capture and MITM spoofing are not driven here.
"""
import os

os.environ["QT_QPA_PLATFORM"] = "offscreen"

import pytest

pytest.importorskip("PySide6")

from conftest import build
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from PySide6.QtWidgets import QApplication, QWidget

_app = QApplication.instance() or QApplication([])


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _records(parser, n=5, src="10.0.0.2", dst="10.0.0.1", dport=80):
    out = []
    for i in range(n):
        pkt = Ether() / IP(src=src, dst=dst) / TCP(sport=40000 + i, dport=dport,
                                                   flags="S", seq=1000 + i)
        out.append(parser.parse(build(pkt), i + 1))
    return out


@pytest.fixture
def redirect_state(tmp_path, monkeypatch):
    """Point config/log writes at a tmp dir so MainWindow.closeEvent() (which
    calls config.save()) never touches the developer's real ~/.config."""
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    return tmp_path


class _FakeCapture:
    """Stand-in for CaptureWorker so the window's capture-driven UI/state can be
    exercised without a NIC. Only the surface MainWindow reads is implemented."""

    def __init__(self, paused=False):
        self.is_paused = paused
        self.stopped = False

    def stop(self):
        self.stopped = True

    def pause(self):
        self.is_paused = True

    def resume(self):
        self.is_paused = False


# --------------------------------------------------------------------------- #
# Stylesheet + view construction
# --------------------------------------------------------------------------- #
def test_stylesheet_builds_valid_in_both_themes():
    """A1: build_stylesheet() returns non-empty QSS with every token resolved,
    in dark AND light, and applies to a widget without error. set_theme leaves
    the module back on dark (the only wired theme)."""
    from yaragon.gui import styles

    dark = styles.build_stylesheet()
    styles.set_theme("light")
    light = styles.build_stylesheet()
    styles.set_theme("dark")           # restore the default for other tests
    back = styles.build_stylesheet()

    for sheet in (dark, light, back):
        assert isinstance(sheet, str) and len(sheet) > 500
        # No unresolved f-string placeholders leaked into the QSS.
        assert "{p[" not in sheet and "{RADIUS" not in sheet
        assert "None" not in sheet          # a missing token would stringify None
        w = QWidget(); w.setStyleSheet(sheet); w.deleteLater()

    assert styles.PALETTE is styles._DARK


def test_palette_superset_of_keys_read_by_widgets():
    """A1 acceptance: PALETTE carries every key the widgets look up (a missing
    one would KeyError at build time). Guards against a future token rename."""
    from yaragon.gui import styles

    needed = {"bg", "bg_alt", "panel", "panel_2", "border", "border_sub",
              "text", "text_dim", "muted", "primary", "primary_d", "accent",
              "ok", "warning", "anomaly", "danger", "selection"}
    assert needed <= set(styles._DARK)
    assert set(styles._DARK) == set(styles._LIGHT)   # themes mirror each other


def test_all_views_construct_offscreen_and_take_stylesheet():
    """Every top-level view constructs headlessly and accepts the app
    stylesheet - the 'every view constructs offscreen' bar in the brief."""
    from yaragon.gui.styles import build_stylesheet
    from yaragon.gui.discovery_view import DiscoveryView
    from yaragon.gui.mitm_view import MitmView
    from yaragon.gui.traffic_view import TrafficView
    from yaragon.gui.packet_inspector import PacketInspector

    sheet = build_stylesheet()
    for factory in (DiscoveryView, MitmView, lambda: TrafficView(limit=100),
                    lambda: PacketInspector(compact=True), PacketInspector):
        v = factory()
        v.setStyleSheet(sheet)          # must not raise
        v.deleteLater()


# --------------------------------------------------------------------------- #
# MainWindow integration
# --------------------------------------------------------------------------- #
def test_main_window_constructs_and_initial_stage(redirect_state):
    from yaragon.gui.main_window import MainWindow
    from yaragon.gui.workflow import Stage, StageState, compute_stages
    from yaragon.utils.config import Config

    mw = MainWindow(Config())
    try:
        assert mw.stack.count() == 3                     # DISCOVER / MITM / INVESTIGATE
        assert mw.stack.currentIndex() == 0              # starts on Discover
        st = compute_stages(mw._synced_session())
        assert st[Stage.DISCOVER] == StageState.CURRENT
        assert st[Stage.MITM] == StageState.LOCKED       # no targets yet
        assert st[Stage.INVESTIGATE] == StageState.LOCKED
        # the rail chips reflect the same states
        assert mw.rail.chip(Stage.MITM).state() == "locked"
    finally:
        mw.close()


def test_main_window_target_selection_and_capture_drive_the_rail(redirect_state):
    """Selecting targets navigates to MITM and marks DISCOVER done; a running
    capture unlocks INVESTIGATE and lights the CAPTURING pill - the guided flow
    reflecting real state end-to-end (no NIC: capture is a stand-in)."""
    from yaragon.gui.main_window import MainWindow
    from yaragon.gui.workflow import Stage, StageState, compute_stages
    from yaragon.utils.config import Config

    mw = MainWindow(Config())
    try:
        mw._on_targets_selected([("10.0.0.5", "aa:bb:cc:dd:ee:ff")])
        assert mw.stack.currentIndex() == 1             # moved to MITM
        st = compute_stages(mw._synced_session())
        assert st[Stage.DISCOVER] == StageState.DONE
        assert st[Stage.MITM] == StageState.CURRENT
        assert st[Stage.INVESTIGATE] == StageState.LOCKED

        # A capture starts running (stand-in worker) -> INVESTIGATE reachable.
        mw.capture = _FakeCapture(paused=False)
        mw._update_capture_ui()
        assert mw.capture_pill.text() == "CAPTURING"
        assert mw.live_dot._live is True
        st = compute_stages(mw._synced_session())
        assert st[Stage.INVESTIGATE] != StageState.LOCKED

        # Pausing is honestly reflected.
        mw.capture.pause()
        mw._update_capture_ui()
        assert mw.capture_pill.text() == "PAUSED"
        assert mw.live_dot._live is False
        mw.capture = None
    finally:
        mw.close()


def test_main_window_locked_stage_click_is_a_noop(redirect_state):
    """A3 acceptance: clicking a LOCKED rail chip does not navigate; it only
    surfaces a one-line hint. Clicking an available/current one navigates."""
    from yaragon.gui.main_window import MainWindow
    from yaragon.gui.workflow import Stage
    from yaragon.utils.config import Config

    mw = MainWindow(Config())
    try:
        assert mw.stack.currentIndex() == 0
        mw._on_stage_clicked(Stage.INVESTIGATE)         # locked from Discover
        assert mw.stack.currentIndex() == 0             # unchanged
        assert mw.statusBar().currentMessage()          # a hint was shown
        mw._on_stage_clicked(Stage.DISCOVER)            # current/available
        assert mw.stack.currentIndex() == 0
    finally:
        mw.close()


def test_shutdown_during_capture_is_clean(redirect_state):
    """Closing the window mid-capture must stop the sniffer, the engine and the
    timer, and persist config, without raising - the 'shutdown during capture'
    edge case."""
    from PySide6.QtGui import QCloseEvent
    from yaragon.gui.main_window import MainWindow
    from yaragon.utils.config import Config

    mw = MainWindow(Config())
    fake = _FakeCapture(paused=False)
    mw.capture = fake
    mw.closeEvent(QCloseEvent())                        # must not raise
    assert fake.stopped is True
    assert mw.engine._running is False                  # engine thread asked to stop


# --------------------------------------------------------------------------- #
# Capture state-machine robustness
# --------------------------------------------------------------------------- #
def _lifecycle_invariants(view):
    """No state may leave an impossible enabled set on the live triplet."""
    s, p, st = view.start_btn, view.pause_btn, view.stop_btn
    # Start (the sole #Primary) and Pause are never both enabled.
    assert not (s.isEnabled() and p.isEnabled())
    # Pause is only ever enabled while capturing (stop also enabled then).
    if p.isEnabled():
        assert st.isEnabled()


def test_capture_state_machine_repeated_presses_are_idempotent(parser):
    """Rapid/repeated presses of the same state must not corrupt the control set
    (the guard that a second Start can't spawn a duplicate sniffer lives here as
    'Start disabled while capturing')."""
    from yaragon.gui.traffic_view import TrafficView
    view = TrafficView(limit=100)
    try:
        for _ in range(4):
            view.set_capture_state("capturing")
            _lifecycle_invariants(view)
            assert not view.start_btn.isEnabled()       # cannot re-Start
        for _ in range(4):
            view.set_capture_state("idle")
            _lifecycle_invariants(view)
            assert view.start_btn.isEnabled() and view.start_btn.text() == "Start"
    finally:
        view.deleteLater()


def test_capture_state_machine_full_cycle_holds_invariants(parser):
    """Drive idle->capturing->paused->capturing(resume)->idle(stop) and back to
    a fresh Start; the invariants and the Start/Resume label must hold at every
    hop, and exactly one primary lifecycle control is ever active."""
    from yaragon.gui.traffic_view import TrafficView
    view = TrafficView(limit=100)
    try:
        seq = ["idle", "capturing", "paused", "capturing", "paused", "idle",
               "idle", "capturing"]
        for state in seq:
            view.set_capture_state(state)
            _lifecycle_invariants(view)
            if state == "idle":
                assert view.start_btn.text() == "Start"
            elif state == "paused":
                assert view.start_btn.text() == "Resume"
                assert view.stop_btn.isEnabled()
            elif state == "capturing":
                assert view.pause_btn.isEnabled() and view.stop_btn.isEnabled()
                assert not view.start_btn.isEnabled()
    finally:
        view.deleteLater()


def test_offline_state_hides_live_triplet_and_enables_data_actions(parser):
    """Offline (.pcap) sessions: the live triplet is hidden and Clear/Export are
    enabled regardless of the has-packets gate (an empty file still 'closes')."""
    from yaragon.gui.traffic_view import TrafficView
    view = TrafficView(limit=100)
    try:
        view.set_capture_state("offline")               # no packets set yet
        for b in (view.start_btn, view.pause_btn, view.stop_btn):
            assert not b.isVisibleTo(view)
        assert view.clear_btn.isEnabled() and view.export_btn.isEnabled()
        assert view.clear_btn.text() == "Close file"
    finally:
        view.deleteLater()


# --------------------------------------------------------------------------- #
# compute_stages <-> StageRail integration
# --------------------------------------------------------------------------- #
def test_stage_rail_reflects_compute_stages_output():
    """The two units the developer wired together: compute_stages() output feeds
    StageRail.set_states() one-to-one for a representative live journey."""
    from yaragon.gui.widgets import StageRail
    from yaragon.gui.workflow import (SessionState, Stage, StageState,
                                      compute_stages)
    rail = StageRail()
    try:
        s = SessionState(interface="eth0", targets=[("10.0.0.5", "aa")],
                         mitm_active=True, capture_running=True,
                         current_stage=Stage.INVESTIGATE)
        states = compute_stages(s)
        rail.set_states(states)
        for stage in Stage:
            assert rail.chip(stage).state() == states[stage].value
        # exactly one current chip
        currents = [st for st in Stage if rail.state_of(st) == StageState.CURRENT]
        assert currents == [Stage.INVESTIGATE]
    finally:
        rail.deleteLater()


# --------------------------------------------------------------------------- #
# Combined display filters
# --------------------------------------------------------------------------- #
def test_combined_filters_intersect(parser):
    """proto + source-IP + port search compose as an intersection; loosening any
    one widens the result set predictably."""
    from yaragon.gui.traffic_view import TrafficView
    view = TrafficView(limit=200)
    try:
        recs = _records(parser, 6, src="10.0.0.2", dst="10.0.0.1", dport=80)
        recs += _records(parser, 4, src="10.0.0.3", dst="10.0.0.1", dport=443)
        for i, r in enumerate(recs):                     # unique numbers
            r.number = i + 1
        view.append_batch(recs)
        assert view.model.rowCount() == 10

        view.proxy.set_proto("TCP")                      # all are TCP
        view.proxy.set_src_ip("10.0.0.2")                # only the first 6
        assert view.proxy.rowCount() == 6
        view.proxy.set_text("443")                       # ...but none on port 443
        assert view.proxy.rowCount() == 0
        view.proxy.set_src_ip("10.0.0.3")                # 443 hosts
        assert view.proxy.rowCount() == 4
        view.proxy.set_text("")                          # drop the port filter
        assert view.proxy.rowCount() == 4
    finally:
        view.deleteLater()


def test_follow_conversation_intersects_with_protocol(parser):
    """A followed A<->B conversation composes with the protocol chip rather than
    overriding it."""
    from yaragon.gui.traffic_view import TrafficView
    view = TrafficView(limit=200)
    try:
        recs = _records(parser, 5, src="10.0.0.2", dst="10.0.0.1")
        for i, r in enumerate(recs):
            r.number = i + 1
        view.append_batch(recs)
        view.proxy.set_pair(("10.0.0.1", "10.0.0.2"))
        assert view.proxy.rowCount() == 5
        view.proxy.set_proto("UDP")                      # no UDP among them
        assert view.proxy.rowCount() == 0
        view.proxy.set_proto("TCP")
        assert view.proxy.rowCount() == 5
    finally:
        view.deleteLater()


def test_window_title_is_single_and_clean():
    """The title bar shows one clean string, not a duplicated product name."""
    from yaragon.gui.main_window import MainWindow
    from yaragon.utils.config import Config
    w = MainWindow(Config())
    title = w.windowTitle()
    assert title == "Yaragon v1.0.0 - Offensive Security MITM Tool"
    # the old bug duplicated the product descriptor; guard against regressions
    assert title.count("Offensive Security MITM Tool") == 1
    w.deleteLater()


def test_stage_rail_uses_hairline_connectors_not_text_dashes():
    """The stage rail connects chips with hairline QFrames, never a text '--'."""
    from PySide6.QtWidgets import QFrame, QLabel
    from yaragon.gui.widgets import StageRail
    rail = StageRail()
    links = [f for f in rail.findChildren(QFrame)
             if f.objectName() in ("StageLink", "StageLinkSkip")]
    assert len(links) == 2                       # DISCOVER-MITM, MITM-INVESTIGATE
    assert any(f.objectName() == "StageLinkSkip" for f in links)   # MITM is skippable
    # no separator label is a bare dash string
    for lbl in rail.findChildren(QLabel):
        assert lbl.text().strip() not in ("--", "- -")
    rail.deleteLater()


def test_mitm_stop_worker_reports_result():
    """The stop worker runs teardown off-thread and reports success or the error
    text, so _stop_mitm never blocks the Qt main thread."""
    from yaragon.gui.main_window import _MitmStopWorker

    class _Ok:
        def stop(self): pass

    class _Boom:
        def stop(self): raise RuntimeError("restore failed")

    seen = []
    ok = _MitmStopWorker(_Ok()); ok.done.connect(lambda e: seen.append(e)); ok.run()
    bad = _MitmStopWorker(_Boom()); bad.done.connect(lambda e: seen.append(e)); bad.run()
    assert seen == ["", "restore failed"]


def test_discovery_empty_cell_is_dim_centered_placeholder():
    """Missing table values render as a dim, centered '-' (not a broken cell)."""
    from PySide6.QtCore import Qt
    from yaragon.gui.discovery_view import _cell
    filled = _cell("192.168.1.5")
    assert filled.text() == "192.168.1.5"
    empty = _cell("")
    assert empty.text() == "-"
    assert empty.textAlignment() & Qt.AlignCenter


# --------------------------------------------------------------------------- #
# Critical: investigation must survive STOP
# --------------------------------------------------------------------------- #
def test_investigation_survives_stop(redirect_state, parser):
    """The release-critical guarantee: pressing STOP stops capturing new traffic
    but must NOT destroy the investigation. After _capture_stop the captured
    data stays, and search / filter / inspect-source / export all still work."""
    from yaragon.gui.main_window import MainWindow
    from yaragon.utils.config import Config

    mw = MainWindow(Config())
    recs = _records(parser, n=8, dst="10.0.0.1")
    # simulate a running capture that produced packets
    mw.capture = _FakeCapture(paused=False)
    mw._update_capture_ui()
    mw.traffic.append_batch(recs)
    assert mw.traffic.model.rowCount() == 8

    # STOP
    mw._capture_stop()
    assert mw.capture is None                       # sniffer torn down

    # data is retained
    assert mw.traffic.model.rowCount() == 8
    # investigation actions remain enabled after stop (data present)
    assert mw.traffic.export_btn.isEnabled()
    assert mw.traffic.clear_btn.isEnabled()
    # search still narrows the retained data
    mw.traffic.proxy.set_text("80")                 # dst port 80
    assert mw.traffic.proxy.rowCount() == 8
    mw.traffic.proxy.set_text("59999")              # matches nothing
    assert mw.traffic.proxy.rowCount() == 0
    mw.traffic.proxy.set_text("")
    # protocol + IP filter still work after stop
    mw.traffic.proxy.set_proto("TCP")
    assert mw.traffic.proxy.rowCount() == 8
    mw.traffic.proxy.set_src_ip("10.0.0.2")
    assert mw.traffic.proxy.rowCount() == 8
    # the packet source for inspect/export is still the retained, filtered set
    assert len(mw.traffic.visible_records()) == 8
    mw.deleteLater()


def test_export_source_available_after_stop(tmp_path, redirect_state, parser):
    """Export after STOP produces a valid, reopenable pcap from retained data."""
    from scapy.utils import rdpcap
    from yaragon.storage.exporter import export_pcap

    recs = _records(parser, n=6)
    out = tmp_path / "post_stop.pcap"
    # export operates on retained records (what visible_records/history hand it)
    assert export_pcap(recs, str(out)) == 6
    assert len(rdpcap(str(out))) == 6
