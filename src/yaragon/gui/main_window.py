"""Yaragon main window.

Three sections that follow the product's single workflow:

    Discover ─▶ MITM ─▶ Traffic ─▶ (inspect packets inline)

The window wires the GUI to the capture worker, analysis engine and - on Linux
only - the MITM controller. Capture runs on a background thread and the GUI
drains batched results on a timer, so it never blocks.
"""
from __future__ import annotations

import time
from typing import Optional

from PySide6.QtCore import QObject, QThread, QTimer, Signal
from PySide6.QtWidgets import (QFileDialog, QFrame, QHBoxLayout,
                               QLabel, QMainWindow, QMessageBox,
                               QStackedWidget, QVBoxLayout, QWidget)

from .. import __app_name__, __version__
from ..engine import AnalysisEngine
from ..network.capture import CaptureWorker
from ..network.interfaces import InterfaceInfo, get_interface
from ..network.mitm import MitmController
from ..platform import get_platform
from ..storage.exporter import export_pcap, import_pcap
from ..utils.config import Config
from ..utils.logging import get_logger
from .discovery_view import DiscoveryView
from .mitm_view import MitmView
from .styles import PALETTE, build_stylesheet
from .traffic_view import TrafficView
from .widgets import LiveDot, StageRail, StatusPill
from .workflow import STAGE_ORDER, SessionState, Stage, StageState, compute_stages

log = get_logger("gui")

# Stage <-> QStackedWidget index: the stack is built in STAGE_ORDER, so the two
# line up one-to-one (DISCOVER=0, MITM=1, INVESTIGATE=2).
_LOCKED_HINT = {
    Stage.MITM: "Select a target on Discover first.",
    Stage.INVESTIGATE: "Nothing to investigate yet - start a capture or open a .pcap.",
}


class _MitmWorker(QObject):
    done = Signal(object, str)

    def __init__(self, controller, iface, targets, gateway_ip, interval):
        super().__init__()
        self.controller = controller
        self.iface = iface
        self.targets = targets
        self.gateway_ip = gateway_ip
        self.interval = interval

    def run(self):
        try:
            session = self.controller.start(
                self.iface, self.targets, self.gateway_ip,
                reassert_interval=self.interval)
            self.done.emit(session, "")
        except Exception as exc:
            self.done.emit(None, str(exc))


class _ReachabilityWorker(QObject):
    """Runs the blocking ARP reachability probe off the Qt thread. Each
    resolve_mac() blocks up to 2s, so a synchronous probe of N targets froze the
    GUI for (N+1)*2s - an adversarial LAN could trigger that freeze."""

    done = Signal(object, str)   # ValidationResult, error

    def __init__(self, controller, iface, targets, gateway_ip):
        super().__init__()
        self.controller = controller
        self.iface = iface
        self.targets = targets
        self.gateway_ip = gateway_ip

    def run(self):
        try:
            res = self.controller.reachability(self.iface, self.targets,
                                               self.gateway_ip)
            self.done.emit(res, "")
        except Exception as exc:
            self.done.emit(None, str(exc))


class _MitmStopWorker(QObject):
    """Runs the blocking MITM teardown off the Qt thread. stop() joins the spoof
    thread (up to 5s) and restores ARP + forwarding, which would otherwise freeze
    the UI while a session is torn down."""

    done = Signal(str)   # error ("" on success)

    def __init__(self, controller):
        super().__init__()
        self.controller = controller

    def run(self):
        try:
            self.controller.stop()
            self.done.emit("")
        except Exception as exc:
            self.done.emit(str(exc))


class MainWindow(QMainWindow):
    # Emitted (via a queued connection) when the MITM spoof thread reports the
    # session has degraded - crossing threads safely from the worker.
    mitm_degraded = Signal()

    def __init__(self, config: Config):
        super().__init__()
        self.config = config
        self.setWindowTitle(f"{__app_name__} v{__version__} - Offensive Security MITM Tool")
        self.resize(1360, 860)
        self.setStyleSheet(build_stylesheet())

        self.platform = get_platform()
        self.capabilities = self.platform.capabilities()
        self.privileges = self.platform.check_privileges()
        self.engine = AnalysisEngine(config)
        self.forwarding = self.platform.create_forwarding()
        self.mitm = MitmController(self.forwarding, config.manage_ip_forwarding)
        self.capture: Optional[CaptureWorker] = None

        self.current_iface: Optional[InterfaceInfo] = None
        self.gateway_ip = self.platform.default_gateway() or ""
        self.gateway_mac = ""
        self.targets: list = []   # list[(ip, mac)] chosen on Discover
        # One honest source of truth for the guided stage rail.
        self.session = SessionState(current_stage=Stage.DISCOVER)

        self._build_ui()
        self._wire()

        initial = self.discovery.iface_combo.currentData()
        if initial:
            self._on_interface(initial)

        self.mitm_view.set_platform_support(
            self.capabilities.can_mitm, self.platform.mitm_unavailable_reason())

        self.engine.start()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._on_tick)
        self.timer.start(max(100, config.gui_flush_interval_ms))

        self._update_capture_ui()

        if not self.capabilities.backend_available or not self.privileges.can_capture:
            self._show_banner()
        else:
            self.banner.hide()

    # ------------------------------------------------------------------ UI
    def _build_ui(self) -> None:
        root = QWidget(); root.setObjectName("Root")
        self.setCentralWidget(root)
        rv = QVBoxLayout(root); rv.setContentsMargins(0, 0, 0, 0); rv.setSpacing(0)
        rv.addWidget(self._build_rail())
        rv.addWidget(self._build_banner())
        self.stack = QStackedWidget()
        rv.addWidget(self.stack, 1)

        self._build_views()
        self._build_menu()
        self.statusBar().showMessage("Discover hosts to begin.")
        self._refresh_stages()

    def _build_menu(self) -> None:
        """A single window-level File menu - the home for the session-entry
        actions that do not belong on the Investigate lifecycle strip."""
        file_menu = self.menuBar().addMenu("&File")
        act_open = file_menu.addAction("Open .pcap…")
        act_open.triggered.connect(self._open_pcap)
        act_export = file_menu.addAction("Export .pcap…")
        act_export.triggered.connect(self._export_pcap)
        file_menu.addSeparator()
        act_quit = file_menu.addAction("Quit")
        act_quit.triggered.connect(self.close)

    def _build_rail(self) -> QFrame:
        """The guided stage rail: brand lockup + DISCOVER · MITM · INVESTIGATE
        chips on the left, the global instrument readouts + capture pill on the
        right. Replaces the old sidebar and top strip in one horizontal bar."""
        self.rail = StageRail()
        self.rail.stage_clicked.connect(self._on_stage_clicked)

        readouts = QWidget()
        tb = QHBoxLayout(readouts); tb.setContentsMargins(0, 0, 0, 0); tb.setSpacing(20)
        tb.addLayout(self._strip_item("INTERFACE", "-", "iface"))
        tb.addLayout(self._strip_item("LOCAL IP", "-", "localip"))
        tb.addLayout(self._strip_item("MITM", "inactive", "mitm"))
        # Global capture status (read-only): a status pill + live dot visible
        # from every screen. The capture is controlled from the Investigate
        # screen, where the packets it produces are shown.
        self.live_dot = LiveDot()
        self.capture_pill = StatusPill("IDLE", "off")
        tb.addWidget(self.live_dot)
        tb.addWidget(self.capture_pill)
        self.rail.add_trailing(readouts)
        return self.rail

    def _strip_item(self, key, val, attr):
        box = QVBoxLayout(); box.setSpacing(0)
        k = QLabel(key); k.setObjectName("StripKey")
        v = QLabel(val); v.setObjectName("StripVal")
        setattr(self, f"strip_{attr}", v)
        box.addWidget(k); box.addWidget(v)
        return box

    def _build_banner(self) -> QFrame:
        self.banner = QFrame()
        self.banner.setStyleSheet(
            f"background: rgba(224,163,78,0.10); border-bottom: 1px solid {PALETTE['warning']};")
        bl = QHBoxLayout(self.banner); bl.setContentsMargins(20, 8, 20, 8)
        self.banner_lbl = QLabel(); self.banner_lbl.setWordWrap(True)
        self.banner_lbl.setStyleSheet(f"color: {PALETTE['warning']};")
        bl.addWidget(self.banner_lbl, 1)
        self.banner.hide()
        return self.banner

    def _build_views(self) -> None:
        self.discovery = DiscoveryView()
        self.mitm_view = MitmView()
        self.traffic = TrafficView(self.config.max_rows_in_packet_table)
        for v in (self.discovery, self.mitm_view, self.traffic):
            self.stack.addWidget(v)

    def _wire(self) -> None:
        self.discovery.interface_selected.connect(self._on_interface)
        self.discovery.targets_selected.connect(self._on_targets_selected)
        self.discovery.capture_only_requested.connect(self._capture_only)
        self.mitm_view.validate_requested.connect(self._validate_mitm)
        self.mitm_view.start_requested.connect(self._start_mitm)
        self.mitm_view.stop_requested.connect(self._stop_mitm)
        # The degraded callback fires on the spoof thread; route it through a
        # signal so the GUI update happens on the Qt thread (queued connection).
        self.mitm_degraded.connect(self._on_mitm_degraded)
        self.mitm.on_degraded = self.mitm_degraded.emit
        self.traffic.start_requested.connect(self._capture_start)
        self.traffic.pause_requested.connect(self._capture_pause)
        self.traffic.stop_requested.connect(self._capture_stop)
        self.traffic.clear_requested.connect(self._clear_session)
        self.traffic.export_requested.connect(self._export_pcap)
        self.traffic.open_requested.connect(self._open_pcap)

    def _goto(self, stage: Stage) -> None:
        """The single navigation chokepoint. Forward motion is driven by each
        screen's primary action, so this trusts its caller and does not gate;
        rail clicks are gated separately in `_on_stage_clicked`."""
        self.stack.setCurrentIndex(STAGE_ORDER.index(stage))
        self.session.current_stage = stage
        self._refresh_stages()

    def _on_stage_clicked(self, stage: Stage) -> None:
        """A rail chip was clicked. Refuse locked stages (no-op + a one-line
        hint); otherwise navigate - DONE stages navigate back to re-configure."""
        states = compute_stages(self._synced_session())
        if states.get(stage) == StageState.LOCKED:
            self.statusBar().showMessage(_LOCKED_HINT.get(stage, "Not available yet."))
            return
        self._goto(stage)

    def _synced_session(self) -> SessionState:
        """Refresh the session dataclass from the live attributes and return it."""
        s = self.session
        s.interface = self.current_iface.name if self.current_iface else ""
        s.targets = list(self.targets)
        s.gateway = self.gateway_ip
        s.mitm_active = self.mitm.active
        s.capture_running = self.capture is not None and not self.capture.is_paused
        s.capture_paused = self.capture is not None and self.capture.is_paused
        return s

    def _refresh_stages(self) -> None:
        self.rail.set_states(compute_stages(self._synced_session()))

    @property
    def target_ips(self) -> list:
        return [ip for ip, _ in self.targets]

    # ------------------------------------------------------- capabilities
    def _show_banner(self) -> None:
        if not self.capabilities.backend_available:
            _, msg = self.platform.capture_backend_available()
            self.banner_lbl.setText("⚠  " + msg)
        else:
            self.banner_lbl.setText("⚠  " + self.privileges.detail)
        self.banner.show()

    # ------------------------------------------------------- interfaces
    def _on_interface(self, name: str) -> None:
        iface = get_interface(name)
        if not iface:
            return
        self.current_iface = iface
        self.config.interface = name
        self.strip_iface.setText(iface.name)
        self.strip_localip.setText(iface.ipv4 or "no IPv4")
        self.gateway_ip = self.platform.default_gateway() or self.gateway_ip
        self.mitm_view.set_context(iface.name, self.gateway_ip, self.gateway_mac)
        self.traffic.set_context(self.target_ips, self.gateway_ip, self.mitm.active)
        self._refresh_stages()

    def _capture_only(self) -> None:
        """Passive on-ramp: go to Investigate and start capturing, no MITM."""
        self.session.mode = "live"
        self._goto(Stage.INVESTIGATE)
        self._capture_start()

    def _on_targets_selected(self, targets: list) -> None:
        self.targets = list(targets)
        self.mitm_view.set_targets(self.targets)
        self.mitm_view.set_context(
            self.current_iface.name if self.current_iface else "-",
            self.gateway_ip, self.gateway_mac)
        self.traffic.set_context(self.target_ips, self.gateway_ip, self.mitm.active)
        self.session.mode = "live"
        self._goto(Stage.MITM)

    # ---------------------------------------------------------- capture
    # The capture lifecycle is driven from the Investigate screen
    # (Start / Pause / Stop, with contextual Clear / Export) and capture is also
    # started automatically when a MITM session begins. A single sniffer exists
    # at a time: it is created by _start_capture and torn down by
    # _teardown_capture, so no path can spawn a duplicate listener.
    def _start_capture(self) -> bool:
        if self.capture is not None:
            # Already running - never spin up a second sniffer thread.
            return True
        if not self.current_iface:
            QMessageBox.warning(self, "Yaragon", "Select a network interface first "
                                "(Discover).")
            return False
        backend_ok, backend_msg = self.platform.capture_backend_available()
        if not backend_ok:
            QMessageBox.critical(self, "Yaragon - capture backend", backend_msg)
            return False
        if not self.privileges.can_capture:
            QMessageBox.critical(self, "Yaragon - permissions", self.privileges.detail)
            return False
        try:
            # A live capture starts a clean session: if an opened .pcap was
            # being viewed, discard those offline records before the first live
            # packet so file data never blends into the capture (and numbering
            # restarts from zero).
            if self.session.mode == "offline":
                self.engine.clear()
                self.traffic.clear()
            self.session.mode = "live"
            # Pick up the capture-time BPF expression from the Investigate screen
            # (empty = capture everything). CaptureWorker already honours it.
            self.config.capture_bpf_filter = self.traffic.capture_filter()
            self.capture = CaptureWorker(
                self.current_iface.name, self.engine.queue,
                self.config.capture_bpf_filter, self.config.max_capture_pps)
            self.capture.start()
            self._update_capture_ui()
            self.statusBar().showMessage(f"Capturing on {self.current_iface.name}")
            return True
        except PermissionError:
            QMessageBox.critical(self, "Yaragon", "Permission denied opening the "
                                 "capture device. Raw-socket privileges are required.")
        except Exception as exc:
            QMessageBox.critical(self, "Yaragon", f"Could not start capture:\n{exc}")
        return False

    def _teardown_capture(self) -> None:
        """Stop the sniffer thread. Packets already collected in the
        engine/history are left untouched."""
        if self.capture is not None:
            try:
                self.capture.stop()
            except Exception as exc:
                log.warning("capture stop failed: %s", exc)
            self.capture = None

    # ---- capture control (Traffic screen) ----------------------------
    def _capture_start(self) -> None:
        """Start (from idle) or resume (from paused) packet capture."""
        if self.capture is None:
            self._start_capture()
        elif self.capture.is_paused:
            self.capture.resume()
            self.statusBar().showMessage("Capture resumed.")
            self._update_capture_ui()

    def _capture_pause(self) -> None:
        """Pause capture, keeping every captured packet available."""
        if self.capture is not None and not self.capture.is_paused:
            self.capture.pause()
            self.statusBar().showMessage("Capture paused - captured packets kept.")
            self._update_capture_ui()

    def _capture_stop(self) -> None:
        """Stop the capture session; captured packets stay for inspection/export."""
        if self.capture is None:
            return
        self._teardown_capture()
        self.statusBar().showMessage("Capture stopped - captured packets kept.")
        self._update_capture_ui()

    def _ensure_capturing(self) -> None:
        """Guarantee capture is running and not paused (used when MITM starts)."""
        if self.capture is None:
            self._start_capture()
        elif self.capture.is_paused:
            self.capture.resume()
            self._update_capture_ui()

    def _update_capture_ui(self) -> None:
        if self.capture is None:
            self.capture_pill.set_state("IDLE", "off")
            self.live_dot.set_live(False)
            self.traffic.set_capture_state("idle")
        elif self.capture.is_paused:
            self.capture_pill.set_state("PAUSED", "warn")
            self.live_dot.set_live(False)
            self.traffic.set_capture_state("paused")
        else:
            self.capture_pill.set_state("CAPTURING", "on")
            self.live_dot.set_live(True)
            self.traffic.set_capture_state("capturing")
        self._refresh_stages()

    def _export_pcap(self) -> None:
        all_records = self.engine.history()
        if not all_records:
            QMessageBox.information(self, "Yaragon - export",
                                   "No packets have been captured yet.")
            return
        records = all_records
        filtered = False
        # When a display filter is active, let the operator hand over just the
        # relevant subset rather than the whole noisy capture.
        if self.traffic.is_filter_active():
            visible = self.traffic.visible_records()
            box = QMessageBox(self)
            box.setWindowTitle("Yaragon - export")
            box.setIcon(QMessageBox.Question)
            box.setText(
                f"A filter is active. Export the filtered subset "
                f"({len(visible)}) or all captured packets ({len(all_records)})?")
            filt_btn = box.addButton(f"Export filtered ({len(visible)})",
                                     QMessageBox.AcceptRole)
            all_btn = box.addButton(f"Export all ({len(all_records)})",
                                    QMessageBox.AcceptRole)
            box.addButton(QMessageBox.Cancel)
            box.exec()
            clicked = box.clickedButton()
            if clicked is filt_btn:
                records = visible
                filtered = True
            elif clicked is all_btn:
                records = all_records
            else:
                return
            if not records:
                QMessageBox.information(self, "Yaragon - export",
                                       "The current filter matches no packets.")
                return
        # Only the bounded in-memory history carries raw frame bytes, so an
        # export can never include packets already evicted from it. Warn when
        # the full capture is larger than what will be written.
        total = self.engine.total
        if not filtered and total > len(records):
            proceed = QMessageBox.question(
                self, "Yaragon - export",
                f"{total} packets were captured, but only the most recent "
                f"{len(records)} are still held in memory and can be exported. "
                "Export those?")
            if proceed != QMessageBox.Yes:
                return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export captured packets", "yaragon-capture.pcap",
            "pcap capture (*.pcap);;All files (*)")
        if not path:
            return
        # Yaragon writes classic pcap (wrpcap), so always land on a .pcap name
        # rather than mislabelling the file .pcapng.
        if not path.lower().endswith(".pcap"):
            path += ".pcap"
        try:
            n = export_pcap(records, path)
        except Exception as exc:
            QMessageBox.critical(self, "Yaragon - export failed",
                                 f"Could not write the capture file:\n{exc}")
            return
        self.statusBar().showMessage(f"Exported {n} packet(s) to {path}")
        QMessageBox.information(self, "Yaragon - export",
                               f"Saved {n} packet(s) to:\n{path}")

    def _open_pcap(self) -> None:
        """Open a saved .pcap for offline inspection. Read-only: any live
        capture is stopped first, then the file replaces the current session."""
        path, _ = QFileDialog.getOpenFileName(
            self, "Open a capture file", "",
            "pcap capture (*.pcap *.pcapng *.cap);;All files (*)")
        if not path:
            return
        if self.capture is not None:
            self._teardown_capture()
            self._update_capture_ui()
        try:
            records = import_pcap(path, self.config.packet_history_limit)
        except Exception as exc:
            QMessageBox.critical(self, "Yaragon - open failed",
                                 f"Could not read the capture file:\n{exc}")
            return
        self.engine.load_records(records)
        self.traffic.clear()
        self.traffic.append_batch(records)
        self.traffic.set_loaded_file(path, len(records))
        self.session.mode = "offline"
        self.traffic.set_capture_state("offline")
        self._goto(Stage.INVESTIGATE)
        self.statusBar().showMessage(f"Loaded {len(records)} packet(s) from {path}")

    # ------------------------------------------------------------- MITM
    def _validate_mitm(self, targets: list, gateway_ip: str) -> None:
        gateway_ip = gateway_ip or self.gateway_ip
        iface = self.current_iface
        if not iface:
            self.mitm_view.append_log("Select an interface first (Discover).", "anomaly")
            return
        self.mitm_view.append_log(
            f"Validating {len(targets)} target(s) via gateway {gateway_ip} on {iface.name}",
            "accent")
        res = self.mitm.validate(iface, targets, gateway_ip)
        for name, passed, detail in res.checks:
            self.mitm_view.append_log(
                f"  {'✓' if passed else '✗'} {name}" + (f" - {detail}" if detail else ""),
                "ok" if passed else "anomaly")
        if res.ok and self.privileges.can_capture:
            self.mitm_view.append_log("Static checks passed. Probing reachability (ARP)…",
                                      "accent")
            # The ARP probe blocks up to 2s per target; run it on a worker so the
            # GUI never freezes mid pre-flight (an unreachable set could hang it).
            self.mitm_view.set_probing(True)
            self._reach_thread = QThread()
            self._reach_worker = _ReachabilityWorker(
                self.mitm, iface, list(targets), gateway_ip)
            self._reach_worker.moveToThread(self._reach_thread)
            self._reach_thread.started.connect(self._reach_worker.run)
            self._reach_worker.done.connect(self._on_reachability)
            self._reach_worker.done.connect(self._reach_thread.quit)
            self._reach_thread.start()

    def _on_reachability(self, reach, error: str) -> None:
        self.mitm_view.set_probing(False)
        if error or reach is None:
            self.mitm_view.append_log(f"Reachability probe failed: {error}", "anomaly")
            return
        for name, passed, detail in reach.checks:
            self.mitm_view.append_log(
                f"  {'✓' if passed else '✗'} {name} - {detail}",
                "ok" if passed else "warning")

    def _start_mitm(self, targets: list, gateway_ip: str) -> None:
        gateway_ip = gateway_ip or self.gateway_ip
        iface = self.current_iface
        if not iface:
            QMessageBox.warning(self, "Yaragon", "Select an interface first (Discover).")
            return
        res = self.mitm.validate(iface, targets, gateway_ip)
        if not res.ok:
            failed = [n for n, p, _ in res.checks if not p]
            QMessageBox.warning(self, "Yaragon - validation failed",
                                "Resolve these first:\n• " + "\n• ".join(failed))
            return
        confirm = QMessageBox.question(
            self, "Start MITM session",
            f"Start an ARP MITM session against {len(targets)} target(s) via "
            f"gateway {gateway_ip} on {iface.name}?\n\nFor authorized security "
            "testing only. Yaragon forwards traffic transparently and restores "
            "ARP on stop.\n\nIntercepts IPv4 (ARP). IPv6/NDP traffic is not "
            "captured.")
        if confirm != QMessageBox.Yes:
            return

        self.gateway_ip = gateway_ip
        self._mitm_requested = list(targets)
        self._ensure_capturing()
        self.mitm_view.append_log("Starting MITM…", "accent")
        self._mitm_thread = QThread()
        self._mitm_worker = _MitmWorker(self.mitm, iface, list(targets), gateway_ip,
                                        self.config.arp_reassert_interval)
        self._mitm_worker.moveToThread(self._mitm_thread)
        self._mitm_thread.started.connect(self._mitm_worker.run)
        self._mitm_worker.done.connect(self._on_mitm_started)
        self._mitm_worker.done.connect(self._mitm_thread.quit)
        self._mitm_thread.start()

    def _on_mitm_started(self, session, error: str) -> None:
        if error or session is None:
            self.mitm_view.append_log(f"MITM failed: {error}", "anomaly")
            QMessageBox.critical(self, "Yaragon", f"Could not start MITM:\n{error}")
            self.mitm_view.set_active(False)
            return
        self.gateway_mac = session.gateway_mac
        since = time.strftime("%H:%M:%S", time.localtime(session.started_at))
        self.mitm_view.set_active(True, since)
        self.mitm_view.set_context(session.iface, session.gateway_ip, session.gateway_mac)
        self.mitm_view.append_log(
            f"MITM active on {len(session.targets)} target(s). gateway_mac="
            f"{session.gateway_mac}. Forwarding: {self.forwarding.current()}.", "ok")
        # If fewer targets resolved than were selected, say so plainly - a tool
        # that quietly does less than asked can invalidate a test's conclusions.
        requested = getattr(self, "_mitm_requested", [])
        resolved = session.target_ips
        if requested and len(resolved) < len(requested):
            dropped = [ip for ip in requested if ip not in resolved]
            self.mitm_view.append_log(
                f"⚠ {len(resolved)} of {len(requested)} selected target(s) are "
                f"active - could not reach: {', '.join(dropped)}", "warning")
        self.strip_mitm.setText("ACTIVE")
        self.strip_mitm.setStyleSheet(f"color: {PALETTE['warning']};")
        self.traffic.set_context(self.target_ips, self.gateway_ip, True)
        self._goto(Stage.INVESTIGATE)

    def _on_mitm_degraded(self) -> None:
        """A running session stopped intercepting. Surface it honestly (red)
        instead of leaving the readout claiming ACTIVE."""
        if not self.mitm.active:
            return
        self.mitm_view.set_degraded()
        self.mitm_view.append_log(
            "⚠ Session degraded - ARP re-assertion is failing; interception may "
            "have stopped.", "anomaly")
        self.strip_mitm.setText("DEGRADED")
        self.strip_mitm.setStyleSheet(f"color: {PALETTE['danger']};")

    def _stop_mitm(self) -> None:
        if not self.mitm.active:
            self.mitm_view.set_active(False)
            return
        # Ignore a re-entrant stop while a teardown is already running.
        if getattr(self, "_stop_thread", None) is not None and self._stop_thread.isRunning():
            return
        self.mitm_view.append_log("Stopping MITM and restoring ARP…", "accent")
        self._stop_thread = QThread()
        self._stop_worker = _MitmStopWorker(self.mitm)
        self._stop_worker.moveToThread(self._stop_thread)
        self._stop_thread.started.connect(self._stop_worker.run)
        self._stop_worker.done.connect(self._on_mitm_stopped)
        self._stop_worker.done.connect(self._stop_thread.quit)
        self._stop_thread.start()

    def _on_mitm_stopped(self, error: str) -> None:
        if error:
            self.mitm_view.append_log(f"Error during stop: {error}", "anomaly")
        else:
            self.mitm_view.append_log("MITM stopped. ARP + forwarding restored.", "ok")
        self.mitm_view.set_active(False)
        self.strip_mitm.setText("inactive")
        self.strip_mitm.setStyleSheet("")
        self.traffic.set_context(self.target_ips, self.gateway_ip, False)
        self._refresh_stages()

    # ------------------------------------------------------------- tick
    def _on_tick(self) -> None:
        batch = self.engine.drain_new()
        if batch:
            self.traffic.append_batch(batch)

    # ---------------------------------------------------------- session
    def _clear_session(self) -> None:
        if QMessageBox.question(self, "Yaragon", "Clear captured packets from view?") \
                == QMessageBox.Yes:
            self.engine.clear()
            self.traffic.clear()
            self.statusBar().showMessage("Cleared.")

    # -------------------------------------------------------- shutdown
    def closeEvent(self, event) -> None:
        log.info("Shutting down Yaragon…")
        try:
            self.timer.stop()
        except Exception:
            pass
        if self.mitm.active:
            try:
                self.mitm.stop()
            except Exception as exc:
                log.warning("MITM stop on exit failed: %s", exc)
        if self.capture is not None:
            try:
                self.capture.stop()
            except Exception:
                pass
        try:
            self.engine.stop()
        except Exception:
            pass
        # Persist the small amount of remembered state (e.g. last interface).
        try:
            self.config.save()
        except Exception as exc:
            log.warning("saving config on exit failed: %s", exc)
        log.info("Yaragon shutdown complete.")
        super().closeEvent(event)
