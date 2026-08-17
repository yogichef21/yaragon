"""Signal-aware cleanup: atexit does NOT run on SIGTERM/SIGINT/SIGHUP, so a
killed / logged-out / terminal-closed process would leave the LAN poisoned.
Yaragon installs Qt-safe handlers that route a terminating signal through the
same restore-and-quit path as a normal close.

Headless: no real signals are delivered (the QSocketNotifier only fires inside a
running event loop). We assert the plumbing is installed and that the graceful
quit performs cleanup.
"""
import os

os.environ["QT_QPA_PLATFORM"] = "offscreen"

import signal

import pytest

pytest.importorskip("PySide6")

from PySide6.QtWidgets import QApplication

_app = QApplication.instance() or QApplication([])


@pytest.fixture
def redirect_state(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    return tmp_path


@pytest.fixture
def preserve_signals():
    """Save/restore the process signal handlers so installing them in a test does
    not leak into the rest of the suite."""
    saved = {s: signal.getsignal(s) for s in (signal.SIGINT, signal.SIGTERM,
                                              signal.SIGHUP)}
    yield
    try:
        signal.set_wakeup_fd(-1)
    except Exception:
        pass
    for s, h in saved.items():
        try:
            signal.signal(s, h)
        except Exception:
            pass


class _FakeCapture:
    def __init__(self):
        self.stopped = False

    def stop(self):
        self.stopped = True

    is_paused = False


def test_install_registers_terminating_signal_handlers(redirect_state, preserve_signals):
    from yaragon.gui.main_window import MainWindow
    from yaragon.utils.config import Config

    mw = MainWindow(Config())
    try:
        mw.install_signal_handlers()
        for s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            handler = signal.getsignal(s)
            # No longer the default terminate action (which would skip cleanup).
            assert handler not in (signal.SIG_DFL, None)
    finally:
        mw.close()


def test_graceful_quit_restores_and_tears_down(redirect_state, preserve_signals):
    """The signal path must stop MITM (restore ARP/forwarding), stop the capture
    and the engine - the same guarantees as a clean close."""
    from yaragon.gui.main_window import MainWindow
    from yaragon.utils.config import Config

    mw = MainWindow(Config())
    stopped = {"mitm": False}

    # Stub the controller so we can prove stop() (the ARP+forwarding restore) is
    # called on the signal path, without a live session.
    class _Mitm:
        active = True

        def stop(self_inner):
            stopped["mitm"] = True
            _Mitm.active = False
    mw.mitm = _Mitm()
    fake = _FakeCapture()
    mw.capture = fake

    mw._graceful_quit()

    assert stopped["mitm"] is True          # ARP + forwarding restore invoked
    assert fake.stopped is True             # sniffer torn down
    assert mw.engine._running is False      # engine asked to stop
