"""First-run experience: a bundled sample capture loads without a live MITM and
is clearly labelled as sample data (never presented as live traffic).
"""
import os

os.environ["QT_QPA_PLATFORM"] = "offscreen"

import pytest

pytest.importorskip("PySide6")

from PySide6.QtWidgets import QApplication

_app = QApplication.instance() or QApplication([])


def test_sample_pcap_is_bundled_and_parses():
    from yaragon.gui.widgets import sample_pcap_path
    from yaragon.storage.exporter import import_pcap
    path = sample_pcap_path()
    assert path is not None, "the sample capture must ship with the app"
    recs = import_pcap(path)
    protos = {r.protocol for r in recs}
    # demonstrates the breadth the first-run should show
    assert {"DNS", "TCP", "HTTP", "TLS", "ARP"} <= protos


@pytest.fixture
def redirect_state(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    return tmp_path


def test_load_sample_populates_and_labels_as_sample(redirect_state):
    from yaragon.gui.main_window import MainWindow
    from yaragon.gui.workflow import Stage
    from yaragon.utils.config import Config

    mw = MainWindow(Config())
    try:
        mw._load_sample()
        assert mw.engine.history()                        # records loaded
        assert mw.traffic.model.rowCount() > 0
        assert mw.session.mode == "offline"               # not live
        assert mw.stack.currentIndex() == Stage.INVESTIGATE.value or \
            mw.stack.currentIndex() == 2
        assert "SAMPLE" in mw.traffic.subtitle.text().upper()
        # investigation works over the sample (conversations available)
        assert mw.engine.conversations()
    finally:
        mw.close()
