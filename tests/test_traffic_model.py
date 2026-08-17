"""The packet table must grow past its cap without a full model reset (which
loses selection and churns the inspector on every batch during long captures).
Eviction uses row remove/insert, not beginResetModel.
"""
import os

os.environ["QT_QPA_PLATFORM"] = "offscreen"

import pytest

pytest.importorskip("PySide6")

from conftest import build
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from PySide6.QtWidgets import QApplication

_app = QApplication.instance() or QApplication([])


def _recs(parser, n, start=1):
    out = []
    for i in range(n):
        pkt = Ether() / IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=40000,
                                                                 dport=80, flags="PA")
        r = parser.parse(build(pkt), start + i)
        r.number = start + i
        out.append(r)
    return out


def test_over_cap_append_uses_remove_insert_not_reset(parser):
    from yaragon.gui.traffic_view import TrafficModel
    model = TrafficModel(limit=100)
    resets = []
    model.modelAboutToBeReset.connect(lambda: resets.append(True))

    model.append_batch(_recs(parser, 100, start=1))     # fills to cap
    assert model.rowCount() == 100
    model.append_batch(_recs(parser, 20, start=101))    # over cap -> evict 20
    assert model.rowCount() == 100                      # still capped
    # the newest record is retained, the oldest evicted
    assert model.record_at(99).number == 120
    assert model.record_at(0).number == 21
    # crucially: no full reset was used for the eviction
    assert resets == []
