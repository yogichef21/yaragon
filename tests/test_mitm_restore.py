"""The cardinal safety property, executed (not merely reasoned about): the MITM
spoof loop restores every endpoint's ARP on stop AND on an unexpected thread
exit, stop() is idempotent, and an unexpected exit notifies the GUI so the
readout never keeps claiming ACTIVE for a torn-down session.

A fake scapy `send` is injected so the frames are captured and asserted without
a NIC or root. This locks `mitm.py:_spoof_loop/_restore/stop`.
"""
import time

import pytest

from yaragon.network.mitm import MitmController, MitmSession


class _FakeForwarding:
    def __init__(self):
        self.enabled = False
        self.restored = 0

    def enable(self):
        self.enabled = True
        return True

    def restore(self):
        self.enabled = False
        self.restored += 1

    def current(self):
        return self.enabled

    def preflight(self, iface_name):
        from yaragon.platform.base import ForwardingPreflight
        return ForwardingPreflight(ok=True, blocked=False)


def _session():
    return MitmSession(
        iface="eth0", gateway_ip="192.168.1.1", gateway_mac="gg:gg:gg:gg:gg:gg",
        local_mac="aa:bb:cc:dd:ee:ff", started_at=time.time(),
        targets=[("192.168.1.20", "tt:tt:tt:tt:tt:tt")])


@pytest.fixture
def captured_arp(monkeypatch):
    """Capture every ARP scapy.send would emit, and make ARP()/send importable
    from `scapy.all` without a real backend by faking the two names the loop
    imports (`from scapy.all import ARP, send`)."""
    sent = []

    class _FakeARP:
        def __init__(self, **kw):
            self.kw = kw

    def _fake_send(pkt, **kw):
        sent.append(pkt.kw)

    import sys
    import types
    fake_scapy_all = types.ModuleType("scapy.all")
    fake_scapy_all.ARP = _FakeARP
    fake_scapy_all.send = _fake_send
    monkeypatch.setitem(sys.modules, "scapy.all", fake_scapy_all)
    return sent


def test_restore_emits_correct_arp_for_every_endpoint(captured_arp):
    """_restore heals the network: for each target it re-ARPs the target (gateway
    is at the real gateway MAC) and the gateway (target is at the real target
    MAC). Correct psrc/hwsrc restore normal layer-2 delivery."""
    ctrl = MitmController(_FakeForwarding(), manage_forwarding=True)
    ctrl._restore(_session(), rounds=1)
    # Two frames per target per round: heal-target + heal-gateway.
    assert len(captured_arp) == 2
    heal_target = next(f for f in captured_arp if f["pdst"] == "192.168.1.20")
    heal_gateway = next(f for f in captured_arp if f["pdst"] == "192.168.1.1")
    # target is told the gateway is back at the REAL gateway MAC
    assert heal_target["psrc"] == "192.168.1.1"
    assert heal_target["hwsrc"] == "gg:gg:gg:gg:gg:gg"
    # gateway is told the target is back at the REAL target MAC
    assert heal_gateway["psrc"] == "192.168.1.20"
    assert heal_gateway["hwsrc"] == "tt:tt:tt:tt:tt:tt"


class _RaisingEvent:
    """A stand-in threading.Event whose wait() raises, to force the spoof loop to
    exit UNEXPECTEDLY (not via a clean stop()) so the finally: self-heal path is
    exercised."""
    def __init__(self):
        self._set = False

    def is_set(self):
        return self._set

    def wait(self, _timeout):
        raise RuntimeError("simulated spoof-thread crash")

    def set(self):
        self._set = True

    def clear(self):
        self._set = False


def test_spoof_loop_self_heals_and_signals_on_unexpected_exit(captured_arp):
    """If the spoof loop exits WITHOUT an explicit stop() (an unexpected error),
    the finally: block restores ARP + forwarding AND fires on_thread_exit so the
    GUI can leave ACTIVE. This is the path the review found unguarded."""
    ctrl = MitmController(_FakeForwarding(), manage_forwarding=True)
    signalled = []
    ctrl.on_thread_exit = lambda: signalled.append(True)
    s = _session()
    ctrl._session = s
    ctrl._stop = _RaisingEvent()   # wait() will raise -> unexpected exit

    ctrl._spoof_loop(s, interval=0.01)   # runs synchronously; exits via finally

    assert signalled == [True]           # the GUI was told the thread died
    assert ctrl.active is False          # session cleared by the self-heal
    assert ctrl.forwarding.restored >= 1  # forwarding restored on the way out


def test_restore_failure_is_reported_not_hidden(captured_arp):
    """The cardinal honesty property: if the ARP restore fails, stop() must NOT
    report a clean teardown. last_restore_ok is False and an error is set, so the
    GUI shows 'cleanup failed' instead of 'ARP + forwarding restored'."""
    ctrl = MitmController(_FakeForwarding(), manage_forwarding=True)
    ctrl._session = _session()
    ctrl._stop.clear()

    import sys
    def _raise(*a, **k):
        raise OSError("Network is down")
    sys.modules["scapy.all"].send = _raise    # the exact module _restore imports

    ctrl.stop()
    assert ctrl.active is False
    assert ctrl.last_restore_ok is False
    assert ctrl.last_restore_error   # a non-empty, honest message


def test_restore_attempts_every_target_despite_one_failure(captured_arp):
    """One failing send must not abort healing for the remaining endpoints -
    each send is guarded individually (unlike a single try around the loop)."""
    ctrl = MitmController(_FakeForwarding(), manage_forwarding=True)
    s = MitmSession(
        iface="eth0", gateway_ip="192.168.1.1", gateway_mac="gg:gg:gg:gg:gg:gg",
        local_mac="aa:bb:cc:dd:ee:ff", started_at=time.time(),
        targets=[("192.168.1.20", "t1"), ("192.168.1.21", "t2")])
    seen = []

    import sys

    def _send(pkt, **kw):
        seen.append(pkt.kw["pdst"])
        if pkt.kw["pdst"] == "192.168.1.20":
            raise OSError("boom on first target")
    sys.modules["scapy.all"].send = _send    # the exact module _restore imports

    ok = ctrl._restore(s, rounds=1)
    assert ok is False                       # a failure occurred
    # but the other target and the gateway were still attempted
    assert "192.168.1.21" in seen
    assert "192.168.1.1" in seen


def test_stop_is_idempotent(captured_arp):
    """stop() twice must not raise and must not double-fail; the second call is a
    no-op once the session is gone."""
    ctrl = MitmController(_FakeForwarding(), manage_forwarding=True)
    ctrl._session = _session()
    ctrl._stop.clear()
    ctrl.stop()
    assert ctrl.active is False
    ctrl.stop()  # second call - no exception, no session
    assert ctrl.active is False
