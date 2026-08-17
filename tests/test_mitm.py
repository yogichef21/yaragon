"""MitmController safety tests (no NIC / no root required).

These exercise the pure guard logic, not the live spoof loop: A11 re-validation
inside start() and A13's degraded-session failure-threshold counter.
"""
import pytest

from yaragon.network.interfaces import InterfaceInfo
from yaragon.network.mitm import (DEGRADE_THRESHOLD, MitmController,
                                  degraded_reached)


class _FakeForwarding:
    def __init__(self):
        self.enabled = False

    def enable(self):
        self.enabled = True
        return True

    def restore(self):
        self.enabled = False

    def current(self):
        return self.enabled


def _iface():
    return InterfaceInfo(name="eth0", ipv4="192.168.1.10",
                         netmask="255.255.255.0", is_up=True, mac="aa:bb:cc:dd:ee:ff")


@pytest.mark.parametrize("targets", [
    ["192.168.1.1"],     # equals the gateway
    ["192.168.1.10"],    # equals this host
    ["10.9.9.9"],        # off the interface subnet
    ["not-an-ip"],       # malformed
    [],                  # no targets at all
])
def test_start_revalidates_and_refuses_invalid_targets(targets):
    """A11: start() re-runs the invariants itself and raises before enabling
    forwarding or spoofing - safe by construction, no prior validate() needed."""
    ctrl = MitmController(_FakeForwarding(), manage_forwarding=True)
    with pytest.raises(ValueError):
        ctrl.start(_iface(), targets, "192.168.1.1")
    assert not ctrl.active
    assert ctrl.forwarding.enabled is False   # never reached forwarding


def test_degraded_threshold_predicate():
    """A13: the failure-count threshold logic is a pure, unit-testable predicate."""
    assert degraded_reached(0) is False
    assert degraded_reached(DEGRADE_THRESHOLD - 1) is False
    assert degraded_reached(DEGRADE_THRESHOLD) is True
    assert degraded_reached(DEGRADE_THRESHOLD + 5) is True
    # threshold is configurable
    assert degraded_reached(2, threshold=2) is True
    assert degraded_reached(1, threshold=2) is False
