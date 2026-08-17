"""Forwarding-path preflight: 'ip_forward=1' is not enough - if the netfilter
FORWARD policy drops the relayed traffic, poisoning ARP black-holes the target.
Yaragon must detect that and fail closed, and must never claim a healthy relay
when the data plane would drop it.

These tests inject the policy/rp_filter readers so no root or nft/iptables is
needed. They lock the decision logic, not the OS calls.
"""
import pytest

from yaragon.platform import linux as lx
from yaragon.network.interfaces import InterfaceInfo
from yaragon.network.mitm import MitmController


def _iface():
    return InterfaceInfo(name="eth0", ipv4="192.168.1.10",
                         netmask="255.255.255.0", is_up=True, mac="aa:bb:cc:dd:ee:ff")


def test_drop_policy_blocks_and_is_not_ok(monkeypatch):
    monkeypatch.setattr(lx, "_forward_policy", lambda: "drop")
    monkeypatch.setattr(lx, "_rp_filter_effective", lambda iface: 0)
    res = lx.LinuxForwarding().preflight("eth0")
    assert res.ok is False
    assert res.blocked is True
    assert "forward" in res.reason.lower()


def test_accept_policy_is_ok(monkeypatch):
    monkeypatch.setattr(lx, "_forward_policy", lambda: "accept")
    monkeypatch.setattr(lx, "_rp_filter_effective", lambda iface: 0)
    res = lx.LinuxForwarding().preflight("eth0")
    assert res.ok is True
    assert res.blocked is False


def test_unknown_policy_does_not_false_block(monkeypatch):
    """When the policy can't be read (the normal cap_net_raw-only case), do NOT
    hard-refuse every MITM - proceed but surface an unverified check."""
    monkeypatch.setattr(lx, "_forward_policy", lambda: "unknown")
    monkeypatch.setattr(lx, "_rp_filter_effective", lambda iface: 0)
    res = lx.LinuxForwarding().preflight("eth0")
    assert res.ok is True
    assert res.blocked is False
    names = [c[0].lower() for c in res.checks]
    assert any("forward" in n for n in names)
    # the forward-policy check is not a hard pass when unknown
    forward_check = next(c for c in res.checks if "forward" in c[0].lower())
    assert forward_check[1] is None  # tri-state: unverified


def test_strict_rp_filter_is_surfaced_but_not_blocking(monkeypatch):
    monkeypatch.setattr(lx, "_forward_policy", lambda: "accept")
    monkeypatch.setattr(lx, "_rp_filter_effective", lambda iface: 1)
    res = lx.LinuxForwarding().preflight("eth0")
    assert res.ok is True          # rp_filter alone does not fail closed
    rp = next(c for c in res.checks if "reverse" in c[0].lower() or "rp_filter" in c[0].lower())
    assert rp[1] is False          # but it is flagged as a risk


class _BlockedForwarding:
    """A forwarding controller whose data-plane path is blocked."""
    def __init__(self):
        self.enabled = False

    def preflight(self, iface_name):
        from yaragon.platform.base import ForwardingPreflight
        return ForwardingPreflight(
            ok=False, blocked=True,
            reason="FORWARD policy is DROP - the target would be black-holed.",
            checks=[("FORWARD policy accepts relay", False, "DROP")])

    def enable(self):
        self.enabled = True
        return True

    def restore(self):
        self.enabled = False

    def current(self):
        return self.enabled


def test_mitm_start_refuses_when_forwarding_path_blocked():
    """start() must fail closed on a blocked forwarding path and never enable
    forwarding or spoof - the black-hole must be prevented, not created."""
    ctrl = MitmController(_BlockedForwarding(), manage_forwarding=True)
    with pytest.raises(RuntimeError) as exc:
        ctrl.start(_iface(), ["192.168.1.20"], "192.168.1.1",
                   gateway_mac="aa:aa:aa:aa:aa:aa")
    assert "black" in str(exc.value).lower() or "forward" in str(exc.value).lower()
    assert ctrl.active is False
    assert ctrl.forwarding.enabled is False
