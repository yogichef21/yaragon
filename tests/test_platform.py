"""Platform abstraction tests (models + adapter contract + factory).

Yaragon is Linux-only, so the adapter is always the Linux one.
"""
from yaragon.platform import get_platform
from yaragon.platform.base import (InterfaceInfo, NetCapabilities, NullForwarding,
                                    PrivilegeStatus)


def test_factory_returns_linux_adapter():
    p = get_platform()
    assert p.name == "Linux"


def test_factory_is_cached():
    assert get_platform() is get_platform()


def test_interface_info_derived_fields():
    i = InterfaceInfo(name="eth0", ipv4="192.168.1.10", netmask="255.255.255.0",
                      is_up=True)
    assert i.link_state == "UP"
    assert i.status == "up"
    assert i.cidr == "192.168.1.0/24"
    down = InterfaceInfo(name="eth1", is_up=False)
    assert down.link_state == "DOWN" and down.cidr == ""


def test_privilege_status_aliases():
    s = PrivilegeStatus(can_capture=True, is_elevated=True, detail="ok",
                        extra={"cap_net_raw": "1", "wireshark_group": "1"})
    assert s.is_root is True
    assert s.has_cap_net_raw is True
    assert s.in_wireshark_group is True


def test_null_forwarding_is_unsupported():
    f = NullForwarding()
    assert f.supported is False
    assert f.current() == "unavailable"
    assert f.enable() is False
    f.restore()  # no-op, must not raise


def test_capabilities_shape():
    caps = get_platform().capabilities()
    assert isinstance(caps, NetCapabilities)
    assert caps.platform == "Linux"
    assert isinstance(caps.can_capture, bool)
    assert isinstance(caps.can_mitm, bool)
    assert isinstance(caps.notes, list)


def test_adapter_discovery_methods_do_not_raise():
    p = get_platform()
    ifaces = p.list_interfaces()
    assert isinstance(ifaces, list)
    # gateway/default interface may be None in odd environments, but must not raise
    p.default_gateway()
    p.default_interface()
    assert isinstance(p.neighbour_cache(), dict)


def test_linux_supports_mitm():
    p = get_platform()
    assert p.supports_mitm() is True
    assert p.create_forwarding().supported is True


def test_forwarding_fails_closed_when_unreadable():
    """SEC-1: if IPv4 forwarding state cannot be read, enable() must refuse so
    the MITM never poisons ARP without a verified relay."""
    from yaragon.platform.linux import LinuxForwarding

    class F(LinuxForwarding):
        @staticmethod
        def _read(path):
            return None

    assert F().enable() is False


def test_forwarding_fails_when_write_not_applied():
    """SEC-1: a write that appears to succeed but does not actually flip the
    flag (re-read still '0') must be treated as failure."""
    from yaragon.platform.linux import LinuxForwarding

    class F(LinuxForwarding):
        @staticmethod
        def _read(path):
            return "0"          # never becomes "1", even after a "successful" write

        @staticmethod
        def _write(path, value):
            return True         # pretend the write succeeded

    assert F().enable() is False


def test_forwarding_enables_when_readable_and_applied():
    """SEC-1: the normal readable + writable path returns True and records that
    it changed IPv4 forwarding (so restore() will put it back)."""
    from yaragon.platform.linux import IPV4_FWD, LinuxForwarding

    state = {}

    class F(LinuxForwarding):
        @staticmethod
        def _read(path):
            return state.get(path, "0")

        @staticmethod
        def _write(path, value):
            state[path] = value
            return True

    f = F()
    assert f.enable() is True
    assert f._changed_v4 is True
    assert state[IPV4_FWD] == "1"


def test_forwarding_escalates_when_unprivileged(monkeypatch):
    """Under CAP_NET_RAW only, a direct sysctl write fails, so _write must
    escalate via pkexec (preferred) to toggle ip_forward for MITM."""
    from yaragon.platform import linux
    from yaragon.platform.linux import IPV4_FWD, LinuxForwarding

    monkeypatch.setattr(LinuxForwarding, "_direct_write",
                        staticmethod(lambda path, value: False))
    monkeypatch.setattr(linux.shutil, "which", lambda name: "/usr/bin/" + name)
    calls = []

    class _Ok:
        returncode = 0

    def fake_run(cmd, **kw):
        calls.append(cmd)
        return _Ok()

    monkeypatch.setattr(linux.subprocess, "run", fake_run)
    assert LinuxForwarding._write(IPV4_FWD, "1") is True
    assert calls and calls[0][0] == "pkexec"          # prefers polkit over sudo
    assert "net.ipv4.ip_forward=1" in calls[0]


def test_forwarding_reports_failure_when_no_escalation(monkeypatch):
    """If neither a direct write nor any privilege helper works, _write reports
    failure so MITM fails closed rather than silently half-configuring."""
    from yaragon.platform import linux
    from yaragon.platform.linux import IPV4_FWD, LinuxForwarding

    monkeypatch.setattr(LinuxForwarding, "_direct_write",
                        staticmethod(lambda path, value: False))
    monkeypatch.setattr(linux.shutil, "which", lambda name: None)
    assert LinuxForwarding._write(IPV4_FWD, "1") is False
