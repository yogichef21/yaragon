"""Platform-neutral data models and the adapter contract.

These live in the lowest layer so every other layer can import them without a
circular dependency. ``network`` and ``utils`` re-export the models for
backwards compatibility.
"""
from __future__ import annotations

import ipaddress
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class InterfaceInfo:
    """A single network interface, described in OS-neutral terms."""
    name: str
    display_name: str = ""          # friendly name, e.g. "Wi-Fi"
    kind: str = "unknown"           # ethernet | wifi | loopback | virtual | unknown
    mac: str = ""
    ipv4: str = ""
    ipv6: str = ""
    netmask: str = ""
    mtu: Optional[int] = None
    is_up: bool = False
    is_loopback: bool = False

    @property
    def status(self) -> str:
        if self.is_loopback:
            return "loopback"
        return "up" if self.is_up else "down"

    @property
    def link_state(self) -> str:
        return "UP" if self.is_up else "DOWN"

    @property
    def cidr(self) -> str:
        if self.ipv4 and self.netmask:
            try:
                return str(ipaddress.IPv4Network(f"{self.ipv4}/{self.netmask}",
                                                 strict=False))
            except Exception:
                return ""
        return ""


@dataclass
class PrivilegeStatus:
    """Whether the process can open raw sockets for capture / lab MITM."""
    can_capture: bool
    is_elevated: bool
    detail: str
    backend: str = ""               # e.g. "libpcap"
    extra: Dict[str, str] = field(default_factory=dict)

    # Backwards-compatible aliases used elsewhere in the app.
    @property
    def is_root(self) -> bool:
        return self.is_elevated

    @property
    def has_cap_net_raw(self) -> bool:
        return self.extra.get("cap_net_raw") == "1"

    @property
    def in_wireshark_group(self) -> bool:
        return self.extra.get("wireshark_group") == "1"


@dataclass
class NetCapabilities:
    """What the current platform + privileges actually allow."""
    platform: str
    can_capture: bool
    can_mitm: bool
    backend_available: bool
    notes: List[str] = field(default_factory=list)


@dataclass
class ForwardingPreflight:
    """Result of checking whether the host will actually *relay* forwarded
    traffic - not just whether ``ip_forward`` is 1. ``blocked`` means a positive
    determination that the target would be black-holed (fail closed); ``ok`` is
    False only then. ``checks`` is a list of (name, passed, detail) where passed
    is True/False/None (None = could not verify)."""
    ok: bool = True
    blocked: bool = False
    reason: str = ""
    checks: List[tuple] = field(default_factory=list)


class ForwardingController(ABC):
    """Controls IP forwarding while an authorized lab MITM is active."""

    @abstractmethod
    def current(self) -> str: ...

    @abstractmethod
    def enable(self) -> bool: ...

    @abstractmethod
    def restore(self) -> bool:
        """Restore the original forwarding state. Return True on success; a
        False/None means the caller must NOT report a clean teardown."""

    def preflight(self, iface_name: str) -> ForwardingPreflight:
        """Check the data-plane forwarding path before poisoning. Default is a
        permissive 'unverified' result; platforms that can inspect the firewall
        (Linux) override this to fail closed on a DROP policy."""
        return ForwardingPreflight(ok=True, blocked=False)

    @property
    def supported(self) -> bool:
        return True


class NullForwarding(ForwardingController):
    """No-op controller for platforms without programmatic IP forwarding."""

    def current(self) -> str:
        return "unavailable"

    def enable(self) -> bool:
        return False

    def restore(self) -> bool:
        return True

    @property
    def supported(self) -> bool:
        return False


class PlatformAdapter(ABC):
    """OS-specific operations behind a single, testable interface."""

    name: str = "unknown"

    # ---- discovery -------------------------------------------------------
    @abstractmethod
    def list_interfaces(self) -> List[InterfaceInfo]: ...

    @abstractmethod
    def default_gateway(self) -> Optional[str]: ...

    @abstractmethod
    def default_interface(self) -> Optional[str]: ...

    @abstractmethod
    def neighbour_cache(self) -> Dict[str, str]: ...

    def get_interface(self, name: str) -> Optional[InterfaceInfo]:
        for iface in self.list_interfaces():
            if iface.name == name:
                return iface
        return None

    # ---- capture / privileges -------------------------------------------
    @abstractmethod
    def capture_backend_available(self) -> tuple[bool, str]:
        """Return (available, human message) for the capture backend."""

    @abstractmethod
    def check_privileges(self) -> PrivilegeStatus: ...

    # ---- lab MITM --------------------------------------------------------
    @abstractmethod
    def supports_mitm(self) -> bool: ...

    @abstractmethod
    def create_forwarding(self) -> ForwardingController: ...

    def mitm_unavailable_reason(self) -> str:
        return ("MITM requires Linux networking capabilities and is not "
                "available on this platform.")

    # ---- summary ---------------------------------------------------------
    def capabilities(self) -> NetCapabilities:
        priv = self.check_privileges()
        backend_ok, _ = self.capture_backend_available()
        notes: List[str] = []
        if not backend_ok:
            notes.append("Capture backend not available.")
        if not self.supports_mitm():
            notes.append(self.mitm_unavailable_reason())
        return NetCapabilities(
            platform=self.name,
            can_capture=priv.can_capture and backend_ok,
            can_mitm=self.supports_mitm() and priv.can_capture,
            backend_available=backend_ok,
            notes=notes,
        )
