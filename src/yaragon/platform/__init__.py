"""Platform abstraction layer.

Yaragon is a Linux-only tool that runs across Linux distributions. Every
OS-specific operation - interface discovery, gateway lookup,
capture-backend/permission checks, IP forwarding - lives behind
:class:`~yaragon.platform.base.PlatformAdapter` so the network, analysis and GUI
layers never call OS commands directly.

Use :func:`get_platform` to obtain the singleton adapter.
"""
from __future__ import annotations

from .base import (ForwardingController, InterfaceInfo, NetCapabilities,
                   NullForwarding, PlatformAdapter, PrivilegeStatus)

_adapter: PlatformAdapter | None = None


def get_platform() -> PlatformAdapter:
    """Return the cached :class:`PlatformAdapter` for Linux."""
    global _adapter
    if _adapter is None:
        from .linux import LinuxAdapter
        _adapter = LinuxAdapter()
    return _adapter


__all__ = [
    "get_platform", "PlatformAdapter", "InterfaceInfo", "PrivilegeStatus",
    "NetCapabilities", "ForwardingController", "NullForwarding",
]
