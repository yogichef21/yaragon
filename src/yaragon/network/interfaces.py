"""Network interface discovery - thin, platform-neutral facade.

The real work lives in the platform adapter (:mod:`yaragon.platform`). This
module keeps the historical function API used across the app and tests while
delegating every OS-specific detail to the Linux adapter.
"""
from __future__ import annotations

from typing import List, Optional

from ..platform import InterfaceInfo, get_platform

__all__ = ["InterfaceInfo", "list_interfaces", "default_gateway",
           "default_interface", "get_interface"]


def list_interfaces() -> List[InterfaceInfo]:
    return get_platform().list_interfaces()


def default_gateway() -> Optional[str]:
    return get_platform().default_gateway()


def default_interface() -> Optional[str]:
    return get_platform().default_interface()


def get_interface(name: str) -> Optional[InterfaceInfo]:
    return get_platform().get_interface(name)
