"""Privilege / capture-backend checks (platform-neutral facade).

Delegates to the active platform adapter. Kept as a module so existing imports
(`from yaragon.utils.permissions import check_privileges`) keep working.
"""
from __future__ import annotations

from ..platform import PrivilegeStatus, get_platform

__all__ = ["PrivilegeStatus", "check_privileges"]


def check_privileges() -> PrivilegeStatus:
    return get_platform().check_privileges()
