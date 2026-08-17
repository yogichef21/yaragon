"""Linux platform adapter - full feature set (capture + lab MITM)."""
from __future__ import annotations

import ipaddress
import os
import shutil
import subprocess
from typing import Dict, List, Optional

from ..utils.logging import get_logger
from .base import (ForwardingController, ForwardingPreflight, InterfaceInfo,
                   PlatformAdapter, PrivilegeStatus)

log = get_logger("platform.linux")

IPV4_FWD = "/proc/sys/net/ipv4/ip_forward"
IPV6_FWD = "/proc/sys/net/ipv6/conf/all/forwarding"


def _run(cmd: List[str]) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=5).stdout
    except Exception:
        return ""


def _forward_policy() -> str:
    """Return the netfilter FORWARD chain default policy as 'accept' | 'drop' |
    'unknown'. 'unknown' is the honest answer when the tables can't be read
    (the normal cap_net_raw-only case) - we then warn rather than false-block.

    Reading iptables/nft usually needs privilege; a failure yields "" from _run
    and falls through to 'unknown'. No shell is used (argv only)."""
    # iptables front-end covers both the legacy and nft backends on modern
    # distros; its first -S line states the chain policy.
    out = _run(["iptables", "-S", "FORWARD"])
    for line in out.splitlines():
        if line.startswith("-P FORWARD "):
            verb = line.split()[2].upper()
            if verb == "ACCEPT":
                return "accept"
            if verb in ("DROP", "REJECT"):
                return "drop"
    # Pure-nftables hosts (no iptables shim): read the ruleset for a forward hook.
    nft = _run(["nft", "list", "ruleset"]).lower()
    if "hook forward" in nft:
        # Find the policy token that follows the forward hook declaration.
        idx = nft.find("hook forward")
        window = nft[idx:idx + 200]
        if "policy drop" in window:
            return "drop"
        if "policy accept" in window:
            return "accept"
    return "unknown"


def _rp_filter_effective(iface: str) -> Optional[int]:
    """Effective reverse-path filter for *iface*: the kernel uses max(all, iface).
    0 = off, 1 = strict, 2 = loose. Returns None if it can't be read (these
    /proc/sys files are world-readable, so that is rare)."""
    def _read_int(path: str) -> Optional[int]:
        try:
            with open(path) as fh:
                return int(fh.read().strip())
        except Exception:
            return None
    all_rp = _read_int("/proc/sys/net/ipv4/conf/all/rp_filter")
    if_rp = _read_int(f"/proc/sys/net/ipv4/conf/{iface}/rp_filter")
    vals = [v for v in (all_rp, if_rp) if v is not None]
    return max(vals) if vals else None


class LinuxForwarding(ForwardingController):
    """Enable IP forwarding for a lab MITM and always restore the original."""

    def __init__(self) -> None:
        self._orig_v4: Optional[str] = None
        self._orig_v6: Optional[str] = None
        self._changed_v4 = False
        self._changed_v6 = False

    @staticmethod
    def _read(path: str) -> Optional[str]:
        try:
            with open(path) as fh:
                return fh.read().strip()
        except Exception:
            return None

    @staticmethod
    def _direct_write(path: str, value: str) -> bool:
        try:
            with open(path, "w") as fh:
                fh.write(value + "\n")
            return True
        except Exception:
            return False

    @staticmethod
    def _write(path: str, value: str) -> bool:
        # 1) Direct write - succeeds as root, or if the sysctl is already writable.
        if LinuxForwarding._direct_write(path, value):
            return True
        # 2) Yaragon runs with CAP_NET_RAW only (no CAP_NET_ADMIN), so it cannot
        #    write a sysctl itself. Escalate transiently for this one toggle:
        #    prefer pkexec (graphical polkit prompt), fall back to non-interactive
        #    sudo. This keeps net-admin OUT of the long-lived interpreter.
        key = "net.ipv4.ip_forward" if "ipv4" in path else "net.ipv6.conf.all.forwarding"
        for launcher in (["pkexec"], ["sudo", "-n"]):
            if shutil.which(launcher[0]) is None:
                continue
            try:
                subprocess.run(launcher + ["sysctl", "-w", f"{key}={value}"],
                               capture_output=True, timeout=30, check=True)
                return True
            except Exception as exc:
                log.debug("%s sysctl failed: %s", launcher[0], exc)
        log.warning("Could not set %s=%s (needs a one-time privilege grant)", path, value)
        return False

    def current(self) -> str:
        return "enabled" if self._read(IPV4_FWD) == "1" else "disabled"

    def enable(self) -> bool:
        self._orig_v4 = self._read(IPV4_FWD)
        self._orig_v6 = self._read(IPV6_FWD)
        # Fail closed: the MITM relies on a verified IPv4 relay. If forwarding
        # state cannot even be read, refuse - poisoning ARP without a confirmed
        # relay would black-hole the target's traffic (a DoS) instead of
        # forwarding it transparently.
        if self._orig_v4 is None:
            return False
        if self._orig_v4 != "1":
            if not self._write(IPV4_FWD, "1"):
                return False
            self._changed_v4 = True
            # Re-read and require the value actually took effect; a silent
            # no-op write must not be reported as success.
            if self._read(IPV4_FWD) != "1":
                return False
        # IPv6 forwarding is best-effort - the IPv4 relay is the safety contract.
        if self._orig_v6 is not None and self._orig_v6 != "1":
            if self._write(IPV6_FWD, "1"):
                self._changed_v6 = True
        return True

    def restore(self) -> bool:
        """Restore the original forwarding sysctls. Returns True only if every
        needed write succeeded; on failure the changed-flag is kept so a later
        restore (e.g. atexit) retries, and the caller reports the failure rather
        than claiming the host was cleaned up."""
        ok = True
        if self._changed_v4 and self._orig_v4 is not None:
            if self._write(IPV4_FWD, self._orig_v4):
                self._changed_v4 = False
                log.info("Restored IPv4 forwarding to %s", self._orig_v4)
            else:
                ok = False
                log.warning("Failed to restore IPv4 forwarding to %s (host may "
                            "still be forwarding)", self._orig_v4)
        if self._changed_v6 and self._orig_v6 is not None:
            if self._write(IPV6_FWD, self._orig_v6):
                self._changed_v6 = False
            else:
                ok = False
        return ok

    def preflight(self, iface_name: str) -> ForwardingPreflight:
        """Check that forwarded traffic will actually be *relayed*, not dropped.
        Enabling ``ip_forward`` is necessary but not sufficient: a netfilter
        FORWARD policy of DROP (ufw / firewalld / a Docker host) black-holes the
        target. We fail closed only on a positive DROP finding; an unreadable
        policy is surfaced as unverified, never a false block. Yaragon makes NO
        firewall changes - it only detects and reports."""
        policy = _forward_policy()
        rp = _rp_filter_effective(iface_name)

        checks = []
        forward_passed = {"accept": True, "drop": False}.get(policy)  # None if unknown
        checks.append((
            "FORWARD policy relays traffic", forward_passed,
            {"accept": "ACCEPT", "drop": "DROP/REJECT"}.get(policy, "could not read (needs privilege)")))

        if rp is None:
            rp_passed = None
            rp_detail = "could not read"
        elif rp == 1:
            rp_passed = False
            rp_detail = "strict (1) - may drop asymmetrically-routed relayed traffic"
        else:
            rp_passed = True
            rp_detail = {0: "off (0)", 2: "loose (2)"}.get(rp, str(rp))
        checks.append(("Reverse-path filter (rp_filter) not strict", rp_passed, rp_detail))

        blocked = policy == "drop"
        reason = ""
        if blocked:
            reason = ("The netfilter FORWARD policy is DROP - forwarded traffic "
                      "would be black-holed instead of relayed. Allow forwarding "
                      "for the target and gateway (e.g. a FORWARD ACCEPT rule) or "
                      "turn off IP-forwarding management, then retry.")
        return ForwardingPreflight(ok=not blocked, blocked=blocked,
                                   reason=reason, checks=checks)


class LinuxAdapter(PlatformAdapter):
    name = "Linux"

    # ---- discovery -------------------------------------------------------
    def list_interfaces(self) -> List[InterfaceInfo]:
        from scapy.all import get_if_addr, get_if_hwaddr
        from scapy.arch import get_if_list

        out: List[InterfaceInfo] = []
        for name in get_if_list():
            info = InterfaceInfo(name=name)
            info.is_loopback = name.startswith("lo")
            info.kind = self._kind(name)
            info.display_name = self._friendly(name, info.kind)
            try:
                info.mac = get_if_hwaddr(name)
            except Exception:
                info.mac = ""
            try:
                ip = get_if_addr(name)
                if ip and ip != "0.0.0.0":
                    info.ipv4 = ip
            except Exception:
                pass
            info.netmask = self._netmask(name)
            info.ipv6 = self._ipv6(name)
            info.mtu = self._mtu(name)
            info.is_up = self._is_up(name)
            out.append(info)
        return out

    def _kind(self, name: str) -> str:
        if name.startswith("lo"):
            return "loopback"
        if os.path.isdir(f"/sys/class/net/{name}/wireless"):
            return "wifi"
        if any(name.startswith(p) for p in ("docker", "br-", "veth", "virbr",
                                            "vmnet", "tun", "tap", "bond")):
            return "virtual"
        if name.startswith(("en", "eth", "enp", "eno", "ens", "enx")):
            return "ethernet"
        return "unknown"

    @staticmethod
    def _friendly(name: str, kind: str) -> str:
        return {"wifi": "Wi-Fi", "ethernet": "Ethernet", "loopback": "Loopback",
                "virtual": "Virtual"}.get(kind, name)

    @staticmethod
    def _is_up(name: str) -> bool:
        try:
            with open(f"/sys/class/net/{name}/operstate") as fh:
                state = fh.read().strip()
            return state in ("up", "unknown") or name.startswith("lo")
        except Exception:
            return False

    @staticmethod
    def _mtu(name: str) -> Optional[int]:
        try:
            with open(f"/sys/class/net/{name}/mtu") as fh:
                return int(fh.read().strip())
        except Exception:
            return None

    @staticmethod
    def _netmask(name: str) -> str:
        out = _run(["ip", "-o", "-f", "inet", "addr", "show", name])
        for token in out.split():
            if "/" in token and token.count(".") == 3:
                try:
                    prefix = int(token.split("/")[1])
                    return str(ipaddress.IPv4Network(f"0.0.0.0/{prefix}").netmask)
                except Exception:
                    pass
        return ""

    @staticmethod
    def _ipv6(name: str) -> str:
        out = _run(["ip", "-o", "-f", "inet6", "addr", "show", name])
        fallback = ""
        for line in out.splitlines():
            parts = line.split()
            for i, tok in enumerate(parts):
                if tok == "inet6" and i + 1 < len(parts):
                    addr = parts[i + 1].split("/")[0]
                    if not addr.startswith("fe80"):
                        return addr
                    fallback = fallback or addr
        return fallback

    def default_gateway(self) -> Optional[str]:
        try:
            from scapy.all import conf
            gw = conf.route.route("0.0.0.0")[2]
            if gw and gw != "0.0.0.0":
                return gw
        except Exception:
            pass
        out = _run(["ip", "route", "show", "default"])
        for line in out.splitlines():
            parts = line.split()
            if "via" in parts:
                return parts[parts.index("via") + 1]
        return None

    def default_interface(self) -> Optional[str]:
        out = _run(["ip", "route", "show", "default"])
        for line in out.splitlines():
            parts = line.split()
            if "dev" in parts:
                return parts[parts.index("dev") + 1]
        for iface in self.list_interfaces():
            if not iface.is_loopback and iface.ipv4 and iface.is_up:
                return iface.name
        return None

    def neighbour_cache(self) -> Dict[str, str]:
        out: Dict[str, str] = {}
        res = _run(["ip", "neigh"])
        for line in res.splitlines():
            parts = line.split()
            if len(parts) >= 5 and parts[3] == "lladdr":
                out[parts[0]] = parts[4]
        return out

    # ---- capture / privileges -------------------------------------------
    def capture_backend_available(self) -> tuple[bool, str]:
        # scapy on Linux uses AF_PACKET / libpcap; a successful import is enough.
        import importlib.util
        if importlib.util.find_spec("scapy") is not None:
            return True, "libpcap / AF_PACKET"
        return False, "scapy is not installed - packet capture is unavailable."

    def check_privileges(self) -> PrivilegeStatus:
        is_root = os.geteuid() == 0 if hasattr(os, "geteuid") else False
        cap_raw = self._has_cap_net_raw()
        in_ws = self._in_group("wireshark")
        can = is_root or cap_raw
        if is_root:
            detail = "Running as root - capture and MITM available."
        elif cap_raw:
            detail = "CAP_NET_RAW present - capture available without root."
        else:
            detail = ("No raw-socket privileges. Capture/MITM need sudo or "
                      "CAP_NET_RAW (see README > Permissions).")
        return PrivilegeStatus(
            can_capture=can, is_elevated=is_root, detail=detail,
            backend="libpcap / AF_PACKET",
            extra={"cap_net_raw": "1" if cap_raw else "0",
                   "wireshark_group": "1" if in_ws else "0"},
        )

    @staticmethod
    def _has_cap_net_raw() -> bool:
        try:
            with open("/proc/self/status") as fh:
                for line in fh:
                    if line.startswith("CapEff:"):
                        eff = int(line.split()[1], 16)
                        return bool(eff & (1 << 13))  # CAP_NET_RAW = 13
        except Exception:
            return False
        return False

    @staticmethod
    def _in_group(group: str) -> bool:
        try:
            import grp
            return grp.getgrnam(group).gr_gid in os.getgroups()
        except Exception:
            return False

    # ---- lab MITM --------------------------------------------------------
    def supports_mitm(self) -> bool:
        return True

    def create_forwarding(self) -> ForwardingController:
        return LinuxForwarding()
