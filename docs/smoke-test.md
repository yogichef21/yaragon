# Yaragon release smoke test (on hardware)

This is the manual end-to-end validation to run on a real Linux host before
tagging a release. It covers the one thing the automated suite cannot: the live
`Discover -> Select -> Intercept -> Investigate -> Export` workflow on a real
network interface. Run it only on a network you own or are authorized to test.

## Preconditions
- A Linux host with a wired or wireless interface and at least one other device
  on the same subnet (the target) plus a reachable gateway.
- A display (the GUI needs X11 or XWayland).
- `polkit` (`pkexec`) or `sudo` available, for the one-time IP-forwarding grant.

## Setup
```bash
git clone https://github.com/yogichef21/yaragon yaragon
cd yaragon
./install.sh                 # installs deps, grants CAP_NET_RAW to the venv python
.venv/bin/python main.py --check   # headless: interfaces, gateway, privileges
./run.sh                     # launch the GUI
```
`--check` should list interfaces, the default gateway, and report
`CAP_NET_RAW present`.

## Workflow checks
1. **Title bar** shows exactly `Yaragon v1.0.0 - Offensive Security MITM Tool`
   (one clean string, no duplication).
2. **Stage rail** reads `DISCOVER  MITM  INVESTIGATE` with thin connector lines
   (the MITM link dashed), DISCOVER current, the others locked. No text dashes.
3. **Discover**: pick the interface, press `Discover Hosts`. Hosts appear with
   IP / MAC / Hostname / Status / Role. Empty cells show a dim centered `-`.
   The host list fills the panel and scrolls; no rows are clipped. `Details`
   reveals the interface table without clipping a row.
4. **Select**: tick a target (not the gateway). `Continue` becomes primary.
5. **Intercept**: on the MITM screen, `Validate` runs without freezing the UI
   (even with several/unreachable targets). `Start MITM` prompts once for the
   IP-forwarding grant (polkit/sudo), then the status pill shows the session is
   active and traffic begins to flow.
6. **Investigate**: packets stream into the table with monotonic numbers and a
   relative `Time (s)` column. Test protocol chips, the IP/port search, and
   right-click `Follow conversation`. Select a packet and confirm the inspector
   fields match (Decoded + Hex). `Pause`/`Resume`/`Stop` behave per the state
   machine; `Stop` does not freeze the UI.
7. **Export**: `Export .pcap`, then open the file in Wireshark or `tcpdump -r`.
   Confirm the packets, addresses, ports, and timestamps match what Yaragon
   showed.
8. **Cleanup**: after `Stop` and on quit, confirm ARP is restored on the target
   and `cat /proc/sys/net/ipv4/ip_forward` returns to its original value.

## Light / dark
Toggle the desktop theme (or set it explicitly) and confirm both render legibly:
text contrast, the amber accent on exactly one primary action per screen, and
the live/paused/stopped states.

## Pass criteria
Every step above behaves as described, Wireshark opens the export cleanly, and
the host's ARP + forwarding state is left as it was found.
