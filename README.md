# Yaragon

**Yaragon is a Linux-native offensive security tool for authorized
man-in-the-middle (MITM) network investigation.** It walks one coherent
workflow end to end - **Discover → Select → Intercept → Investigate** - so you
can place yourself between a target and its gateway, watch the traffic on the
wire, investigate it packet by packet, and hand off a clean `.pcap`. Built with
Python, PySide6 and Scapy; capture runs on a background thread so the interface
stays responsive.

It is built for controlled, authorized security testing, lab, and education
environments, not for attacking networks you do not own or are not permitted to
test.

## Safety posture

Yaragon is deliberately built so it **cannot be turned into a credential
stealer**:

- **No TLS decryption** - encrypted payloads are labelled and left alone.
- **No credential harvesting** - the curated Decoded view drops
  `Authorization`/`Cookie` headers and shows only the query-free request path.
- **No on-disk persistence by default** - packets live in a bounded in-memory
  buffer; you export a `.pcap` deliberately when you want to keep a capture.
- **ARP is always restored** - on stop, on exit, and even on abnormal
  termination; and MITM **refuses to start** unless IP forwarding is verified,
  so a test can never silently black-hole its target.

The full plaintext on the wire is still visible in the Hex/ASCII/Raw views and
in any exported `.pcap`, exactly as with Wireshark or tcpdump - Yaragon adds no
new exposure, it just declines to build a harvesting workflow on top.

## Features

- Host discovery (IP, MAC, hostname, role) on the selected interface
- A passive **Capture only** on-ramp - watch your own traffic with no MITM
- Authorized ARP MITM that forwards traffic transparently and restores ARP,
  and reports plainly if fewer targets resolved than were selected
- Live packet table with one-click protocol filters, Source/Destination IP
  filters, free-text/port search, relative-time column, and sequential
  packet numbering
- Right-click to pivot (filter by source/destination IP or port) and copy
- State-driven capture controls - Start, Pause, Stop, with Clear and Export
  contextual to captured data - plus an optional capture-time BPF filter;
  pausing or stopping never discards packets
- Packet inspector: decoded fields grouped by OSI layer, plus Hex/ASCII/Raw,
  faithful to the captured bytes
- Protocol decoding for ARP, IPv4/IPv6, TCP, UDP, ICMP/ICMPv6, DNS, DHCP
  (including host name and vendor class), HTTP and TLS metadata
- Export the capture - all packets or just the filtered subset - to a standard
  `.pcap`, and **open a saved `.pcap`** for offline inspection (no root needed)

## Requirements

- Linux (any distribution)
- Python 3.10+
- `libpcap` for capture (installed by `install.sh`)

## Installation

```bash
git clone https://github.com/yogichef21/yaragon yaragon
cd yaragon
./install.sh
```

Docker: see [docs/docker.md](docs/docker.md).

## Usage

```bash
./run.sh
```

The app starts directly - there is no privilege menu. `install.sh` grants the
app's interpreter only `CAP_NET_RAW` (via `setcap`) so capture and ARP work
without running the GUI as root. The one admin action MITM needs, toggling
`net.ipv4.ip_forward`, is requested transiently at MITM start through a
polkit/sudo prompt rather than baked into the interpreter. If capture privileges
are missing, the app still opens and explains how to enable them.

Workflow:

1. **Discover** - pick an interface, discover hosts, select one or more targets.
2. **MITM** - review the target/gateway, then start the lab (with confirmation).
   Capture starts automatically with the session.
3. **Investigate** - watch packets flow through Yaragon; filter by protocol,
   Source/Destination IP or port and follow a conversation; control capture with
   Start / Pause / Stop (with Clear and Export available once there are packets);
   click a packet to inspect its layers and bytes; export the capture to `.pcap`.

## MITM Lab

MITM uses ARP to place Yaragon between the target and the gateway, forwards
traffic transparently, and restores ARP and IP forwarding when stopped, on exit,
and even on abnormal termination (via an `atexit` safeguard) so the LAN is never
left poisoned. If IP forwarding cannot be enabled, Yaragon refuses to start
rather than black-hole the target's traffic.

Use it only on networks and hosts you own or are authorized to test. Yaragon
does not decrypt TLS, harvest credentials, or hide its activity.

## Development

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements-dev.txt
python -m pytest
python main.py
```

Layout: `src/yaragon/` (`platform`, `network`, `analysis`, `storage`, `gui`,
`utils`), `tests/`, `docs/`.

## Security

External commands use argument lists (no shell). Capture uses the minimum
capability (`CAP_NET_RAW` on the venv interpreter) rather than root;
`CAP_NET_ADMIN` is never granted to the interpreter, so a compromised dependency
cannot reconfigure host networking. IP forwarding for MITM is toggled through a
one-time polkit/sudo prompt at session start and restored on stop. HTTP parsing
ignores `Authorization` and `Cookie` headers.

Yaragon does not persist captures to disk. Raw frame bytes are kept **in memory**
for the inspector's Hex/ASCII/Raw views and are included only when you explicitly
export a `.pcap` (that file therefore contains full plaintext frames, exactly
like a Wireshark capture - handle it accordingly).

## License

MIT. See [LICENSE](LICENSE).
