# Yaragon

**Offensive Security MITM Investigation Tool** - a precision instrument for
authorized network investigation.

Website: https://yaragon.com

**Yaragon is a Linux-native offensive-security tool for authorized
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
- **ARP is always restored** - on stop, on exit, and on termination signals
  (SIGINT/SIGTERM/SIGHUP - a kill, logout, or closed terminal), not only on a
  clean quit. (A `SIGKILL` or power loss cannot be caught by any program; the
  short ARP re-assert interval lets a victim recover once the poisoner is gone.)
- **Never black-holes the target** - MITM refuses to start unless it can both
  enable IP forwarding *and* verify the host will actually relay the traffic
  (it checks the netfilter FORWARD policy and rp_filter, and fails closed on a
  DROP policy rather than cutting the target off). Yaragon makes no firewall
  changes itself - it only detects and reports.
- **Honest live state** - the session readout reflects the real backend: if the
  spoof thread dies or cleanup fails, that is shown, never hidden behind a
  cheerful "active".

The full plaintext on the wire is still visible in the Hex view, in **Follow
Stream** (the reassembled transcript, exactly like Wireshark's "Follow Stream"),
and in any exported `.pcap` - Yaragon adds no new exposure, it just declines to
build a harvesting workflow on top. The credential-free curation is a property of
the **Decoded** view specifically; the raw bytes on the wire are shown honestly
elsewhere, as any analyzer does.

## Features

- Host discovery (IP, MAC, hostname, role) on the selected interface
- A passive **Capture only** on-ramp - watch your own traffic with no MITM
- Authorized ARP MITM that forwards traffic transparently and restores ARP,
  and reports plainly if fewer targets resolved than were selected
- Live, **sortable** packet table with **multi-select** protocol filters (view
  TCP + TLS + DNS at once), Source/Destination IP filters, free-text/port
  search, a live match count, relative-time column, and sequential numbering.
  Search/filter run over the **full capture history**, not just the visible rows
- Right-click to pivot (filter by source/destination IP or port), copy, follow a
  conversation, follow the reassembled stream, or open target intelligence
- **Conversations** - triage a noisy capture as ranked endpoint-pair flows
  (packets, bytes, protocols, ports, duration); open one to follow it
- **Follow Stream** - the reassembled two-colour transcript of one conversation
  (TLS/encrypted spans are labelled, never decrypted)
- **Target Intelligence** - a per-host rollup of what was observed: names
  resolved (DNS), servers contacted (TLS SNI / HTTP Host), User-Agents, DHCP
  identity, protocols and top peers - all from already-parsed metadata
- Keyboard-driven investigation: `/` focus search, `Esc` clear filters, `F`
  follow the selected conversation, `1`-`8` toggle protocol chips, `Ctrl+O` open,
  `Ctrl+E` export (shortcuts never fire while you're typing in a field)
- State-driven capture controls - Start, Pause, Stop, with Clear and Export
  contextual to captured data - plus an optional capture-time BPF filter;
  pausing or stopping never discards packets
- Packet inspector: decoded fields grouped by OSI layer, plus Hex, faithful to
  the captured bytes (built on demand, so a large history stays light)
- Protocol decoding for ARP, IPv4/IPv6, TCP, UDP, ICMP/ICMPv6, DNS, DHCP
  (including host name and vendor class), HTTP and TLS metadata
- **A bundled sample capture** (`Load sample capture`) so a new user can explore
  the inspector, search, conversations and follow-stream on first run with no
  live MITM - clearly labelled as synthetic sample data
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
3. **Investigate** - watch packets flow through Yaragon; filter by protocol
   (multi-select), Source/Destination IP or port, sort any column, and follow a
   conversation or its reassembled stream; open **Conversations** to triage flows
   or **Target intelligence** to profile a host; control capture with Start /
   Pause / Stop (with Clear and Export available once there are packets); click a
   packet to inspect its layers and bytes; export the capture to `.pcap`.

No lab yet? Choose **Load sample capture** on the Investigate screen (or File →
Load sample capture) to explore everything above on bundled synthetic data.

## MITM Lab

MITM uses ARP to place Yaragon between the target and the gateway, forwards
traffic transparently, and restores ARP and IP forwarding when stopped, on a
clean exit, and on the common termination signals (SIGINT/SIGTERM/SIGHUP) via a
Qt-safe handler, with an `atexit` safeguard as a backstop, so the LAN is not left
poisoned. A `SIGKILL` or power loss cannot be caught by any program; the short
ARP re-assert interval lets a victim recover once the poisoner is gone.

Before poisoning, Yaragon verifies it can actually relay the traffic: it requires
IP forwarding and checks the netfilter FORWARD policy and rp_filter. If the relay
would be dropped, it refuses to start rather than black-hole the target. It makes
no firewall changes itself.

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
for the inspector's Hex view and Follow Stream, and are included only when you
explicitly export a `.pcap` (that file therefore contains full plaintext frames,
exactly like a Wireshark capture - handle it accordingly).

## Project status

Yaragon 1.0.0. Linux-only. The Discover -> Select -> Intercept -> Investigate
workflow, the safety behavior described above, and the investigation tools
(Conversations, Follow Stream, Target Intelligence) are implemented and covered
by an automated test suite. Live ARP MITM must be exercised on a network you are
authorized to test; the automated tests cover everything that can be verified
without a live victim.

## Contributing

Yaragon is source-available (see License below), not open source. Issue reports
and small, focused pull requests are welcome, but please open an issue to discuss
before larger changes. Contributions are accepted under the project's license,
and the Yaragon name and logo are not licensed for use in other products or
distributions.

## License

Yaragon is **source-available**, under the Yaragon Source-Available License 1.0 -
see [LICENSE](LICENSE). This is not an Open Source (OSI) license and not the MIT
License. In short: you may read, study, and use Yaragon for personal, educational,
research, and authorized security-testing purposes; commercial redistribution or
selling Yaragon (or a substantially modified derivative) requires permission, and
the Yaragon name and logo are not licensed. Third-party dependencies keep their
own licenses. The license is project-specific and should be reviewed by legal
counsel before commercial use.
