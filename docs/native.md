# Yaragon - Native Linux setup

Yaragon runs on any Linux distribution with Python 3.10+ (3.12 recommended).

## 1. Install

```bash
git clone https://github.com/yogichef21/yaragon yaragon
cd yaragon
./install.sh
```

`install.sh` detects your package manager (`apt`, `dnf`, `pacman` or `zypper`)
and installs the system packages Yaragon needs:

- Python 3 with `venv` and `pip`
- `libpcap` - capture backend for scapy
- `iproute2` - the `ip` tool for interface/gateway discovery
- `setcap` (from `libcap`) - to grant capture capabilities
- the Qt **xcb** runtime libraries required by PySide6

…then creates `./.venv` and installs `requirements.txt`.

If you prefer to install the system packages by hand, use your distribution's
package manager. For example:

```bash
# Debian / Ubuntu family
sudo apt-get install -y python3 python3-venv python3-pip libpcap0.8 iproute2 \
  libcap2-bin libgl1 libegl1 libxkbcommon0 libxcb-cursor0 libfontconfig1

# Fedora / RHEL family
sudo dnf install -y python3 python3-pip libpcap iproute libcap mesa-libGL \
  libxkbcommon xcb-util-cursor fontconfig

# Arch family
sudo pacman -S --needed python python-pip libpcap iproute2 libcap qt6-base \
  xcb-util-cursor libxkbcommon-x11 fontconfig
```

Then create the environment:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

## 2. Capture privileges

`install.sh` grants the venv interpreter the minimum capabilities for capture
(`CAP_NET_RAW` only) via `scripts/setcaps.sh`, so you don't run the
GUI as root. To (re)apply it manually:

```bash
sudo ./scripts/setcaps.sh
```

## 3. Run

```bash
./run.sh
```

or directly:

```bash
.venv/bin/python main.py
```

## 4. Typical workflow

1. **Discover** - pick an interface, discover hosts, select one or more targets.
2. **MITM** - review the target and gateway, then start the authorized lab
   session (with confirmation). Capture starts automatically with the session.
3. **Investigate** - watch packets flow through Yaragon; filter by protocol,
   Source/Destination IP or port and follow a conversation; control capture with
   **Start / Pause / Stop** (Clear and Export appear once there are packets);
   click a packet to inspect its OSI layers and bytes; export to a `.pcap` file.

You can also use the **Capture only** action on Discover to start a passive
capture on the interface, without running a MITM session.

## Notes

- The default sysctl for `net.ipv4.ip_forward` is `0` on most distributions;
  Yaragon enables it only if needed and restores the original value on MITM
  stop / app exit.
- If a host firewall is active, ensure it does not drop forwarded lab traffic.
  In an isolated authorized lab the firewall is usually disabled.
- Confined/sandboxed Python builds are not recommended; use the system
  `python3`.
