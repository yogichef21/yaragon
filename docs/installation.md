# Yaragon - Installation

Yaragon is a **Linux-only** tool that runs across Linux distributions. Pick one
installation path:

1. **Native Linux** - see [`native.md`](native.md)
2. **Docker on Linux** - see [`docker.md`](docker.md)

Docker is **not** required; native installation is fully supported.

## Requirements

| Requirement | Native | Docker |
|---|---|---|
| Linux host (any distribution) | ✔ | ✔ |
| Python 3.10+ (3.12 recommended) | ✔ (installed by `install.sh`) | baked into image |
| X11 / XWayland display for the GUI | ✔ | ✔ (shared in) |
| Raw-socket privileges for capture/MITM | ✔ (sudo / setcap) | ✔ (`NET_RAW`/`NET_ADMIN`) |

## Native quick start

```bash
git clone https://github.com/yogichef21/yaragon yaragon
cd yaragon
./install.sh     # system packages (sudo) + .venv + Python deps + capture caps
./run.sh         # launch the GUI
```

`install.sh`:
- detects the distribution's package manager (`apt`, `dnf`, `pacman` or
  `zypper`),
- installs system packages with it (Python, venv, `libpcap`, `iproute2`,
  `setcap`, and the Qt **xcb** runtime libraries PySide6 needs),
- creates `./.venv` and installs `requirements.txt` into it,
- grants the venv interpreter `CAP_NET_RAW` (via `setcap`) so capture works
  without running the GUI as root (IP forwarding for MITM is granted transiently
  via a polkit/sudo prompt at session start, not baked into the interpreter).

`run.sh` simply starts the app - no privilege menu. If capture capabilities are
missing it tries to grant them once (polkit/sudo) and otherwise opens the GUI,
which explains how to enable capture.

## Headless self-check (no display)

```bash
.venv/bin/python main.py --check
```

Prints the app version, the interfaces Yaragon discovered, the default gateway,
and the current privilege status. Useful for CI or verifying an install on a
server.

## Verifying the install with tests

```bash
.venv/bin/python -m pytest tests/ -q
```

## Uninstalling

Yaragon is self-contained. Remove the clone and the venv:

```bash
rm -rf yaragon          # the project directory (includes .venv)
```

If you granted capabilities to a system Python instead of the venv, clear them:

```bash
sudo setcap -r "$(readlink -f .venv/bin/python)"   # before deleting, if desired
```

Runtime config/logs/database live under `~/.config/yaragon` and
`~/.local/share/yaragon`; delete those to remove all traces.
