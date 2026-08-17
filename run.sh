#!/usr/bin/env bash
#
# Start Yaragon.
#
#   ./run.sh            launch the GUI
#   ./run.sh --check    headless self-check (no display / privileges needed)
#
# Privileges are handled automatically. Packet capture needs CAP_NET_RAW; if the
# venv interpreter doesn't have it yet, Yaragon tries to grant it once (via the
# desktop's polkit prompt, or sudo if available) and then starts as a normal
# user. If that isn't possible, the GUI still opens and explains what to do -
# there is no privilege menu to navigate.
#
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

VENV_PY="$HERE/.venv/bin/python"
if [ ! -x "$VENV_PY" ]; then
    echo "Yaragon is not installed. Run ./install.sh first." >&2
    exit 1
fi

# Headless flags never need privileges.
case "${1:-}" in
    --check|--version) exec "$VENV_PY" main.py "$1" ;;
esac

have_caps() {
    getcap "$(readlink -f "$VENV_PY")" 2>/dev/null | grep -q cap_net_raw
}

# Acquire capture capabilities once, non-interactively where possible. Any
# failure is non-fatal: Yaragon opens and shows guidance in the GUI.
if [ "$(id -u)" -ne 0 ] && ! have_caps; then
    if command -v pkexec >/dev/null 2>&1 && [ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]; then
        pkexec "$HERE/scripts/setcaps.sh" >/dev/null 2>&1 || true
    elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
        sudo -n "$HERE/scripts/setcaps.sh" >/dev/null 2>&1 || true
    fi
fi

exec "$VENV_PY" main.py
