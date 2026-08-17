#!/usr/bin/env bash
#
# Grant the Yaragon virtual-env Python the minimum capability needed for packet
# capture, WITHOUT running the GUI as root.
#
#   CAP_NET_RAW - open raw / AF_PACKET sockets (capture + ARP)
#
# CAP_NET_ADMIN is deliberately NOT granted to the interpreter: it would let any
# code the interpreter ever runs reconfigure host networking. The only admin
# operation Yaragon needs is toggling net.ipv4.ip_forward for the lab MITM, and
# that is done transiently at MITM start via a polkit/sudo prompt (see
# platform/linux.py), not baked into the interpreter.
#
# To keep the privilege scoped to Yaragon (and not system-wide Python), the
# venv interpreter is turned into a private copy before the capability is
# applied. This script must run as root; it is invoked by install.sh and, if
# needed, by run.sh via pkexec/sudo. It is idempotent.
#
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_PY="$HERE/.venv/bin/python"

if [ ! -e "$VENV_PY" ]; then
    echo "setcaps: venv python not found at $VENV_PY" >&2
    exit 1
fi

if ! command -v setcap >/dev/null 2>&1; then
    echo "setcaps: 'setcap' not available (install libcap2-bin)" >&2
    exit 1
fi

# If the venv python is a symlink to the system interpreter, replace it with a
# private copy so capabilities apply only to Yaragon's interpreter.
if [ -L "$VENV_PY" ]; then
    target="$(readlink -f "$VENV_PY")"
    rm -f "$VENV_PY"
    cp "$target" "$VENV_PY"
fi

# Restrict the capability-bearing interpreter to its owner+group so it is not a
# world-usable path to raw sockets / net-admin.
chmod 0750 "$(readlink -f "$VENV_PY")" || true

# +ep (effective+permitted) only - the interpreter uses the cap itself, so the
# inheritable flag is unnecessary and would only widen the surface for children.
setcap cap_net_raw+ep "$(readlink -f "$VENV_PY")"
echo "setcaps: granted CAP_NET_RAW to $VENV_PY"
