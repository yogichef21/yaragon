#!/usr/bin/env bash
#
# Yaragon - native installer for Linux.
#
# Runs on any Linux distribution. Creates an isolated Python virtual environment
# in ./.venv, installs all Python dependencies from requirements.txt, and
# installs the system packages needed for the PySide6 GUI and libpcap-based
# capture using whichever package manager the distribution provides. Nothing is
# hardcoded to a particular interface or address - Yaragon discovers those at
# runtime.
#
# Usage:   ./install.sh
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

echo "==> Yaragon installer"
echo "    Project: $HERE"

# ---------------------------------------------------------------- distro
DISTRO="unknown"
if [ -r /etc/os-release ]; then
    . /etc/os-release
    DISTRO="${ID:-unknown}"
fi
echo "    Detected distro: $DISTRO"

# ---------------------------------------------------- system dependencies
# Yaragon needs: Python 3 (with venv + pip), libpcap (capture), iproute2 (the
# `ip` tool), setcap (grant capture capabilities), and the Qt/xcb runtime libs
# PySide6 links against. Package names differ per distribution, so we pick the
# set that matches the detected package manager. Installation is best-effort:
# if it fails, the venv/pip steps still run and the app reports what is missing.
install_system_packages() {
    if [ "$(id -u)" -eq 0 ]; then SUDO=""; else SUDO="sudo"; fi

    if command -v apt-get >/dev/null 2>&1; then
        echo "==> Installing system packages with apt (needs sudo)…"
        $SUDO apt-get update -y
        # shellcheck disable=SC2086
        $SUDO apt-get install -y \
            python3 python3-venv python3-pip libpcap0.8 iproute2 libcap2-bin \
            libgl1 libegl1 libxkbcommon0 libxcb-cursor0 libdbus-1-3 \
            libxcb-icccm4 libxcb-image0 libxcb-keysyms1 libxcb-randr0 \
            libxcb-render-util0 libxcb-shape0 libxcb-xinerama0 libfontconfig1 \
            libglib2.0-0 || echo "    WARNING: some packages failed; continuing."
    elif command -v dnf >/dev/null 2>&1; then
        echo "==> Installing system packages with dnf (needs sudo)…"
        $SUDO dnf install -y \
            python3 python3-pip libpcap iproute libcap mesa-libGL mesa-libEGL \
            libxkbcommon xcb-util-cursor libxcb dbus-libs fontconfig glib2 \
            || echo "    WARNING: some packages failed; continuing."
    elif command -v pacman >/dev/null 2>&1; then
        echo "==> Installing system packages with pacman (needs sudo)…"
        $SUDO pacman -Sy --needed --noconfirm \
            python python-pip libpcap iproute2 libcap qt6-base xcb-util-cursor \
            libxkbcommon-x11 mesa dbus fontconfig glib2 \
            || echo "    WARNING: some packages failed; continuing."
    elif command -v zypper >/dev/null 2>&1; then
        echo "==> Installing system packages with zypper (needs sudo)…"
        $SUDO zypper install -y \
            python3 python3-pip libpcap1 iproute2 libcap-progs Mesa-libGL1 \
            Mesa-libEGL1 libxkbcommon0 xcb-util-cursor0 libdbus-1-3 \
            fontconfig glib2 || echo "    WARNING: some packages failed; continuing."
    else
        echo "    (No supported package manager found. Install these with your"
        echo "     distribution's package manager: Python 3 + venv + pip,"
        echo "     libpcap, iproute2, setcap (libcap), and the Qt xcb runtime"
        echo "     libraries required by PySide6.)"
    fi
}

install_system_packages

# ------------------------------------------------------- python venv
if [ -x ".venv/bin/python" ]; then
    echo "==> Reusing existing virtual environment (.venv)"
else
    echo "==> Creating virtual environment (.venv)…"
    python3 -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install --upgrade pip
echo "==> Installing Python dependencies (idempotent)…"
pip install -r requirements.txt
deactivate

# Grant capture capabilities to the venv interpreter now, so ./run.sh just
# starts (no runtime privilege prompts). Best-effort; the app still runs and
# explains itself if this step is skipped.
echo "==> Granting packet-capture capabilities (needs sudo)…"
if [ "$(id -u)" -eq 0 ]; then
    ./scripts/setcaps.sh || echo "    (skipped - capture will prompt at first run)"
elif command -v sudo >/dev/null 2>&1; then
    sudo ./scripts/setcaps.sh || echo "    (skipped - capture will prompt at first run)"
else
    echo "    (no sudo - run ./run.sh once to grant capture privileges)"
fi

echo ""
echo "==> Yaragon installed.  Start it with:  ./run.sh"
echo "    Headless self-check:  ./run.sh --check"
