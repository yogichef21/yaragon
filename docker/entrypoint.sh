#!/usr/bin/env bash
#
# Yaragon Docker entrypoint.
#
# Modes:
#   gui     (default) - launch the PySide6 GUI (needs an X11 display shared in)
#   check             - headless self-check: imports, interfaces, privileges
#   test              - run the unit test suite inside the container
#   shell             - drop into a shell for debugging
#
set -euo pipefail
cd /opt/yaragon

MODE="${1:-gui}"

check_capture_privs() {
    # CapEff bit 13 = CAP_NET_RAW. Warn (do not fail) if missing.
    local capeff
    capeff="$(grep CapEff /proc/self/status | awk '{print $2}')"
    # shellcheck disable=SC2004
    if (( (0x${capeff} & (1 << 13)) == 0 )); then
        echo "WARNING: CAP_NET_RAW not present in this container."
        echo "         Packet capture and lab MITM will be unavailable."
        echo "         Ensure docker-compose grants cap_add: NET_RAW (and"
        echo "         NET_ADMIN for MITM) and uses network_mode: host."
        echo "         See docs/docker.md."
    fi
}

case "$MODE" in
    gui)
        check_capture_privs
        if [ -z "${DISPLAY:-}" ]; then
            echo "ERROR: DISPLAY is not set inside the container."
            echo "       The GUI needs a shared X11 display. On the host run:"
            echo "         xhost +local:root"
            echo "       and start with docker compose (it forwards DISPLAY +"
            echo "       /tmp/.X11-unix). See docs/docker.md. Falling back to"
            echo "       headless self-check:"
            exec python main.py --check
        fi
        exec python main.py
        ;;
    check)
        exec python main.py --check
        ;;
    test)
        # pytest is baked into the image (see Dockerfile); no runtime install.
        # Tests run headless; never touch the live xcb display.
        export QT_QPA_PLATFORM=offscreen
        exec python -m pytest tests/ -q
        ;;
    shell)
        exec /bin/bash
        ;;
    *)
        # Pass anything else straight to python main.py
        exec python main.py "$@"
        ;;
esac
