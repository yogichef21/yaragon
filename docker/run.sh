#!/usr/bin/env bash
#
# Yaragon - Docker convenience launcher (Linux hosts).
#
# Authorizes the local X server, builds if needed, and starts the GUI via
# docker compose with host networking + minimal capabilities. This is optional
# sugar around the documented `docker compose` commands.
#
#   ./docker/run.sh            # build (if needed) + start GUI
#   ./docker/run.sh check      # headless self-check in the container
#   ./docker/run.sh test       # run the test suite in the container
#   ./docker/run.sh down       # stop and remove the container
#
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$HERE"

if [[ "$(uname -s)" != "Linux" ]]; then
    echo "This helper targets Linux hosts. On other platforms see docker/README.md" >&2
fi

MODE="${1:-gui}"

case "$MODE" in
    down)
        docker compose down --remove-orphans
        exit 0 ;;
    check|test|shell)
        exec docker compose run --rm yaragon "$MODE" ;;
esac

# GUI mode: authorize the local X server for the container user.
if command -v xhost >/dev/null 2>&1; then
    xhost +local:root >/dev/null 2>&1 || \
        echo "note: could not run 'xhost +local:root' (Wayland? see docker/README.md)"
fi

docker compose build
docker compose up
