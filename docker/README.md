# Yaragon in Docker

Reproducible Yaragon runtime with all Python + system dependencies baked in.
This directory holds the container entrypoint and a convenience launcher; the
build files (`Dockerfile`, `docker-compose.yml`, `.dockerignore`) live at the
repo root. Full walkthrough: [`../docs/docker.md`](../docs/docker.md).

## Quick start (Linux host)

```bash
# from the repo root
xhost +local:root
docker compose build
docker compose up          # GUI on your display
docker compose down        # stop

# or use the helper
./docker/run.sh            # build + start GUI
./docker/run.sh check      # headless self-check
./docker/run.sh test       # run the test suite in the image
./docker/run.sh down       # stop
```

## What the container is granted (and why)

Packet capture needs the host's network view and raw sockets. Instead of
`--privileged`, the compose file grants only:

| Setting                | Why                                                        |
|------------------------|------------------------------------------------------------|
| `network_mode: host`   | See the **real** host interfaces/traffic (a bridge network would only show NAT'd container traffic). Linux only. |
| `cap_add: NET_RAW`     | Open raw / AF_PACKET sockets for capture + ARP.            |
| `cap_add: NET_ADMIN`   | Toggle `ip_forward` for the Linux-only lab MITM.           |

For passive capture only, you may drop `NET_ADMIN`.

## Platform notes

- **Linux (any distribution):** full support - host capture + GUI over X11.
  The same image runs on any Linux host.
- **Wayland Linux sessions:** the GUI renders via XWayland (ships with most
  Linux desktop environments). If the window doesn't appear, start from an
  X11 session or confirm XWayland is running.

## Persistent data

Named volumes keep config and logs across runs:

```
yaragon-config  -> /root/.config/yaragon
yaragon-data    -> /root/.local/share/yaragon
```
