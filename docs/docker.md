# Yaragon - Docker deployment (Linux)

Run Yaragon in a reproducible container with all Python and system
dependencies baked in - no host Python setup required.

> Yaragon is Linux-only. GUI-over-Docker relies on the host's X11 display
> (see [Limitations](#limitations)).

## TL;DR

```bash
xhost +local:root          # once per login: allow the container to use X
docker compose build       # build the image
docker compose up          # launch the Yaragon GUI on your display
docker compose down        # stop and remove the container
```

Other modes:

```bash
docker compose run --rm yaragon check   # headless self-check
docker compose run --rm yaragon test    # run the unit tests inside the image
docker compose run --rm yaragon shell   # debug shell
```

## Why host networking + capabilities (not `--privileged`)

### `network_mode: host`

A default Docker **bridge** network isolates the container in its own network
namespace. It would see only NAT'd bridge traffic - **not** your real lab
segment - so packet capture, interface discovery and the ARP lab would not
work. Host networking puts the container in the **host's** network namespace,
so `ip`, interface enumeration, capture and ARP behave exactly as native.

### Minimal capabilities

Instead of `--privileged` (which grants *everything*), the container is given
only what it needs:

| Capability  | Purpose |
|-------------|---------|
| `NET_RAW`   | Open raw / AF_PACKET sockets → packet capture and ARP frames. |
| `NET_ADMIN` | Toggle `net.ipv4.ip_forward` for transparent lab MITM; read/adjust interface state. |

Both are declared in `docker-compose.yml` under `cap_add:`.

If you only want **passive capture** (no MITM), you can drop `NET_ADMIN` and
keep `NET_RAW`.

## GUI over Docker (X11)

`docker-compose.yml`:
- passes `DISPLAY` from the host,
- mounts the X socket `/tmp/.X11-unix`,
- optionally mounts your `XAUTHORITY`,
- sets `QT_QPA_PLATFORM=xcb`.

On the host, authorize the local container to use your X server once per
session:

```bash
xhost +local:root
```

(Undo later with `xhost -local:root`.)

### Wayland hosts

Yaragon's GUI uses Qt **xcb** (X11). On a Wayland-only session it renders
through **XWayland**, which ships with most Linux desktop environments. If the
window fails to appear, confirm XWayland is running (an `Xwayland` process) or
start Yaragon from an X11 login session.

## Persistent data

Two named volumes keep your config and logs across runs (Yaragon does not
persist captures; export a `.pcap` when you want to keep one):

```yaml
volumes:
  - yaragon-data:/root/.local/share/yaragon    # logs
  - yaragon-config:/root/.config/yaragon        # config.json
```

Exported CSV/JSON files are written inside the container; to retrieve them,
export into a bind-mounted directory or copy with `docker cp`.

## Building manually (without compose)

```bash
docker build -t yaragon:latest .

docker run --rm -it \
  --network host \
  --cap-add NET_RAW --cap-add NET_ADMIN \
  -e DISPLAY="$DISPLAY" \
  -v /tmp/.X11-unix:/tmp/.X11-unix:rw \
  yaragon:latest
```

## Troubleshooting

| Symptom | Fix |
|---|---|
| `cannot connect to display` / `could not connect to display` | `xhost +local:root`; ensure `DISPLAY` is set on the host; Wayland needs XWayland. |
| `qt.qpa.plugin: could not load the Qt platform plugin "xcb"` | Ensure you started via compose (X socket mounted). The image already ships the xcb libs. |
| Capture says insufficient privileges | Confirm `cap_add: [NET_RAW, NET_ADMIN]` and `network_mode: host` are present (they are by default). |
| No lab traffic visible | Host networking must be active; verify the host itself is on the lab segment. |
| GUI won't start in headless CI | Use `docker compose run --rm yaragon check` / `test` instead. |

## Limitations

- GUI-over-Docker relies on the host's **X11** display (XWayland works). If the
  window doesn't appear, run `xhost +local:root` and confirm `DISPLAY` is shared.
- `network_mode: host` is required for real traffic visibility.
- The container runs as root internally but with only `NET_RAW`/`NET_ADMIN`
  added - not full `--privileged`.
