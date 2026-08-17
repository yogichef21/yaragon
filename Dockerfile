# Yaragon - Offensive Security MITM Tool for Linux
# Reproducible runtime image with all Python + system dependencies baked in.
#
# The image is intentionally NOT run with --privileged. It needs only:
#   * host network namespace  (to see real lab traffic / discover interfaces)
#   * CAP_NET_RAW             (open raw/AF_PACKET sockets for capture + ARP)
#   * CAP_NET_ADMIN           (toggle ip_forward for transparent lab MITM)
# These are granted in docker-compose.yml and documented in docs/docker.md.
#
FROM python:3.12-slim-bookworm

LABEL org.opencontainers.image.title="Yaragon" \
      org.opencontainers.image.description="Offensive security MITM tool for authorized network investigation (isolated-lab use)" \
      org.opencontainers.image.version="1.0.0" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    QT_QPA_PLATFORM=xcb \
    YARAGON_IN_DOCKER=1

# ---- system dependencies -------------------------------------------------
# libpcap        : packet capture backend for scapy
# iproute2       : `ip` used for interface / gateway discovery
# net-tools      : convenience for lab debugging
# Qt xcb runtime : the shared libs PySide6 needs to talk to an X11 display
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpcap0.8 \
        iproute2 \
        net-tools \
        libgl1 \
        libegl1 \
        libxkbcommon0 \
        libxcb-cursor0 \
        libxcb-icccm4 \
        libxcb-image0 \
        libxcb-keysyms1 \
        libxcb-randr0 \
        libxcb-render-util0 \
        libxcb-shape0 \
        libxcb-xinerama0 \
        libdbus-1-3 \
        libfontconfig1 \
        libglib2.0-0 \
        fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/yaragon

# ---- python dependencies (cached layer) ----------------------------------
# Dev deps (pytest) are baked in so the `test` entrypoint mode is reproducible
# and needs no network access at run time.
COPY requirements.txt requirements-dev.txt ./
RUN pip install --upgrade pip && pip install -r requirements-dev.txt

# ---- application ----------------------------------------------------------
COPY src/ ./src/
COPY tests/ ./tests/
COPY assets/ ./assets/
COPY main.py docker/entrypoint.sh ./
RUN chmod +x /opt/yaragon/entrypoint.sh

# Data / config live under /root by default; mount a volume to persist them.
ENTRYPOINT ["/opt/yaragon/entrypoint.sh"]
CMD ["gui"]
