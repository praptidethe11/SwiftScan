# Base image. Kali is a rolling release, so pin it by digest for reproducible
# builds. Get the digest with:  docker pull kalilinux/kali-rolling && \
#   docker inspect --format='{{index .RepoDigests 0}}' kalilinux/kali-rolling
# then build with:  docker build --build-arg BASE_IMAGE=kalilinux/kali-rolling@sha256:<digest> .
ARG BASE_IMAGE=kalilinux/kali-rolling:latest
FROM ${BASE_IMAGE}

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    SWIFTSCAN_REPORTS_DIR=/data/reports \
    SWIFTSCAN_LOG_DIR=/data/logs \
    NMAP_PRIVILEGED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv ca-certificates git libcap2-bin \
    nmap nikto dnsrecon wafw00f sslyze amass theharvester dirb fierce \
    dmitry dnsenum whatweb wapiti xsser uniscan davtest lbd dnsmap \
    dnswalk wget whois bind9-host \
    && setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip "$(readlink -f "$(command -v nmap)")" \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Unprivileged user; reports and logs live on a volume it owns.
RUN useradd --create-home --uid 1000 scanner \
    && mkdir -p /app /data/reports /data/logs \
    && chown -R scanner:scanner /app /data

WORKDIR /app

# Hash-pinned dependencies (--require-hashes refuses anything not in the lock file).
COPY requirements.txt .
RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --require-hashes -r requirements.txt
ENV PATH="/opt/venv/bin:$PATH"

COPY --chown=scanner:scanner . .

USER scanner
VOLUME ["/data"]
EXPOSE 5000

# /healthz is open and returns nothing but {"status": "ok"}.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/healthz', timeout=4)" || exit 1

# ONE worker: the "one scan at a time" slot is per process. Scans run in
# background threads, so a long request is no problem for gthread; the worker
# timeout only fires if the worker itself stops responding.
# The container refuses non-local clients unless SWIFTSCAN_TOKEN is set:
#   docker run -p 127.0.0.1:5000:5000 -e SWIFTSCAN_TOKEN=... -v swiftscan-data:/data swiftscan
CMD ["python3", "-m", "gunicorn", "--bind", "0.0.0.0:5000", "--worker-class", "gthread", "--workers", "1", "--threads", "8", "--timeout", "120", "web_app:app"]
