# ---------------------------------------------------------------------
# Decentralized AI Prompt Injection Firewall — Gateway image
#
# Contains the proxy, the inspection pipeline (Layers 1-2 and the output
# scanner) and the Layer 2 ONNX model. Schema is created at startup by
# init_schema() — no SQL file is copied.
#
# Air-gapped operation (SRS 2.4 / 9.4): everything the gateway needs to
# inspect traffic is baked into this image. Nothing is downloaded when the
# container starts.
#
# Layer 3 is the exception: its reasoning model runs OUTSIDE this container.
# The gateway only calls it over HTTP at LAYER3_BASE_URL (set in .env). Note
# that "localhost" inside the container is the container itself, so point
# LAYER3_BASE_URL at an address the container can reach (e.g. the model
# server's host or LAN address), not at http://localhost:11434/v1.
# ---------------------------------------------------------------------
FROM python:3.11-slim

# No .pyc files; log lines are written immediately (visible in `docker logs`).
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install Python dependencies first so this layer is cached across builds
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application code (including src/models/), configuration and operational scripts
COPY src/ ./src/
COPY config/ ./config/
COPY scripts/ ./scripts/

# Fail the build, with a clear message, if the Layer 2 model assets are missing.
# The model files are git-ignored, so a fresh clone does not have them.
# `-s` also rejects empty placeholder files.
RUN set -eu; \
    missing=""; \
    for f in src/models/classifier.onnx src/models/tokenizer/tokenizer.json; do \
        if [ ! -s "$f" ]; then missing="$missing $f"; fi; \
    done; \
    if [ -n "$missing" ]; then \
        echo "ERROR: Layer 2 model assets are missing or empty in the build context:" >&2; \
        for f in $missing; do echo "  - $f" >&2; done; \
        echo "Place them there BEFORE running 'docker build' (they are git-ignored)," >&2; \
        echo "and make sure .dockerignore does not exclude them (e.g. a '*.onnx' rule)." >&2; \
        echo "See src/models/README.md for how the team shares them." >&2; \
        exit 1; \
    fi

# Run as an unprivileged user. The app only reads /app (it writes nothing to
# disk; logs go to stdout), so the code stays owned by root and read-only to
# the runtime user. chmod makes sure model files with restrictive host
# permissions are still readable.
RUN chmod -R a+rX /app \
    && groupadd --gid 10001 firewall \
    && useradd --uid 10001 --gid firewall --no-create-home \
               --shell /usr/sbin/nologin firewall \
    && mkdir -p /app/runtime \
    && cp /app/config/firewall.yaml /app/runtime/firewall.yaml \
    && chown -R 10001:10001 /app/runtime
USER firewall

EXPOSE 8000

# start-period is generous: startup loads and warms up the ONNX model.
HEALTHCHECK --interval=15s --timeout=3s --start-period=60s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/healthz', timeout=2)"

CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"]