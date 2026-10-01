# ---------------------------------------------------------------------
# Decentralized AI Prompt Injection Firewall — Gateway image
# Week 1 scope: proxy + Layer 1 + database logging.
# Schema is created at startup by init_schema() — no SQL file is copied.
# ---------------------------------------------------------------------
FROM python:3.11-slim

WORKDIR /app

# Install Python dependencies first so this layer is cached across builds
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application code, configuration and operational scripts
COPY src/ ./src/
COPY config/ ./config/
COPY scripts/ ./scripts/

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/healthz', timeout=2)"

CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"]