# Dockerfile
FROM python:3.11-slim AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy source for build
COPY pyproject.toml README.md ./
COPY src/ ./src/

# Install Python dependencies
RUN pip install --no-cache-dir .

FROM python:3.11-slim

WORKDIR /app

# Copy installed packages
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin/aiproxyguard /usr/local/bin/aiproxyguard

# Copy application
COPY src/ ./src/
COPY signatures/ ./signatures/

# Create config directory and copy default config
RUN mkdir -p /etc/aiproxyguard
COPY config.docker.yaml /etc/aiproxyguard/config.yaml

# Set default signature path
ENV AIPROXYGUARD_SIGNATURES_PATH=/app/signatures

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/healthz')" || exit 1

# Run
ENTRYPOINT ["aiproxyguard"]
CMD ["-c", "/etc/aiproxyguard/config.yaml"]
