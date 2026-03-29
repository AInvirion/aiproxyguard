# Dockerfile - Optimized for multi-platform builds
FROM python:3.11-slim AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy only dependency files first (better caching)
COPY pyproject.toml README.md ./

# Create minimal src structure for pip install
RUN mkdir -p src/aiproxyguard && \
    echo '__version__ = "0.0.0"' > src/aiproxyguard/__init__.py

# Install dependencies with pip cache mount (much faster rebuilds)
# Use [enterprise] to include onnxruntime for ONNX model support
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --no-cache-dir ".[enterprise]"

# Now copy actual source
COPY src/ ./src/

# Reinstall to get correct version
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --no-cache-dir ".[enterprise]"

FROM python:3.11-slim

WORKDIR /app

# Install CA certificates and locales for ONNX runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    locales \
    && sed -i '/en_US.UTF-8/s/^# //g' /etc/locale.gen \
    && locale-gen \
    && rm -rf /var/lib/apt/lists/*

ENV LANG=en_US.UTF-8
ENV LC_ALL=en_US.UTF-8

# Copy installed packages
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin/aiproxyguard /usr/local/bin/aiproxyguard

# Copy application
COPY src/ ./src/
COPY models/ ./models/

# Copy bundled signatures for offline fallback (free tier)
COPY signatures/ /app/signatures/

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
