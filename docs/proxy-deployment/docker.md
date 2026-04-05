---
title: Docker
parent: Proxy Deployment
nav_order: 1
---

# Docker Deployment

Deploy AIProxyGuard locally or on any Docker-compatible host.

> **Image:** `ghcr.io/ainvirion/aiproxyguard` (primary) or `ainvirion/aiproxyguard` (Docker Hub)

## Quick Start

```bash
docker run -d \
  --name aiproxyguard \
  -p 8080:8080 \
  ghcr.io/ainvirion/aiproxyguard:latest
```

Verify it's running:

```bash
curl http://localhost:8080/healthz
# {"status": "healthy"}
```

## With Custom Config

```bash
docker run -d \
  --name aiproxyguard \
  -p 8080:8080 \
  -v $(pwd)/config.yaml:/etc/aiproxyguard/config.yaml \
  ghcr.io/ainvirion/aiproxyguard:latest
```

## With Resource Limits

```bash
docker run -d \
  --name aiproxyguard \
  -p 8080:8080 \
  -v $(pwd)/config.yaml:/etc/aiproxyguard/config.yaml \
  --memory=512m \
  --cpus=1 \
  --restart=unless-stopped \
  ghcr.io/ainvirion/aiproxyguard:latest
```

## With Fleet Registration

Connect to the control plane for automatic signature updates:

```bash
docker run -d \
  --name aiproxyguard \
  -p 8080:8080 \
  -e AIPROXYGUARD_CONTROL_PLANE_ENABLED=true \
  -e AIPROXYGUARD_CONTROL_PLANE_URL=https://aiproxyguard.com \
  -e AIPROXYGUARD_CONTROL_PLANE_API_KEY=your-api-key-here \
  --restart=unless-stopped \
  ghcr.io/ainvirion/aiproxyguard:latest
```

## Docker Compose

```yaml
version: "3.8"

services:
  aiproxyguard:
    image: ghcr.io/ainvirion/aiproxyguard:latest
    ports:
      - "8080:8080"
    volumes:
      - ./config.yaml:/etc/aiproxyguard/config.yaml:ro
    environment:
      # Fleet registration (optional)
      - AIPROXYGUARD_CONTROL_PLANE_ENABLED=true
      - AIPROXYGUARD_CONTROL_PLANE_URL=https://aiproxyguard.com
      - AIPROXYGUARD_CONTROL_PLANE_API_KEY=${AIPROXYGUARD_API_KEY}
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/healthz"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 10s
    deploy:
      resources:
        limits:
          memory: 512M
          cpus: '1'
```

### With Prometheus & Grafana

```yaml
version: "3.8"

services:
  aiproxyguard:
    image: ghcr.io/ainvirion/aiproxyguard:latest
    ports:
      - "8080:8080"
    volumes:
      - ./config.yaml:/etc/aiproxyguard/config.yaml:ro
    restart: unless-stopped

  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml:ro
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
```

**prometheus.yml:**
```yaml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'aiproxyguard'
    static_configs:
      - targets: ['aiproxyguard:8080']
```

## Troubleshooting

### Container Keeps Restarting

Check logs for startup errors:
```bash
docker logs --tail 50 aiproxyguard
```

Common issues:
- Invalid config YAML syntax
- Missing required upstream URL
- Port already in use

### API Key Invalid

If you see this error:
```
API key invalid or revoked. Control plane features disabled.
```

1. Get a new API key from [aiproxyguard.com](https://aiproxyguard.com)
2. Update the `AIPROXYGUARD_CONTROL_PLANE_API_KEY` environment variable
3. Restart: `docker restart aiproxyguard`

The proxy continues running with bundled signatures while the API key is invalid.
