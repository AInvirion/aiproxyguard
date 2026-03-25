---
title: Deployment
---

# Deployment

## Docker

```bash
docker run -d \
  --name aiproxyguard \
  -p 8080:8080 \
  -v /path/to/config.yaml:/etc/aiproxyguard/config.yaml \
  ovalenzuela/aiproxyguard:latest
```

## Docker Compose

```yaml
version: "3.8"
services:
  aiproxyguard:
    image: ovalenzuela/aiproxyguard:latest
    ports:
      - "8080:8080"
    volumes:
      - ./config.yaml:/etc/aiproxyguard/config.yaml
    restart: unless-stopped
```

## Kubernetes

Coming soon - Helm chart in development.

## Health Checks

- **Liveness**: `GET /healthz`
- **Readiness**: `GET /readyz`
- **Metrics**: `GET /metrics` (Prometheus format)
