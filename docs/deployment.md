---
title: Deployment
nav_order: 4
---

# Deployment

> **DigitalOcean users**: See the dedicated [DigitalOcean Guide](guides/digitalocean-guide.md) for step-by-step App Platform deployment.

## Docker

### Basic

```bash
docker run -d \
  --name aiproxyguard \
  -p 8080:8080 \
  ovalenzuela/aiproxyguard:latest
```

### With Custom Config

```bash
docker run -d \
  --name aiproxyguard \
  -p 8080:8080 \
  -v $(pwd)/config.yaml:/etc/aiproxyguard/config.yaml \
  ovalenzuela/aiproxyguard:latest
```

### With Resource Limits

```bash
docker run -d \
  --name aiproxyguard \
  -p 8080:8080 \
  -v $(pwd)/config.yaml:/etc/aiproxyguard/config.yaml \
  --memory=512m \
  --cpus=1 \
  --restart=unless-stopped \
  ovalenzuela/aiproxyguard:latest
```

### With Fleet Registration

Connect to the control plane for automatic signature updates and fleet management:

```bash
docker run -d \
  --name aiproxyguard \
  -p 8080:8080 \
  -e AIPROXYGUARD_CONTROL_PLANE_ENABLED=true \
  -e AIPROXYGUARD_CONTROL_PLANE_URL=https://aiproxyguard.com \
  -e AIPROXYGUARD_CONTROL_PLANE_API_KEY=your-api-key-here \
  --restart=unless-stopped \
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
      - ./config.yaml:/etc/aiproxyguard/config.yaml:ro
    environment:
      # Fleet registration (optional)
      - AIPROXYGUARD_CONTROL_PLANE_ENABLED=true
      - AIPROXYGUARD_CONTROL_PLANE_URL=https://aiproxyguard.com
      - AIPROXYGUARD_CONTROL_PLANE_API_KEY=${AIPROXYGUARD_API_KEY}  # Set in .env file
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

### With Prometheus

```yaml
version: "3.8"

services:
  aiproxyguard:
    image: ovalenzuela/aiproxyguard:latest
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

## DigitalOcean App Platform

Deploy AIProxyGuard as a managed container on DigitalOcean.

### Prerequisites

1. [DigitalOcean account](https://cloud.digitalocean.com/)
2. [doctl CLI](https://docs.digitalocean.com/reference/doctl/how-to/install/) installed and authenticated

### Step 1: Create App Spec

Create `app.yaml`:

```yaml
name: aiproxyguard
region: nyc
services:
  - name: proxy
    image:
      registry_type: DOCKER_HUB
      registry: ovalenzuela
      repository: aiproxyguard
      tag: latest
    instance_count: 1
    instance_size_slug: basic-xxs  # $5/mo - 512MB RAM, 1 vCPU
    http_port: 8080
    health_check:
      http_path: /healthz
      initial_delay_seconds: 10
      period_seconds: 30
    routes:
      - path: /
    envs:
      - key: LOG_LEVEL
        value: "info"
```

### Step 2: Deploy

```bash
# Create the app
doctl apps create --spec app.yaml

# Or update existing
doctl apps update <app-id> --spec app.yaml
```

### Step 3: Get App URL

```bash
doctl apps list
# Note the default URL: https://aiproxyguard-xxxxx.ondigitalocean.app
```

### Step 4: Configure Your Apps

Update your applications to use the proxy URL:

```python
from openai import OpenAI

client = OpenAI(
    base_url="https://aiproxyguard-xxxxx.ondigitalocean.app/openai/v1",
    api_key="your-openai-key"
)
```

### Custom Config on DigitalOcean

For custom configuration, either:

**Option A: Environment Variables**

```yaml
services:
  - name: proxy
    # ...
    envs:
      - key: AIPROXYGUARD_CONTROL_PLANE_ENABLED
        value: "true"
      - key: AIPROXYGUARD_CONTROL_PLANE_URL
        value: "https://aiproxyguard.com"
      - key: AIPROXYGUARD_CONTROL_PLANE_API_KEY
        type: SECRET
        value: "your-api-key-here"
```

**Option B: Build from Repo with Config**

```yaml
name: aiproxyguard
services:
  - name: proxy
    github:
      repo: AInvirion/aiproxyguard
      branch: main
    dockerfile_path: Dockerfile
    http_port: 8080
    # Config is baked into the image
```

### Scaling

```yaml
services:
  - name: proxy
    instance_count: 3  # Scale horizontally
    instance_size_slug: basic-s  # $12/mo per instance
```

### Custom Domain

```yaml
domains:
  - domain: proxy.yourdomain.com
    type: PRIMARY
```

## DigitalOcean Droplet (Manual)

For more control, deploy on a Droplet:

### Step 1: Create Droplet

```bash
doctl compute droplet create aiproxyguard \
  --image docker-20-04 \
  --size s-1vcpu-1gb \
  --region nyc1
```

### Step 2: SSH and Deploy

```bash
ssh root@<droplet-ip>

# Create config
cat > /root/config.yaml << 'EOF'
server:
  host: "0.0.0.0"
  port: 8080

upstreams:
  openai:
    url: "https://api.openai.com"
    auth_header: "Authorization"
  anthropic:
    url: "https://api.anthropic.com"
    auth_header: "x-api-key"

scanner:
  enabled: true
  regex: true
  heuristics: true

policy:
  default_action: "block"

logging:
  level: "info"
  format: "json"
EOF

# Run container
docker run -d \
  --name aiproxyguard \
  -p 80:8080 \
  -v /root/config.yaml:/etc/aiproxyguard/config.yaml \
  --restart=always \
  ovalenzuela/aiproxyguard:latest
```

### Step 3: Add SSL with Caddy

```bash
# Install Caddy
apt install -y debian-keyring debian-archive-keyring apt-transport-https
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list
apt update && apt install caddy

# Configure Caddy
cat > /etc/caddy/Caddyfile << 'EOF'
proxy.yourdomain.com {
    reverse_proxy localhost:8080
}
EOF

systemctl restart caddy
```

## Health Checks

All deployment methods should configure health checks:

| Endpoint | Purpose | Expected Response |
|----------|---------|-------------------|
| `GET /healthz` | Liveness | `{"status": "healthy"}` |
| `GET /readyz` | Readiness | `{"status": "ready", ...}` |
| `GET /metrics` | Prometheus | Prometheus text format |

## Architecture Recommendations

### Single Region

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│   Your App  │────▶│ AIProxyGuard │────▶│ OpenAI/etc  │
└─────────────┘     └──────────────┘     └─────────────┘
```

### Multi-Region with Load Balancer

```
                    ┌──────────────┐
              ┌────▶│ AIProxyGuard │────┐
┌──────────┐  │     │   (NYC)      │    │     ┌─────────────┐
│   Load   │──┤     └──────────────┘    ├────▶│ OpenAI/etc  │
│ Balancer │  │     ┌──────────────┐    │     └─────────────┘
└──────────┘  └────▶│ AIProxyGuard │────┘
                    │   (SFO)      │
                    └──────────────┘
```

### Resource Sizing

| Traffic | Instance Size | Memory | Notes |
|---------|---------------|--------|-------|
| < 100 req/min | basic-xxs | 512 MB | Development |
| 100-1000 req/min | basic-xs | 1 GB | Small production |
| 1000-10000 req/min | basic-s | 2 GB | Medium production |
| > 10000 req/min | Multiple instances | 2+ GB each | Scale horizontally |

## Troubleshooting

### API Key Invalid or Revoked

If you see this error in logs:
```json
{"level": "error", "message": "API key invalid or revoked. Control plane features disabled. Update your API key in the config and restart the proxy."}
```

**Cause:** The control plane API key is invalid, expired, or was deleted from the cloud dashboard.

**Solution:**
1. Get a new API key from [aiproxyguard.com](https://aiproxyguard.com)
2. Update your configuration (see [Updating API Keys](configuration.md#updating-or-rotating-api-keys))
3. Restart the proxy:

```bash
# Docker
docker restart aiproxyguard

# Docker Compose
docker-compose restart aiproxyguard

# Kubernetes
kubectl rollout restart deployment/aiproxyguard

# Systemd
sudo systemctl restart aiproxyguard
```

**Note:** The proxy continues running in offline mode with bundled signatures while the API key is invalid.

### Proxy Not Receiving Cloud Updates

If signatures or policies aren't syncing:

1. **Check connectivity:**
   ```bash
   docker exec aiproxyguard curl -s https://aiproxyguard.com/healthz
   ```

2. **Check registration status in logs:**
   ```bash
   docker logs aiproxyguard | grep -i "registered\|heartbeat"
   ```

3. **Verify API key is set:**
   ```bash
   docker exec aiproxyguard env | grep AIPROXYGUARD_CONTROL_PLANE
   ```

### Container Keeps Restarting

Check logs for startup errors:
```bash
docker logs --tail 50 aiproxyguard
```

Common issues:
- Invalid config YAML syntax
- Missing required upstream URL
- Port already in use
