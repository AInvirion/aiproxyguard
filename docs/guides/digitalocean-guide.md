---
title: DigitalOcean
parent: Guides
nav_order: 1
---

# DigitalOcean Deployment Guide

Deploy AIProxyGuard on DigitalOcean as an LLM security proxy.

| Option | Best For | Cost |
|--------|----------|------|
| [1. Docker on Droplet](#option-1-docker-on-a-droplet-recommended) | Simple setup, full control | From $6/mo |
| [2. One-Click Deploy](#option-2-one-click-deploy) | Quick start, no CLI | From $5/mo |
| [3. App Platform CLI](#option-3-app-platform-cli) | Automation, CI/CD | From $5/mo |
| [4. App Platform Web UI](#option-4-app-platform-web-ui) | Manual App Platform setup | From $5/mo |

## Option 1: Docker on a Droplet (Recommended)

The simplest way to deploy - just pull and run the container.

### Step 1: Create a Droplet

1. Go to [cloud.digitalocean.com/droplets](https://cloud.digitalocean.com/droplets)
2. Click **Create Droplet**
3. Choose **Docker** from the Marketplace tab (or any Linux + install Docker manually)
4. Select size: **Basic $6/mo** is sufficient for most use cases
5. Choose your region
6. Add your SSH key
7. Click **Create Droplet**

### Step 2: SSH into the Droplet

```bash
ssh root@your-droplet-ip
```

### Step 3: Pull and Run

**From GitHub Container Registry (recommended):**
```bash
docker run -d \
  --name aiproxyguard \
  --restart unless-stopped \
  -p 8080:8080 \
  ghcr.io/ainvirion/aiproxyguard:latest
```

**From Docker Hub:**
```bash
docker run -d \
  --name aiproxyguard \
  --restart unless-stopped \
  -p 8080:8080 \
  ovalenzuela/aiproxyguard:latest
```

### Step 4: Verify

```bash
curl http://localhost:8080/healthz
# {"status": "healthy"}
```

### Step 5: Configure Firewall

Allow traffic on port 8080:
```bash
ufw allow 8080/tcp
```

Your proxy is now accessible at: `http://your-droplet-ip:8080`

### With Docker Compose

Create `docker-compose.yml`:

```yaml
services:
  aiproxyguard:
    image: ghcr.io/ainvirion/aiproxyguard:latest
    # Alternative: ovalenzuela/aiproxyguard:latest
    restart: unless-stopped
    ports:
      - "8080:8080"
    environment:
      - AIPROXYGUARD_CONTROL_PLANE_ENABLED=true
      - AIPROXYGUARD_CONTROL_PLANE_URL=https://aiproxyguard.com
      - AIPROXYGUARD_CONTROL_PLANE_API_KEY=${AIPROXYGUARD_API_KEY}
```

Run:
```bash
docker compose up -d
```

---

## Option 2: One-Click Deploy

Deploy to App Platform with one click.

[![Deploy to DigitalOcean](https://www.deploytodo.com/do-btn-blue.svg)](https://cloud.digitalocean.com/apps/new?repo=https://github.com/AInvirion/aiproxyguard/tree/main&refcode=)

1. Click the button above
2. Log in to your DigitalOcean account
3. Review the default settings (Basic plan, $5/mo works for most use cases)
4. Click **Create Resources**
5. Wait for deployment to complete (~2 minutes)
6. Copy your app URL: `https://aiproxyguard-xxxxx.ondigitalocean.app`

**Test it:**
```bash
curl https://aiproxyguard-xxxxx.ondigitalocean.app/healthz
```

---

## Option 3: App Platform CLI

Best for automation, CI/CD pipelines, or repeatable deployments.

### Prerequisites

Install and authenticate `doctl`:
```bash
brew install doctl  # macOS
# or: snap install doctl  # Linux
doctl auth init
```

### Step 1: Create App Spec

Create `do-app.yaml`:

```yaml
name: aiproxyguard
region: nyc

services:
  - name: proxy
    image:
      registry_type: GHCR
      registry: ainvirion
      repository: aiproxyguard
      tag: latest
    instance_count: 1
    instance_size_slug: basic-xxs  # $5/mo
    http_port: 8080
    health_check:
      http_path: /healthz
      initial_delay_seconds: 10
      period_seconds: 30
      timeout_seconds: 5
      success_threshold: 1
      failure_threshold: 3
    routes:
      - path: /
```

> **Docker Hub alternative:** Use `registry_type: DOCKER_HUB`, `registry: ovalenzuela`

### Step 2: Deploy

```bash
doctl apps create --spec do-app.yaml
```

### Step 3: Get the URL

```bash
doctl apps list
```

Note the URL: `https://aiproxyguard-xxxxx.ondigitalocean.app`

---

## Option 4: App Platform Web UI

Deploy through the DigitalOcean console without any CLI tools.

### Step 1: Create New App

1. Go to [cloud.digitalocean.com/apps](https://cloud.digitalocean.com/apps)
2. Click **Create App**

### Step 2: Choose Source

1. Select **Container Registry** as the source
2. Choose **GHCR (GitHub Container Registry)**
3. Enter:
   - **Registry:** `ainvirion`
   - **Repository:** `aiproxyguard`
   - **Tag:** `latest`
4. Click **Next**

> **Docker Hub alternative:** Select **Docker Hub**, registry `ovalenzuela`, repository `aiproxyguard`

### Step 3: Configure Resources

1. Keep the default **Web Service** type
2. Set **HTTP Port** to `8080`
3. Under **Health Check**, set path to `/healthz`
4. Choose your plan:
   - **Basic ($5/mo)** - Good for development/testing
   - **Basic ($10/mo)** - Good for small production
5. Click **Next**

### Step 4: Environment Variables (Optional)

Skip this step for default configuration, or add:
- `AIPROXYGUARD_LOG_LEVEL`: `info` or `debug`

Click **Next**

### Step 5: Review and Deploy

1. Choose your region (closest to your other apps)
2. Review the configuration
3. Click **Create Resources**
4. Wait for deployment (~2 minutes)

### Step 6: Get Your URL

Once deployed, find your URL in the app dashboard:
`https://aiproxyguard-xxxxx.ondigitalocean.app`

---

## Test Your Deployment

**For Droplet deployments:**
```bash
curl http://your-droplet-ip:8080/healthz
```

**For App Platform deployments:**
```bash
curl https://aiproxyguard-xxxxx.ondigitalocean.app/healthz
```

**Test with OpenAI:**
```bash
curl -X POST http://your-proxy-url:8080/openai/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -d '{"model": "gpt-4", "messages": [{"role": "user", "content": "Hello!"}]}'
```

---

## Connect to Control Plane (Recommended)

Register your proxy with [aiproxyguard.com](https://aiproxyguard.com) to enable:
- Automatic signature updates (new threat patterns)
- Fleet management dashboard
- Telemetry and analytics

### Step 1: Get Your API Key

1. Sign up at [aiproxyguard.com](https://aiproxyguard.com)
2. Create a new proxy instance in the dashboard
3. Copy your API key

### Step 2: Add Environment Variables

**For Droplet deployments:**

```bash
docker run -d \
  --name aiproxyguard \
  --restart unless-stopped \
  -p 8080:8080 \
  -e AIPROXYGUARD_CONTROL_PLANE_ENABLED=true \
  -e AIPROXYGUARD_CONTROL_PLANE_URL=https://aiproxyguard.com \
  -e AIPROXYGUARD_CONTROL_PLANE_API_KEY=your-api-key-here \
  ghcr.io/ainvirion/aiproxyguard:latest
```

**For App Platform (One-Click or Web UI):**

1. Go to your app in the [DO Console](https://cloud.digitalocean.com/apps)
2. Click **Settings** → **App-Level Environment Variables**
3. Add these variables:

| Variable | Value |
|----------|-------|
| `AIPROXYGUARD_CONTROL_PLANE_ENABLED` | `true` |
| `AIPROXYGUARD_CONTROL_PLANE_URL` | `https://aiproxyguard.com` |
| `AIPROXYGUARD_CONTROL_PLANE_API_KEY` | `your-api-key-here` |

4. Click **Save** → The app will redeploy automatically

**For App Platform CLI (doctl):**

Add to your `do-app.yaml`:

```yaml
services:
  - name: proxy
    # ... existing config ...
    envs:
      - key: AIPROXYGUARD_CONTROL_PLANE_ENABLED
        value: "true"
      - key: AIPROXYGUARD_CONTROL_PLANE_URL
        value: "https://aiproxyguard.com"
      - key: AIPROXYGUARD_CONTROL_PLANE_API_KEY
        value: "your-api-key-here"
        type: SECRET
```

Then update:
```bash
doctl apps update <app-id> --spec do-app.yaml
```

### Step 3: Verify Registration

**Droplet:**
```bash
docker logs aiproxyguard | grep "control plane"
```

**App Platform:**
```bash
doctl apps logs <app-id> | grep "control plane"
```

You should see:
```
{"level": "info", "message": "Connected to control plane", "instance_id": "..."}
```

---

## Update Your Apps

Point your applications to use the proxy:

**Environment variable:**
```bash
OPENAI_BASE_URL=http://your-proxy-url:8080/openai/v1
```

**In code:**
```python
from openai import OpenAI

client = OpenAI(
    base_url="http://your-proxy-url:8080/openai/v1",
    api_key=os.environ["OPENAI_API_KEY"]
)
```

---

## Advanced Configuration

### Internal Network (App Platform)

For production, keep the proxy internal and not exposed to the internet.

```yaml
services:
  - name: proxy
    image:
      registry_type: GHCR
      registry: ainvirion
      repository: aiproxyguard
      tag: latest
    http_port: 8080
    internal_ports:
      - 8080  # Only accessible within DO network
    health_check:
      http_path: /healthz
```

Other apps in the same region access via internal URL:
```
http://proxy.aiproxyguard.internal:8080
```

### VPC Network (Droplet)

For Droplet deployments, use DigitalOcean VPC to keep traffic internal:

1. Create both Droplets in the same VPC
2. Use private IP addresses for communication
3. Don't expose port 8080 to the public internet

### Custom Configuration

**Via environment variables:**
```bash
docker run -d \
  --name aiproxyguard \
  -p 8080:8080 \
  -e AIPROXYGUARD_CONFIG='server:
    port: 8080
  scanner:
    enabled: true
  policy:
    default_action: block' \
  ghcr.io/ainvirion/aiproxyguard:latest
```

**Via custom config file:**
```bash
docker run -d \
  --name aiproxyguard \
  -p 8080:8080 \
  -v /path/to/config.yaml:/app/config.yaml \
  ghcr.io/ainvirion/aiproxyguard:latest
```

### Scaling

**Droplet:** Use a load balancer in front of multiple Droplets.

**App Platform:**

| Traffic Level | Instances | Size | Monthly Cost |
|---------------|-----------|------|--------------|
| Development | 1 | basic-xxs | $5 |
| Small Prod | 1 | basic-xs | $10 |
| Medium Prod | 2 | basic-s | $24 |
| Large Prod | 3+ | basic-m | $60+ |

```yaml
services:
  - name: proxy
    instance_count: 3
    instance_size_slug: basic-s
```

### Custom Domain

**Droplet:** Point your domain's A record to the Droplet IP.

**App Platform:**

1. Add to app spec:
   ```yaml
   domains:
     - domain: proxy.yourdomain.com
       type: PRIMARY
   ```

2. Add CNAME record in your DNS:
   ```
   proxy.yourdomain.com → aiproxyguard-xxxxx.ondigitalocean.app
   ```

---

## Monitoring

**Droplet:**
```bash
docker logs -f aiproxyguard
```

**App Platform:**
```bash
doctl apps logs <app-id> --follow
```

**Prometheus integration:**

The proxy exposes `/metrics`. Configure scrape target:
```yaml
scrape_configs:
  - job_name: 'aiproxyguard'
    static_configs:
      - targets: ['your-proxy-ip:8080']
```

---

## Troubleshooting

### Container Won't Start

**Droplet:**
```bash
docker logs aiproxyguard
```

**App Platform:**
```bash
doctl apps logs <app-id>
```

Common issues:
- Image pull failed → Check GHCR/Docker Hub is accessible
- Health check failing → Verify `/healthz` returns 200

### Requests Timing Out

- Increase Droplet/instance size
- Check upstream timeout in config
- Verify network connectivity to OpenAI/Anthropic

### High Latency

- Scanner timeout may be too high
- Consider larger instances
- Check if many requests are being blocked (high scan time)

---

## Next Steps

1. [Configure custom detection policies](../configuration)
2. [Set up Prometheus monitoring](../deployment#with-prometheus)
3. [Enable response scanning](../security#response-scanning)
