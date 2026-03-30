---
title: DigitalOcean
parent: Guides
nav_order: 1
---

# DigitalOcean Deployment Guide

Deploy AIProxyGuard on DigitalOcean App Platform as an LLM security proxy.

| Option | Best For | Cost |
|--------|----------|------|
| [1. Container Image (Recommended)](#option-1-deploy-container-image-recommended) | Simple setup, pre-built image | From $5/mo |
| [2. One-Click Deploy](#option-2-one-click-deploy) | Quick start from repo | From $5/mo |
| [3. CLI with doctl](#option-3-cli-with-doctl) | Automation, CI/CD | From $5/mo |

## Option 1: Deploy Container Image (Recommended)

Deploy the pre-built container image from GitHub Container Registry or Docker Hub.

### Step 1: Create App

1. Go to [cloud.digitalocean.com/apps](https://cloud.digitalocean.com/apps)
2. Click **Create App**

### Step 2: Select Container Image

1. Under "Create Resource From", select **Container Image**
2. Choose your registry:

**GitHub Container Registry:**
- Image Source: **GHCR**
- Repository: `ainvirion/aiproxyguard`
- Tag: `latest`

**Docker Hub:**
- Image Source: **Docker Hub**
- Repository: `ovalenzuela/aiproxyguard`
- Tag: `latest`

3. Click **Next**

### Step 3: Select Resources

1. Keep the default **Web Service** type
2. Choose your plan:
   - **Basic ($5/mo)** - Development/testing
   - **Basic ($10/mo)** - Small production
   - **Professional ($25/mo)** - Production with auto-scaling
3. Click **Next**

### Step 4: Configure App

1. Set **HTTP Port** to `8080`
2. Under **Health Check**, set path to `/healthz`
3. Add environment variables (optional):
   - `AIPROXYGUARD_LOG_LEVEL`: `info` or `debug`

**Want fleet management?** Add the control plane environment variables to get automatic signature updates, analytics, and fleet management. See [Connect to Control Plane](#connect-to-control-plane-recommended) for details.

4. Click **Next**

### Step 5: Review and Deploy

1. Choose your region (closest to your apps)
2. Review the configuration
3. Click **Create Resources**
4. Wait for deployment (~2 minutes)

### Step 6: Get Your URL

Once deployed, copy your app URL from the dashboard:
```
https://aiproxyguard-xxxxx.ondigitalocean.app
```

**Test it:**
```bash
curl https://aiproxyguard-xxxxx.ondigitalocean.app/healthz
# {"status": "healthy"}
```

For more details, see [DigitalOcean's container image deployment guide](https://docs.digitalocean.com/products/app-platform/how-to/deploy-from-container-images/).

---

## Option 2: One-Click Deploy

Deploy directly from the GitHub repository.

[![Deploy to DigitalOcean](https://www.deploytodo.com/do-btn-blue.svg)](https://cloud.digitalocean.com/apps/new?repo=https://github.com/AInvirion/aiproxyguard/tree/main&refcode=)

1. Click the button above
2. Log in to your DigitalOcean account
3. Review the default settings (Basic plan, $5/mo)
4. Click **Create Resources**
5. Wait for deployment (~2 minutes)
6. Copy your app URL: `https://aiproxyguard-xxxxx.ondigitalocean.app`

**Want fleet management?** After deployment, go to **Settings** → **App-Level Environment Variables** and add the control plane variables. [Sign up at aiproxyguard.com](https://aiproxyguard.com) to get your API key. See [Connect to Control Plane](#connect-to-control-plane-recommended) for details.

**Test it:**
```bash
curl https://aiproxyguard-xxxxx.ondigitalocean.app/healthz
```

---

## Option 3: CLI with doctl

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

> **Docker Hub:** Use `registry_type: DOCKER_HUB`, `registry: ovalenzuela`

### Step 2: Deploy

```bash
doctl apps create --spec do-app.yaml
```

### Step 3: Get the URL

```bash
doctl apps list
```

Note the URL: `https://aiproxyguard-xxxxx.ondigitalocean.app`

**Want fleet management?** Add the control plane environment variables to your app spec. See [Connect to Control Plane](#connect-to-control-plane-recommended) for the YAML configuration.

---

## Test Your Deployment

```bash
# Health check
curl https://aiproxyguard-xxxxx.ondigitalocean.app/healthz
# {"status": "healthy"}

# Test with OpenAI
curl -X POST https://aiproxyguard-xxxxx.ondigitalocean.app/openai/v1/chat/completions \
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

1. Go to your app in the [DO Console](https://cloud.digitalocean.com/apps)
2. Click **Settings** → **App-Level Environment Variables**
3. Add these variables:

| Variable | Value |
|----------|-------|
| `AIPROXYGUARD_CONTROL_PLANE_ENABLED` | `true` |
| `AIPROXYGUARD_CONTROL_PLANE_URL` | `https://aiproxyguard.com` |
| `AIPROXYGUARD_CONTROL_PLANE_API_KEY` | `your-api-key-here` |

4. Click **Save** → The app will redeploy automatically

**For doctl deployments**, add to your `do-app.yaml`:

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

Check the logs for successful registration:
```bash
doctl apps logs <app-id> | grep "control plane"
# {"level": "info", "message": "Connected to control plane", "instance_id": "..."}
```

Or in the DO Console: **Apps** → **aiproxyguard** → **Runtime Logs**

---

## Update Your Apps

Point your applications to use the proxy:

**Environment variable:**
```bash
OPENAI_BASE_URL=https://aiproxyguard-xxxxx.ondigitalocean.app/openai/v1
```

**In code:**
```python
from openai import OpenAI

client = OpenAI(
    base_url="https://aiproxyguard-xxxxx.ondigitalocean.app/openai/v1",
    api_key=os.environ["OPENAI_API_KEY"]
)
```

---

## Advanced Configuration

### Internal Network

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

### Custom Configuration

**Via environment variables:**

Add `AIPROXYGUARD_CONFIG` in the app settings:

```yaml
server:
  port: 8080
scanner:
  enabled: true
policy:
  default_action: block
```

**Via forked repository:**

Fork the repo, customize `config.docker.yaml`, then deploy from your repo using One-Click Deploy.

### Scaling

| Traffic Level | Instances | Size | Monthly Cost |
|---------------|-----------|------|--------------|
| Development | 1 | basic-xxs | $5 |
| Small Prod | 1 | basic-xs | $10 |
| Medium Prod | 2 | basic-s | $24 |
| Large Prod | 3+ | basic-m | $60+ |

In your app settings or `do-app.yaml`:
```yaml
services:
  - name: proxy
    instance_count: 3
    instance_size_slug: basic-s
```

### Custom Domain

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

3. Update the app:
   ```bash
   doctl apps update <app-id> --spec do-app.yaml
   ```

---

## Monitoring

**View logs (CLI):**
```bash
doctl apps logs <app-id> --follow
```

**View logs (Console):**
1. Go to Apps → aiproxyguard → Runtime Logs

**View metrics:**
1. Go to Apps → aiproxyguard → Insights
2. View CPU, Memory, Request metrics

**Prometheus integration:**

The proxy exposes `/metrics`. Configure scrape target:
```yaml
scrape_configs:
  - job_name: 'aiproxyguard'
    static_configs:
      - targets: ['proxy.aiproxyguard.internal:8080']
```

---

## Alerts

Set up alerts in DO Console:

1. Apps → aiproxyguard → Alerts
2. Add alerts for:
   - High error rate (> 5%)
   - High latency (p95 > 1s)
   - Instance restarts

---

## Troubleshooting

### App Won't Start

Check logs:
```bash
doctl apps logs <app-id>
```

Common issues:
- Image pull failed → Check GHCR/Docker Hub is accessible
- Health check failing → Verify `/healthz` returns 200

### Requests Timing Out

- Increase `instance_size_slug`
- Check upstream timeout in config
- Verify network connectivity to OpenAI/Anthropic

### High Latency

- Scanner timeout may be too high
- Consider `basic-s` or larger instances
- Check if many requests are being blocked (high scan time)

---

## Next Steps

1. [Configure custom detection policies](../configuration)
2. [Set up Prometheus monitoring](../deployment#with-prometheus)
3. [Enable response scanning](../security#response-scanning)
