---
title: DigitalOcean
parent: Guides
nav_order: 1
---

# DigitalOcean Deployment Guide

This guide walks through deploying AIProxyGuard on DigitalOcean App Platform so your DO apps can use it as an LLM security proxy.

## Overview

```
┌─────────────────────────────────────────────────────────┐
│                  DigitalOcean                            │
│                                                          │
│  ┌──────────────┐     ┌──────────────┐                  │
│  │   Your App   │────▶│ AIProxyGuard │────▶ OpenAI/etc  │
│  │  (DO App)    │     │  (DO App)    │                  │
│  └──────────────┘     └──────────────┘                  │
│         │                    │                           │
│         └────────────────────┘                           │
│            Internal network                              │
└─────────────────────────────────────────────────────────┘
```

## Prerequisites

1. DigitalOcean account
2. `doctl` CLI installed and authenticated:
   ```bash
   brew install doctl  # macOS
   doctl auth init
   ```

## Option 1: App Platform (Recommended)

> **Image:** Uses `ghcr.io/ainvirion/aiproxyguard`. Alternative: Docker Hub with `registry_type: DOCKER_HUB`, `registry: ovalenzuela`

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

### Step 2: Deploy

```bash
doctl apps create --spec do-app.yaml
```

### Step 3: Get the URL

```bash
doctl apps list
```

Note the URL like: `https://aiproxyguard-xxxxx.ondigitalocean.app`

### Step 4: Test

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

### Step 5: Update Your Apps

In your DigitalOcean apps, add an environment variable:

```bash
OPENAI_BASE_URL=https://aiproxyguard-xxxxx.ondigitalocean.app/openai/v1
```

Or in your code:

```python
from openai import OpenAI

client = OpenAI(
    base_url="https://aiproxyguard-xxxxx.ondigitalocean.app/openai/v1",
    api_key=os.environ["OPENAI_API_KEY"]
)
```

## Option 2: Internal Network (More Secure)

For production, keep the proxy internal and not exposed to the internet.

### Step 1: Create App Spec with Internal Routing

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
    instance_size_slug: basic-xxs
    http_port: 8080
    internal_ports:
      - 8080  # Only accessible within DO network
    health_check:
      http_path: /healthz
```

### Step 2: Access from Other DO Apps

Other apps in the same region can access via internal URL:
```
http://proxy.aiproxyguard.internal:8080
```

## Custom Configuration

### Method 1: Environment Variables

```yaml
services:
  - name: proxy
    # ...
    envs:
      - key: AIPROXYGUARD_CONFIG
        value: |
          server:
            port: 8080
          upstreams:
            openai:
              url: https://api.openai.com
          scanner:
            enabled: true
          policy:
            default_action: block
```

### Method 2: Build from Repository

Fork the repo and customize `config.docker.yaml`, then deploy from your repo:

```yaml
services:
  - name: proxy
    github:
      repo: your-username/aiproxyguard
      branch: main
    dockerfile_path: Dockerfile
    http_port: 8080
```

## Scaling

### Horizontal Scaling

```yaml
services:
  - name: proxy
    instance_count: 3
    instance_size_slug: basic-s  # $12/mo each
```

### Size Guide

| Traffic Level | Instances | Size | Monthly Cost |
|---------------|-----------|------|--------------|
| Development | 1 | basic-xxs | $5 |
| Small Prod | 1 | basic-xs | $10 |
| Medium Prod | 2 | basic-s | $24 |
| Large Prod | 3+ | basic-m | $60+ |

## Custom Domain

### Step 1: Add Domain to App Spec

```yaml
domains:
  - domain: proxy.yourdomain.com
    type: PRIMARY
```

### Step 2: Configure DNS

Add a CNAME record:
```
proxy.yourdomain.com → aiproxyguard-xxxxx.ondigitalocean.app
```

### Step 3: Update App

```bash
doctl apps update <app-id> --spec do-app.yaml
```

## Monitoring

### View Logs

```bash
doctl apps logs <app-id> --follow
```

### View Metrics in DO Console

1. Go to Apps → aiproxyguard → Insights
2. View CPU, Memory, Request metrics

### Prometheus Integration

The proxy exposes `/metrics`. To scrape:

1. Deploy Prometheus on DO
2. Configure scrape target:
   ```yaml
   scrape_configs:
     - job_name: 'aiproxyguard'
       static_configs:
         - targets: ['proxy.aiproxyguard.internal:8080']
   ```

## Alerts

Set up alerts in DO Console:

1. Apps → aiproxyguard → Alerts
2. Add alert for:
   - High error rate (> 5%)
   - High latency (p95 > 1s)
   - Instance restarts

## Complete Example

Here's a full `do-app.yaml` for production:

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
    instance_count: 2
    instance_size_slug: basic-s
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

alerts:
  - rule: DEPLOYMENT_FAILED
  - rule: DOMAIN_FAILED
  - rule: HTTP_RESPONSE_ERRORS_RATE
    value: 5
    window: FIVE_MINUTES
    operator: GREATER_THAN

domains:
  - domain: proxy.yourdomain.com
    type: PRIMARY
```

Deploy:

```bash
doctl apps create --spec do-app.yaml
```

## Troubleshooting

### App Won't Start

Check logs:
```bash
doctl apps logs <app-id>
```

Common issues:
- Image pull failed → Check GHCR is accessible
- Health check failing → Verify `/healthz` returns 200

### Requests Timing Out

- Increase `instance_size_slug`
- Check upstream timeout in config
- Verify network connectivity to OpenAI/Anthropic

### High Latency

- Scanner timeout may be too high
- Consider `basic-s` or larger instances
- Check if many requests are being blocked (high scan time)

## Next Steps

1. [Configure custom detection policies](configuration.md)
2. [Set up Prometheus monitoring](deployment.md#with-prometheus)
3. [Enable response scanning](security.md#response-scanning)
