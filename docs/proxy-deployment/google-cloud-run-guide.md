---
title: Google Cloud Run
parent: Proxy Deployment
nav_order: 5
---

# Google Cloud Run Deployment Guide

Deploy AIProxyGuard on Google Cloud Run as an LLM security proxy.

| Option | Best For |
|--------|----------|
| [1. One-Click Deploy](#option-1-one-click-deploy-easiest) | Quick start |
| [2. Cloud Console](#option-2-cloud-console) | Visual interface, more control |
| [3. gcloud CLI](#option-3-gcloud-cli) | Automation, CI/CD |

## Option 1: One-Click Deploy (Easiest)

[![Run on Google Cloud](https://deploy.cloud.run/button.svg)](https://deploy.cloud.run?git_repo=https://github.com/AInvirion/aiproxyguard)

1. Click the button above
2. Select your Google Cloud project
3. Choose a region
4. Click **Deploy**
5. Wait for deployment (~2-3 minutes)

Once deployed, copy your service URL and test:
```bash
curl https://aiproxyguard-xxxxx-uc.a.run.app/healthz
```

**Want fleet management?** After deployment, add the control plane environment variables. See [Connect to Control Plane](#connect-to-control-plane-recommended) for details.

---

## Option 2: Cloud Console

Deploy using the Google Cloud Console web interface.

### Step 1: Create Service

1. Go to [console.cloud.google.com/run](https://console.cloud.google.com/run)
2. Click **Create Service**

### Step 2: Configure Container

1. Select **Deploy one revision from an existing container image**
2. **Container image URL**: `ghcr.io/ainvirion/aiproxyguard:latest`

> **Docker Hub alternative:** Use `docker.io/ovalenzuela/aiproxyguard:latest`

### Step 3: Configure Service

1. **Service name**: `aiproxyguard`
2. **Region**: Select closest to your apps (e.g., `us-central1`)
3. **CPU allocation**: **CPU is only allocated during request processing** (recommended for cost savings)

### Step 4: Configure Authentication

1. Under **Authentication**, select **Allow unauthenticated invocations**

### Step 5: Container Settings

Click **Container, Networking, Security** to expand, then:

1. **Container port**: `8080`
2. **Memory**: `512 MiB` (can increase if needed)
3. **CPU**: `1`
4. **Request timeout**: `300` seconds
5. **Maximum concurrent requests per instance**: `80`

### Step 6: Environment Variables (Optional)

Under **Variables & Secrets**, click **Add Variable**:

| Name | Value |
|------|-------|
| `AIPROXYGUARD_LOG_LEVEL` | `info` |

**Want fleet management?** Add the control plane environment variables to get automatic signature updates, analytics, and fleet management. See [Connect to Control Plane](#connect-to-control-plane-recommended) for details.

### Step 7: Deploy

1. Click **Create**
2. Wait for deployment (~1-2 minutes)

### Step 8: Get Your URL

Once deployed, copy your service URL from the console:
```
https://aiproxyguard-xxxxx-uc.a.run.app
```

**Test it:**
```bash
curl https://aiproxyguard-xxxxx-uc.a.run.app/healthz
# {"status": "healthy"}
```

---

## Option 3: gcloud CLI

Best for automation and CI/CD pipelines.

### Prerequisites

Install and authenticate gcloud CLI:
```bash
# Install
brew install google-cloud-sdk  # macOS
# or: curl https://sdk.cloud.google.com | bash  # Linux

# Login and set project
gcloud auth login
gcloud config set project YOUR_PROJECT_ID
```

### Quick Deploy (One Command)

```bash
gcloud run deploy aiproxyguard \
  --image ghcr.io/ainvirion/aiproxyguard:latest \
  --port 8080 \
  --region us-central1 \
  --allow-unauthenticated
```

> **Docker Hub:** Use `docker.io/ovalenzuela/aiproxyguard:latest`

### With All Options

```bash
gcloud run deploy aiproxyguard \
  --image ghcr.io/ainvirion/aiproxyguard:latest \
  --port 8080 \
  --region us-central1 \
  --allow-unauthenticated \
  --memory 512Mi \
  --cpu 1 \
  --timeout 300 \
  --concurrency 80 \
  --min-instances 0 \
  --max-instances 10
```

### Get the URL

```bash
gcloud run services describe aiproxyguard \
  --region us-central1 \
  --format 'value(status.url)'
```

**Want fleet management?** Add environment variables to your deployment. See [Connect to Control Plane](#connect-to-control-plane-recommended) for the CLI configuration.

---

## Test Your Deployment

```bash
# Health check
curl https://aiproxyguard-xxxxx-uc.a.run.app/healthz
# {"status": "healthy"}

# Test with OpenAI
curl -X POST https://aiproxyguard-xxxxx-uc.a.run.app/openai/v1/chat/completions \
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

**Via Cloud Console:**

1. Go to [Cloud Run](https://console.cloud.google.com/run)
2. Click on your service → **Edit & Deploy New Revision**
3. Expand **Variables & Secrets**
4. Add environment variables:

| Name | Value |
|------|-------|
| `AIPROXYGUARD_CONTROL_PLANE_ENABLED` | `true` |
| `AIPROXYGUARD_CONTROL_PLANE_URL` | `https://aiproxyguard.com` |
| `AIPROXYGUARD_CONTROL_PLANE_API_KEY` | `your-api-key-here` |

5. Click **Deploy**

**Via gcloud CLI:**

```bash
gcloud run services update aiproxyguard \
  --region us-central1 \
  --set-env-vars \
    AIPROXYGUARD_CONTROL_PLANE_ENABLED=true,\
    AIPROXYGUARD_CONTROL_PLANE_URL=https://aiproxyguard.com,\
    AIPROXYGUARD_CONTROL_PLANE_API_KEY=your-api-key-here
```

**Using Secret Manager (recommended for API keys):**

```bash
# Create secret
echo -n "your-api-key-here" | gcloud secrets create aiproxyguard-api-key --data-file=-

# Grant access to Cloud Run
gcloud secrets add-iam-policy-binding aiproxyguard-api-key \
  --member="serviceAccount:YOUR_PROJECT_NUMBER-compute@developer.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"

# Deploy with secret
gcloud run services update aiproxyguard \
  --region us-central1 \
  --set-env-vars AIPROXYGUARD_CONTROL_PLANE_ENABLED=true \
  --set-env-vars AIPROXYGUARD_CONTROL_PLANE_URL=https://aiproxyguard.com \
  --set-secrets AIPROXYGUARD_CONTROL_PLANE_API_KEY=aiproxyguard-api-key:latest
```

### Step 3: Verify Registration

View logs in Cloud Console:
1. Go to Cloud Run → your service → **Logs**
2. Look for: `Connected to control plane`

Or via CLI:
```bash
gcloud run services logs read aiproxyguard --region us-central1 --limit 50
```

---

## Update Your Apps

Point your applications to use the proxy:

**Environment variable:**
```bash
OPENAI_BASE_URL=https://aiproxyguard-xxxxx-uc.a.run.app/openai/v1
```

**In code:**
```python
from openai import OpenAI

client = OpenAI(
    base_url="https://aiproxyguard-xxxxx-uc.a.run.app/openai/v1",
    api_key=os.environ["OPENAI_API_KEY"]
)
```

---

## Advanced Configuration

### Health Checks

Cloud Run automatically checks your container starts and listens on the configured port. For custom health checks:

1. Go to service → **Edit & Deploy New Revision**
2. Expand **Container** section
3. Configure **Startup probe**:
   - **Type**: HTTP
   - **Path**: `/healthz`
   - **Initial delay**: 0 seconds
   - **Timeout**: 240 seconds

### Scaling

```bash
gcloud run services update aiproxyguard \
  --region us-central1 \
  --min-instances 1 \
  --max-instances 10 \
  --cpu 2 \
  --memory 1Gi
```

| Traffic Level | Min/Max Instances | CPU | Memory |
|---------------|-------------------|-----|--------|
| Development | 0/1 | 1 | 512Mi |
| Small Prod | 1/5 | 1 | 512Mi |
| Medium Prod | 1/10 | 2 | 1Gi |
| Large Prod | 2/20 | 2 | 2Gi |

### Custom Domain

**Via Cloud Console:**
1. Go to Cloud Run → **Manage Custom Domains**
2. Click **Add Mapping**
3. Select your service
4. Enter domain: `proxy.yourdomain.com`
5. Add the DNS records shown

**Via gcloud CLI:**
```bash
gcloud run domain-mappings create \
  --service aiproxyguard \
  --domain proxy.yourdomain.com \
  --region us-central1
```

Add DNS records as instructed (CNAME or A record depending on domain type).

---

## Monitoring

**View logs (Console):**
1. Go to Cloud Run → your service → **Logs**

**View logs (CLI):**
```bash
gcloud run services logs read aiproxyguard \
  --region us-central1 \
  --limit 100
```

**Metrics:**
1. Go to Cloud Run → your service → **Metrics**
2. View Request count, Latency, Container instances, CPU/Memory utilization

---

## Troubleshooting

### Deployment Failed

Check build/deploy logs:
```bash
gcloud run services logs read aiproxyguard --region us-central1
```

Common issues:
- Image pull failed → Verify image URL is correct and public
- Container failed to start → Check port is `8080`

### Container Not Starting

- Ensure container listens on `0.0.0.0:$PORT` (read PORT env var)
- Default timeout is 240 seconds for startup
- Check logs for startup errors

### High Latency

- Increase min-instances to avoid cold starts
- Increase CPU/memory allocation
- Check region proximity to OpenAI/Anthropic

### Cold Starts

For low-latency requirements:
```bash
gcloud run services update aiproxyguard \
  --region us-central1 \
  --min-instances 1
```

---

## Cleanup

Delete the service:
```bash
gcloud run services delete aiproxyguard --region us-central1
```

---

## Next Steps

1. [Configure custom detection policies](../configuration)
2. [Set up monitoring](../deployment#monitoring)
3. [Enable response scanning](../security#response-scanning)
