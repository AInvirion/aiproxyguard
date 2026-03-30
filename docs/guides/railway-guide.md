---
title: Railway
parent: Guides
nav_order: 5
---

# Railway Deployment Guide

Deploy AIProxyGuard on Railway as an LLM security proxy. Railway is popular with startups for its developer-friendly experience and simple pricing.

| Option | Best For | Cost |
|--------|----------|------|
| [1. Dashboard (Recommended)](#option-1-dashboard-recommended) | Simple setup, visual interface | $5/mo Hobby |
| [2. Railway CLI](#option-2-railway-cli) | Automation, CI/CD | $5/mo Hobby |

## Option 1: Dashboard (Recommended)

Deploy using the Railway web dashboard.

### Step 1: Create Project

1. Go to [railway.app](https://railway.app) and sign in
2. Click **New Project**

### Step 2: Add Docker Image

1. Click **Add a Service** on the Project Canvas
2. Select **Docker Image**
3. Enter the image URL: `ghcr.io/ainvirion/aiproxyguard:latest`

> **Docker Hub alternative:** Use `ovalenzuela/aiproxyguard:latest`

4. Press **Enter** and click **Deploy**

### Step 3: Configure Port

1. Click on your service to open settings
2. Go to **Settings** tab
3. Under **Networking**, click **Generate Domain**
4. Set **Port**: `8080`

### Step 4: Environment Variables (Optional)

1. Go to **Variables** tab
2. Click **New Variable** and add:

| Name | Value |
|------|-------|
| `PORT` | `8080` |
| `AIPROXYGUARD_LOG_LEVEL` | `info` |

**Want fleet management?** Add the control plane environment variables to get automatic signature updates, analytics, and fleet management. See [Connect to Control Plane](#connect-to-control-plane-recommended) for details.

### Step 5: Deploy

Railway automatically deploys when you add variables. Wait ~1-2 minutes.

### Step 6: Get Your URL

Find your URL in **Settings** → **Networking**:
```
https://aiproxyguard-production-xxxx.up.railway.app
```

**Test it:**
```bash
curl https://aiproxyguard-production-xxxx.up.railway.app/healthz
# {"status": "healthy"}
```

---

## Option 2: Railway CLI

Best for automation and CI/CD pipelines.

### Prerequisites

Install Railway CLI:
```bash
# macOS
brew install railway

# npm
npm install -g @railway/cli

# Login
railway login
```

### Step 1: Create Project

```bash
railway init
```

Select **Empty Project** when prompted.

### Step 2: Deploy Image

```bash
railway up --image ghcr.io/ainvirion/aiproxyguard:latest
```

> **Docker Hub:** Use `ovalenzuela/aiproxyguard:latest`

### Step 3: Configure Variables

```bash
railway variables set PORT=8080
railway variables set AIPROXYGUARD_LOG_LEVEL=info
```

### Step 4: Generate Domain

```bash
railway domain
```

### Step 5: Get URL

```bash
railway status
```

**Want fleet management?** Add environment variables via CLI. See [Connect to Control Plane](#connect-to-control-plane-recommended) for the configuration.

---

## Test Your Deployment

```bash
# Health check
curl https://aiproxyguard-production-xxxx.up.railway.app/healthz
# {"status": "healthy"}

# Test with OpenAI
curl -X POST https://aiproxyguard-production-xxxx.up.railway.app/openai/v1/chat/completions \
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

**Via Dashboard:**

1. Go to your service → **Variables** tab
2. Click **New Variable** and add:

| Name | Value |
|------|-------|
| `AIPROXYGUARD_CONTROL_PLANE_ENABLED` | `true` |
| `AIPROXYGUARD_CONTROL_PLANE_URL` | `https://aiproxyguard.com` |
| `AIPROXYGUARD_CONTROL_PLANE_API_KEY` | `your-api-key-here` |

3. Railway automatically redeploys

**Via CLI:**

```bash
railway variables set AIPROXYGUARD_CONTROL_PLANE_ENABLED=true
railway variables set AIPROXYGUARD_CONTROL_PLANE_URL=https://aiproxyguard.com
railway variables set AIPROXYGUARD_CONTROL_PLANE_API_KEY=your-api-key-here
railway redeploy
```

### Step 3: Verify Registration

View logs in Dashboard:
1. Go to your service → **Deployments**
2. Click on latest deployment → **View Logs**
3. Look for: `Connected to control plane`

Or via CLI:
```bash
railway logs
```

---

## Update Your Apps

Point your applications to use the proxy:

**Environment variable:**
```bash
OPENAI_BASE_URL=https://aiproxyguard-production-xxxx.up.railway.app/openai/v1
```

**In code:**
```python
from openai import OpenAI

client = OpenAI(
    base_url="https://aiproxyguard-production-xxxx.up.railway.app/openai/v1",
    api_key=os.environ["OPENAI_API_KEY"]
)
```

---

## Advanced Configuration

### Health Checks

1. Go to service **Settings**
2. Under **Deploy**, set **Health Check Path**: `/healthz`
3. Railway checks this endpoint and waits for HTTP 200 before routing traffic

Default timeout is 300 seconds (5 minutes).

### Custom Domain

1. Go to service **Settings** → **Networking**
2. Click **+ Custom Domain**
3. Enter your domain: `proxy.yourdomain.com`
4. Railway provides a CNAME value
5. Add CNAME record in your DNS provider:
   ```
   proxy.yourdomain.com → xxx.up.railway.app
   ```
6. Wait for DNS propagation and verification

Railway automatically provisions SSL certificates via Let's Encrypt.

### Scaling

Railway scales based on your plan limits:

| Plan | RAM | CPU | Best For |
|------|-----|-----|----------|
| Hobby ($5/mo) | 512MB | 0.5 vCPU | Development, small prod |
| Pro ($20/mo) | 8GB | 8 vCPU | Production, scaling |

To increase resources beyond defaults, upgrade to Pro plan in Project Settings.

---

## Monitoring

**View logs (Dashboard):**
1. Go to your service → **Deployments**
2. Click on deployment → **View Logs**

**View logs (CLI):**
```bash
railway logs --follow
```

**Metrics:**
1. Go to your service → **Metrics**
2. View CPU, Memory, Network usage

---

## Pricing

| Plan | Monthly | Included Credits | Best For |
|------|---------|------------------|----------|
| Free | $0 | $1 | Experimentation only |
| Hobby | $5 | $5 | Indie devs, small projects |
| Pro | $20 | $20 | Teams, production |

**Resource costs (beyond credits):**
- RAM: $10/GB per month
- CPU: $20/vCPU per month
- Network: $0.05/GB egress

**Hobby plan** is the sweet spot - $5/month covers most small production workloads.

---

## Troubleshooting

### Deployment Failed

Check build logs:
1. Go to service → **Deployments**
2. Click failed deployment → **View Logs**

Common issues:
- Image pull failed → Verify image URL is correct
- Health check failing → Ensure `/healthz` returns 200 on port 8080

### Container Not Starting

- Ensure `PORT` environment variable is set to `8080`
- Check container listens on `0.0.0.0:$PORT`
- Review deployment logs for errors

### Health Check Timeout

- Default timeout is 300 seconds
- Increase via `RAILWAY_HEALTHCHECK_TIMEOUT_SEC` env var
- Ensure your app starts within the timeout

### Domain Not Working

- Wait up to 72 hours for DNS propagation
- Verify CNAME record is correct
- Remove any AAAA (IPv6) records that might conflict

---

## Cleanup

Delete the project:
1. Go to **Project Settings** → **Danger Zone**
2. Click **Delete Project**

Or via CLI:
```bash
railway down
```

---

## Next Steps

1. [Configure custom detection policies](../configuration)
2. [Set up monitoring](../deployment#monitoring)
3. [Enable response scanning](../security#response-scanning)
