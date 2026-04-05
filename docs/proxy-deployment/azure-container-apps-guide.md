---
title: Azure Container Apps
parent: Proxy Deployment
nav_order: 4
---

# Azure Container Apps Deployment Guide

Deploy AIProxyGuard on Azure Container Apps as an LLM security proxy.

| Option | Best For |
|--------|----------|
| [1. Azure Portal (Recommended)](#option-1-azure-portal-recommended) | Simple setup, visual interface |
| [2. Azure CLI](#option-2-azure-cli) | Automation, CI/CD |

## Option 1: Azure Portal (Recommended)

Deploy using the Azure Portal web interface.

### Step 1: Create Container App

1. Go to [portal.azure.com](https://portal.azure.com)
2. Search for **Container Apps** in the top search bar
3. Click **Create** → **Container App**

### Step 2: Configure Basics

1. **Subscription**: Select your Azure subscription
2. **Resource group**: Create new or select existing
3. **Container app name**: `aiproxyguard`
4. **Region**: Select closest to your apps

### Step 3: Create Container Apps Environment

1. Click **Create new** under Container Apps Environment
2. Enter environment name: `aiproxyguard-env`
3. Leave other settings as default
4. Click **Create**

### Step 4: Configure Container

1. Uncheck **Use quickstart image**
2. **Image source**: Select **Docker Hub or other registries**
3. **Image and tag**: `ghcr.io/ainvirion/aiproxyguard:latest`

> **Docker Hub alternative:** Use `docker.io/ainvirion/aiproxyguard:latest`

### Step 5: Configure Ingress

1. Check **Enabled** for Ingress
2. **Ingress traffic**: Select **Accepting traffic from anywhere**
3. **Ingress type**: HTTP
4. **Target port**: `8080`

### Step 6: Environment Variables (Optional)

Click **Environment variables** and add:

| Name | Value |
|------|-------|
| `AIPROXYGUARD_LOG_LEVEL` | `info` |

**Want fleet management?** Add the control plane environment variables to get automatic signature updates, analytics, and fleet management. See [Connect to Control Plane](#connect-to-control-plane-recommended) for details.

### Step 7: Review and Create

1. Click **Review + create**
2. Review settings
3. Click **Create**
4. Wait for deployment (~2-5 minutes)

### Step 8: Get Your URL

Once deployed:
1. Go to your Container App resource
2. Find the **Application Url** on the Overview page

```
https://aiproxyguard.xxx.azurecontainerapps.io
```

**Test it:**
```bash
curl https://aiproxyguard.xxx.azurecontainerapps.io/healthz
# {"status": "healthy"}
```

---

## Option 2: Azure CLI

Best for automation and CI/CD pipelines.

### Prerequisites

Install and authenticate Azure CLI:
```bash
# Install
brew install azure-cli  # macOS
# or: curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash  # Linux

# Login
az login
```

### Quick Deploy (One Command)

The fastest way to deploy:

```bash
az containerapp up \
  --name aiproxyguard \
  --resource-group aiproxyguard-rg \
  --image ghcr.io/ainvirion/aiproxyguard:latest \
  --target-port 8080 \
  --ingress external \
  --location eastus
```

This automatically creates the resource group, environment, and deploys the app.

### Step-by-Step Deploy

For more control:

**1. Create resource group:**
```bash
az group create \
  --name aiproxyguard-rg \
  --location eastus
```

**2. Create Container Apps environment:**
```bash
az containerapp env create \
  --name aiproxyguard-env \
  --resource-group aiproxyguard-rg \
  --location eastus
```

**3. Deploy the container:**
```bash
az containerapp create \
  --name aiproxyguard \
  --resource-group aiproxyguard-rg \
  --environment aiproxyguard-env \
  --image ghcr.io/ainvirion/aiproxyguard:latest \
  --target-port 8080 \
  --ingress external \
  --query properties.configuration.ingress.fqdn \
  --output tsv
```

> **Docker Hub:** Use `docker.io/ainvirion/aiproxyguard:latest`

### Get the URL

```bash
az containerapp show \
  --name aiproxyguard \
  --resource-group aiproxyguard-rg \
  --query properties.configuration.ingress.fqdn \
  --output tsv
```

**Want fleet management?** Add environment variables to your deployment. See [Connect to Control Plane](#connect-to-control-plane-recommended) for the CLI configuration.

---

## Test Your Deployment

```bash
# Health check
curl https://aiproxyguard.xxx.azurecontainerapps.io/healthz
# {"status": "healthy"}

# Test with OpenAI
curl -X POST https://aiproxyguard.xxx.azurecontainerapps.io/openai/v1/chat/completions \
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

**Via Azure Portal:**

1. Go to your Container App in [Azure Portal](https://portal.azure.com)
2. Click **Containers** → **Environment variables**
3. Add:

| Name | Value |
|------|-------|
| `AIPROXYGUARD_CONTROL_PLANE_ENABLED` | `true` |
| `AIPROXYGUARD_CONTROL_PLANE_URL` | `https://aiproxyguard.com` |
| `AIPROXYGUARD_CONTROL_PLANE_API_KEY` | `your-api-key-here` |

4. Click **Save** → Creates new revision automatically

**Via Azure CLI:**

```bash
az containerapp update \
  --name aiproxyguard \
  --resource-group aiproxyguard-rg \
  --set-env-vars \
    AIPROXYGUARD_CONTROL_PLANE_ENABLED=true \
    AIPROXYGUARD_CONTROL_PLANE_URL=https://aiproxyguard.com \
    AIPROXYGUARD_CONTROL_PLANE_API_KEY=your-api-key-here
```

**For secrets (recommended for API keys):**

```bash
# Create secret
az containerapp secret set \
  --name aiproxyguard \
  --resource-group aiproxyguard-rg \
  --secrets control-plane-key=your-api-key-here

# Reference in env var
az containerapp update \
  --name aiproxyguard \
  --resource-group aiproxyguard-rg \
  --set-env-vars \
    AIPROXYGUARD_CONTROL_PLANE_ENABLED=true \
    AIPROXYGUARD_CONTROL_PLANE_URL=https://aiproxyguard.com \
    AIPROXYGUARD_CONTROL_PLANE_API_KEY=secretref:control-plane-key
```

### Step 3: Verify Registration

View logs in Azure Portal:
1. Go to Container App → **Log stream**
2. Look for: `Connected to control plane`

Or via CLI:
```bash
az containerapp logs show \
  --name aiproxyguard \
  --resource-group aiproxyguard-rg \
  --follow
```

---

## Update Your Apps

Point your applications to use the proxy:

**Environment variable:**
```bash
OPENAI_BASE_URL=https://aiproxyguard.xxx.azurecontainerapps.io/openai/v1
```

**In code:**
```python
from openai import OpenAI

client = OpenAI(
    base_url="https://aiproxyguard.xxx.azurecontainerapps.io/openai/v1",
    api_key=os.environ["OPENAI_API_KEY"]
)
```

---

## Advanced Configuration

### Health Checks

Configure health probes for better reliability:

```bash
az containerapp update \
  --name aiproxyguard \
  --resource-group aiproxyguard-rg \
  --set-probe livenessProbe \
  --probe-type http \
  --probe-path /healthz \
  --probe-port 8080 \
  --initial-delay 10 \
  --interval-seconds 30 \
  --timeout-seconds 5
```

### Scaling

```bash
az containerapp update \
  --name aiproxyguard \
  --resource-group aiproxyguard-rg \
  --min-replicas 1 \
  --max-replicas 5 \
  --cpu 0.5 \
  --memory 1.0Gi
```

| Traffic Level | Min/Max Replicas | CPU | Memory |
|---------------|------------------|-----|--------|
| Development | 0/1 | 0.25 | 0.5Gi |
| Small Prod | 1/2 | 0.5 | 1Gi |
| Medium Prod | 1/5 | 1 | 2Gi |
| Large Prod | 2/10 | 2 | 4Gi |

### Custom Domain

**Via Portal:**
1. Go to Container App → **Custom domains**
2. Click **Add custom domain**
3. Enter domain: `proxy.yourdomain.com`
4. Select **Managed certificate** (free, auto-renewed)
5. Add DNS records as instructed

**Via CLI:**
```bash
az containerapp hostname add \
  --name aiproxyguard \
  --resource-group aiproxyguard-rg \
  --hostname proxy.yourdomain.com
```

Add CNAME record in your DNS:
```
proxy.yourdomain.com → aiproxyguard.xxx.azurecontainerapps.io
```

---

## Monitoring

**View logs (Portal):**
1. Go to Container App → **Log stream**

**View logs (CLI):**
```bash
az containerapp logs show \
  --name aiproxyguard \
  --resource-group aiproxyguard-rg \
  --follow
```

**Metrics:**
1. Go to Container App → **Metrics**
2. View CPU, Memory, Requests, Response time

---

## Troubleshooting

### Deployment Failed

Check logs:
```bash
az containerapp logs show \
  --name aiproxyguard \
  --resource-group aiproxyguard-rg
```

Common issues:
- Image pull failed → Verify image URL
- Health check failing → Ensure `/healthz` returns 200 on port 8080

### Container Not Starting

- Verify target port is `8080`
- Check container listens on `0.0.0.0:8080` not `localhost:8080`

### High Latency

- Increase CPU/memory allocation
- Add more replicas
- Check region proximity to OpenAI/Anthropic

---

## Cleanup

Delete all resources:
```bash
az group delete --name aiproxyguard-rg --yes
```

---

## Next Steps

1. [Configure custom detection policies](../configuration)
2. [Set up monitoring](../deployment#monitoring)
3. [Enable response scanning](../security#response-scanning)
