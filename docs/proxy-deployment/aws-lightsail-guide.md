---
title: AWS Lightsail
parent: Proxy Deployment
nav_order: 3
---

# AWS Lightsail Deployment Guide

Deploy AIProxyGuard on AWS Lightsail Container Service as an LLM security proxy.

| Option | Best For |
|--------|----------|
| [1. Container Service (Recommended)](#option-1-container-service-recommended) | Simple setup, managed containers |
| [2. AWS CLI](#option-2-aws-cli) | Automation, CI/CD |

## Option 1: Container Service (Recommended)

Deploy the pre-built container image using the Lightsail console.

### Step 1: Create Container Service

1. Go to [lightsail.aws.amazon.com](https://lightsail.aws.amazon.com)
2. Click **Containers** in the left menu
3. Click **Create container service**

### Step 2: Choose Capacity

1. Select your **AWS Region** (closest to your apps)
2. Choose your capacity:
   - **Nano** - 512 MB RAM, 0.25 vCPU - Development/testing
   - **Micro** - 1 GB RAM, 0.5 vCPU - Small production
   - **Small** - 2 GB RAM, 1 vCPU - Production
3. Choose **Scale**: 1 (can increase later)

### Step 3: Configure Deployment

1. Click **Set up deployment**
2. Choose **Specify a custom deployment**
3. Enter container settings:

| Field | Value |
|-------|-------|
| **Container name** | `aiproxyguard` |
| **Image** | `ghcr.io/ainvirion/aiproxyguard:latest` |

> **Docker Hub alternative:** Use `ainvirion/aiproxyguard:latest`

4. Click **Add open port**:
   - **Port**: `8080`
   - **Protocol**: `HTTP`

5. Under **Health check**:
   - **Path**: `/healthz`

### Step 4: Environment Variables (Optional)

Click **Add environment variable** for basic setup:

| Key | Value |
|-----|-------|
| `AIPROXYGUARD_LOG_LEVEL` | `info` |

**Want fleet management?** Add the control plane environment variables to get automatic signature updates, analytics, and fleet management. See [Connect to Control Plane](#connect-to-control-plane-recommended) for details.

### Step 5: Configure Public Endpoint

1. Under **Public endpoint**, select your container: `aiproxyguard`
2. Port will auto-fill to `8080`

### Step 6: Create Service

1. Enter a service name: `aiproxyguard`
2. Click **Create container service**
3. Wait for deployment (~3-5 minutes)

### Step 7: Get Your URL

Once the status shows **Running**, find your public URL:
```
https://aiproxyguard.xxxxx.us-east-1.cs.amazonlightsail.com
```

**Test it:**
```bash
curl https://aiproxyguard.xxxxx.us-east-1.cs.amazonlightsail.com/healthz
# {"status": "healthy"}
```

---

## Option 2: AWS CLI

Best for automation, CI/CD pipelines, or repeatable deployments.

### Prerequisites

Install and configure AWS CLI:
```bash
# Install
brew install awscli  # macOS
# or: pip install awscli

# Configure
aws configure
```

### Step 1: Create Container Service

```bash
aws lightsail create-container-service \
  --service-name aiproxyguard \
  --power nano \
  --scale 1 \
  --region us-east-1
```

Power options: `nano`, `micro`, `small`, `medium`, `large`, `xlarge`

### Step 2: Wait for Service to be Ready

```bash
aws lightsail get-container-services --service-name aiproxyguard \
  --query 'containerServices[0].state'
```

Wait until state is `READY` (takes 1-2 minutes).

### Step 3: Create Deployment

Create `deployment.json`:

```json
{
  "containers": {
    "aiproxyguard": {
      "image": "ghcr.io/ainvirion/aiproxyguard:latest",
      "ports": {
        "8080": "HTTP"
      },
      "environment": {
        "AIPROXYGUARD_LOG_LEVEL": "info"
      }
    }
  },
  "publicEndpoint": {
    "containerName": "aiproxyguard",
    "containerPort": 8080,
    "healthCheck": {
      "path": "/healthz",
      "intervalSeconds": 30,
      "timeoutSeconds": 5,
      "healthyThreshold": 2,
      "unhealthyThreshold": 2
    }
  }
}
```

Deploy:
```bash
aws lightsail create-container-service-deployment \
  --service-name aiproxyguard \
  --cli-input-json file://deployment.json
```

### Step 4: Get the URL

```bash
aws lightsail get-container-services --service-name aiproxyguard \
  --query 'containerServices[0].url' --output text
```

**Want fleet management?** Add the control plane environment variables to your deployment.json. See [Connect to Control Plane](#connect-to-control-plane-recommended) for the configuration.

---

## Test Your Deployment

```bash
# Health check
curl https://aiproxyguard.xxxxx.us-east-1.cs.amazonlightsail.com/healthz
# {"status": "healthy"}

# Test with OpenAI
curl -X POST https://aiproxyguard.xxxxx.us-east-1.cs.amazonlightsail.com/openai/v1/chat/completions \
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

**For Console deployments:**

1. Go to your container service in [Lightsail Console](https://lightsail.aws.amazon.com)
2. Click **Deployments** tab
3. Click **Modify your deployment**
4. Add environment variables:

| Key | Value |
|-----|-------|
| `AIPROXYGUARD_CONTROL_PLANE_ENABLED` | `true` |
| `AIPROXYGUARD_CONTROL_PLANE_URL` | `https://aiproxyguard.com` |
| `AIPROXYGUARD_CONTROL_PLANE_API_KEY` | `your-api-key-here` |

5. Click **Save and deploy**

**For CLI deployments:**

Update your `deployment.json`:

```json
{
  "containers": {
    "aiproxyguard": {
      "image": "ghcr.io/ainvirion/aiproxyguard:latest",
      "ports": {
        "8080": "HTTP"
      },
      "environment": {
        "AIPROXYGUARD_LOG_LEVEL": "info",
        "AIPROXYGUARD_CONTROL_PLANE_ENABLED": "true",
        "AIPROXYGUARD_CONTROL_PLANE_URL": "https://aiproxyguard.com",
        "AIPROXYGUARD_CONTROL_PLANE_API_KEY": "your-api-key-here"
      }
    }
  },
  "publicEndpoint": {
    "containerName": "aiproxyguard",
    "containerPort": 8080,
    "healthCheck": {
      "path": "/healthz"
    }
  }
}
```

Redeploy:
```bash
aws lightsail create-container-service-deployment \
  --service-name aiproxyguard \
  --cli-input-json file://deployment.json
```

### Step 3: Verify Registration

Check the logs:
```bash
aws lightsail get-container-log \
  --service-name aiproxyguard \
  --container-name aiproxyguard
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
OPENAI_BASE_URL=https://aiproxyguard.xxxxx.us-east-1.cs.amazonlightsail.com/openai/v1
```

**In code:**
```python
from openai import OpenAI

client = OpenAI(
    base_url="https://aiproxyguard.xxxxx.us-east-1.cs.amazonlightsail.com/openai/v1",
    api_key=os.environ["OPENAI_API_KEY"]
)
```

---

## Advanced Configuration

### Custom Domain

1. In Lightsail Console, go to your container service
2. Click **Custom domains** tab
3. Click **Create certificate**
4. Enter your domain: `proxy.yourdomain.com`
5. Validate via DNS (add the CNAME records shown)
6. Once validated, click **Attach certificate**
7. Add a CNAME record in your DNS:
   ```
   proxy.yourdomain.com → aiproxyguard.xxxxx.us-east-1.cs.amazonlightsail.com
   ```

### Scaling

**Via Console:**
1. Go to your container service
2. Click **Capacity** tab
3. Adjust **Power** and **Scale**
4. Click **Save and deploy**

**Via CLI:**
```bash
aws lightsail update-container-service \
  --service-name aiproxyguard \
  --power small \
  --scale 2
```

| Traffic Level | Power | Scale |
|---------------|-------|-------|
| Development | nano | 1 |
| Small Prod | micro | 1 |
| Medium Prod | small | 2 |
| Large Prod | medium | 3 |

### Private Deployment (VPC)

Lightsail container services are public by default. For private deployments within AWS:

1. Consider using **AWS App Runner** or **ECS Fargate** instead
2. Or deploy on a Lightsail Instance with Docker (see [Deployment Guide](../deployment))

---

## Monitoring

**View logs (Console):**
1. Go to your container service
2. Click **Deployments** tab
3. Click **Open log** next to your container

**View logs (CLI):**
```bash
aws lightsail get-container-log \
  --service-name aiproxyguard \
  --container-name aiproxyguard
```

**Metrics:**
1. Go to your container service
2. Click **Metrics** tab
3. View CPU, Memory utilization

---

## Troubleshooting

### Deployment Failed

Check deployment status:
```bash
aws lightsail get-container-services --service-name aiproxyguard \
  --query 'containerServices[0].currentDeployment'
```

Common issues:
- Image pull failed → Check image name and registry access
- Health check failing → Verify `/healthz` path and port `8080`

### Container Won't Start

View logs:
```bash
aws lightsail get-container-log \
  --service-name aiproxyguard \
  --container-name aiproxyguard \
  --filter-pattern "error"
```

### High Latency

- Upgrade to a higher power tier
- Increase scale for more instances
- Check if region is far from OpenAI/Anthropic endpoints

---

## Cleanup

To delete the container service:

**Console:**
1. Go to your container service
2. Click **Delete** tab
3. Click **Delete container service**

**CLI:**
```bash
aws lightsail delete-container-service --service-name aiproxyguard
```

---

## Next Steps

1. [Configure custom detection policies](../configuration)
2. [Set up monitoring](../deployment#monitoring)
3. [Enable response scanning](../security#response-scanning)
