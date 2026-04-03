---
title: Proxy Deployment
nav_order: 5
has_children: true
---

# Proxy Deployment

Deploy the AIProxyGuard proxy for self-hosted prompt injection detection.

> **Don't want to manage infrastructure?** Use the [Cloud API](https://aiproxyguard.com) directly with our [SDKs](../sdks/) - no proxy deployment required.

## Deployment Options

| Platform | Best For | Guide |
|----------|----------|-------|
| [Docker](docker) | Local development, simple deployments | Quick start |
| [DigitalOcean](digitalocean-guide) | Small-medium production | App Platform |
| [AWS Lightsail](aws-lightsail-guide) | AWS ecosystem | Container Service |
| [Azure Container Apps](azure-container-apps-guide) | Azure ecosystem | Serverless containers |
| [Google Cloud Run](google-cloud-run-guide) | GCP ecosystem | Serverless |
| [Railway](railway-guide) | Startups, quick deploys | One-click deploy |

## Health Endpoints

All deployments should configure health checks:

| Endpoint | Purpose | Response |
|----------|---------|----------|
| `GET /healthz` | Liveness | `{"status": "healthy"}` |
| `GET /readyz` | Readiness | `{"status": "ready", ...}` |
| `GET /metrics` | Prometheus | Prometheus text format |

## Resource Sizing

| Traffic | Memory | Notes |
|---------|--------|-------|
| < 100 req/min | 512 MB | Development |
| 100-1000 req/min | 1 GB | Small production |
| 1000-10000 req/min | 2 GB | Medium production |
| > 10000 req/min | 2+ GB × N instances | Scale horizontally |
