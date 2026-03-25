---
title: Home
---

# AIProxyGuard

LLM Security Proxy with Prompt Injection Detection.

## What is AIProxyGuard?

AIProxyGuard is a security proxy that sits between your application and LLM providers (OpenAI, Anthropic, etc.) to detect and block prompt injection attacks, jailbreak attempts, and other malicious inputs before they reach the model.

```
Your App  →  AIProxyGuard  →  OpenAI/Anthropic/etc.
              ↓
         Scan & Block
         Malicious Input
```

## Quick Start

```bash
# Pull and run
docker run -d -p 8080:8080 ovalenzuela/aiproxyguard:latest

# Verify it's running
curl http://localhost:8080/healthz
```

Then point your LLM client to `http://localhost:8080/openai/v1` instead of `https://api.openai.com/v1`.

## Features

| Feature | Status | Description |
|---------|--------|-------------|
| **Multi-Provider Routing** | Production | OpenAI, Anthropic, OpenRouter, Ollama |
| **Request Scanning** | Production | Regex + heuristics with configurable timeouts |
| **Response Scanning** | Production | Detect sensitive data leakage |
| **Policy Engine** | Production | Per-category actions with thresholds |
| **Prometheus Metrics** | Production | Full observability at `/metrics` |
| **Health Endpoints** | Production | `/healthz`, `/readyz` for orchestration |
| **Control Plane** | Beta | Fleet management, signature sync |
| **TLS Interception** | Beta | HTTPS inspection via MITM proxy |

## Detection Categories

| Category | Description | Default |
|----------|-------------|---------|
| `prompt_injection` | Instruction override attempts | Block |
| `jailbreak` | DAN mode, persona exploits | Block |
| `encoding_evasion` | Base64/hex obfuscation | Warn |

## Next Steps

- [Getting Started](getting-started.md) - Installation and basic setup
- [Configuration](configuration.md) - Full config reference
- [Deployment](deployment.md) - Docker, Docker Compose, production guides
- [DigitalOcean Guide](digitalocean-guide.md) - Step-by-step DO App Platform deployment
- [API Reference](api-reference.md) - Endpoints and response formats
- [Security](security.md) - Threat detection and reporting
