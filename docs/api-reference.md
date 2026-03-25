---
title: API Reference
---

# API Reference

## Proxy Endpoints

All upstream provider APIs are proxied under their respective paths:

| Provider | Proxy Path | Upstream |
|----------|------------|----------|
| OpenAI | `/openai/*` | `https://api.openai.com/*` |
| Anthropic | `/anthropic/*` | `https://api.anthropic.com/*` |
| OpenRouter | `/openrouter/*` | `https://openrouter.ai/api/*` |
| Ollama | `/ollama/*` | `http://localhost:11434/*` |

## Health Endpoints

### GET /healthz

Liveness probe.

```json
{"status": "healthy"}
```

### GET /readyz

Readiness probe.

```json
{"status": "ready", "checks": {"scanner": "ok", "signatures": "ok"}}
```

### GET /metrics

Prometheus metrics endpoint.
