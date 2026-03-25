---
title: Home
---

# AIProxyGuard

LLM Security Proxy with Prompt Injection Detection.

## What is AIProxyGuard?

AIProxyGuard is a security proxy that sits between your application and LLM providers (OpenAI, Anthropic, etc.) to detect and block prompt injection attacks, jailbreak attempts, and other malicious inputs.

## Quick Start

```bash
docker pull ovalenzuela/aiproxyguard:latest
docker run -p 8080:8080 ovalenzuela/aiproxyguard:latest
```

Then point your LLM client to `http://localhost:8080/openai/` instead of `https://api.openai.com/`.

## Features

- **Prompt Injection Detection** - Blocks attempts to override system instructions
- **Jailbreak Prevention** - Detects DAN, evil mode, and other jailbreak patterns
- **Multiple Providers** - Supports OpenAI, Anthropic, OpenRouter, Ollama
- **Streaming Support** - Full SSE pass-through with optional buffered scanning
- **Fleet Management** - Centralized control plane for managing multiple proxies
- **Hot Reload** - Update signatures without restarting

## Next Steps

- [Getting Started](getting-started.md) - Installation and basic setup
- [Configuration](configuration.md) - Config file reference
- [Deployment](deployment.md) - Production deployment guides
