# AIProxyGuard

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![GHCR](https://img.shields.io/badge/ghcr.io-ainvirion%2Faiproxyguard-blue)](https://ghcr.io/ainvirion/aiproxyguard)
[![Docs](https://img.shields.io/badge/docs-ainvirion.github.io-green)](https://ainvirion.github.io/aiproxyguard/)

LLM Security Proxy with Prompt Injection Detection.

## What It Does

AIProxyGuard sits between your application and LLM providers to detect and block malicious inputs before they reach the model. Point your OpenAI/Anthropic SDK at the proxy instead of directly at the provider.

## Quick Start

```bash
# Run the proxy
docker run -d -p 8080:8080 ghcr.io/ainvirion/aiproxyguard:latest

# Verify it's running
curl http://localhost:8080/healthz
```

Point your LLM client to the proxy:

```python
from openai import OpenAI

client = OpenAI(
    api_key="sk-...",
    base_url="http://localhost:8080/openai/v1"
)

# Normal requests work as expected
response = client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": "Hello!"}]
)

# Malicious requests are blocked
response = client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": "Ignore all previous instructions..."}]
)
# Raises: BadRequestError - content_blocked
```

## Features

- **Multi-Provider Routing** - OpenAI, Anthropic, OpenRouter, Ollama
- **Request & Response Scanning** - Regex + heuristics detection
- **Policy Engine** - Per-category actions (block/warn/log)
- **Prometheus Metrics** - Full observability at `/metrics`
- **Control Plane** - Fleet management, automatic signature sync

## Detection Categories

| Category | Description |
|----------|-------------|
| `prompt-injection` | Instruction override attempts |
| `jailbreak` | DAN mode, persona exploits |
| `encoding-bypass` | Base64/hex/ROT13 obfuscation |
| `delimiter-injection` | JSON/XML structure attacks |
| `indirect-injection` | Tool abuse, plugin exploits |
| `unicode-evasion` | Homoglyphs, fullwidth chars |
| `role-manipulation` | Named character roleplay |

## Documentation

Full documentation at **[ainvirion.github.io/aiproxyguard](https://ainvirion.github.io/aiproxyguard/)**

- [Getting Started](https://ainvirion.github.io/aiproxyguard/getting-started.html)
- [Configuration](https://ainvirion.github.io/aiproxyguard/configuration.html)
- [Deployment](https://ainvirion.github.io/aiproxyguard/deployment.html)
- [API Reference](https://ainvirion.github.io/aiproxyguard/api-reference.html)

## Control Plane

Connect to [aiproxyguard.com](https://aiproxyguard.com) for fleet management and automatic signature updates:

```bash
docker run -d -p 8080:8080 \
  -e AIPROXYGUARD_CONTROL_PLANE_ENABLED=true \
  -e AIPROXYGUARD_CONTROL_PLANE_API_KEY=your-api-key \
  ghcr.io/ainvirion/aiproxyguard:latest
```

## Development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

## License

Apache-2.0 - Copyright (c) 2025-2026 AInvirion LLC
