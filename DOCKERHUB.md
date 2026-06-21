# AIProxyGuard

**LLM security proxy that blocks prompt injection — and cuts your token bill.**

AIProxyGuard sits between your application and LLM providers (OpenAI, Anthropic,
OpenRouter, Ollama). Point your client's `base_url` at the proxy and every
request/response is scanned for prompt injection, jailbreaks, and other
malicious patterns — while opt-in cost features reduce your spend.

- 📚 Docs: https://ainvirion.github.io/aiproxyguard/
- 🐙 Source: https://github.com/AInvirion/aiproxyguard
- ☁️ Hosted control plane: https://aiproxyguard.com

## Quick start

```bash
docker run -d -p 8080:8080 ainvirion/aiproxyguard:latest
curl http://localhost:8080/healthz
```

Point your LLM client at the proxy:

```python
from openai import OpenAI
client = OpenAI(api_key="sk-...", base_url="http://localhost:8080/openai/v1")
```

Malicious prompts are blocked; normal requests pass through unchanged.

## Tags

- `latest` — most recent release
- `X.Y.Z` — pinned version (e.g. `0.2.61`)
- `X.Y` — latest patch of a minor line

## Security features

- **Request & response scanning** — regex + heuristics + ML classifier
- **Policy engine** — per-category actions (block / warn / log) with thresholds
- **Detection-only mode** — `/check` endpoint to validate text without forwarding
- **Prometheus metrics** at `/metrics`, health at `/healthz` / `/readyz`
- **Control plane** — fleet management + automatic signature sync (free API key)

## Cost optimization (opt-in, off by default)

Applies to traffic **forwarded through the proxy**:

- **Prompt caching** — Anthropic `cache_control` injection for the cached-prefix discount
- **Smart model routing** — route/downgrade to a cheaper same-provider model
- **Response caching** — serve repeat identical requests from a Redis-backed exact-match cache (still scanned before serving)
- **Usage & cost analytics** — billed-token spend tracking, surfaced in the control plane

See the [Cost Optimization guide](https://ainvirion.github.io/aiproxyguard/cost-optimization.html).

## Configuration

Mount a config file at `/etc/aiproxyguard/config.yaml`, or use environment
variables. Connect to the hosted control plane:

```bash
docker run -d -p 8080:8080 \
  -e AIPROXYGUARD_CONTROL_PLANE_ENABLED=true \
  -e AIPROXYGUARD_CONTROL_PLANE_API_KEY=apg_your_key \
  ainvirion/aiproxyguard:latest
```

Full reference: https://ainvirion.github.io/aiproxyguard/configuration.html

## License

Apache-2.0 — Copyright (c) 2025-2026 AInvirion LLC
