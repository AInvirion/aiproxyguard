# AIProxyGuard

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Docker](https://img.shields.io/docker/v/ovalenzuela/aiproxyguard?label=docker)](https://hub.docker.com/r/ovalenzuela/aiproxyguard)
[![Tests](https://img.shields.io/badge/tests-165%20passing-brightgreen)](https://github.com/AInvirion/aiproxyguard)

LLM Security Proxy with Prompt Injection Detection.

## What It Does

AIProxyGuard sits between your application and LLM providers to detect and block malicious inputs before they reach the model. Point your OpenAI/Anthropic SDK at the proxy instead of directly at the provider.

```
Your App  →  AIProxyGuard  →  OpenAI/Anthropic/etc.
              ↓
         Scan & Block
         Malicious Input
```

## Quick Start

### Docker (Recommended)

```bash
# Pull and run
docker run -d -p 8080:8080 ovalenzuela/aiproxyguard:latest

# Verify it's running
curl http://localhost:8080/healthz
# {"status": "healthy"}
```

### From Source

```bash
git clone https://github.com/AInvirion/aiproxyguard.git
cd aiproxyguard
pip install .
aiproxyguard -c config.yaml
```

## Usage

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

Or set environment variables:

```bash
export OPENAI_BASE_URL="http://localhost:8080/openai/v1"
export ANTHROPIC_BASE_URL="http://localhost:8080/anthropic/v1"
```

## Features

| Feature | Status | Description |
|---------|--------|-------------|
| **Multi-Provider Routing** | Production | OpenAI, Anthropic, OpenRouter, Ollama, custom endpoints |
| **Request Scanning** | Production | Regex + heuristics detection with configurable timeouts |
| **Response Scanning** | Production | Detect sensitive data leakage (SSN, credit cards, API keys) |
| **Policy Engine** | Production | Per-category actions (block/warn/log/allow) with thresholds |
| **Prometheus Metrics** | Production | Request latency, detection rates, signature coverage |
| **JSON Logging** | Production | Structured logs with sensitive data redaction |
| **Health Endpoints** | Production | `/healthz`, `/readyz` for container orchestration |
| **Control Plane** | Beta | Fleet management, signature sync, telemetry |
| **TLS Interception** | Beta | MITM proxy for HTTPS inspection |

## Detection Categories

| Category | Description | Default Action |
|----------|-------------|----------------|
| `prompt_injection` | Instruction override, delimiter injection | Block |
| `jailbreak` | DAN mode, persona exploits, restriction bypass | Block |
| `encoding_evasion` | Base64, hex, unicode obfuscation detected by heuristics | Warn |

Additional signature categories available via control plane subscription.

## Fleet Registration (Control Plane)

Connect your instance to the AIProxyGuard control plane for fleet management, automatic signature updates, and telemetry.

### Via Environment Variables (Recommended)

```bash
docker run -d -p 8080:8080 \
  -e AIPROXYGUARD_CONTROL_PLANE_ENABLED=true \
  -e AIPROXYGUARD_CONTROL_PLANE_URL=https://aiproxyguard.com \
  -e AIPROXYGUARD_CONTROL_PLANE_API_KEY=your-api-key-here \
  ovalenzuela/aiproxyguard:latest
```

### Via Config File

```yaml
control_plane:
  enabled: true
  url: "https://aiproxyguard.com"
  api_key: "your-api-key-here"
  heartbeat_interval: 60
  sync_signatures: true      # Auto-update signatures from control plane
  report_telemetry: true     # Report detection metrics
```

When enabled, the proxy will:
1. Register with the fleet on startup
2. Send periodic heartbeats with status
3. Sync new signatures automatically
4. Report detection telemetry (if enabled)

Get your API key at [aiproxyguard.com](https://aiproxyguard.com).

## Configuration

Create a `config.yaml`:

```yaml
server:
  host: "0.0.0.0"
  port: 8080

upstreams:
  openai:
    url: "https://api.openai.com"
    auth_header: "Authorization"
  anthropic:
    url: "https://api.anthropic.com"
    auth_header: "x-api-key"

scanner:
  enabled: true
  regex: true
  heuristics: true

policy:
  default_action: "block"
  categories:
    prompt_injection:
      action: "block"
      threshold: 0.8
    jailbreak:
      action: "block"
      threshold: 0.7

security:
  failure_mode: "open"        # "open" = allow on error, "closed" = block on error
  scanner_timeout_ms: 100     # Max time for scanning before timeout
  max_request_size: 10485760  # 10MB
```

Mount your config:

```bash
docker run -d -p 8080:8080 \
  -v $(pwd)/config.yaml:/etc/aiproxyguard/config.yaml \
  ovalenzuela/aiproxyguard:latest
```

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `/openai/*` | Proxy to OpenAI API |
| `/anthropic/*` | Proxy to Anthropic API |
| `/healthz` | Liveness probe |
| `/readyz` | Readiness probe |
| `/metrics` | Prometheus metrics |

## Block Response Format

When a request is blocked:

```json
{
  "error": {
    "type": "content_blocked",
    "code": "prompt_injection_detected",
    "message": "Request blocked: potential prompt injection detected"
  }
}
```

HTTP status: `400 Bad Request`

## Metrics

Prometheus metrics at `/metrics`:

```
aiproxyguard_requests_total{upstream, method, status}
aiproxyguard_request_duration_seconds{upstream, method}
aiproxyguard_scans_total{scanner, result}
aiproxyguard_detections_total{category, action, signature_id}
aiproxyguard_signatures_loaded
```

## Deployment

See [docs/deployment.md](docs/deployment.md) for:
- Docker / Docker Compose
- DigitalOcean App Platform
- Kubernetes (coming soon)

## Development

```bash
# Setup
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Run tests (165 tests)
PYTHONPATH=src pytest

# Lint
ruff check .
```

## Security

- API keys are passed through but never logged
- Signatures are cryptographically verified (Ed25519)
- Manifest sequence numbers prevent rollback attacks
- Report vulnerabilities to security@ainvirion.com

## License

Apache-2.0 - See [LICENSE](LICENSE) file.

Copyright (c) 2025-2026 AInvirion LLC.

## Links

- [Documentation](docs/)
- [Docker Hub](https://hub.docker.com/r/ovalenzuela/aiproxyguard)
- [GitHub Issues](https://github.com/AInvirion/aiproxyguard/issues)
