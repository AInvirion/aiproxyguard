# AIProxyGuard

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![GitHub Issues](https://img.shields.io/github/issues/ainvirion/aiproxyguard.svg)](https://github.com/ainvirion/aiproxyguard/issues)
[![GitHub Pull Requests](https://img.shields.io/github/issues-pr/ainvirion/aiproxyguard.svg)](https://github.com/ainvirion/aiproxyguard/pulls)

LLM Security Proxy with Prompt Injection Detection.

## Features

- **Multi-provider routing** - OpenAI, Anthropic, Azure OpenAI, OpenRouter, Ollama, custom endpoints
- **Attack detection** - Prompt injection, jailbreak, PII/PHI extraction, data exfiltration, harmful content
- **Policy engine** - Configurable actions (block/warn/log/allow) with client allowlists
- **Signature library** - 99+ detection patterns across 8 categories
- **Control plane integration** - Fleet management, signature sync, telemetry
- **Prometheus metrics** - Request latency, detection rates, signature coverage
- **Structured JSON logging** - With sensitive data redaction

## Quick Start

```bash
# Using Docker
docker run -p 8080:8080 -v /path/to/config.yaml:/etc/aiproxyguard/config.yaml ainvirion/aiproxyguard

# From source
pip install .
aiproxyguard -c config.yaml
```

## Configuration

See `config.example.yaml` for a complete configuration example.

### Client Integration

```python
# OpenAI SDK
from openai import OpenAI
client = OpenAI(
    api_key="sk-...",
    base_url="http://localhost:8080/openai/v1"
)

# Anthropic SDK
from anthropic import Anthropic
client = Anthropic(
    api_key="sk-ant-...",
    base_url="http://localhost:8080/anthropic/v1"
)
```

Or via environment variables:
```bash
export OPENAI_BASE_URL="http://localhost:8080/openai/v1"
export ANTHROPIC_BASE_URL="http://localhost:8080/anthropic/v1"
```

## Signature Library

AIProxyGuard includes detection signatures for common LLM attack patterns:

| Category | Signatures | Tier | Description |
|----------|------------|------|-------------|
| `prompt_injection` | 10 | Free | Instruction override, delimiter injection, system prompt extraction |
| `jailbreak` | 12 | Free | DAN mode, persona exploits, restriction bypass |
| `pii` | 12 | Free | SSN, credit cards, credentials, email/phone extraction |
| `child_protection` | 11 | Free | Grooming patterns, CSAM requests, exploitation |
| `encoding_evasion` | 14 | Free | Base64, hex, unicode, leetspeak filter bypass |
| `phi` | 13 | Pro | HIPAA-compliant PHI detection (medical records, diagnoses) |
| `data_exfil` | 12 | Pro | Database dumps, API key extraction, network recon |
| `harmful_content` | 15 | Pro | Violence, weapons, drugs, hacking, fraud |

### Signature Format

```yaml
signatures:
  - id: "PI-001"
    name: "Ignore instructions"
    category: "prompt_injection"
    severity: "high"
    patterns:
      - "ignore (all |any )?(previous |prior )?instructions"
    action: "block"
```

### Block Response

```json
{
  "error": {
    "type": "content_blocked",
    "code": "prompt_injection_detected",
    "message": "Request blocked: potential prompt injection detected",
    "signature_id": "PI-001",
    "category": "prompt_injection"
  }
}
```

## Testing

Run the signature test suite:

```bash
# Start the proxy
source .venv/bin/activate
aiproxyguard -c config.test.yaml &

# Run tests
python scripts/test_proxy.py

# Test specific category
python scripts/test_proxy.py --category prompt_injection

# Verbose output
python scripts/test_proxy.py -v
```

## Control Plane Integration

AIProxyGuard can connect to the hosted control plane for:
- Fleet management and monitoring
- Signature updates and sync
- Telemetry and analytics
- Tiered access (free/pro/enterprise)

Configure in `config.yaml`:
```yaml
signatures:
  sync:
    enabled: true
    api_url: "https://api.aiproxyguard.com"
    api_key: "${AIPROXYGUARD_API_KEY}"
    interval: 300s
```

### Upload Signatures (Admin)

```bash
python scripts/upload_signatures.py --email admin@aiproxyguard.com
```

## Architecture

```
Client Request
     │
     ▼
┌─────────────┐   ┌────────┐   ┌──────────┐   ┌──────────┐
│   Router    │──▶│Request │──▶│ Forward  │──▶│ Response │
│             │   │Scanner │   │          │   │ Scanner  │
└─────────────┘   └────────┘   └──────────┘   └──────────┘
                       │
                       ▼
                 ┌──────────┐   ┌──────────┐
                 │  Policy  │   │ Metrics  │
                 │  Engine  │   │ Exporter │
                 └──────────┘   └──────────┘
```

## Metrics

Prometheus metrics available at `/metrics`:

```
aiproxyguard_requests_total{upstream, method, status}
aiproxyguard_scans_total{scanner, result}
aiproxyguard_detections_total{category, action, signature_id}
aiproxyguard_signatures_loaded{tier}
```

## Development

```bash
# Setup
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Run tests
pytest

# Lint
ruff check .
```

## Security Model

- API keys never logged or sent to control plane
- Proxy runs in user's trust boundary
- Signatures cryptographically verified (Ed25519)
- Manifests prevent rollback attacks

## Contributing

We welcome contributions from the community! Please read our [Contributing Guidelines](CONTRIBUTING.md) before submitting a pull request.

## Security

If you discover a security vulnerability, please follow our [Security Policy](SECURITY.md).

## License

Apache-2.0 - See [LICENSE](LICENSE) file for details.

Copyright (c) 2025-2026 AInvirion LLC. All Rights Reserved.

## Links

- [Control Plane Portal](https://portal.aiproxyguard.com)
- [Documentation](https://docs.aiproxyguard.com)
- [GitHub Issues](https://github.com/AInvirion/aiproxyguard/issues)
