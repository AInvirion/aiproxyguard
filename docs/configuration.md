---
title: Configuration
---

# Configuration

AIProxyGuard uses a YAML configuration file.

## Minimal Config

```yaml
server:
  host: "0.0.0.0"
  port: 8080

upstreams:
  openai:
    url: "https://api.openai.com"
    auth_header: "Authorization"

scanner:
  enabled: true
```

## Full Reference

```yaml
server:
  host: "0.0.0.0"
  port: 8080
  workers: 2

upstreams:
  openai:
    url: "https://api.openai.com"
    timeout: 60s
    auth_header: "Authorization"
  anthropic:
    url: "https://api.anthropic.com"
    timeout: 60s
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
    jailbreak:
      action: "block"

security:
  max_request_size: 10485760
  max_response_size: 52428800

metrics:
  enabled: true
  path: "/metrics"

logging:
  level: "info"
  format: "json"
```

## Environment Variables

Config values support environment variable substitution:

```yaml
upstreams:
  openai:
    url: "${OPENAI_BASE_URL:-https://api.openai.com}"
```
