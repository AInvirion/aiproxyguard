---
title: Configuration
nav_order: 3
---

# Configuration

AIProxyGuard uses a YAML configuration file. Environment variables are supported with `${VAR}` or `${VAR:-default}` syntax.

## Minimal Config

```yaml
server:
  port: 8080

upstreams:
  openai:
    url: "https://api.openai.com"
```

## Full Reference

```yaml
# Server settings
server:
  host: "0.0.0.0"           # Bind address
  port: 8080                 # Listen port
  workers: 2                 # Number of workers (currently unused, reserved)

# Upstream LLM providers
upstreams:
  openai:
    url: "https://api.openai.com"
    timeout: 60s                      # Request timeout
    auth_header: "Authorization"      # Header containing API key
  anthropic:
    url: "https://api.anthropic.com"
    timeout: 60s
    auth_header: "x-api-key"
  openrouter:
    url: "https://openrouter.ai/api"
    timeout: 120s
    auth_header: "Authorization"
  ollama:
    url: "http://localhost:11434"
    timeout: 300s
    auth_header: null                 # Ollama doesn't require auth

# Scanner settings
scanner:
  enabled: true              # Master switch for all scanning
  regex: true                # Enable regex pattern matching
  heuristics: true           # Enable heuristic detection (base64, encoding, etc.)
  ml_classifier: false       # ML classifier (not yet implemented)
  response:                  # Response scanning settings
    enabled: false           # Scan responses for sensitive data
    mode: "buffered"         # "passthrough", "buffered", or "full"
    buffer_size: 1024        # Chars to buffer before scanning (buffered mode)
    categories: []           # Categories to scan for (empty = all)

# Policy engine
policy:
  default_action: "block"    # Default action: "allow", "log", "warn", "block"
  categories:
    prompt_injection:
      action: "block"
      threshold: 0.8         # Confidence threshold (0.0-1.0)
    jailbreak:
      action: "block"
      threshold: 0.7
    encoding_evasion:
      action: "warn"
      threshold: 0.6
  allowlists:                # Bypass scanning for specific clients
    - client_id: "internal-service-*"
      categories: ["prompt_injection"]

# Signature location
signatures:
  path: "/app/signatures"    # Path to signature YAML files

# Security settings
security:
  failure_mode: "open"       # "open" = allow on error, "closed" = block on error
  scanner_timeout_ms: 100    # Max scanner execution time before timeout
  upstream_timeout_s: 60     # Upstream request timeout
  max_request_size: 10485760   # 10 MB max request body
  max_response_size: 52428800  # 50 MB max response body
  expose_details: false      # Never expose signature patterns to clients

# Prometheus metrics
metrics:
  enabled: true
  path: "/metrics"

# Structured logging
logging:
  level: "info"              # "debug", "info", "warning", "error"
  format: "json"             # "json" or "text"
  redact_keys: true          # Redact API keys in logs

# Client identity resolution
identity:
  method: "ip"               # "ip", "header", "token", "mtls"
  header_name: "X-Client-ID" # Header to extract client ID from
  fallback_header: null      # Fallback header if primary is missing
  trust_xff: false           # Trust X-Forwarded-For for IP resolution
  hash_token: true           # Hash tokens for privacy

# Control plane - fleet registration and management
control_plane:
  enabled: false                                              # Enable fleet registration
  url: "${AIPROXYGUARD_CONTROL_PLANE_URL:-https://aiproxyguard.com}"
  api_key: "${AIPROXYGUARD_CONTROL_PLANE_API_KEY}"           # Required when enabled
  heartbeat_interval: 60                                      # Seconds between heartbeats
  sync_signatures: true                                       # Auto-sync signatures from control plane
  report_telemetry: true                                      # Report detection metrics

# TLS interception (optional, advanced)
tls:
  enabled: false
  ca_cert: "/etc/aiproxyguard/ca.crt"
  ca_key: "/etc/aiproxyguard/ca.key"
  cert_cache_size: 1000
  cert_validity_days: 30
```

## Environment Variables

Use `${VAR}` or `${VAR:-default}` syntax:

```yaml
upstreams:
  openai:
    url: "${OPENAI_BASE_URL:-https://api.openai.com}"

control_plane:
  api_key: "${CONTROL_PLANE_API_KEY}"
```

## Policy Actions

| Action | Behavior |
|--------|----------|
| `allow` | Pass through without scanning |
| `log` | Scan and log detections, allow request |
| `warn` | Scan and log detections with warning, allow request |
| `block` | Scan and block if detection confidence >= threshold |

## Failure Modes

| Mode | Behavior |
|------|----------|
| `open` | On scanner error/timeout, allow the request |
| `closed` | On scanner error/timeout, block the request |

Use `open` for availability-focused deployments, `closed` for security-focused.

## Response Scanning Modes

| Mode | Behavior |
|------|----------|
| `passthrough` | Forward response chunks immediately, scan asynchronously |
| `buffered` | Buffer N chars before scanning, then stream |
| `full` | Buffer entire response, scan, then return |

## Control Plane (Fleet Registration)

The control plane enables centralized fleet management, automatic signature updates, and telemetry reporting.

### Enabling Fleet Registration

**Option 1: Environment Variables (Recommended for Docker)**

```bash
docker run -d -p 8080:8080 \
  -e AIPROXYGUARD_CONTROL_PLANE_ENABLED=true \
  -e AIPROXYGUARD_CONTROL_PLANE_URL=https://aiproxyguard.com \
  -e AIPROXYGUARD_CONTROL_PLANE_API_KEY=your-api-key-here \
  ovalenzuela/aiproxyguard:latest
```

**Option 2: Config File**

```yaml
control_plane:
  enabled: true
  url: "https://aiproxyguard.com"
  api_key: "your-api-key-here"
  heartbeat_interval: 60
  sync_signatures: true
  report_telemetry: true
```

### Control Plane Settings

| Setting | Description | Default |
|---------|-------------|---------|
| `enabled` | Enable fleet registration | `false` |
| `url` | Control plane API URL | `https://aiproxyguard.com` |
| `api_key` | Your API key (required when enabled) | - |
| `heartbeat_interval` | Seconds between heartbeats | `60` |
| `sync_signatures` | Auto-download new signatures | `true` |
| `report_telemetry` | Report detection events | `true` |

### What Happens When Enabled

1. **Registration**: On startup, the proxy registers with the fleet, sending instance metadata (hostname, OS, version)
2. **Heartbeats**: Periodic heartbeats report status and check for updates
3. **Signature Sync**: New detection signatures are automatically downloaded and hot-reloaded
4. **Policy Sync**: Policy changes from the control plane are applied without restart
5. **Telemetry**: Detection events (counts, categories) are reported for analytics

### Getting an API Key

Sign up at [aiproxyguard.com](https://aiproxyguard.com) to get your API key.

### Updating or Rotating API Keys

If your API key is revoked, expired, or you need to rotate it, you must update the configuration and restart the proxy.

**What happens when the API key is invalid:**

The proxy detects 401/403 errors and stops retrying:
```json
{"level": "error", "message": "API key invalid or revoked. Control plane features disabled. Update your API key in the config and restart the proxy."}
{"level": "info", "message": "Heartbeat loop stopped due to invalid API key. Proxy continues in offline mode."}
```

The proxy continues running in **offline mode** with:
- Bundled free-tier signatures
- Bundled free-tier ML model
- Local configuration (no cloud sync)

**To update the API key:**

**Option 1: Environment Variable (Docker)**

```bash
# Update the environment variable and restart
docker stop aiproxyguard
docker run -d --name aiproxyguard -p 8080:8080 \
  -e AIPROXYGUARD_CONTROL_PLANE_API_KEY=your-new-api-key \
  ovalenzuela/aiproxyguard:latest

# Or with docker-compose
docker-compose down
# Edit .env or docker-compose.yml with new key
docker-compose up -d
```

**Option 2: Config File (Volume Mount)**

```bash
# 1. Edit the mounted config file
vim /path/to/config.yaml
# Update: api_key: "your-new-api-key"

# 2. Restart the container
docker restart aiproxyguard
```

**Option 3: Kubernetes**

```bash
# Update the secret
kubectl create secret generic aiproxyguard-secrets \
  --from-literal=api-key=your-new-api-key \
  --dry-run=client -o yaml | kubectl apply -f -

# Restart the deployment
kubectl rollout restart deployment/aiproxyguard
```

> **Note:** A restart is required because the API key is loaded at startup. Hot-reload of API keys may be added in a future version.

## Cloud Policies (Control Plane)

When connected to the control plane, policies are managed centrally and synced to all fleet instances. Cloud policies override local `policy:` configuration.

### Detection Thresholds

Each detection category has a configurable **threshold** (0.0-1.0) that controls sensitivity:

| Threshold | Behavior | Use Case |
|-----------|----------|----------|
| **0.3** | Aggressive - catches more attacks, higher false positive risk | High-security environments |
| **0.5** | Balanced - good accuracy with minimal false positives | Most deployments (default) |
| **0.7** | Conservative - prioritizes avoiding false positives | User-facing applications |
| **0.9** | Very conservative - only high-confidence detections | When false positives are unacceptable |

### Default Cloud Policy Thresholds

| Category | Default Threshold | Action |
|----------|------------------|--------|
| `prompt-injection` | 0.5 | block |
| `jailbreak` | 0.5 | block |
| `pii` | 0.5 | warn |
| `data_exfil` | 0.5 | block |
| `harmful_content` | 0.5 | block |
| `encoding-bypass` | 0.7 | block |
| `delimiter-injection` | 0.7 | block |
| `indirect-injection` | 0.7 | block |
| `unicode-evasion` | 0.7 | block |
| `role-manipulation` | 0.7 | block |

### Tuning for Your Use Case

**High Recall (catch more attacks):**
- Lower thresholds to 0.3-0.4
- Accept some false positives
- Good for internal tools, security-critical apps

**High Precision (minimize false positives):**
- Keep thresholds at 0.5-0.7
- Some attacks may pass through
- Good for user-facing chatbots, customer support

**Balanced:**
- Use defaults (0.5 for common attacks, 0.7 for evasion techniques)
- Monitor metrics and adjust per-category as needed

### Modifying Thresholds

Thresholds are configured in the cloud portal under **Policies > Detection Rules**. Changes sync to all fleet instances within 60 seconds.

## Docker Volume Mounts

```bash
docker run -d -p 8080:8080 \
  -v $(pwd)/config.yaml:/etc/aiproxyguard/config.yaml \
  -v $(pwd)/signatures:/app/signatures \
  ovalenzuela/aiproxyguard:latest
```

## Example Configs

### Minimal (OpenAI only)

```yaml
server:
  port: 8080
upstreams:
  openai:
    url: "https://api.openai.com"
scanner:
  enabled: true
```

### Production (Multiple providers, strict policy)

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
  response:
    enabled: true
    mode: "buffered"

policy:
  default_action: "block"
  categories:
    prompt_injection:
      action: "block"
      threshold: 0.7
    jailbreak:
      action: "block"
      threshold: 0.7

security:
  failure_mode: "closed"
  scanner_timeout_ms: 50
  max_request_size: 1048576  # 1 MB

metrics:
  enabled: true

logging:
  level: "info"
  format: "json"
  redact_keys: true
```

### Local Development (Ollama)

```yaml
server:
  port: 8080

upstreams:
  ollama:
    url: "http://localhost:11434"
    timeout: 300s

scanner:
  enabled: true
  regex: true
  heuristics: true

policy:
  default_action: "warn"  # Log but don't block during development

logging:
  level: "debug"
  format: "text"
```
