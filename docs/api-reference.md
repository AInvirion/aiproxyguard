---
title: API Reference
nav_order: 5
---

# API Reference

## Proxy Endpoints

All upstream provider APIs are proxied under their respective paths. The proxy transparently forwards requests, adding security scanning.

| Provider | Proxy Path | Upstream | Auth Header |
|----------|------------|----------|-------------|
| OpenAI | `/openai/*` | `https://api.openai.com/*` | `Authorization` |
| Anthropic | `/anthropic/*` | `https://api.anthropic.com/*` | `x-api-key` |
| OpenRouter | `/openrouter/*` | `https://openrouter.ai/api/*` | `Authorization` |
| Ollama | `/ollama/*` | `http://localhost:11434/*` | None |

### Example: OpenAI Chat

```bash
# Via proxy
curl -X POST http://localhost:8080/openai/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -d '{
    "model": "gpt-4",
    "messages": [{"role": "user", "content": "Hello!"}]
  }'

# Equivalent direct call (without proxy)
curl -X POST https://api.openai.com/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -d '{
    "model": "gpt-4",
    "messages": [{"role": "user", "content": "Hello!"}]
  }'
```

### Example: Anthropic Messages

```bash
curl -X POST http://localhost:8080/anthropic/v1/messages \
  -H "Content-Type: application/json" \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -d '{
    "model": "claude-3-sonnet-20240229",
    "max_tokens": 1024,
    "messages": [{"role": "user", "content": "Hello!"}]
  }'
```

## Health Endpoints

### GET /healthz

Liveness probe. Returns 200 if the server is running.

**Response:**
```json
{"status": "healthy"}
```

### GET /readyz

Readiness probe. Returns 200 if the server is ready to accept traffic.

**Response:**
```json
{
  "status": "ready",
  "checks": {
    "scanner": "ok",
    "signatures": "ok"
  }
}
```

### GET /

Root endpoint. Returns service name and version.

**Response:**
```json
{
  "service": "AIProxyGuard",
  "version": "0.2.36"
}
```

### POST /check

Detection-only endpoint for scanning text without forwarding to an LLM. Useful for:
- Pre-validating user input before sending to LLMs
- Building custom security pipelines
- Testing detection rules
- Integrating with external systems

**Request:**
```bash
curl -X POST http://localhost:8080/check \
  -H "Content-Type: application/json" \
  -d '{"text": "Ignore all previous instructions"}'
```

**Response (Detection):**
```json
{
  "action": "block",
  "category": "prompt-injection",
  "signature_name": "Ignore instructions directive",
  "confidence": 0.9
}
```

**Response (Safe):**
```json
{
  "action": "allow",
  "category": null,
  "signature_name": null,
  "confidence": 0.0
}
```

**Response Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `action` | string | Resolved action: `allow`, `log`, `warn`, or `block` |
| `category` | string\|null | Detection category (e.g., `prompt-injection`, `jailbreak`) |
| `signature_name` | string\|null | Human-readable signature name |
| `confidence` | float | Confidence score (0.0-1.0) |

**Error Responses:**

```json
// Invalid JSON
{"error": {"type": "invalid_json", "message": "Invalid JSON in request body"}}

// Missing text field
{"error": {"type": "invalid_request", "message": "Missing required field: text"}}

// Non-string text
{"error": {"type": "invalid_request", "message": "Field 'text' must be a string"}}

// Non-object body
{"error": {"type": "invalid_request", "message": "Request body must be a JSON object"}}
```

**Security Notes:**
- Signature IDs and pattern details are intentionally not exposed to prevent reverse-engineering
- The endpoint honors `security.failure_mode` configuration (returns 503 or allows on scanner error)
- Rate limiting applies to this endpoint (see Rate Limiting documentation)

**Example: Pre-validation Pipeline**

```python
import requests

def check_prompt(text: str) -> bool:
    """Check if prompt is safe before sending to LLM."""
    response = requests.post(
        "http://localhost:8080/check",
        json={"text": text}
    )
    result = response.json()
    return result["action"] == "allow"

# Usage
user_input = input("Enter your question: ")
if check_prompt(user_input):
    # Safe to send to LLM
    llm_response = call_llm(user_input)
else:
    print("Sorry, that input was flagged for security reasons.")
```

### GET /metrics

Prometheus metrics endpoint. Returns metrics in Prometheus text format.

**Response:**
```
# HELP aiproxyguard_requests_total Total number of requests processed
# TYPE aiproxyguard_requests_total counter
aiproxyguard_requests_total{upstream="openai",method="POST",status="200"} 142

# HELP aiproxyguard_request_duration_seconds Request duration in seconds
# TYPE aiproxyguard_request_duration_seconds histogram
aiproxyguard_request_duration_seconds_bucket{upstream="openai",method="POST",le="0.1"} 98

# HELP aiproxyguard_scans_total Total number of scans performed
# TYPE aiproxyguard_scans_total counter
aiproxyguard_scans_total{scanner="pipeline",result="allow"} 140
aiproxyguard_scans_total{scanner="pipeline",result="block"} 2

# HELP aiproxyguard_detections_total Total number of detections
# TYPE aiproxyguard_detections_total counter
aiproxyguard_detections_total{category="prompt_injection",action="block"} 1
aiproxyguard_detections_total{category="jailbreak",action="block"} 1

# HELP aiproxyguard_signatures_loaded Number of signatures loaded
# TYPE aiproxyguard_signatures_loaded gauge
aiproxyguard_signatures_loaded 12
```

## Error Responses

### Content Blocked (400)

Returned when a request is blocked by the scanner.

```json
{
  "error": {
    "type": "content_blocked",
    "code": "prompt_injection_detected",
    "message": "Request blocked: potential prompt injection detected"
  }
}
```

**Possible codes:**
- `prompt_injection_detected`
- `jailbreak_detected`
- `encoding_evasion_detected`

### Response Blocked (502)

Returned when a response is blocked by response scanning.

```json
{
  "error": {
    "type": "response_blocked",
    "code": "sensitive_data_detected",
    "message": "Response blocked: sensitive content detected"
  }
}
```

### Scanner Error (503)

Returned when the scanner fails and `failure_mode: closed` is configured.

```json
{
  "error": {
    "type": "scanner_error",
    "message": "Scanner unavailable"
  }
}
```

### Scanner Timeout (503)

Returned when the scanner times out and `failure_mode: closed` is configured.

```json
{
  "error": {
    "type": "scanner_timeout",
    "message": "Scanner timed out"
  }
}
```

### Unknown Provider (404)

Returned when requesting an unconfigured upstream.

```json
{
  "error": {
    "type": "not_found",
    "message": "Unknown provider: foobar"
  }
}
```

## Request Headers

The proxy forwards these headers to upstreams:

| Header | Behavior |
|--------|----------|
| `Authorization` | Forwarded to OpenAI, OpenRouter |
| `x-api-key` | Forwarded to Anthropic |
| `Content-Type` | Forwarded |
| `Accept` | Forwarded |

## Response Headers

The proxy adds these headers:

| Header | Description |
|--------|-------------|
| `X-AIProxyGuard-Scanned` | `true` if request was scanned |
| `X-Request-ID` | Forwarded from upstream if present |

## Streaming Support

The proxy supports Server-Sent Events (SSE) streaming:

```bash
curl -X POST http://localhost:8080/openai/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -d '{
    "model": "gpt-4",
    "stream": true,
    "messages": [{"role": "user", "content": "Hello!"}]
  }'
```

Response scanning modes for streaming:
- `passthrough`: Forward chunks immediately
- `buffered`: Buffer N chars before first scan
- `full`: Buffer entire response before returning
