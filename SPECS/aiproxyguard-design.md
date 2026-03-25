# AIProxyGuard Design Specification

**Product:** AIProxyGuard - LLM Security Proxy with Signature Sync
**Author:** AInvirion
**Date:** 2026-03-18
**Status:** Approved

---

## Executive Summary

AIProxyGuard is an open-source HTTP proxy that sits between applications and LLM APIs (OpenAI, Anthropic, Azure, etc.), inspecting every request and response for prompt injection, data leakage, and anomalous behavior. It requires no SDK changes - apps just point at the proxy.

**Business model:** Open-source proxy with bundled basic signatures. Paid subscription for continuously-updated compiled signatures, fleet management, and advanced ML detection.

**Part of:** AInvirion open-source portfolio

---

## 1. System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              AIProxyGuard                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  CONTROL PLANE (SaaS)                                                       │
│  api.aiproxyguard.com / portal.aiproxyguard.com                            │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  FastAPI          PostgreSQL       DO Spaces      Stripe            │   │
│  │  • REST API       • Accounts       • Compiled     • Billing         │   │
│  │  • Auth           • Policies       • Signatures   • Subscriptions   │   │
│  │  • Sync           • Fleet          • (.hsdb)      • Webhooks        │   │
│  │  • Telemetry      • Audit                                           │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                        │
│                          HTTPS (mTLS optional)                              │
│                                    │                                        │
│  DATA PLANE (Customer Premises)                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                   AIProxyGuard Docker                                │   │
│  │  ┌─────────┐   ┌─────────────┐   ┌─────────────────┐                │   │
│  │  │  Proxy  │──▶│  Scanner    │──▶│  Decision       │                │   │
│  │  │ (async) │   │  Pipeline   │   │  Engine         │                │   │
│  │  └─────────┘   └─────────────┘   └─────────────────┘                │   │
│  │       │              │                   │                          │   │
│  │  ┌─────────┐   ┌─────────────┐   ┌─────────────────┐                │   │
│  │  │   TLS   │   │ Signatures  │   │  Local Logs     │                │   │
│  │  │  (MITM) │   │ Free + Paid │   │  (JSON/Syslog)  │                │   │
│  │  └─────────┘   └─────────────┘   └─────────────────┘                │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│   Apps ──▶ Proxy:8080 ──▶ OpenAI/Anthropic/Azure                           │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Key Decisions

| Aspect | Decision | Rationale |
|--------|----------|-----------|
| Control plane | FastAPI + PostgreSQL | Same stack as aisniff-server |
| Data plane | Python async proxy | ML integration, familiar ecosystem |
| Signature format | Hyperscan .hsdb (paid) + YAML (free) | Performance + protection |
| Config sync | Pull-based (proxy polls API) | Works behind NAT, air-gap friendly |
| Telemetry | Opt-in, anonymized stats | Privacy-first, compliance friendly |
| Deployment | Single Docker image | Simple ops, easy updates |

---

## 2. Data Plane (Proxy)

### Scanner Pipeline

```
REQUEST FLOW

App ──▶ [TLS Intercept] ──▶ [Extract Body] ──▶ [Scanner Pipeline]

                    ┌──────────────────┐
                    │  1. FAST LAYER   │  < 1ms
                    │  • Hyperscan DB  │  (compiled regex)
                    │  • Blocklist     │  (known bad hashes)
                    └────────┬─────────┘
                             ▼
                    ┌──────────────────┐
                    │  2. HEURISTICS   │  < 5ms
                    │  • Encoding det. │  (base64, unicode)
                    │  • Entropy score │  (suspicious randomness)
                    │  • Trigger words │  (weighted scoring)
                    └────────┬─────────┘
                             ▼
                    ┌──────────────────┐
                    │  3. ML LAYER     │  ~50ms (optional)
                    │  • DeBERTa ONNX  │  (PIGuard-style)
                    │  • Embedding sim │  (known attack vectors)
                    └────────┬─────────┘
                             ▼
                    ┌──────────────────┐
                    │  4. LLM LAYER    │  ~500ms (future, optional)
                    │  • Local LLM     │  (semantic analysis)
                    │  • Cloud LLM API │  (hosted service)
                    └────────┬─────────┘
                             ▼
                    ┌──────────────────────────────────────────┐
                    │              DECISION ENGINE              │
                    │  Score aggregation + policy lookup        │
                    │  Actions:  ALLOW │ LOG │ WARN │ BLOCK    │
                    └──────────────────────────────────────────┘

RESPONSE FLOW (same pipeline, different signatures)
• PII/PHI detection (Presidio patterns)
• Data exfiltration patterns (encoded dumps, URLs)
• Semantic coherence (ask vs answer mismatch)
```

### Streaming & SSE Handling

**LLM API Traffic Patterns:**
| Provider | Protocol | Format |
|----------|----------|--------|
| OpenAI | HTTP/1.1 + SSE | `text/event-stream`, chunked `data:` lines |
| Anthropic | HTTP/1.1 + SSE | `text/event-stream`, chunked JSON |
| Azure OpenAI | HTTP/1.1 + SSE | Same as OpenAI |
| Local (Ollama) | HTTP/1.1 + SSE or JSON | Varies |

**MVP Scope (Phase 1): HTTP/1.1 only**
- WebSocket and HTTP/2 deferred to Phase 4
- Covers 95%+ of LLM API traffic

**Streaming Strategy:**
```
REQUEST (non-streaming):
  App ──▶ Proxy buffers full request ──▶ Scan ──▶ Forward/Block

RESPONSE (streaming SSE):
  LLM ──▶ Proxy receives chunks ──▶ Buffer window ──▶ Scan window ──▶ Forward

  ┌─────────────────────────────────────────────────────────────────┐
  │  STREAMING SCAN MODES                                           │
  ├─────────────────────────────────────────────────────────────────┤
  │                                                                  │
  │  MODE 1: Pass-through with async scan (default)                 │
  │  • Forward chunks immediately to client                         │
  │  • Accumulate in background buffer                              │
  │  • Scan complete response async, log/alert only                 │
  │  • Latency: ~0ms added                                          │
  │                                                                  │
  │  MODE 2: Buffered scan (high-security)                          │
  │  • Buffer first N tokens (configurable, default: 100)           │
  │  • Scan buffer, if clean → stream rest                          │
  │  • If suspicious → buffer more or block                         │
  │  • Latency: +200-500ms on first chunk                           │
  │                                                                  │
  │  MODE 3: Full buffer (maximum security)                         │
  │  • Buffer entire response                                        │
  │  • Scan complete response                                        │
  │  • Forward only if clean                                         │
  │  • Latency: Full response time (defeats streaming UX)           │
  │                                                                  │
  └─────────────────────────────────────────────────────────────────┘
```

**Configuration:**
```yaml
scanner:
  response:
    mode: "passthrough"  # "passthrough" | "buffered" | "full"
    buffer_chars: 500    # for buffered mode (character count, not tokens)
    async_scan: true     # scan complete response after streaming
```

**Token vs Character Counting:**
- SSE responses arrive as byte chunks with no token metadata
- `buffer_chars` uses character count (deterministic, provider-agnostic)
- Approximate: 1 token ≈ 4 characters for English text
- `buffer_chars: 500` ≈ 125 tokens, enough to detect most attack patterns

**Security Implications by Mode:**

| Mode | Request Blocking | Response Blocking | Use Case |
|------|------------------|-------------------|----------|
| passthrough | YES (sync) | NO (async alert only) | Low-latency, logging focus |
| buffered | YES (sync) | PARTIAL (first N chars) | Balanced security/UX |
| full | YES (sync) | YES (complete scan) | Maximum security, compliance |

**Important:** Pass-through mode does NOT block malicious responses — it only logs/alerts. For data leakage prevention, use `buffered` or `full` mode.

### Client Identity

**How the proxy identifies clients for allowlists and policy scoping:**

```yaml
# config.yaml
client_identity:
  method: "header"  # "header" | "mtls" | "ip" | "token"

  # Method: header (default, simplest)
  header:
    name: "X-Client-ID"           # custom header from app
    fallback: "X-Forwarded-For"   # fallback to IP if header missing

  # Method: mtls (strongest, Enterprise)
  mtls:
    client_cert_cn: true          # use CN from client certificate
    require_cert: true            # reject requests without client cert

  # Method: ip (simple but weak)
  ip:
    trust_xff: false              # trust X-Forwarded-For header

  # Method: token (extract from Authorization)
  token:
    extract_from: "Authorization" # Bearer token
    hash_token: true              # hash for privacy, use as client_id
```

**Client ID Resolution Order:**
1. If mTLS enabled and client cert present → use cert CN
2. If `X-Client-ID` header present → use header value
3. If token extraction configured → hash of Bearer token
4. Fallback → client IP address

**Allowlist Configuration:**
```yaml
policies:
  categories:
    pii_outbound:
      action: "block"
      allowlist:
        - client_id: "hr-assistant"      # exact match
        - client_id: "medical-*"         # wildcard
        - client_ip: "10.0.0.0/8"        # CIDR range
```

### Decision Engine Logic

**Scoring Algorithm:**
```python
def compute_decision(scan_results: list[LayerResult]) -> Decision:
    """
    Each layer returns: (category, confidence, severity)

    Scoring:
    - fast layer:      weight = 1.0 (high confidence regex)
    - heuristics:      weight = 0.7 (may have false positives)
    - ml classifier:   weight = 0.9 (good accuracy)
    - llm layer:       weight = 0.8 (semantic but slow)

    Final score = max(layer_score * weight for each match)
    """

    # Priority: explicit blocks first
    for result in scan_results:
        if result.signature.action == "block":
            return Decision.BLOCK

    # Then score aggregation
    weighted_scores = []
    for result in scan_results:
        layer_weight = LAYER_WEIGHTS[result.layer]
        score = result.confidence * result.severity * layer_weight
        weighted_scores.append((score, result))

    max_score, max_result = max(weighted_scores, key=lambda x: x[0])

    # Threshold lookup from policy
    policy = get_policy(max_result.category)

    if max_score >= policy.block_threshold:    # default: 0.9
        return Decision.BLOCK
    elif max_score >= policy.warn_threshold:   # default: 0.7
        return Decision.WARN
    elif max_score >= policy.log_threshold:    # default: 0.3
        return Decision.LOG
    else:
        return Decision.ALLOW
```

**Conflict Resolution:**
- If multiple categories match, use highest severity
- If same severity, prefer fast layer (most reliable)
- Allowlist overrides all (if client in allowlist, skip that category)

**Threshold Tuning:**
```yaml
policies:
  categories:
    prompt_injection:
      action: "block"
      block_threshold: 0.85   # slightly lower = more aggressive
      warn_threshold: 0.6
      log_threshold: 0.3

    encoding_suspicious:
      action: "warn"
      block_threshold: 0.95   # higher = less aggressive (encoding common)
      warn_threshold: 0.7
      log_threshold: 0.4
```

### Response Scanning Details

**Scan Timing:**
- **Synchronous:** PII detection runs on buffered/full modes before forwarding
- **Asynchronous:** Semantic coherence and exfiltration run after streaming completes

**PII/PHI Detection:**

Two implementations available (configurable):

| Implementation | Speed | Accuracy | Dependencies |
|----------------|-------|----------|--------------|
| **Hyperscan regex** | <1ms | Good (pattern-based) | libhyperscan |
| **Presidio NLP** | ~50ms | Better (NER-based) | spaCy, presidio |

```yaml
# config.yaml
scanner:
  pii:
    engine: "hyperscan"  # "hyperscan" | "presidio" | "both"
    # "both" = Hyperscan first (fast), Presidio on flagged content (accurate)
```

**Hyperscan PII patterns (default):**
```python
# Regex patterns compiled to Hyperscan .hsdb
PII_PATTERNS = {
    "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
    "CREDIT_CARD": r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",
    "EMAIL": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    "PHONE": r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b",
    # ... more patterns in signature bundle
}
```

**Presidio NLP (optional, more accurate):**
```python
# Uses spaCy NER models for entity recognition
ENTITY_TYPES = [
    "PERSON", "EMAIL", "PHONE", "SSN", "CREDIT_CARD",
    "IBAN", "IP_ADDRESS", "MEDICAL_LICENSE", "DATE_OF_BIRTH"
]

# Only used if engine: "presidio" or "both"
entities = presidio_analyzer.analyze(response_text, ENTITY_TYPES)
```

**Decision logic:**
```python
# Check against policy
if entities and not client_in_allowlist(request.client_id, "pii_outbound"):
    return Decision.BLOCK
```

**Semantic Coherence (Phase 4):**
```python
# Compare request intent vs response content
request_embedding = embed(request.prompt)
response_embedding = embed(response.content)

similarity = cosine_similarity(request_embedding, response_embedding)

if similarity < COHERENCE_THRESHOLD:  # default: 0.3
    # Response doesn't match what was asked - possible exfiltration
    flag_for_review(request, response, "semantic_mismatch")
```

### Technical Constraints

**Hyperscan Integration:**
```
Challenge: Hyperscan is C library, needs Python bindings
Solution: Use python-hyperscan package (maintained, pip-installable)

Performance:
- Hyperscan scan: ~0.1ms for typical prompt (async-friendly)
- Pattern compilation: ~100ms (done at startup/reload)
- Memory: ~50MB for 1000 patterns

Event Loop:
- Hyperscan.scan() is fast enough to run in event loop
- For very large payloads (>1MB), offload to thread pool
```

**Platform Support:**

| Platform | Hyperscan | Fallback |
|----------|-----------|----------|
| Linux x86_64 | Native | N/A |
| Linux ARM64 | Not available | Python `re2` (10x slower) |
| macOS x86_64 | Native | N/A |
| macOS ARM64 | Via Rosetta | Python `re2` |
| Windows | Not supported | Python `re2` |

**Docker Image Strategy:**
```dockerfile
# Multi-stage build
FROM python:3.11-slim AS base

# x86_64: Install Hyperscan
FROM base AS amd64
RUN apt-get install -y libhyperscan5

# ARM64: Use re2 fallback
FROM base AS arm64
RUN pip install google-re2

# Final image detects and uses appropriate backend
```

**ML Layer Hardware Requirements:**

| Component | CPU-only | GPU (optional) |
|-----------|----------|----------------|
| DeBERTa classifier (184MB) | 50-100ms/request | 5-10ms/request |
| Embedding model (100MB) | 20-50ms/request | 2-5ms/request |
| Memory footprint | 512MB | 2GB VRAM |

**Batching Strategy (high-throughput):**
```yaml
scanner:
  ml:
    enabled: true
    batch_size: 8           # batch requests for GPU efficiency
    batch_timeout_ms: 10    # max wait for batch to fill
    max_concurrent: 4       # parallel inference workers
```

### Configuration

```yaml
# /etc/aiproxyguard/config.yaml

proxy:
  listen: "0.0.0.0:8080"
  tls:
    ca_cert: "/etc/aiproxyguard/ca.pem"
    ca_key: "/etc/aiproxyguard/ca.key"
  upstream_timeout: 30s

sync:
  enabled: true
  api_url: "https://api.aiproxyguard.com"
  api_key: "${AIPROXYGUARD_API_KEY}"
  interval: 300  # seconds

scanner:
  layers:
    fast: true
    heuristics: true
    ml: false        # opt-in
    llm: false       # future

policies:
  default_action: "log"

  categories:
    prompt_injection:
      action: "block"
      notify: true
    jailbreak:
      action: "warn"
    encoding_suspicious:
      action: "log"
    pii_outbound:
      action: "block"
      allowlist: ["hr-assistant", "medical-bot"]

logging:
  format: "json"
  destination: "stdout"
  include_prompts: false  # privacy default

telemetry:
  enabled: false           # opt-in only
  endpoint: "https://api.aiproxyguard.com/api/telemetry/batch"
  batch_size: 100
  flush_interval_seconds: 60
```

### Logging vs Telemetry (Clarification)

**Local Logs (always available, customer-controlled):**
```json
// Written to stdout/file/syslog on the proxy
{
  "ts": "2026-03-18T14:30:00Z",
  "level": "warn",
  "event": "request_blocked",
  "category": "prompt_injection",
  "signature": "inj-core-042",
  "client_ip": "10.0.0.5",
  "upstream": "api.openai.com",
  "latency_ms": 2.3,
  "request_id": "req_abc123"
  // If include_prompts: true (customer choice):
  // "prompt_preview": "First 100 chars of prompt..."
}
```
- **Content:** Full event details, optionally including prompt snippets
- **Destination:** Local only (stdout, file, syslog)
- **Retention:** Customer-controlled
- **Privacy:** Customer's data, customer's rules

**Telemetry (opt-in, anonymized, sent to control plane):**
```json
// Sent to control plane if telemetry.enabled: true
{
  "instance_id": "inst_abc123",  // anonymized
  "timestamp": "2026-03-18T14:30:00Z",
  "event_type": "block",
  "category": "prompt_injection",
  "signature_id": "inj-core-042",
  "latency_ms": 2.3
  // NO: prompt content, client IP, request details
}
```
- **Content:** Category counts and latency only
- **Destination:** Control plane (if enabled)
- **Retention:** 90 days, then aggregated
- **Privacy:** Schema-enforced, no PII possible

**Portal "Logs" Page:**
- Shows aggregated telemetry (if opt-in)
- Displays: "23 blocks today", "Top category: prompt_injection"
- Does NOT show actual prompts (those stay local)

### Docker Deployment

```bash
docker run -d \
  --name aiproxyguard \
  -p 8080:8080 \
  -e AIPROXYGUARD_API_KEY=apg_xxx \
  -v /etc/aiproxyguard:/etc/aiproxyguard \
  ghcr.io/ainvirion/aiproxyguard:latest

# App configuration
export HTTPS_PROXY=http://localhost:8080
```

---

## 3. Control Plane (Portal)

### Architecture

```
┌────────────────────────────────────────────────────────────────────┐
│                         PORTAL UI                                   │
│                    portal.aiproxyguard.com                          │
│  Dashboard │ Fleet │ Policies │ Signatures │ Billing │ Logs        │
└────────────────────────────────────────────────────────────────────┘
                                │
                           FastAPI
                                │
┌───────────────────────────────┴────────────────────────────────────┐
│                           API SERVER                                │
│                       api.aiproxyguard.com                          │
│                                                                     │
│  /auth          /fleet         /signatures    /policies             │
│  • Login        • Register     • List         • CRUD                │
│  • API keys     • Heartbeat    • Download     • Push                │
│  • Teams        • Status       • Changelog    • Versions            │
│                                                                     │
│  /telemetry     /billing                                            │
│  • Ingest       • Stripe                                            │
│  • Aggregate    • Plans                                             │
│  • Alerts       • Usage                                             │
└─────────────────────────────────────────────────────────────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        ▼                       ▼                       ▼
  PostgreSQL             DO Spaces               Stripe
  • accounts             • sigs/*.hsdb           • customers
  • api_keys             • sigs/*.yaml           • subscriptions
  • fleet                • changelogs            • invoices
  • policies
  • telemetry
```

### Database Schema

```sql
-- Accounts & Auth
CREATE TABLE accounts (
    id UUID PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    name TEXT,
    stripe_customer_id TEXT,
    plan TEXT DEFAULT 'free',
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE api_keys (
    id UUID PRIMARY KEY,
    account_id UUID REFERENCES accounts(id),
    key_hash TEXT NOT NULL,
    name TEXT,
    scopes TEXT[] DEFAULT '{}',
    last_used_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT now()
);

-- Fleet Management
CREATE TABLE fleet_instances (
    id UUID PRIMARY KEY,
    account_id UUID REFERENCES accounts(id),
    instance_id TEXT UNIQUE,
    name TEXT,
    version TEXT,
    last_heartbeat TIMESTAMPTZ,
    config_version INT DEFAULT 0,
    status TEXT DEFAULT 'active',
    metadata JSONB DEFAULT '{}'
);

-- Policies
CREATE TABLE policies (
    id UUID PRIMARY KEY,
    account_id UUID REFERENCES accounts(id),
    name TEXT NOT NULL,
    version INT DEFAULT 1,
    config JSONB NOT NULL,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);

-- Telemetry (opt-in, schema-enforced)
CREATE TABLE telemetry (
    id UUID PRIMARY KEY,
    instance_id TEXT,
    timestamp TIMESTAMPTZ,
    event_type TEXT CHECK (event_type IN ('allow', 'log', 'warn', 'block')),
    category TEXT,
    signature_id TEXT,
    latency_ms NUMERIC(10,2),
    -- NO metadata JSONB column - prevents arbitrary data ingestion
    -- All fields are typed and constrained
    created_at TIMESTAMPTZ DEFAULT now()
);

-- API validates payload against this schema before insert
-- Rejects any fields not in this list
```

### Portal Pages

| Page | Purpose |
|------|---------|
| Dashboard | Overview: active instances, blocks today, signature freshness |
| Fleet | List instances, status, last seen, config sync status |
| Policies | Create/edit policies, assign to instances or groups |
| Signatures | Browse available signatures, see changelog, download |
| Billing | Current plan, usage, upgrade, payment methods |
| Logs | Aggregated telemetry (if opt-in), search, export |
| Settings | API keys, team members, notifications |

### Billing Tiers

| Plan | Price | Signatures | Fleet Size | Support |
|------|-------|------------|------------|---------|
| Free | $0 | Bundled (basic) | 1 instance | Community |
| Pro | $49/mo | Full sync | 10 instances | Email |
| Enterprise | Custom | Full + custom | Unlimited | Dedicated |

**Detailed Pricing:**

| Feature | Free | Pro | Enterprise |
|---------|------|-----|------------|
| Signature updates | Bundled only (quarterly) | Real-time sync | Real-time + custom |
| Fleet instances | 1 | 10 included | Unlimited |
| Additional instances | N/A | $5/instance/mo | Included |
| Requests/month | Unlimited | Unlimited | Unlimited |
| ML classifier | Not included | Included | Included |
| Policy management | Local config only | Portal + push | Full fleet orchestration |
| Telemetry dashboard | Not included | Basic | Advanced + export |
| Support | GitHub issues | Email (48h SLA) | Dedicated (4h SLA) |
| SSO/SAML | Not included | Not included | Included |
| Custom signatures | Not included | Not included | Included |
| Air-gapped packages | Not included | Not included | Included |

**Overage & Limits:**

| Limit | Free | Pro | Enterprise |
|-------|------|-----|------------|
| Instance overage | Hard block | $5/instance/mo auto-billed | N/A |
| Signature sync rate | 1x/day | Every 5 min | Every 1 min |
| API rate limit | 10 req/min | 100 req/min | 1000 req/min |
| Telemetry retention | N/A | 30 days | 1 year |

**Enterprise Pricing Factors:**
- Base: $500/mo (includes 50 instances)
- Per additional 50 instances: $200/mo
- Custom signature development: $5,000 one-time + $500/mo maintenance
- Air-gapped package: $200/mo
- Priority support: Included

---

## 4. Signature System

### Signature Types

| Type | Format | Purpose |
|------|--------|---------|
| Regex patterns | Hyperscan .hsdb | Fast pattern matching (<1ms) |
| Heuristic rules | Encrypted YAML | Scoring weights, thresholds |
| ML models | ONNX | DeBERTa classifier, embeddings |
| Vector database | SQLite + numpy | Known attack embeddings |

### Distribution

```
BUILD PIPELINE (your side)

┌─────────┐    ┌─────────────┐    ┌──────────────────┐    ┌─────────────┐
│ Source  │───▶│  Compile    │───▶│ Compute SHA256   │───▶│  Publish    │
│ Rules   │    │  (Hyperscan)│    │ for each file    │    │  (DO Spaces)│
│ (.yaml) │    │  (.hsdb)    │    │                  │    │             │
└─────────┘    └─────────────┘    └────────┬─────────┘    └─────────────┘
                                           │
                                           ▼
                                  ┌──────────────────┐
                                  │ Sign MANIFEST    │
                                  │ (Ed25519)        │
                                  │ Contains all     │
                                  │ file hashes      │
                                  └──────────────────┘
```

**What Gets Signed:**
- The MANIFEST is signed (not individual files)
- Manifest contains SHA256 hash of each file
- Proxy verifies: manifest signature + each file's hash against manifest

**SYNC PROTOCOL (proxy side):**

```
1. GET /api/signatures/manifest
   Response: {
     "version": "2026.03.18.1",
     "files": [
       {"name": "injection-core.hsdb", "sha256": "abc123..."},
       ...
     ],
     "signature": "Ed25519-signature-of-this-manifest"
   }

2. Proxy verifies manifest signature using embedded public key

3. GET /api/signatures/download?file=injection-core.hsdb
   Headers: Authorization: Bearer apg_xxx

4. Proxy computes SHA256 of downloaded file

5. Proxy compares computed hash to manifest hash
   - Match → file is authentic
   - Mismatch → reject, alert, keep old signatures

6. Hot-reload signatures (no restart)
```

**Verification Code:**
```python
def verify_signature_bundle(manifest: dict, files: dict[str, bytes]) -> bool:
    # Step 1: Verify manifest signature
    manifest_bytes = canonical_json(manifest["files"])
    if not ed25519_verify(manifest_bytes, manifest["signature"], PUBLIC_KEY):
        raise SignatureError("Invalid manifest signature")

    # Step 2: Verify each file hash
    for file_meta in manifest["files"]:
        file_content = files[file_meta["name"]]
        computed_hash = sha256(file_content).hexdigest()
        if computed_hash != file_meta["sha256"]:
            raise SignatureError(f"Hash mismatch for {file_meta['name']}")

    return True
```

### API Contracts

**Fleet Registration:**
```http
POST /api/fleet/register
Authorization: Bearer apg_xxx
Content-Type: application/json

{
  "fingerprint": "fp_a1b2c3d4e5f6",
  "version": "1.2.0",
  "hostname": "proxy-prod-01",
  "metadata": {
    "os": "linux",
    "arch": "x86_64",
    "docker_version": "24.0.5"
  }
}

Response 201:
{
  "instance_id": "inst_abc123",
  "license_token": "eyJ...",
  "config_version": 42,
  "next_heartbeat_seconds": 60
}
```

**Fleet Heartbeat:**
```http
POST /api/fleet/heartbeat
Authorization: Bearer apg_xxx
Content-Type: application/json

{
  "instance_id": "inst_abc123",
  "fingerprint": "fp_a1b2c3d4e5f6",
  "signature_version": "2026.03.18.1",
  "config_version": 42,
  "stats": {
    "requests_total": 15420,
    "blocks_total": 23,
    "uptime_seconds": 86400
  }
}

Response 200:
{
  "status": "ok",
  "config_version": 43,           // if changed, proxy should fetch new config
  "signature_version": "2026.03.18.2",  // if changed, proxy should sync
  "next_heartbeat_seconds": 60
}
```

**Signature Manifest:**
```http
GET /api/signatures/manifest
Authorization: Bearer apg_xxx

Response 200:
{
  "version": "2026.03.18.1",
  "sequence": 1047,
  "released_at": "2026-03-18T14:30:00Z",
  "expires_at": "2026-03-25T14:30:00Z",
  "min_proxy_version": "1.2.0",
  "previous_hash": "sha256:abc123...",
  "files": [
    {
      "name": "injection-core.hsdb",
      "type": "hyperscan",
      "size": 245760,
      "sha256": "def456...",
      "tier": "free",
      "url": "/api/signatures/download/injection-core.hsdb"
    }
  ],
  "signature": "Ed25519:..."
}
```

**Policy Fetch:**
```http
GET /api/policies/active
Authorization: Bearer apg_xxx
X-Instance-ID: inst_abc123

Response 200:
{
  "policy_id": "pol_xyz789",
  "version": 3,
  "updated_at": "2026-03-18T10:00:00Z",
  "config": {
    "default_action": "log",
    "categories": {
      "prompt_injection": {
        "action": "block",
        "block_threshold": 0.85,
        "notify": true
      },
      "pii_outbound": {
        "action": "block",
        "allowlist": ["hr-assistant"]
      }
    }
  }
}
```

**Telemetry Ingestion:**
```http
POST /api/telemetry/batch
Authorization: Bearer apg_xxx
Content-Type: application/json

{
  "instance_id": "inst_abc123",
  "events": [
    {
      "timestamp": "2026-03-18T14:30:00Z",
      "event_type": "block",
      "category": "prompt_injection",
      "signature_id": "inj-core-042",
      "latency_ms": 2.3
    },
    {
      "timestamp": "2026-03-18T14:30:05Z",
      "event_type": "warn",
      "category": "encoding_suspicious",
      "signature_id": "enc-b64-001",
      "latency_ms": 1.1
    }
  ]
}

Response 202:
{
  "accepted": 2,
  "rejected": 0
}
```

**Pagination (for list endpoints):**
```http
GET /api/fleet/instances?limit=20&cursor=eyJ...
Authorization: Bearer apg_xxx

Response 200:
{
  "items": [...],
  "next_cursor": "eyJ...",  // null if no more
  "total": 47
}
```

**Auth Scopes:**
| Scope | Allows |
|-------|--------|
| `signatures:read` | Download signatures, fetch manifest |
| `fleet:write` | Register/heartbeat instances |
| `fleet:read` | List fleet instances |
| `policies:read` | Fetch active policy |
| `policies:write` | Create/update policies |
| `telemetry:write` | Submit telemetry events |
| `admin` | All operations |

### Protection Mechanisms

| Layer | Mechanism |
|-------|-----------|
| Binary compilation | Hyperscan DFA, not reversible to regex |
| Cryptographic signing | Ed25519, tamper detection |
| Expiry timestamp | 7-day expiry, forces re-sync |
| Instance binding | Optional, Enterprise tier |
| License validation | Startup + daily check |

### Licensing & Activation (Anti-Piracy)

**Technical Protection:**
```
┌─────────────────────────────────────────────────────────────────────────┐
│  SIGNATURE ACTIVATION FLOW                                               │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  1. Proxy generates instance fingerprint (hardware + install ID)        │
│     fingerprint = hash(machine_id + install_timestamp + random_salt)   │
│                                                                          │
│  2. On first sync, instance registers with control plane                │
│     POST /api/fleet/register { fingerprint, version, metadata }         │
│                                                                          │
│  3. Control plane issues instance-bound license token                   │
│     license = sign(account_id + fingerprint + plan + expiry)            │
│                                                                          │
│  4. Signatures downloaded include license check                         │
│     .hsdb header contains: expected_license_hash                        │
│     Proxy validates: hash(current_license) == expected_license_hash    │
│                                                                          │
│  5. If license invalid → signatures won't load (graceful fallback)      │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

**Instance Binding (Pro/Enterprise):**
- Each signature bundle is encrypted with instance-specific key
- Key derived from: `HKDF(master_key, instance_fingerprint, account_id)`
- Sharing .hsdb files between instances → decryption fails
- Master key rotates monthly; proxies auto-fetch new keys

**License Validation:**
```python
# Proxy validates license on:
# 1. Startup
# 2. Every signature sync
# 3. Daily background check

def validate_license(license_token: str) -> bool:
    # Verify signature
    if not verify_ed25519(license_token, LICENSE_PUBLIC_KEY):
        return False

    # Check expiry
    claims = decode_license(license_token)
    if claims.expires_at < now():
        return False

    # Check instance binding (if Pro/Enterprise)
    if claims.plan != "free":
        if claims.fingerprint != get_instance_fingerprint():
            return False

    # Check revocation list (cached, refreshed daily)
    if claims.license_id in REVOCATION_LIST:
        return False

    return True
```

**Sharing Prevention:**

| Scenario | Prevention | Enforcement |
|----------|------------|-------------|
| Copy .hsdb to another machine | Instance-bound encryption | Won't decrypt |
| Share API key | Fingerprint mismatch on different machine | Sync rejected |
| Share license token | Different fingerprint | Validation fails |
| Decompile signatures | Hyperscan DFA not reversible | N/A |
| Proxy code modification | License check in multiple places | Difficult to patch all |

**Legal Protection:**
- Terms of Service: Signatures licensed per-instance, non-transferable
- DMCA: Compiled signatures are copyrighted works
- License audit: Enterprise customers subject to annual audit rights

**Grace Periods:**
- License expired: 7-day grace period (warn, don't block)
- Instance fingerprint changed (hardware swap): 24h grace, then re-register
- Account suspended: Immediate, no grace (abuse case)

### Signature Manifest

```json
{
  "version": "2026.03.18.1",
  "released_at": "2026-03-18T14:30:00Z",
  "expires_at": "2026-03-25T14:30:00Z",
  "files": [
    {
      "name": "injection-core.hsdb",
      "type": "hyperscan",
      "size": 245760,
      "sha256": "abc123...",
      "tier": "free"
    },
    {
      "name": "injection-advanced.hsdb",
      "type": "hyperscan",
      "size": 512000,
      "sha256": "def456...",
      "tier": "pro"
    }
  ],
  "signature": "Ed25519-signature-here"
}
```

### Signature Categories

| Category | Description | Tier |
|----------|-------------|------|
| injection-core | Basic prompt injection patterns | Free |
| injection-advanced | Sophisticated injection, multi-layer encoding | Pro |
| jailbreak-patterns | DAN, roleplay, authority impersonation | Pro |
| exfiltration | Data extraction, URL encoding, image tags | Pro |
| pii-outbound | PII/PHI detection in requests | Pro |
| pii-inbound | PII/PHI detection in responses | Pro |
| encoding-detection | Base64, unicode, HTML entity detection | Free |
| context-drift | Multi-turn conversation manipulation | Enterprise |
| ml-classifier | DeBERTa prompt injection model | Enterprise |
| attack-vectors-db | Known attack embeddings for similarity | Enterprise |

---

## 5. Threat Model & Security

### Trust Boundaries

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           TRUST BOUNDARIES                               │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  BOUNDARY 1: Control Plane ↔ Internet                                   │
│  • API exposed to internet (rate-limited, authenticated)                │
│  • Portal requires login (MFA recommended)                              │
│  • Signature downloads require valid API key                            │
│                                                                          │
│  BOUNDARY 2: Control Plane ↔ Data Plane                                 │
│  • Proxies authenticate with API keys (scoped, rotatable)               │
│  • Signatures cryptographically signed (Ed25519)                        │
│  • Policies pulled by proxy (push = notify to pull, not direct push)    │
│  • mTLS optional for Enterprise                                         │
│                                                                          │
│  BOUNDARY 3: Data Plane ↔ Customer Apps                                 │
│  • Apps trust proxy's CA certificate                                    │
│  • Proxy sees all request/response content (MITM)                       │
│  • Content never leaves customer premises by default                    │
│                                                                          │
│  BOUNDARY 4: Data Plane ↔ LLM APIs                                      │
│  • Proxy terminates TLS to LLM provider                                 │
│  • Customer API keys for LLM pass through proxy                         │
│  • Proxy does NOT store or log API keys                                 │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### Failure Modes & Behavior

| Failure | Default Behavior | Configurable |
|---------|------------------|--------------|
| **Control plane unreachable** | Continue with cached signatures (grace period: 7 days) | Yes |
| **Signature sync fails** | Log warning, continue with existing signatures | Yes |
| **Signature expired** | WARN mode (log + pass traffic), not BLOCK | Yes |
| **Scanner crashes** | Fail-open (pass traffic) with alert | Yes (fail-closed option) |
| **Hyperscan load fails** | Fall back to Python regex (slower) | Yes |
| **ML model unavailable** | Skip ML layer, continue with fast+heuristics | Always |
| **Upstream LLM timeout** | Return 504 to client, log event | N/A |

**Fail-open vs Fail-closed:**
```yaml
# config.yaml
security:
  failure_mode: "open"  # "open" = pass traffic on error, "closed" = block
  grace_period_days: 7  # how long to run with expired signatures
  alert_on_degraded: true
```

### Compromise Scenarios

| Scenario | Impact | Mitigation |
|----------|--------|------------|
| **Control plane compromised** | Attacker could push malicious signatures | Signatures signed with offline key; proxy verifies Ed25519 |
| **Signature signing key stolen** | Attacker can create valid signatures | Key stored in HSM; revocation list checked on sync |
| **Proxy host compromised** | Attacker sees all LLM traffic | Proxy runs as non-root, read-only FS; no shell |
| **API key leaked** | Attacker can sync signatures for that account | Keys scoped, rotatable, usage logged; anomaly alerts |
| **CA private key leaked** | Attacker can MITM without proxy | Customer-managed CA; rotation guidance provided |

### Deployment Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| Connected | Auto-sync signatures, policies from portal | Default |
| Air-gapped | Offline packages, extended license (90 days) | High-security |
| Hybrid | Internal mirror syncs with portal | Compliance |

### Air-Gapped Deployment Workflow

**For environments with no internet connectivity:**

```
┌─────────────────────────────────────────────────────────────────────────┐
│  AIR-GAPPED DEPLOYMENT                                                   │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  INITIAL SETUP (on connected machine)                                   │
│  ════════════════════════════════════                                   │
│                                                                          │
│  1. Purchase Enterprise plan with air-gap option                        │
│                                                                          │
│  2. Generate offline license via portal:                                │
│     POST /api/licenses/offline                                          │
│     {                                                                   │
│       "instance_count": 10,                                             │
│       "validity_days": 90,                                              │
│       "fingerprints": ["fp_abc", "fp_def", ...]  // optional prebind   │
│     }                                                                   │
│     Response: license_bundle.zip                                        │
│                                                                          │
│  3. Download signature package:                                         │
│     GET /api/signatures/offline-bundle                                  │
│     Response: signatures_2026.03.18.zip                                 │
│     Contains: .hsdb files, manifest, offline license                    │
│                                                                          │
│  TRANSFER TO AIR-GAPPED ENVIRONMENT                                    │
│  ═══════════════════════════════════                                    │
│                                                                          │
│  4. Transfer via approved media (USB, secure file transfer)            │
│     - license_bundle.zip                                                │
│     - signatures_2026.03.18.zip                                         │
│     - aiproxyguard Docker image (docker save)                          │
│                                                                          │
│  INSTALLATION                                                            │
│  ════════════                                                            │
│                                                                          │
│  5. Load Docker image:                                                  │
│     docker load < aiproxyguard_v1.2.0.tar                               │
│                                                                          │
│  6. Extract signatures:                                                 │
│     unzip signatures_2026.03.18.zip -d /etc/aiproxyguard/signatures/   │
│                                                                          │
│  7. Configure for offline mode:                                         │
│     # /etc/aiproxyguard/config.yaml                                     │
│     sync:                                                               │
│       enabled: false                                                    │
│     license:                                                            │
│       mode: "offline"                                                   │
│       file: "/etc/aiproxyguard/license.jwt"                            │
│     signatures:                                                         │
│       path: "/etc/aiproxyguard/signatures/"                            │
│                                                                          │
│  8. Start proxy:                                                        │
│     docker run -v /etc/aiproxyguard:/etc/aiproxyguard ...              │
│                                                                          │
│  RENEWAL (every 90 days)                                                │
│  ═══════════════════════                                                │
│                                                                          │
│  9. On connected machine: generate new offline bundle                   │
│ 10. Transfer and replace files                                          │
│ 11. Restart proxy (or hot-reload if supported)                         │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

**Offline License Format:**
```json
{
  "license_id": "lic_offline_abc123",
  "account_id": "acc_xyz",
  "plan": "enterprise",
  "issued_at": "2026-03-18T00:00:00Z",
  "expires_at": "2026-06-16T00:00:00Z",  // 90 days
  "instance_limit": 10,
  "fingerprints": [],  // empty = any instance, populated = prebind
  "offline": true,
  "signature": "Ed25519..."
}
```

**Offline Validation (no network required):**
```python
def validate_offline_license(license_jwt: str) -> bool:
    # Decode and verify signature (public key in binary)
    claims = jwt_decode(license_jwt, PUBLIC_KEY)

    # Check expiry
    if claims["expires_at"] < now():
        return False

    # Check instance limit
    if claims["fingerprints"] and get_fingerprint() not in claims["fingerprints"]:
        return False

    # NO network call, NO revocation check (offline)
    return True
```

### TLS & Certificate Management

**CA Distribution Workflow:**
```
1. Customer generates CA (or uses existing internal CA)
   $ openssl genrsa -out ca.key 4096
   $ openssl req -new -x509 -days 365 -key ca.key -out ca.pem

2. Mount CA into proxy container
   -v /path/to/ca.pem:/etc/aiproxyguard/ca.pem
   -v /path/to/ca.key:/etc/aiproxyguard/ca.key

3. Distribute ca.pem to client machines
   • macOS: Add to System Keychain, mark as trusted
   • Linux: Copy to /usr/local/share/ca-certificates/, run update-ca-certificates
   • Windows: Import to Trusted Root Certification Authorities
   • Containers: Mount or bake into base image

4. Rotation (recommended: annually)
   • Generate new CA with overlapping validity
   • Deploy new CA to clients first
   • Update proxy with new CA
   • Remove old CA after grace period
```

**Certificate Pinning:**
- If clients pin LLM provider certs, they will reject proxy's certs
- Document known pinning behaviors (OpenAI SDK: no pinning, Anthropic SDK: no pinning)
- Provide bypass guidance for custom clients that pin

**TLS Options:**

| Option | Description | When to Use |
|--------|-------------|-------------|
| Customer CA | Customer provides CA cert/key, mounts into container | Production, security-conscious |
| Auto-generated | Proxy generates ephemeral CA on first run | Quick testing, POC |
| Transparent | No MITM, proxy at API gateway level (before TLS) | When MITM not acceptable |

### Secrets Management

**Supported Backends:**

| Backend | How | Use Case |
|---------|-----|----------|
| Environment variables | `AIPROXYGUARD_API_KEY` | Simple deployments |
| Mounted files | `/etc/aiproxyguard/secrets/` | Kubernetes secrets |
| HashiCorp Vault | `vault://secret/aiproxyguard` | Enterprise |
| AWS Secrets Manager | `aws-sm://aiproxyguard/api-key` | AWS deployments |
| Azure Key Vault | `az-kv://aiproxyguard` | Azure deployments |

**CA Key Protection:**
```yaml
# config.yaml
tls:
  ca_key: "/etc/aiproxyguard/ca.key"
  ca_key_password: "${CA_KEY_PASSWORD}"  # encrypted key support
  # OR for HSM:
  ca_key_hsm:
    provider: "pkcs11"
    library: "/usr/lib/softhsm/libsofthsm2.so"
    slot: 0
    pin: "${HSM_PIN}"
```

**Rotation Policy:**
- API keys: 90-day rotation recommended, forced on compromise
- CA certificates: Annual rotation with 30-day overlap
- Signing keys: Stored in HSM, rotated on compromise only

### Telemetry & Privacy

**What Telemetry Collects (opt-in only):**
```json
{
  "instance_id": "i-abc123",          // anonymized hash
  "timestamp": "2026-03-18T14:30:00Z",
  "event_type": "block",
  "category": "prompt_injection",
  "signature_id": "inj-core-042",
  "latency_ms": 2.3,
  // NO prompt content, NO response content, NO PII
}
```

**What Telemetry NEVER Collects:**
- Prompt or response content
- User identifiers or IP addresses
- LLM API keys
- Conversation context

**Redaction Strategy:**

The proxy automatically redacts sensitive data from all log outputs:

```python
REDACTION_PATTERNS = {
    # LLM API keys (never log these)
    "Authorization": r"Bearer\s+[\w-]+",           # → "Bearer [REDACTED]"
    "api-key": r"sk-[a-zA-Z0-9]+",                 # → "[REDACTED]"
    "x-api-key": r".+",                            # → "[REDACTED]"

    # Customer secrets
    "AIPROXYGUARD_API_KEY": r"apg_[a-zA-Z0-9]+",  # → "[REDACTED]"

    # PII in headers (optional)
    "X-User-Email": r".+",                         # → "[REDACTED]"
    "X-User-ID": r".+",                            # → "[REDACTED]" (if enabled)
}

def redact_request(request):
    """Applied before any logging or telemetry"""
    headers = {k: redact(k, v) for k, v in request.headers.items()}
    # Body redaction only if include_prompts: false (default)
    body = "[BODY_REDACTED]" if not config.include_prompts else request.body
    return RedactedRequest(headers=headers, body=body)
```

**What Gets Redacted:**

| Data Type | Redaction | Configurable |
|-----------|-----------|--------------|
| Authorization headers | Always | No |
| API keys in body | Always | No |
| LLM provider tokens | Always | No |
| Prompt content | Default redacted | Yes (`include_prompts`) |
| Response content | Default redacted | Yes (`include_responses`) |
| Client IP | Default redacted | Yes (`include_client_ip`) |

**Retention:**
- Control plane telemetry: 90 days, then aggregated
- Local logs: Customer-controlled
- Audit logs (who changed policies): 1 year

### Signature Sync Security

**Replay/Downgrade Protection:**
```json
{
  "version": "2026.03.18.1",
  "sequence": 1047,           // monotonic, must increase
  "min_proxy_version": "1.2.0", // reject if proxy too old
  "previous_hash": "sha256:...", // chain integrity
  "expires_at": "2026-03-25T14:30:00Z",
  "signature": "Ed25519..."
}
```

**Proxy Validation Rules:**
1. Sequence must be > last seen sequence (no rollback)
2. `previous_hash` must match hash of last manifest (chain integrity)
3. `expires_at` must be in future
4. Ed25519 signature must verify against embedded public key
5. Each file's SHA256 must match manifest

**Revocation:**
- Compromised signatures: Push new manifest with higher sequence
- Compromised signing key: Proxy checks revocation list on sync
- Revocation list URL embedded in proxy binary, checked every sync

### Security Guarantees

- **Data privacy:** Prompts/responses never sent to control plane by default
- **Telemetry:** Opt-in, anonymized (category counts only, schema-enforced)
- **Container:** Runs as non-root (UID 1000), read-only filesystem
- **Signatures:** Ed25519 signed, SHA256 checksums, monotonic versioning
- **API keys:** bcrypt hashed, scoped permissions, rotation supported
- **Secrets:** HSM/KMS integration for CA keys and signing keys

### Monitoring

```
GET /healthz          → 200 OK (liveness)
GET /readyz           → 200 OK (readiness)
GET /metrics          → Prometheus format

Metrics:
• aiproxyguard_requests_total{action="allow|block|warn"}
• aiproxyguard_latency_seconds{layer="fast|heuristic|ml"}
• aiproxyguard_signatures_version
• aiproxyguard_signatures_age_seconds
```

### Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: aiproxyguard
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: proxy
        image: ghcr.io/ainvirion/aiproxyguard:latest
        ports:
        - containerPort: 8080
        env:
        - name: AIPROXYGUARD_API_KEY
          valueFrom:
            secretKeyRef:
              name: aiproxyguard-secrets
              key: api-key
        livenessProbe:
          httpGet:
            path: /healthz
            port: 8080
        readinessProbe:
          httpGet:
            path: /readyz
            port: 8080
```

---

## 6. Phasing

**Revised timelines based on technical complexity assessment.**

### Phase 1A: Core Proxy (Foundation) — 4 weeks

**Deliverable:** HTTP/1.1 proxy with basic scanning (no TLS intercept yet)

- Async HTTP proxy (aiohttp-based, transparent mode)
- Scanner pipeline: Python regex only (no Hyperscan yet)
- Basic heuristics (encoding detection, trigger words)
- YAML configuration
- JSON logging to stdout
- Docker image (x86_64 only)
- Basic README

**Explicitly out of scope:**
- TLS interception (Phase 1B)
- Hyperscan (Phase 1B)
- Prometheus metrics (Phase 1B)
- Multi-arch (Phase 2)

### Phase 1B: TLS & Performance — 3 weeks

**Deliverable:** Full MITM proxy with Hyperscan

- TLS interception with configurable CA
- Hyperscan integration (x86_64)
- Python re2 fallback (ARM64)
- SSE pass-through streaming
- Prometheus /metrics endpoint
- /healthz and /readyz endpoints
- CA distribution documentation

### Phase 2A: Signature Infrastructure — 4 weeks

**Deliverable:** Signature compiler + distribution API

- Signature compiler (YAML → Hyperscan .hsdb)
- Ed25519 signing pipeline
- FastAPI server (minimal)
- DO Spaces integration
- GET /api/signatures/manifest
- GET /api/signatures/download
- Proxy sync module + hot-reload

**Out of scope:** Portal UI, fleet management, billing

### Phase 2B: Fleet & Portal — 4 weeks

**Deliverable:** Basic portal + fleet visibility

- PostgreSQL schema (accounts, fleet, api_keys)
- API key authentication
- Fleet registration + heartbeat
- Instance fingerprinting
- Basic portal: login, API keys, fleet list
- Signature changelog page

### Phase 3A: Policy Management — 3 weeks

**Deliverable:** Policy editor + push

- Policy CRUD API
- Policy versioning
- Policy update notification (proxy polls, sees new version, pulls)
- Portal: policy editor UI
- Policy templates library

### Phase 3B: Billing & Tiers — 3 weeks

**Deliverable:** Stripe integration

- Stripe customer/subscription sync
- Tiered signature access enforcement
- Instance limits per plan
- Billing portal page
- Usage tracking

### Phase 4A: ML Detection — 4 weeks

**Deliverable:** DeBERTa classifier integration

- ONNX runtime integration
- DeBERTa model packaging
- Batch inference support
- Confidence thresholds
- CPU-only deployment

### Phase 4B: Response Scanning — 3 weeks

**Deliverable:** Outbound data protection

- PII detection (Presidio patterns → Hyperscan)
- Async response scanning
- Exfiltration pattern library
- Allowlist management

### Phase 4C: Advanced Features — 4 weeks

**Deliverable:** Multi-turn + embeddings

- Conversation context tracking
- Semantic drift detection
- Vector similarity (known attacks)
- Telemetry dashboard

### Phase 5: Enterprise — Ongoing

**Deliverables added incrementally:**

| Feature | Estimated Time | Notes |
|---------|----------------|-------|
| Air-gapped packages | 2 weeks | See air-gap workflow below |
| Instance binding encryption | 2 weeks | |
| SSO/SAML | 3 weeks | |
| SIEM integrations | 2 weeks | |
| Helm chart | 2 weeks | |
| LLM detection layer | 4 weeks | |
| Custom signature service | 4 weeks | |
| ARM64 native Hyperscan | 2 weeks | Until then, re2 fallback works (10x slower) |
| HTTP/2 + WebSocket | 4 weeks | Native support; HTTP/1.1 SSE covers most APIs |

**Note on ARM64:** ARM64 Docker images are available from Phase 1B using the Python `re2` fallback. Phase 5 adds native Hyperscan compilation for better performance.

**Note on HTTP/2:** HTTP/1.1 + SSE covers OpenAI, Anthropic, Azure (95%+ of traffic). HTTP/2 native support is for edge cases and future-proofing.

### Phase Summary

| Phase | Duration | Cumulative |
|-------|----------|------------|
| 1A: Foundation | 4 weeks | 4 weeks |
| 1B: TLS & Performance | 3 weeks | 7 weeks |
| 2A: Signature Infra | 4 weeks | 11 weeks |
| 2B: Fleet & Portal | 4 weeks | 15 weeks |
| 3A: Policy Mgmt | 3 weeks | 18 weeks |
| 3B: Billing | 3 weeks | 21 weeks |
| 4A: ML Detection | 4 weeks | 25 weeks |
| 4B: Response Scanning | 3 weeks | 28 weeks |
| 4C: Advanced | 4 weeks | 32 weeks |
| **Total to feature-complete** | | **~8 months** |

### Milestones

| Milestone | Phase | What It Enables |
|-----------|-------|-----------------|
| **OSS Launch** | After 1B | Community adoption, GitHub presence |
| **Beta Launch** | After 2B | Early customers, signature sync |
| **GA Launch** | After 3B | Paid subscriptions, production ready |
| **Enterprise Launch** | After Phase 5 items | Large org sales |

---

## 7. Success Metrics

| Phase | Metric | Target |
|-------|--------|--------|
| Phase 1 | GitHub stars / Docker pulls | 500+ stars, 1K+ pulls |
| Phase 2 | Registered accounts | 100+ free accounts |
| Phase 3 | Paying customers | 10+ Pro subscriptions |
| Phase 4 | Detection accuracy | >90% known attacks, <5% FPR |
| Phase 5 | Enterprise deals | 2+ Enterprise contracts |

---

## 8. Research References

Based on analysis of:

- [OWASP LLM01:2025 Prompt Injection Guide](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)
- [Awesome Prompt Injection Repository](https://github.com/Joe-B-Security/awesome-prompt-injection)
- [LLM Guard by Protect AI](https://github.com/protectai/llm-guard)
- [Garak by NVIDIA](https://github.com/NVIDIA/garak)
- [Augustus by Praetorian](https://github.com/praetorian-inc/augustus)
- [PIGuard/InjecGuard Research](https://arxiv.org/html/2410.22770v1)

Key finding: Defense-in-depth with multiple detection layers is essential. No single method achieves perfect detection. The proxy architecture provides unique value by intercepting all LLM traffic without SDK changes.

---

## 9. Repository Structure

```
aiproxyguard/
├── src/
│   └── aiproxyguard/
│       ├── proxy/           # Async proxy core
│       ├── scanner/         # Detection pipeline
│       │   ├── fast.py      # Hyperscan layer
│       │   ├── heuristics.py
│       │   └── ml.py        # Optional ML layer
│       ├── signatures/      # Signature loading/verification
│       ├── sync/            # Control plane sync
│       ├── config/          # Configuration loading
│       └── logging/         # Structured logging
├── signatures/              # Bundled free signatures (YAML)
├── tests/
├── docs/
├── Dockerfile
├── pyproject.toml
└── README.md

aiproxyguard-server/
├── src/
│   └── aiproxyguard_server/
│       ├── api/             # FastAPI routes
│       ├── models/          # SQLAlchemy models
│       ├── services/        # Business logic
│       ├── compiler/        # Signature compilation
│       └── billing/         # Stripe integration
├── portal/                  # Frontend (HTMX or React)
├── deploy/                  # DO App Platform config
├── tests/
└── pyproject.toml
```

---

## Appendix: Attack Categories Covered

### Direct Prompt Injection
- Instruction override patterns
- Mode/role switch patterns
- DAN-style jailbreaks
- Authority impersonation

### Encoding/Obfuscation
- Base64 encoding
- Unicode homoglyphs
- Zero-width characters
- HTML entity encoding
- Character splicing

### Indirect Injection
- RAG poisoning indicators
- Document-embedded instructions
- Tool description poisoning

### Data Exfiltration
- Image tag injection
- URL parameter encoding
- Conversation history extraction
- System prompt exfiltration

### Multi-turn Attacks
- Semantic drift detection
- Escalation patterns
- Context manipulation
