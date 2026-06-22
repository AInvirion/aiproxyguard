---
title: Cost Optimization
nav_order: 4
---

# Cost Optimization

AIProxyGuard can cut your LLM bill while it secures your traffic. Four opt-in
features reduce token spend on the requests that flow **through the proxy**:

| Feature | What it does | Requires |
|---------|--------------|----------|
| **Prompt caching** | Injects Anthropic `cache_control` so repeated system prefixes bill at the cached-token discount | Anthropic Messages API |
| **Smart model routing** | Routes/downgrades requests to a cheaper model in the same provider | A `routing` config |
| **Response caching** | Serves repeat identical requests from an exact-match cache, skipping the upstream call entirely | Redis |
| **Usage & cost analytics** | Tracks provider-billed token spend per request for cost attribution | Control plane |

All four are **off by default** and are typically managed from the control
plane (the cloud portal's **Optimization** and **Usage** pages).

## Important: cost optimization needs forward-proxy mode

These features only apply to traffic that the proxy can **rewrite and
intercept** — i.e. requests sent *through* the forward proxy, where you point
your LLM client's `base_url` at AIProxyGuard:

```python
client = OpenAI(api_key="sk-...", base_url="http://localhost:8080/openai/v1")
```

The detection-only **`/check`** endpoint (and the SDK `.check()` methods) only
inspect the prompt text and return a verdict — they never make the LLM call, so
there is **nothing to route, cache, or bill**. If you integrate via `/check`
and call the LLM yourself, you get security scanning but **no cost savings**.
To save money, route the actual LLM traffic through the proxy.

---

## Prompt caching (Anthropic)

For Anthropic Messages-API requests, the proxy injects
`cache_control: {type: ephemeral}` into the top-level `system` prompt, so
Anthropic bills that prefix at the cached-token discount on repeat requests.

```yaml
cost_optimization:
  anthropic_prompt_cache: true   # env: AIPROXYGUARD_ANTHROPIC_PROMPT_CACHE
```

Runs as a pipeline body mutator (parse → mutate → serialize → scan → forward),
so the scanner still inspects the exact bytes forwarded. Only a top-level
`system` string on `/v1/messages` is touched; everything else is forwarded
unchanged, and parse failures fail open (original bytes forwarded).

## Smart model routing

Route requests to a cheaper model in the **same provider**. Two modes, both
configured under the `routing` section (usually pushed from the control plane):

**1. Task aliases** — send `model: "router:<task>"` and the proxy resolves the
task's cheapest-first pool to the first capable model:

```yaml
routing:
  tasks:
    summarize:
      ordered_pool: ["gpt-4o-mini", "gpt-4o"]   # cheapest first
      fallback: ["gpt-4o"]
```

The chosen model is reported in the `x-aiproxyguard-routed-model` response
header. An unknown task fails closed (400); an upstream 5xx retries the next
model in the pool (rescanning each forwarded body).

**2. Complexity-scored downgrades** — transparently downgrade *simple* requests
that didn't use an alias:

```yaml
routing:
  downgrades:
    - {provider: openai, from: gpt-4o, to: gpt-4o-mini}
  dry_run: true    # observe-only until you set false
```

A deterministic scorer keeps complex prompts (any code/reasoning/analysis/
technical signal) on the original model; tool/multimodal/streaming requests are
never downgraded. **Ships dry-run by default** — it emits an
`x-aiproxyguard-routing-decision` header without rewriting until you set
`dry_run: false`.

## Response caching

Serve repeat identical requests from a Redis-backed exact-match cache, skipping
the upstream call entirely. **Off by default.** It activates only when **all**
of the following hold:

1. **Infrastructure** — a reachable `cache.redis_url` and `cache.enabled: true`.
2. **Opt-in** — a policy enables `cost_optimization.response_cache` (and,
   optionally, the request path matches `response_cache_routes`).
3. **Eligibility** — the request is deterministic and side-effect-free.

```yaml
cache:
  enabled: true                              # env: AIPROXYGUARD_CACHE_ENABLED
  redis_url: "${AIPROXYGUARD_CACHE_REDIS_URL}"  # rediss://… (TLS recommended)
  ttl_seconds: 3600                          # capped at 1h
  namespace: ""                              # default: hash of the control-plane API key

cost_optimization:
  response_cache: true                       # per-policy opt-in (env: AIPROXYGUARD_RESPONSE_CACHE)
  response_cache_routes:                     # optional allowlist (empty = all eligible routes)
    - "/openai/*"
```

**Eligibility** (a request is cached only if all are true): no
`tools`/`functions`/`tool_choice`, no `response_format`, no streaming, no
audio/non-text modalities, no multimodal content, and deterministic generation
(`temperature == 0` or a `seed` is set).

**Safety guarantees:**

- **Tenant isolation** — the cache key is a SHA-256 of the full canonicalized
  request body, namespaced per deployment (explicit `cache.namespace`, else a
  hash of the control-plane API key) plus provider and path. Two orgs sharing a
  Redis can never collide. If no namespace can be derived, the cache **fails
  closed** (disabled).
- **Never a policy bypass** — a cached response still runs response scanning
  before it is served.
- **Sensitive data** — caching is automatically disabled for a policy that has
  PII/PHI detection enabled.
- **Graceful degradation** — any Redis error disables the cache for the process
  (logged once); a cache problem never fails a request.

A served cache hit returns the `x-aiproxyguard-cache: hit` response header
(misses return `miss`).

### Route-level scoping

`response_cache_routes` is an optional allowlist of
[fnmatch](https://docs.python.org/3/library/fnmatch.html) patterns. Empty =
cache every eligible route; non-empty = cache **only** requests whose path
matches a pattern (e.g. `/openai/*`). The query string is ignored when matching.

### Redis

Response caching is the one cost feature with a new dependency. Cloud
deployments use a managed Redis/Valkey; on-prem deployments provide their own
and set `cache.redis_url`. Use a TLS endpoint (`rediss://`) and restrict access
to the proxy.

## Usage & cost analytics

The proxy extracts provider-billed token counts (the `usage` field; OpenAI and
Anthropic shapes) from upstream responses and reports per-request `usage`
telemetry to the control plane:

```yaml
control_plane:
  report_usage: true    # default true; env: AIPROXYGUARD_REPORT_USAGE
```

Best-effort and fully off the client response path (parsing runs in a
background task). In the cloud portal this powers the **Usage** page (spend by
model/provider/instance, CSV/JSON export) and the optimization-savings figures
on the **Report**/**Analytics**/**Dashboard** pages — including the savings
attributed to routing, prompt caching, and response-cache hits.

## How savings surface

When connected to the control plane, routing/cache provenance and cache-hit
events flow up as telemetry, and the portal attributes the dollar savings:

- **Routing** — realized when a downgrade was applied, projected when in
  dry-run.
- **Prompt cache** — Anthropic cached-token reads.
- **Response cache** — the avoided spend on each served cache hit.

See the cloud portal's **Optimization** page to enable these per policy and the
**Report**/**Usage** pages to track the savings.
