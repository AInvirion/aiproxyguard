# Copyright (c) 2025-2026 AInvirion. All Rights Reserved.
"""Exact-match response cache (#307).

Caches LLM responses keyed by an exact request fingerprint and serves them on
repeat hits, saving the entire upstream call. Exact-match ONLY (no semantic) —
defensible for correctness and privacy.

Safety invariants (enforced here + in the pipeline):
- Tenant isolation: every key is namespaced per deployment (a hash of the
  control-plane API key) and includes provider/endpoint/model/params, so two
  orgs sharing a Redis can never collide.
- Cacheable only when deterministic and side-effect-free: no tools/functions,
  no response_format, no multimodal content, non-streaming, and temperature==0
  or an explicit seed.
- Never a policy bypass: the pipeline still runs response scanning on a cached
  body before serving it (this module only stores/loads bytes).
- Graceful degradation: any Redis error disables the cache for the process
  (logged once) — a cache problem must never fail a request.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class CachedResponse:
    """A stored upstream response plus the accounting needed for savings."""

    body: bytes
    content_type: str
    input_tokens: int
    output_tokens: int
    model: str | None
    status: int = 200


def _has_multimodal_parts(items: object) -> bool:
    """True if any chat message / Responses-API input item carries list content (parts)."""
    if not isinstance(items, list):
        return False
    for m in items:
        if isinstance(m, dict) and isinstance(m.get("content"), list):
            return True
    return False


def is_cacheable(body: dict) -> bool:
    """True only when the request is safe to cache (deterministic, text-only, no tools)."""
    if body.get("tools") or body.get("functions") or body.get("tool_choice"):
        return False
    if body.get("response_format"):
        return False
    if body.get("stream"):
        return False
    # Audio / non-text output modalities are not cacheable.
    if body.get("audio"):
        return False
    modalities = body.get("modalities")
    if isinstance(modalities, list) and any(m != "text" for m in modalities):
        return False
    # Deterministic only: temperature exactly 0, or an explicit seed.
    temperature = body.get("temperature")
    if not (temperature == 0 or body.get("seed") is not None):
        return False
    # No multimodal content — chat `messages` or Responses-API `input` with parts.
    if _has_multimodal_parts(body.get("messages")) or _has_multimodal_parts(body.get("input")):
        return False
    return True


class ResponseCache:
    """Redis-backed exact-match response cache. No-ops when disabled/unhealthy."""

    def __init__(
        self,
        *,
        redis_url: str | None,
        ttl_seconds: int = 3600,
        namespace: str = "default",
        enabled: bool = False,
    ) -> None:
        self.enabled = bool(enabled and redis_url)
        self._redis_url = redis_url
        self.ttl_seconds = max(1, min(int(ttl_seconds), 3600))
        self.namespace = namespace or "default"
        self._redis = None
        self._broken = False

    async def _client(self):
        if self._broken or not self.enabled:
            return None
        if self._redis is None:
            try:
                import redis.asyncio as aioredis

                self._redis = aioredis.from_url(
                    self._redis_url, socket_connect_timeout=2, socket_timeout=2
                )
            except Exception as e:  # pragma: no cover - import/url errors
                logger.warning("Response cache disabled (redis init failed): %s", e)
                self._broken = True
                return None
        return self._redis

    def compute_key(self, provider: str, path: str, outbound: bytes) -> str | None:
        """Cache key for an effective (post-routing) request, or None if ineligible."""
        if not self.enabled:
            return None
        try:
            body = json.loads(outbound)
        except Exception:
            return None
        if not isinstance(body, dict) or not is_cacheable(body):
            return None
        # Exact match: key on the ENTIRE canonicalized request body, so any
        # field that influences output (input/instructions/logit_bias/etc.)
        # naturally yields a distinct key — no collisions across request shapes.
        canon = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        digest = hashlib.sha256(canon.encode()).hexdigest()
        return f"apgcache:{self.namespace}:{provider}:{path}:{digest}"

    async def get(self, key: str) -> CachedResponse | None:
        client = await self._client()
        if client is None:
            return None
        try:
            raw = await client.get(key)
        except Exception as e:
            logger.warning("Response cache get failed; disabling: %s", e)
            self._broken = True
            return None
        if not raw:
            return None
        try:
            d = json.loads(raw)
            return CachedResponse(
                body=base64.b64decode(d["body"]),
                content_type=d.get("content_type", "application/json"),
                input_tokens=int(d.get("input_tokens", 0)),
                output_tokens=int(d.get("output_tokens", 0)),
                model=d.get("model"),
                status=int(d.get("status", 200)),
            )
        except Exception:  # pragma: no cover - corrupt entry
            return None

    async def set(self, key: str, resp: CachedResponse) -> None:
        client = await self._client()
        if client is None:
            return
        try:
            payload = json.dumps(
                {
                    "body": base64.b64encode(resp.body).decode(),
                    "content_type": resp.content_type,
                    "input_tokens": resp.input_tokens,
                    "output_tokens": resp.output_tokens,
                    "model": resp.model,
                    "status": resp.status,
                }
            )
            await client.set(key, payload, ex=self.ttl_seconds)
        except Exception as e:
            logger.warning("Response cache set failed; disabling: %s", e)
            self._broken = True
