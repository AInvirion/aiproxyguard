# Copyright (c) 2025-2026 AInvirion. All Rights Reserved.

"""Exact-match response cache (#307) — key derivation, eligibility, storage."""

import json

import pytest

from aiproxyguard.cache import CachedResponse, ResponseCache, is_cacheable


def body(**ov):
    base = {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}], "temperature": 0}
    base.update(ov)
    return base


class TestEligibility:
    def test_deterministic_temperature_zero_is_cacheable(self):
        assert is_cacheable(body(temperature=0)) is True

    def test_seed_makes_it_cacheable_without_temp(self):
        b = body(seed=42)
        del b["temperature"]
        assert is_cacheable(b) is True

    def test_nondeterministic_rejected(self):
        b = body(temperature=0.7)
        assert is_cacheable(b) is False
        b2 = body()
        del b2["temperature"]
        assert is_cacheable(b2) is False  # no temp, no seed

    def test_tools_rejected(self):
        assert is_cacheable(body(tools=[{"type": "function"}])) is False
        assert is_cacheable(body(functions=[{"name": "f"}])) is False
        assert is_cacheable(body(tool_choice="auto")) is False

    def test_response_format_rejected(self):
        assert is_cacheable(body(response_format={"type": "json_object"})) is False

    def test_streaming_rejected(self):
        assert is_cacheable(body(stream=True)) is False

    def test_multimodal_content_rejected(self):
        b = body(messages=[{"role": "user", "content": [{"type": "text", "text": "x"}]}])
        assert is_cacheable(b) is False

    def test_responses_api_input_parts_rejected(self):
        b = body()
        del b["messages"]
        b["input"] = [{"role": "user", "content": [{"type": "input_text", "text": "x"}]}]
        assert is_cacheable(b) is False

    def test_audio_and_nontext_modalities_rejected(self):
        assert is_cacheable(body(audio={"voice": "alloy"})) is False
        assert is_cacheable(body(modalities=["text", "audio"])) is False
        assert is_cacheable(body(modalities=["text"])) is True  # text-only is fine


class TestComputeKey:
    def _cache(self, **ov):
        kw = dict(redis_url="redis://x", enabled=True, namespace="ns1")
        kw.update(ov)
        return ResponseCache(**kw)

    def test_none_when_disabled(self):
        c = ResponseCache(redis_url=None, enabled=False, namespace="ns1")
        assert c.compute_key("openai", "/v1/chat", json.dumps(body()).encode()) is None

    def test_none_when_ineligible(self):
        c = self._cache()
        assert c.compute_key("openai", "/v1/chat", json.dumps(body(temperature=0.9)).encode()) is None

    def test_deterministic_same_key(self):
        c = self._cache()
        b = json.dumps(body()).encode()
        assert c.compute_key("openai", "/v1/chat", b) == c.compute_key("openai", "/v1/chat", b)

    def test_key_varies_by_model_params_messages(self):
        c = self._cache()
        base = c.compute_key("openai", "/v1/chat", json.dumps(body()).encode())
        assert base != c.compute_key("openai", "/v1/chat", json.dumps(body(model="gpt-4o")).encode())
        assert base != c.compute_key("openai", "/v1/chat", json.dumps(body(seed=1)).encode())
        assert base != c.compute_key("openai", "/v1/chat",
                                     json.dumps(body(messages=[{"role": "user", "content": "bye"}])).encode())

    def test_tenant_namespace_isolates(self):
        b = json.dumps(body()).encode()
        k1 = self._cache(namespace="org-a").compute_key("openai", "/v1/chat", b)
        k2 = self._cache(namespace="org-b").compute_key("openai", "/v1/chat", b)
        assert k1 != k2
        assert k1.startswith("apgcache:org-a:")

    def test_key_varies_by_provider_and_path(self):
        c = self._cache()
        b = json.dumps(body()).encode()
        assert c.compute_key("openai", "/v1/chat", b) != c.compute_key("anthropic", "/v1/chat", b)
        assert c.compute_key("openai", "/v1/chat", b) != c.compute_key("openai", "/v2/chat", b)

    def test_key_covers_full_body_not_a_subset(self):
        # An arbitrary output-affecting field (logit_bias) must change the key —
        # proves we hash the whole body, not a hand-picked subset.
        c = self._cache()
        base = c.compute_key("openai", "/v1/chat", json.dumps(body()).encode())
        with_bias = c.compute_key("openai", "/v1/chat", json.dumps(body(logit_bias={"50256": -1})).encode())
        assert base != with_bias


class _FakeRedis:
    """Minimal in-memory async stand-in for redis.asyncio."""

    def __init__(self):
        self.store = {}
        self.last_ex = None

    async def get(self, key):
        return self.store.get(key)

    async def set(self, key, value, ex=None):
        self.store[key] = value
        self.last_ex = ex


class TestStorage:
    @pytest.mark.asyncio
    async def test_set_then_get_roundtrip(self):
        c = ResponseCache(redis_url="redis://x", enabled=True, namespace="ns", ttl_seconds=1800)
        c._redis = _FakeRedis()
        resp = CachedResponse(body=b'{"ok":true}', content_type="application/json",
                              input_tokens=12, output_tokens=34, model="gpt-4o-mini")
        await c.set("k1", resp)
        assert c._redis.last_ex == 1800  # ttl applied
        got = await c.get("k1")
        assert got.body == b'{"ok":true}'
        assert got.input_tokens == 12 and got.output_tokens == 34 and got.model == "gpt-4o-mini"
        assert got.status == 200

    @pytest.mark.asyncio
    async def test_status_roundtrips(self):
        c = ResponseCache(redis_url="redis://x", enabled=True, namespace="ns")
        c._redis = _FakeRedis()
        await c.set("k", CachedResponse(b"x", "application/json", 0, 0, None, status=201))
        assert (await c.get("k")).status == 201

    @pytest.mark.asyncio
    async def test_ttl_capped_at_one_hour(self):
        c = ResponseCache(redis_url="redis://x", enabled=True, namespace="ns", ttl_seconds=99999)
        assert c.ttl_seconds == 3600

    @pytest.mark.asyncio
    async def test_disabled_cache_is_noop(self):
        c = ResponseCache(redis_url=None, enabled=False, namespace="ns")
        await c.set("k", CachedResponse(b"x", "application/json", 0, 0, None))
        assert await c.get("k") is None

    @pytest.mark.asyncio
    async def test_get_miss_returns_none(self):
        c = ResponseCache(redis_url="redis://x", enabled=True, namespace="ns")
        c._redis = _FakeRedis()
        assert await c.get("absent") is None


class TestBuildResponseCache:
    """server._build_response_cache namespace/tenant-isolation behavior (#307)."""

    def _cfg(self, cache_cfg, api_key=""):
        from types import SimpleNamespace
        return SimpleNamespace(cache=cache_cfg, control_plane=SimpleNamespace(api_key=api_key))

    def test_disabled_when_no_namespace_and_no_api_key(self):
        from aiproxyguard.config import CacheConfig
        from aiproxyguard.server import _build_response_cache
        c = _build_response_cache(self._cfg(CacheConfig(enabled=True, redis_url="redis://x"), api_key=""))
        assert c.enabled is False  # fail closed: no way to isolate tenants

    def test_namespace_derived_from_api_key(self):
        from aiproxyguard.config import CacheConfig
        from aiproxyguard.server import _build_response_cache
        c = _build_response_cache(self._cfg(CacheConfig(enabled=True, redis_url="redis://x"), api_key="apg_secret"))
        assert c.enabled is True
        assert c.namespace not in ("", "default") and len(c.namespace) == 16

    def test_explicit_namespace_used(self):
        from aiproxyguard.config import CacheConfig
        from aiproxyguard.server import _build_response_cache
        c = _build_response_cache(self._cfg(CacheConfig(enabled=True, redis_url="redis://x", namespace="org-x"), api_key=""))
        assert c.enabled is True and c.namespace == "org-x"
